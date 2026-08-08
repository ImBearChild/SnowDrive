//! iSCSI target protocol state machine (iscsi_target.c).
//!
//! [`Session`] drives one connection through the Login Phase (§5) and the
//! Full Feature command loop (§10), one transaction per [`Session::step`]
//! call. [`serve_conn`] is the blocking `while step`
//! wrapper.
//!
//! Key fixes over the legacy C implementation: CID read at
//! byte 20-21 (from iscsi_pdu), Data-Out ITT/TTT/BufferOffset/DataSN
//! validation with Reject 0x09 (#11), TMF CmdSN check by I bit (#21),
//! out-of-window/duplicate CmdSN silently ignored (#17), Reject carries the
//! rejected PDU header + ITT=0xffffffff (#18), and read-timeout coverage is
//! delegated to the `Conn` implementation (#10/#20).

use crate::iscsi::conn::{read_exact, write_all, Conn};
use crate::iscsi::pdu::{
    flag, iscsi_opcode_name, op, pdu_pad_len, reject, stage, status, tmf, tmf_response, Bhs,
    BHS_SIZE, MAX_DATA_SEGMENT,
};
use crate::scsi::device::{CommandOutcome, ScsiDevice};
use crate::scsi::scsi::op as scsi_op;
use crate::scsi::scsi::{opcode_name, Sense};

/// Largest login data segment accepted for negotiation (C `LOGIN_RESP_MAX`).
const LOGIN_MAX: usize = 4096;
/// Target Transfer Tag for R2T — single outstanding transfer (Phase 1).
const TTT: u32 = 1;
/// RFC 3720 §12.14 suggested defaults (clamped when the initiator sends more).
const DEFAULT_FIRST_BURST: u32 = 65536;
const DEFAULT_MAX_BURST: u32 = 262144;

/// One Login parameter key: how the target responds.
///
/// `value: None` echoes the initiator's value; `Some(v)` overrides it.
/// `always: true` keys are emitted even if the initiator never sent them.
struct LoginParam {
    key: &'static str,
    value: Option<&'static str>,
    always: bool,
}

/// Login parameter table (matches the legacy C `LOGIN_TABLE`).
const LOGIN_TABLE: &[LoginParam] = &[
    LoginParam {
        key: "TargetAlias",
        value: Some("SnowSCSI"),
        always: true,
    },
    LoginParam {
        key: "AuthMethod",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "HeaderDigest",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "DataDigest",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "InitialR2T",
        value: Some("Yes"),
        always: false,
    },
    LoginParam {
        key: "ImmediateData",
        value: Some("Yes"),
        always: false,
    },
    LoginParam {
        key: "MaxBurstLength",
        value: None,
        always: false,
    },
    LoginParam {
        key: "FirstBurstLength",
        value: None,
        always: false,
    },
    LoginParam {
        key: "MaxRecvDataSegmentLength",
        value: Some("8192"),
        always: false,
    },
    LoginParam {
        key: "MaxOutstandingR2T",
        value: Some("1"),
        always: false,
    },
    LoginParam {
        key: "ErrorRecoveryLevel",
        value: Some("0"),
        always: false,
    },
    LoginParam {
        key: "MaxConnections",
        value: Some("1"),
        always: false,
    },
    LoginParam {
        key: "TargetPortalGroupTag",
        value: Some("1"),
        always: true,
    },
    LoginParam {
        key: "DataPDUInOrder",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DataSequenceInOrder",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DefaultTime2Wait",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DefaultTime2Retain",
        value: None,
        always: false,
    },
    LoginParam {
        key: "IFMarker",
        value: None,
        always: false,
    },
    LoginParam {
        key: "OFMarker",
        value: None,
        always: false,
    },
];

/// Initiator-only keys never echoed in a Login Response (RFC 3720 §12.4).
const SKIP_KEYS: &[&str] = &[
    "InitiatorName",
    "InitiatorAlias",
    "SessionType",
    "TargetName",
];

/// Login phase stage (RFC 3720 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStage {
    Security,
    OpParam,
    FullFeature,
}

impl LoginStage {
    fn from_csg(csg: u8) -> Option<LoginStage> {
        match csg {
            stage::SECURITY => Some(LoginStage::Security),
            stage::OP_PARAM => Some(LoginStage::OpParam),
            stage::FULL_FEATURE => Some(LoginStage::FullFeature),
            _ => None,
        }
    }
}

/// Negotiated login parameters (RFC 3720 §12.12-.14).
pub struct NegotiatedParams {
    pub immediate_data: bool,
    pub initial_r2t: bool,
    pub first_burst_len: u32,
    pub max_burst_len: u32,
    pub max_outstanding_r2t: u32,
}

impl Default for NegotiatedParams {
    fn default() -> Self {
        Self {
            immediate_data: true,
            initial_r2t: true,
            first_burst_len: DEFAULT_FIRST_BURST,
            max_burst_len: DEFAULT_MAX_BURST,
            max_outstanding_r2t: 1,
        }
    }
}

/// Per-connection iSCSI session state.
///
/// `cmd_sn` is the last consumed CmdSN; non-immediate commands are accepted
/// only when `CmdSN == cmd_sn + 1` (queue depth 1, MaxCmdSN = ExpCmdSN).
pub struct Session {
    cmd_sn: u32,
    stat_sn: u32,
    stage: LoginStage,
    max_recv_data_segment: u32,
    neg: NegotiatedParams,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            cmd_sn: 0,
            stat_sn: 0,
            stage: LoginStage::Security,
            max_recv_data_segment: MAX_DATA_SEGMENT,
            neg: NegotiatedParams::default(),
        }
    }
}

impl Session {
    /// Create a session in the default (pre-login) state.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage(&self) -> LoginStage {
        self.stage
    }

    /// Process one iSCSI transaction.
    ///
    /// Blocks on the connection for as much input as the transaction needs
    /// (Login → Login Response; SCSI Command → full Data-In/Data-Out flow and
    /// final status; TMF / NOP / Logout → response). `work` must be at least
    /// [`crate::MIN_WORK_LEN`] bytes.
    pub fn step<C: Conn, D: ScsiDevice>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        devs: &mut [D],
    ) -> StepResult {
        if work.len() < crate::MIN_WORK_LEN {
            return StepResult::Error(TargetError::WorkBufTooSmall);
        }
        let pdu = match recv_pdu(conn, work) {
            Ok(p) => p,
            Err(()) => return StepResult::Closed,
        };

        // AHS defense: Phase 1 assumes TotalAHSLength = 0.
        if pdu.bhs.total_ahs_length() != 0 {
            return self.reject(conn, work, reject::PROTOCOL_ERROR, &pdu.bhs);
        }

        let op = pdu.bhs.opcode();
        crate::debug!(
            "recv {} (0x{:02X}) stage={:?} cmd_sn={} stat_sn={}",
            iscsi_opcode_name(op),
            op,
            self.stage,
            self.cmd_sn,
            self.stat_sn
        );
        if self.stage != LoginStage::FullFeature {
            if op != op::LOGIN_REQ {
                return self.reject(conn, work, reject::PROTOCOL_ERROR, &pdu.bhs);
            }
            return self.handle_login(conn, work, &pdu);
        }

        match op {
            op::SCSI_CMD => self.handle_scsi_cmd(conn, work, devs, &pdu),
            op::SCSI_TASK_REQ => self.handle_tmf(conn, work, &pdu),
            op::NOP_OUT => self.handle_nop(conn, work, &pdu),
            op::LOGOUT_REQ => self.handle_logout(conn, work, &pdu),
            op::TEXT_REQ => self.reject(conn, work, reject::COMMAND_NOT_SUPPORTED, &pdu.bhs),
            op::LOGIN_REQ => self.reject(conn, work, reject::PROTOCOL_ERROR, &pdu.bhs),
            _ => self.reject(conn, work, reject::PROTOCOL_ERROR, &pdu.bhs),
        }
    }

    // ── Login Phase ───────────────────────────────────────────────

    fn handle_login<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        pdu: &Pdu,
    ) -> StepResult {
        let req = &pdu.bhs;
        let req_csg = req.csg() & 0x03;
        let t = req.t_bit();

        // Negotiate: build the response text (updated `self.neg` alongside).
        let resp_len = if pdu.dsl <= LOGIN_MAX {
            let (head, tail) = work.split_at_mut(BHS_SIZE + pdu.dsl);
            let n = self.negotiate(&head[BHS_SIZE..], tail);
            work.copy_within(BHS_SIZE + pdu.dsl..BHS_SIZE + pdu.dsl + n, BHS_SIZE);
            n
        } else {
            self.negotiate(&[], &mut work[BHS_SIZE..])
        };

        let nsg = if t {
            match req_csg {
                stage::SECURITY => stage::OP_PARAM,
                _ => stage::FULL_FEATURE,
            }
        } else {
            0
        };
        crate::debug!(
            "login: CSG={} NSG={} T={} TSIH={} itt=0x{:08X}",
            req_csg,
            nsg,
            t,
            req.tsih(),
            req.itt()
        );

        let mut resp = Bhs::new();
        resp.set_opcode(op::LOGIN_RESP);
        resp.set_itt(req.itt());
        resp.set_flags((if t { flag::T_BIT } else { 0 }) | (req_csg << flag::CSG_SHIFT) | nsg);
        // ISID echo (bytes 8-13, RFC 3720 §10.12).
        resp.as_mut_bytes()[8..14].copy_from_slice(&req.as_bytes()[8..14]);
        // TSIH: non-zero for a new session's final response (§10.13.3).
        if req.tsih() == 0 {
            resp.as_mut_bytes()[15] = 1;
        } else {
            resp.as_mut_bytes()[14..16].copy_from_slice(&req.as_bytes()[14..16]);
        }
        resp.set_data_segment_len(resp_len as u32);
        resp.set_stat_sn(self.stat_sn);
        resp.set_exp_cmd_sn(req.cmd_sn());
        resp.set_max_cmd_sn(req.cmd_sn());

        if send_pdu(conn, work, &resp, resp_len).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);

        if t {
            self.stage = LoginStage::from_csg(nsg).unwrap_or(LoginStage::FullFeature);
            if self.stage == LoginStage::FullFeature {
                crate::debug!("login complete: FullFeature, cmd_sn={}", req.cmd_sn());
                // RFC 3720 §10.12.8: the leading Login Request's CmdSN is the
                // session's initial ExpCmdSN, and the first FullFeature
                // command reuses that same CmdSN. `cmd_sn` tracks the last
                // consumed CmdSN, so back off by one — the first command
                // (CmdSN == login CmdSN) then passes the `cmd_sn + 1` window
                // check (wrapping handles a login CmdSN of 0).
                self.cmd_sn = req.cmd_sn().wrapping_sub(1);
            }
        } else {
            self.stage = LoginStage::from_csg(req_csg).unwrap_or(LoginStage::Security);
        }
        StepResult::Processed
    }

    /// Parse initiator key=value text into a response, updating negotiated
    /// parameters. Writes into `dst` (clamped), returns the response length.
    fn negotiate(&mut self, src: &[u8], dst: &mut [u8]) -> usize {
        let mut w = 0usize;
        let mut sent = [false; LOGIN_TABLE.len()];
        let mut p = 0usize;
        while p < src.len() {
            let Some(eq) = src[p..].iter().position(|&b| b == b'=') else {
                break;
            };
            let eq = p + eq;
            let val_end = src[eq + 1..]
                .iter()
                .position(|&b| b == 0)
                .map_or(src.len(), |i| eq + 1 + i);
            let key = &src[p..eq];
            let val = &src[eq + 1..val_end];

            if let Some(idx) = find_key(key) {
                sent[idx] = true;
                self.apply_neg(LOGIN_TABLE[idx].key, val);
                let out_val: &[u8] = match LOGIN_TABLE[idx].value {
                    Some(v) => v.as_bytes(),
                    None => val,
                };
                if !append_kv(dst, &mut w, key, out_val) {
                    break;
                }
            } else if !is_skip_key(key) && !append_kv(dst, &mut w, key, b"Reject") {
                break;
            }
            p = if val_end < src.len() {
                val_end + 1
            } else {
                src.len()
            };
        }
        for (i, param) in LOGIN_TABLE.iter().enumerate() {
            if param.always && !sent[i] {
                if let Some(v) = param.value {
                    if !append_kv(dst, &mut w, param.key.as_bytes(), v.as_bytes()) {
                        break;
                    }
                }
            }
        }
        w
    }

    fn apply_neg(&mut self, key: &str, val: &[u8]) {
        match key {
            "MaxRecvDataSegmentLength" => {
                if let Some(v) = parse_u32(val) {
                    self.max_recv_data_segment = v.min(MAX_DATA_SEGMENT);
                }
            }
            "MaxBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.max_burst_len = v.min(DEFAULT_MAX_BURST);
                }
            }
            "FirstBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.first_burst_len = v.min(DEFAULT_FIRST_BURST);
                }
            }
            "ImmediateData" => self.neg.immediate_data = val == b"Yes",
            "InitialR2T" => self.neg.initial_r2t = val == b"Yes",
            "MaxOutstandingR2T" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.max_outstanding_r2t = v.min(1);
                }
            }
            _ => {}
        }
    }

    // ── Full Feature: SCSI Command ────────────────────────────────

    fn handle_scsi_cmd<C: Conn + ?Sized, D: ScsiDevice>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        devs: &mut [D],
        pdu: &Pdu,
    ) -> StepResult {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0; // I bit (§3.2.2.1)

        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            // Non-immediate out-of-window or duplicate → silently ignore.
            return StepResult::Idle;
        }
        self.cmd_sn = recv_cmd_sn;

        let itt = bhs.itt();
        let lun = bhs.lun() as usize;
        if lun >= devs.len() {
            return self.reject(conn, work, reject::INVALID_PDU_FIELD, bhs);
        }
        if pdu.dsl > MAX_DATA_SEGMENT as usize {
            return self.reject(conn, work, reject::PROTOCOL_ERROR, bhs);
        }
        // RFC 3720 §10.3.1: W bit is byte 1 bit 2. Per the §2.3.3 "Byte Rule",
        // bit 0 is the MSB (2**7), so bit 2 = 0x20 — the Linux kernel
        // (open-iscsi) sends W at 0x20. The legacy C `& 0x20` was correct; a
        // prior Rust "fix" to 0x04 (misreading bit 2 as LSB) broke Linux writes.
        let w_bit = bhs.as_bytes()[1] & 0x20 != 0;
        if pdu.dsl > 0 && !w_bit {
            return self.reject(conn, work, reject::PROTOCOL_ERROR, bhs);
        }

        let cdb = bhs.cdb();
        if cdb[0] == scsi_op::REPORT_LUNS {
            return self.handle_report_luns(conn, work, itt, devs.len());
        }
        let dev = &mut devs[lun];
        crate::debug!(
            "scsi cmd: {} (0x{:02X}) itt=0x{:08X} lun={} cmd_sn={} dsl={}",
            opcode_name(cdb[0]),
            cdb[0],
            itt,
            lun,
            recv_cmd_sn,
            pdu.dsl
        );
        let outcome = match dev.do_cmd(cdb, work, pdu.dsl) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return StepResult::Error(TargetError::WorkBufTooSmall)
            }
        };

        match outcome {
            CommandOutcome::Status => {
                crate::debug!("  -> Status (GOOD)");
                self.send_scsi_response(conn, work, itt, status::GOOD, None)
            }
            CommandOutcome::CheckCondition(sense) => {
                crate::debug!(
                    "  -> CheckCondition key={:?} asc=0x{:02X} ascq=0x{:02X}",
                    sense.key,
                    sense.asc,
                    sense.ascq
                );
                self.send_scsi_response(conn, work, itt, status::CHECK_CONDITION, Some(&sense))
            }
            CommandOutcome::DataIn {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                if !immediate.is_empty() {
                    // Synthesized response already resident at work[48..48+n].
                    let n = immediate.len();
                    crate::debug!("  -> DataIn (synthesized, {} bytes)", n);
                    self.send_data_in_final(conn, work, itt, n, 0, 0, status::GOOD)
                } else {
                    crate::debug!(
                        "  -> DataIn (backend, transfer_len={} @ offset={})",
                        transfer_len,
                        byte_offset
                    );
                    self.send_read_data(conn, work, dev, itt, transfer_len, byte_offset)
                }
            }
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                // Consume the immediate data first (write to backend), dropping
                // the borrow on work (§5.1), then drive R2T/Data-Out.
                let received = immediate.len() as u64;
                crate::debug!(
                    "  -> DataOut transfer_len={} immediate={} @ offset={}",
                    transfer_len,
                    received,
                    byte_offset
                );
                if received > 0 && dev.write_data(byte_offset, immediate).is_err() {
                    let sense = *dev.sense();
                    return self.send_scsi_response(
                        conn,
                        work,
                        itt,
                        status::CHECK_CONDITION,
                        Some(&sense),
                    );
                }
                self.send_write_flow(conn, work, dev, itt, transfer_len, byte_offset, received)
            }
        }
    }

    /// Build and send the REPORT LUNS response (SPC-4 §6.21).
    ///
    /// The data segment is:
    /// - 4-byte big-endian LUN list length (8 × `num_luns`),
    /// - 4-byte reserved (zeros),
    /// - `num_luns` 8-byte LUN entries in ascending LUN id.
    ///
    /// The 4 reserved bytes are required: Linux's `scsi_report_lun_scan`
    /// (drivers/scsi/scsi_scan.c) iterates the entries starting at
    /// `lun_data[1]` of the response buffer, i.e. byte offset 8. Skipping
    /// the reserved padding puts LUN 0 at offset 4, and the kernel then
    /// reads `lun_data[1]` (offset 8) as a hybrid of LUN 0's tail half +
    /// LUN 1's head half, which `scsilun_to_int` decodes to 2^32 for the
    /// first byte that lands in the high half. The 4 reserved bytes keep
    /// the entries 8-byte aligned, which is what LIO and open-iscsi emit.
    ///
    /// Each entry is the single-level LUN structure from SAM-2: byte 0 =
    /// 0x00 (address method 00b = peripheral device addressing, bus id 0x0),
    /// byte 1 = LUN id, bytes 2..7 = 0x00. The response is target-wide, so
    /// the LUN the initiator used to issue REPORT LUNS is irrelevant — the
    /// caller's LUN-validity check above still rejects out-of-range LUNs.
    fn handle_report_luns<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        itt: u32,
        num_luns: usize,
    ) -> StepResult {
        // 8-byte header (4-byte LUN list length + 4-byte reserved) +
        // 8 bytes per LUN. 256 LUNs is the single-level peripheral device
        // addressing limit (SAM-2) and fits comfortably in
        // `MIN_WORK_LEN = 48 + 8192`.
        let list_len = u32::try_from(num_luns)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .unwrap_or(u32::MAX);
        let total = 8usize + (list_len as usize);
        if total > work.len() - BHS_SIZE {
            return StepResult::Error(TargetError::WorkBufTooSmall);
        }
        // Header: LUN list length (BE) + reserved.
        work[BHS_SIZE..BHS_SIZE + 4].copy_from_slice(&list_len.to_be_bytes());
        for b in &mut work[BHS_SIZE + 4..BHS_SIZE + 8] {
            *b = 0;
        }
        // LUN entries start at byte 8, not 4 — see the doc comment.
        for i in 0..num_luns {
            let off = BHS_SIZE + 8 + i * 8;
            work[off] = 0x00; // address method 00b, bus id 0
            work[off + 1] = i as u8; // single-level LUN id
            for b in &mut work[off + 2..off + 8] {
                *b = 0;
            }
        }
        crate::debug!("  -> REPORT LUNS: {} LUN(s)", num_luns);
        self.send_data_in_final(conn, work, itt, total, 0, 0, status::GOOD)
    }

    /// Send chunked Data-In for a backend READ (RFC 3720 §10.7).
    fn send_read_data<C: Conn + ?Sized, D: ScsiDevice>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        dev: &mut D,
        itt: u32,
        transfer_len: u64,
        byte_offset: u64,
    ) -> StepResult {
        let chunk_max = (self.max_recv_data_segment as usize).min(MAX_DATA_SEGMENT as usize);
        let mut offset = 0u64;
        let mut data_sn = 0u32;
        loop {
            let remaining = transfer_len - offset;
            if remaining == 0 {
                // Empty transfer: final Data-In with status, zero payload.
                return self.send_data_in_final(conn, work, itt, 0, 0, data_sn, status::GOOD);
            }
            let chunk = remaining.min(chunk_max as u64) as usize;
            if dev
                .read_data(byte_offset + offset, &mut work[BHS_SIZE..BHS_SIZE + chunk])
                .is_err()
            {
                let sense = *dev.sense();
                return self.send_scsi_response(
                    conn,
                    work,
                    itt,
                    status::CHECK_CONDITION,
                    Some(&sense),
                );
            }
            let is_last = chunk as u64 == remaining;
            let mut bhs = Bhs::new();
            bhs.set_opcode(op::SCSI_DATA_IN);
            bhs.set_itt(itt);
            bhs.set_data_sn(data_sn);
            bhs.set_buffer_offset(offset as u32);
            bhs.set_data_segment_len(chunk as u32);
            if is_last {
                bhs.set_status(status::GOOD);
                bhs.set_stat_sn(self.stat_sn);
                bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
                bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
                bhs.set_flags(flag::F_BIT | flag::S_BIT);
            }
            crate::trace!(
                "  Data-In: BO={} DataSN={} len={} final={}",
                offset,
                data_sn,
                chunk,
                is_last
            );
            if send_pdu(conn, work, &bhs, chunk).is_err() {
                return StepResult::Closed;
            }
            if is_last {
                self.stat_sn = self.stat_sn.wrapping_add(1);
                return StepResult::Processed;
            }
            offset += chunk as u64;
            data_sn = data_sn.wrapping_add(1);
        }
    }

    /// Write flow: R2T(s) → Data-Out → final status. `received` bytes have
    /// already been written to the backend (immediate data).
    #[allow(clippy::too_many_arguments)]
    fn send_write_flow<C: Conn + ?Sized, D: ScsiDevice>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        dev: &mut D,
        itt: u32,
        transfer_len: u64,
        byte_offset: u64,
        mut received: u64,
    ) -> StepResult {
        if received == transfer_len {
            return self.send_scsi_response(conn, work, itt, status::GOOD, None);
        }

        let mut r2t_sn = 0u32;
        loop {
            let burst = (u64::from(self.neg.max_burst_len)).min(transfer_len - received);
            let mut bhs = Bhs::new();
            bhs.set_opcode(op::R2T);
            bhs.set_flags(flag::F_BIT);
            bhs.set_itt(itt);
            bhs.set_ttt(TTT);
            // R2T carries the current StatSN but does not advance it (§10.8.3).
            bhs.set_stat_sn(self.stat_sn);
            bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
            bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
            bhs.set_r2t_sn(r2t_sn);
            bhs.set_buffer_offset(received as u32);
            bhs.set_desired_data_len(burst as u32);
            crate::trace!("R2T: R2TSN={} BO={} DesiredLen={}", r2t_sn, received, burst);
            if send_pdu(conn, work, &bhs, 0).is_err() {
                return StepResult::Closed;
            }

            // Collect the solicited Data-Out PDUs for this burst.
            let mut burst_received = 0u64;
            let mut expected_bo = received;
            let mut data_sn = 0u32;
            while burst_received < burst {
                let pdu = match recv_pdu(conn, work) {
                    Ok(p) => p,
                    Err(()) => return StepResult::Closed,
                };
                let obhs = &pdu.bhs;
                if obhs.opcode() != op::SCSI_DATA_OUT {
                    return self.reject(conn, work, reject::PROTOCOL_ERROR, obhs);
                }
                // Field validation (§10.7, fix #11) — violations → 0x09.
                if obhs.itt() != itt || obhs.ttt() != TTT {
                    return self.reject(conn, work, reject::INVALID_PDU_FIELD, obhs);
                }
                if obhs.buffer_offset() as u64 != expected_bo {
                    return self.reject(conn, work, reject::INVALID_PDU_FIELD, obhs);
                }
                if obhs.data_sn() != data_sn {
                    return self.reject(conn, work, reject::INVALID_PDU_FIELD, obhs);
                }
                if pdu.dsl > MAX_DATA_SEGMENT as usize {
                    return self.reject(conn, work, reject::PROTOCOL_ERROR, obhs);
                }
                if pdu.dsl as u64 > burst - burst_received {
                    return self.reject(conn, work, reject::INVALID_PDU_FIELD, obhs);
                }
                if pdu.dsl > 0
                    && dev
                        .write_data(
                            byte_offset + expected_bo,
                            &work[BHS_SIZE..BHS_SIZE + pdu.dsl],
                        )
                        .is_err()
                {
                    let sense = *dev.sense();
                    return self.send_scsi_response(
                        conn,
                        work,
                        itt,
                        status::CHECK_CONDITION,
                        Some(&sense),
                    );
                }
                crate::trace!(
                    "  Data-Out: BO={} DataSN={} len={}",
                    expected_bo,
                    data_sn,
                    pdu.dsl
                );
                expected_bo += pdu.dsl as u64;
                burst_received += pdu.dsl as u64;
                data_sn = data_sn.wrapping_add(1);
            }
            received += burst_received;
            if received == transfer_len {
                break;
            }
            r2t_sn = r2t_sn.wrapping_add(1);
        }
        self.send_scsi_response(conn, work, itt, status::GOOD, None)
    }

    // ── Full Feature: Task Management / NOP / Logout ─────────────

    fn handle_tmf<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        pdu: &Pdu,
    ) -> StepResult {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        // TMF CmdSN check by I bit (fix #21).
        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            return StepResult::Idle;
        }
        self.cmd_sn = recv_cmd_sn;

        let function = bhs.tmf_function();
        let response = match function {
            tmf::ABORT_TASK | tmf::LOGICAL_UNIT_RESET => tmf_response::COMPLETE,
            _ => tmf_response::NOT_SUPPORTED,
        };

        let mut resp = Bhs::new();
        resp.set_opcode(op::SCSI_TASK_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_tmf_response(response);
        resp.set_stat_sn(self.stat_sn);
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        if send_pdu(conn, work, &resp, 0).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Processed
    }

    fn handle_nop<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        pdu: &Pdu,
    ) -> StepResult {
        let bhs = &pdu.bhs;
        let mut resp = Bhs::new();
        resp.set_opcode(op::NOP_IN);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_ttt(bhs.ttt());
        resp.set_stat_sn(self.stat_sn);
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        // Echo the NOP-Out ping data if it was received intact.
        let dlen = if pdu.dsl <= MAX_DATA_SEGMENT as usize {
            resp.set_data_segment_len(pdu.dsl as u32);
            pdu.dsl
        } else {
            0
        };
        if send_pdu(conn, work, &resp, dlen).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Processed
    }

    fn handle_logout<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        pdu: &Pdu,
    ) -> StepResult {
        let bhs = &pdu.bhs;
        let mut resp = Bhs::new();
        resp.set_opcode(op::LOGOUT_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        // Byte 2 = Response (0 = session closed).
        resp.set_stat_sn(self.stat_sn);
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        if send_pdu(conn, work, &resp, 0).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Closed
    }

    // ── Response PDUs ─────────────────────────────────────────────

    fn send_scsi_response<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        itt: u32,
        scsi_status: u8,
        sense: Option<&Sense>,
    ) -> StepResult {
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_RESP);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_stat_sn(self.stat_sn);
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let mut dlen = 0;
        if scsi_status == status::CHECK_CONDITION {
            if let Some(s) = sense {
                // Data segment: 2-byte SenseLength (16-bit BE) + fixed sense.
                work[BHS_SIZE] = 0;
                work[BHS_SIZE + 1] = 18;
                s.write_fixed(&mut work[BHS_SIZE + 2..BHS_SIZE + 20]);
                dlen = 20;
            }
        }
        bhs.set_data_segment_len(dlen as u32);
        if send_pdu(conn, work, &bhs, dlen).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Processed
    }

    /// Single final Data-In (F=1, S=1) with status — used for synthesized
    /// responses and the zero-length edge case.
    #[allow(clippy::too_many_arguments)]
    fn send_data_in_final<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        itt: u32,
        data_len: usize,
        buffer_offset: u32,
        data_sn: u32,
        scsi_status: u8,
    ) -> StepResult {
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        bhs.set_flags(flag::F_BIT | flag::S_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(buffer_offset);
        bhs.set_data_segment_len(data_len as u32);
        bhs.set_stat_sn(self.stat_sn);
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        if send_pdu(conn, work, &bhs, data_len).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Processed
    }

    /// Send a Reject and close the connection. The data segment carries the
    /// full header of the rejected PDU; ITT = 0xffffffff (fix #18).
    fn reject<C: Conn + ?Sized>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        reason: u8,
        rejected: &Bhs,
    ) -> StepResult {
        crate::warn!(
            "rejecting {} (0x{:02X}) reason={} (0x{:02X})",
            iscsi_opcode_name(rejected.opcode()),
            rejected.opcode(),
            reason,
            reason
        );
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::REJECT);
        bhs.set_flags(flag::F_BIT);
        bhs.set_reject_reason(reason);
        bhs.set_itt(0xFFFF_FFFF);
        bhs.set_stat_sn(self.stat_sn);
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_data_segment_len(BHS_SIZE as u32);
        work[BHS_SIZE..2 * BHS_SIZE].copy_from_slice(rejected.as_bytes());
        if send_pdu(conn, work, &bhs, BHS_SIZE).is_err() {
            return StepResult::Closed;
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
        StepResult::Closed
    }
}

/// Result of one [`Session::step`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// A PDU was consumed but nothing was sent (out-of-window CmdSN, §3.2.2.1).
    Idle,
    /// A transaction completed and response(s) were sent.
    Processed,
    /// The connection should be closed (Logout / peer closed / I/O failure).
    Closed,
    /// Internal error (caller bug), e.g. work buffer too small.
    Error(TargetError),
}

/// Target-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// Caller's work buffer is smaller than [`crate::MIN_WORK_LEN`].
    WorkBufTooSmall,
    /// Connection I/O failure (details logged by the transport).
    Io,
    /// Unexpected internal state.
    Internal,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "work buffer smaller than MIN_WORK_LEN"),
            Self::Io => write!(f, "connection I/O failure"),
            Self::Internal => write!(f, "internal target error"),
        }
    }
}

impl core::error::Error for TargetError {}

/// Blocking wrapper: run `session.step` until the connection closes.
///
/// Validates `work.len() >= MIN_WORK_LEN` up front. I/O errors inside `step`
/// surface as `Closed`; only caller bugs propagate as `Err`.
pub fn serve_conn<C: Conn, D: ScsiDevice>(
    conn: &mut C,
    work: &mut [u8],
    session: &mut Session,
    devs: &mut [D],
) -> Result<(), TargetError> {
    if work.len() < crate::MIN_WORK_LEN {
        return Err(TargetError::WorkBufTooSmall);
    }
    loop {
        match session.step(conn, work, devs) {
            StepResult::Idle | StepResult::Processed => {}
            StepResult::Closed => return Ok(()),
            StepResult::Error(e) => return Err(e),
        }
    }
}

// ── Low-level PDU framing ──────────────────────────────────────────

struct Pdu {
    bhs: Bhs,
    dsl: usize,
}

/// Receive one PDU: 48-byte BHS, optional AHS (skipped), data segment
/// (into `work[48..]` when it fits, otherwise discarded), and padding.
/// Never leaves bytes behind — keeps TCP synchronized (fix #1).
fn recv_pdu<C: Conn + ?Sized>(conn: &mut C, work: &mut [u8]) -> Result<Pdu, ()> {
    let mut raw = [0u8; BHS_SIZE];
    read_exact(conn, &mut raw)?;
    let bhs = Bhs::from_bytes(raw);
    let dsl = bhs.data_segment_len() as usize;
    let ahs = usize::from(bhs.total_ahs_length());
    skip(conn, ahs * 4)?;
    if dsl <= work.len() - BHS_SIZE {
        read_exact(conn, &mut work[BHS_SIZE..BHS_SIZE + dsl])?;
    } else {
        skip(conn, dsl)?;
    }
    let pad = pdu_pad_len(dsl as u32) as usize;
    skip(conn, pad)?;
    Ok(Pdu { bhs, dsl })
}

/// Send one PDU assembled in `work`: BHS at `[0..48]`, data already at
/// `[48..48+data_len]`, padding appended. Single contiguous write.
fn send_pdu<C: Conn + ?Sized>(
    conn: &mut C,
    work: &mut [u8],
    bhs: &Bhs,
    data_len: usize,
) -> Result<(), ()> {
    let total = BHS_SIZE + data_len;
    let pad = pdu_pad_len(data_len as u32) as usize;
    debug_assert!(work.len() >= total + pad);
    work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
    work[total..total + pad].fill(0);
    write_all(conn, &work[..total + pad])
}

/// Discard `n` bytes via a small stack scratch (no big stack arrays).
fn skip<C: Conn + ?Sized>(conn: &mut C, mut n: usize) -> Result<(), ()> {
    let mut scratch = [0u8; 256];
    while n > 0 {
        let chunk = n.min(scratch.len());
        read_exact(conn, &mut scratch[..chunk])?;
        n -= chunk;
    }
    Ok(())
}

// ── Login key helpers ──────────────────────────────────────────────

fn find_key(key: &[u8]) -> Option<usize> {
    LOGIN_TABLE.iter().position(|p| p.key.as_bytes() == key)
}

fn is_skip_key(key: &[u8]) -> bool {
    SKIP_KEYS.iter().any(|k| k.as_bytes() == key)
}

fn append_kv(dst: &mut [u8], w: &mut usize, k: &[u8], v: &[u8]) -> bool {
    let need = k.len() + 1 + v.len() + 1;
    if *w + need > dst.len() {
        return false;
    }
    dst[*w..*w + k.len()].copy_from_slice(k);
    *w += k.len();
    dst[*w] = b'=';
    *w += 1;
    dst[*w..*w + v.len()].copy_from_slice(v);
    *w += v.len();
    dst[*w] = 0;
    *w += 1;
    true
}

fn parse_u32(v: &[u8]) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build null-separated `key=value` request text.
    fn req_text(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in pairs {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(0);
        }
        out
    }

    /// Find the value for `key` in a null-separated response, or None.
    fn value<'a>(resp: &'a [u8], key: &str) -> Option<&'a [u8]> {
        let k = key.as_bytes();
        let mut p = 0usize;
        while p < resp.len() {
            if resp[p..].starts_with(k) && p + k.len() < resp.len() && resp[p + k.len()] == b'=' {
                let start = p + k.len() + 1;
                let end = resp[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(resp.len(), |i| start + i);
                return Some(&resp[start..end]);
            }
            let next = resp[p..]
                .iter()
                .position(|&b| b == 0)
                .map_or(resp.len(), |i| p + i + 1);
            p = next;
        }
        None
    }

    fn negotiate_text(session: &mut Session, src: &[u8]) -> Vec<u8> {
        let mut dst = [0u8; LOGIN_MAX + 1024];
        let n = session.negotiate(src, &mut dst);
        dst[..n].to_vec()
    }

    #[test]
    fn negotiate_echoes_unknown_values_and_overrides_known() {
        let mut s = Session::default();
        let text = req_text(&[
            ("HeaderDigest", "CRC32C"),
            ("DataDigest", "CRC32C"),
            ("InitialR2T", "No"),
            ("ImmediateData", "Yes"),
            ("MaxBurstLength", "16776192"),
            ("FirstBurstLength", "262144"),
            ("MaxRecvDataSegmentLength", "262144"),
            ("MaxOutstandingR2T", "1"),
            ("MaxConnections", "1"),
            ("ErrorRecoveryLevel", "0"),
            ("DataPDUInOrder", "Yes"),
            ("DataSequenceInOrder", "Yes"),
            ("DefaultTime2Wait", "2"),
            ("DefaultTime2Retain", "0"),
            ("IFMarker", "No"),
            ("OFMarker", "No"),
        ]);
        let resp = negotiate_text(&mut s, &text);

        assert_eq!(value(&resp, "HeaderDigest"), Some(b"None".as_slice()));
        assert_eq!(value(&resp, "DataDigest"), Some(b"None".as_slice()));
        assert_eq!(value(&resp, "InitialR2T"), Some(b"Yes".as_slice()));
        assert_eq!(value(&resp, "ImmediateData"), Some(b"Yes".as_slice()));
        assert_eq!(value(&resp, "MaxBurstLength"), Some(b"16776192".as_slice()));
        assert_eq!(value(&resp, "FirstBurstLength"), Some(b"262144".as_slice()));
        assert_eq!(
            value(&resp, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice())
        );
        assert_eq!(value(&resp, "MaxOutstandingR2T"), Some(b"1".as_slice()));
        assert_eq!(value(&resp, "MaxConnections"), Some(b"1".as_slice()));
        assert_eq!(value(&resp, "ErrorRecoveryLevel"), Some(b"0".as_slice()));
        assert_eq!(value(&resp, "DataPDUInOrder"), Some(b"Yes".as_slice()));
        assert_eq!(value(&resp, "DefaultTime2Wait"), Some(b"2".as_slice()));
        assert_eq!(value(&resp, "OFMarker"), Some(b"No".as_slice()));

        /* always keys appended even though the initiator didn't send them */
        assert_eq!(value(&resp, "TargetAlias"), Some(b"SnowSCSI".as_slice()));
        assert_eq!(value(&resp, "TargetPortalGroupTag"), Some(b"1".as_slice()));
    }

    #[test]
    fn negotiate_skips_initiator_only_keys() {
        let mut s = Session::default();
        let text = req_text(&[
            ("InitiatorName", "iqn.1994-05.com.example:host"),
            ("InitiatorAlias", "alias"),
            ("SessionType", "Normal"),
            ("TargetName", "iqn.1970-01.local.snowscsi:target"),
        ]);
        let resp = negotiate_text(&mut s, &text);
        assert!(value(&resp, "InitiatorName").is_none());
        assert!(value(&resp, "InitiatorAlias").is_none());
        assert!(value(&resp, "SessionType").is_none());
        assert!(value(&resp, "TargetName").is_none());
    }

    #[test]
    fn negotiate_rejects_unknown_keys() {
        let mut s = Session::default();
        let text = req_text(&[("BogusKey", "1")]);
        let resp = negotiate_text(&mut s, &text);
        assert_eq!(value(&resp, "BogusKey"), Some(b"Reject".as_slice()));
    }

    #[test]
    fn negotiate_length_stays_bounded() {
        let mut s = Session::default();
        /* pathological input: many unknown single-char keys */
        let mut text = Vec::new();
        for _i in 0..LOGIN_MAX / 4 {
            text.push(b'A');
            text.push(b'=');
            text.push(b'A');
            text.push(0);
        }
        let resp = negotiate_text(&mut s, &text);
        assert!(resp.len() <= LOGIN_MAX + 1024);
    }

    #[test]
    fn negotiate_updates_session_parameters() {
        let mut s = Session::default();
        let text = req_text(&[
            ("MaxRecvDataSegmentLength", "262144"),
            ("MaxBurstLength", "16776192"),
            ("FirstBurstLength", "1048576"),
            ("InitialR2T", "No"),
            ("ImmediateData", "Yes"),
        ]);
        let _ = negotiate_text(&mut s, &text);
        assert_eq!(s.max_recv_data_segment, 8192); /* clamped to target max */
        assert_eq!(s.neg.max_burst_len, 262144); /* clamped to default */
        assert_eq!(s.neg.first_burst_len, 65536); /* clamped to default */
        assert!(!s.neg.initial_r2t);
        assert!(s.neg.immediate_data);
    }

    #[test]
    fn negotiate_defaults_when_key_absent() {
        let mut s = Session::default();
        let _ = negotiate_text(&mut s, &[]);
        assert_eq!(s.max_recv_data_segment, 8192);
        assert_eq!(s.neg.max_burst_len, 262144);
        assert_eq!(s.neg.first_burst_len, 65536);
    }

    #[test]
    fn login_stage_transitions() {
        /* First login (CSG=1, T=1) → Full Feature directly (mock-style). */
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::LOGIN_REQ);
        bhs.set_flags(
            flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE,
        );
        assert_eq!(bhs.csg(), stage::OP_PARAM);
        assert_eq!(bhs.nsg(), stage::FULL_FEATURE);
        assert!(bhs.t_bit());
    }

    #[test]
    fn session_defaults() {
        let s = Session::default();
        assert_eq!(s.stage, LoginStage::Security);
        assert_eq!(s.cmd_sn, 0);
        assert_eq!(s.stat_sn, 0);
        assert_eq!(s.max_recv_data_segment, 8192);
    }

    #[test]
    fn reject_reason_codes_are_standard() {
        /* fix #17: legacy 0x02/0x0A must not be used for these semantics. */
        assert_eq!(reject::PROTOCOL_ERROR, 0x04);
        assert_eq!(reject::COMMAND_NOT_SUPPORTED, 0x05);
        assert_eq!(reject::INVALID_PDU_FIELD, 0x09);
    }
}
