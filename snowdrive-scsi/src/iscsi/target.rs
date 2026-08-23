//! iSCSI target protocol state machine (RFC 3720 §5 / §10).
//!
//! [`IscsiSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O.  A driver feeds one
//! [`SessionEvent::PduReceived`] per [`IscsiSession::poll`] call and learns the
//! next need from the returned [`SessionStep`].  The blocking
//! [`IscsiSession::step`] wrapper drives the same state machine over a `Conn`.
//!
//! Key fixes over the legacy C implementation: CID read at
//! byte 20-21 (from iscsi_pdu), Data-Out ITT/TTT/BufferOffset/DataSN
//! validation with Reject 0x09 (#11), TMF CmdSN check by I bit (#21),
//! out-of-window/duplicate CmdSN silently ignored (#17), Reject carries
//! the rejected PDU header + ITT=0xffffffff (#18), and read-timeout
//! coverage is delegated to the `Conn` implementation (#10/#20).

use core::cell::Cell;

use crate::iscsi::conn::{read_exact, write_all, Conn};
use crate::iscsi::pdu::{
    flag, iscsi_opcode_name, op, pdu_pad_len, reject, stage, status, tmf, tmf_response, Bhs,
    BHS_SIZE, MAX_DATA_SEGMENT,
};
use crate::scsi::device::{CommandOutcome, ScsiDevice, XferOutcome};
use crate::scsi::scsi::op as scsi_op;
use crate::scsi::scsi::{asc, opcode_from_cdb, opcode_name, Sense, SenseKey};

// ── Public types ─────────────────────────────────────────────────────

/// One event fed from the driver to [`IscsiSession::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// A complete iSCSI PDU has been received into the work buffer.
    /// `dsl` is the data-segment length (from the BHS header).
    PduReceived { dsl: u32 },
}

/// The core's next need, returned by [`IscsiSession::poll`].
///
/// `NeedSend` borrows the work buffer; the driver must consume (send) the
/// slice before calling `poll` again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStep<'a> {
    /// Receive the next complete PDU from the wire into the work buffer.
    NeedRecv,
    /// Send `data` to the wire (a complete PDU: BHS + optional data +
    /// padding).  `data` borrows the work buffer.
    NeedSend(&'a [u8]),
    /// The transaction completed and the connection should be closed
    /// (Logout response sent, peer closed, or fatal I/O error).
    Closed,
    /// An internal error (caller bug) — work buffer too small, etc.
    Error(TargetError),
}

/// Result of one [`IscsiSession::step`] call.
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
    /// Caller's work buffer is smaller than [`crate::MIN_DATA_LEN`] +
    /// `BHS_SIZE` (data area too small for the SCSI layer).
    WorkBufTooSmall,
    /// Connection I/O failure (details logged by the transport).
    Io,
    /// Unexpected internal state.
    Internal,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "work buffer smaller than MIN_DATA_LEN + BHS_SIZE"),
            Self::Io => write!(f, "connection I/O failure"),
            Self::Internal => write!(f, "internal target error"),
        }
    }
}

impl core::error::Error for TargetError {}

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

/// Negotiated login parameters (RFC 3720 §10.12-.14).
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

// ── Private constants ───────────────────────────────────────────────

/// Target Transfer Tag for R2T — single outstanding transfer.
const TTT: u32 = 1;
/// RFC 3720 §12.14 suggested defaults (clamped when the initiator sends more).
const DEFAULT_FIRST_BURST: u32 = 65536;
const DEFAULT_MAX_BURST: u32 = 262144;
/// Upper bound for the negotiated MaxRecvDataSegmentLength: the BHS
/// DataSegmentLength field is 24 bits (RFC 3720 §3.1).
const HARD_CAP: usize = 0xFF_FFFF;
/// Largest login data segment accepted for negotiation (C `LOGIN_RESP_MAX`).
const LOGIN_MAX: usize = 4096;

// ── Login parameter table ──────────────────────────────────────────

struct LoginParam {
    key: &'static str,
    value: Option<&'static str>,
    always: bool,
}

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
        value: None, // advertised dynamically (buffer-derived, §6.4.1)
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

// ── Session state machine ──────────────────────────────────────────

/// Per-connection iSCSI session state.
///
/// `cmd_sn` is the last consumed CmdSN; non-immediate commands are accepted
/// only when `CmdSN == cmd_sn + 1` (queue depth 1, MaxCmdSN = ExpCmdSN).
pub struct IscsiSession {
    cmd_sn: u32,
    stat_sn: Cell<u32>,
    stage: LoginStage,
    max_recv_data_segment: u32,
    neg: NegotiatedParams,
    state: IscsiState,
}

/// Internal state machine (private).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IscsiState {
    /// Waiting for the next PDU from the initiator.
    RecvPdu,
    /// Data-In phase: sending data to the initiator.
    DataIn {
        transfer_len: u64,
        sent: u64,
        itt: u32,
        chunk: usize,
        lun: usize,
    },
    /// Data-Out phase: receiving data from the initiator via R2T.
    R2tSend {
        itt: u32,
        transfer_len: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        lun: usize,
    },
    /// Collecting Data-Out PDUs for the current R2T burst.
    R2tCollect {
        itt: u32,
        transfer_len: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        expected_bo: u32,
        burst_remaining: u64,
        lun: usize,
    },
    /// Collecting ParamOut data via R2T.
    ParamCollect {
        itt: u32,
        expected: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        expected_bo: u32,
        burst_remaining: u64,
        cdb: [u8; 16],
        cdb_len: usize,
        /// Accumulation offset into work[BHS_SIZE..].
        acc_offset: usize,
        lun: usize,
    },
    /// Stalled after invalid CBW (iSCSI: fatal protocol error).
    /// Only `reset()` or a new connection unfreezes.
    Closed,
}

impl Default for IscsiSession {
    fn default() -> Self {
        Self::new()
    }
}

impl IscsiSession {
    /// Create a session in the default (pre-login) state.
    pub fn new() -> Self {
        crate::info!("new iSCSI session");
        Self {
            cmd_sn: 0,
            stat_sn: Cell::new(0),
            stage: LoginStage::Security,
            max_recv_data_segment: MAX_DATA_SEGMENT,
            neg: NegotiatedParams::default(),
            state: IscsiState::RecvPdu,
        }
    }

    pub fn stage(&self) -> LoginStage {
        self.stage
    }

    // ── Poll interface (non-blocking state machine) ───────────────

    /// Non-blocking state-machine step: consume one event and return the
    /// next need.
    ///
    /// `work` is the PDU scratch buffer (≥ [`crate::MIN_DATA_LEN`] +
    /// `BHS_SIZE`); `devs` is the LUN slice.  During the login phase the
    /// data area is used for parameter negotiation; during Full Feature
    /// it is the CDB/Data-In/Data-Out staging area.
    pub fn poll<'a, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent,
        work: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        match self.state {
            IscsiState::RecvPdu => self.poll_recv(ev, work, devs),
            IscsiState::DataIn { .. } => self.poll_data_in(work, devs),
            IscsiState::R2tSend { .. } => self.poll_r2t_send(work),
            IscsiState::R2tCollect { .. } => self.poll_r2t_collect(ev, work, devs),
            IscsiState::ParamCollect { .. } => self.poll_param_collect(ev, work, devs),
            IscsiState::Closed => SessionStep::Closed,
        }
    }

    /// Blocking convenience wrapper: drive `poll` in a loop over a `Conn`,
    /// processing one complete transaction (Login request/response or
    /// Full Feature SCSI command including data phases and final status).
    ///
    /// `work` must be at least [`crate::MIN_DATA_LEN`] + `BHS_SIZE` bytes.
    /// Blocking convenience wrapper: process one complete iSCSI transaction
    /// (Login or SCSI command including all data phases and final status).
    ///
    /// `work` must be at least [`crate::MIN_DATA_LEN`] + `BHS_SIZE` bytes.
    pub fn step<C: Conn, D: ScsiDevice>(
        &mut self,
        conn: &mut C,
        work: &mut [u8],
        devs: &mut [D],
    ) -> StepResult {
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return StepResult::Error(TargetError::WorkBufTooSmall);
        }
        // Phase 1: receive and process the first PDU.
        match recv_pdu(conn, work) {
            Ok(dsl) => {
                let r = self.poll(SessionEvent::PduReceived { dsl }, work, devs);
                match r {
                    SessionStep::NeedSend(data) => {
                        let len = data.len();

                        let _ = r;
                        if write_all(conn, &work[..len]).is_err() {
                            return StepResult::Closed;
                        }
                        // Only final responses carry StatSN and advance it.
                        // Intermediate Data-In (state stays DataIn) and R2T
                        // (state → R2tCollect) are not final.
                        if matches!(self.state, IscsiState::RecvPdu | IscsiState::Closed) {
                            self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
                        }
                    }
                    SessionStep::NeedRecv => return StepResult::Idle,
                    SessionStep::Closed => return StepResult::Closed,
                    SessionStep::Error(e) => return StepResult::Error(e),
                }
            }
            Err(()) => return StepResult::Closed,
        }
        // Phase 2: drive remaining data phases to completion.
        loop {
            match self.state {
                IscsiState::RecvPdu | IscsiState::Closed => break,
                IscsiState::DataIn { .. } => {
                    // Blocking Data-In: load chunks from backend, write
                    // Data-In BHS per chunk, send over conn.
                    let st = self.state;
                    let IscsiState::DataIn {
                        transfer_len,
                        sent,
                        itt,
                        chunk,
                        lun,
                    } = st
                    else {
                        unreachable!()
                    };
                    let mut data_sn: u32 = 1; // Phase 1 sent DataSN=0
                    let mut offset = sent; // continue from where Phase 1 left off
                    while offset < transfer_len {
                        let remaining = transfer_len - offset;
                        let len = (remaining as usize).min(chunk);
                        if lun < devs.len() {
                            let dev = &mut devs[lun];
                            match dev.xfer_out(offset, &mut work[BHS_SIZE..BHS_SIZE + len]) {
                                XferOutcome::Ok => {}
                                XferOutcome::Error(_) => {
                                    let sense = dev.take_sense();
                                    let r = self.send_scsi_response(
                                        work,
                                        itt,
                                        status::CHECK_CONDITION,
                                        sense.as_ref(),
                                    );
                                    if let SessionStep::NeedSend(data) = r {
                                        let l = data.len();
                                        let _ = r;
                                        let _ = write_all(conn, &work[..l]);
                                    }
                                    return StepResult::Closed;
                                }
                            }
                        }
                        let is_last = offset + len as u64 == transfer_len;
                        let mut bhs = Bhs::new();
                        bhs.set_opcode(op::SCSI_DATA_IN);
                        bhs.set_itt(itt);
                        bhs.set_data_sn(data_sn);
                        bhs.set_buffer_offset(offset as u32);
                        bhs.set_data_segment_len(len as u32);
                        if is_last {
                            bhs.set_status(status::GOOD);
                            bhs.set_stat_sn(self.stat_sn.get());
                            bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
                            bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
                            bhs.set_flags(flag::F_BIT | flag::S_BIT);
                        }
                        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
                        let total = BHS_SIZE + len;
                        let pad = pdu_pad_len(len as u32) as usize;
                        work[total..total + pad].fill(0);
                        if write_all(conn, &work[..total + pad]).is_err() {
                            return StepResult::Closed;
                        }
                        if is_last {
                            self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
                        }
                        offset += len as u64;
                        data_sn = data_sn.wrapping_add(1);
                    }
                    self.state = IscsiState::RecvPdu;
                    return StepResult::Processed;
                }
                // R2tSend: build R2T (no StatSN advance; only final response advances).
                IscsiState::R2tSend { .. } => {
                    let r = self.poll(SessionEvent::PduReceived { dsl: 0 }, work, devs);
                    if let SessionStep::NeedSend(data) = r {
                        let len = data.len();
                        let _ = r;
                        if write_all(conn, &work[..len]).is_err() {
                            return StepResult::Closed;
                        }
                    }
                }
                // R2tCollect / ParamCollect: need real Data-Out PDUs
                // from the wire.
                IscsiState::R2tCollect { .. } | IscsiState::ParamCollect { .. } => {
                    match recv_pdu(conn, work) {
                        Ok(dsl) => {
                            let r = self.poll(SessionEvent::PduReceived { dsl }, work, devs);
                            match r {
                                SessionStep::NeedSend(data) => {
                                    let len = data.len();
                                    let _ = r;
                                    if write_all(conn, &work[..len]).is_err() {
                                        return StepResult::Closed;
                                    }
                                    self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
                                }
                                SessionStep::NeedRecv => continue,
                                SessionStep::Closed => return StepResult::Closed,
                                SessionStep::Error(e) => return StepResult::Error(e),
                            }
                        }
                        Err(()) => return StepResult::Closed,
                    }
                }
            }
        }
        if self.state == IscsiState::Closed {
            StepResult::Closed
        } else {
            StepResult::Processed
        }
    }

    // ── Poll sub-handlers ─────────────────────────────────────────

    fn poll_recv<'a, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent,
        work: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        // Validate work buffer up front (same as the old step()).
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return SessionStep::Error(TargetError::WorkBufTooSmall);
        }

        match ev {
            SessionEvent::PduReceived { dsl } => {
                let pdu = Pdu {
                    bhs: Bhs::from_bytes(work[..BHS_SIZE].try_into().unwrap()),
                    dsl: dsl as usize,
                };

                // AHS defense: Assumes TotalAHSLength = 0.
                if pdu.bhs.total_ahs_length() != 0 {
                    return self.reject(work, reject::PROTOCOL_ERROR, &pdu.bhs);
                }

                let iscsi_op = pdu.bhs.opcode();
                crate::debug!(
                    "recv {} (0x{:02X}) stage={:?} cmd_sn={} stat_sn={}",
                    iscsi_opcode_name(iscsi_op),
                    iscsi_op,
                    self.stage,
                    self.cmd_sn,
                    self.stat_sn.get()
                );
                if self.stage != LoginStage::FullFeature {
                    if iscsi_op != op::LOGIN_REQ {
                        return self.reject(work, reject::PROTOCOL_ERROR, &pdu.bhs);
                    }
                    return self.handle_login(work, &pdu);
                }

                match iscsi_op {
                    op::SCSI_CMD => self.handle_scsi_cmd(work, devs, &pdu),
                    op::SCSI_TASK_REQ => self.handle_tmf(work, &pdu),
                    op::NOP_OUT => self.handle_nop(work, &pdu),
                    op::LOGOUT_REQ => self.handle_logout(work, &pdu),
                    op::TEXT_REQ => self.reject(work, reject::COMMAND_NOT_SUPPORTED, &pdu.bhs),
                    op::LOGIN_REQ => self.reject(work, reject::PROTOCOL_ERROR, &pdu.bhs),
                    _ => self.reject(work, reject::PROTOCOL_ERROR, &pdu.bhs),
                }
            }
        }
    }

    fn poll_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let IscsiState::DataIn {
            transfer_len,
            sent,
            itt,
            chunk,
            lun,
        } = st
        else {
            unreachable!()
        };

        if sent >= transfer_len {
            // Whole transfer sent — send final Data-In with status.
            self.state = IscsiState::RecvPdu;
            return self.send_data_in_final(work, itt, 0, 0, 0, status::GOOD);
        }

        let next = ((transfer_len - sent) as usize).min(chunk);
        if lun < devs.len() {
            let dev = &mut devs[lun];
            match dev.xfer_out(sent, &mut work[BHS_SIZE..BHS_SIZE + next]) {
                XferOutcome::Ok => {}
                XferOutcome::Error(_) => {
                    let sense = dev.take_sense();
                    return self.send_scsi_response(
                        work,
                        itt,
                        status::CHECK_CONDITION,
                        sense.as_ref(),
                    );
                }
            }
        }
        self.state = IscsiState::DataIn {
            transfer_len,
            sent: sent + next as u64,
            itt,
            chunk: next,
            lun,
        };
        SessionStep::NeedSend(&work[..BHS_SIZE + next])
    }

    fn poll_r2t_send<'a>(&'a mut self, work: &'a mut [u8]) -> SessionStep<'a> {
        let st = self.state;
        let IscsiState::R2tSend {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            lun,
        } = st
        else {
            unreachable!()
        };

        let burst = (u64::from(self.neg.max_burst_len)).min(transfer_len - received);
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::R2T);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_ttt(TTT);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_r2t_sn(r2t_sn);
        bhs.set_buffer_offset(received as u32);
        bhs.set_desired_data_len(burst as u32);
        crate::trace!("R2T: R2TSN={} BO={} DesiredLen={}", r2t_sn, received, burst);

        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        self.state = IscsiState::R2tCollect {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo: received as u32,
            burst_remaining: burst,
            lun,
        };
        SessionStep::NeedSend(&work[..BHS_SIZE])
    }

    fn poll_r2t_collect<'a, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent,
        work: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let IscsiState::R2tCollect {
            itt,
            transfer_len,
            mut received,
            r2t_sn,
            mut data_sn,
            mut expected_bo,
            mut burst_remaining,
            lun,
        } = st
        else {
            unreachable!()
        };

        let SessionEvent::PduReceived { dsl } = ev;
        let pdu_bhs = Bhs::from_bytes(work[..BHS_SIZE].try_into().unwrap());
        let pdu_dsl = dsl as usize;

        if pdu_bhs.opcode() != op::SCSI_DATA_OUT {
            return self.reject(work, reject::PROTOCOL_ERROR, &pdu_bhs);
        }
        if pdu_bhs.itt() != itt || pdu_bhs.ttt() != TTT {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_bhs.buffer_offset() != expected_bo {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_bhs.data_sn() != data_sn {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, &pdu_bhs);
        }
        if pdu_dsl as u64 > burst_remaining {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }

        if pdu_dsl > 0 && lun < devs.len() {
            let dev = &mut devs[lun];
            match dev.xfer_in(expected_bo as u64, &work[BHS_SIZE..BHS_SIZE + pdu_dsl]) {
                XferOutcome::Ok => {}
                XferOutcome::Error(_) => {
                    let sense = dev.take_sense();
                    return self.send_scsi_response(
                        work,
                        itt,
                        status::CHECK_CONDITION,
                        sense.as_ref(),
                    );
                }
            }
        }

        crate::trace!(
            "  Data-Out: BO={} DataSN={} len={}",
            expected_bo,
            data_sn,
            pdu_dsl
        );
        expected_bo += pdu_dsl as u32;
        received += pdu_dsl as u64;
        burst_remaining -= pdu_dsl as u64;
        data_sn = data_sn.wrapping_add(1);

        if burst_remaining == 0 {
            if received == transfer_len {
                // Transfer complete — send SCSI Response.
                return self.send_scsi_response(work, itt, status::GOOD, None);
            }
            // Next R2T — DataSN resets per R2T (RFC 3720 §10.7, DataSN is
            // relative to the R2T's buffer offset, not the whole command).
            self.state = IscsiState::R2tSend {
                itt,
                transfer_len,
                received,
                r2t_sn: r2t_sn + 1,
                data_sn: 0,
                lun,
            };
            return self.poll_r2t_send(work);
        }

        // More Data-Out PDUs expected in this burst.
        self.state = IscsiState::R2tCollect {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            lun,
        };
        SessionStep::NeedRecv
    }

    fn poll_param_collect<'a, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent,
        work: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let IscsiState::ParamCollect {
            itt,
            expected,
            mut received,
            r2t_sn,
            mut data_sn,
            mut expected_bo,
            mut burst_remaining,
            cdb,
            cdb_len,
            mut acc_offset,
            lun,
        } = st
        else {
            unreachable!()
        };

        let SessionEvent::PduReceived { dsl } = ev;
        let pdu_bhs = Bhs::from_bytes(work[..BHS_SIZE].try_into().unwrap());
        let pdu_dsl = dsl as usize;

        if pdu_bhs.opcode() != op::SCSI_DATA_OUT {
            return self.reject(work, reject::PROTOCOL_ERROR, &pdu_bhs);
        }
        if pdu_bhs.itt() != itt || pdu_bhs.ttt() != TTT {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_bhs.buffer_offset() != expected_bo {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_bhs.data_sn() != data_sn {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }
        if pdu_dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, &pdu_bhs);
        }
        if pdu_dsl as u64 > burst_remaining {
            return self.reject(work, reject::INVALID_PDU_FIELD, &pdu_bhs);
        }

        // Accumulate into work[BHS_SIZE + acc_offset ..].
        // `copy_within` is safe because acc_offset > 0, so the
        // destination is always at a higher address than the source.
        if pdu_dsl > 0 {
            work.copy_within(BHS_SIZE..BHS_SIZE + pdu_dsl, BHS_SIZE + acc_offset);
        }
        acc_offset += pdu_dsl;
        expected_bo += pdu_dsl as u32;
        received += pdu_dsl as u64;
        burst_remaining -= pdu_dsl as u64;
        data_sn = data_sn.wrapping_add(1);

        if received >= expected {
            // All data collected — complete the parameter.
            let cdb_slice = &cdb[..cdb_len];
            let param_data = &work[BHS_SIZE..BHS_SIZE + expected as usize];
            let outcome = if lun < devs.len() {
                devs[lun].complete_param(cdb_slice, param_data)
            } else {
                CommandOutcome::CheckCondition
            };
            return match outcome {
                CommandOutcome::Status => self.send_scsi_response(work, itt, status::GOOD, None),
                CommandOutcome::StatusWithSense => {
                    self.send_scsi_response(work, itt, status::GOOD, None)
                }
                CommandOutcome::CheckCondition => {
                    let sense = if lun < devs.len() {
                        devs[lun].take_sense()
                    } else {
                        None
                    };
                    self.send_scsi_response(work, itt, status::CHECK_CONDITION, sense.as_ref())
                }
                _ => {
                    let sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
                    self.send_scsi_response(work, itt, status::CHECK_CONDITION, Some(&sense))
                }
            };
        }

        if burst_remaining == 0 {
            // Next R2T.
            self.state = IscsiState::ParamCollect {
                itt,
                expected,
                received,
                r2t_sn: r2t_sn + 1,
                data_sn,
                expected_bo,
                burst_remaining: (u64::from(self.neg.max_burst_len)).min(expected - received),
                cdb,
                cdb_len,
                acc_offset,
                lun,
            };
            return self.send_param_r2t(work, itt, received, r2t_sn + 1);
        }

        self.state = IscsiState::ParamCollect {
            itt,
            expected,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            cdb,
            cdb_len,
            acc_offset,
            lun,
        };
        SessionStep::NeedRecv
    }

    /// Build and send a ParamOut R2T PDU.
    fn send_param_r2t<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        buffer_offset: u64,
        r2t_sn: u32,
    ) -> SessionStep<'a> {
        let st = self.state;
        let IscsiState::ParamCollect {
            expected, received, ..
        } = st
        else {
            unreachable!()
        };
        let burst = (u64::from(self.neg.max_burst_len)).min(expected - received);
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::R2T);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_ttt(TTT);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_r2t_sn(r2t_sn);
        bhs.set_buffer_offset(buffer_offset as u32);
        bhs.set_desired_data_len(burst as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        // Update burst_remaining in state.
        if let IscsiState::ParamCollect {
            ref mut burst_remaining,
            ..
        } = self.state
        {
            *burst_remaining = burst;
        }
        SessionStep::NeedSend(&work[..BHS_SIZE])
    }

    // ── Login Phase ───────────────────────────────────────────────

    fn handle_login<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> SessionStep<'a> {
        let req = &pdu.bhs;
        let req_csg = req.csg() & 0x03;
        let t = req.t_bit();

        // §6.4.1: the receive data-segment capability scales with the
        // caller's scratch buffer (data area = work minus BHS, 4-aligned,
        // bounded by the 24-bit DataSegmentLength field). Negotiation then
        // clamps the initiator's declared value to this cap.
        self.max_recv_data_segment =
            crate::scsi::device::data_capacity(work.len() - BHS_SIZE).min(HARD_CAP) as u32;

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
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(req.cmd_sn());
        resp.set_max_cmd_sn(req.cmd_sn());

        // Assemble: BHS at work[0..48], data at work[48..48+resp_len].
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + resp_len;
        let pad = pdu_pad_len(resp_len as u32) as usize;
        work[total..total + pad].fill(0);
        // stat_sn incremented by step() after sending.

        if t {
            self.stage = LoginStage::from_csg(nsg).unwrap_or(LoginStage::FullFeature);
            if self.stage == LoginStage::FullFeature {
                crate::debug!("login complete: FullFeature, cmd_sn={}", req.cmd_sn());
                self.cmd_sn = req.cmd_sn().wrapping_sub(1);
            }
        } else {
            self.stage = LoginStage::from_csg(req_csg).unwrap_or(LoginStage::Security);
        }
        SessionStep::NeedSend(&work[..total + pad])
    }

    /// Parse initiator key=value text into a response, updating negotiated
    /// parameters.  Writes into `dst` (clamped), returns the response length.
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
                if key == b"MaxRecvDataSegmentLength" {
                    // Advertise the negotiated (buffer-derived) value
                    // (§6.4.1), not the raw initiator figure.
                    if !append_kv_u32(dst, &mut w, key, self.max_recv_data_segment) {
                        break;
                    }
                } else {
                    let out_val: &[u8] = match LOGIN_TABLE[idx].value {
                        Some(v) => v.as_bytes(),
                        None => val,
                    };
                    if !append_kv(dst, &mut w, key, out_val) {
                        break;
                    }
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
                    self.max_recv_data_segment = v.min(self.max_recv_data_segment);
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

    fn handle_scsi_cmd<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &mut [D],
        pdu: &Pdu,
    ) -> SessionStep<'a> {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;
        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            return SessionStep::NeedRecv;
        }
        self.cmd_sn = recv_cmd_sn;

        let itt = bhs.itt();
        if !bhs.lun_is_single_level() {
            return self.reject(work, reject::INVALID_PDU_FIELD, bhs);
        }
        let lun = bhs.lun() as usize;
        if lun >= devs.len() {
            let sense = Sense::new(SenseKey::IllegalRequest, asc::LOGICAL_UNIT_NOT_SUPPORTED, 0);
            return self.send_scsi_response(work, itt, status::CHECK_CONDITION, Some(&sense));
        }
        if pdu.dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, bhs);
        }
        let w_bit = bhs.as_bytes()[1] & 0x20 != 0;
        if pdu.dsl > 0 && !w_bit {
            return self.reject(work, reject::PROTOCOL_ERROR, bhs);
        }

        let cdb = bhs.cdb();
        let scsi_opcode = opcode_from_cdb(cdb);

        if scsi_opcode == scsi_op::REPORT_LUNS {
            return self.handle_report_luns(work, itt, devs.len());
        }

        crate::debug!(
            "scsi cmd: {} (0x{:02X}) itt=0x{:08X} lun={} cmd_sn={} dsl={}",
            opcode_name(scsi_opcode),
            scsi_opcode,
            itt,
            lun,
            recv_cmd_sn,
            pdu.dsl
        );

        let dev = &mut devs[lun];
        let outcome = match dev.do_cmd(cdb, &mut work[BHS_SIZE..]) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return SessionStep::Error(TargetError::WorkBufTooSmall)
            }
            Err(_) => return SessionStep::Error(TargetError::Internal),
        };

        match outcome {
            CommandOutcome::Status => {
                crate::debug!("  -> Status (GOOD)");
                self.send_scsi_response(work, itt, status::GOOD, None)
            }
            CommandOutcome::StatusWithSense => {
                crate::debug!("  -> StatusWithSense (GOOD, sense pending)");
                self.send_scsi_response(work, itt, status::GOOD, None)
            }
            CommandOutcome::CheckCondition => {
                let sense = devs[lun].take_sense();
                if let Some(ref s) = sense {
                    crate::debug!(
                        "  -> CheckCondition key={:?} asc=0x{:02X} ascq=0x{:02X}",
                        s.key,
                        s.asc,
                        s.ascq
                    );
                } else {
                    crate::debug!("  -> CheckCondition (no sense)");
                }
                self.send_scsi_response(work, itt, status::CHECK_CONDITION, sense.as_ref())
            }
            CommandOutcome::OutInline { len } => {
                crate::debug!("  -> OutInline (synthesized, {} bytes)", len);
                let n = len as usize;
                self.send_data_in_final(work, itt, n, 0, 0, status::GOOD)
            }
            CommandOutcome::OutXfer { len: transfer_len } => {
                crate::debug!("  -> OutXfer (backend, transfer_len={})", transfer_len);
                let chunk = (transfer_len as usize).min(work.len() - BHS_SIZE);
                if lun < devs.len() {
                    let dev = &mut devs[lun];
                    match dev.xfer_out(0, &mut work[BHS_SIZE..BHS_SIZE + chunk]) {
                        XferOutcome::Ok => {}
                        XferOutcome::Error(_) => {
                            let sense = dev.take_sense();
                            return self.send_scsi_response(
                                work,
                                itt,
                                status::CHECK_CONDITION,
                                sense.as_ref(),
                            );
                        }
                    }
                }
                if chunk as u64 == transfer_len {
                    // All data fits in one chunk — send as final Data-In (F+S).
                    let mut dib = Bhs::new();
                    dib.set_opcode(op::SCSI_DATA_IN);
                    dib.set_itt(itt);
                    dib.set_flags(flag::F_BIT | flag::S_BIT);
                    dib.set_status(status::GOOD);
                    dib.set_stat_sn(self.stat_sn.get());
                    dib.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
                    dib.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
                    dib.set_data_segment_len(chunk as u32);
                    work[..BHS_SIZE].copy_from_slice(dib.as_bytes());
                    self.state = IscsiState::RecvPdu;
                } else {
                    // Multi-chunk: first chunk is intermediate (F=0, S=0).
                    let mut dib = Bhs::new();
                    dib.set_opcode(op::SCSI_DATA_IN);
                    dib.set_itt(itt);
                    dib.set_data_segment_len(chunk as u32);
                    work[..BHS_SIZE].copy_from_slice(dib.as_bytes());
                    self.state = IscsiState::DataIn {
                        transfer_len,
                        sent: chunk as u64,
                        itt,
                        chunk,
                        lun,
                    };
                }
                SessionStep::NeedSend(&work[..BHS_SIZE + chunk])
            }
            CommandOutcome::InXfer { len: transfer_len } => {
                // Host→device write: consume immediate data already in work.
                let received = (pdu.dsl as u64).min(transfer_len);
                crate::debug!(
                    "  -> InXfer transfer_len={} immediate={}",
                    transfer_len,
                    received
                );
                if received > 0 && lun < devs.len() {
                    let dev = &mut devs[lun];
                    let imm = &work[BHS_SIZE..BHS_SIZE + received as usize];
                    match dev.xfer_in(0, imm) {
                        XferOutcome::Ok => {}
                        XferOutcome::Error(_) => {
                            let sense = dev.take_sense();
                            return self.send_scsi_response(
                                work,
                                itt,
                                status::CHECK_CONDITION,
                                sense.as_ref(),
                            );
                        }
                    }
                }
                if received == transfer_len {
                    return self.send_scsi_response(work, itt, status::GOOD, None);
                }

                // Enter R2T state: send the first R2T.
                self.state = IscsiState::R2tSend {
                    itt,
                    transfer_len,
                    received,
                    r2t_sn: 0,
                    data_sn: 0,
                    lun,
                };
                self.poll_r2t_send(work)
            }
            CommandOutcome::InParam { expected_len } => {
                let expected = expected_len as u64;
                let received = (pdu.dsl as u64).min(expected);
                crate::debug!("  -> InParam expected={} immediate={}", expected, received);
                if expected > 0 && !w_bit {
                    return self.reject(work, reject::PROTOCOL_ERROR, bhs);
                }
                if (pdu.dsl as u64) > expected {
                    return self.reject(work, reject::PROTOCOL_ERROR, bhs);
                }
                if expected as usize > work.len() - BHS_SIZE {
                    return SessionStep::Error(TargetError::WorkBufTooSmall);
                }

                let mut cdb_buf = [0u8; 16];
                let cdb_len = cdb.len().min(16);
                cdb_buf[..cdb_len].copy_from_slice(&cdb[..cdb_len]);

                if received == expected {
                    // All present — complete immediately.
                    let outcome2 = if lun < devs.len() {
                        devs[lun].complete_param(
                            &cdb_buf[..cdb_len],
                            &work[BHS_SIZE..BHS_SIZE + expected as usize],
                        )
                    } else {
                        CommandOutcome::CheckCondition
                    };
                    return match outcome2 {
                        CommandOutcome::Status => {
                            self.send_scsi_response(work, itt, status::GOOD, None)
                        }
                        CommandOutcome::StatusWithSense => {
                            self.send_scsi_response(work, itt, status::GOOD, None)
                        }
                        CommandOutcome::CheckCondition => {
                            let sense = if lun < devs.len() {
                                devs[lun].take_sense()
                            } else {
                                None
                            };
                            self.send_scsi_response(
                                work,
                                itt,
                                status::CHECK_CONDITION,
                                sense.as_ref(),
                            )
                        }
                        _ => {
                            let sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
                            self.send_scsi_response(
                                work,
                                itt,
                                status::CHECK_CONDITION,
                                Some(&sense),
                            )
                        }
                    };
                }

                // Need to receive the remainder via R2T.
                let acc_offset = received as usize;
                let burst = (u64::from(self.neg.max_burst_len)).min(expected - received);
                self.state = IscsiState::ParamCollect {
                    itt,
                    expected,
                    received,
                    r2t_sn: 0,
                    data_sn: 0,
                    expected_bo: received as u32,
                    burst_remaining: burst,
                    cdb: cdb_buf,
                    cdb_len,
                    acc_offset,
                    lun,
                };
                self.send_param_r2t(work, itt, received, 0)
            }
        }
    }

    /// Build and send the REPORT LUNS response (SPC-4 §6.21).
    fn handle_report_luns<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        num_luns: usize,
    ) -> SessionStep<'a> {
        let list_len = u32::try_from(num_luns)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .unwrap_or(u32::MAX);
        let total = 8usize + (list_len as usize);
        if total > work.len() - BHS_SIZE {
            return SessionStep::Error(TargetError::WorkBufTooSmall);
        }
        work[BHS_SIZE..BHS_SIZE + 4].copy_from_slice(&list_len.to_be_bytes());
        for b in &mut work[BHS_SIZE + 4..BHS_SIZE + 8] {
            *b = 0;
        }
        for i in 0..num_luns {
            let off = BHS_SIZE + 8 + i * 8;
            work[off] = 0x00;
            work[off + 1] = i as u8;
            for b in &mut work[off + 2..off + 8] {
                *b = 0;
            }
        }
        crate::debug!("  -> REPORT LUNS: {} LUN(s)", num_luns);
        self.send_data_in_final(work, itt, total, 0, 0, status::GOOD)
    }

    // ── Full Feature: Task Management / NOP / Logout ─────────────

    fn handle_tmf<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> SessionStep<'a> {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            return SessionStep::NeedRecv;
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
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        SessionStep::NeedSend(&work[..BHS_SIZE + pad])
    }

    fn handle_nop<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> SessionStep<'a> {
        let bhs = &pdu.bhs;
        let mut resp = Bhs::new();
        resp.set_opcode(op::NOP_IN);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_ttt(bhs.ttt());
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let dlen = if pdu.dsl <= MAX_DATA_SEGMENT as usize {
            resp.set_data_segment_len(pdu.dsl as u32);
            pdu.dsl
        } else {
            0
        };
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[total..total + pad].fill(0);
        SessionStep::NeedSend(&work[..total + pad])
    }

    fn handle_logout<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> SessionStep<'a> {
        let bhs = &pdu.bhs;
        let mut resp = Bhs::new();
        resp.set_opcode(op::LOGOUT_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        self.state = IscsiState::Closed;
        SessionStep::NeedSend(&work[..BHS_SIZE + pad])
    }

    // ── Response PDU builders ─────────────────────────────────────

    fn send_scsi_response<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        scsi_status: u8,
        sense: Option<&Sense>,
    ) -> SessionStep<'a> {
        self.state = IscsiState::RecvPdu;
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_RESP);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let mut dlen = 0;
        if scsi_status == status::CHECK_CONDITION {
            if let Some(s) = sense {
                work[BHS_SIZE] = 0;
                work[BHS_SIZE + 1] = 18;
                s.write_fixed(&mut work[BHS_SIZE + 2..BHS_SIZE + 20]);
                dlen = 20;
            }
        }
        bhs.set_data_segment_len(dlen as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[total..total + pad].fill(0);
        SessionStep::NeedSend(&work[..total + pad])
    }

    /// Single final Data-In (F=1, S=1) with status — used for synthesized
    /// responses and the zero-length edge case.
    fn send_data_in_final<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        data_len: usize,
        buffer_offset: u32,
        data_sn: u32,
        scsi_status: u8,
    ) -> SessionStep<'a> {
        self.state = IscsiState::RecvPdu;
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        bhs.set_flags(flag::F_BIT | flag::S_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(buffer_offset);
        bhs.set_data_segment_len(data_len as u32);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + data_len;
        let pad = pdu_pad_len(data_len as u32) as usize;
        work[total..total + pad].fill(0);
        SessionStep::NeedSend(&work[..total + pad])
    }

    /// Send a Reject and close the connection.  The data segment carries
    /// the full header of the rejected PDU; ITT = 0xffffffff (fix #18).
    fn reject<'a>(&'a mut self, work: &'a mut [u8], reason: u8, rejected: &Bhs) -> SessionStep<'a> {
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
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_data_segment_len(BHS_SIZE as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        work[BHS_SIZE..2 * BHS_SIZE].copy_from_slice(rejected.as_bytes());
        let total = 2 * BHS_SIZE;
        let pad = pdu_pad_len(BHS_SIZE as u32) as usize;
        work[total..total + pad].fill(0);
        self.state = IscsiState::Closed;
        SessionStep::NeedSend(&work[..total + pad])
    }
}

/// Blocking wrapper: run `session.step` until the connection closes.
///
/// Validates `work.len() >= MIN_DATA_LEN + BHS_SIZE` up front.  I/O errors
/// inside `step` surface as `Closed`; only caller bugs propagate as `Err`.
pub fn serve_conn<C: Conn, D: ScsiDevice>(
    conn: &mut C,
    work: &mut [u8],
    session: &mut IscsiSession,
    devs: &mut [D],
) -> Result<(), TargetError> {
    if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
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

// ── Private helpers ─────────────────────────────────────────────────

struct Pdu {
    bhs: Bhs,
    dsl: usize,
}

/// Receive one PDU: 48-byte BHS, optional AHS (skipped), data segment
/// (into `work[BHS_SIZE..]` when it fits, otherwise discarded), and padding.
/// Returns the data-segment length.  Never leaves bytes behind — keeps
/// TCP synchronized (fix #1).
fn recv_pdu<C: Conn + ?Sized>(conn: &mut C, work: &mut [u8]) -> Result<u32, ()> {
    let mut raw = [0u8; BHS_SIZE];
    let mut got = 0usize;
    while got < BHS_SIZE {
        match conn.read(&mut raw[got..]) {
            Ok(0) => {
                crate::warn!("recv: BHS EOF after {got}/{BHS_SIZE} bytes (peer closed)");
                return Err(());
            }
            Ok(n) => got += n,
            Err(_) => {
                crate::warn!("recv: BHS I/O error after {got}/{BHS_SIZE} bytes");
                return Err(());
            }
        }
    }
    // Copy BHS into work[0..48] so the poll model can inspect it.
    work[..BHS_SIZE].copy_from_slice(&raw);
    let bhs = Bhs::from_bytes(raw);
    let dsl = bhs.data_segment_len() as usize;
    let ahs = usize::from(bhs.total_ahs_length());
    let mut hexbuf = [0u8; BHS_SIZE * 2];
    let hlen = fmt_hex(&raw, &mut hexbuf);
    crate::trace!(
        "recv BHS: hex={} op_raw=0x{:02X} op=0x{:02X} dsl={} ahs={}",
        core::str::from_utf8(&hexbuf[..hlen]).unwrap_or("<invalid>"),
        raw[0],
        bhs.opcode(),
        dsl,
        ahs
    );
    if ahs > 0 && skip(conn, ahs * 4).is_err() {
        crate::warn!("recv: connection closed while reading AHS ({ahs}*4 bytes)");
        return Err(());
    }
    if dsl <= work.len() - BHS_SIZE {
        if read_exact(conn, &mut work[BHS_SIZE..BHS_SIZE + dsl]).is_err() {
            crate::warn!("recv: connection closed while reading data segment (dsl={dsl})");
            return Err(());
        }
    } else if skip(conn, dsl).is_err() {
        crate::warn!("recv: connection closed while discarding oversized data segment (dsl={dsl})");
        return Err(());
    }
    let pad = pdu_pad_len(dsl as u32) as usize;
    if pad > 0 && skip(conn, pad).is_err() {
        crate::warn!("recv: connection closed while reading padding (pad={pad})");
        return Err(());
    }
    Ok(dsl as u32)
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

fn append_kv_u32(dst: &mut [u8], w: &mut usize, key: &[u8], v: u32) -> bool {
    let mut buf = [0u8; 10];
    let digits = fmt_u32(v, &mut buf);
    append_kv(dst, w, key, digits)
}

fn fmt_u32(v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut n = v;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

fn fmt_hex(bytes: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0;
    for &b in bytes {
        if i + 2 > out.len() {
            break;
        }
        out[i] = HEX[(b >> 4) as usize];
        out[i + 1] = HEX[(b & 0x0F) as usize];
        i += 2;
    }
    i
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
        n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(n)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iscsi::pdu::BHS_SIZE;

    /// Verify poll model round-trips: Login → Full Feature → SCSI INQUIRY
    /// → Logout produces the same logical flow as the old step() model.
    #[test]
    fn poll_login_and_inquiry() {
        use crate::scsi::backend::{BlockBackend, RamBackend};
        use crate::scsi::block::BlockDevice;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs =
            [
                BlockDevice::<BlockBackend>::new(BlockBackend::Ram(RamBackend::new(&mut ram)), 512)
                    .unwrap(),
            ];
        let mut session = IscsiSession::new();
        let mut work = vec![0u8; crate::MIN_DATA_LEN + BHS_SIZE];

        // Build a Login Request BHS (I=1, T=1, CSG=1, NSG=3).
        let login_text = b"InitiatorName=iqn.test\0SessionType=Normal\0";
        let mut login_bhs = [0u8; 48];
        login_bhs[0] = op::LOGIN_REQ | 0x40;
        login_bhs[1] =
            flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        login_bhs[5] = (login_text.len() >> 16) as u8;
        login_bhs[6] = (login_text.len() >> 8) as u8;
        login_bhs[7] = login_text.len() as u8;

        // Place the PDU into work.
        work[..48].copy_from_slice(&login_bhs);
        work[48..48 + login_text.len()].copy_from_slice(login_text);

        // Poll: should get NeedSend (Login Response).
        match session.poll(
            SessionEvent::PduReceived {
                dsl: login_text.len() as u32,
            },
            &mut work,
            &mut devs,
        ) {
            SessionStep::NeedSend(data) => {
                assert!(data.len() >= BHS_SIZE);
                let resp_op = data[0] & 0x3F;
                assert_eq!(resp_op, op::LOGIN_RESP);
            }
            other => panic!("expected NeedSend for login response, got {other:?}"),
        }

        // Simulate "send done" by advancing stat_sn (the blocking wrapper
        // does this automatically).
        // After login with T=1, stage should be FullFeature.
        assert_eq!(session.stage(), LoginStage::FullFeature);

        // Now issue an INQUIRY CDB via a SCSI Command PDU.
        let inquiry_cdb = [0x12, 0, 0, 0, 96, 0]; // INQUIRY, alloc=96
        let mut scsi_bhs = [0u8; 48];
        scsi_bhs[0] = op::SCSI_CMD | 0x40; // I=1 (Immediate) + SCSI_CMD
        scsi_bhs[1] = 0x80; // R=1 (Data-In expected)
        scsi_bhs[16..20].copy_from_slice(&0u32.to_be_bytes()); // ITT=0
        scsi_bhs[24..28].copy_from_slice(&0u32.to_be_bytes()); // CmdSN=0 (next after login)
        scsi_bhs[32..32 + inquiry_cdb.len()].copy_from_slice(&inquiry_cdb);

        work[..48].copy_from_slice(&scsi_bhs);
        work[48..].fill(0);

        match session.poll(SessionEvent::PduReceived { dsl: 0 }, &mut work, &mut devs) {
            SessionStep::NeedSend(data) => {
                assert!(data.len() > BHS_SIZE);
                // First byte of INQUIRY response: PDT = 0x00 (direct access).
                assert_eq!(data[BHS_SIZE] & 0x1F, 0x00);
            }
            other => panic!("expected NeedSend for INQUIRY response, got {other:?}"),
        }
    }

    #[test]
    fn poll_reject_on_ahs() {
        use crate::scsi::backend::{BlockBackend, RamBackend};
        use crate::scsi::block::BlockDevice;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs =
            [
                BlockDevice::<BlockBackend>::new(BlockBackend::Ram(RamBackend::new(&mut ram)), 512)
                    .unwrap(),
            ];
        let mut session = IscsiSession::new();
        let mut work = vec![0u8; crate::MIN_DATA_LEN + BHS_SIZE];

        // Login first.
        let login_text = b"InitiatorName=iqn.test\0SessionType=Normal\0";
        let mut login_bhs = [0u8; 48];
        login_bhs[0] = op::LOGIN_REQ | 0x40;
        login_bhs[1] =
            flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        login_bhs[5] = (login_text.len() >> 16) as u8;
        login_bhs[6] = (login_text.len() >> 8) as u8;
        login_bhs[7] = login_text.len() as u8;
        work[..48].copy_from_slice(&login_bhs);
        work[48..48 + login_text.len()].copy_from_slice(login_text);
        let _ = session.poll(
            SessionEvent::PduReceived {
                dsl: login_text.len() as u32,
            },
            &mut work,
            &mut devs,
        );
        assert_eq!(session.stage(), LoginStage::FullFeature);

        // Send a SCSI Command with non-zero AHS → should Reject.
        let mut scsi_bhs = [0u8; 48];
        scsi_bhs[0] = op::SCSI_CMD;
        scsi_bhs[4] = 1; // TotalAHSLength = 1 → invalid
        work[..48].copy_from_slice(&scsi_bhs);

        match session.poll(SessionEvent::PduReceived { dsl: 0 }, &mut work, &mut devs) {
            SessionStep::NeedSend(data) => {
                assert_eq!(data[0] & 0x3F, op::REJECT);
                assert_eq!(session.stage(), LoginStage::FullFeature);
            }
            other => panic!("expected NeedSend for Reject, got {other:?}"),
        }
    }
}
