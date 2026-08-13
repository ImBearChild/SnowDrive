//! USB MSC Bulk-Only Transport session state machine (target.rs).
//!
//! [`BotSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O. A driver feeds one [`BotEvent`]
//! (an I/O completion) per [`BotSession::poll`] call and learns the next
//! need from the returned [`BotStep`] (or the copyable [`BotSession::need`]).
//! The same core is driven by the PC FunctionFS poll loop, the blocking
//! [`BotSession::step`] convenience wrapper, and embedded `select!` drivers.
//!
//! Out-of-band control never enters the core: Bulk-Only Reset and Get Max
//! LUN arrive on the control pipe at any time (even mid data phase), so the
//! driver calls [`BotSession::reset`] / [`BotSession::max_lun`] directly
//! between bulk events.
//!
//! Design invariants (§4 / §3.7 / §3.8):
//! - CBW (31B) accumulates into an internal buffer; CSW (13B) is assembled
//!   in an internal buffer; the caller's `data` area holds only SCSI data.
//! - STALL is used only for invalid CBWs; data-phase errors are expressed
//!   as short packets + CSW status/residue (never STALL, never ZLP).
//! - Data-Out host overrun is drained to a short packet so leftover bytes
//!   never corrupt the next CBW.
//! - After a reset the session injects a UNIT ATTENTION: delivered on the
//!   next TEST UNIT READY (Failed CSW), cleared by REQUEST SENSE.

use core::time::Duration;

use crate::scsi::device::{CommandOutcome, ScsiDevice};
use crate::scsi::scsi::{asc, op as scsi_op, Sense, SenseKey};
use crate::usb::bot::{BotDir, Cbw, Csw, CswStatus};
use crate::usb::io::BotIo;
use crate::usb::{CBW_LEN, CSW_LEN};

/// Blocking `step` receive granularity: drives the poll loop and bounds the
/// Data-Out overrun drain wait (mirrors the PC driver's 50ms ctrl poll).
const STEP_RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// One bulk I/O completion fed from the driver to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotEvent<'a> {
    /// bulk OUT (host → device): `data` is a CBW fragment or a Data-Out
    /// chunk (borrowed from the driver's receive buffer).
    OutRecv { data: &'a [u8] },
    /// bulk IN (device → host): the pending packet has been sent.
    InSent,
    /// The driver's bulk-OUT receive found no data (timed out). Ignored by
    /// every state except the Data-Out overrun drain, where it ends the
    /// drain and moves on to the CSW.
    OutIdle,
}

/// The core's next need, returned by [`BotSession::poll`].
///
/// `NeedIn` borrows the caller's `data` region (Data-In chunks / synthesized
/// responses) or the internal CSW buffer; `NeedOut` needs `len` more bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotStep<'a> {
    /// Receive `len` more bytes. `probe` marks a non-blocking drain receive
    /// (Data-Out overrun): the driver should try once; a WouldBlock result
    /// ends the data phase and should be fed back as [`BotEvent::OutIdle`].
    NeedOut { len: usize, probe: bool },
    /// Send these bytes (chunk from `data`, or the internal CSW).
    NeedIn(&'a [u8]),
    /// The transaction ended; the driver stops feeding bulk events.
    Done(BotStepResult),
}

/// Copyable variant of [`BotStep`] (no borrows), for [`BotSession::need`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotNeed {
    /// See [`BotStep::NeedOut`].
    NeedOut { len: usize, probe: bool },
    /// Send `len` bytes (fetch via [`BotSession::out_slice`]).
    NeedIn { len: usize },
    /// Transaction ended; the driver stops feeding bulk events.
    Done(BotStepResult),
}

/// How a transaction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotStepResult {
    /// CSW sent; back in Command phase.
    Processed,
    /// Invalid CBW — STALL both bulk endpoints and wait for a reset.
    Stalled,
    /// I/O link failed (used by the blocking `step` wrapper).
    Closed,
    /// Caller bug (buffer too small / impossible event).
    Error(BotTargetError),
}

/// Core-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotTargetError {
    /// The caller's `data` buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// I/O failure (reported through the blocking `step` wrapper).
    Io,
    /// An impossible state transition (driver fed a wrong event).
    Internal,
}

impl core::fmt::Display for BotTargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "data buffer smaller than MIN_DATA_LEN"),
            Self::Io => write!(f, "bulk I/O failure"),
            Self::Internal => write!(f, "internal BOT state error"),
        }
    }
}

impl core::error::Error for BotTargetError {}

/// BOT phase machine state (all Copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotState {
    /// Command phase: accumulate the 31-byte CBW.
    Command { got: usize },
    /// Data-In phase: send chunks from the device until `sent == transfer_len`.
    DataIn {
        expected: u64,
        transfer_len: u64,
        byte_offset: u64,
        sent: u64,
        tag: u32,
        lun: usize,
        chunk: usize,
    },
    /// Data-Out phase: receive chunks and write to the backend.
    DataOut {
        declared: u64,
        to_write: u64,
        byte_offset: u64,
        received: u64,
        written: u64,
        tag: u32,
        lun: usize,
        failed: bool,
        chunk: usize,
    },
    /// Data-Out host overrun: read-and-discard until a short packet.
    DataOutOverrun {
        tag: u32,
        residue: u64,
        status: CswStatus,
        chunk: usize,
    },
    /// CSW pending in the internal buffer.
    Csw,
    /// Frozen after an invalid CBW; only `reset()` unfreezes.
    Stalled,
}

/// BOT session: a non-blocking protocol state machine over one bulk pipe
/// pair (plus the driver-mediated control pipe).
pub struct BotSession {
    state: BotState,
    cbw: [u8; CBW_LEN],
    csw: [u8; CSW_LEN],
    num_luns: u8,
    invalid_lun_sense: Option<Sense>,
    pending_ua: Option<Sense>,
}

impl Default for BotSession {
    fn default() -> Self {
        Self::new()
    }
}

impl BotSession {
    /// A session serving a single LUN.
    pub fn new() -> Self {
        Self::with_luns(1)
    }

    /// A session serving `num_luns` logical units (1..=16), used by drivers
    /// that must answer Get Max LUN before the first [`poll`] call.
    ///
    /// [`poll`]: Self::poll
    pub fn with_luns(num_luns: usize) -> Self {
        Self {
            state: BotState::Command { got: 0 },
            cbw: [0u8; CBW_LEN],
            csw: [0u8; CSW_LEN],
            num_luns: num_luns.clamp(1, 16) as u8,
            invalid_lun_sense: None,
            pending_ua: None,
        }
    }

    /// The session's current need (Copy; the driver polls the matching
    /// endpoint / checks ep0 in between).
    pub fn need(&self) -> BotNeed {
        match self.state {
            BotState::Command { got } => BotNeed::NeedOut {
                len: CBW_LEN - got,
                probe: false,
            },
            BotState::DataIn { chunk, .. } => BotNeed::NeedIn { len: chunk },
            BotState::DataOut { chunk, .. } => BotNeed::NeedOut {
                len: chunk,
                probe: false,
            },
            BotState::DataOutOverrun { chunk, .. } => BotNeed::NeedOut {
                len: chunk,
                probe: true,
            },
            BotState::Csw => BotNeed::NeedIn { len: CSW_LEN },
            BotState::Stalled => BotNeed::Done(BotStepResult::Stalled),
        }
    }

    /// The bytes to send when `need() == NeedIn`: a Data-In chunk from the
    /// caller's `data` region, or the internal CSW buffer.
    pub fn out_slice<'a>(&'a mut self, data: &'a [u8]) -> &'a [u8] {
        match self.state {
            BotState::Csw => &self.csw[..],
            BotState::DataIn { chunk, .. } => &data[..chunk],
            _ => &[],
        }
    }

    /// Get Max LUN answer value (`num_luns - 1`, ≤ 15). The LUN count is
    /// refreshed from the device slice on every command.
    pub fn max_lun(&self) -> u8 {
        self.num_luns.saturating_sub(1)
    }

    /// Bulk-Only Reset / LinkReset: abort any in-flight transaction, return
    /// to the Command phase, and inject a UNIT ATTENTION for the next
    /// TEST UNIT READY (BOT §4.2, §5.2).
    pub fn reset(&mut self) {
        self.state = BotState::Command { got: 0 };
        self.cbw = [0u8; CBW_LEN];
        self.invalid_lun_sense = None;
        self.pending_ua = Some(Sense::new(SenseKey::UnitAttention, asc::POWER_ON_RESET, 0));
    }

    /// Non-blocking state-machine step: consume one event and return the
    /// next need. `data` is the pure SCSI data area (≥
    /// [`crate::MIN_DATA_LEN`] for commands routed to the device); `devs`
    /// is the LUN slice.
    pub fn poll<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: BotEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> BotStep<'a> {
        match self.state {
            BotState::Stalled => BotStep::Done(BotStepResult::Stalled),
            BotState::Command { got } => self.poll_command(ev, data, devs, got),
            BotState::DataIn { .. } => self.poll_data_in(ev, data, devs),
            BotState::DataOut { .. } => self.poll_data_out(ev, data, devs),
            BotState::DataOutOverrun { .. } => self.poll_overrun(ev),
            BotState::Csw => self.poll_csw(ev),
        }
    }

    /// Blocking convenience wrapper over `need()` + `poll()`: drives one
    /// transaction to completion using `io`. `recv` is the driver's receive
    /// scratch (≥ `data.len()`). Out-of-band control is NOT handled here.
    pub fn step<B: BotIo, D: ScsiDevice>(
        &mut self,
        io: &mut B,
        data: &mut [u8],
        recv: &mut [u8],
        devs: &mut [D],
    ) -> BotStepResult {
        if data.len() < crate::MIN_DATA_LEN {
            return BotStepResult::Error(BotTargetError::WorkBufTooSmall);
        }
        loop {
            match self.need() {
                BotNeed::NeedOut { len, .. } => {
                    if len > recv.len() {
                        return BotStepResult::Error(BotTargetError::WorkBufTooSmall);
                    }
                    match io.recv_out(&mut recv[..len], Some(STEP_RECV_TIMEOUT)) {
                        Ok(n) => {
                            if n == 0 {
                                return BotStepResult::Closed;
                            }
                            let step =
                                self.poll(BotEvent::OutRecv { data: &recv[..n] }, data, devs);
                            if let BotStep::Done(r) = step {
                                return r;
                            }
                        }
                        Err(crate::usb::BotIoErr::WouldBlock) => {
                            let step = self.poll(BotEvent::OutIdle, data, devs);
                            if let BotStep::Done(r) = step {
                                return r;
                            }
                        }
                        Err(_) => return BotStepResult::Closed,
                    }
                }
                BotNeed::NeedIn { len } => {
                    let bytes = self.out_slice(&data[..]);
                    if bytes.len() != len {
                        return BotStepResult::Error(BotTargetError::Internal);
                    }
                    if io.send_in(bytes).is_err() {
                        return BotStepResult::Closed;
                    }
                    let step = self.poll(BotEvent::InSent, data, devs);
                    if let BotStep::Done(r) = step {
                        return r;
                    }
                }
                BotNeed::Done(r) => return r,
            }
        }
    }

    // ── Command phase ──────────────────────────────────────────────

    fn poll_command<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: BotEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
        got: usize,
    ) -> BotStep<'a> {
        match ev {
            BotEvent::InSent => BotStep::Done(BotStepResult::Error(BotTargetError::Internal)),
            BotEvent::OutIdle => BotStep::NeedOut {
                len: CBW_LEN - got,
                probe: false,
            },
            BotEvent::OutRecv { data: chunk } => {
                let add = chunk.len().min(CBW_LEN - got);
                self.cbw[got..got + add].copy_from_slice(&chunk[..add]);
                let got = got + add;
                if got < CBW_LEN {
                    self.state = BotState::Command { got };
                    return BotStep::NeedOut {
                        len: CBW_LEN - got,
                        probe: false,
                    };
                }
                match Cbw::parse(&self.cbw) {
                    None => {
                        self.state = BotState::Stalled;
                        BotStep::Done(BotStepResult::Stalled)
                    }
                    Some(cbw) => self.dispatch_cbw(&cbw, data, devs),
                }
            }
        }
    }

    // ── Command dispatch ───────────────────────────────────────────

    fn dispatch_cbw<'a, D: ScsiDevice>(
        &'a mut self,
        cbw: &Cbw,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> BotStep<'a> {
        self.num_luns = devs.len().clamp(1, 16) as u8;
        let cdb = cbw.cdb_slice();
        let declared = u64::from(cbw.data_len);

        // REPORT LUNS is served for any addressed LUN (§5.3).
        if cdb.first() == Some(&scsi_op::REPORT_LUNS) {
            let n = write_report_luns(data, devs.len());
            return self.synthesize_data_in(cbw, data, n as u64);
        }

        if cbw.lun as usize >= devs.len() {
            // Invalid LUN (§4.6): Failed CSW + REQUEST SENSE (ASC 0x25).
            // The stored sense is served by the core's REQUEST SENSE path
            // below, since the addressed device does not exist.
            if cdb.first() == Some(&scsi_op::REQUEST_SENSE) {
                if let Some(sense) = self.invalid_lun_sense.take() {
                    let n = sense.write_fixed(data);
                    return self.synthesize_data_in(cbw, data, n as u64);
                }
            }
            self.invalid_lun_sense = Some(Sense::new(
                SenseKey::IllegalRequest,
                asc::LOGICAL_UNIT_NOT_SUPPORTED,
                0,
            ));
            return self.finish_csw_bot(cbw.tag, 0, CswStatus::Failed);
        }

        // Valid LUN: unit-attention injection (§5.2). The UA is delivered
        // on the next TEST UNIT READY and cleared by REQUEST SENSE.
        if self.pending_ua.is_some() {
            match cdb.first() {
                Some(&scsi_op::TEST_UNIT_READY) => {
                    return self.finish_csw_bot(cbw.tag, 0, CswStatus::Failed);
                }
                Some(&scsi_op::REQUEST_SENSE) => {
                    let sense = self.pending_ua.take().expect("checked above");
                    let n = sense.write_fixed(data);
                    return self.synthesize_data_in(cbw, data, n as u64);
                }
                _ => {}
            }
        }

        let lun = cbw.lun as usize;
        let outcome = match devs[lun].do_cmd(cdb, data, 0) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return BotStep::Done(BotStepResult::Error(BotTargetError::WorkBufTooSmall));
            }
        };
        match outcome {
            CommandOutcome::Status => self.finish_csw_bot(cbw.tag, declared, CswStatus::Passed),
            CommandOutcome::CheckCondition(_) => self.finish_csw_bot(cbw.tag, 0, CswStatus::Failed),
            CommandOutcome::DataIn {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                if declared == 0 {
                    return self.finish_csw_bot(cbw.tag, 0, CswStatus::Passed);
                }
                if cbw.dir != BotDir::DataIn {
                    return self.finish_csw_bot(cbw.tag, declared, CswStatus::PhaseError);
                }
                // Copy `immediate`'s length out so the reference (and its
                // borrow of `data`) dies before `data` is reborrowed
                // mutably for the backend read.
                let immediate_len = immediate.len() as u64;
                let available = if immediate_len == 0 {
                    transfer_len
                } else {
                    immediate_len
                };
                let actual = available.min(declared);
                if actual == 0 {
                    return self.finish_csw_bot(cbw.tag, declared, CswStatus::Passed);
                }
                let chunk = (actual as usize).min(data.len());
                if immediate_len == 0
                    && devs[lun]
                        .read_data(byte_offset, &mut data[..chunk])
                        .is_err()
                {
                    return self.finish_csw_bot(cbw.tag, declared, CswStatus::Failed);
                }
                self.state = BotState::DataIn {
                    expected: declared,
                    transfer_len: actual,
                    byte_offset,
                    sent: chunk as u64,
                    tag: cbw.tag,
                    lun,
                    chunk,
                };
                BotStep::NeedIn(&data[..chunk])
            }
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                if declared == 0 {
                    return self.finish_csw_bot(cbw.tag, 0, CswStatus::Passed);
                }
                if cbw.dir != BotDir::DataOut {
                    return self.finish_csw_bot(cbw.tag, declared, CswStatus::PhaseError);
                }
                // Never write past the command's range: only `transfer_len`
                // bytes (bounded by the declared phase) are written; the
                // remainder is received and discarded (§3.8).
                let to_write = transfer_len.min(declared);
                let mut written = 0u64;
                let mut failed = false;
                if !immediate.is_empty() {
                    let w = (immediate.len() as u64).min(to_write) as usize;
                    if devs[lun].write_data(byte_offset, &immediate[..w]).is_err() {
                        failed = true;
                    } else {
                        written = w as u64;
                    }
                }
                let chunk = (declared as usize).min(data.len());
                self.state = BotState::DataOut {
                    declared,
                    to_write,
                    byte_offset,
                    received: written,
                    written,
                    tag: cbw.tag,
                    lun,
                    failed,
                    chunk,
                };
                BotStep::NeedOut {
                    len: chunk,
                    probe: false,
                }
            }
        }
    }

    /// Enter a Data-In phase for a response already synthesized into
    /// `data[0..available]` (REPORT LUNS, core-injected sense).
    fn synthesize_data_in<'a>(
        &'a mut self,
        cbw: &Cbw,
        data: &'a mut [u8],
        available: u64,
    ) -> BotStep<'a> {
        let declared = u64::from(cbw.data_len);
        let actual = available.min(declared);
        if actual == 0 {
            return self.finish_csw_bot(cbw.tag, declared, CswStatus::Passed);
        }
        let chunk = (actual as usize).min(data.len());
        self.state = BotState::DataIn {
            expected: declared,
            transfer_len: actual,
            byte_offset: 0,
            sent: chunk as u64,
            tag: cbw.tag,
            lun: usize::from(cbw.lun),
            chunk,
        };
        BotStep::NeedIn(&data[..chunk])
    }

    /// Assemble the CSW into the internal buffer and move to the CSW state.
    fn finish_csw_bot<'a>(&'a mut self, tag: u32, residue: u64, status: CswStatus) -> BotStep<'a> {
        let csw = Csw {
            tag,
            residue: residue as u32,
            status,
        };
        csw.write(&mut self.csw);
        self.state = BotState::Csw;
        BotStep::NeedIn(&self.csw[..])
    }

    // ── Data-In phase ───────────────────────────────────────────────

    fn poll_data_in<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: BotEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> BotStep<'a> {
        let st = self.state;
        let BotState::DataIn {
            expected,
            transfer_len,
            byte_offset,
            sent,
            tag,
            lun,
            chunk,
        } = st
        else {
            unreachable!("poll_data_in entered outside DataIn state")
        };
        match ev {
            BotEvent::InSent => {
                if sent >= transfer_len {
                    // Whole transfer sent: short/full packet + residue.
                    let residue = expected - transfer_len;
                    return self.finish_csw_bot(tag, residue, CswStatus::Passed);
                }
                let next = ((transfer_len - sent) as usize).min(data.len());
                if devs[lun]
                    .read_data(byte_offset + sent, &mut data[..next])
                    .is_err()
                {
                    let residue = expected - sent;
                    return self.finish_csw_bot(tag, residue, CswStatus::Failed);
                }
                self.state = BotState::DataIn {
                    expected,
                    transfer_len,
                    byte_offset,
                    sent: sent + next as u64,
                    tag,
                    lun,
                    chunk: next,
                };
                BotStep::NeedIn(&data[..next])
            }
            BotEvent::OutRecv { .. } | BotEvent::OutIdle => {
                // No-op: still need to send the pending chunk.
                BotStep::NeedIn(&data[..chunk])
            }
        }
    }

    // ── Data-Out phase ──────────────────────────────────────────────

    fn poll_data_out<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: BotEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> BotStep<'a> {
        let st = self.state;
        let BotState::DataOut {
            declared,
            to_write,
            byte_offset,
            received,
            written,
            tag,
            lun,
            failed,
            chunk,
        } = st
        else {
            unreachable!("poll_data_out entered outside DataOut state")
        };
        match ev {
            BotEvent::OutRecv { data: recv } => {
                let mut written = written;
                let mut failed = failed;
                if !failed && written < to_write {
                    let w = (recv.len() as u64).min(to_write - written) as usize;
                    if w > 0 {
                        if devs[lun]
                            .write_data(byte_offset + written, &recv[..w])
                            .is_ok()
                        {
                            written += w as u64;
                        } else {
                            failed = true;
                        }
                    }
                }
                let received = received + recv.len() as u64;
                if received >= declared {
                    let residue = declared - written;
                    let status = if failed {
                        CswStatus::Failed
                    } else {
                        CswStatus::Passed
                    };
                    if received > declared {
                        // Overshoot already consumed the excess: straight to CSW.
                        return self.finish_csw_bot(tag, residue, status);
                    }
                    // Exact end of the declared phase: probe for a host
                    // overrun (leftover bytes would corrupt the next CBW).
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue,
                        status,
                        chunk: data.len(),
                    };
                    return BotStep::NeedOut {
                        len: data.len(),
                        probe: true,
                    };
                }
                let next = ((declared - received) as usize).min(data.len());
                self.state = BotState::DataOut {
                    declared,
                    to_write,
                    byte_offset,
                    received,
                    written,
                    tag,
                    lun,
                    failed,
                    chunk: next,
                };
                BotStep::NeedOut {
                    len: next,
                    probe: false,
                }
            }
            BotEvent::OutIdle => {
                // Host paused mid phase: keep waiting for the chunk.
                BotStep::NeedOut {
                    len: chunk,
                    probe: false,
                }
            }
            BotEvent::InSent => BotStep::Done(BotStepResult::Error(BotTargetError::Internal)),
        }
    }

    // ── Data-Out overrun drain ──────────────────────────────────────

    fn poll_overrun<'a>(&'a mut self, ev: BotEvent<'_>) -> BotStep<'a> {
        let st = self.state;
        let BotState::DataOutOverrun {
            tag,
            residue,
            status,
            chunk,
        } = st
        else {
            unreachable!("poll_overrun entered outside DataOutOverrun state")
        };
        match ev {
            BotEvent::OutRecv { data } => {
                if data.len() < chunk {
                    // Short packet: leftover drained → CSW.
                    return self.finish_csw_bot(tag, residue, status);
                }
                // Full chunk: more leftover pending.
                self.state = BotState::DataOutOverrun {
                    tag,
                    residue,
                    status,
                    chunk,
                };
                BotStep::NeedOut {
                    len: chunk,
                    probe: true,
                }
            }
            BotEvent::OutIdle => self.finish_csw_bot(tag, residue, status),
            BotEvent::InSent => BotStep::Done(BotStepResult::Error(BotTargetError::Internal)),
        }
    }

    // ── CSW phase ───────────────────────────────────────────────────

    fn poll_csw<'a>(&'a mut self, ev: BotEvent<'_>) -> BotStep<'a> {
        match ev {
            BotEvent::InSent => {
                self.state = BotState::Command { got: 0 };
                BotStep::Done(BotStepResult::Processed)
            }
            BotEvent::OutRecv { .. } | BotEvent::OutIdle => BotStep::NeedIn(&self.csw[..]),
        }
    }
}

/// Build the REPORT LUNS response (SPC-4 §6.21) into `data`: 4-byte BE LUN
/// list length + 4 reserved bytes + 8-byte single-level LUN entries. Returns
/// the number of bytes written (clamped to `data.len()`).
///
/// The 4 reserved bytes keep the 8-byte entries 8-aligned, as required by
/// Linux's `scsi_report_lun_scan` (see the iSCSI target's comment).
fn write_report_luns(data: &mut [u8], num_luns: usize) -> usize {
    let list_len = u32::try_from(num_luns)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .unwrap_or(u32::MAX);
    let total = 8usize + (list_len as usize);
    let n = total.min(data.len());
    let entries = num_luns.min(n.saturating_sub(8) / 8);
    data[0..4].copy_from_slice(&list_len.to_be_bytes());
    data[4..n.min(8)].fill(0);
    for i in 0..entries {
        let off = 8 + i * 8;
        data[off] = 0x00; // address method 00b, bus id 0
        data[off + 1] = i as u8; // single-level LUN id
        data[off + 2..off + 8].fill(0);
    }
    n
}
