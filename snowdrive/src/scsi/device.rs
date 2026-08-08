//! Device abstraction: result outcomes and device types (device.h).
//!
//! The SCSI device seam ([`ScsiDevice`]) and the [`Device`] enum live in
//! `device.rs` until the rest of the leaf `snowscsi` crate is folded in.
//! Once `block` and `cdblock` are in place, this file will grow the
//! `ScsiDevice` trait and the `Device<'a>` enum.

use crate::scsi::scsi::Sense;

/// Device type reported via INQUIRY (device.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Block,
    Cdrom,
}

impl DeviceType {
    /// Peripheral device type byte (INQUIRY byte 0, bits 0-4, SPC-4 §6.4.1).
    pub fn pdt(&self) -> u8 {
        match self {
            Self::Block => 0x00,
            Self::Cdrom => 0x05,
        }
    }
}

/// Outcome of processing one SCSI command (C `snowscsi_result_t`, device.h).
///
/// Borrowed, zero-alloc: the device never holds a cross-command buffer.
/// For `DataIn` / `DataOut`, `transfer_len` is the whole-transfer byte
/// count and `byte_offset` is the backing-store byte offset
/// (= LBA × sector_size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome<'a> {
    /// No data phase, command succeeded (GOOD).
    Status,
    /// Device → host. `immediate` is empty for backend reads (READ*):
    /// the target reads `transfer_len` bytes from the backend at
    /// `byte_offset`. Non-empty `immediate` (INQUIRY, MODE SENSE, ...)
    /// is a synthesized response already placed at work[48..48+len].
    DataIn {
        transfer_len: u64,
        byte_offset: u64,
        immediate: &'a [u8],
    },
    /// Host → device: write `transfer_len` bytes starting at `byte_offset`.
    /// `immediate` borrows the caller's work buffer (already-received data).
    DataOut {
        transfer_len: u64,
        byte_offset: u64,
        immediate: &'a [u8],
    },
    /// Command failed, sense data in `Sense`.
    CheckCondition(Sense),
}

/// Core command-processing error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Caller's work buffer is smaller than [`crate::MIN_WORK_LEN`].
    WorkBufTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "work buffer smaller than MIN_WORK_LEN"),
        }
    }
}

impl core::error::Error for Error {}
