//! Device abstraction: result outcomes, device types, and the SCSI
//! device seam (device.h).
//!
//! The [`Device<'_>`] enum (the borrowed, type-erased container that
//! targets drive) lands here in a later commit once `cdblock` is in
//! place.  Only the trait ([`ScsiDevice`]) + the simple types move now.

use crate::scsi::backend::BlockStorageError;
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

/// The SCSI device seam: the minimal command set the iSCSI target needs from
/// any device. The target is generic over `D: ScsiDevice`, so it can serve a
/// homogeneous `&mut [BlockDevice<B>]` or a heterogeneous `&mut [Device<'_>]`
/// equally.
pub trait ScsiDevice {
    /// Process one SCSI command. `work` must be at least
    /// [`crate::MIN_WORK_LEN`] bytes; `dsl` is the length of data already
    /// received into `work[48..48+dsl]`.
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error>;

    /// Read `buf.len()` bytes from the backing store at `byte_offset`
    /// (the READ data path — `CommandOutcome::DataIn` with empty
    /// `immediate`).
    fn read_data(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError>;

    /// Write `buf` to the backing store at `byte_offset`
    /// (the WRITE data path — `CommandOutcome::DataOut`).
    fn write_data(&mut self, byte_offset: u64, buf: &[u8]) -> Result<(), BlockStorageError>;

    fn sense(&self) -> &Sense;

    fn device_type(&self) -> DeviceType;
}
