#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! SCSI device emulation + iSCSI target protocol.
//!
//! ## Modules
//! - [`scsi`]: opcodes, sense data, CDB field parsing (SPC-4 / SBC-3)
//! - [`device`]: command outcome + device types (device.h)
//! - [`backend`]: block storage backends (RAM + file), no_std error type
//!
//! ## Features
//! - `std` (default): enables BSD transport (TcpStream), FileBackend

pub mod backend;
pub mod device;
pub mod scsi;

pub use backend::{BlockBackend, BlockBackendError, RamBackend};
pub use device::{CommandOutcome, DeviceType};
pub use scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, opcode_name, Sense, SenseKey,
};

pub const MIN_WORK_LEN: usize = 48 + 8192;

pub use snowcommon;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
