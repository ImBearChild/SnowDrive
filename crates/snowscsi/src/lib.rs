#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! SCSI device emulation + iSCSI target protocol.
//!
//! ## Features
//! - `std` (default): enables BSD transport (TcpStream) and FileBackend

pub const MIN_WORK_LEN: usize = 48 + 8192;

pub use snowcommon;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
