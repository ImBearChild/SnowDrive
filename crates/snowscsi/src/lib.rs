#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! SCSI device emulation + iSCSI target protocol.
//!
//! ## Modules
//! - [`scsi`]: opcodes, sense data, CDB field parsing (SPC-4 / SBC-3)
//! - [`device`]: command outcome + device types (device.h)
//! - [`backend`]: file block backend + re-exports of the storage seam
//!   (`BlockStorage` / `BlockStorageError` / `RamBackend` live in
//!   `snowcommon::block_storage`)
//! - [`spc`]: SPC command parsing + shared execution (INQUIRY, MODE SENSE, ...)
//! - [`block`]: SBC block device command set (block.c)
//! - [`iscsi_pdu`]: iSCSI PDU (BHS) field codec (RFC 3720 §10.x)
//! - [`conn`]: connection abstraction (`embedded_io::Read + Write`)
//! - [`transport`]: BSD TCP transport (`std` feature only)
//! - [`iscsi_target`]: iSCSI target session state machine (RFC 3720 §5/§10)
//!
//! ## Features
//! - `std` (default): enables BSD transport (TcpStream), FileBackend

pub mod backend;
pub mod block;
pub mod conn;
pub mod device;
pub mod iscsi_pdu;
pub mod iscsi_target;
pub mod scsi;
pub mod spc;
#[cfg(feature = "std")]
pub mod transport;

pub use backend::{BlockStorage, BlockStorageError, RamBackend};
pub use block::Device;
pub use conn::Conn;
pub use device::{CommandOutcome, DeviceType, Error};
pub use iscsi_pdu::{cdb_len_from_opcode, iscsi_opcode_name, pdu_pad_len, Bhs};
pub use iscsi_target::{
    serve_conn, LoginStage, NegotiatedParams, Session, StepResult, TargetError,
};
pub use scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, opcode_name, Sense, SenseKey,
};
pub use spc::{execute_spc, parse_spc, DeviceIdentity, SpcCommand, SpcDevice, SpcEffect};
#[cfg(feature = "std")]
pub use transport::{serve, TcpConn};

pub const MIN_WORK_LEN: usize = 48 + 8192;

pub use snowcommon;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
