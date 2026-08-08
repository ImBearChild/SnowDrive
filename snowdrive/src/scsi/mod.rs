//! SCSI core + devices (plan §3 / §5).
//!
//! ## Modules (filled in as the leaf `snowscsi` crate is folded in)
//! - [`scsi`]: opcodes, sense data, CDB field parsing (SPC-4 / SBC-3 /
//!   MMC-6).  No dependencies on the rest of the crate.
//! - [`device`]: command outcome + device types (device.h).
//! - `backend`: `FileBackend` + the aggregating `BlockBackend` enum
//!   (gated by `std`).
//! - `fs_backend`: `StdFsBackend` + `FsBackend` enum (gated by `std`).
//! - `spc`: SPC command parsing + shared execution (INQUIRY, MODE SENSE, ...).
//! - `sbc`: SBC command parsing + execution (block device set, SBC-3 §5).
//! - `block`: SBC block device command set (block.c).
//! - `cdblock`: CDBlock device — read-only CD-ROM over a flat file
//!   (gated by `std`).
//! - `cdrom_common`: shared CD-ROM SPC/MMC layer.
//! - `cdrom`: `CdromDevice<B>` — flat ISO/RAM CD-ROM (gated by `cdrom`).
//! - `iscsi_pdu`: iSCSI PDU (BHS) field codec (RFC 3720 §10.x).
//! - `conn`: connection abstraction (`embedded_io::Read + Write`).
//! - `iscsi_target`: iSCSI target session state machine (RFC 3720 §5/§10).
//! - `transport`: BSD TCP transport (gated by `std`).

pub mod backend;
pub mod device;
#[allow(clippy::module_inception)]
pub mod scsi;
