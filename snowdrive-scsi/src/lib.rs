//! SnowDrive SCSI: core + iSCSI + USB MSC + CD-ROM device emulation.
//!
//! This is the main API surface of the SnowDrive workspace — a SCSI
//! device-emulation toolkit (iSCSI target, USB MSC gadget, virtual
//! disks/optical drives) built on zero-alloc, `no_std`-clean seams.
//!
//! # Workspace map
//!
//! - **this crate** — SPC/SBC/MMC command layers, `BlockDevice` /
//!   [`CdromDrive`](cdrom::CdromDrive), iSCSI target (`iscsi`),
//!   USB BOT core (`usb`), UDF skeleton ([`udf_void`]).
//! - [`snowdrive_common`] — the storage seams everything is written
//!   against: the capability ladder
//!   [`common::block_storage::FlatData`] →
//!   [`common::block_storage::WritableFlatData`] →
//!   [`common::block_storage::BlockStorage`], the FS seam
//!   [`common::fs_storage::FsStorage`], and the unified logging macros.
//! - [`snowdrive_disc`] — ISO9660 + Joliet live generation
//!   ([`LiveData`](snowdrive_disc::live::LiveData),
//!   [`compute_layout`](snowdrive_disc::live::compute_layout)).
//! - `snowdrive-cli` (no docs; a thin binary shell) — the `snowdrive`
//!   executable: `serve` and `mkisofs`.
//!
//! Start at [`scsi::device::ScsiDevice`] (the LUN seam every transport
//! drives), [`scsi::block::BlockDevice`] (disk/CD-ROM profiles over any
//! byte plane) or [`iscsi::target::IscsiSession`] /
//! [`usb::BotSession`] (the two transports). Each subsystem's module docs
//! carry runnable examples: [`iscsi`], [`usb`], and — behind the `cdrom`
//! feature — [`cdrom`].

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub use snowdrive_common as common;
pub use snowdrive_common::{debug, error, info, trace, warn};

pub mod scsi;

#[cfg(feature = "cdrom")]
pub mod cdrom;

#[cfg(feature = "iscsi")]
pub mod iscsi;

#[cfg(feature = "usb")]
pub mod usb;

#[cfg(feature = "udf_void")]
pub mod udf_void;

/// Minimum data-area size for `ScsiDevice::do_cmd`: 8192 bytes.
///
/// Every command-processing entry point (`do_cmd`, `poll`, `step`) takes a
/// caller-provided scratch buffer and rejects smaller ones at runtime with
/// `WorkBufTooSmall`. Total RAM budget for one transport + LUN set:
///
/// | Component | Size |
/// |-----------|------|
/// | SCSI data area (`data` / work buffer data region) | ≥ [`MIN_DATA_LEN`] |
/// | iSCSI: PDU header prefix in front of the data area | `BHS_SIZE` (48 B) |
/// | USB BOT: separate driver receive scratch | ≥ `data.len()` |
/// | Session state (`IscsiSession` / `BotSession`) | few hundred bytes each |
///
/// See `ScsiDevice` for the full contract.
pub const MIN_DATA_LEN: usize = 8192;
