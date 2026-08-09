//! # SnowDrive — unified SCSI / iSCSI / ISO9660 toolkit.
//!
//! This is the `snowdrive` lib crate.  All functionality is gated by
//! Cargo features so the public surface matches the use case:
//!
//! | Use case | Required features |
//! |----------|-------------------|
//! | SCSI block device core | `scsi` |
//! | ISO9660 algorithm library | `iso9660` |
//! | iSCSI target over a TCP socket | `scsi`, `iscsi`, `std` |
//! | Flat CD-ROM device (`CdromDevice`) | `cdrom` (implies `scsi`) |
//! | Live ISO9660 CD-ROM (`CdLiveFsDevice`) | `livefs` (implies `cdrom`+`iso9660`) |
//! | C ABI exports | `capi` (implies `std`) |
//!
//! ## Modules
//! - [`common`]: zero-alloc storage seams + unified logging macros
//!   (always available, no feature gate).
//! - [`scsi`] *(gated by `scsi`)*: SCSI core, devices, iSCSI PDU + target.
//! - `iso9660` *(gated by `iso9660`)*: ISO9660/Joliet algorithms.
//! - `cdrom` *(gated by `cdrom`)*: CD-ROM device emulation (flat / live).
//! - `capi` *(gated by `capi`)*: C ABI exports (`#[allow(unsafe_code)]`).
//!
//! ## ISO9660 name limits
//! The live generator (`iso9660::live`) truncates Joliet identifiers
//! longer than [`iso9660::live::MAX_JOLIET_NAME_CHARS`] (default 32 UCS-2
//! chars) and accepts host paths up to
//! [`iso9660::live::MAX_PATH_LEN`] bytes. Both are public constants you
//! can raise when wider names are required.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod common;

#[cfg(feature = "cdrom")]
pub mod cdrom;
#[cfg(feature = "iscsi")]
pub mod iscsi;
#[cfg(feature = "iso9660")]
pub mod iso9660;
#[cfg(feature = "scsi")]
pub mod scsi;

/// Minimum work-buffer size: BHS (48) + MaxRecvDataSegmentLength (8192) +
/// padding (≤ 3) = 8240 (derived in the plan; see also the iSCSI target
/// state machine). Any `&mut [u8]` passed to `do_cmd` / `step` must be
/// at least this long.
pub const MIN_WORK_LEN: usize = 48 + 8192;
