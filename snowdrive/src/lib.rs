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
//! longer than [`iso9660::live::MAX_JOLIET_NAME_CHARS`] (default 64 UCS-2
//! chars, the Annex J Level 1 limit) and accepts host paths up to
//! [`iso9660::live::MAX_PATH_LEN`] bytes. Both are public constants you
//! can raise when wider names are required.

// The no_std contract applies to production code (embedded consumers).
// The test harness runs on the host, so the crate is allowed to use std
// under `cfg(test)` — test modules keep full std access (Vec, format!, ...).
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
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

/// Minimum data-area size for `ScsiDevice::do_cmd`: 8192 bytes
/// (= MaxRecvDataSegmentLength). The `data` argument is a pure data
/// region, transport-layout independent (each transport derives its own
/// scratch buffer from it — iSCSI prepends its 48-byte BHS, USB MSC uses
/// it directly). Any `&mut [u8]` passed as `data` to `do_cmd` must be at
/// least this long.
pub const MIN_DATA_LEN: usize = 8192;
