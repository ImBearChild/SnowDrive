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
//! | CD-ROM device (flat / live / bundle) | `cdrom` (implies `scsi`+`iso9660`) |
//! | C ABI exports | `capi` (implies `std`) |
//!
//! ## Modules
//! - [`common`]: zero-alloc storage seams + unified logging macros
//!   (always available, no feature gate).
//! - [`scsi`] *(gated by `scsi`)*: SCSI core, devices, iSCSI PDU + target.
//! - `iso9660` *(gated by `iso9660`)*: ISO9660/Joliet algorithms.
//! - `capi` *(gated by `capi`)*: C ABI exports (`#[allow(unsafe_code)]`).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod common;
#[cfg(feature = "scsi")]
pub mod scsi;
