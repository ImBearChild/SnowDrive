//! # SnowDrive — unified SCSI / iSCSI / ISO9660 toolkit.
//!
//! This is the `snowdrive` lib crate (plan §15.7).  All functionality is
//! gated by Cargo features so the public surface matches the use case:
//!
//! | Use case | Required features |
//! |----------|-------------------|
//! | SCSI block device core | `scsi` |
//! | ISO9660 algorithm library | `iso9660` |
//! | iSCSI target over a TCP socket | `scsi`, `iscsi`, `std` |
//! | CD-ROM device (flat / live / bundle) | `cdrom` (implies `scsi`+`iso9660`) |
//! | C ABI exports | `capi` (implies `std`) |
//!
//! No module is declared yet — each P0.* step moves one crate in.  This
//! skeleton exists only to claim the `snowdrive` package name and lock
//! down the feature map.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
