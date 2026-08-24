//! SnowDrive SCSI: core + iSCSI + USB MSC + CD-ROM device emulation.

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
