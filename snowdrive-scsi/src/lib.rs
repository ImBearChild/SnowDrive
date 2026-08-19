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
pub const MIN_DATA_LEN: usize = 8192;
