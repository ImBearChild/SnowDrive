//! Thin re-export of the SBC block device moved into the unified
//! `snowdrive` lib crate.  The actual code lives at
//! `snowdrive::scsi::block::*`; this shim keeps the existing
//! `crate::block::*` imports in the still-to-be-migrated `snowscsi`
//! crate working.

pub use snowdrive::scsi::block::*;
