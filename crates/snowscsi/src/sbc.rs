//! Thin re-export of the SBC command layer moved into the unified
//! `snowdrive` lib crate.  The actual code lives at
//! `snowdrive::scsi::sbc::*`; this shim keeps the existing
//! `crate::sbc::*` imports in the still-to-be-migrated `snowscsi`
//! crate working.

pub use snowdrive::scsi::sbc::*;
