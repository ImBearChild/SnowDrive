//! Thin re-export of the SPC command layer moved into the unified
//! `snowdrive` lib crate.  The actual code lives at
//! `snowdrive::scsi::spc::*`; this shim keeps the existing
//! `crate::spc::*` imports in the still-to-be-migrated `snowscsi`
//! crate working.

pub use snowdrive::scsi::spc::*;
