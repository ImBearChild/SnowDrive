//! Thin re-export of the CDBlock device moved into the unified
//! `snowdrive` lib crate.  The actual code lives at
//! `snowdrive::scsi::cdblock::*`; this shim keeps the existing
//! `crate::cdblock::*` imports in the still-to-be-migrated `snowscsi`
//! crate working.

pub use snowdrive::scsi::cdblock::*;
