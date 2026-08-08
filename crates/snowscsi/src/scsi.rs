//! Thin re-export of the SCSI core moved into the unified `snowdrive`
//! lib crate.  All public items live at `snowdrive::scsi::scsi::*`; this
//! file is kept as a single `pub use` line so the still-to-be-migrated
//! `snowscsi` crate keeps its `crate::scsi::op`, `crate::scsi::Sense`,
//! etc. imports until the rest of the crate is folded in.

pub use snowdrive::scsi::scsi::*;
