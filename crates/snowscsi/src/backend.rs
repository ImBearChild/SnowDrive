//! Thin re-export of the block storage backends moved into the unified
//! `snowdrive` lib crate.  The actual code now lives at
//! `snowdrive::scsi::backend::*`; this shim keeps the existing
//! `crate::backend::{BlockStorage, ...}` imports in the still-to-be-
//! migrated `snowscsi` crate working.

pub use snowdrive::scsi::backend::*;
