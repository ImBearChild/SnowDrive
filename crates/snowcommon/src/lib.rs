//! Thin re-export shim for the unified `snowdrive` lib crate (plan §15.7).
//!
//! All storage seams and logging macros were moved into
//! `snowdrive::common::*` in P0.2.  The old `snowcommon` package is kept
//! as a workspace member so the still-to-be-migrated `snowscsi` crate
//! can keep its `use snowcommon::block_storage::*` and similar imports.
//! This shim will be deleted in P0.8 once `snowscsi` itself has been
//! folded into `snowdrive::scsi`.

pub use snowdrive::common::block_storage;
pub use snowdrive::common::fs_storage;
pub use snowdrive::common::logging;

pub use snowdrive::common::block_storage::{BlockStorage, BlockStorageError, RamBackend};
pub use snowdrive::common::fs_storage::{DirEntry, FileHandle, FsError, FsStorage, OpenOptions};

pub use snowdrive::{debug, error, info, trace, warn};
