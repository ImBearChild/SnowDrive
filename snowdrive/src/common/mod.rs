//! #![no_std] zero-alloc utilities shared across the `snowdrive` lib crate.
//!
//! Originally the `snowcommon` crate; merged into the unified `snowdrive`
//! lib (plan §15.7 P0.2).  Always available — the `common` module has no
//! feature gate (the storage seams here are depended on by every other
//! module that wants a `BlockStorage` / `FsStorage` implementation).
//!
//! ## Modules
//! - [`block_storage`]: random-access block storage seam (`BlockStorage`
//!   trait + error + [`RamBackend`]) — implementable by embedded drivers.
//! - [`fs_storage`]: file/directory storage seam (`FsStorage` trait +
//!   error + [`FileHandle`]) — for CD-ROM bundle / live FS.
//! - [`logging`]: the unified `trace!`/`debug!`/`info!`/`warn!`/`error!`
//!   macros dispatching to either the `log` crate or `defmt`, depending
//!   on which Cargo feature is enabled (the two are mutually exclusive).

pub mod block_storage;
pub mod fs_storage;
pub mod logging;
