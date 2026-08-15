//! CD-ROM device emulation (plan §8.2).
//!
//! The optical-media device layer, independent of the SCSI block stack
//! (`snowdrive::scsi`): SPC commands are delegated to `snowdrive::scsi::spc`,
//! MMC commands (READ TOC, GET CONFIGURATION, READ BUFFER CAPACITY, ...) are
//! handled here.  The goal is an MMC surface complete enough for optical
//! tooling (cdrwtool, cdrdao, ...) — unlike `snowdrive::scsi::cdblock`, which
//! is a deliberately minimal, self-contained block-only CD-ROM in the SCSI
//! core (no filesystem backend, no external deps) and does not chase burner
//! tools. Use this module when a full MMC command set is required.
//!
//! ## Modules
//! - [`common`]: shared SPC-level state + mode pages for every CD-ROM device.
//! - [`device`]: `CdromDevice<B>` — flat ISO/RAM CD-ROM over any
//!   [`BlockStorage`](crate::scsi::backend::BlockStorage).
//! - `livefs` *(gated by `livefs`)*: `CdLiveFsDevice<F>` — live ISO9660
//!   CD-ROM over a host directory (`FsStorage`).
//!
//! ## Features
//! - `cdrom` — flat device (`common` + `device`), implies `scsi`.
//! - `livefs` — live device, implies `cdrom` + `iso9660`.

pub mod common;
pub mod device;
#[cfg(feature = "livefs")]
pub mod livefs;
#[cfg(feature = "udf_void")]
pub mod udfrw;

pub use common::{
    build_get_config_response, CdromDeviceCommon, CurrentProfile, CDROM_IDENTITY, SECTOR_SIZE,
};
pub use device::CdromDevice;
#[cfg(feature = "livefs")]
pub use livefs::CdLiveFsDevice;
#[cfg(feature = "udf_void")]
pub use udfrw::{UdfRwError, UdfRwMedia};
