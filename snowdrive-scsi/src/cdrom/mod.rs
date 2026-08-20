//! CD-ROM device emulation.
//!
//! The optical-media device layer, independent of the SCSI block stack.
//! All MMC commands are dispatched through [`CdromDrive`]; media types
//! only provide geometry and a data plane.

pub mod common;
pub mod drive;
pub mod media;
#[cfg(feature = "udf_void")]
pub mod udfrw;

pub use common::{
    build_get_config_response, build_read_buffer_capacity, build_read_disc_info, CdromCapabilities,
    CurrentProfile, DiscInfo, CDROM_IDENTITY, SECTOR_SIZE,
};
pub use drive::CdromDrive;
pub use media::{
    CdLiveFsError, CdMedia, FlatData, FlatMedia, LiveData, LiveDataBuilder, MediaError,
};
#[cfg(feature = "udf_void")]
pub use udfrw::{UdfRwError, UdfRwMedia};
