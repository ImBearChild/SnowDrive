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
    CurrentProfile, DiscInfo, MediaState, CDROM_IDENTITY, HYPER_MULTI_CAPS, SECTOR_SIZE,
    UDFRW_CAPS,
};
pub use drive::CdromDrive;
pub use media::{CdLiveFsError, CdMedia, FlatMedia, LiveData, LiveDataBuilder, MediaError, Tray};
pub use snowdrive_common::block_storage::FlatData;
#[cfg(feature = "udf_void")]
pub use udfrw::{UdfRwError, UdfRwMedia};
