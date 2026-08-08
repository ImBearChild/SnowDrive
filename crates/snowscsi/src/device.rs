//! Re-exports the simple types from the unified `snowdrive` lib and keeps
//! the legacy `Device<'_>` enum (which depends on `cdblock`, still in the
//! legacy crate) until the rest of `snowscsi` is folded in.

pub use snowdrive::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice};

use crate::backend::{BlockBackend, BlockStorageError};
use crate::block::BlockDevice;
#[cfg(feature = "std")]
use crate::cdblock::CDBlockDevice;
use crate::scsi::Sense;

/// Borrowed, type-erased device container.
///
/// The `'a` lifetime unifies the RAM disk-image borrow across variants
/// (`Block` wraps `BlockBackend<'a>`), so mock stack RAM and CLI owned
/// `Vec<u8>` images enter the enum without `'static` or `Box::leak`.
/// Variants grow with Phase 2 (CdFlat / CdLiveFs) and Phase 3 (CdBundle).
pub enum Device<'a> {
    Block(BlockDevice<BlockBackend<'a>>),
    #[cfg(feature = "std")]
    CdBlock(CDBlockDevice),
}

impl ScsiDevice for Device<'_> {
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        match self {
            Self::Block(dev) => dev.do_cmd(cdb, work, dsl),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.do_cmd(cdb, work, dsl),
        }
    }

    fn read_data(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Block(dev) => dev.read_data(byte_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.read_data(byte_offset, buf),
        }
    }

    fn write_data(&mut self, byte_offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Block(dev) => dev.write_data(byte_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.write_data(byte_offset, buf),
        }
    }

    fn sense(&self) -> &Sense {
        match self {
            Self::Block(dev) => dev.sense(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.sense(),
        }
    }

    fn device_type(&self) -> DeviceType {
        match self {
            Self::Block(dev) => dev.device_type(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => <CDBlockDevice as ScsiDevice>::device_type(dev),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RamBackend;
    use crate::scsi::op;
    fn work() -> [u8; crate::MIN_WORK_LEN] {
        [0u8; crate::MIN_WORK_LEN]
    }

    /// Run INQUIRY through the enum and return the first DataIn byte (PDT).
    fn inquiry_pdt(dev: &mut Device<'_>, w: &mut [u8]) -> u8 {
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        match dev.do_cmd(&cdb, w, 0).unwrap() {
            CommandOutcome::DataIn { immediate, .. } => immediate[0],
            _ => panic!("expected DataIn"),
        }
    }

    #[test]
    fn device_enum_block_dispatch() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut dev = Device::Block(
            BlockDevice::new(BlockBackend::Ram(RamBackend::new(&mut ram)), 512).unwrap(),
        );
        let mut w = work();
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x00); /* disk */
        assert_eq!(dev.device_type(), DeviceType::Block);
        assert!(dev.write_data(0, &[0u8; 4]).is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn device_enum_cdblock_dispatch() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_device_cdblock_{}.iso",
            std::process::id()
        ));
        std::fs::write(&path, vec![0u8; 2048 * 100]).unwrap();
        let dev = CDBlockDevice::new(path.to_str().unwrap()).unwrap();
        let mut dev = Device::CdBlock(dev);
        let mut w = work();
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x05); /* CD-ROM */
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        assert_eq!(
            dev.write_data(0, &[0u8; 4]),
            Err(BlockStorageError::NotWritable)
        );
        std::fs::remove_file(&path).unwrap();
    }
}
