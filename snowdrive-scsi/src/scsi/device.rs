//! Device abstraction: result outcomes, device types, the SCSI device
//! seam, and the borrowed type-erased container that targets drive.

#[cfg(feature = "cdrom")]
use crate::cdrom::drive::CdromDrive;
use crate::scsi::backend::{BlockBackend, BlockStorageError};
use crate::scsi::block::BlockDevice;
#[cfg(feature = "std")]
use crate::scsi::cdblock::CDBlockDevice;
use crate::scsi::scsi::{asc, Sense, SenseKey};

/// Device type reported via INQUIRY (device.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Block,
    Cdrom,
}

impl DeviceType {
    /// Peripheral device type byte (INQUIRY byte 0, bits 0-4, SPC-4 §6.4.1).
    pub fn pdt(&self) -> u8 {
        match self {
            Self::Block => 0x00,
            Self::Cdrom => 0x05,
        }
    }
}

/// Outcome of processing one SCSI command (C `snowscsi_result_t`, device.h).
///
/// Borrowed, zero-alloc: the device never holds a cross-command buffer.
/// For `DataIn` / `DataOut`, `transfer_len` is the whole-transfer byte
/// count and `byte_offset` is the backing-store byte offset
/// (= LBA × sector_size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome<'a> {
    /// No data phase, command succeeded (GOOD).
    Status,
    /// Device → host. `immediate` is empty for backend reads (READ*):
    /// the target reads `transfer_len` bytes from the backend at
    /// `byte_offset`. Non-empty `immediate` (INQUIRY, MODE SENSE, ...)
    /// is a synthesized response already placed at `data[0..len]`.
    DataIn {
        transfer_len: u64,
        byte_offset: u64,
        immediate: &'a [u8],
    },
    /// Host → device: write `transfer_len` bytes starting at `byte_offset`.
    /// `immediate` borrows the caller's data buffer (already-received data).
    DataOut {
        transfer_len: u64,
        byte_offset: u64,
        immediate: &'a [u8],
    },
    /// Command failed, sense data in `Sense`.
    CheckCondition(Sense),
    /// Host → device: parameter list (MODE SELECT, FORMAT UNIT, …).
    /// `expected_len` is the total parameter length the device expects
    /// (from the CDB's allocation field); `immediate` is the already
    /// received prefix borrowed from `data[0..dsl]`. The transport must
    /// receive the remaining `expected_len - immediate.len()` bytes via
    /// its Data-Out phase (iSCSI R2T / USB bulk OUT) and then call
    /// [`ScsiDevice::complete_param`].
    ParamOut {
        expected_len: usize,
        immediate: &'a [u8],
    },
}

/// Core command-processing error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Caller's data buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "data buffer smaller than MIN_DATA_LEN"),
        }
    }
}

impl core::error::Error for Error {}

/// Data-area capacity of a transport scratch buffer, rounded down to a
/// 4-byte multiple.
///
/// Each transport derives its usable data region from its own framing:
/// - iSCSI: `data_capacity(work.len() - BHS_SIZE)` — the PDU data segment
///   must keep `48 + dsl` 4-byte aligned so padding stays zero and
///   `send_pdu`'s `total + pad <= work.len()` invariant holds.
/// - USB MSC: the whole buffer is the data area (`data_capacity(work.len())`),
///   the alignment is a harmless chunk-granularity nicety.
pub fn data_capacity(work_len: usize) -> usize {
    work_len & !3
}

/// The SCSI device seam: the minimal command set the iSCSI target needs from
/// any device. The target is generic over `D: ScsiDevice`, so it can serve a
/// homogeneous `&mut [BlockDevice<B>]` or a heterogeneous `&mut [Device<'_>]`
/// equally.
pub trait ScsiDevice {
    /// Process one SCSI command. `data` must be at least
    /// [`crate::MIN_DATA_LEN`] bytes; `dsl` is the length of data already
    /// received into `data[0..dsl]`.
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error>;

    /// Read `buf.len()` bytes from the backing store at `byte_offset`
    /// (the READ data path — `CommandOutcome::DataIn` with empty
    /// `immediate`).
    fn read_data(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError>;

    /// Write `buf` to the backing store at `byte_offset`
    /// (the WRITE data path — `CommandOutcome::DataOut`).
    fn write_data(&mut self, byte_offset: u64, buf: &[u8]) -> Result<(), BlockStorageError>;

    fn sense(&self) -> &Sense;

    fn device_type(&self) -> DeviceType;

    /// Complete a parameter-list Data-Out phase (`ParamOut`).
    ///
    /// `cdb` is the original CDB, `data` the full parameter list
    /// (`expected_len` bytes) already collected in the transport's
    /// work buffer. Returns `Status` on success or `CheckCondition`.
    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome<'static> {
        let _ = (cdb, data);
        CommandOutcome::CheckCondition(Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0))
    }
}

/// Borrowed, type-erased device container.
///
/// The `'a` lifetime unifies the RAM disk-image borrow across variants
/// (`Block` wraps `BlockBackend<'a>`), so mock stack RAM and CLI owned
/// `Vec<u8>` images enter the enum without `'static` or `Box::leak`.
///
/// The variants differ in size (`CdLiveFsDevice` embeds a live layout plus
/// open handles). This is deliberate: the plan mandates a zero-alloc,
/// no-boxing container whose arms monomorphize per device (§3.4) — the enum
/// is a borrowed convenience type for desktop/CLI setups, never moved
/// around by the target hot path.
#[allow(clippy::large_enum_variant)]
pub enum Device<'a> {
    Block(BlockDevice<BlockBackend<'a>>),
    #[cfg(feature = "std")]
    CdBlock(CDBlockDevice),
    /// Unified CD-ROM device with swappable media.
    #[cfg(feature = "cdrom")]
    Cdrom(CdromDrive<'a>),
}

impl ScsiDevice for Device<'_> {
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        match self {
            Self::Block(dev) => dev.do_cmd(cdb, data, dsl),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.do_cmd(cdb, data, dsl),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.do_cmd(cdb, data, dsl),
        }
    }

    fn read_data(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Block(dev) => dev.read_data(byte_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.read_data(byte_offset, buf),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.read_data(byte_offset, buf),
        }
    }

    fn write_data(&mut self, byte_offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Block(dev) => dev.write_data(byte_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.write_data(byte_offset, buf),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.write_data(byte_offset, buf),
        }
    }

    fn sense(&self) -> &Sense {
        match self {
            Self::Block(dev) => dev.sense(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.sense(),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.sense(),
        }
    }

    fn device_type(&self) -> DeviceType {
        match self {
            Self::Block(dev) => dev.device_type(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => <CDBlockDevice as ScsiDevice>::device_type(dev),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => <CdromDrive<'_> as ScsiDevice>::device_type(dev),
        }
    }

    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome<'static> {
        match self {
            Self::Block(dev) => dev.complete_param(cdb, data),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.complete_param(cdb, data),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.complete_param(cdb, data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;
    use crate::scsi::scsi::op;
    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    #[test]
    fn data_capacity_aligns_down_to_4_bytes() {
        assert_eq!(data_capacity(8192), 8192);
        assert_eq!(data_capacity(8190), 8188);
        assert_eq!(data_capacity(8240), 8240);
        assert_eq!(data_capacity(262144 - 48), 262096);
        assert_eq!(data_capacity(0), 0);
    }

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
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x00);
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
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x05);
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        assert_eq!(
            dev.write_data(0, &[0u8; 4]),
            Err(BlockStorageError::NotWritable)
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "cdrom")]
    #[test]
    fn device_enum_cdrom_dispatch() {
        use crate::cdrom::drive::CdromDrive;
        use crate::cdrom::media::{CdMedia, FlatMedia};
        use crate::scsi::backend::RamBackend;
        let mut img = vec![0xAAu8; 2048 * 100];
        let backend = BlockBackend::Ram(RamBackend::new(&mut img));
        let flat = FlatMedia::new(backend, crate::cdrom::common::CurrentProfile::CdRom);
        let mut drive = CdromDrive::new();
        drive.load(CdMedia::Flat(flat));
        let mut dev = Device::Cdrom(drive);
        let mut w = work();
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x05);
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        // Data path reads through the backend.
        let mut buf = [0u8; 4];
        dev.read_data(0, &mut buf).unwrap();
        assert_eq!(buf, [0xAA; 4]);
        assert_eq!(
            dev.write_data(0, &[0u8; 4]),
            Err(BlockStorageError::NotWritable)
        );
    }

    #[cfg(all(feature = "livefs", feature = "std"))]
    #[test]
    fn device_enum_cdlivefs_dispatch() {
        use crate::cdrom::drive::CdromDrive;
        use crate::cdrom::media::{CdMedia, FlatMedia, LiveData};
        use crate::scsi::fs_backend::StdFsBackend;
        let dir =
            std::env::temp_dir().join(format!("snowscsi_device_livefs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();
        let fs = StdFsBackend::new(&dir.to_str().unwrap());
        let live = LiveData::new(fs, "TEST").unwrap();
        let flat = FlatMedia::new(live, crate::cdrom::common::CurrentProfile::CdRom);
        let mut drive = CdromDrive::new();
        drive.load(CdMedia::Live(Box::new(flat)));
        let mut dev = Device::Cdrom(drive);
        let mut w = work();
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x05);
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        // File data is reachable through the virtual disc (first file extent).
        let first = match &mut dev {
            Device::Cdrom(inner) => {
                if let Some(crate::cdrom::media::CdMedia::Live(ref mut m)) = inner.media {
                    m.data()
                        .layout()
                        .extents
                        .first()
                        .expect("DATA.BIN extent")
                        .lba
                } else {
                    unreachable!("expected Live variant")
                }
            }
            _ => unreachable!("Cdrom variant"),
        };
        let mut buf = [0u8; 2048];
        dev.read_data(u64::from(first) * 2048, &mut buf).unwrap();
        assert_eq!(&buf[..4], &[0x42; 4]);
        assert_eq!(
            dev.write_data(0, &[0u8; 4]),
            Err(BlockStorageError::NotWritable)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
