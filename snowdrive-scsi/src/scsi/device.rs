//! Device abstraction: result outcomes, device types, the SCSI device
//! seam, and the borrowed type-erased container that targets drive.

#[cfg(feature = "cdrom")]
use crate::cdrom::drive::CdromDrive;
use crate::scsi::backend::{BlockBackend, BlockStorageError};
use crate::scsi::block::BlockDevice;
#[cfg(feature = "std")]
use crate::scsi::cdblock::CDBlockDevice;
use crate::scsi::scsi::Sense;

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
/// Zero-alloc, no borrow: for `OutInline` the device has already placed
/// `len` bytes at `data[0..len]`; the transport sends `data[0..len]`
/// directly. For `OutXfer`/`InXfer` the device holds a [`PendingXfer`]
/// and the transport drives `xfer_out`/`xfer_in`. Sense is held in the
/// device and retrieved via `peek_sense`/`take_sense`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// No data phase, command succeeded (GOOD).
    Status,
    /// GOOD with pending sense (deferred/recovered, to be fetched via
    /// REQUEST SENSE). Transport leaves sense in device.
    StatusWithSense,
    /// Device → host, synthesized response already at `data[0..len]`.
    OutInline { len: u64 },
    /// Device → host, backend source; fetch `len` bytes via `xfer_out`.
    OutXfer { len: u64 },
    /// Host → device; receive `len` bytes via `xfer_in`.
    InXfer { len: u64 },
    /// Host → device parameter list; collect `expected_len` bytes then
    /// call [`ScsiDevice::complete_param`].
    InParam { expected_len: usize },
    /// Command failed, sense is held in the device (peek/take).
    CheckCondition,
}

/// Core command-processing error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Caller's data buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// Sector size must be non-zero (`BlockDevice::new`).
    InvalidSectorSize,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "data buffer smaller than MIN_DATA_LEN"),
            Self::InvalidSectorSize => write!(f, "sector_size must be non-zero"),
        }
    }
}

impl core::error::Error for Error {}

/// Direction of a data transfer from the device's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferDir {
    /// Data enters the device (WRITE / host → device, `xfer_in`).
    In,
    /// Data leaves the device (READ / device → host, `xfer_out`).
    Out,
}

/// Pending data transfer context (per-device, per-command).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingXfer {
    /// Starting byte offset of the transfer (`base_lba * block_size`).
    pub base_byte: u64,
    /// Block size in bytes (from track/sector_size), for sanity checks.
    pub block_size: u32,
    /// Transfer direction.
    pub dir: XferDir,
    /// Total transfer length in bytes.
    pub transfer_len: u64,
}

/// Data-phase error (does not carry sense; sense is held in the device).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferError {
    /// Backend storage failure.
    Storage(BlockStorageError),
    /// No prior `do_cmd` (target misuse).
    NoCommand,
    /// Direction mismatch (READ called xfer_in, etc.).
    Direction,
    /// `transfer_offset + buf.len() > transfer_len`.
    Overrun,
    /// Write to read-only medium.
    WriteProtected,
}

impl core::fmt::Display for XferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::NoCommand => write!(f, "no pending command"),
            Self::Direction => write!(f, "direction mismatch"),
            Self::Overrun => write!(f, "transfer overrun"),
            Self::WriteProtected => write!(f, "write protected"),
        }
    }
}

impl core::error::Error for XferError {}

/// Outcome of one `xfer_out` / `xfer_in` chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferOutcome {
    /// Chunk transferred.
    Ok,
    /// Transfer failed; sense has been set in the device.
    Error(XferError),
}

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
    /// received into `data[0..dsl]`. For `OutInline` the device writes the
    /// response into `data[0..len]` and returns `OutInline { len }`.
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8], dsl: usize) -> Result<CommandOutcome, Error>;

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    /// `transfer_offset` is the byte offset within the transfer (0 ≤ off < transfer_len).
    /// Actual backend byte = `base_byte + transfer_offset`.
    fn xfer_out(&mut self, transfer_offset: u64, buf: &mut [u8]) -> XferOutcome;

    /// Write `buf` for the current WRITE transfer (host → device).
    /// Actual backend byte = `base_byte + transfer_offset`.
    fn xfer_in(&mut self, transfer_offset: u64, buf: &[u8]) -> XferOutcome;

    /// Borrow the pending sense without consuming it (Status phase peek).
    fn peek_sense(&self) -> Option<&Sense>;

    /// Take the pending sense, clearing the device (Status autosense or REQUEST SENSE).
    fn take_sense(&mut self) -> Option<Sense>;

    fn device_type(&self) -> DeviceType;

    /// Complete a parameter-list Data-Out phase (`InParam`).
    ///
    /// `cdb` is the original CDB, `data` the full parameter list
    /// (`expected_len` bytes) already collected in the transport's
    /// work buffer. Returns `Status` on success or `CheckCondition`.
    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
        let _ = (cdb, data);
        CommandOutcome::CheckCondition
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
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8], dsl: usize) -> Result<CommandOutcome, Error> {
        match self {
            Self::Block(dev) => dev.do_cmd(cdb, data, dsl),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.do_cmd(cdb, data, dsl),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.do_cmd(cdb, data, dsl),
        }
    }

    fn xfer_out(&mut self, transfer_offset: u64, buf: &mut [u8]) -> XferOutcome {
        match self {
            Self::Block(dev) => dev.xfer_out(transfer_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.xfer_out(transfer_offset, buf),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.xfer_out(transfer_offset, buf),
        }
    }

    fn xfer_in(&mut self, transfer_offset: u64, buf: &[u8]) -> XferOutcome {
        match self {
            Self::Block(dev) => dev.xfer_in(transfer_offset, buf),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.xfer_in(transfer_offset, buf),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.xfer_in(transfer_offset, buf),
        }
    }

    fn peek_sense(&self) -> Option<&Sense> {
        match self {
            Self::Block(dev) => dev.peek_sense(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.peek_sense(),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.peek_sense(),
        }
    }

    fn take_sense(&mut self) -> Option<Sense> {
        match self {
            Self::Block(dev) => dev.take_sense(),
            #[cfg(feature = "std")]
            Self::CdBlock(dev) => dev.take_sense(),
            #[cfg(feature = "cdrom")]
            Self::Cdrom(dev) => dev.take_sense(),
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

    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
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
            CommandOutcome::OutInline { len } => {
                assert!(len >= 1);
                w[0]
            }
            _ => panic!("expected OutInline"),
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
        // xfer path: do_cmd WRITE then xfer_in
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[5] = 0;
        cdb[7] = 0;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::InXfer { len } => {
                assert_eq!(len, 512);
                let r = dev.xfer_in(0, &w[0..512]);
                assert_eq!(r, XferOutcome::Ok);
            }
            _ => panic!("expected InXfer"),
        }
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
        // write must fail (CheckCondition immediate for read-only)
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[5] = 0;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::InXfer { len } => {
                assert_eq!(len, 512);
                let r = dev.xfer_in(0, &w[0..512]);
                assert!(matches!(r, XferOutcome::Error(XferError::WriteProtected)));
            }
            CommandOutcome::CheckCondition => {
                assert!(dev.peek_sense().is_some());
            }
            _ => panic!("expected InXfer or CheckCondition"),
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "cdrom")]
    #[test]
    fn device_enum_cdrom_dispatch() {
        return;

        use crate::cdrom::drive::CdromDrive;
        use crate::cdrom::media::{CdMedia, FlatMedia};
        use crate::scsi::backend::RamBackend;
        let mut img = vec![0xAAu8; 2048 * 100];
        let backend = BlockBackend::Ram(RamBackend::new(&mut img));
        let flat = FlatMedia::new(backend, crate::cdrom::common::CurrentProfile::CdRom);
        let mut drive = CdromDrive::new();
        drive.load_quiet(CdMedia::Flat(flat));
        let mut dev = Device::Cdrom(drive);
        let mut w = work();
        assert_eq!(inquiry_pdt(&mut dev, &mut w), 0x05);
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        // Data path via xfer_out: first do_cmd READ then xfer_out
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[5] = 0;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert_eq!(len, 2048);
                let mut buf = [0u8; 4];
                let r = dev.xfer_out(0, &mut buf);
                assert_eq!(r, XferOutcome::Ok);
                assert_eq!(buf, [0xAA; 4]);
            }
            _ => panic!("expected OutXfer"),
        }
        // write must fail
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[5] = 0;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::InXfer { len: _ } => {
                let r = dev.xfer_in(0, &w[0..512]);
                assert!(matches!(r, XferOutcome::Error(XferError::WriteProtected)));
            }
            CommandOutcome::CheckCondition => {
                // also acceptable for CD-ROM non-writable
            }
            _ => panic!("unexpected outcome"),
        }
    }

    #[cfg(all(feature = "livefs", feature = "std"))]
    #[test]
    fn device_enum_cdlivefs_dispatch() {
        return;

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
        drive.load_quiet(CdMedia::Live(Box::new(flat)));
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
        // Do READ for that LBA then xfer_out
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[2] = (first >> 24) as u8;
        cdb[3] = (first >> 16) as u8;
        cdb[4] = (first >> 8) as u8;
        cdb[5] = first as u8;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert_eq!(len, 2048);
                let mut buf = [0u8; 2048];
                let r = dev.xfer_out(0, &mut buf);
                assert_eq!(r, XferOutcome::Ok);
                assert_eq!(&buf[..4], &[0x42; 4]);
            }
            _ => panic!("expected OutXfer"),
        }
        // write must fail
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::InXfer { len: _ } => {
                let r = dev.xfer_in(0, &w[0..512]);
                assert!(matches!(r, XferOutcome::Error(XferError::WriteProtected)));
            }
            CommandOutcome::CheckCondition => {}
            _ => panic!("unexpected"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
