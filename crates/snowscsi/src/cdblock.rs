//! CDBlock device: a "lazy CD" (Phase 1.5, plan §8.1b).
//!
//! Reports itself as a CD-ROM (PDT=0x05) while reading a flat ISO image
//! through a read-only [`FileBackend`]. Implements a minimal MMC command set
//! (READ TOC, GET CONFIGURATION); SPC commands (INQUIRY, MODE SENSE, ...) are
//! delegated to [`crate::spc`]; all write commands return DATA PROTECT.
//! Because the backing store is always a read-only file, this module is
//! `std`-gated (`RamBackend` images are not supported).

use crate::backend::{BlockStorage, BlockStorageError, FileBackend};
use crate::device::DeviceType;
use crate::scsi::Sense;
use crate::spc::{block_mode_page, DeviceIdentity, SpcDevice, SpcEffect};

/// CD-ROM logical block size (Mode 1: 2048 data bytes per sector).
pub const SECTOR_SIZE: u32 = 2048;

/// INQUIRY identity for the CDBlock device (plan §8.1b): SCSI family, with
/// the SPC-4 and MMC-6 version descriptors replacing the block device's SBC.
pub const CDBLOCK_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"Virtual CD-ROM  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x05C0], /* SAM-5, iSCSI, SPC-4, MMC-6 */
};

/// The CDBlock device: a read-only CD-ROM emulated over a flat file.
pub struct CDBlockDevice {
    backend: FileBackend,
    sector_size: u32,
    sense: Sense,
    prevent_removal: bool,
}

impl CDBlockDevice {
    /// Open `path` read-only as a CD-ROM image (ISO9660, Joliet, ...).
    /// The file must already exist; the device is immutable (every write
    /// command returns DATA PROTECT).
    pub fn new(path: &str) -> Result<Self, BlockStorageError> {
        Ok(Self {
            backend: FileBackend::open(path, false)?,
            sector_size: SECTOR_SIZE,
            sense: Sense::clear(),
            prevent_removal: false,
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.sense
    }

    /// Raw backend access (target data path reads chunks via
    /// [`BlockStorage::read`]; the device is read-only, so only reads are
    /// meaningful).
    pub fn backend(&mut self) -> &mut FileBackend {
        &mut self.backend
    }

    /// Image size in bytes (from the file opened at construction).
    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
    }
}

impl SpcDevice for CDBlockDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &CDBLOCK_IDENTITY
    }

    fn id(&self) -> u64 {
        self.backend.capacity()
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        // Plan §8.1b: MODE SENSE is "same as Phase 1" — the caching page
        // (0x08), vendor page (0x00) and the 0x3F concatenation.
        block_mode_page(page)
    }

    fn sense(&self) -> &Sense {
        &self.sense
    }

    fn sense_mut(&mut self) -> &mut Sense {
        &mut self.sense
    }

    fn start_stop(&mut self, _loej: bool, _load: bool) -> SpcEffect {
        // Plan §8.1b: START STOP UNIT is accepted and ignored.
        SpcEffect::Good
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::CommandOutcome;

    /// Create a temp file of `len` bytes, returning the cleaned-up path
    /// string on drop. Each file gets a unique name (parallel tests).
    struct TempFile {
        path: std::path::PathBuf,
    }

    impl TempFile {
        fn new(len: u64) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir();
            let path = dir.join(format!("snowscsi_cdblock_{}_{}.iso", std::process::id(), n));
            std::fs::write(&path, vec![0u8; len as usize]).unwrap();
            Self { path }
        }

        fn path_str(&self) -> &str {
            self.path.to_str().unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn cdblock_new_reports_capacity() {
        let f = TempFile::new(2048 * 100);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 2048 * 100);
        assert_eq!(dev.sector_size(), SECTOR_SIZE);
        assert_eq!(dev.sector_size(), 2048);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE) - 1, 99);
    }

    #[test]
    fn cdblock_empty_image_has_zero_lba() {
        let f = TempFile::new(0);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 0);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE), 0);
    }

    #[test]
    fn cdblock_partial_sector_counts_as_zero_sectors() {
        let f = TempFile::new(2048);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 2048);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE) - 1, 0);
    }

    #[test]
    fn cdblock_new_rejects_missing_file() {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_cdblock_missing_{}_{}.iso",
            std::process::id(),
            n
        ));
        let r = CDBlockDevice::new(path.to_str().unwrap());
        assert!(matches!(r, Err(BlockStorageError::Io(_))));
    }

    #[test]
    fn cdblock_backend_is_read_only() {
        let f = TempFile::new(2048);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(
            dev.backend().write(0, &[0xAA; 16]),
            Err(BlockStorageError::NotWritable)
        );
    }

    #[test]
    fn cdblock_backend_reads_file_contents() {
        let f = TempFile::new(4096);
        std::fs::write(&f.path, vec![0x42u8; 4096]).unwrap();
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut buf = [0u8; 4];
        dev.backend().read(2048, &mut buf).unwrap();
        assert_eq!(buf, [0x42; 4]);
    }

    fn work() -> [u8; crate::MIN_WORK_LEN] {
        [0u8; crate::MIN_WORK_LEN]
    }

    fn data_in(outcome: CommandOutcome<'_>, buf: &mut [u8]) -> usize {
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                immediate,
                ..
            } => {
                assert!(transfer_len as usize <= buf.len());
                let n = transfer_len as usize;
                buf[..n].copy_from_slice(&immediate[..n]);
                n
            }
            _ => panic!("expected DataIn"),
        }
    }

    /// Run one SPC command (via `parse_spc` + `execute_spc`) against the
    /// device and return the outcome.
    fn run<'a>(dev: &mut CDBlockDevice, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        crate::spc::execute_spc(dev, crate::spc::parse_spc(cdb).unwrap(), work, 0)
    }

    #[test]
    fn cdblock_inquiry_reports_cdrom() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let outcome = run(&mut dev, &cdb, &mut w);
        let mut buf = [0u8; 96];
        let n = data_in(outcome, &mut buf);
        assert!(n >= 66);
        assert_eq!(buf[0], 0x05); /* PDT = CD-ROM */
        assert_eq!(buf[1], 0x80); /* removable */
        assert_eq!(buf[2], 0x06); /* SPC-4 */
        assert_eq!(buf[4], 91); /* additional length (n-4) */
        assert_eq!(buf[7], 0x02); /* CmdQue */
        assert_eq!(&buf[8..16], b"SnowSCSI");
        assert_eq!(&buf[16..32], b"Virtual CD-ROM  ");
        assert_eq!(
            &buf[58..66],
            &[0x00, 0xA0, 0x09, 0x60, 0x04, 0x60, 0x05, 0xC0]
        );
    }

    #[test]
    fn cdblock_inquiry_vpd_pages() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x00;
        cdb[4] = 7;
        let mut buf = [0u8; 7];
        data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        assert_eq!(&buf[3..7], &[0x03, 0x00, 0x80, 0x83]);

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x80;
        cdb[4] = 20;
        let mut buf = [0u8; 20];
        data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        assert_eq!(buf[1], 0x80);
        assert_eq!(buf[3], 16);
        assert_eq!(&buf[4..8], b"SNOW");

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x83;
        cdb[4] = 16;
        let mut buf = [0u8; 16];
        data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        assert_eq!(buf[1], 0x83);
        assert_eq!(buf[4], 0x01); /* CODE SET binary */
        assert_eq!(buf[5], 0x03); /* NAA */
        assert_eq!(buf[8], 0x30); /* NAA-3 prefix */
    }

    #[test]
    fn cdblock_mode_sense_6_caching_page() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x08;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        assert!(n >= 24);
        assert_eq!(buf[4], 0x88); /* PS=1, page 0x08 */
        assert_eq!(buf[5], 18);
    }

    #[test]
    fn cdblock_mode_sense_10() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x08;
        cdb[8] = 32;
        let mut buf = [0u8; 32];
        data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        let mode_len = (u16::from(buf[0]) << 8) | u16::from(buf[1]);
        assert_eq!(mode_len, 26);
        assert_eq!(buf[8], 0x88);
    }

    #[test]
    fn cdblock_mode_sense_unsupported_page_rejected() {
        use crate::device::CommandOutcome;
        use crate::scsi::{asc, op, Sense, SenseKey};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x01;
        cdb[4] = 32;
        let outcome = run(&mut dev, &cdb, &mut w);
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::INVALID_FIELD,
                0
            ))
        );
    }

    #[test]
    fn cdblock_test_unit_ready_and_request_sense() {
        use crate::scsi::{asc, op};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let cdb = [op::TEST_UNIT_READY; 6];
        assert_eq!(run(&mut dev, &cdb, &mut w), CommandOutcome::Status);

        // Force a CHECK CONDITION, then read it back via REQUEST SENSE.
        let mut bad = [0u8; 6];
        bad[0] = op::MODE_SENSE_6;
        bad[2] = 0x01;
        bad[4] = 32;
        assert!(matches!(
            run(&mut dev, &bad, &mut w),
            CommandOutcome::CheckCondition(_)
        ));

        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let mut buf = [0u8; 18];
        let n = data_in(run(&mut dev, &cdb, &mut w), &mut buf);
        assert_eq!(n, 18);
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[2], 0x05); /* ILLEGAL REQUEST */
        assert_eq!(buf[12], asc::INVALID_FIELD);
    }

    #[test]
    fn cdblock_start_stop_ignored() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x02; /* LoEj=1 (eject) */
        assert_eq!(run(&mut dev, &cdb, &mut w), CommandOutcome::Status);
        cdb[4] = 0x00; /* stop */
        assert_eq!(run(&mut dev, &cdb, &mut w), CommandOutcome::Status);
    }

    #[test]
    fn cdblock_prevent_allow_records_prevent() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        cdb[4] = 0x01;
        assert_eq!(run(&mut dev, &cdb, &mut w), CommandOutcome::Status);
        assert!(dev.prevent_removal);
    }

    #[test]
    fn cdblock_send_diagnostic_pf_only_is_good() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x08; /* PF=1, SELFTEST=0 */
        assert_eq!(run(&mut dev, &cdb, &mut w), CommandOutcome::Status);
    }
}
