//! CDBlock device: a "lazy CD" (Phase 1.5, plan §8.1b).
//!
//! Reports itself as a CD-ROM (PDT=0x05) while reading a flat ISO image
//! through a read-only [`FileBackend`]. Implements a minimal MMC command set
//! (READ TOC, GET CONFIGURATION); SPC commands (INQUIRY, MODE SENSE, ...) are
//! delegated to [`crate::spc`]; all write commands return DATA PROTECT.
//! Because the backing store is always a read-only file, this module is
//! `std`-gated (`RamBackend` images are not supported).

use crate::backend::{BlockStorage, BlockStorageError, FileBackend};
use crate::device::{CommandOutcome, DeviceType, Error};
use crate::scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, Sense, SenseKey,
};
use crate::spc::{block_mode_page, execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect};

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

    /// Largest readable LBA: `(file_size / 2048) - 1`. Saturates to 0 for
    /// images smaller than one sector (READ CAPACITY still reports a valid
    /// last-LBA of 0).
    pub(crate) fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Sense::new(key, asc, ascq);
    }

    /// CHECK CONDITION helper for non-SPC commands (SBC/MMC dispatch).
    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.sense)
    }

    /// Read data from the backend (target data path), setting MEDIUM ERROR
    /// sense on failure.
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self.backend.read(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
                Err(e)
            }
        }
    }

    /// Process one SCSI command (mirrors `BlockDevice::do_cmd`). `work`
    /// must be at least [`crate::MIN_WORK_LEN`] bytes; `dsl` is the length
    /// of data already received (immediate data, never used by this
    /// read-only device).
    ///
    /// Dispatch order: SPC commands go to [`execute_spc`]; the SBC read-only
    /// set (READ 6/10/12/16, READ CAPACITY 10/16) is handled here; write
    /// commands (WRITE 6/10/12/16, SYNCHRONIZE CACHE) return DATA PROTECT;
    /// unknown MMC opcodes return INVALID COMMAND.
    pub fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        if work.len() < crate::MIN_WORK_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let outcome = if let Some(cmd) = parse_spc(cdb) {
            execute_spc(self, cmd, work, dsl)
        } else {
            match cdb_opcode(cdb) {
                op::READ_6 => self.read_cmd(u64::from(cdb_lba6(cdb)), cdb_transfer_len6(cdb), work),
                op::READ_10 => self.read_cmd(
                    u64::from(cdb_lba10(cdb)),
                    u32::from(cdb_transfer_len10(cdb)),
                    work,
                ),
                op::READ_12 => {
                    self.read_cmd(u64::from(cdb_lba12(cdb)), cdb_transfer_len12(cdb), work)
                }
                op::READ_16 => self.read_cmd(cdb_lba16(cdb), cdb_transfer_len16(cdb), work),
                op::READ_CAPACITY_10 => {
                    self.read_capacity_10_cmd(cdb[1] & 0x01 != 0, cdb_lba10(cdb), work)
                }
                op::SERVICE_ACTION_IN => {
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    self.read_capacity_16_cmd(cdb[1], alloc, work)
                }
                op::READ_TOC => self.read_toc_cmd(cdb, work),
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, work),
                op::WRITE_6
                | op::WRITE_10
                | op::WRITE_12
                | op::WRITE_16
                | op::SYNCHRONIZE_CACHE_10 => {
                    // Plan §8.1b: every write command → DATA PROTECT.
                    self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                }
                _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND),
            }
        };
        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.sense = Sense::clear();
        }
        Ok(outcome)
    }

    /// Shared READ(6/10/12/16) handler (2048-byte sectors, backend read).
    pub(crate) fn read_cmd<'a>(
        &mut self,
        lba: u64,
        count: u32,
        work: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = u64::from(count)
            .checked_mul(u64::from(SECTOR_SIZE))
            .and_then(|b| u32::try_from(b).ok())
        else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        CommandOutcome::DataIn {
            transfer_len: bytes as u64,
            byte_offset: lba * u64::from(SECTOR_SIZE),
            immediate: &work[48..48],
        }
    }

    /// LBA range check: `lba + count` must not exceed `max_lba + 1`.
    fn check_lba_range(&self, lba: u64, count: u32) -> bool {
        lba <= self.max_lba()
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= self.max_lba() + 1)
    }

    pub(crate) fn read_capacity_10_cmd<'a>(
        &mut self,
        pmi: bool,
        req_lba: u32,
        work: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        work[48..56].copy_from_slice(&buf);
        CommandOutcome::DataIn {
            transfer_len: 8,
            byte_offset: 0,
            immediate: &work[48..56],
        }
    }

    pub(crate) fn read_capacity_16_cmd<'a>(
        &mut self,
        sa: u8,
        alloc: u32,
        work: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if sa != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        let n = 32.min(alloc as usize);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }

    /// READ TOC/PMA/ATIP (0x43) — minimal implementation (MMC-6 §6.25).
    ///
    /// Supports only Format 0000b (formatted TOC: single data track +
    /// lead-out, plan §8.1b) and Format 0001b (session info: single
    /// session). Track/Session Number 0 or 1 returns the full TOC; AAh
    /// returns just the lead-out descriptor; MSF selects MSF-form addresses
    /// (LBA 0 → 00:02:00); the response is clamped to the allocation length
    /// without shrinking the TOC Data Length field.
    fn read_toc_cmd<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let msf = cdb[1] & 0x02 != 0;
        let format = cdb[2] & 0x0F;
        let track = cdb[6];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        // TOC Data Length = bytes following the 2-byte length field, always
        // the full value (not clamped by the allocation length, MMC-6 §6.25.3).
        // Response layout: 2-byte length + first/last + 8-byte descriptors,
        // so the totals are 20 (two descriptors) or 12 (one descriptor).
        let (buf, n): ([u8; 22], usize) = match format {
            0x0 => {
                let lead_out = self.lead_out_lba();
                let track1_addr = self.toc_address(0, msf);
                let lead_addr = self.toc_address(lead_out, msf);
                let mut b = [0u8; 22];
                b[1] = 0x12; /* data length: 2 (first/last) + 2 × 8 */
                b[2] = 0x01; /* first track */
                b[3] = 0x01; /* last track */
                match track {
                    0 | 1 => {
                        // Track 1 descriptor.
                        b[5] = 0x14; /* ADR=1 (position), CONTROL=4 (data) */
                        b[6] = 0x01;
                        b[8..12].copy_from_slice(&track1_addr);
                        // Lead-out descriptor.
                        b[13] = 0x14;
                        b[14] = 0xAA;
                        b[16..20].copy_from_slice(&lead_addr);
                        (b, 20)
                    }
                    0xAA => {
                        // Lead-out only: 2-byte length + first/last + 1 × 8,
                        // descriptor starts at byte 4.
                        b[1] = 0x0A;
                        b[5] = 0x14;
                        b[6] = 0xAA;
                        b[8..12].copy_from_slice(&lead_addr);
                        (b, 12)
                    }
                    _ => return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
                }
            }
            0x1 => {
                // Session info: 2-byte length + sessions + 1 × 8 descriptor.
                let mut b = [0u8; 22];
                b[1] = 0x0A; /* data length: 2 (sessions) + 8 */
                b[2] = 0x01; /* first complete session */
                b[3] = 0x01; /* last complete session */
                b[5] = 0x14; /* ADR/CTL */
                b[6] = 0x01; /* first track in last session */
                b[8..12].copy_from_slice(&self.toc_address(0, msf));
                (b, 12)
            }
            _ => return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        };
        let n = n.min(alloc as usize);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }

    /// Lead-out start LBA: the number of sectors in the image.
    fn lead_out_lba(&self) -> u32 {
        (self.capacity() / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32
    }

    /// Encode a track/session start address in LBA or MSF form. MSF uses the
    /// 2-second (150-frame) lead-in offset: LBA 0 → 00:02:00 (MMC-6 §4.2.3.3).
    fn toc_address(&self, lba: u32, msf: bool) -> [u8; 4] {
        if !msf {
            return lba.to_be_bytes();
        }
        let v = lba + 150;
        let m = v / (75 * 60);
        let s = (v % (75 * 60)) / 75;
        let f = v % 75;
        [0x00, m as u8, s as u8, f as u8]
    }

    /// GET CONFIGURATION (0x46) — minimal implementation (MMC-6 §6.5).
    ///
    /// Returns the Current Profile (0x0008 CD-ROM for images ≤ 700 MiB,
    /// 0x0010 DVD-ROM otherwise, plan §8.1b) and four feature descriptors:
    /// Core (0x0001), Removable Medium (0x0003), Random Readable (0x0010,
    /// logical block size 2048) and CD Read (0x001E). RT=00b/01b return all
    /// features; RT=10b filters to the Starting Feature Number and higher;
    /// RT=11b is rejected. The response is clamped to the allocation length
    /// without shrinking the Data Length field.
    fn get_configuration_cmd<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }

        let mut buf = [0u8; 44];
        let profile = self.current_profile();
        buf[6] = (profile >> 8) as u8;
        buf[7] = profile as u8;

        // RT=10b: only the Starting Feature Number and higher are returned.
        let include = |code: u16| rt != 0x02 || code >= start;
        let mut off = 8usize;

        // Core (0x0001): version 0010b, persistent, current; additional
        // length 8 — physical interface standard (SCSI family) + INQ2/DBE.
        if include(0x0001) {
            buf[off] = 0x00;
            buf[off + 1] = 0x01;
            buf[off + 2] = 0x03;
            buf[off + 3] = 0x08;
            buf[off + 4..off + 8].copy_from_slice(&[0, 0, 0, 1]); /* SCSI family */
            buf[off + 8] = 0x06; /* INQ2 | DBE */
            off += 12;
        }

        // Removable Medium (0x0003): current; no dependent data.
        if include(0x0003) {
            buf[off] = 0x00;
            buf[off + 1] = 0x03;
            buf[off + 2] = 0x01; /* current */
            off += 4;
        }

        // Random Readable (0x0010): current; additional length 8 — logical
        // block size 2048, blocking 1, no error-recovery page (PP=0).
        if include(0x0010) {
            buf[off] = 0x00;
            buf[off + 1] = 0x10;
            buf[off + 2] = 0x01; /* current */
            buf[off + 3] = 0x08;
            buf[off + 4..off + 8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
            buf[off + 8] = 0x00;
            buf[off + 9] = 0x01; /* blocking = 1 */
            off += 12;
        }

        // CD Read (0x001E): version 0010b, current; additional length 4 —
        // DAP/C2/CD-Text all clear.
        if include(0x001E) {
            buf[off] = 0x00;
            buf[off + 1] = 0x1E;
            buf[off + 2] = 0x03;
            buf[off + 3] = 0x04;
            off += 8;
        }

        // Data Length = descriptor bytes following the 8-byte header.
        let data_len = (off - 8) as u32;
        buf[0..4].copy_from_slice(&data_len.to_be_bytes());

        let n = off.min(alloc as usize);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }

    /// Current profile for GET CONFIGURATION: CD-ROM up to 700 MiB, DVD-ROM
    /// beyond (plan §8.1b / §8.2 profile table).
    fn current_profile(&self) -> u16 {
        if self.capacity() <= 700 * 1024 * 1024 {
            0x0008
        } else {
            0x0010
        }
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

        /// Sparse temp file of `len` bytes (no backing disk blocks) — used
        /// for capacity-derived behavior without allocating the image.
        fn sparse(len: u64) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir();
            let path = dir.join(format!(
                "snowscsi_cdblock_sparse_{}_{}.iso",
                std::process::id(),
                n
            ));
            let f = std::fs::File::create(&path).unwrap();
            f.set_len(len).unwrap();
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

    /// Run one full SCSI command via `do_cmd` and fetch the payload, reading
    /// backend-resident DataIn through `dev.read_data` when `immediate` is
    /// empty.
    fn do_data_in(dev: &mut CDBlockDevice, cdb: &[u8], work: &mut [u8], buf: &mut [u8]) -> usize {
        let outcome = dev.do_cmd(cdb, work, 0).unwrap();
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert!(transfer_len as usize <= buf.len());
                let n = transfer_len as usize;
                if immediate.is_empty() {
                    dev.read_data(byte_offset, &mut buf[..n]).unwrap();
                } else {
                    buf[..n].copy_from_slice(&immediate[..n]);
                }
                n
            }
            _ => panic!("expected DataIn"),
        }
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

    fn make_cdb6(opcode: u8, lba: u32, transfer_len: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = opcode;
        cdb[1] = ((lba >> 16) & 0x1F) as u8;
        cdb[2] = (lba >> 8) as u8;
        cdb[3] = lba as u8;
        cdb[4] = transfer_len;
        cdb
    }

    fn make_cdb10(opcode: u8, lba: u32, transfer_len: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[7] = (transfer_len >> 8) as u8;
        cdb[8] = transfer_len as u8;
        cdb
    }

    fn make_cdb12(opcode: u8, lba: u32, transfer_len: u32) -> [u8; 12] {
        let mut cdb = [0u8; 12];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[6] = (transfer_len >> 24) as u8;
        cdb[7] = (transfer_len >> 16) as u8;
        cdb[8] = (transfer_len >> 8) as u8;
        cdb[9] = transfer_len as u8;
        cdb
    }

    fn make_cdb16(opcode: u8, lba: u64, transfer_len: u32) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = opcode;
        cdb[2] = (lba >> 56) as u8;
        cdb[3] = (lba >> 48) as u8;
        cdb[4] = (lba >> 40) as u8;
        cdb[5] = (lba >> 32) as u8;
        cdb[6] = (lba >> 24) as u8;
        cdb[7] = (lba >> 16) as u8;
        cdb[8] = (lba >> 8) as u8;
        cdb[9] = lba as u8;
        cdb[10] = (transfer_len >> 24) as u8;
        cdb[11] = (transfer_len >> 16) as u8;
        cdb[12] = (transfer_len >> 8) as u8;
        cdb[13] = transfer_len as u8;
        cdb
    }

    /// Check condition sense from a do_cmd dispatch.
    fn check_condition(outcome: CommandOutcome<'_>) -> (SenseKey, u8) {
        match outcome {
            CommandOutcome::CheckCondition(s) => (s.key, s.asc),
            _ => panic!("expected CheckCondition"),
        }
    }

    #[test]
    fn cdblock_read_10_roundtrip() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut img = vec![0xAAu8; 2048 * 100];
        img[2048..2048 + 4].copy_from_slice(&[1, 2, 3, 4]);
        std::fs::write(&f.path, &img).unwrap();
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let cdb = make_cdb10(op::READ_10, 1, 1);
        let mut buf = [0u8; 2048];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 2048);
        assert_eq!(buf[..4], [1, 2, 3, 4]);
        assert_eq!(buf[4..], [0xAA; 2044]);
        assert_eq!(dev.sense().key, SenseKey::None);
    }

    #[test]
    fn cdblock_read_6_12_16() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut img = vec![0u8; 2048 * 100];
        img[5 * 2048 + 1] = 0x5B;
        img[20 * 2048] = 0x4C;
        img[30 * 2048 + 2] = 0xE3;
        std::fs::write(&f.path, &img).unwrap();
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let mut buf = [0u8; 2048];
        let n = do_data_in(&mut dev, &make_cdb6(op::READ_6, 5, 1), &mut w, &mut buf);
        assert_eq!(n, 2048);
        assert_eq!(buf[1], 0x5B);

        let mut buf = [0u8; 2048];
        let n = do_data_in(&mut dev, &make_cdb12(op::READ_12, 20, 1), &mut w, &mut buf);
        assert_eq!(n, 2048);
        assert_eq!(buf[0], 0x4C);

        let mut buf = [0u8; 2048];
        let n = do_data_in(&mut dev, &make_cdb16(op::READ_16, 30, 1), &mut w, &mut buf);
        assert_eq!(n, 2048);
        assert_eq!(buf[2], 0xE3);
    }

    #[test]
    fn cdblock_read_6_zero_blocks_means_256() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        // 256 blocks × 2048 = 524288 bytes overflows the 100-block image —
        // the LBA range check must reject it before the backend is touched.
        let cdb = make_cdb6(op::READ_6, 0, 0);
        let (key, _) = check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap());
        assert_eq!(key, SenseKey::IllegalRequest);
    }

    #[test]
    fn cdblock_read_lba_out_of_range() {
        use crate::scsi::{asc, op};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 100, 1);
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE)
        );
        // Partial overrun is also rejected.
        let cdb = make_cdb10(op::READ_10, 99, 2);
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE)
        );
    }

    #[test]
    fn cdblock_read_capacity_10() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 700);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let mut buf = [0u8; 8];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 8);
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 699);
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 2048);
    }

    #[test]
    fn cdblock_read_capacity_10_pmi_zero_lba_nonzero_rejected() {
        use crate::scsi::{asc, op};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        cdb[5] = 0x01; /* PMI=0, LBA=1 */
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    #[test]
    fn cdblock_read_capacity_16() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 700);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0x10;
        cdb[13] = 0x20;
        let mut buf = [0u8; 32];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 32);
        assert_eq!(
            u64::from_be_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]),
            699
        );
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x08, 0x00]);
        assert_eq!(&buf[12..], &[0u8; 20]);
    }

    #[test]
    fn cdblock_read_capacity_16_unknown_sa_rejected() {
        use crate::scsi::{asc, op};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0xFF;
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    #[test]
    fn cdblock_write_commands_return_data_protect() {
        use crate::scsi::{asc, op};

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let mut assert_data_protect = |cdb: &[u8]| {
            assert_eq!(
                check_condition(dev.do_cmd(cdb, &mut w, 0).unwrap()),
                (SenseKey::DataProtect, asc::WRITE_PROTECTED)
            );
        };
        assert_data_protect(&make_cdb6(op::WRITE_6, 0, 1));
        assert_data_protect(&make_cdb10(op::WRITE_10, 0, 1));
        assert_data_protect(&make_cdb12(op::WRITE_12, 0, 1));
        assert_data_protect(&make_cdb16(op::WRITE_16, 0, 1));

        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_data_protect(&cdb);
    }

    #[test]
    fn cdblock_unknown_opcode_returns_invalid_command() {
        use crate::scsi::asc;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_COMMAND)
        );
        // READ DISC INFORMATION (0x51) is an MMC command this minimal
        // device does not implement → INVALID COMMAND (plan §8.1b).
        let mut cdb = [0u8; 10];
        cdb[0] = 0x51;
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_COMMAND)
        );
    }

    #[test]
    fn cdblock_work_buf_too_small() {
        use crate::scsi::op;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut small = [0u8; 100];
        let cdb = make_cdb10(op::READ_10, 0, 1);
        assert_eq!(dev.do_cmd(&cdb, &mut small, 0), Err(Error::WorkBufTooSmall));
    }

    #[test]
    fn cdblock_read_failure_sets_medium_error() {
        use crate::scsi::asc;

        let f = TempFile::new(2048 * 4);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut buf = [0u8; 2048];
        let r = dev.read_data(2048 * 5, &mut buf);
        assert_eq!(r, Err(BlockStorageError::OutOfBounds));
        assert_eq!(dev.sense().key, SenseKey::MediumError);
        assert_eq!(dev.sense().asc, asc::UNRECOVERED_READ_ERROR);
    }

    fn make_cdb_read_toc(msf: bool, format: u8, track: u8, alloc: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[1] = if msf { 0x02 } else { 0x00 };
        cdb[2] = format;
        cdb[6] = track;
        cdb[7] = (alloc >> 8) as u8;
        cdb[8] = alloc as u8;
        cdb
    }

    #[test]
    fn cdblock_read_toc_format_0_lba() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0x00, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        // Header.
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x12); /* data length 18 */
        assert_eq!(buf[2], 0x01); /* first track */
        assert_eq!(buf[3], 0x01); /* last track */
        // Track 1 descriptor.
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x14); /* ADR=1, CONTROL=4 (data) */
        assert_eq!(buf[6], 0x01);
        assert_eq!(buf[7], 0x00);
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]); /* start LBA 0 */
        // Lead-out descriptor.
        assert_eq!(buf[12], 0x00);
        assert_eq!(buf[13], 0x14);
        assert_eq!(buf[14], 0xAA);
        assert_eq!(buf[15], 0x00);
        assert_eq!(&buf[16..20], &[0, 0, 0, 100]); /* lead-out = 100 */
    }

    #[test]
    fn cdblock_read_toc_format_0_msf() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(true, 0x00, 0x00, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        // Track 1: LBA 0 → 00:02:00.
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x02, 0x00]);
        // Lead-out: LBA 100 → 100+150 = 250 → 00:03:25.
        assert_eq!(&buf[16..20], &[0x00, 0x00, 0x03, 0x19]);
    }

    #[test]
    fn cdblock_read_toc_format_0_track_aa_returns_leadout() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0xAA, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12); /* length + first/last + lead-out descriptor only */
        assert_eq!(buf[1], 0x0A);
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x01);
        assert_eq!(buf[5], 0x14);
        assert_eq!(buf[6], 0xAA);
        assert_eq!(&buf[8..12], &[0, 0, 0, 100]);
    }

    #[test]
    fn cdblock_read_toc_format_0_track_1_returns_full() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0x01, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(buf[6], 0x01);
        assert_eq!(buf[14], 0xAA);
    }

    #[test]
    fn cdblock_read_toc_format_0_invalid_track_rejected() {
        use crate::scsi::asc;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0x02, 64);
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    #[test]
    fn cdblock_read_toc_format_1_lba_and_msf() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        let cdb = make_cdb_read_toc(false, 0x01, 0x00, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(buf[1], 0x0A); /* data length 10 */
        assert_eq!(buf[2], 0x01); /* first session */
        assert_eq!(buf[3], 0x01); /* last session */
        assert_eq!(buf[5], 0x14);
        assert_eq!(buf[6], 0x01); /* first track in last session */
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]); /* start LBA 0 */

        let cdb = make_cdb_read_toc(true, 0x01, 0x00, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x02, 0x00]);
    }

    #[test]
    fn cdblock_read_toc_alloc_clamp_keeps_data_length() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0x00, 12);
        let mut buf = [0u8; 12];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12); /* clamped to allocation length */
        assert_eq!(buf[1], 0x12); /* data length still the full value */
    }

    #[test]
    fn cdblock_read_toc_alloc_zero_transfers_nothing() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_read_toc(false, 0x00, 0x00, 0);
        let mut buf = [0u8; 4];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn cdblock_read_toc_unsupported_format_rejected() {
        use crate::scsi::asc;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        // Format 0010b (raw TOC) is a valid MMC format this minimal device
        // does not implement → INVALID FIELD IN CDB.
        let cdb = make_cdb_read_toc(true, 0x02, 0x01, 64);
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    fn make_cdb_get_configuration(rt: u8, start: u16, alloc: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_CONFIGURATION;
        cdb[1] = rt & 0x03;
        cdb[2] = (start >> 8) as u8;
        cdb[3] = start as u8;
        cdb[7] = (alloc >> 8) as u8;
        cdb[8] = alloc as u8;
        cdb
    }

    #[test]
    fn cdblock_get_configuration_cd_profile_full_features() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_get_configuration(0x00, 0x0000, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 44);

        // Header: data length 36, reserved, current profile CD-ROM.
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x24]);
        assert_eq!(buf[4], 0);
        assert_eq!(buf[5], 0);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x08); /* CD-ROM */

        // Core (0x0001): version 2 + persistent + current, addlen 8,
        // SCSI-family physical interface, INQ2|DBE.
        assert_eq!(&buf[8..10], &[0x00, 0x01]);
        assert_eq!(buf[10], 0x03);
        assert_eq!(buf[11], 0x08);
        assert_eq!(&buf[12..16], &[0, 0, 0, 1]);
        assert_eq!(buf[16], 0x06);

        // Removable Medium (0x0003): current, no dependent data.
        assert_eq!(&buf[20..22], &[0x00, 0x03]);
        assert_eq!(buf[22], 0x01);
        assert_eq!(buf[23], 0x00);

        // Random Readable (0x0010): current, addlen 8, block size 2048.
        assert_eq!(&buf[24..26], &[0x00, 0x10]);
        assert_eq!(buf[26], 0x01);
        assert_eq!(buf[27], 0x08);
        assert_eq!(&buf[28..32], &[0x00, 0x00, 0x08, 0x00]); /* 2048 */
        assert_eq!(&buf[32..34], &[0x00, 0x01]); /* blocking 1 */

        // CD Read (0x001E): version 2 + current, addlen 4, flags clear.
        assert_eq!(&buf[36..38], &[0x00, 0x1E]);
        assert_eq!(buf[38], 0x03);
        assert_eq!(buf[39], 0x04);
        assert_eq!(&buf[40..44], &[0u8; 4]);
    }

    #[test]
    fn cdblock_get_configuration_dvd_profile_over_700_mib() {
        // Sparse 701 MiB image — capacity-derived profile, no disk blocks.
        let f = TempFile::sparse(701 * 1024 * 1024);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_get_configuration(0x00, 0x0000, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 44);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x10); /* DVD-ROM */
    }

    #[test]
    fn cdblock_get_configuration_starting_feature_filters() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();

        // RT=10b, start 0x0010 → Random Readable + CD Read (12 + 8 = 20).
        let cdb = make_cdb_get_configuration(0x02, 0x0010, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 28);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x14]); /* data len 20 */
        assert_eq!(&buf[8..10], &[0x00, 0x10]);
        assert_eq!(&buf[20..22], &[0x00, 0x1E]);

        // RT=10b, start 0x001E → CD Read only (8 bytes).
        let cdb = make_cdb_get_configuration(0x02, 0x001E, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 16);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x08]);
        assert_eq!(&buf[8..10], &[0x00, 0x1E]);

        // RT=10b, start 0x0020 (unsupported) → header only, data length 0.
        let cdb = make_cdb_get_configuration(0x02, 0x0020, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 8);
        assert_eq!(&buf[0..4], &[0u8; 4]);
        assert_eq!(buf[7], 0x08);
    }

    #[test]
    fn cdblock_get_configuration_rt_current_only_same_result() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_get_configuration(0x01, 0x0000, 64);
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 44);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x24]);
    }

    #[test]
    fn cdblock_get_configuration_rt_reserved_rejected() {
        use crate::scsi::asc;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_get_configuration(0x03, 0x0000, 64);
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    #[test]
    fn cdblock_get_configuration_alloc_clamp_keeps_data_length() {
        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let cdb = make_cdb_get_configuration(0x00, 0x0000, 8);
        let mut buf = [0u8; 8];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 8); /* header only */
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x24]); /* full data length */
        assert_eq!(buf[7], 0x08);
    }
}
