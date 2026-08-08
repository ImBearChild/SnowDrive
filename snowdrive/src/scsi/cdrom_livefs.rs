//! CdLiveFsDevice: live ISO9660 CD-ROM over a host directory (Phase 2e).
//!
//! The device scans a host directory tree via [`FsStorage`] at
//! construction, computes an ISO9660/Joliet LBA layout with the pure
//! algorithms in [`crate::iso9660::live`], and serves it as a read-only
//! CD-ROM.  Metadata sectors (PVD / SVD / Path Table / root directory)
//! are generated on the fly by [`gen_sector`]; file-data sectors are
//! read from the host filesystem via [`resolve`] → `fs.read(handle, ...)`.
//!
//! The device is read-only: all write commands return DATA PROTECT.

use heapless::Vec;

use crate::common::fs_storage::{DirEntry, FileHandle, FsError, FsStorage, OpenOptions};
use crate::iso9660::live::{
    compute_layout, gen_sector, resolve, FileEntry, IsoError, Layout, MAX_FILES, SECTOR_SIZE,
};
use crate::scsi::cdrom_common::{
    build_get_config_response, cdrom_mode_page, CdromDeviceCommon, CurrentProfile, CDROM_IDENTITY,
};
use crate::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, Sense, SenseKey,
};
use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect};

/// Directory-scan buffer size (entries per `read_dir` call).  A single
/// directory with more entries than this is rejected (`DirTooLarge`) —
/// the scan buffer lives on the stack.
const SCAN_BUF: usize = 32;

/// Error opening a live FS device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdLiveFsError {
    /// Filesystem failure during the tree scan.
    Fs(FsError),
    /// The tree exceeds the layout capacity (MAX_FILES).
    TooManyFiles,
    /// A directory has more entries than the scan buffer can hold.
    DirTooLarge,
}

impl core::fmt::Display for CdLiveFsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "filesystem error: {e}"),
            Self::TooManyFiles => write!(f, "too many files for the live layout"),
            Self::DirTooLarge => write!(f, "directory exceeds the live scan buffer"),
        }
    }
}

impl core::error::Error for CdLiveFsError {}

impl From<FsError> for CdLiveFsError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

/// Map a filesystem error onto the block-storage error used by the
/// SCSI data plane (`ScsiDevice::read_data`).
impl From<FsError> for crate::scsi::backend::BlockStorageError {
    fn from(e: FsError) -> Self {
        match e {
            FsError::NotFound | FsError::OutOfBounds => Self::OutOfBounds,
            FsError::NotWritable => Self::NotWritable,
            FsError::Io(kind) => Self::Io(kind),
        }
    }
}

/// Live ISO9660 CD-ROM device (plan §8.2 / §3.2 / §11.2).
///
/// Generic over any [`FsStorage`] implementation (StdFsBackend on desktop,
/// an embedded file system for no_std).  Read-only: write commands return
/// DATA PROTECT.
pub struct CdLiveFsDevice<F: FsStorage> {
    pub(crate) common: CdromDeviceCommon,
    pub(crate) fs: F,
    pub(crate) layout: Layout,
    /// Open handle per scanned entry, aligned with the `files` slice the
    /// layout's `extents[].file_index` indexes into (`None` for dirs).
    pub(crate) handles: Vec<Option<FileHandle>, MAX_FILES>,
}

/// Recursively scan `dir_rel` ("" = root), appending entries and opening
/// file handles.  Directories appear before their children.
fn scan_dir<F: FsStorage>(
    fs: &mut F,
    dir_rel: &str,
    files: &mut Vec<FileEntry, MAX_FILES>,
    handles: &mut Vec<Option<FileHandle>, MAX_FILES>,
    buf: &mut [DirEntry; SCAN_BUF],
) -> Result<(), CdLiveFsError> {
    let n = fs.read_dir(dir_rel, buf)?;
    if n == SCAN_BUF {
        // Could be truncated — reject rather than silently drop entries.
        return Err(CdLiveFsError::DirTooLarge);
    }
    for i in 0..n {
        let entry = &buf[i];
        // Relative path of this entry.
        let mut path = heapless::String::<512>::new();
        if !dir_rel.is_empty() {
            path.push_str(dir_rel)
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
            path.push('/').map_err(|_| CdLiveFsError::TooManyFiles)?;
        }
        path.push_str(entry.name.as_str())
            .map_err(|_| CdLiveFsError::TooManyFiles)?;

        files
            .push(FileEntry {
                path: path.clone(),
                size: entry.size,
                is_dir: entry.is_dir,
            })
            .map_err(|_| CdLiveFsError::TooManyFiles)?;

        if entry.is_dir {
            handles
                .push(None)
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
            scan_dir(fs, path.as_str(), files, handles, buf)?;
        } else {
            let h = fs.open(path.as_str(), OpenOptions::read_only())?;
            handles
                .push(Some(h))
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
        }
    }
    Ok(())
}

impl<F: FsStorage> CdLiveFsDevice<F> {
    /// Scan the tree under `fs`'s root and build the live layout.
    ///
    /// `label` is the ISO9660 volume label (truncated to 16 ASCII chars).
    pub fn new(mut fs: F, label: &str) -> Result<Self, CdLiveFsError> {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        let mut handles = Vec::<Option<FileHandle>, MAX_FILES>::new();
        let mut buf = core::array::from_fn(|_| DirEntry {
            name: heapless::String::new(),
            is_dir: false,
            size: 0,
        });
        scan_dir(&mut fs, "", &mut files, &mut handles, &mut buf)?;
        let layout = compute_layout(&files, label).map_err(|e: IsoError| match e {
            IsoError::TooManyFiles => CdLiveFsError::TooManyFiles,
        })?;
        Ok(Self {
            common: CdromDeviceCommon::new(CurrentProfile::from_capacity(
                u64::from(layout.total) * u64::from(SECTOR_SIZE),
            )),
            fs,
            layout,
            handles,
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.common.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.common.sense
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Flush the underlying filesystem (graceful-shutdown path).
    pub fn sync(&mut self) -> Result<(), FsError> {
        self.fs.sync()
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.common.sense = Sense::new(key, asc, ascq);
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.common.sense)
    }

    /// Virtual disc capacity in bytes (from the layout's total sectors).
    fn capacity(&self) -> u64 {
        u64::from(self.layout.total) * u64::from(SECTOR_SIZE)
    }

    /// Largest readable LBA.
    pub(crate) fn max_lba(&self) -> u64 {
        u64::from(self.layout.total).saturating_sub(1)
    }

    /// Lead-out start LBA = number of data sectors.
    fn lead_out_lba(&self) -> u32 {
        self.layout.total
    }

    /// Fill one 2048-byte sector at `lba` (metadata or file data).
    fn fill_sector(
        &mut self,
        lba: u32,
        sector: &mut [u8; SECTOR_SIZE as usize],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        let metadata_end = self.layout.root_dir_lba + self.layout.root_dir_sectors;
        if lba < metadata_end {
            // System area (zeros) + metadata (PVD/SVD/Path Table/root dir).
            gen_sector(&self.layout, lba, sector);
            return Ok(());
        }
        if let Some((file_index, file_offset, remaining)) = resolve(&self.layout, lba) {
            let handle = self.handles[file_index]
                .ok_or(crate::scsi::backend::BlockStorageError::OutOfBounds)?;
            let need = (remaining as usize).min(SECTOR_SIZE as usize);
            let got = self.fs.read(&handle, file_offset, &mut sector[..need])?;
            sector[got..need].fill(0);
            Ok(())
        } else {
            Err(crate::scsi::backend::BlockStorageError::OutOfBounds)
        }
    }

    /// Read data from the virtual disc (target data path).  Reads are
    /// resolved sector-by-sector so a buffer may span the metadata/file
    /// boundary or cross file extents.  On failure sets MEDIUM ERROR.
    pub fn read_data(
        &mut self,
        byte_offset: u64,
        buf: &mut [u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        let mut off = byte_offset;
        let mut dst = buf;
        while !dst.is_empty() {
            let lba = (off / u64::from(SECTOR_SIZE)) as u32;
            let within = (off % u64::from(SECTOR_SIZE)) as usize;
            let n = (SECTOR_SIZE as usize - within).min(dst.len());
            let mut sector = [0u8; SECTOR_SIZE as usize];
            if self.fill_sector(lba, &mut sector).is_err() {
                self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
                return Err(crate::scsi::backend::BlockStorageError::OutOfBounds);
            }
            dst[..n].copy_from_slice(&sector[within..within + n]);
            off += n as u64;
            dst = &mut dst[n..];
        }
        Ok(())
    }

    /// Write data (target data path).  Read-only → NotWritable.
    pub fn write_data(
        &mut self,
        _offset: u64,
        _buf: &[u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        Err(crate::scsi::backend::BlockStorageError::NotWritable)
    }

    /// Process one SCSI command (execute_mmc_livefs).
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
            execute_spc(&mut self.common, cmd, work, dsl)
        } else {
            match cdb_opcode(cdb) {
                // READ(6/10/12/16)
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

                // READ CAPACITY(10)
                op::READ_CAPACITY_10 => {
                    self.read_capacity_10_cmd(cdb[1] & 0x01 != 0, cdb_lba10(cdb), work)
                }

                // READ CAPACITY(16) via SERVICE ACTION IN
                op::SERVICE_ACTION_IN => {
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    self.read_capacity_16_cmd(cdb[1], alloc, work)
                }

                // READ TOC (0x43)
                op::READ_TOC => self.read_toc_cmd(cdb, work),

                // GET CONFIGURATION (0x46)
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, work),

                // WRITE commands → DATA PROTECT (read-only)
                op::WRITE_6
                | op::WRITE_10
                | op::WRITE_12
                | op::WRITE_16
                | op::SYNCHRONIZE_CACHE_10 => self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED),

                // Unknown → INVALID COMMAND
                _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND),
            }
        };
        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.common.sense = Sense::clear();
        }
        Ok(outcome)
    }

    // ── READ handler ────────────────────────────────────────────────

    fn read_cmd<'a>(&mut self, lba: u64, count: u32, _work: &'a mut [u8]) -> CommandOutcome<'a> {
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
            immediate: &[],
        }
    }

    fn check_lba_range(&self, lba: u64, count: u32) -> bool {
        lba <= self.max_lba()
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= self.max_lba() + 1)
    }

    // ── READ CAPACITY ───────────────────────────────────────────────

    fn read_capacity_10_cmd<'a>(
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

    fn read_capacity_16_cmd<'a>(
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

    // ── READ TOC ────────────────────────────────────────────────────

    fn read_toc_cmd<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let msf = cdb[1] & 0x02 != 0;
        let format = cdb[2] & 0x0F;
        let track = cdb[6];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        let (buf, n): ([u8; 22], usize) = match format {
            0x0 => {
                let lead_out = self.lead_out_lba();
                let track1_addr = self.toc_address(0, msf);
                let lead_addr = self.toc_address(lead_out, msf);
                let mut b = [0u8; 22];
                b[1] = 0x12;
                b[2] = 0x01;
                b[3] = 0x01;
                match track {
                    0 | 1 => {
                        b[5] = 0x14;
                        b[6] = 0x01;
                        b[8..12].copy_from_slice(&track1_addr);
                        b[13] = 0x14;
                        b[14] = 0xAA;
                        b[16..20].copy_from_slice(&lead_addr);
                        (b, 20)
                    }
                    0xAA => {
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
                let mut b = [0u8; 22];
                b[1] = 0x0A;
                b[2] = 0x01;
                b[3] = 0x01;
                b[5] = 0x14;
                b[6] = 0x01;
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

    // ── GET CONFIGURATION ───────────────────────────────────────────

    fn get_configuration_cmd<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }

        build_get_config_response(work, self.common.profile, rt, start, alloc)
    }
}

// ── SpcDevice impl (delegates to common) ────────────────────────────

impl<F: FsStorage> SpcDevice for CdLiveFsDevice<F> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &CDROM_IDENTITY
    }

    fn id(&self) -> u64 {
        self.capacity()
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        cdrom_mode_page(page)
    }

    fn sense(&self) -> &Sense {
        &self.common.sense
    }

    fn sense_mut(&mut self) -> &mut Sense {
        &mut self.common.sense
    }

    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
        self.common.start_stop(loej, load)
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.common.set_prevent(prevent);
    }
}

// ── ScsiDevice impl ─────────────────────────────────────────────────

impl<F: FsStorage> ScsiDevice for CdLiveFsDevice<F> {
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        self.do_cmd(cdb, work, dsl)
    }

    fn read_data(
        &mut self,
        byte_offset: u64,
        buf: &mut [u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        self.read_data(byte_offset, buf)
    }

    fn write_data(
        &mut self,
        _byte_offset: u64,
        _buf: &[u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        Err(crate::scsi::backend::BlockStorageError::NotWritable)
    }

    fn sense(&self) -> &Sense {
        self.sense()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::BlockStorageError;
    use crate::scsi::fs_backend::StdFsBackend;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "snowscsi_livefs_{}_{}_{}",
            name,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn work() -> [u8; crate::MIN_WORK_LEN] {
        [0u8; crate::MIN_WORK_LEN]
    }

    /// Build a temp tree: README.TXT (1000 B), DATA.BIN (4096 B), SUB/NOTES.TXT (256 B).
    fn sample_tree() -> (std::path::PathBuf, StdFsBackend) {
        let dir = temp_dir("tree");
        std::fs::write(dir.join("README.TXT"), vec![0x41u8; 1000]).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 4096]).unwrap();
        std::fs::create_dir_all(dir.join("SUB")).unwrap();
        std::fs::write(dir.join("SUB/NOTES.TXT"), vec![0x43u8; 256]).unwrap();
        let fs = StdFsBackend::new(&dir.to_string_lossy());
        (dir, fs)
    }

    fn data_in(outcome: CommandOutcome<'_>, buf: &mut [u8]) -> usize {
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                immediate,
                ..
            } => {
                let n = transfer_len as usize;
                buf[..n].copy_from_slice(&immediate[..n]);
                n
            }
            _ => panic!("expected DataIn"),
        }
    }

    #[test]
    fn scan_builds_file_tree_and_layout() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let layout = dev.layout();
        assert_eq!(layout.label.as_str(), "TEST");
        // 3 files + 1 dir (SUB) = 4 entries; extents only for files.
        assert_eq!(layout.extents.len(), 3);
        // Metadata: PVD(16)+SVD(17)+Term(18)+PathTable(19)+Root(20) = 21, then files.
        assert_eq!(layout.root_dir_lba, 20);
        assert!(layout.total > 21);
    }

    #[test]
    fn metadata_sectors_generate_pvd_and_pad() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[8] = 0x08; // transfer 8 blocks... but only LBA 0 region
                       // READ LBA 0 (system area) → zeros.
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let _ = outcome;
        // Direct read of LBA 16 (PVD) via read_data.
        let mut sector = [0u8; 2048];
        dev.read_data(16 * 2048, &mut sector).unwrap();
        // PVD: byte 0 = volume descriptor type 1, byte 1 = "CD001".
        assert_eq!(sector[0], 0x01);
        assert_eq!(&sector[1..6], b"CD001");
        // System area LBA 0 → zeros.
        let mut sector = [0u8; 2048];
        dev.read_data(0, &mut sector).unwrap();
        assert_eq!(sector, [0u8; 2048]);
        drop(w);
    }

    #[test]
    fn read_capacity_reflects_total_sectors() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let mut out = [0u8; 8];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut out);
        assert_eq!(n, 8);
        let max_lba = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        let blk = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
        assert_eq!(blk, SECTOR_SIZE);
        assert_eq!(max_lba, dev.layout().total - 1);
    }

    #[test]
    fn file_data_reads_through_resolve() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        // DATA.BIN = 4096 B = 2 sectors. Locate its LBA via the layout.
        let data_extent = dev
            .layout()
            .extents
            .iter()
            .find(|e| e.size == 4096)
            .unwrap();
        let mut sector = [0u8; 2048];
        dev.read_data(u64::from(data_extent.lba) * 2048, &mut sector)
            .unwrap();
        assert_eq!(sector, [0x42u8; 2048]);
        // SUB/NOTES.TXT = 256 B — its last sector is zero-padded.
        let notes = dev.layout().extents.iter().find(|e| e.size == 256).unwrap();
        let mut sector = [0u8; 2048];
        dev.read_data(u64::from(notes.lba) * 2048, &mut sector)
            .unwrap();
        assert_eq!(&sector[..256], &[0x43u8; 256]);
        assert_eq!(&sector[256..], &[0u8; 2048 - 256]);
    }

    #[test]
    fn read_spanning_metadata_and_file_boundary() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        // READ 8 sectors from LBA 16 (PVD) → covers metadata (16-20) + first file (21+).
        let mut buf = vec![0u8; 8 * 2048];
        dev.read_data(16 * 2048, &mut buf).unwrap();
        // LBA 16 = PVD type 1.
        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..6], b"CD001");
        // LBA 20 = root directory (non-zero). LBA 21 = first file data.
        assert_ne!(&buf[4 * 2048..4 * 2048 + 16], &[0u8; 16]);
        // The first file extent begins at the first_file_lba (root_dir + 1).
        let first_lba = dev.layout().root_dir_lba + dev.layout().root_dir_sectors;
        let first_extent = dev.layout().extents.first().unwrap();
        assert_eq!(first_extent.lba, first_lba);
        // The data byte at the first file LBA must be non-zero (a real file).
        assert_ne!(buf[5 * 2048], 0);
        // And it must match one of our fill bytes (a real file's content).
        assert!([0x41u8, 0x42, 0x43].contains(&buf[5 * 2048]));
    }

    #[test]
    fn read_crosses_file_extents() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        // DATA.BIN (4096 B = exactly 2 full sectors). If a following
        // extent exists, a read past its 2 sectors must cross into it
        // (resolve() continues into the next extent) without error.
        let data_idx = dev
            .layout()
            .extents
            .iter()
            .position(|e| e.size == 4096)
            .unwrap();
        let data = dev.layout().extents[data_idx].clone();
        // Read exactly DATA's 2 sectors + the following extent's sectors,
        // which stays within the total disc. This crosses the file boundary.
        if data_idx + 1 < dev.layout().extents.len() {
            let next = dev.layout().extents[data_idx + 1].clone();
            let total_secs = (data.sectors + next.sectors) as usize;
            let mut buf = vec![0u8; total_secs * 2048];
            dev.read_data(u64::from(data.lba) * 2048, &mut buf).unwrap();
            assert_eq!(&buf[..2 * 2048], &[0x42u8; 2 * 2048]);
            // The next file's first byte differs from 0x42.
            assert_ne!(buf[2 * 2048], 0x42);
        } else {
            // DATA.BIN is the last extent — only its 2 sectors are valid.
            let mut two = vec![0u8; 2 * 2048];
            dev.read_data(u64::from(data.lba) * 2048, &mut two).unwrap();
            assert_eq!(two, vec![0x42u8; 2 * 2048]);
        }
    }

    #[test]
    fn write_returns_data_protect() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        assert_eq!(
            dev.write_data(0, &[0u8; 16]),
            Err(BlockStorageError::NotWritable)
        );
        // WRITE(10) CDB → CHECK CONDITION (DATA PROTECT).
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        let mut w = work();
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
    }

    #[test]
    fn inquiry_reports_cdrom() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let mut out = [0u8; 96];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut out);
        assert!(n >= 66);
        assert_eq!(out[0] & 0x1F, 0x05); // PDT = CD-ROM
    }

    #[test]
    fn get_configuration_profile_and_features() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_CONFIGURATION;
        cdb[8] = 0x40; // alloc 64
        let mut out = [0u8; 64];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut out);
        assert!(n >= 8);
        // Current profile (bytes 6-7) = CD-ROM (0x0008) for small trees.
        assert_eq!(&out[6..8], &[0x00, 0x08]);
        // Feature list starts at byte 8.
        assert!(out[8] == 0x00 && out[9] == 0x01); // Core
    }

    #[test]
    fn read_toc_single_track() {
        let (_dir, fs) = sample_tree();
        let mut dev = CdLiveFsDevice::new(fs, "TEST").unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[8] = 0x14; // alloc 20
        let mut out = [0u8; 20];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut out);
        assert_eq!(n, 20);
        assert_eq!(out[1], 0x12); // data length 18
        assert_eq!(out[2], 0x01); // first track
        assert_eq!(out[3], 0x01); // last track
        assert_eq!(out[5], 0x14); // track 1 descriptor
        assert_eq!(out[6], 0x01);
        assert_eq!(&out[8..12], &[0u8; 4]); // track 1 start = LBA 0
    }

    #[test]
    fn empty_tree_is_valid_empty_disc() {
        let dir = temp_dir("empty");
        let fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut dev = CdLiveFsDevice::new(fs, "EMPTY").unwrap();
        assert_eq!(dev.layout().extents.len(), 0);
        // READ CAPACITY → max_lba = 20 (metadata only).
        assert_eq!(dev.max_lba(), 20);
    }

    #[test]
    fn too_many_files_is_rejected() {
        let dir = temp_dir("many");
        for i in 0..(MAX_FILES + 1) {
            std::fs::write(dir.join(format!("F{i}.BIN")), vec![0u8; 1]).unwrap();
        }
        let fs = StdFsBackend::new(&dir.to_string_lossy());
        // The scan buffer is 32, so a 129-entry dir → DirTooLarge.
        assert!(matches!(
            CdLiveFsDevice::new(fs, "MANY"),
            Err(CdLiveFsError::DirTooLarge)
        ));
    }

    #[test]
    fn missing_root_dir_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("snowscsi_livefs_missing_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fs = StdFsBackend::new(&dir.to_string_lossy());
        assert!(CdLiveFsDevice::new(fs, "MISS").is_err());
    }
}
