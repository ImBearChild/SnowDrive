//! CDBlock device: a "lazy CD" — minimal CD-ROM.
//!
//! Reports itself as a CD-ROM (PDT=0x05) while reading a flat ISO image
//! through a read-only [`FileBackend`]. Implements a minimal MMC command set
//! (READ TOC, GET CONFIGURATION); SPC commands (INQUIRY, MODE SENSE, ...) are
//! delegated to [`crate::scsi::spc`]; all write commands return DATA PROTECT.
//! Because the backing store is always a read-only file, this module is
//! `std`-gated (`RamBackend` images are not supported).
//!
//! ## Scope boundary
//!
//! This device is a **deliberately independent, self-contained implementation
//! that lives in the SCSI core**: no filesystem backend, no external
//! dependencies. It is a "lazy CD" — it only does the minimum needed to be a
//! mountable read-only CD-ROM, and it does **not** chase burner-tool
//! compatibility (READ BUFFER CAPACITY, SET SPEED, write-parameters mode
//! page, READ DISC/TRACK INFO, ...). Tools like `cdrwtool` probe that full
//! MMC surface and will fail against this device — use [`crate::cdrom`]
//! (`CdromDevice` / `CdLiveFsDevice`) when a complete MMC command set is
//! required. READ TOC (0x43) is kept because the
//! Linux `sr`/generic-cdrom driver needs it to mount `/dev/srX`.

use crate::scsi::backend::{BlockStorage, BlockStorageError, FileBackend};
use crate::scsi::device::{
    CommandOutcome, DeviceType, Error, PendingXfer, ScsiDevice, XferDir, XferError, XferOutcome,
};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_len_from_opcode, cdb_opcode, cdb_read_args, op, Sense, SenseKey,
};
use crate::scsi::spc::{
    block_mode_page, execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect,
};

/// CD-ROM logical block size (Mode 1: 2048 data bytes per sector).
pub const SECTOR_SIZE: u32 = 2048;

/// INQUIRY identity for the CDBlock device (plan §8.1b): SCSI family, with
/// the SPC-4 and MMC-6 version descriptors replacing the block device's SBC.
pub const CDBLOCK_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"HyperMulti DVD  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x05C0], /* SAM-5, iSCSI, SPC-4, MMC-6 */
};

const CLEAR_SENSE: Sense = Sense::clear();

/// The CDBlock device: a read-only CD-ROM emulated over a flat file.
pub struct CDBlockDevice {
    backend: FileBackend,
    sector_size: u32,
    sense: Option<Sense>,
    pending: Option<PendingXfer>,
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
            sense: None,
            pending: None,
            prevent_removal: false,
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn peek_sense(&self) -> Option<&Sense> {
        self.sense.as_ref().filter(|s| s.key != SenseKey::None)
    }

    pub fn take_sense(&mut self) -> Option<Sense> {
        let s = self.sense.take()?;
        if s.key == SenseKey::None {
            None
        } else {
            Some(s)
        }
    }

    /// Raw backend access (target data path reads chunks via
    /// [`BlockStorage`]; the device is read-only, so only reads are
    /// meaningful).
    pub fn backend(&mut self) -> &mut FileBackend {
        &mut self.backend
    }

    /// Image size in bytes (from the file opened at construction).
    pub fn capacity(&self) -> u64 {
        BlockStorage::capacity(&self.backend)
    }

    /// Largest readable LBA: `(file_size / 2048) - 1`. Saturates to 0 for
    /// images smaller than one sector (READ CAPACITY still reports a valid
    /// last-LBA of 0).
    pub(crate) fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Some(Sense::new(key, asc, ascq));
    }

    /// CHECK CONDITION helper for non-SPC commands (SBC/MMC dispatch).
    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<(), BlockStorageError> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(BlockStorageError::OutOfBounds)?;
        if end > BlockStorage::capacity(&self.backend) {
            return Err(BlockStorageError::OutOfBounds);
        }
        Ok(())
    }

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    /// `transfer_offset` is the byte offset within the transfer.
    pub fn xfer_out(&mut self, transfer_offset: u64, buf: &mut [u8]) -> XferOutcome {
        let (dir, transfer_len, base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return XferOutcome::Error(XferError::NoCommand);
            }
        };
        if dir != XferDir::Out {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return XferOutcome::Error(XferError::Direction);
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return XferOutcome::Error(XferError::Overrun);
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return XferOutcome::Error(XferError::Overrun);
        }
        let actual = base_byte + transfer_offset;
        if self.check_bounds(actual, buf.len()).is_err() {
            self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::OutOfBounds));
        }
        if embedded_io::Seek::seek(&mut self.backend, embedded_io::SeekFrom::Start(actual)).is_err()
        {
            self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        if embedded_io::Read::read_exact(&mut self.backend, buf).is_err() {
            self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        XferOutcome::Ok
    }

    /// Write `buf` for the current WRITE transfer (host → device).
    /// This device is read-only; any write is rejected with DATA PROTECT.
    pub fn xfer_in(&mut self, transfer_offset: u64, buf: &[u8]) -> XferOutcome {
        let (dir, transfer_len, _base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return XferOutcome::Error(XferError::NoCommand);
            }
        };
        if dir != XferDir::In {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return XferOutcome::Error(XferError::Direction);
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return XferOutcome::Error(XferError::Overrun);
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return XferOutcome::Error(XferError::Overrun);
        }
        self.set_sense(SenseKey::DataProtect, asc::WRITE_PROTECTED, 0);
        XferOutcome::Error(XferError::WriteProtected)
    }

    /// Process one SCSI command (mirrors `BlockDevice::do_cmd`). `data`
    /// must be at least [`crate::MIN_DATA_LEN`] bytes.
    ///
    /// Dispatch order: SPC commands go to [`execute_spc`]; the SBC read-only
    /// set (READ 6/10/12/16, READ CAPACITY 10/16) is handled here; write
    /// commands (WRITE 6/10/12/16, SYNCHRONIZE CACHE) return DATA PROTECT;
    /// unknown MMC opcodes return INVALID COMMAND.
    pub fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
        self.pending = None;
        if data.len() < crate::MIN_DATA_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let outcome = if let Some(cmd) = parse_spc(cdb) {
            execute_spc(self, cmd, data)
        } else {
            // Total: `do_cmd` is public API — reject CDBs shorter than
            // their opcode group's fixed length (SPC-4 §7.3) before any
            // field access, instead of panicking on a short slice.
            let Some(op) = cdb_opcode(cdb) else {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            };
            if cdb.len() < usize::from(cdb_len_from_opcode(op)) {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            }
            match op {
                op::READ_6 | op::READ_10 | op::READ_12 | op::READ_16 => {
                    let Some((lba, count)) = cdb_read_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_cmd(lba, count, data)
                }
                op::READ_CAPACITY_10 => {
                    let Some(lba) = cdb_lba10(cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_capacity_10_cmd(cdb[1] & 0x01 != 0, lba, data)
                }
                op::SERVICE_ACTION_IN => {
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    self.read_capacity_16_cmd(cdb[1], alloc, data)
                }
                op::READ_TOC => self.read_toc_cmd(cdb, data),
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, data),
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
        Ok(outcome)
    }

    /// Shared READ(6/10/12/16) handler (2048-byte sectors, backend read).
    pub(crate) fn read_cmd(&mut self, lba: u64, count: u32, _data: &mut [u8]) -> CommandOutcome {
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
        let transfer_len = u64::from(bytes);
        let base_byte = lba * u64::from(SECTOR_SIZE);
        self.pending = Some(PendingXfer {
            base_byte,
            block_size: SECTOR_SIZE,
            dir: XferDir::Out,
            transfer_len,
        });
        CommandOutcome::OutXfer { len: transfer_len }
    }

    /// LBA range check: `lba + count` must not exceed `max_lba + 1`.
    fn check_lba_range(&self, lba: u64, count: u32) -> bool {
        lba <= self.max_lba()
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= self.max_lba() + 1)
    }

    pub(crate) fn read_capacity_10_cmd(
        &mut self,
        pmi: bool,
        req_lba: u32,
        data: &mut [u8],
    ) -> CommandOutcome {
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        data[0..8].copy_from_slice(&buf);
        CommandOutcome::OutInline { len: 8 }
    }

    pub(crate) fn read_capacity_16_cmd(
        &mut self,
        sa: u8,
        alloc: u32,
        data: &mut [u8],
    ) -> CommandOutcome {
        if sa != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        let n = 32.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n as u64 }
    }

    /// READ TOC/PMA/ATIP (0x43) — minimal implementation (MMC-6 §6.25).
    ///
    /// Supports only Format 0000b (formatted TOC: single data track +
    /// lead-out, plan §8.1b) and Format 0001b (session info: single
    /// session). Track/Session Number 0 or 1 returns the full TOC; AAh
    /// returns just the lead-out descriptor; MSF selects MSF-form addresses
    /// (LBA 0 → 00:02:00); the response is clamped to the allocation length
    /// without shrinking the TOC Data Length field.
    fn read_toc_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
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
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n as u64 }
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
    fn get_configuration_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
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
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n as u64 }
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
        BlockStorage::capacity(&self.backend)
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        // MODE SENSE is identical to the block device — the caching page
        // (0x08), vendor page (0x00) and the 0x3F concatenation.
        block_mode_page(page)
    }

    fn sense(&self) -> &Sense {
        self.sense
            .as_ref()
            .filter(|s| s.key != SenseKey::None)
            .unwrap_or(&CLEAR_SENSE)
    }

    fn sense_mut(&mut self) -> &mut Sense {
        if self.sense.is_none() {
            self.sense = Some(Sense::clear());
        }
        self.sense.as_mut().unwrap()
    }

    fn start_stop(&mut self, _loej: bool, _load: bool) -> SpcEffect {
        // Plan §8.1b: START STOP UNIT is accepted and ignored.
        SpcEffect::Good
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }
}

impl ScsiDevice for CDBlockDevice {
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
        self.do_cmd(cdb, data)
    }

    fn xfer_out(&mut self, transfer_offset: u64, buf: &mut [u8]) -> XferOutcome {
        self.xfer_out(transfer_offset, buf)
    }

    fn xfer_in(&mut self, transfer_offset: u64, buf: &[u8]) -> XferOutcome {
        self.xfer_in(transfer_offset, buf)
    }

    fn peek_sense(&self) -> Option<&Sense> {
        self.peek_sense()
    }

    fn take_sense(&mut self) -> Option<Sense> {
        self.take_sense()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn complete_param(&mut self, _cdb: &[u8], _data: &[u8]) -> CommandOutcome {
        // CDBlock accepts MODE SELECT as no-op.
        CommandOutcome::Status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::device::{CommandOutcome, XferError, XferOutcome};

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
        use embedded_io::Write;
        assert_eq!(
            dev.backend().write(&[0xAA; 16]),
            Err(embedded_io::ErrorKind::Other)
        );
    }

    #[test]
    fn cdblock_backend_reads_file_contents() {
        let f = TempFile::new(4096);
        std::fs::write(&f.path, vec![0x42u8; 4096]).unwrap();
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut buf = [0u8; 4];
        use embedded_io::Read;
        use embedded_io::Seek;
        dev.backend()
            .seek(embedded_io::SeekFrom::Start(2048))
            .unwrap();
        dev.backend().read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x42; 4]);
    }

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    /// Run one full SCSI command via `do_cmd` and fetch the payload, reading
    /// backend-resident DataIn through `xfer_out` when `immediate` is empty.
    fn do_data_in(dev: &mut CDBlockDevice, cdb: &[u8], work: &mut [u8], buf: &mut [u8]) -> usize {
        let outcome = dev.do_cmd(cdb, work).unwrap();
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert!(len as usize <= buf.len());
                let n = len as usize;
                assert_eq!(dev.xfer_out(0, &mut buf[..n]), XferOutcome::Ok);
                n
            }
            CommandOutcome::OutInline { len } => {
                assert!(len as usize <= buf.len());
                let n = len as usize;
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected DataIn"),
        }
    }

    /// Check condition sense from a do_cmd dispatch.
    fn check_condition(dev: &CDBlockDevice, outcome: CommandOutcome) -> (SenseKey, u8) {
        match outcome {
            CommandOutcome::CheckCondition => {
                let s = dev.peek_sense().expect("sense should be set");
                (s.key, s.asc)
            }
            _ => panic!("expected CheckCondition"),
        }
    }

    #[test]
    fn cdblock_unknown_opcode_returns_invalid_command() {
        use crate::scsi::scsi::asc;

        let f = TempFile::new(2048 * 100);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(
            check_condition(&dev, outcome),
            (SenseKey::IllegalRequest, asc::INVALID_COMMAND)
        );
        // READ DISC INFORMATION (0x51) is an MMC command this minimal
        // device does not implement → INVALID COMMAND (plan §8.1b).
        let mut cdb = [0u8; 10];
        cdb[0] = 0x51;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(
            check_condition(&dev, outcome),
            (SenseKey::IllegalRequest, asc::INVALID_COMMAND)
        );
    }

    #[test]
    fn cdblock_read_failure_sets_medium_error() {
        let f = TempFile::new(2048 * 4);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        // xfer_out without prior do_cmd -> NoCommand -> IllegalRequest 0x24
        let mut buf = [0u8; 2048];
        let r = dev.xfer_out(0, &mut buf);
        assert_eq!(r, XferOutcome::Error(XferError::NoCommand));
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, 0x24);
        // Valid read then overrun
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[5] = 0;
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        match outcome {
            CommandOutcome::OutXfer { len } => assert_eq!(len, 2048),
            _ => panic!("expected DataIn"),
        }
        let mut big = [0u8; 4096];
        let r = dev.xfer_out(0, &mut big);
        assert_eq!(r, XferOutcome::Error(XferError::Overrun));
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, 0x21);
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
}
