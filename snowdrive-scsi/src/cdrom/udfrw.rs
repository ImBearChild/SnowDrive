//! UdfRw media + device layer (`__UDFRW_PLAN.md` §7, commits 2–3).
//!
//! A random-writable DVD+RW over any [`BlockStorage`] backend, built on the
//! pure volume skeleton of [`crate::udf_void`].
//!
//! ## [`UdfRwMedia`] (commit 2) — the media layer
//! - **Materialize** the empty UDF 2.01 volume into the backend (once, on
//!   first use) by streaming the structured sectors from
//!   [`udf_void::gen_sector`] and patching the multi-sector SBD CRC.
//! - **Detect** an already-formatted volume (valid AVDP at sector 256) so
//!   reopening a persistent image does not rewrite it.
//! - **Data plane**: random byte-plane reads/writes through the backend.
//! - **Geometry**: capacity / last LBA / lead-out for the device layer.
//!
//! ## [`UdfRwDevice`] (commit 3) — the SCSI device
//! Presents the media as a DVD+RW: profile 0x001A, Random Writable + DVD+RW
//! features, and a READ/WRITE data plane. MMC commands dispatch here; SPC
//! commands go to [`CdromDeviceCommon`]. When the `CdromDrive`/`CdMedia`
//! rewrite (plan M1–M9) lands, the media becomes `CdMedia::UdfRw`.
//!
//! Free space is left as zeros; the OS filesystem (`udf`) allocates and
//! writes it later. This layer never parses UDF contents.

use crate::cdrom::common::{
    build_get_config_response, CdromDeviceCommon, CurrentProfile, SECTOR_SIZE, UDFRW_CAPS,
};
use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_len_from_opcode, cdb_opcode, cdb_read_args,
    cdb_transfer_len10, cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, Sense,
    SenseKey,
};
use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect};
use crate::udf_void::{
    compute_layout, gen_sector, is_avdp, patch_sbd_crc, sbd_crc, Layout, UdfError,
};

/// INQUIRY identity for the UdfRw device (plan §11.3 builder territory):
/// SCSI family with SPC-4 and MMC-6 version descriptors.
pub const UDFRW_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"Virtual UDF RW  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x05C0], /* SAM-5, iSCSI, SPC-4, MMC-6 */
};

/// A random-writable DVD+RW (UDF 2.01 plain build) over a byte plane.
pub struct UdfRwMedia<B: BlockStorage> {
    backend: B,
    layout: Layout,
}

impl<B: BlockStorage> UdfRwMedia<B> {
    /// Whether `backend` already holds a formatted UdfRw volume — a valid
    /// AVDP at sector 256 (tag id 2 + checksum + CRC).
    pub fn formatted(backend: &mut B) -> bool {
        let mut sector = [0u8; SECTOR_SIZE as usize];
        let off = u64::from(crate::udf_void::AVDP_LBA) * u64::from(SECTOR_SIZE);
        if backend.seek(embedded_io::SeekFrom::Start(off)).is_err()
            || backend.read_exact(&mut sector).is_err()
        {
            return false;
        }
        is_avdp(&sector)
    }

    /// Open an existing volume, or materialize a fresh one into `backend`.
    ///
    /// `force_mkfs` re-formats even when a valid volume is present (the
    /// `mkfs=true` CLI contract). `scratch` (≥ 1 byte) backs the space
    /// bitmap CRC computation.
    pub fn open_or_materialize(
        backend: B,
        label: &str,
        force_mkfs: bool,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let mut b = backend;
        if !force_mkfs && Self::formatted(&mut b) {
            let layout =
                compute_layout(sectors_of(b.capacity())?, label).map_err(UdfRwError::Layout)?;
            return Ok(Self { backend: b, layout });
        }
        Self::materialize(b, label, scratch)
    }

    /// Materialize the empty UDF 2.01 volume into `backend` unconditionally
    /// (destructive). Writes only the structured sectors; free space stays
    /// zero. `scratch` (≥ 1 byte) backs the SBD CRC computation.
    pub fn materialize(
        mut backend: B,
        label: &str,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let layout =
            compute_layout(sectors_of(backend.capacity())?, label).map_err(UdfRwError::Layout)?;

        let mut sector = [0u8; SECTOR_SIZE as usize];

        // VRS (3 sectors), main anchor.
        for lba in [16u32, 17, 18, crate::udf_void::AVDP_LBA] {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // Main VDS (PVD, IUVD, PD, LVD, USD, TD).
        for lba in layout.vds_lba..layout.vds_lba + 6 {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // LVID extent.
        write_sector(&mut backend, &layout, layout.lvid_lba, &mut sector)?;
        // Reserve VDS (mirror).
        for lba in layout.reserve_vds_lba..layout.reserve_vds_lba + 6 {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // Second + third anchors (N-257, N-1).
        write_sector(&mut backend, &layout, layout.anchor2_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.anchor3_lba, &mut sector)?;
        // Partition: FSD, USE, SBD (with the real CRC), root FE, root dir.
        write_sector(&mut backend, &layout, layout.fsd_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.use_lba, &mut sector)?;
        let crc = sbd_crc(&layout, scratch).map_err(UdfRwError::Layout)?;
        gen_sector(&layout, layout.sbd_lba, &mut sector);
        patch_sbd_crc(&mut sector, crc);
        let off = u64::from(layout.sbd_lba) * u64::from(SECTOR_SIZE);
        backend
            .seek(embedded_io::SeekFrom::Start(off))
            .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
        backend
            .write_all(&sector)
            .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
        for lba in (layout.sbd_lba + 1)..(layout.sbd_lba + layout.sbd_sectors) {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        write_sector(&mut backend, &layout, layout.root_icb_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.root_dir_lba, &mut sector)?;

        Ok(Self { backend, layout })
    }

    /// Capacity in bytes (the backend length).
    pub fn capacity(&self) -> u64 {
        BlockStorage::capacity(&self.backend)
    }

    /// Largest readable LBA (`capacity / 2048 − 1`, saturating).
    pub fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    /// Lead-out start LBA (number of data sectors).
    pub fn lead_out_lba(&self) -> u32 {
        (self.capacity() / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32
    }

    /// The underlying UDF void layout geometry.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Raw backend access.
    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Read from the byte plane (target data path).
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        self.backend
            .seek(embedded_io::SeekFrom::Start(offset))
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
        self.backend
            .read_exact(buf)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        self.backend
            .seek(embedded_io::SeekFrom::Start(offset))
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
        self.backend
            .write_all(buf)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// Flush the byte plane.
    pub fn sync(&mut self) -> Result<(), BlockStorageError> {
        BlockStorage::sync(&mut self.backend)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// Clear the logical medium as the destructive part of FORMAT UNIT.
    /// Formatting is completed logically by the command handler; the host
    /// writes the filesystem structures afterwards.
    fn clear(&mut self) -> Result<(), BlockStorageError> {
        let zeroes = [0u8; 8192];
        let mut offset = 0u64;
        while offset < self.capacity() {
            let len = (self.capacity() - offset).min(zeroes.len() as u64) as usize;
            self.backend
                .seek(embedded_io::SeekFrom::Start(offset))
                .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
            self.backend
                .write_all(&zeroes[..len])
                .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
            offset += len as u64;
        }
        Ok(())
    }
}

/// Floor `capacity` to whole 2048-byte sectors, rejecting volumes that do
/// not fit in the UDF void address space.
fn sectors_of(capacity: u64) -> Result<u32, UdfRwError> {
    u32::try_from(capacity / u64::from(SECTOR_SIZE)).map_err(|_| UdfRwError::CapacityTooLarge)
}

/// Generate and write one structured sector at `lba`.
fn write_sector<B: BlockStorage>(
    backend: &mut B,
    layout: &Layout,
    lba: u32,
    sector: &mut [u8; SECTOR_SIZE as usize],
) -> Result<(), UdfRwError> {
    gen_sector(layout, lba, sector);
    let off = u64::from(lba) * u64::from(SECTOR_SIZE);
    backend
        .seek(embedded_io::SeekFrom::Start(off))
        .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
    backend
        .write_all(sector)
        .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))
}

// ── SCSI device ─────────────────────────────────────────────────────

/// A random-writable DVD+RW SCSI device over a [`UdfRwMedia`] (plan
/// commit 3): DVD+RW profile, Random Writable + DVD+RW features, and a
/// full READ/WRITE data plane.
pub struct UdfRwDevice<B: BlockStorage> {
    common: CdromDeviceCommon,
    media: UdfRwMedia<B>,
}

impl<B: BlockStorage> UdfRwDevice<B> {
    /// Open an existing volume, or materialize a fresh one (see
    /// [`UdfRwMedia::open_or_materialize`]).
    pub fn open_or_materialize(
        backend: B,
        label: &str,
        force_mkfs: bool,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let media = UdfRwMedia::open_or_materialize(backend, label, force_mkfs, scratch)?;
        Ok(Self {
            common: CdromDeviceCommon::new(CurrentProfile::DvdRw),
            media,
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.common.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.common.sense
    }

    /// Raw media access (geometry, materialization, data plane).
    pub fn media(&mut self) -> &mut UdfRwMedia<B> {
        &mut self.media
    }

    pub fn capacity(&self) -> u64 {
        self.media.capacity()
    }

    fn max_lba(&self) -> u64 {
        self.media.max_lba()
    }

    fn lead_out_lba(&self) -> u32 {
        self.media.lead_out_lba()
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.common.sense = Sense::new(key, asc, ascq);
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.common.sense)
    }

    /// Read from the byte plane (target data path).
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self.media.read_data(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
                Err(e)
            }
        }
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        if offset == u64::MAX {
            // FORMAT UNIT's parameter list is consumed by the transport, not
            // written into the emulated medium.
            return Ok(());
        }
        match self.media.write_data(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
                Err(e)
            }
        }
    }

    /// Process one SCSI command. Dispatch order: SPC commands →
    /// `execute_spc`; MMC commands → handlers below; unknown → INVALID
    /// COMMAND.
    pub fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        if data.len() < crate::MIN_DATA_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let outcome = if let Some(cmd) = parse_spc(cdb) {
            // Dispatch via `self` (not `self.common`) so MODE SENSE 0x2A
            // reports the writable UdfRw capabilities, not the read-only
            // CD-ROM page.
            execute_spc(self, cmd, data, dsl)
        } else {
            let Some(op) = cdb_opcode(cdb) else {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            };
            if cdb.len() < usize::from(cdb_len_from_opcode(op)) {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            }
            match op {
                op::FORMAT_UNIT => self.format_unit_cmd(cdb),
                op::READ_6 | op::READ_10 | op::READ_12 | op::READ_16 => {
                    let Some((lba, count)) = cdb_read_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_cmd(lba, count, data)
                }
                op::WRITE_6 | op::WRITE_10 | op::WRITE_12 | op::WRITE_16 => {
                    let Some((lba, count)) = cdb_write_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.write_cmd(lba, count, data, dsl)
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
                op::READ_DISC_INFORMATION => self.read_disc_info_cmd(cdb, data),
                op::READ_TRACK_INFORMATION => self.read_track_information_cmd(cdb, data),
                op::CLOSE_TRACK => CommandOutcome::Status,
                op::SEND_OPC_INFORMATION => {
                    // DoOpc=1 performs drive-side calibration and carries no
                    // parameter data. The virtual medium has no OPC step.
                    if cdb[1] & 0x01 != 0 || cdb[7] == 0 && cdb[8] == 0 {
                        CommandOutcome::Status
                    } else {
                        // Consume a supplied OPC list without modifying the
                        // logical byte plane.
                        CommandOutcome::DataOut {
                            transfer_len: 0,
                            byte_offset: 0,
                            immediate: &[],
                        }
                    }
                }
                op::SET_STREAMING => CommandOutcome::DataOut {
                    // Performance hints are accepted and discarded. Returning
                    // DataOut with zero writes still drains the host payload.
                    transfer_len: 0,
                    byte_offset: 0,
                    immediate: &[],
                },
                op::SET_CD_SPEED => CommandOutcome::Status,
                op::GET_EVENT_STATUS_NOTIFICATION => self.gesn_cmd(cdb, data),
                op::GET_PERFORMANCE => self.get_performance_cmd(cdb, data),
                op::READ_DVD_STRUCTURE => self.read_dvd_structure_cmd(cdb, data),
                op::READ_FORMAT_CAPACITIES => self.read_format_capacities_cmd(cdb, data),
                op::SYNCHRONIZE_CACHE_10 => self.sync_cache_cmd(),
                _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND),
            }
        };
        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.common.sense = Sense::clear();
        }
        Ok(outcome)
    }

    /// FORMAT UNIT (0x04) for the DVD+RW Basic Format descriptor. Windows
    /// sends the 12-byte descriptor for this media even with FmtData clear
    /// (the captured command is `04 11 ...`). Accept that data phase as a
    /// compatibility behavior; a zero-length BOT transaction still completes
    /// immediately.
    ///
    /// CDB byte 1 bit layout (MMC-6 §6.4):
    /// - bit 7 (FmtData): 1 = parameter list follows, 0 = no parameter list
    /// - bit 4 (DCRT): Disable Certification — must be 1
    /// - bit 3 (Immediate): 0 = format completes before status, 1 = status
    ///   returned immediately. Both are accepted here since the virtual
    ///   medium clears synchronously either way.
    /// - bits 2:0: Defect List Format — must be 1 (format descriptor)
    fn format_unit_cmd<'a>(&mut self, cdb: &[u8]) -> CommandOutcome<'a> {
        if cdb[1] & 0x10 == 0 || cdb[1] & 0x07 != 1 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if self.media.clear().is_err() {
            return self.cc(SenseKey::MediumError, asc::WRITE_FAULT);
        }
        // The Windows optical formatter supplies the Basic Format Descriptor
        // despite clearing FmtData. Consume it either way so BOT reports zero
        // residue instead of treating the host payload as an overrun.
        CommandOutcome::DataOut {
            transfer_len: 12,
            byte_offset: u64::MAX,
            immediate: &[],
        }
    }

    /// Shared READ(6/10/12/16) handler (2048-byte sectors).
    fn read_cmd<'a>(&mut self, lba: u64, count: u32, _data: &'a mut [u8]) -> CommandOutcome<'a> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = count_to_bytes(count) else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        CommandOutcome::DataIn {
            transfer_len: u64::from(bytes),
            byte_offset: lba * u64::from(SECTOR_SIZE),
            immediate: &[],
        }
    }

    /// Shared WRITE(6/10/12/16) handler. The target delivers the payload
    /// via [`ScsiDevice::write_data`] at `byte_offset`.
    fn write_cmd<'a>(
        &mut self,
        lba: u64,
        count: u32,
        data: &'a mut [u8],
        dsl: usize,
    ) -> CommandOutcome<'a> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = count_to_bytes(count) else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        let bytes = bytes as usize;
        let imm = dsl.min(bytes).min(data.len());
        CommandOutcome::DataOut {
            transfer_len: bytes as u64,
            byte_offset: lba * u64::from(SECTOR_SIZE),
            immediate: &data[0..imm],
        }
    }

    fn check_lba_range(&self, lba: u64, count: u32) -> bool {
        lba <= self.max_lba()
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= self.max_lba() + 1)
    }

    fn read_capacity_10_cmd<'a>(
        &mut self,
        pmi: bool,
        req_lba: u32,
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        data[0..8].copy_from_slice(&buf);
        CommandOutcome::DataIn {
            transfer_len: 8,
            byte_offset: 0,
            immediate: &data[0..8],
        }
    }

    fn read_capacity_16_cmd<'a>(
        &mut self,
        sa: u8,
        alloc: u32,
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if sa != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        let n = 32.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[0..n],
        }
    }

    /// READ TOC/PMA/ATIP (0x43): single data track + lead-out, single
    /// session (the UdfRw volume's geometry, "one big track").
    fn read_toc_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
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
                        b[5] = 0x14; /* ADR=1, CONTROL=4 (data) */
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
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[0..n],
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

    /// GET CONFIGURATION (0x46): DVD+RW profile with Random Writable +
    /// DVD+RW features.
    fn get_configuration_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        build_get_config_response(
            data,
            self.common.profile,
            &UDFRW_CAPS,
            rt,
            start,
            alloc,
            self.max_lba().min(u32::MAX as u64) as u32,
        )
    }

    /// READ DISC INFORMATION (0x51): an appendable, erasable (rewritable)
    /// single-session data disc.
    fn read_disc_info_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        if cdb[1] & 0x07 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        // DVD+RW uses the short 32-byte disc-information body. This is a
        // formatted, erasable disc with one complete session. This logical
        // UDF medium is already prepared, so report completed formatting and
        // unrestricted write use.
        let mut buf = [0u8; 34];
        buf[0..2].copy_from_slice(&0x0020u16.to_be_bytes());
        buf[2] = 0x1E; // erasable | complete session | non-sequential disc
        buf[3] = 1; // first track
        buf[4] = 1; // number of sessions
        buf[5] = 1; // first track in last session
        buf[6] = 1; // last track in last session
                    // FORMAT UNIT is synchronous in this emulation, so report background
                    // formatting complete rather than leaving Windows in MRW active state.
        buf[7] = 0x23; // URU=1 | MRW=11b (background format complete)
        buf[8] = 0x00; // Disc Type is defined only for CD media (Table 365)
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// GET EVENT STATUS NOTIFICATION (0x4A): Windows polls the Media class
    /// to confirm media presence; failing this makes it treat the drive as
    /// unreliable.
    /// Respond with a Media "No Change" event, media present.
    fn gesn_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        let class = cdb[4];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        // Event Status Notification Response (MMC-6 Table 264/265) with a
        // Media class descriptor: no change, media present, tray closed.
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&4u16.to_be_bytes()); // descriptor length
        if class & 0x10 != 0 {
            buf[2] = 0x80 | 0x04; // NEA=0, Notification Class = Media (100b)
            buf[3] = 0x10; // supported event classes: Media
        } else {
            buf[2] = 0x80; // NEA=1, no requested class supported
        }
        // Event descriptor: Event Code 0 (NoChg), Media Present (bit 1).
        buf[4] = 0x00;
        buf[5] = 0x02;
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// GET PERFORMANCE (0xAC): return one conservative read/write speed
    /// descriptor. Hosts commonly use this as a capability probe; a short
    /// valid descriptor list is preferable to treating 0xAC as GESN.
    fn get_performance_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        let max_descriptors = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        if max_descriptors == 0 {
            data[0..4].copy_from_slice(&0u32.to_be_bytes());
            return CommandOutcome::DataIn {
                transfer_len: 4,
                byte_offset: 0,
                immediate: &data[..4],
            };
        }

        // Descriptor: start LBA, end LBA, read speed, write speed.
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&16u32.to_be_bytes());
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..12].copy_from_slice(&(self.max_lba().min(u32::MAX as u64) as u32).to_be_bytes());
        let speed = 1_385u32; // 1x DVD, in kB/s
        buf[12..16].copy_from_slice(&speed.to_be_bytes());
        buf[16..20].copy_from_slice(&speed.to_be_bytes());
        let n = buf.len().min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// READ TRACK INFORMATION (0x52): a formatted DVD+RW data track
    /// (MMC-6 §6.26, Table 494). Windows' optical stack queries this to
    /// determine media state; an INVALID COMMAND reply makes it fall back to
    /// read-only handling.
    fn read_track_information_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        let type_code = cdb[1] & 0x0F;
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        // Track Number Type (MMC-6 Table 492): 0=track, 1=session,
        // 2=track (extended), 3=session (extended). Tools query by session
        // (dvd+rw-mediainfo sends type 1) or by track; every form maps to
        // our single complete track, so only reject reserved types.
        if type_code > 3 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let capacity = self.lead_out_lba();
        // Track Information Block, 48 bytes (Data Length = 0x2E).
        let mut buf = [0u8; 48];
        buf[0..2].copy_from_slice(&0x002Eu16.to_be_bytes()); // data length
        buf[2] = 1; // logical track number (LSB)
        buf[3] = 1; // session number (LSB)
        buf[6] = 0x04; // uninterrupted Mode-1 data track
        buf[7] = 0x21; // Packet/Inc + Mode 1; LRA_V/NWA_V clear
        buf[8..12].copy_from_slice(&0u32.to_be_bytes()); // track start LBA
        buf[12..16].copy_from_slice(&0u32.to_be_bytes()); // NWA
        buf[16..20].copy_from_slice(&0u32.to_be_bytes()); // free blocks
        buf[20..24].copy_from_slice(&16u32.to_be_bytes()); // fixed packet size
        buf[24..28].copy_from_slice(&capacity.to_be_bytes()); // track size
        buf[28..32].copy_from_slice(&0u32.to_be_bytes()); // LRA
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// READ DVD STRUCTURE (0xAD): format 0 (Physical Format Information,
    /// MMC-6 §6.22.3.2.1, Table 398) and format 30h (Disc Control Blocks,
    /// MMC-6 §6.22.3.2.25). Format 0 reports a single-layer rewritable
    /// DVD+RW (Windows uses the Disk Category / Layer Type to decide whether
    /// the medium is writable); format 30h returns the Write Inhibit DCB
    /// (WDCB) whose Write Protect Actions field carries the media
    /// write-protect state — the authoritative channel for DVD+RW.
    fn read_dvd_structure_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        let media_type = cdb[1] & 0x3F;
        let layer = cdb[6] & 0x0F;
        let format = cdb[7];
        let alloc = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        if media_type != 0 || layer != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        match format {
            0 => {
                let capacity = self.lead_out_lba();
                let start = 0x0003_0000u32; // DVD data area start (physical sector)
                let end = start + capacity;
                let mut buf = [0u8; 28];
                buf[0..2].copy_from_slice(&0x0018u16.to_be_bytes()); // structure data length
                buf[4] = 0x91; // Disk Category 1001b (DVD+RW) | Part Version 1
                buf[6] = 0x04; // single layer, rewritable (Layer Type bit 2)
                buf[9..13].copy_from_slice(&start.to_be_bytes());
                buf[13..17].copy_from_slice(&end.to_be_bytes());
                buf[17..21].copy_from_slice(&end.to_be_bytes());
                let n = buf.len().min(alloc as usize).min(data.len());
                data[..n].copy_from_slice(&buf[..n]);
                CommandOutcome::DataIn {
                    transfer_len: n as u64,
                    byte_offset: 0,
                    immediate: &data[..n],
                }
            }
            0x30 => self.read_wdcb_cmd(cdb, alloc, data),
            0xC0 => self.read_write_protect_status_cmd(alloc, data),
            _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        }
    }

    /// READ DISC STRUCTURE format C0h: report aggregate write protection.
    fn read_write_protect_status_cmd<'a>(
        &mut self,
        alloc: u16,
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&4u16.to_be_bytes());
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// READ DVD STRUCTURE format 30h: return the Write Inhibit DCB (WDCB,
    /// Content Descriptor 57444300h, MMC-6 Table 435) with Write Protect
    /// Actions = 00b (media fully write enabled). The address field carries
    /// the requested Content Descriptor; only the WDCB is present on this
    /// drive.
    fn read_wdcb_cmd<'a>(
        &mut self,
        cdb: &[u8],
        alloc: u16,
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        let address = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]);
        if address != 0x5744_4300 && address != 0xFFFF_FFFF {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // Response: 2-byte structure data length + 2 reserved + the 32 KiB
        // DCB (padded with zeros per §6.22.3.2.25.1).
        const DCB_SIZE: usize = 32768;
        let mut buf = [0u8; 4 + DCB_SIZE];
        buf[0..2].copy_from_slice(&(DCB_SIZE as u16).to_be_bytes());
        // DCB header (Table 432): Content Descriptor + Unknown Actions +
        // Vendor ID.
        buf[4..8].copy_from_slice(&0x5744_4300u32.to_be_bytes());
        // Vendor ID: 32 bytes (Table 432 bytes 8-39).
        buf[12..44].copy_from_slice(b"SnowSCSI Virtual UDF RW\0\0\0\0\0\0\0\0\0");
        // WDCB (Table 435): Update Count (0) and Write Protect Actions (0 =
        // fully write enabled) at bytes 40/44 of the DCB; the password area
        // is zero-filled on read. All already zero.
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    /// READ FORMAT CAPACITIES (0x23): formatted media, random-writable —
    /// the current/maximum capacity descriptor carries the formatted
    /// partition length (MMC-6 §6.23.3.2.3, Table 466: DVD+RW).
    fn read_format_capacities_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if cdb[1] != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let partition_len = self.media.layout().partition_len;
        let mut buf = [0u8; 20];
        buf[3] = 16; // current descriptor + DVD+RW formattable descriptor
        buf[4..8].copy_from_slice(&partition_len.to_be_bytes());
        buf[8] = 0x02; // Descriptor Type: formatted media
        buf[9] = 0x00;
        buf[10] = 0x08; // Block Length 2048 (24-bit)
        buf[11] = 0x00;
        // MMC-6 Table 469: Format Type 26h is the mandatory DVD+RW full
        // format. The type-dependent parameter is zero for DVD+RW.
        buf[12..16].copy_from_slice(&partition_len.to_be_bytes());
        // Format Type occupies bits 7..2 of this byte (MMC-6 Table 468), so
        // DVD+RW Format Type 26h is transferred as 98h.
        buf[16] = 0x26 << 2;
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[0..n],
        }
    }

    /// SYNCHRONIZE CACHE (0x35): flush the byte plane.
    fn sync_cache_cmd(&mut self) -> CommandOutcome<'static> {
        match self.media.sync() {
            Ok(()) => CommandOutcome::Status,
            Err(_) => self.cc(SenseKey::MediumError, asc::WRITE_FAULT),
        }
    }
}

/// `count * 2048`, rejected (None) if it exceeds u32::MAX.
fn count_to_bytes(count: u32) -> Option<u32> {
    let bytes = u64::from(count).checked_mul(u64::from(SECTOR_SIZE))?;
    u32::try_from(bytes).ok()
}

/// Parse (LBA, transfer length) from a WRITE(6/10/12/16) CDB — the same
/// layout as the corresponding READ opcodes (`cdb_read_args` only handles
/// reads).
fn cdb_write_args(op: u8, cdb: &[u8]) -> Option<(u64, u32)> {
    match op {
        op::WRITE_6 => Some((u64::from(cdb_lba6(cdb)?), cdb_transfer_len6(cdb)?)),
        op::WRITE_10 => Some((
            u64::from(cdb_lba10(cdb)?),
            u32::from(cdb_transfer_len10(cdb)?),
        )),
        op::WRITE_12 => Some((u64::from(cdb_lba12(cdb)?), cdb_transfer_len12(cdb)?)),
        op::WRITE_16 => Some((cdb_lba16(cdb)?, cdb_transfer_len16(cdb)?)),
        _ => None,
    }
}

// ── SpcDevice impl (delegates to common) ────────────────────────────

impl<B: BlockStorage> SpcDevice for UdfRwDevice<B> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn medium_type(&self) -> u8 {
        0x41
    }

    fn identity(&self) -> &DeviceIdentity {
        &UDFRW_IDENTITY
    }

    fn id(&self) -> u64 {
        self.media.capacity()
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        crate::cdrom::common::udfrw_mode_page(page)
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

impl<B: BlockStorage> ScsiDevice for UdfRwDevice<B> {
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        self.do_cmd(cdb, data, dsl)
    }

    fn read_data(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        self.read_data(byte_offset, buf)
    }

    fn write_data(&mut self, byte_offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        self.write_data(byte_offset, buf)
    }

    fn sense(&self) -> &Sense {
        self.sense()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }
}

// ── Error type ──────────────────────────────────────────────────────

/// UdfRw media error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfRwError {
    /// Backend storage failure.
    Block(BlockStorageError),
    /// UDF void layout failure (capacity too small / scratch too small).
    Layout(UdfError),
    /// Backend capacity exceeds the UDF void address space.
    CapacityTooLarge,
}

impl From<BlockStorageError> for UdfRwError {
    fn from(e: BlockStorageError) -> Self {
        Self::Block(e)
    }
}

impl From<UdfError> for UdfRwError {
    fn from(e: UdfError) -> Self {
        Self::Layout(e)
    }
}

impl core::fmt::Display for UdfRwError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Block(e) => write!(f, "storage error: {e}"),
            Self::Layout(e) => write!(f, "layout error: {e}"),
            Self::CapacityTooLarge => {
                write!(f, "backend capacity exceeds the UDF void address space")
            }
        }
    }
}

impl core::error::Error for UdfRwError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;

    fn ram(capacity: u64) -> Vec<u8> {
        vec![0u8; capacity as usize]
    }

    /// Materialize into `img` (kept alive by the caller for the media's
    /// lifetime).
    fn materialize_into<'a>(img: &'a mut [u8]) -> UdfRwMedia<RamBackend<'a>> {
        let mut scratch = [0u8; 256];
        UdfRwMedia::materialize(RamBackend::new(img), "TEST", &mut scratch).unwrap()
    }

    #[test]
    fn formatted_detects_blank() {
        let mut img = ram(2048 * 4096);
        assert!(!UdfRwMedia::formatted(&mut RamBackend::new(&mut img)));
    }

    #[test]
    fn materialize_creates_valid_volume() {
        let mut img = ram(2048 * 4096);
        let mut m = materialize_into(&mut img);
        // Detection now succeeds on the materialized volume.
        assert!(UdfRwMedia::formatted(m.backend()));
        // VRS markers present.
        let mut s = [0u8; 2048];
        m.read_data(16 * 2048, &mut s).unwrap();
        assert_eq!(&s[1..6], b"BEA01");
        m.read_data(17 * 2048, &mut s).unwrap();
        assert_eq!(&s[1..6], b"NSR03");
        // Second + third anchors (N-257, N-1) have valid AVDPs.
        let n = m.layout().capacity_sectors;
        for anchor in [n - 257, n - 1] {
            let mut s = [0u8; 2048];
            m.read_data(u64::from(anchor) * 2048, &mut s).unwrap();
            assert!(is_avdp(&s), "anchor at {anchor}");
        }
    }

    #[test]
    fn write_data_read_data_roundtrip() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut m = UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch).unwrap();
        // Free block well past the partition head.
        let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
        let data = [0xAB; 2048];
        m.write_data(off, &data).unwrap();
        let mut out = [0u8; 2048];
        m.read_data(off, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn open_preserves_existing_content() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        {
            let mut m =
                UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch).unwrap();
            let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
            m.write_data(off, &[0xCD; 2048]).unwrap();
        }
        // Reopen without force: the volume (and the marker) survive.
        let mut m =
            UdfRwMedia::open_or_materialize(RamBackend::new(&mut img), "T", false, &mut scratch)
                .unwrap();
        assert!(UdfRwMedia::formatted(m.backend()));
        let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
        let mut out = [0u8; 2048];
        m.read_data(off, &mut out).unwrap();
        assert_eq!(out, [0xCD; 2048]);
    }

    #[test]
    fn force_mkfs_reformats_structure() {
        let mut img = ram(2048 * 4096);
        {
            let mut m = materialize_into(&mut img);
            // Corrupt the PVD (a structure sector), not the anchor.
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            m.write_data(pvd_off, &[0xEE; 2048]).unwrap();
        }
        // Without force: the AVDP is still valid, so the volume is opened
        // as-is and the corrupted PVD survives.
        {
            let mut scratch = [0u8; 256];
            let mut m = UdfRwMedia::open_or_materialize(
                RamBackend::new(&mut img),
                "TEST",
                false,
                &mut scratch,
            )
            .unwrap();
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            let mut s = [0u8; 2048];
            m.read_data(pvd_off, &mut s).unwrap();
            assert_eq!(s[0], 0xEE, "open must not rewrite a formatted volume");
        }
        // With force: the structure sectors are re-materialized.
        {
            let mut scratch = [0u8; 256];
            let m = UdfRwMedia::open_or_materialize(
                RamBackend::new(&mut img),
                "TEST",
                true,
                &mut scratch,
            )
            .unwrap();
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            let mut s = [0u8; 2048];
            let mut m = m;
            m.read_data(pvd_off, &mut s).unwrap();
            assert_eq!(s[24], 8, "PVD CS0 8-bit compression code");
            assert_eq!(&s[25..29], b"TEST");
        }
    }

    #[test]
    fn capacity_too_small_errors() {
        let mut img = ram(2048 * 100);
        let mut scratch = [0u8; 256];
        assert!(matches!(
            UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch),
            Err(UdfRwError::Layout(UdfError::CapacityTooSmall))
        ));
    }

    #[test]
    fn unaligned_capacity_floors_to_sectors() {
        let mut img = ram(2048 * 4096 + 100);
        let m = materialize_into(&mut img);
        assert_eq!(m.max_lba(), 4095);
        assert_eq!(m.lead_out_lba(), 4096);
    }

    // ── UdfRwDevice ──────────────────────────────────────────────────

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
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

    fn do_device_data_in<B: BlockStorage>(
        dev: &mut UdfRwDevice<B>,
        cdb: &[u8],
        work: &mut [u8],
        buf: &mut [u8],
    ) -> usize {
        let outcome = dev.do_cmd(cdb, work, 0).unwrap();
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                byte_offset,
                immediate,
            } => {
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
    fn device_write_read_roundtrip() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();

        // WRITE(10) to LBA 512 (free space) → DataOut; deliver the payload.
        let cdb = make_cdb10(op::WRITE_10, 512, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 2048);
                assert_eq!(byte_offset, 512 * 2048);
                assert!(immediate.is_empty());
                let payload = [0xA5u8; 2048];
                dev.write_data(byte_offset, &payload).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        // READ(10) it back.
        let cdb = make_cdb10(op::READ_10, 512, 1);
        let mut buf = [0u8; 2048];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 2048);
        assert_eq!(buf, [0xA5; 2048]);
    }

    #[test]
    fn device_write_out_of_range_rejected() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let cdb = make_cdb10(op::WRITE_10, 1 << 20, 1);
        match dev.do_cmd(&cdb, &mut w, 0).unwrap() {
            CommandOutcome::CheckCondition(s) => {
                assert_eq!(s.key, SenseKey::IllegalRequest);
                assert_eq!(s.asc, asc::LBA_OUT_OF_RANGE);
            }
            _ => panic!("expected CheckCondition"),
        }
    }

    #[test]
    fn device_get_configuration_dvd_rw() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_CONFIGURATION;
        cdb[8] = 255;
        let mut buf = [0u8; 256];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(buf[7], 0x1A, "current profile DVD+RW");
        let mut off = 8usize;
        let mut saw_rw = false;
        let mut saw_dvdrw = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            match code {
                0x0020 => saw_rw = true,
                0x002A => {
                    saw_dvdrw = true;
                    assert_eq!(buf[off + 4], 0x01); // Write
                }
                _ => {}
            }
            off += 4 + add_len;
        }
        assert!(saw_rw && saw_dvdrw, "Random Writable + DVD+RW features");
    }

    #[test]
    fn device_read_format_capacities() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::READ_FORMAT_CAPACITIES;
        cdb[8] = 20;
        let mut buf = [0u8; 20];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(buf[3], 16, "capacity list length: two descriptors");
        let plen = dev.media().layout().partition_len;
        assert_eq!(&buf[4..8], &plen.to_be_bytes(), "formatted capacity");
        assert_eq!(buf[8], 0x02, "descriptor type: formatted");
        assert_eq!(&buf[9..12], &[0x00, 0x08, 0x00], "block length 2048");
        assert_eq!(&buf[12..16], &plen.to_be_bytes(), "DVD+RW format capacity");
        assert_eq!(buf[16], 0x98, "DVD+RW full format (26h in bits 7..2)");
    }

    #[test]
    fn device_read_disc_info_erasable() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_DISC_INFORMATION;
        cdb[8] = 52;
        let mut buf = [0u8; 52];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 34);
        // Erasable 1 | State 11b | Disc Status 11b (non-sequential).
        assert_eq!(buf[2], 0x1E);
        assert_eq!(buf[8], 0x00, "DVD media has no CD disc type");
        // URU=1 and background format complete.
        assert_eq!(buf[7], 0x23);
        assert_eq!(buf[3], 1); // first track
    }

    #[test]
    fn device_read_toc_single_track() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[8] = 64;
        let mut buf = [0u8; 64];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(buf[2], 0x01); // first track
        assert_eq!(buf[3], 0x01); // last track
        assert_eq!(buf[5], 0x14); // data track
        assert_eq!(&buf[16..20], &4096u32.to_be_bytes()); // lead-out
    }

    #[test]
    fn device_sync_cache_flushes() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert!(matches!(
            dev.do_cmd(&cdb, &mut w, 0).unwrap(),
            CommandOutcome::Status
        ));
    }

    #[test]
    fn device_close_track_is_accepted() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::CLOSE_TRACK;
        assert!(matches!(
            dev.do_cmd(&cdb, &mut w, 0).unwrap(),
            CommandOutcome::Status
        ));
    }

    #[test]
    fn device_accepts_formatting_setup_commands() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();

        let mut opc = [0u8; 10];
        opc[0] = op::SEND_OPC_INFORMATION;
        opc[1] = 0x01; // DoOpc=1
        assert!(matches!(
            dev.do_cmd(&opc, &mut w, 0).unwrap(),
            CommandOutcome::Status
        ));

        let mut streaming = [0u8; 12];
        streaming[0] = op::SET_STREAMING;
        streaming[10] = 28;
        assert!(matches!(
            dev.do_cmd(&streaming, &mut w, 0).unwrap(),
            CommandOutcome::DataOut {
                transfer_len: 0,
                ..
            }
        ));

        let mut speed = [0u8; 12];
        speed[0] = op::SET_CD_SPEED;
        assert!(matches!(
            dev.do_cmd(&speed, &mut w, 0).unwrap(),
            CommandOutcome::Status
        ));
    }

    #[test]
    fn device_accepts_dvd_rw_format_unit_with_param_list() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        // FmtData=1 (bit7), DCRT=1 (bit4), DefectListFormat=1 (bits2:0) = 0x91
        let format = [0x04, 0x91, 0, 0, 0, 0];
        assert!(matches!(
            dev.do_cmd(&format, &mut w, 0).unwrap(),
            CommandOutcome::DataOut {
                transfer_len: 12,
                byte_offset: u64::MAX,
                ..
            }
        ));
        assert!(dev.write_data(u64::MAX, &[0u8; 12]).is_ok());
        assert!(!UdfRwMedia::formatted(dev.media().backend()));

        let mut info_cdb = [0u8; 10];
        info_cdb[0] = op::READ_DISC_INFORMATION;
        info_cdb[8] = 52;
        let mut info = [0u8; 52];
        let n = do_device_data_in(&mut dev, &info_cdb, &mut w, &mut info);
        assert_eq!(n, 34);
        assert_eq!(info[2], 0x1E);
        assert_eq!(info[7], 0x23, "URU=1 | background format complete");
        assert_eq!(info[8], 0x00, "DVD media has no CD disc type");

        let tur = [op::TEST_UNIT_READY; 6];
        assert!(matches!(
            dev.do_cmd(&tur, &mut w, 0).unwrap(),
            CommandOutcome::Status
        ));
    }

    #[test]
    fn device_format_unit_with_windows_param_list_returns_data_out() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        // Windows uses FmtData=0 (bit7 clear), DCRT=1 and DefectListFormat=1
        // (bits2:0) = 0x11, while still sending the 12-byte descriptor.
        let format = [0x04, 0x11, 0, 0, 0, 0];
        assert!(matches!(
            dev.do_cmd(&format, &mut w, 0).unwrap(),
            CommandOutcome::DataOut {
                transfer_len: 12,
                byte_offset: u64::MAX,
                ..
            }
        ));
    }

    #[test]
    fn device_mode_sense_2a_reports_writable() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x2A;
        cdb[4] = 64;
        let mut buf = [0u8; 64];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 60); // 4 header + 56-byte page
        assert_eq!(buf[0], 0x3B, "mode data length");
        assert_eq!(buf[1], 0x41, "DVD+RW medium type");
        assert_eq!(buf[4], 0x2A); // page code
                                  // Page byte 2 (buf[6]): CD-R/CD-RW read, Mode 2, Multi-Session, CD-DA.
        assert_eq!(buf[6] & 0x40, 0x40, "CD-R read");
        assert_eq!(buf[6] & 0x80, 0x80, "CD-RW read");
        // Page byte 3 (buf[7]): DVD read.
        assert_eq!(buf[7] & 0x08, 0x08, "DVD read");
        // Page byte 4 (buf[8]): CD-R write, CD-RW write, Test Write, BurnProof.
        assert_eq!(buf[8] & 0x40, 0x40, "CD-R write");
        assert_eq!(buf[8] & 0x80, 0x80, "CD-RW write");
    }

    #[test]
    fn device_read_disc_info_not_mrw() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_DISC_INFORMATION;
        cdb[8] = 52;
        let mut buf = [0u8; 64];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 34);
        // URU=1 and background format complete; this is not MRW status.
        assert_eq!(buf[7], 0x23);
        // Erasable bit (byte 2 bit 4).
        assert_eq!(buf[2] & 0x10, 0x10, "erasable");
    }

    #[test]
    fn device_read_dvd_structure_physical_format() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::READ_DVD_STRUCTURE;
        cdb[7] = 0; // format 0 = physical format information
        cdb[8] = 0;
        cdb[9] = 28;
        let mut buf = [0u8; 64];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 28);
        // Structure data length 0x18, Disk Category DVD+RW (0x9) | version 1.
        assert_eq!(&buf[0..2], &[0x00, 0x18]);
        assert_eq!(buf[4] >> 4, 0x9, "Disk Category = DVD+RW");
        // Layer Type rewritable (bit 2).
        assert_eq!(buf[6] & 0x04, 0x04, "rewritable layer");
    }

    #[test]
    fn device_read_dvd_structure_write_inhibit_dcb() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::READ_DVD_STRUCTURE;
        cdb[2] = 0x57; // address = Content Descriptor 57444300h (WDCB)
        cdb[3] = 0x44;
        cdb[4] = 0x43;
        cdb[5] = 0x00;
        cdb[7] = 0x30; // format 30h = Disc Control Blocks
        cdb[8] = 0x00;
        cdb[9] = 0x80; // alloc 128
        let mut buf = [0u8; 8192];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 128);
        // Disc Structure Data Length = 32768 (the full DCB), then reserved.
        assert_eq!(&buf[0..2], &[0x80, 0x00]);
        // DCB header Content Descriptor = "WDC\0".
        assert_eq!(&buf[4..8], &[0x57, 0x44, 0x43, 0x00]);
        // WDCB Write Protect Actions (DCB bytes 44..48) = 0 → fully write
        // enabled.
        assert_eq!(&buf[48..52], &[0, 0, 0, 0], "media not write protected");

        // An unknown Content Descriptor is rejected.
        let mut cdb2 = cdb;
        cdb2[5] = 0x01;
        let outcome = dev.do_cmd(&cdb2, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
    }

    #[test]
    fn device_read_dvd_structure_write_protect_status_clear() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::READ_DVD_STRUCTURE;
        cdb[7] = 0xC0;
        cdb[8] = 0;
        cdb[9] = 8;
        let mut buf = [0u8; 8];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 8);
        assert_eq!(&buf[0..2], &[0, 4]);
        assert_eq!(buf[4], 0, "no write protection is active");
    }

    #[test]
    fn device_read_track_information_complete() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TRACK_INFORMATION;
        cdb[2] = 0;
        cdb[3] = 1; // track 1
        cdb[7] = 0;
        cdb[8] = 38;
        let mut buf = [0u8; 64];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 38);
        // Track 1, session 1, formatted DVD+RW data track.
        assert_eq!(buf[2], 1);
        assert_eq!(buf[3], 1);
        assert_eq!(buf[6], 0x04, "Mode-1 data track");
        assert_eq!(buf[7], 0x21, "Packet/Inc, LRA/NWA invalid");
        assert_eq!(&buf[20..24], &16u32.to_be_bytes(), "fixed packet size");
        // Formatted DVD+RW reports no sequential NWA/free-space fields.
        let nwa = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let free = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(nwa, 0);
        assert_eq!(free, 0);
    }

    #[test]
    fn device_gesn_media_present() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_EVENT_STATUS_NOTIFICATION;
        cdb[1] = 0x01; // polled
        cdb[4] = 0x10; // Media class
        cdb[8] = 8;
        let mut buf = [0u8; 16];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 8);
        assert_eq!(&buf[0..2], &[0x00, 0x04]); // descriptor length
        assert_eq!(buf[2] & 0x80, 0x80, "NEA=0");
        assert_eq!(buf[2] & 0x07, 0x04, "Media class");
        assert_eq!(buf[3], 0x10, "supported: Media");
        assert_eq!(buf[5] & 0x02, 0x02, "media present");
    }

    #[test]
    fn device_get_performance_is_not_gesn() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut dev = UdfRwDevice::open_or_materialize(
            RamBackend::new(&mut img),
            "TEST",
            false,
            &mut scratch,
        )
        .unwrap();
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::GET_PERFORMANCE;
        cdb[8] = 0;
        cdb[9] = 1;
        let mut buf = [0u8; 32];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(&buf[0..4], &16u32.to_be_bytes());
        assert_eq!(&buf[12..16], &1_385u32.to_be_bytes());
    }
}
