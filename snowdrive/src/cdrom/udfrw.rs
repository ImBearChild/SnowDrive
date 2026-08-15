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
    build_get_config_response, build_read_disc_info, CdromDeviceCommon, CurrentProfile, DiscInfo,
    SECTOR_SIZE, UDFRW_CAPS,
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
        if backend.read(off, &mut sector).is_err() {
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
        backend
            .write(u64::from(layout.sbd_lba) * u64::from(SECTOR_SIZE), &sector)
            .map_err(UdfRwError::Block)?;
        for lba in (layout.sbd_lba + 1)..(layout.sbd_lba + layout.sbd_sectors) {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        write_sector(&mut backend, &layout, layout.root_icb_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.root_dir_lba, &mut sector)?;

        Ok(Self { backend, layout })
    }

    /// Capacity in bytes (the backend length).
    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
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
        self.backend.read(offset, buf)
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        self.backend.write(offset, buf)
    }

    /// Flush the byte plane.
    pub fn sync(&mut self) -> Result<(), BlockStorageError> {
        self.backend.sync()
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
    backend.write(off, sector).map_err(UdfRwError::Block)
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

    /// READ DISC INFORMATION (0x51): a finalized, erasable (rewritable)
    /// single-session data disc.
    fn read_disc_info_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        if cdb[1] & 0x07 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let info = DiscInfo {
            disc_status: 2,           // finalized
            state_of_last_session: 3, // complete
            erasable: true,           // rewritable
            sessions: 1,
            first_track: 1,
            last_track: 1,
            disc_type: 0x00, // oracle-verify: DVD media disc type
            lead_out_lba: self.lead_out_lba(),
        };
        build_read_disc_info(data, alloc, &info)
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
        let mut buf = [0u8; 12];
        buf[3] = 8; // Capacity List Length: one descriptor
        buf[4..8].copy_from_slice(&partition_len.to_be_bytes());
        buf[8] = 0x02; // Descriptor Type: formatted media
        buf[9] = 0x00;
        buf[10] = 0x08; // Block Length 2048 (24-bit)
        buf[11] = 0x00;
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
        cdb[8] = 12;
        let mut buf = [0u8; 12];
        let n = do_device_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(buf[3], 8, "capacity list length: one descriptor");
        let plen = dev.media().layout().partition_len;
        assert_eq!(&buf[4..8], &plen.to_be_bytes(), "formatted capacity");
        assert_eq!(buf[8], 0x02, "descriptor type: formatted");
        assert_eq!(&buf[9..12], &[0x00, 0x08, 0x00], "block length 2048");
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
        assert_eq!(n, 52);
        // Erasable 1 | State 11b | Disc Status 10b = 0b00011110.
        assert_eq!(buf[2], 0x1E);
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
        assert_eq!(n, 28); // 4 header + 24 page
        assert_eq!(buf[4], 0x2A); // page code
                                  // Byte 3 (as read by the kernel's sr driver): CD-R/CD-RW write,
                                  // DVD-R write (0x10), DVD-RAM write (0x20).
        assert_eq!(buf[7] & 0x01, 0x01, "CD-R write");
        assert_eq!(buf[7] & 0x10, 0x10, "DVD-R write");
        assert_eq!(buf[7] & 0x20, 0x20, "DVD-RAM write");
        // Byte 2 bit 3: DVD read.
        assert_eq!(buf[6] & 0x08, 0x08, "DVD read");
    }
}
