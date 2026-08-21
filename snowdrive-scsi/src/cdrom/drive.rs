//! CdromDrive: unified CD-ROM device with swappable media (plan ).
//!
//! One constant device identity + one mutable media slot.  **All** MMC
//! command dispatch lives here; media types only provide geometry and a
//! data plane.  `SpcDevice` is implemented directly — `CdromDeviceCommon`
//! is retired.
//!
//! `CdromDrive::builder()` constructs the drive identity (INQUIRY, caps,
//! drive_id).  Media is injected at runtime via `load()`/`eject()`.

use crate::cdrom::common::{
    build_get_config_response_for_media, build_read_buffer_capacity, build_read_disc_info,
    cdrom_mode_page_for_caps, default_write_params_page, CdromCapabilities, DiscInfo, MediaState,
    CDROM_IDENTITY, SECTOR_SIZE,
};
use crate::cdrom::media::CdMedia;
#[cfg(feature = "udf_void")]
use crate::cdrom::udfrw::UdfRwMedia;
use crate::scsi::device::{CommandOutcome, DeviceType};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_len_from_opcode, cdb_opcode, cdb_read_args, cdb_write_args, op, Sense,
    SenseKey,
};
use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcCommand, SpcDevice, SpcEffect};

// ── CdromDrive ────────────────────────────────────────

/// Unified CD-ROM drive with a swappable media slot.
///
/// The drive identity (INQUIRY, caps, drive_id) is constant; the media
/// slot is mutable.  `SpcDevice` is implemented directly here.
pub struct CdromDrive<'a> {
    pub(crate) sense: Sense,
    pub(crate) prevent_removal: bool,
    /// Pending sense to be reported on the next command (except INQUIRY).
    /// This subsumes the old `pending`: a UA is just a sense with
    /// `06/28` that is pending until the next CHECK. After it is reported
    /// (whether via a CHECK's Response or via a subsequent REQUEST SENSE),
    /// it is considered delivered and cleared.
    pub(crate) pending: Option<Sense>,
    /// Device capability model — single source for GET CONFIG features
    /// and MODE SENSE 0x2A page.
    pub(crate) caps: CdromCapabilities,
    /// VPD 0x80/0x83恒定标识（换盘不漂移,）.
    pub(crate) drive_id: u64,
    /// INQUIRY identity.
    pub(crate) identity: DeviceIdentity,
    /// Media slot: `None` = empty tray.
    pub(crate) media: Option<CdMedia<'a>>,
    /// Tray state: `true` = open (plan  ASCQ).
    pub(crate) tray_open: bool,
    /// Page 0x05 write parameter cache (plan /).
    #[allow(dead_code)] // used in later milestones
    pub(crate) mode_page_05: [u8; 52],
    #[allow(dead_code)]
    pub(crate) mode_page_05_valid: bool,
    /// `true` when `load()` was requested by START STOP Load=1 on empty tray
    /// (plan /).
    pub(crate) media_requested: bool,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl Default for CdromDrive<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CdromDrive<'a> {
    /// Create a drive with default identity and capabilities.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Start building a new drive.
    pub fn builder() -> CdromDriveBuilder {
        CdromDriveBuilder {
            identity: CDROM_IDENTITY,
            caps: CdromCapabilities::hyper_multi(),
            drive_id: 0,
        }
    }

    // ── Media slot ─────────────────────────────────────

    /// Load media into the drive (sets UNIT ATTENTION).
    pub fn load(&mut self, media: CdMedia<'a>) {
        self.media = Some(media);
        self.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
    }

    /// Load media without setting UNIT ATTENTION (for test setup / initial load).
    pub fn load_quiet(&mut self, media: CdMedia<'a>) {
        self.media = Some(media);
    }

    /// Eject the media.
    pub fn eject(&mut self) {
        self.media = None;
        self.tray_open = true;
        self.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
    }

    /// Whether media is present.
    pub fn is_media_present(&self) -> bool {
        self.media.is_some()
    }

    /// Whether `load()` was requested by START STOP Load=1 on empty tray.
    pub fn media_requested(&self) -> bool {
        self.media_requested
    }

    // ── Helper ─────────────────────────────────────────────────────

    fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Sense::new(key, asc, ascq);
    }

    fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.sense)
    }

    fn not_ready(&mut self) -> CommandOutcome<'static> {
        let ascq = if self.tray_open {
            asc::MEDIUM_NOT_PRESENT_TRAY_OPEN
        } else {
            asc::MEDIUM_NOT_PRESENT_TRAY_CLOSED
        };
        self.cc(SenseKey::NotReady, asc::MEDIUM_NOT_PRESENT);
        // The above sets ascq=0, but we need the specific ASCQ.
        // Override sense with correct ASCQ.
        self.sense = Sense::new(SenseKey::NotReady, asc::MEDIUM_NOT_PRESENT, ascq);
        CommandOutcome::CheckCondition(self.sense)
    }

    fn lead_out_lba(&self) -> u32 {
        if let Some(ref m) = self.media {
            return m.lead_out_lba();
        }
        0
    }

    fn max_lba(&self) -> u64 {
        if let Some(ref m) = self.media {
            return m.max_lba();
        }
        0
    }

    /// Whether the loaded medium accepts SBC random writes.
    fn is_random_writable(&self) -> bool {
        self.media_state().random_writable
    }

    fn media_state(&self) -> MediaState {
        self.media
            .as_ref()
            .map(CdMedia::state)
            .unwrap_or_else(MediaState::empty)
    }

    /// TOC address helper (LBA or MSF).
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

    // ── Unified command dispatch ───────────────────────

    /// Process one SCSI command.  **All** MMC commands are dispatched
    /// here — media only provides structured values.
    pub fn do_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'b>, crate::scsi::device::Error> {
        if data.len() < crate::MIN_DATA_LEN {
            return Err(crate::scsi::device::Error::WorkBufTooSmall);
        }

        // Plan : UNIT ATTENTION takes priority over everything
        // except INQUIRY / REQUEST SENSE / REPORT LUNS.
        let spc = parse_spc(cdb);
        if let Some(ua) = self.pending {
            if let Some(cmd) = spc {
                match cmd {
                    SpcCommand::Inquiry { .. } | SpcCommand::ReceiveDiagnosticResults { .. } => {
                        // Bypass: don't report or clear UA.
                    }
                    SpcCommand::RequestSense { .. } => {
                        // Merge UA into sense; execute_spc will read & clear it.
                        self.sense = ua;
                        self.pending = None;
                    }
                    _ => {
                        // iSCSI delivers sense in the Response PDU, so the
                        // host may never send REQUEST SENSE; clear UA after
                        // the first CHECK so the next command (e.g. TEST_UNIT_READY
                        // retried by udev) sees GOOD.
                        self.pending = None;
                        self.sense = ua;
                        return Ok(CommandOutcome::CheckCondition(ua));
                    }
                }
            } else {
                // Non-SPC opcodes: check REPORT LUNS and REQUEST SENSE.
                let op = cdb_opcode(cdb);
                match op {
                    Some(o) if o == op::REPORT_LUNS => {}
                    Some(o) if o == op::REQUEST_SENSE => {
                        self.sense = ua;
                        self.pending = None;
                    }
                    _ => {
                        self.pending = None;
                        self.sense = ua;
                        return Ok(CommandOutcome::CheckCondition(ua));
                    }
                }
            }
        }

        // ── Intercept TUR before execute_spc ──────────
        if let Some(SpcCommand::TestUnitReady) = spc {
            if self.media.is_some() {
                let outcome = CommandOutcome::Status;
                self.sense = Sense::clear();
                return Ok(outcome);
            }
            return Ok(self.not_ready());
        }

        if let Some(SpcCommand::ModeSense {
            long,
            page: 0x05,
            alloc,
        }) = spc
        {
            return Ok(self.mode_sense_write_params(long, alloc, data));
        }
        if let Some(SpcCommand::ModeSelect { long, alloc }) = spc {
            return Ok(self.mode_select_cmd(long, alloc, data, dsl));
        }

        let outcome = if let Some(cmd) = spc {
            execute_spc(self, cmd, data, dsl)
        } else {
            let Some(op) = cdb_opcode(cdb) else {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            };
            if cdb.len() < usize::from(cdb_len_from_opcode(op)) {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            }
            match op {
                op::FORMAT_UNIT => self.format_unit_cmd(cdb, data, dsl),
                // ── READ(6/10/12/16) ────────────────────────────
                op::READ_6 | op::READ_10 | op::READ_12 | op::READ_16 => {
                    let Some((lba, count)) = cdb_read_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_cmd(lba, count, data)
                }

                // ── WRITE(6/10/12/16) ───────────────────────────
                op::WRITE_6 | op::WRITE_10 | op::WRITE_12 | op::WRITE_16 => {
                    let Some((lba, count)) = cdb_write_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    if !self.is_random_writable() {
                        self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                    } else if count == 0 {
                        CommandOutcome::Status
                    } else if lba > self.max_lba()
                        || lba
                            .checked_add(u64::from(count))
                            .is_none_or(|end| end > self.max_lba() + 1)
                    {
                        self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE)
                    } else {
                        let Some(bytes) = u64::from(count).checked_mul(u64::from(SECTOR_SIZE))
                        else {
                            return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD));
                        };
                        let received = dsl.min(data.len());
                        if received as u64 > bytes {
                            self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                        } else {
                            CommandOutcome::DataOut {
                                transfer_len: bytes,
                                byte_offset: lba * u64::from(SECTOR_SIZE),
                                immediate: &data[..received],
                            }
                        }
                    }
                }

                // ── READ CAPACITY(10) ───────────────────────────
                op::READ_CAPACITY_10 => {
                    let Some(lba) = cdb_lba10(cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_capacity_10_cmd(cdb[1] & 0x01 != 0, lba, data)
                }

                // ── READ CAPACITY(16) ───────────────────────────
                op::SERVICE_ACTION_IN => {
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    self.read_capacity_16_cmd(cdb[1], alloc, data)
                }

                // ── READ TOC (0x43) ─────────────────────────────
                op::READ_TOC => {
                    if self.media.is_none() {
                        return Ok(self.not_ready());
                    }
                    self.read_toc_cmd(cdb, data)
                }

                // ── GET CONFIGURATION (0x46) ─────────────────────
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, data),

                // ── READ DISC INFORMATION (0x51) ─────────────────
                op::READ_DISC_INFORMATION => {
                    if self.media.is_none() {
                        return Ok(self.not_ready());
                    }
                    self.read_disc_info_cmd(cdb, data)
                }

                // ── READ BUFFER CAPACITY (0x5C) ──────────────────
                op::READ_BUFFER_CAPACITY => self.read_buffer_capacity_cmd(cdb, data),

                // ── GET EVENT STATUS NOTIFICATION (0x4A) ──────────
                op::GET_EVENT_STATUS_NOTIFICATION => self.gesn_cmd(cdb, data),

                // ── READ DVD STRUCTURE (0xAD) ────────────────────
                op::READ_DVD_STRUCTURE => {
                    if self.media.is_none() {
                        return Ok(self.not_ready());
                    }
                    self.read_dvd_structure_cmd(cdb, data)
                }

                // ── READ TRACK INFORMATION (0x52) ────────────────
                op::READ_TRACK_INFORMATION => {
                    if self.media.is_none() {
                        return Ok(self.not_ready());
                    }
                    self.read_track_information_cmd(cdb, data)
                }

                // ── READ FORMAT CAPACITIES (0x23) ────────────────
                op::READ_FORMAT_CAPACITIES => self.read_format_capacities_cmd(cdb, data),

                // ── SYNCHRONIZE CACHE(10) ────────────────────────
                op::SYNCHRONIZE_CACHE_10 => self.sync_cache_cmd(),

                // ── SET CD SPEED (0xBB) ──────────────────────────
                op::SET_CD_SPEED => CommandOutcome::Status,

                // ── SEND OPC (0x54) ──────────────────────────────
                op::SEND_OPC_INFORMATION => {
                    if cdb[1] & 0x01 != 0 || cdb[7] == 0 && cdb[8] == 0 {
                        CommandOutcome::Status
                    } else {
                        CommandOutcome::DataOut {
                            transfer_len: 0,
                            byte_offset: 0,
                            immediate: &[],
                        }
                    }
                }

                // ── SET STREAMING (0xB6) ─────────────────────────
                op::SET_STREAMING => CommandOutcome::DataOut {
                    transfer_len: 0,
                    byte_offset: 0,
                    immediate: &[],
                },

                // ── CLOSE TRACK (0x5B) ───────────────────────────
                op::CLOSE_TRACK => CommandOutcome::Status,

                // ── BLANK (0xA1) — for DVD-RAM alias to FORMAT (BurnAware clear)
                0xA1 => {
                    if self.is_random_writable() {
                        #[cfg(feature = "udf_void")]
                        {
                            if let Some(CdMedia::UdfRw(ref mut media)) = self.media {
                                match media.format_unit() {
                                    Ok(()) => {
                                        self.pending = Some(Sense::new(
                                            SenseKey::UnitAttention,
                                            asc::MEDIUM_MAY_HAVE_CHANGED,
                                            0,
                                        ));
                                        CommandOutcome::Status
                                    }
                                    Err(_) => self.cc(SenseKey::MediumError, asc::WRITE_FAULT),
                                }
                            } else {
                                self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                            }
                        }
                        #[cfg(not(feature = "udf_void"))]
                        {
                            self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                        }
                    } else {
                        self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                    }
                }

                // ── Unknown → INVALID COMMAND ─────────────────────
                _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND),
            }
        };

        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.sense = Sense::clear();
        }
        Ok(outcome)
    }

    fn mode_sense_write_params<'b>(
        &self,
        long: bool,
        alloc: u16,
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        let page = if self.mode_page_05_valid {
            &self.mode_page_05[..]
        } else {
            default_write_params_page()
        };
        let header_len = if long { 8 } else { 4 };
        let total = header_len + page.len();
        let mode_len = if long { total - 2 } else { total - 1 };
        let mut buf = [0u8; 64];
        if long {
            buf[0..2].copy_from_slice(&(mode_len as u16).to_be_bytes());
            buf[2] = self.medium_type();
        } else {
            buf[0] = mode_len as u8;
            buf[1] = self.medium_type();
        }
        buf[header_len..total].copy_from_slice(page);
        let n = total.min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    fn mode_select_cmd<'b>(
        &mut self,
        long: bool,
        alloc: u16,
        data: &'b mut [u8],
        dsl: usize,
    ) -> CommandOutcome<'b> {
        let expected = alloc as usize;
        if expected == 0 {
            return CommandOutcome::Status;
        }
        let imm = dsl.min(expected).min(data.len());
        if imm < expected {
            return CommandOutcome::ParamOut {
                expected_len: expected,
                immediate: &data[..imm],
            };
        }
        // Full parameter already present (iSCSI Immediate or direct test).
        return self.complete_mode_select(long, alloc, &data[..expected]);
    }

    fn complete_mode_select(
        &mut self,
        long: bool,
        _alloc: u16,
        data: &[u8],
    ) -> CommandOutcome<'static> {
        let header_len = if long { 8 } else { 4 };
        if data.len() < header_len {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let block_len = if long {
            usize::from(u16::from_be_bytes([data[6], data[7]]))
        } else {
            usize::from(data[3])
        };
        let page_start = header_len + block_len;
        if page_start + 2 > data.len() {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let page_code = data[page_start] & 0x3F;
        let page_len = usize::from(data[page_start + 1]);
        let end = page_start + 2 + page_len;
        if page_code != 0x05
            || page_len < 2
            || end > data.len()
            || page_len + 2 > self.mode_page_05.len()
        {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        self.mode_page_05.fill(0);
        self.mode_page_05[..2 + page_len].copy_from_slice(&data[page_start..end]);
        self.mode_page_05_valid = true;
        CommandOutcome::Status
    }

    fn format_unit_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
        dsl: usize,
    ) -> CommandOutcome<'b> {
        if self.media.is_none() {
            return self.not_ready();
        }
        if cdb[1] & 0x10 == 0 || cdb[1] & 0x03 != 0x01 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let expected = 12usize;
        let imm = dsl.min(expected).min(data.len());
        if imm < expected {
            return CommandOutcome::ParamOut {
                expected_len: expected,
                immediate: &data[..imm],
            };
        }
        return self.complete_format_unit(cdb, &data[..expected]);
    }

    fn complete_format_unit(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome<'static> {
        if self.media.is_none() {
            return self.not_ready();
        }
        if data.len() != 12 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if cdb[1] & 0x10 == 0 || cdb[1] & 0x03 != 0x01 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let options = data[1];
        if options & (0x40 | 0x10 | 0x04) != 0
            || u16::from_be_bytes([data[2], data[3]]) != 8
            || data[4..8] != [0, 0, 0, 0]
        {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let format_type = data[8];
        if format_type != 0x00 || u16::from_be_bytes([data[10], data[11]]) != 2048 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if options & 0x02 != 0 {
            return CommandOutcome::Status;
        }
        #[cfg(feature = "udf_void")]
        if let Some(CdMedia::UdfRw(ref mut media)) = self.media {
            return match media.format_unit() {
                Ok(()) => {
                    // Signal media change so host re-reads DiscInfo/TOC/Capacity.
                    self.pending = Some(Sense::new(
                        SenseKey::UnitAttention,
                        asc::MEDIUM_MAY_HAVE_CHANGED,
                        0,
                    ));
                    CommandOutcome::Status
                }
                Err(_) => self.cc(SenseKey::MediumError, asc::WRITE_FAULT),
            };
        }
        self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
    }

    // ── READ handler ────────────────────────────────────────────────

    fn read_cmd<'b>(&mut self, lba: u64, count: u32, _data: &'b mut [u8]) -> CommandOutcome<'b> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        let max = self.max_lba();
        if lba > max
            || lba
                .checked_add(u64::from(count))
                .is_none_or(|end| end > max + 1)
        {
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

    // ── READ CAPACITY ───────────────────────────────────────────────

    fn read_capacity_10_cmd<'b>(
        &mut self,
        pmi: bool,
        req_lba: u32,
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        if self.media.is_none() {
            return self.not_ready();
        }
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        data[0..4].copy_from_slice(&max_lba.to_be_bytes());
        data[4..8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        CommandOutcome::DataIn {
            transfer_len: 8,
            byte_offset: 0,
            immediate: &data[0..8],
        }
    }

    fn read_capacity_16_cmd<'b>(
        &mut self,
        sa: u8,
        alloc: u32,
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        if self.media.is_none() {
            return self.not_ready();
        }
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

    // ── READ TOC ────────────────────────────────────────────────────

    fn read_toc_cmd<'b>(&mut self, cdb: &[u8], data: &'b mut [u8]) -> CommandOutcome<'b> {
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
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[0..n],
        }
    }

    // ── GET CONFIGURATION ───────────────────────────────────────────

    fn get_configuration_cmd<'b>(&mut self, cdb: &[u8], data: &'b mut [u8]) -> CommandOutcome<'b> {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let media = self.media_state();
        let outcome =
            build_get_config_response_for_media(data, &self.caps, &media, rt, start, alloc);
        outcome
    }

    // ── READ DISC INFORMATION ───────────────────────────────────────

    fn read_disc_info_cmd<'b>(&mut self, cdb: &[u8], data: &'b mut [u8]) -> CommandOutcome<'b> {
        if cdb[1] & 0x07 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        // For DVD-RAM, reflect actual UDF presence: blank (no AVDP) -> empty,
        // otherwise complete. This makes Windows not prompt “needs format” when
        // a valid mkudffs image is already present, and makes post-WRITE
        // verification see a change after the host creates a new filesystem.
        let has_udf = match self.media {
            #[cfg(feature = "udf_void")]
            Some(CdMedia::UdfRw(ref mut m)) => UdfRwMedia::has_udf(m.backend()),
            _ => false,
        };
        let (disc_status, state_of_last_session, erasable) = if self.is_random_writable() {
            if has_udf {
                (2, 3, true) // complete, erasable — has valid UDF
            } else {
                (0, 0, true) // empty, erasable — blank formatted
            }
        } else {
            (2, 3, false)
        };
        let info = DiscInfo {
            disc_status,
            state_of_last_session,
            erasable,
            sessions: 1,
            first_track: 1,
            last_track: 1,
            disc_type: 0x00,
            mrw_status: 0,
            lead_out_lba: self.lead_out_lba(),
        };
        build_read_disc_info(data, alloc, &info)
    }

    // ── READ BUFFER CAPACITY ────────────────────────────────────────

    fn read_buffer_capacity_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        if cdb[1] & 0x01 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        build_read_buffer_capacity(data, alloc, 0, 0)
    }

    // ── GET EVENT STATUS NOTIFICATION ────────────────────────────────

    fn gesn_cmd<'b>(&mut self, cdb: &[u8], data: &'b mut [u8]) -> CommandOutcome<'b> {
        let class = cdb[4];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&4u16.to_be_bytes());
        if class & 0x10 != 0 {
            buf[2] = 0x80 | 0x04; // NEA=0, Notification Class = Media (100b)
            buf[3] = 0x10;
        } else {
            buf[2] = 0x80; // NEA=1
        }
        // Event Code 0 (NoChg)edia Present (bit 1).
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

    // ── READ DVD STRUCTURE ──────────────────────────────────────────

    fn read_dvd_structure_cmd<'b>(&mut self, cdb: &[u8], data: &'b mut [u8]) -> CommandOutcome<'b> {
        let media_type = cdb[1] & 0x3F;
        let layer = cdb[6] & 0x0F;
        let format = cdb[7];
        let alloc = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        if media_type != 0 || layer != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        match format {
            0 => {
                #[cfg(feature = "udf_void")]
                if let Some(ref m) = self.media {
                    if let Some(pf) = m.dvd_physical_format() {
                        let mut buf = [0u8; 28];
                        buf[0..2].copy_from_slice(&0x0018u16.to_be_bytes());
                        buf[4] = pf.disk_category_part_version;
                        buf[6] = pf.layer_type;
                        buf[9..13].copy_from_slice(&pf.data_start.to_be_bytes());
                        buf[13..17].copy_from_slice(&pf.data_end.to_be_bytes());
                        buf[17..21].copy_from_slice(&pf.next_writable.to_be_bytes());
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::DataIn {
                            transfer_len: n as u64,
                            byte_offset: 0,
                            immediate: &data[..n],
                        };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x08 => {
                // DVD-RAM DDS — synthetic 2048-byte DDS info (MMC-6 Table 414)
                #[cfg(feature = "udf_void")]
                if let Some(ref m) = self.media {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 2052];
                        buf[0..2].copy_from_slice(&0x0802u16.to_be_bytes());
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::DataIn {
                            transfer_len: n as u64,
                            byte_offset: 0,
                            immediate: &data[..n],
                        };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x09 => {
                // DVD-RAM Medium Status — 4-byte payload (Table 415)
                #[cfg(feature = "udf_void")]
                if let Some(ref m) = self.media {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 8];
                        buf[0..2].copy_from_slice(&0x0006u16.to_be_bytes());
                        // bytes 4..8: Cartridge=0, MSWI=0, no write protect
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::DataIn {
                            transfer_len: n as u64,
                            byte_offset: 0,
                            immediate: &data[..n],
                        };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x0A => {
                // DVD-RAM Spare Area Information — 12-byte payload (Table 417)
                // SSA=0 logical model: zero spare counts, no allocation.
                #[cfg(feature = "udf_void")]
                if let Some(ref m) = self.media {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 16];
                        buf[0..2].copy_from_slice(&0x000Eu16.to_be_bytes());
                        // bytes 4..7 primary unused, 8..11 supplementary unused, 12..15 allocated
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::DataIn {
                            transfer_len: n as u64,
                            byte_offset: 0,
                            immediate: &data[..n],
                        };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x0B => {
                // DVD-RAM Recording Type — 4-byte payload, Recording Type 0 = general data
                #[cfg(feature = "udf_void")]
                if let Some(ref m) = self.media {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 8];
                        buf[0..2].copy_from_slice(&0x0006u16.to_be_bytes());
                        // payload Recording Type bit 0
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::DataIn {
                            transfer_len: n as u64,
                            byte_offset: 0,
                            immediate: &data[..n],
                        };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x30 => {
                // WDCB (write inhibit DCB) — accept and return empty DCB
                let mut buf = [0u8; 4 + 32768];
                buf[0..2].copy_from_slice(&32768u16.to_be_bytes());
                buf[4..8].copy_from_slice(&0x5744_4300u32.to_be_bytes());
                let n = buf.len().min(alloc as usize).min(data.len());
                data[..n].copy_from_slice(&buf[..n]);
                CommandOutcome::DataIn {
                    transfer_len: n as u64,
                    byte_offset: 0,
                    immediate: &data[..n],
                }
            }
            0xC0 => {
                // Write protect status — all clear
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
            _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        }
    }

    // ── READ TRACK INFORMATION ───────────────────────────────────────

    fn read_track_information_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        let type_code = cdb[1] & 0x0F;
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        if type_code > 3 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let capacity = self.lead_out_lba();
        let mut buf = [0u8; 48];
        buf[0..2].copy_from_slice(&0x002Eu16.to_be_bytes());
        buf[2] = 1;
        buf[3] = 1;
        buf[6] = 0x04; // uninterrupted Mode-1 data track
        buf[7] = 0x21; // Packet/Inc + Mode 1
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());
        buf[12..16].copy_from_slice(&0u32.to_be_bytes());
        buf[16..20].copy_from_slice(&0u32.to_be_bytes());
        buf[20..24].copy_from_slice(&16u32.to_be_bytes());
        buf[24..28].copy_from_slice(&capacity.to_be_bytes());
        buf[28..32].copy_from_slice(&0u32.to_be_bytes());
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[..n],
        }
    }

    // ── READ FORMAT CAPACITIES ───────────────────────────────────────

    fn read_format_capacities_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
    ) -> CommandOutcome<'b> {
        if cdb[1] != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let partition_len = self.max_lba().min(u32::MAX as u64) as u32 + 1;
        let mut buf = [0u8; 20];
        buf[3] = 16;
        buf[4..8].copy_from_slice(&partition_len.to_be_bytes());
        buf[8] = 0x02; // formatted media
        buf[10] = 0x08; // Block Length 2048 (24-bit)
        buf[12..16].copy_from_slice(&partition_len.to_be_bytes());
        // DVD-RAM uses the standard formatted-medium descriptor.  The
        // descriptor's format type is not the DVD+RW 26h type.
        buf[16] = if self.is_random_writable() {
            0x00
        } else {
            0x26 << 2
        };
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &data[0..n],
        }
    }

    // ── SYNCHRONIZE CACHE ────────────────────────────────────────────

    /// Flush the media (SYNCHRONIZE CACHE equivalent).
    pub fn sync_media(&mut self) -> bool {
        if let Some(ref mut m) = self.media {
            m.sync().is_err()
        } else {
            false
        }
    }

    pub fn sync_cache_cmd(&mut self) -> CommandOutcome<'static> {
        if let Some(ref mut m) = self.media {
            if m.sync().is_err() {
                return self.cc(SenseKey::MediumError, asc::WRITE_FAULT);
            }
            return CommandOutcome::Status;
        }
        CommandOutcome::Status
    }
}

// ── SpcDevice impl ─────────────────────────────────────────────────

impl SpcDevice for CdromDrive<'_> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn medium_type(&self) -> u8 {
        0x41 // removable media
    }

    fn id(&self) -> u64 {
        self.drive_id
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        cdrom_mode_page_for_caps(page, &self.caps)
    }

    fn sense(&self) -> &Sense {
        &self.sense
    }

    fn sense_mut(&mut self) -> &mut Sense {
        &mut self.sense
    }

    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
        if loej && !load {
            // Eject.
            if self.prevent_removal {
                return SpcEffect::RemovalPrevented;
            }
            self.eject();
            SpcEffect::Good
        } else if loej && load {
            // Load on empty tray → media_requested.
            if self.media.is_none() {
                self.tray_open = false;
                self.media_requested = true;
            }
            SpcEffect::Good
        } else {
            SpcEffect::Good
        }
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }
}

// ── ScsiDevice impl ─────────────────────────────────────────────────

impl crate::scsi::device::ScsiDevice for CdromDrive<'_> {
    fn do_cmd<'b>(
        &mut self,
        cdb: &[u8],
        data: &'b mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'b>, crate::scsi::device::Error> {
        self.do_cmd(cdb, data, dsl)
    }

    fn read_data(
        &mut self,
        byte_offset: u64,
        buf: &mut [u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        if let Some(ref mut m) = self.media {
            return m.read_data(byte_offset, buf);
        }
        Err(crate::scsi::backend::BlockStorageError::OutOfBounds)
    }

    fn write_data(
        &mut self,
        byte_offset: u64,
        buf: &[u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
        if let Some(ref mut m) = self.media {
            return m.write_data(byte_offset, buf).map_err(|e| match e {
                crate::cdrom::media::MediaError::OutOfBounds => {
                    crate::scsi::backend::BlockStorageError::OutOfBounds
                }
                crate::cdrom::media::MediaError::WriteProtected => {
                    crate::scsi::backend::BlockStorageError::NotWritable
                }
                crate::cdrom::media::MediaError::Io => {
                    crate::scsi::backend::BlockStorageError::Io(embedded_io::ErrorKind::Other)
                }
                _ => crate::scsi::backend::BlockStorageError::NotWritable,
            });
        }
        Err(crate::scsi::backend::BlockStorageError::NotWritable)
    }

    fn sense(&self) -> &Sense {
        &self.sense
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn complete_param(
        &mut self,
        cdb: &[u8],
        data: &[u8],
    ) -> crate::scsi::device::CommandOutcome<'static> {
        match cdb.first().copied() {
            Some(op::MODE_SELECT_6) => {
                let alloc = u16::from(cdb[4]);
                self.complete_mode_select(false, alloc, data)
            }
            Some(op::MODE_SELECT_10) => {
                let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
                self.complete_mode_select(true, alloc, data)
            }
            Some(op::FORMAT_UNIT) => self.complete_format_unit(cdb, data),
            _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        }
    }
}

// ── Builder ───────────────────────────────────────────

/// Builder for `CdromDrive`.
///
/// Constructs the drive identity; media is injected at runtime via
/// `load()`.
pub struct CdromDriveBuilder {
    identity: DeviceIdentity,
    caps: CdromCapabilities,
    drive_id: u64,
}

impl CdromDriveBuilder {
    /// Set INQUIRY identity (vendor, product, revision).
    pub fn identity(mut self, vendor: &[u8; 8], product: &[u8; 16], rev: &[u8; 4]) -> Self {
        self.identity = DeviceIdentity {
            vendor: *vendor,
            product: *product,
            revision: *rev,
            version_descriptors: self.identity.version_descriptors,
        };
        self
    }

    /// Set VPD 0x80/0x83 drive serial number (constant, survives media swaps).
    pub fn drive_id(mut self, id: u64) -> Self {
        self.drive_id = id;
        self
    }

    /// Set device capabilities directly.
    pub fn capabilities(mut self, caps: CdromCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// Enable/disable eject and lock (plan  true-device calibration).
    pub fn eject_capable(mut self, eject: bool) -> Self {
        self.caps.eject = eject;
        self.caps.lock = eject;
        self.caps.load = eject;
        self
    }

    /// Build the drive (empty tray).
    pub fn build(self) -> CdromDrive<'static> {
        CdromDrive {
            sense: Sense::clear(),
            prevent_removal: false,
            pending: None,
            caps: self.caps,
            drive_id: self.drive_id,
            identity: self.identity,
            media: None,
            tray_open: false,
            mode_page_05: [0u8; 52],
            mode_page_05_valid: false,
            media_requested: false,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdrom::common::CurrentProfile;
    use crate::cdrom::media::FlatMedia;
    use crate::scsi::backend::{BlockBackend, RamBackend};

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
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

    fn check_condition(outcome: CommandOutcome<'_>) -> (SenseKey, u8) {
        match outcome {
            CommandOutcome::CheckCondition(s) => (s.key, s.asc),
            _ => panic!("expected CheckCondition"),
        }
    }

    #[test]
    fn drive_new_defaults() {
        let dev = CdromDrive::new();
        assert_eq!(dev.sense, Sense::clear());
        assert!(!dev.prevent_removal);
        assert!(!dev.tray_open);
        assert!(!dev.media_requested);
        assert_eq!(dev.drive_id, 0);
    }

    #[test]
    fn drive_builder_identity() {
        let dev = CdromDrive::builder()
            .identity(b"TESTDRVR", b"Virtual CD-ROM  ", b"0200")
            .drive_id(0xDEAD_BEEF)
            .eject_capable(true)
            .build();
        assert_eq!(dev.identity.vendor, *b"TESTDRVR");
        assert_eq!(dev.drive_id, 0xDEAD_BEEF);
        assert!(dev.caps.eject);
        assert!(dev.caps.lock);
        assert!(dev.caps.load);
    }

    #[test]
    fn drive_inquiry() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let mut buf = [0u8; 96];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut buf);
        assert!(n >= 95);
        assert_eq!(buf[0] & 0x1F, 0x05); // PDT = CD-ROM
        assert_eq!(&buf[8..16], b"SnowSCSI");
    }

    #[test]
    fn drive_empty_tray_tur() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
        // Empty tray → 3Ah/01h (tray closed).
        assert_eq!(dev.sense.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(dev.sense.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_CLOSED);
    }

    #[test]
    fn drive_get_configuration_empty_profile() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_CONFIGURATION;
        cdb[8] = 64;
        let mut buf = [0u8; 64];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut buf);
        assert!(n >= 8);
        // Empty tray → profile 0000h.
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
    }

    #[test]
    fn drive_read_capacity_empty_tray() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
        assert_eq!(dev.sense.asc, asc::MEDIUM_NOT_PRESENT);
    }

    #[test]
    fn drive_mode_sense_2a() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x2A;
        cdb[4] = 100;
        let mut buf = [0u8; 128];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut buf);
        // 4-byte MODE SENSE(6) header + 64-byte 0x2A page.
        assert_eq!(n, 4 + 64);
        assert_eq!(buf[4], 0x2A);
    }

    #[test]
    fn drive_mode_select_write_parameters_roundtrip() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut select = [0u8; 6];
        select[0] = op::MODE_SELECT_6;
        select[1] = 0x10; // PF=1
        select[4] = 56;
        w[4] = 0x05;
        w[5] = 0x32;
        w[6] = 0x41;
        w[7] = 0xC4;
        assert_eq!(
            dev.do_cmd(&select, &mut w, 56).unwrap(),
            CommandOutcome::Status
        );
        assert!(dev.mode_page_05_valid);

        let mut sense = [0u8; 6];
        sense[0] = op::MODE_SENSE_6;
        sense[2] = 0x05;
        sense[4] = 60;
        let outcome = dev.do_cmd(&sense, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                immediate,
                ..
            } => {
                assert_eq!(transfer_len, 4 + 52);
                assert_eq!(&immediate[4..8], &[0x05, 0x32, 0x41, 0xC4]);
            }
            _ => panic!("expected MODE SENSE data"),
        }
    }

    #[test]
    fn drive_format_unit_rejects_read_only_media() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 2048];
        let flat = FlatMedia::new(
            BlockBackend::Ram(RamBackend::new(&mut img)),
            CurrentProfile::CdRom,
        );
        dev.load_quiet(CdMedia::Flat(flat));
        let mut cdb = [0u8; 6];
        cdb[0] = op::FORMAT_UNIT;
        cdb[1] = 0x11; // FmtData + format code 1
        let mut w = work();
        w[2..4].copy_from_slice(&8u16.to_be_bytes());
        w[8] = 0x00; // full format
        w[10..12].copy_from_slice(&2048u16.to_be_bytes());
        let outcome = dev.do_cmd(&cdb, &mut w, 12).unwrap();
        assert!(matches!(
            outcome,
            CommandOutcome::CheckCondition(Sense {
                key: SenseKey::DataProtect,
                asc: asc::WRITE_PROTECTED,
                ..
            })
        ));
    }

    #[test]
    fn drive_pending_overrides_tur() {
        let mut dev = CdromDrive::new();
        // Manually inject a pending UA.
        dev.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::CheckCondition(s) => {
                assert_eq!(s.key, SenseKey::UnitAttention);
                assert_eq!(s.asc, asc::MEDIUM_MAY_HAVE_CHANGED);
            }
            _ => panic!("expected CheckCondition with UA"),
        }
        // UA is cleared after being reported (iSCSI delivers sense in the
        // Response, so the host may never send REQUEST SENSE).
        assert!(dev.pending.is_none());
        // Next TUR should not be UA again (may be NOT READY if no media).
        let outcome2 = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome2 {
            CommandOutcome::CheckCondition(s) => {
                assert_ne!(s.key, SenseKey::UnitAttention, "UA should not repeat");
            }
            CommandOutcome::Status => {}
            _ => panic!("unexpected outcome"),
        }
    }

    #[test]
    fn drive_request_sense_clears_pending() {
        let mut dev = CdromDrive::new();
        dev.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let _ = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        // UA should now be cleared.
        assert!(dev.pending.is_none());
    }

    #[test]
    fn drive_inquiry_bypasses_ua() {
        let mut dev = CdromDrive::new();
        dev.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::DataIn { .. }));
        // UA is NOT cleared by INQUIRY.
        assert!(dev.pending.is_some());
    }

    #[test]
    fn drive_empty_tray_tur_open_ascq() {
        let mut dev = CdromDrive::new();
        dev.tray_open = true;
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
        assert_eq!(dev.sense.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(dev.sense.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_OPEN);
    }

    #[test]
    fn drive_load_eject_ua_cycle() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];

        // Initially empty tray → NOT READY.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
        assert_eq!(dev.sense.asc, asc::MEDIUM_NOT_PRESENT);

        // START STOP LoEj=1, Load=1 → load media on empty tray.
        use crate::scsi::spc::SpcDevice;
        let effect = dev.start_stop(true, true); // loej=true, load=true
        assert_eq!(effect, SpcEffect::Good);
        assert!(dev.media_requested);
        assert!(!dev.tray_open);

        // Simulate integrator loading media.
        let mut img = vec![0u8; 2048];
        let flat = FlatMedia::new(
            BlockBackend::Ram(RamBackend::new(&mut img)),
            CurrentProfile::CdRom,
        );
        dev.load(CdMedia::Flat(flat));
        assert!(dev.is_media_present());

        // TUR → CC(UA 28h/00h).
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::CheckCondition(s) => {
                assert_eq!(s.key, SenseKey::UnitAttention);
                assert_eq!(s.asc, asc::MEDIUM_MAY_HAVE_CHANGED);
            }
            _ => panic!("expected CheckCondition with UA"),
        }
        // UA is cleared after being reported (no need to wait for REQUEST SENSE).
        assert!(dev.pending.is_none());
        // REQUEST SENSE still returns the UA sense (from sense, not pending).
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let outcome_rs = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome_rs, CommandOutcome::DataIn { .. }));
        assert!(dev.pending.is_none());

        // TUR → GOOD.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(outcome, CommandOutcome::Status);

        // START STOP LoEj=1, Load=0 → eject.
        let effect = dev.start_stop(true, false); // loej=true, load=false
        assert_eq!(effect, SpcEffect::Good);
        assert!(dev.tray_open);
        assert!(!dev.is_media_present());

        // TUR → CC(UA 28h/00h) then → NOT READY 3Ah/02h.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::CheckCondition(s) => {
                assert_eq!(s.key, SenseKey::UnitAttention);
                assert_eq!(s.asc, asc::MEDIUM_MAY_HAVE_CHANGED);
            }
            _ => panic!("expected CheckCondition with UA"),
        }
        // REQUEST SENSE → clears UA.
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let _ = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        // TUR → NOT READY 3Ah/02h (tray open).
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::CheckCondition(_)));
        assert_eq!(dev.sense.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(dev.sense.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_OPEN);
    }

    #[test]
    fn drive_ua_overrides_read_capacity() {
        let mut dev = CdromDrive::new();
        dev.pending = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::CheckCondition(s) => {
                assert_eq!(s.key, SenseKey::UnitAttention);
                assert_eq!(s.asc, asc::MEDIUM_MAY_HAVE_CHANGED);
            }
            _ => panic!("expected CheckCondition with UA"),
        }
    }

    #[test]
    fn drive_prevent_removal_blocks_eject() {
        let mut dev = CdromDrive::new();
        use crate::scsi::spc::SpcDevice;
        dev.set_prevent(true);
        let effect = dev.start_stop(true, false); // loej=true, load=false
        assert_eq!(effect, SpcEffect::RemovalPrevented);
    }

    #[test]
    fn drive_format_unit_rejects_type_01() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 4096 * 2048];
        // UdfRw requires udf_void feature
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x00; // options zero
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x01; // Spare Area Expansion — must be rejected
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w, 12).unwrap();
            assert!(matches!(
                outcome,
                CommandOutcome::CheckCondition(Sense {
                    key: SenseKey::IllegalRequest,
                    asc: asc::INVALID_FIELD,
                    ..
                })
            ));
        }
        #[cfg(not(feature = "udf_void"))]
        {
            let _ = (dev, img);
        }
    }

    #[test]
    fn drive_format_unit_rejects_init_pattern() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x00;
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // non-zero init pattern with IP=0
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w, 12).unwrap();
            assert!(matches!(
                outcome,
                CommandOutcome::CheckCondition(Sense {
                    key: SenseKey::IllegalRequest,
                    asc: asc::INVALID_FIELD,
                    ..
                })
            ));
        }
        #[cfg(not(feature = "udf_void"))]
        {
            let _ = (dev, img);
        }
    }

    #[test]
    fn drive_format_unit_tryout_does_not_clear() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let mut dev = CdromDrive::new();
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            // Write pattern
            dev.media
                .as_mut()
                .unwrap()
                .write_data(0, &[0xA5; 2048])
                .unwrap();
            // Try-out format (byte1 bit1 = 0x02) should validate and return GOOD without clearing
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x02; // Try-out
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w, 12).unwrap();
            assert_eq!(outcome, CommandOutcome::Status);
            // Verify data still present (not cleared)
            let mut out = [0u8; 2048];
            dev.media.as_mut().unwrap().read_data(0, &mut out).unwrap();
            assert_eq!(out, [0xA5; 2048]);
        }
    }

    #[test]
    fn drive_format_unit_clears_logical_blocks() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let mut dev = CdromDrive::new();
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            // Write some data
            let mut pattern = [0x5A; 2048];
            dev.media
                .as_mut()
                .unwrap()
                .write_data(2048, &pattern)
                .unwrap();
            // Normal format (not try-out) should clear
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x00;
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w, 12).unwrap();
            assert_eq!(outcome, CommandOutcome::Status);
            let mut out = [0u8; 2048];
            dev.media
                .as_mut()
                .unwrap()
                .read_data(2048, &mut out)
                .unwrap();
            assert_eq!(out, [0u8; 2048]);
            // UDF structures should be zeroed — check BEA sector
            let mut sec = [0u8; 2048];
            dev.media
                .as_mut()
                .unwrap()
                .read_data(16 * 2048, &mut sec)
                .unwrap();
            assert_eq!(sec, [0u8; 2048]);
        }
    }

    #[test]
    fn drive_read_dvd_structure_08_09_0a_0b_for_dvdram() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let mut dev = CdromDrive::new();
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            let mut w = work();
            for &fmt in &[0x08u8, 0x09, 0x0A, 0x0B] {
                let mut cdb = [0u8; 12];
                cdb[0] = op::READ_DVD_STRUCTURE;
                cdb[7] = fmt;
                cdb[8] = 0x08; // alloc 2048
                cdb[9] = 0x00;
                let mut out = [0u8; 4096];
                let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut out);
                assert!(n >= 4, "format {:02X} should succeed", fmt);
                let len = u16::from_be_bytes([out[0], out[1]]) as usize;
                if fmt == 0x08 {
                    assert_eq!(len, 0x0802);
                } else if fmt == 0x0A {
                    assert_eq!(len, 0x000E);
                } else {
                    assert_eq!(len, 0x0006);
                }
            }
            // Same formats must fail for CD-ROM flat media
            let mut img2 = vec![0u8; 2048];
            let flat = FlatMedia::new(
                BlockBackend::Ram(RamBackend::new(&mut img2)),
                CurrentProfile::CdRom,
            );
            let mut dev2 = CdromDrive::new();
            dev2.load_quiet(CdMedia::Flat(flat));
            for &fmt in &[0x08u8, 0x09, 0x0A, 0x0B] {
                let mut cdb = [0u8; 12];
                cdb[0] = op::READ_DVD_STRUCTURE;
                cdb[7] = fmt;
                cdb[8] = 0x08;
                let outcome = dev2.do_cmd(&cdb, &mut w, 0).unwrap();
                assert!(matches!(
                    outcome,
                    CommandOutcome::CheckCondition(Sense {
                        key: SenseKey::IllegalRequest,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn dvd_ram_always_formatted_no_medium_not_formatted() {
        // Logical DVD-RAM never returns NOT READY/MEDIUM NOT FORMATTED per §2.1
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let mut scratch = [0u8; 256];
            let mut dev = CdromDrive::new();
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));
            // Immediately after load, TUR is GOOD (no format needed)
            let mut w = work();
            let mut cdb = [0u8; 6];
            cdb[0] = op::TEST_UNIT_READY;
            assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
            // READ/WRITE should not return MEDIUM NOT FORMATTED
            let mut cdb10 = [0u8; 10];
            cdb10[0] = op::READ_10;
            cdb10[8] = 0x01;
            let out = dev.do_cmd(&cdb10, &mut w, 0).unwrap();
            assert!(matches!(out, CommandOutcome::DataIn { .. }));
            cdb10[0] = op::WRITE_10;
            let out2 = dev.do_cmd(&cdb10, &mut w, 0).unwrap();
            assert!(matches!(out2, CommandOutcome::DataOut { .. }));
            // Format then TUR should be UA 28h (media changed), then GOOD after REQUEST SENSE
            let mut cdbf = [0u8; 6];
            cdbf[0] = op::FORMAT_UNIT;
            cdbf[1] = 0x11;
            let mut w2 = work();
            w2[2..4].copy_from_slice(&8u16.to_be_bytes());
            w2[8] = 0x00;
            w2[10..12].copy_from_slice(&2048u16.to_be_bytes());
            assert_eq!(
                dev.do_cmd(&cdbf, &mut w2, 12).unwrap(),
                CommandOutcome::Status
            );
            assert!(matches!(
                dev.do_cmd(&cdb, &mut w, 0).unwrap(),
                CommandOutcome::CheckCondition(Sense {
                    key: SenseKey::UnitAttention,
                    asc: 0x28,
                    ..
                })
            ));
            let mut cdb_rs = [0u8; 6];
            cdb_rs[0] = op::REQUEST_SENSE;
            cdb_rs[4] = 18;
            let _ = dev.do_cmd(&cdb_rs, &mut w, 0).unwrap();
            assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
        }
    }

    /// Verify READ DISC INFORMATION (51h) reflects actual UDF state:
    /// materialized UDF → complete, after FORMAT UNIT → empty, after
    /// WRITE_10 recreating AVDP → complete again. This is the core
    /// invariant that makes Windows accept the disc and not report
    /// "format failed".
    #[test]
    fn disc_info_reflects_udf_state_transitions() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "udf_void")]
        {
            use crate::cdrom::udfrw::UdfRwMedia;
            let img_len = img.len(); // capture before mutable borrow

            fn disc_status(dev: &mut CdromDrive<'_>) -> u8 {
                let mut w = [0u8; crate::MIN_DATA_LEN];
                let mut cdb = [0u8; 10];
                cdb[0] = op::READ_DISC_INFORMATION;
                cdb[8] = 0xFF;
                let mut buf = [0u8; 256];
                let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut buf);
                assert!(n >= 3, "READ DISC INFORMATION returned {n} bytes");
                // byte 2: erasable(4) | state_of_last_session(3:2) | disc_status(1:0)
                buf[2] & 0x03
            }

            let mut scratch = [0u8; 256];
            let mut dev = CdromDrive::new();
            let media = UdfRwMedia::materialize(
                BlockBackend::Ram(RamBackend::new(&mut img)),
                "TEST",
                &mut scratch,
            )
            .unwrap();
            dev.load_quiet(CdMedia::UdfRw(media));

            // 1) Materialized UDF → disc_status 2 (complete)
            assert_eq!(disc_status(&mut dev), 2, "with UDF: complete");

            // 2) FORMAT UNIT clears blocks → disc_status 0 (empty)
            let mut cdbf = [0u8; 6];
            cdbf[0] = op::FORMAT_UNIT;
            cdbf[1] = 0x11;
            let mut w = work();
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            assert_eq!(
                dev.do_cmd(&cdbf, &mut w, 12).unwrap(),
                CommandOutcome::Status
            );
            // Consume UA from format
            let mut cdb_rs = [0u8; 6];
            cdb_rs[0] = op::REQUEST_SENSE;
            cdb_rs[4] = 18;
            let _ = dev.do_cmd(&cdb_rs, &mut w, 0).unwrap();
            assert_eq!(disc_status(&mut dev), 0, "after FORMAT UNIT: empty");

            // 3) Write AVDP at LBA 256 directly → disc_status 2 (complete)
            let avdp = {
                use crate::udf_void;
                let mut sector = [0u8; 2048];
                let layout = udf_void::compute_layout((img_len / 2048) as u32, "TEST").unwrap();
                udf_void::gen_sector(&layout, udf_void::AVDP_LBA, &mut sector);
                sector
            };
            dev.media
                .as_mut()
                .unwrap()
                .write_data(256 * 2048, &avdp)
                .unwrap();
            assert_eq!(disc_status(&mut dev), 2, "after write AVDP: complete");
        }
    }
}
