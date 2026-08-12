//! CdromDevice: flat ISO/RAM CD-ROM (Phase 2c, plan §8.2).
//!
//! A read-only CD-ROM emulated over any [`BlockStorage`] backend (ISO file,
//! RAM disk). SPC commands are delegated to [`CdromDeviceCommon`]; MMC
//! commands (READ TOC, GET CONFIGURATION, READ CAPACITY, READ/WRITE) are
//! handled here.
//!
//! Write commands return DATA PROTECT (read-only device).

use crate::cdrom::common::{
    build_get_config_response, cdrom_mode_page, CdromDeviceCommon, CurrentProfile, CDROM_IDENTITY,
    SECTOR_SIZE,
};
use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_len_from_opcode, cdb_opcode, cdb_read_args, op, Sense, SenseKey,
};
use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect};

/// Flat ISO/RAM CD-ROM device (plan §8.2 / §3.2).
///
/// Read-only: all write commands return DATA PROTECT. Generic over any
/// [`BlockStorage`] backend (FileBackend for ISO files, RamBackend for
/// in-memory images).
pub struct CdromDevice<B: BlockStorage> {
    pub(crate) common: CdromDeviceCommon,
    pub(crate) backend: B,
}

impl<B: BlockStorage> CdromDevice<B> {
    /// Create a new CD-ROM device over `backend`.
    ///
    /// The profile is derived from the backend capacity (≤700 MiB → CD-ROM,
    /// >700 MiB → DVD-ROM).
    pub fn new(backend: B) -> Self {
        let profile = CurrentProfile::from_capacity(backend.capacity());
        Self {
            common: CdromDeviceCommon::new(profile),
            backend,
        }
    }

    /// Create a new CD-ROM device with an explicit profile override.
    pub fn with_profile(backend: B, profile: CurrentProfile) -> Self {
        Self {
            common: CdromDeviceCommon::new(profile),
            backend,
        }
    }

    pub fn sector_size(&self) -> u32 {
        self.common.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.common.sense
    }

    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
    }

    /// Largest readable LBA: `(capacity / 2048) - 1`. Saturates to 0 for
    /// images smaller than one sector.
    pub(crate) fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    /// Lead-out start LBA (number of data sectors).
    fn lead_out_lba(&self) -> u32 {
        (self.capacity() / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.common.sense = Sense::new(key, asc, ascq);
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.common.sense)
    }

    /// Read data from the backend (target data path), setting MEDIUM ERROR
    /// on failure.
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self.backend.read(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0);
                Err(e)
            }
        }
    }

    /// Write data to the backend (target data path). For this read-only
    /// device, always returns NotWritable.
    pub fn write_data(&mut self, _offset: u64, _buf: &[u8]) -> Result<(), BlockStorageError> {
        Err(BlockStorageError::NotWritable)
    }

    /// Process one SCSI command. Dispatch order: SPC commands →
    /// `execute_spc`; MMC commands → `execute_mmc_flat`; unknown →
    /// INVALID COMMAND.
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
            execute_spc(&mut self.common, cmd, data, dsl)
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
                // READ(6/10/12/16) — same as CDBlockDevice
                op::READ_6 | op::READ_10 | op::READ_12 | op::READ_16 => {
                    let Some((lba, count)) = cdb_read_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_cmd(lba, count, data)
                }

                // READ CAPACITY(10)
                op::READ_CAPACITY_10 => {
                    let Some(lba) = cdb_lba10(cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_capacity_10_cmd(cdb[1] & 0x01 != 0, lba, data)
                }

                // READ CAPACITY(16) via SERVICE ACTION IN
                op::SERVICE_ACTION_IN => {
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    self.read_capacity_16_cmd(cdb[1], alloc, data)
                }

                // READ TOC (0x43)
                op::READ_TOC => self.read_toc_cmd(cdb, data),

                // GET CONFIGURATION (0x46)
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, data),

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

    /// Shared READ(6/10/12/16) handler (2048-byte sectors).
    fn read_cmd<'a>(&mut self, lba: u64, count: u32, _data: &'a mut [u8]) -> CommandOutcome<'a> {
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

    // ── READ TOC ────────────────────────────────────────────────────

    /// READ TOC/PMA/ATIP (0x43) — plan §8.2.
    ///
    /// Format 0000b: single data track + lead-out.
    /// Format 0001b: single session.
    /// Format 0010b: unsupported → INVALID FIELD.
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
                b[1] = 0x12; /* data length: 18 */
                b[2] = 0x01; /* first track */
                b[3] = 0x01; /* last track */
                match track {
                    0 | 1 => {
                        // Track 1 descriptor.
                        b[5] = 0x14; /* ADR=1, CONTROL=4 (data) */
                        b[6] = 0x01;
                        b[8..12].copy_from_slice(&track1_addr);
                        // Lead-out descriptor.
                        b[13] = 0x14;
                        b[14] = 0xAA;
                        b[16..20].copy_from_slice(&lead_addr);
                        (b, 20)
                    }
                    0xAA => {
                        // Lead-out only.
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
                // Session info.
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

    // ── GET CONFIGURATION ───────────────────────────────────────────

    /// GET CONFIGURATION (0x46) — plan §8.2.
    ///
    /// Current Profile from capacity; common features from
    /// [`build_get_config_response`].
    fn get_configuration_cmd<'a>(&mut self, cdb: &[u8], data: &'a mut [u8]) -> CommandOutcome<'a> {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }

        build_get_config_response(data, self.common.profile, rt, start, alloc)
    }
}

// ── SpcDevice impl (delegates to common) ────────────────────────────

impl<B: BlockStorage> SpcDevice for CdromDevice<B> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &CDROM_IDENTITY
    }

    fn id(&self) -> u64 {
        self.backend.capacity()
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

impl<B: BlockStorage> ScsiDevice for CdromDevice<B> {
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

    fn write_data(&mut self, _byte_offset: u64, _buf: &[u8]) -> Result<(), BlockStorageError> {
        Err(BlockStorageError::NotWritable)
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
    use crate::scsi::backend::RamBackend;
    use crate::scsi::device::CommandOutcome;
    use crate::scsi::scsi::{asc, op, SenseKey};

    /// Helper: create a RamBackend of `size` bytes filled with `fill`.
    fn ram_image(size: usize, fill: u8) -> Vec<u8> {
        vec![fill; size]
    }

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

    /// Run a command that yields DataIn from the backend (empty immediate)
    /// by reading the data via `read_data`.
    fn do_data_in<B: BlockStorage>(
        dev: &mut CdromDevice<B>,
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

    fn check_condition(outcome: CommandOutcome<'_>) -> (SenseKey, u8) {
        match outcome {
            CommandOutcome::CheckCondition(s) => (s.key, s.asc),
            _ => panic!("expected CheckCondition"),
        }
    }

    // ── Constructor ─────────────────────────────────────────────────

    #[test]
    fn new_cdrom_from_ram() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let dev = CdromDevice::new(b);
        assert_eq!(dev.capacity(), 2048 * 100);
        assert_eq!(dev.sector_size(), 2048);
        assert_eq!(dev.max_lba(), 99);
    }

    #[test]
    fn new_cdrom_profile_cdrom_under_700m() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let dev = CdromDevice::new(b);
        assert_eq!(dev.common.profile, CurrentProfile::CdRom);
    }

    #[test]
    fn new_cdrom_profile_dvd_over_700m() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let dev = CdromDevice::with_profile(b, CurrentProfile::DvdRom);
        assert_eq!(dev.common.profile, CurrentProfile::DvdRom);
    }

    // ── READ TOC ────────────────────────────────────────────────────

    #[test]
    fn read_toc_format_0_lba() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[6] = 0x00;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(buf[1], 0x12);
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x01);
        assert_eq!(buf[5], 0x14);
        assert_eq!(buf[6], 0x01);
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
        assert_eq!(buf[14], 0xAA);
        assert_eq!(&buf[16..20], &[0, 0, 0, 100]);
    }

    #[test]
    fn read_toc_format_0_msf() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[1] = 0x02;
        cdb[6] = 0x00;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 20);
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x02, 0x00]);
        assert_eq!(&buf[16..20], &[0x00, 0x00, 0x03, 0x19]);
    }

    #[test]
    fn read_toc_format_0_track_aa_lead_out_only() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[6] = 0xAA;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(buf[1], 0x0A);
    }

    #[test]
    fn read_toc_format_0_invalid_track_rejected() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[6] = 0x02;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    #[test]
    fn read_toc_format_1_session_info() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[2] = 0x01;
        cdb[6] = 0x00;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(buf[1], 0x0A);
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x01);
    }

    #[test]
    fn read_toc_alloc_clamp() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[6] = 0x00;
        cdb[7] = 0x00;
        cdb[8] = 0x0C;
        let mut buf = [0u8; 64];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(buf[1], 0x12);
    }

    #[test]
    fn read_toc_alloc_zero_transfers_nothing() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[6] = 0x00;
        cdb[8] = 0x00;
        let mut buf = [0u8; 4];
        let n = do_data_in(&mut dev, &cdb, &mut w, &mut buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn read_toc_unsupported_format_rejected() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_TOC;
        cdb[1] = 0x02;
        cdb[2] = 0x02;
        cdb[6] = 0x01;
        cdb[7] = 0x00;
        cdb[8] = 0x40;
        assert_eq!(
            check_condition(dev.do_cmd(&cdb, &mut w, 0).unwrap()),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD)
        );
    }

    // ── WRITE commands → DATA PROTECT ───────────────────────────────

    #[test]
    fn write_commands_return_data_protect() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();

        let mut assert_dp = |cdb: &[u8]| {
            assert_eq!(
                check_condition(dev.do_cmd(cdb, &mut w, 0).unwrap()),
                (SenseKey::DataProtect, asc::WRITE_PROTECTED)
            );
        };
        assert_dp(&make_cdb6(op::WRITE_6, 0, 1));
        assert_dp(&make_cdb10(op::WRITE_10, 0, 1));
        assert_dp(&make_cdb12(op::WRITE_12, 0, 1));
        assert_dp(&make_cdb16(op::WRITE_16, 0, 1));
        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_dp(&cdb);
    }

    // ── MODE SENSE ──────────────────────────────────────────────────

    #[test]
    fn mode_sense_6_cd_params() {
        let mut img = ram_image(2048 * 100, 0);
        let b = RamBackend::new(&mut img);
        let mut dev = CdromDevice::new(b);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x0D;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = data_in(dev.do_cmd(&cdb, &mut w, 0).unwrap(), &mut buf);
        assert_eq!(n, 8);
        assert_eq!(buf[4], 0x0D);
    }

    // ── Helpers ─────────────────────────────────────────────────────

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
}
