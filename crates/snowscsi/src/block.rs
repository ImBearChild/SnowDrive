//! SBC block device command set (block.c).
//!
//! Implements the direct-access block device commands
//! (SPC-4 / SBC-3). Synthesized responses (INQUIRY, MODE SENSE, ...) are
//! written by the handler into `work[48..48+len]` and returned via
//! [`CommandOutcome::DataIn::immediate`]; READ commands return an empty
//! `immediate` and the target reads the backend at `byte_offset`.

use crate::backend::BlockBackend;
use crate::device::{CommandOutcome, DeviceType, Error};
use crate::scsi::{
    asc, cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op, opcode_name, Sense, SenseKey,
};

/// INQUIRY standard data length (additional length = 91 per SPC-3 (n-4)).
const INQUIRY_STD_LEN: usize = 95;
/// VPD 0x00 page list length (7 = 4 + 3 supported pages).
const VPD_PAGE_LIST_LEN: usize = 7;
/// VPD 0x80 unit serial length (4 header + 16 serial).
const VPD_SERIAL_LEN: usize = 20;
/// VPD 0x83 device identification length (4 + 4 descriptor + 8 NAA-3).
const VPD_ID_LEN: usize = 16;
/// REQUEST SENSE response length (fixed format).
const SENSE_LEN: usize = 18;

/// Direct-access block device (device_internal.h `snowscsi_device`).
pub struct Device<B: BlockBackend> {
    backend: B,
    sector_size: u32,
    sense: Sense,
    prevent_removal: bool,
}

impl<B: BlockBackend> Device<B> {
    /// Create a block device over `backend` with the given sector size.
    /// Returns `None` if `sector_size == 0` (C `snowscsi_block_create`).
    pub fn new(backend: B, sector_size: u32) -> Option<Self> {
        if sector_size == 0 {
            return None;
        }
        Some(Self {
            backend,
            sector_size,
            sense: Sense::clear(),
            prevent_removal: false,
        })
    }

    /// Raw backend access for the target data path (READ reads chunks,
    /// WRITE writes received data back).
    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.sense
    }

    pub fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn max_lba(&self) -> u64 {
        let nblocks = self.backend.capacity() / u64::from(self.sector_size);
        nblocks.saturating_sub(1)
    }

    fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Sense::new(key, asc, ascq);
    }

    fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.sense)
    }

    /// Write received data to the backend, setting sense on failure
    /// (C `snowscsi_write_data` backend flush semantics).
    pub fn write_data(
        &mut self,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), crate::backend::BlockBackendError> {
        match self.backend.write(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
                Err(e)
            }
        }
    }

    /// Read data from the backend, setting sense on failure.
    pub fn read_data(
        &mut self,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), crate::backend::BlockBackendError> {
        match self.backend.read(offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_sense(SenseKey::MediumError, 0x11, 0);
                Err(e)
            }
        }
    }

    /// Process one SCSI command (`snowscsi_do_cmd`). `work` must be at
    /// least [`crate::MIN_WORK_LEN`] bytes; `dsl` is the length of data
    /// already received into `work[48..48+dsl]` (immediate data for WRITE).
    pub fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        if work.len() < crate::MIN_WORK_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let outcome = self.handle_cmd(cdb, work, dsl);
        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.sense = Sense::clear();
        }
        Ok(outcome)
    }

    fn handle_cmd<'a>(&mut self, cdb: &[u8], work: &'a mut [u8], dsl: usize) -> CommandOutcome<'a> {
        let opcode = cdb_opcode(cdb);
        let max_lba = self.max_lba();

        let outcome = match opcode {
            op::TEST_UNIT_READY => CommandOutcome::Status,

            op::REQUEST_SENSE => {
                let alloc = cdb[4] as usize;
                let mut buf = [0u8; SENSE_LEN];
                let n = self.sense.write_fixed(&mut buf);
                let n = n.min(alloc);
                work[48..48 + n].copy_from_slice(&buf[..n]);
                CommandOutcome::DataIn {
                    transfer_len: n as u64,
                    byte_offset: 0,
                    immediate: &work[48..48 + n],
                }
            }

            op::INQUIRY => self.inquiry(cdb, work),
            op::READ_CAPACITY_10 => self.read_capacity_10(cdb, work),
            op::SERVICE_ACTION_IN => self.read_capacity_16(cdb, work),
            op::SYNCHRONIZE_CACHE_10 => {
                let _ = self.backend.sync();
                CommandOutcome::Status
            }
            op::MODE_SENSE_6 => self.mode_sense(cdb, work, false),
            op::MODE_SENSE_10 => self.mode_sense(cdb, work, true),
            op::MODE_SELECT_6 | op::MODE_SELECT_10 => CommandOutcome::Status,
            op::SEND_DIAGNOSTIC => {
                if cdb[1] & 0x04 != 0 {
                    self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                } else {
                    CommandOutcome::Status
                }
            }
            op::RECEIVE_DIAGNOSTIC => {
                let alloc = ((u16::from(cdb[3]) << 8) | u16::from(cdb[4])) as usize;
                let buf = [0u8; 4];
                let n = 4.min(alloc);
                work[48..48 + n].copy_from_slice(&buf[..n]);
                CommandOutcome::DataIn {
                    transfer_len: n as u64,
                    byte_offset: 0,
                    immediate: &work[48..48 + n],
                }
            }
            op::REPORT_LUNS => self.report_luns(cdb, work),
            op::PREVENT_ALLOW => {
                self.prevent_removal = cdb[4] & 0x03 != 0;
                CommandOutcome::Status
            }
            op::START_STOP_UNIT => {
                let loej = (cdb[4] >> 1) & 0x01;
                let load = cdb[4] & 0x01;
                if loej == 1 && load == 0 && self.prevent_removal {
                    self.cc(SenseKey::IllegalRequest, asc::MEDIUM_REMOVAL_PREVENTED)
                } else {
                    CommandOutcome::Status
                }
            }

            op::READ_6 => self.read_cmd(
                max_lba,
                u64::from(cdb_lba6(cdb)),
                cdb_transfer_len6(cdb),
                work,
            ),
            op::WRITE_6 => self.write_cmd(
                max_lba,
                u64::from(cdb_lba6(cdb)),
                cdb_transfer_len6(cdb),
                work,
                dsl,
            ),
            op::READ_10 => self.read_cmd(
                max_lba,
                u64::from(cdb_lba10(cdb)),
                u32::from(cdb_transfer_len10(cdb)),
                work,
            ),
            op::WRITE_10 => self.write_cmd(
                max_lba,
                u64::from(cdb_lba10(cdb)),
                u32::from(cdb_transfer_len10(cdb)),
                work,
                dsl,
            ),
            op::READ_12 => self.read_cmd(
                max_lba,
                u64::from(cdb_lba12(cdb)),
                cdb_transfer_len12(cdb),
                work,
            ),
            op::WRITE_12 => self.write_cmd(
                max_lba,
                u64::from(cdb_lba12(cdb)),
                cdb_transfer_len12(cdb),
                work,
                dsl,
            ),
            op::READ_16 => self.read_cmd(max_lba, cdb_lba16(cdb), cdb_transfer_len16(cdb), work),
            op::WRITE_16 => {
                self.write_cmd(max_lba, cdb_lba16(cdb), cdb_transfer_len16(cdb), work, dsl)
            }

            other => {
                let _ = opcode_name(other);
                self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND)
            }
        };
        outcome
    }

    /// Shared READ(6/10/12/16) handler.
    fn read_cmd<'a>(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        work: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(max_lba, lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let bytes = self.count_to_bytes(count);
        let Some(bytes) = bytes else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        CommandOutcome::DataIn {
            transfer_len: bytes as u64,
            byte_offset: lba * u64::from(self.sector_size),
            immediate: &work[48..48],
        }
    }

    /// Shared WRITE(6/10/12/16) handler.
    fn write_cmd<'a>(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        work: &'a mut [u8],
        dsl: usize,
    ) -> CommandOutcome<'a> {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(max_lba, lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = self.count_to_bytes(count) else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        let bytes = bytes as usize;
        let imm = dsl.min(bytes).min(work.len() - 48);
        CommandOutcome::DataOut {
            transfer_len: bytes as u64,
            byte_offset: lba * u64::from(self.sector_size),
            immediate: &work[48..48 + imm],
        }
    }

    /// LBA range check: `lba + count` must not exceed `max_lba + 1`.
    fn check_lba_range(&self, max_lba: u64, lba: u64, count: u32) -> bool {
        lba <= max_lba
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= max_lba + 1)
    }

    /// `count * sector_size`, rejected (None) if it exceeds u32::MAX.
    fn count_to_bytes(&self, count: u32) -> Option<u32> {
        let bytes = u64::from(count).checked_mul(u64::from(self.sector_size))?;
        u32::try_from(bytes).ok()
    }

    fn inquiry<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let evpd = cdb[1] & 0x01;
        let page_code = cdb[2];
        let alloc = ((u16::from(cdb[3]) << 8) | u16::from(cdb[4])) as usize;

        if evpd == 1 {
            let data: &[u8] = match page_code {
                0x00 => {
                    let mut buf = [0u8; VPD_PAGE_LIST_LEN];
                    buf[3] = 3;
                    buf[4] = 0x00;
                    buf[5] = 0x80;
                    buf[6] = 0x83;
                    work[48..48 + VPD_PAGE_LIST_LEN].copy_from_slice(&buf);
                    &work[48..48 + VPD_PAGE_LIST_LEN]
                }
                0x80 => {
                    let mut buf = [0u8; VPD_SERIAL_LEN];
                    buf[1] = 0x80;
                    buf[3] = 16;
                    let size = self.backend.capacity();
                    buf[4..8].copy_from_slice(b"SNOW");
                    let hex = format_hex16(size);
                    buf[8..20].copy_from_slice(&hex[4..16]);
                    work[48..48 + VPD_SERIAL_LEN].copy_from_slice(&buf);
                    &work[48..48 + VPD_SERIAL_LEN]
                }
                0x83 => {
                    let mut buf = [0u8; VPD_ID_LEN];
                    buf[1] = 0x83;
                    buf[3] = 12;
                    buf[4] = 0x01; /* CODE SET = binary */
                    buf[5] = 0x03; /* designator type = NAA */
                    buf[7] = 8;
                    let id = 0x3000_0000_0000_0000u64
                        | (self.backend.capacity() & 0x0FFF_FFFF_FFFF_FFFF);
                    buf[8..16].copy_from_slice(&id.to_be_bytes());
                    work[48..48 + VPD_ID_LEN].copy_from_slice(&buf);
                    &work[48..48 + VPD_ID_LEN]
                }
                _ => {
                    return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
                }
            };
            let n = data.len().min(alloc);
            CommandOutcome::DataIn {
                transfer_len: n as u64,
                byte_offset: 0,
                immediate: &work[48..48 + n],
            }
        } else {
            if page_code != 0 {
                return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
            }
            let mut buf = [0u8; INQUIRY_STD_LEN];
            buf[2] = 0x06; /* SPC-4 (分歧2, was 0x05) */
            buf[3] = 0x02; /* response data format */
            buf[4] = (INQUIRY_STD_LEN as u8) - 4; /* additional length (n-4) */
            buf[7] = 0x02; /* CmdQue */
            buf[8..16].copy_from_slice(b"SnowSCSI");
            buf[16..32].copy_from_slice(b"Virtual Disk    ");
            buf[32..36].copy_from_slice(b"0100");
            buf[58] = 0x00;
            buf[59] = 0xA0; /* SAM-5 */
            buf[60] = 0x09;
            buf[61] = 0x60; /* iSCSI */
            buf[62] = 0x04;
            buf[63] = 0x60; /* SPC-4 */
            buf[64] = 0x04;
            buf[65] = 0xC0; /* SBC-3 */
            let n = INQUIRY_STD_LEN.min(alloc);
            work[48..48 + n].copy_from_slice(&buf[..n]);
            CommandOutcome::DataIn {
                transfer_len: n as u64,
                byte_offset: 0,
                immediate: &work[48..48 + n],
            }
        }
    }

    fn read_capacity_10<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let pmi = cdb[1] & 0x01;
        let req_lba = (u32::from(cdb[2]) << 24)
            | (u32::from(cdb[3]) << 16)
            | (u32::from(cdb[4]) << 8)
            | u32::from(cdb[5]);
        if pmi == 0 && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sector_size.to_be_bytes());
        work[48..56].copy_from_slice(&buf);
        CommandOutcome::DataIn {
            transfer_len: 8,
            byte_offset: 0,
            immediate: &work[48..56],
        }
    }

    fn read_capacity_16<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        if cdb.len() < 16 || cdb[1] != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = ((u32::from(cdb[10]) << 24)
            | (u32::from(cdb[11]) << 16)
            | (u32::from(cdb[12]) << 8)
            | u32::from(cdb[13])) as usize;
        let max_lba = self.max_lba();
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&self.sector_size.to_be_bytes());
        let n = 32.min(alloc);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }

    fn report_luns<'a>(&mut self, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        let alloc = ((u32::from(cdb[6]) << 24)
            | (u32::from(cdb[7]) << 16)
            | (u32::from(cdb[8]) << 8)
            | u32::from(cdb[9])) as usize;
        let mut buf = [0u8; 12];
        buf[3] = 8; /* LUN list length: one 8-byte LUN 0 */
        let n = 12.min(alloc);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }

    /// MODE SENSE(6)/(10). `long` selects the 10-byte CDB/8-byte header form.
    fn mode_sense<'a>(&mut self, cdb: &[u8], work: &'a mut [u8], long: bool) -> CommandOutcome<'a> {
        let page = cdb[2] & 0x3F;
        let alloc = if long {
            ((u16::from(cdb[7]) << 8) | u16::from(cdb[8])) as usize
        } else {
            cdb[4] as usize
        };

        let mut pages = [0u8; 24];
        let mut off = 0usize;
        if page == 0x3F || page == 0x08 {
            let mut caching = [0u8; 20];
            caching[0] = 0x88; /* PS=1, SPF=0, page 0x08 */
            caching[1] = 18; /* page length */
            caching[12] = 0x20; /* DRA=1 */
            pages[..20].copy_from_slice(&caching);
            off = 20;
        }
        if page == 0x3F || page == 0x00 {
            pages[off..off + 4].copy_from_slice(&[0x00, 2, 0x00, 0x08]);
            off += 4;
        }
        if page != 0x3F && page != 0x00 && page != 0x08 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }

        let header_len = if long { 8 } else { 4 };
        let total = header_len + off;
        let mode_len = if long { total - 2 } else { total - 1 };
        let mut buf = [0u8; 32];
        if long {
            buf[0] = (mode_len >> 8) as u8;
            buf[1] = mode_len as u8;
        } else {
            buf[0] = mode_len as u8;
        }
        buf[header_len..total].copy_from_slice(&pages[..off]);
        let n = total.min(alloc);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }
}

/// Format a u64 as 16 uppercase hex digits (VPD 0x80 serial).
fn format_hex16(v: u64) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; 16];
    let mut x = v;
    for i in (0..16).rev() {
        out[i] = HEX[(x & 0xF) as usize];
        x >>= 4;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RamBackend;

    /// Build a 6-byte CDB (test_block.c `make_cdb6`).
    fn make_cdb6(opcode: u8, lba: u32, transfer_len: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = opcode;
        cdb[1] = ((lba >> 16) & 0x1F) as u8;
        cdb[2] = (lba >> 8) as u8;
        cdb[3] = lba as u8;
        cdb[4] = transfer_len;
        cdb
    }

    /// Build a 10-byte CDB (test_block.c `make_cdb10`).
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

    /// Build a 12-byte CDB (test_block.c `make_cdb12`).
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

    /// Build a 16-byte CDB (test_block.c `make_cdb16`).
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

    fn work() -> [u8; crate::MIN_WORK_LEN] {
        [0u8; crate::MIN_WORK_LEN]
    }

    fn ram_dev<'a>(ram: &'a mut [u8]) -> Device<RamBackend<'a>> {
        Device::new(RamBackend::new(ram), 512).unwrap()
    }

    /// Extract the DataIn payload (backend read or work-resident).
    /// Returns the number of bytes transferred.
    fn data_in<B: BlockBackend>(
        dev: &mut Device<B>,
        outcome: CommandOutcome<'_>,
        buf: &mut [u8],
    ) -> usize {
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
    fn block_create_ram() {
        let mut ram = [0u8; 1024 * 1024];
        let dev = ram_dev(&mut ram);
        assert_eq!(dev.device_type(), DeviceType::Block);
        assert_eq!(dev.sector_size(), 512);
    }

    #[test]
    fn block_create_rejects_zero_sector() {
        let mut ram = [0u8; 512];
        assert!(Device::new(RamBackend::new(&mut ram), 0).is_none());
    }

    #[test]
    fn block_read_zero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, [0u8; 512]);
    }

    #[test]
    fn block_write_read_roundtrip() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 10, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(byte_offset, 10 * 512);
                assert_eq!(immediate, pattern.as_slice());
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb10(op::READ_10, 10, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_lba_out_of_range() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::LBA_OUT_OF_RANGE,
                0
            ))
        );
        assert_eq!(dev.sense().key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_unknown_opcode() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::INVALID_COMMAND,
                0
            ))
        );
        assert_eq!(dev.sense().key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense().asc, asc::INVALID_COMMAND);
    }

    #[test]
    fn block_test_unit_ready() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = [0u8; 6];
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_request_sense() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();

        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        dev.do_cmd(&cdb, &mut w, 0).unwrap();

        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 18];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[0], 0x70); /* response code */
        assert_eq!(buf[2], 0x05); /* ILLEGAL REQUEST */
        assert_eq!(buf[12], asc::INVALID_COMMAND);
        /* sense cleared after REQUEST SENSE */
        assert_eq!(dev.sense().key, SenseKey::None);
    }

    #[test]
    fn block_read_capacity() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 8];
        data_in(&mut dev, outcome, &mut buf);
        let max_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(max_lba, 2047);
        assert_eq!(block_size, 512);
    }

    #[test]
    fn block_read_capacity_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0x10;
        cdb[13] = 0x20;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 32];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(&buf[..8], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xFF]);
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x02, 0x00]);
        assert_eq!(&buf[12..], &[0u8; 20]);
    }

    #[test]
    fn block_read_capacity_16_unknown_sa() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
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
    fn block_read_6_zero_blocks() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb6(op::READ_6, 0, 0); /* 0 = 256 blocks */
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = vec![0u8; 256 * 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, vec![0u8; 256 * 512]);
    }

    #[test]
    fn block_write_read_roundtrip_6() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 512].copy_from_slice(&pattern);

        let cdb = make_cdb6(op::WRITE_6, 5, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(byte_offset, 5 * 512);
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb6(op::READ_6, 5, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_write_read_roundtrip_12() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 1024].copy_from_slice(&pattern);

        let cdb = make_cdb12(op::WRITE_12, 20, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 1024).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert_eq!(byte_offset, 20 * 512);
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb12(op::READ_12, 20, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 1024];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_write_read_roundtrip_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 1024].copy_from_slice(&pattern);

        let cdb = make_cdb16(op::WRITE_16, 30, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 1024).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert_eq!(byte_offset, 30 * 512);
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb16(op::READ_16, 30, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 1024];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_lba_out_of_range_6() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb6(op::READ_6, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::LBA_OUT_OF_RANGE,
                0
            ))
        );
    }

    #[test]
    fn block_lba_out_of_range_12() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb12(op::READ_12, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::LBA_OUT_OF_RANGE,
                0
            ))
        );
    }

    #[test]
    fn block_lba_out_of_range_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb16(op::READ_16, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::LBA_OUT_OF_RANGE,
                0
            ))
        );
    }

    #[test]
    fn block_inquiry_version_spc4() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 96];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[0], 0x00); /* PDT = disk */
        assert_eq!(buf[2], 0x06); /* SPC-4 (分歧2) */
        assert_eq!(buf[7], 0x02); /* CmdQue */
        assert_eq!(buf[4], 91); /* additional length (n-4) */
        assert_eq!(&buf[8..16], b"SnowSCSI");
        assert_eq!(&buf[16..32], b"Virtual Disk    ");
        assert_eq!(&buf[32..36], b"0100");
        assert_eq!(buf[58], 0x00);
        assert_eq!(buf[59], 0xA0); /* SAM-5 */
        assert_eq!(buf[60], 0x09);
        assert_eq!(buf[61], 0x60); /* iSCSI */
    }

    #[test]
    fn block_inquiry_evpd_page_code_nonzero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[2] = 0x01;
        cdb[4] = 96;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
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
    fn block_inquiry_vpd_00() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x00;
        cdb[4] = 8;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 7];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[3], 0x03);
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x80);
        assert_eq!(buf[6], 0x83);
    }

    #[test]
    fn block_inquiry_vpd_80() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x80;
        cdb[4] = 20;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 20];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[1], 0x80);
        assert_eq!(buf[3], 16);
        assert_eq!(&buf[4..8], b"SNOW");
    }

    #[test]
    fn block_inquiry_vpd_83() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x83;
        cdb[4] = 16;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 16];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[1], 0x83);
        assert_eq!(buf[4], 0x01); /* CODE SET binary (§7 #3) */
        assert_eq!(buf[5], 0x03); /* NAA */
        assert_eq!(buf[8], 0x30); /* NAA-3 prefix */
    }

    #[test]
    fn block_inquiry_vpd_unsupported() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0xFF;
        cdb[4] = 96;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
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
    fn block_mode_sense_6_caching_page() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x08;
        cdb[4] = 32;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 32];
        let n = data_in(&mut dev, outcome, &mut buf);
        assert!(n >= 24); /* 4 header + 20 page */
        assert!(buf[0] >= 23); /* mode data length */
        assert_eq!(buf[4], 0x88); /* PS=1, page 0x08 */
        assert_eq!(buf[5], 18); /* page length */
        assert_eq!(buf[6], 0x00); /* WCE=0, RCD=0 */
        assert_eq!(buf[16], 0x20); /* DRA=1 */
    }

    #[test]
    fn block_mode_sense_6_page_00() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x00;
        cdb[4] = 16;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 16];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 2);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x08);
    }

    #[test]
    fn block_mode_sense_6_page_3f() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x3F;
        cdb[4] = 32;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 32];
        let n = data_in(&mut dev, outcome, &mut buf);
        assert!(n >= 28); /* 4 header + 20 caching + 4 page list */
        assert_eq!(buf[4], 0x88);
        assert_eq!(buf[24], 0x00); /* page 0x00 header */
        assert_eq!(buf[27], 0x08);
    }

    #[test]
    fn block_mode_sense_6_unsupported_page() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x01;
        cdb[4] = 32;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
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
    fn block_mode_sense_10() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x08;
        cdb[8] = 32;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 32];
        data_in(&mut dev, outcome, &mut buf);
        let mode_len = (u16::from(buf[0]) << 8) | u16::from(buf[1]);
        assert!(mode_len >= 26); /* 6 header + 20 page */
        assert_eq!(buf[8], 0x88);
        assert_eq!(buf[9], 18);
    }

    #[test]
    fn block_mode_select_10() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SELECT_10;
        cdb[1] = 0x10; /* PF=1 */
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_report_luns() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 12];
        cdb[0] = op::REPORT_LUNS;
        cdb[9] = 16;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 16];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x08); /* LUN list length: one LUN */
        assert_eq!(buf[4], 0x00); /* LUN 0 */
    }

    #[test]
    fn block_send_diagnostic() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x10; /* PF=1, SelfTest=0 */
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_synchronize_cache() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_prevent_allow_start_stop_eject() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();

        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        cdb[4] = 0x01;
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);

        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x02; /* LoEj=1, Load=0 (eject) */
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(
            outcome,
            CommandOutcome::CheckCondition(Sense::new(
                SenseKey::IllegalRequest,
                asc::MEDIUM_REMOVAL_PREVENTED,
                0
            ))
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x00; /* stop */
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_read_capacity_pmi_zero_lba_nonzero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        cdb[5] = 0x01; /* PMI=0, LBA=1 */
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
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
    fn block_read_capacity_pmi_zero_lba_zero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert!(matches!(outcome, CommandOutcome::DataIn { .. }));
    }

    #[test]
    fn block_work_buf_too_small() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut small = [0u8; 100];
        let cdb = make_cdb10(op::READ_10, 0, 1);
        assert_eq!(dev.do_cmd(&cdb, &mut small, 0), Err(Error::WorkBufTooSmall));
    }

    #[cfg(feature = "std")]
    #[test]
    fn block_file_write_read_roundtrip() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_block_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let backend = crate::backend::FileBackend::open(&path.to_string_lossy(), true).unwrap();
        let mut dev = Device::new(backend, 512).unwrap();
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[..512], pattern.as_slice());

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn block_file_read_only() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_block_ro_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 512]).unwrap();

        let backend = crate::backend::FileBackend::open(&path.to_string_lossy(), false).unwrap();
        let mut dev = Device::new(backend, 512).unwrap();
        let mut w = work();

        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                byte_offset,
                immediate,
                ..
            } => {
                let r = dev.write_data(byte_offset, immediate);
                assert_eq!(r, Err(crate::backend::BlockBackendError::NotWritable));
                assert_eq!(dev.sense().key, SenseKey::MediumError);
                assert_eq!(dev.sense().asc, asc::WRITE_FAULT);
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb10(op::READ_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, [0u8; 512]);

        std::fs::remove_file(&path).unwrap();
    }
}
