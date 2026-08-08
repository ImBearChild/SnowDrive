//! SBC block device command set (block.c).
//!
//! Implements the direct-access block device commands (SPC-4 / SBC-3).
//! SPC commands (INQUIRY, MODE SENSE, ...) are delegated to
//! [`crate::scsi::spc`]; READ commands return an empty `immediate` and
//! the target reads the backend at `byte_offset`.

use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice};
use crate::scsi::sbc::{execute_sbc, parse_sbc, SbcCommand};
use crate::scsi::scsi::{asc, Sense, SenseKey};
use crate::scsi::spc::{
    block_mode_page, execute_spc, DeviceIdentity, SpcDevice, SpcEffect, BLOCK_IDENTITY,
};

/// Direct-access block device (device_internal.h `snowscsi_device`).
pub struct BlockDevice<B: BlockStorage> {
    backend: B,
    sector_size: u32,
    sense: Sense,
    prevent_removal: bool,
}

impl<B: BlockStorage> BlockDevice<B> {
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

    pub(crate) fn max_lba(&self) -> u64 {
        let nblocks = self.backend.capacity() / u64::from(self.sector_size);
        nblocks.saturating_sub(1)
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Sense::new(key, asc, ascq);
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition(self.sense)
    }

    /// Write received data to the backend, setting sense on failure
    /// (C `snowscsi_write_data` backend flush semantics).
    pub fn write_data(
        &mut self,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
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
    ) -> Result<(), crate::scsi::backend::BlockStorageError> {
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
    ///
    /// The CDB is parsed by [`parse_sbc`]: SPC commands are dispatched to
    /// [`execute_spc`] (via the `SbcCommand::Spc` fall-through), SBC commands
    /// to [`execute_sbc`]; unknown opcodes yield INVALID COMMAND.
    pub fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        if work.len() < crate::MIN_WORK_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let Some(cmd) = parse_sbc(cdb) else {
            return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
        };
        let outcome = match cmd {
            SbcCommand::Spc(cmd) => execute_spc(self, cmd, work, dsl),
            cmd => execute_sbc(self, cmd, work, dsl),
        };
        if !matches!(outcome, CommandOutcome::CheckCondition(_)) {
            self.sense = Sense::clear();
        }
        Ok(outcome)
    }

    /// Shared READ(6/10/12/16) handler.
    pub(crate) fn read_cmd<'a>(
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
    pub(crate) fn write_cmd<'a>(
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
        buf[4..8].copy_from_slice(&self.sector_size.to_be_bytes());
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
        buf[8..12].copy_from_slice(&self.sector_size.to_be_bytes());
        let n = 32.min(alloc as usize);
        work[48..48 + n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            byte_offset: 0,
            immediate: &work[48..48 + n],
        }
    }
}

impl<B: BlockStorage> SpcDevice for BlockDevice<B> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn identity(&self) -> &DeviceIdentity {
        &BLOCK_IDENTITY
    }

    fn id(&self) -> u64 {
        self.backend.capacity()
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        block_mode_page(page)
    }

    fn sense(&self) -> &Sense {
        &self.sense
    }

    fn sense_mut(&mut self) -> &mut Sense {
        &mut self.sense
    }

    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
        if loej && !load && self.prevent_removal {
            SpcEffect::RemovalPrevented
        } else {
            SpcEffect::Good
        }
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }
}

impl<B: BlockStorage> ScsiDevice for BlockDevice<B> {
    fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        work: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        self.do_cmd(cdb, work, dsl)
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
        self.device_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::{BlockBackend, RamBackend};
    use crate::scsi::scsi::op;

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

    fn ram_dev<'a>(ram: &'a mut [u8]) -> BlockDevice<RamBackend<'a>> {
        BlockDevice::new(RamBackend::new(ram), 512).unwrap()
    }

    /// Extract the DataIn payload (backend read or work-resident).
    /// Returns the number of bytes transferred.
    fn data_in<B: BlockStorage>(
        dev: &mut BlockDevice<B>,
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
        assert!(BlockDevice::new(RamBackend::new(&mut ram), 0).is_none());
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
    fn block_send_diagnostic() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x08; /* PF=1, SelfTest=0 (SPC-3 table 171) */
        assert_eq!(dev.do_cmd(&cdb, &mut w, 0).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_send_diagnostic_self_test() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x0A; /* PF=1, SelfTest=1 */
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
    fn block_device_over_block_backend_ram() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = BlockDevice::new(BlockBackend::Ram(RamBackend::new(&mut ram)), 512).unwrap();
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[48..48 + 512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 7, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                byte_offset,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(byte_offset, 7 * 512);
                assert_eq!(immediate, pattern.as_slice());
                dev.write_data(byte_offset, immediate).unwrap();
            }
            _ => panic!("expected DataOut"),
        }

        let cdb = make_cdb10(op::READ_10, 7, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &mut buf);
        assert_eq!(buf, pattern.as_slice());
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

        let backend =
            crate::scsi::backend::FileBackend::open(&path.to_string_lossy(), true).unwrap();
        let mut dev = BlockDevice::new(backend, 512).unwrap();
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

        let backend =
            crate::scsi::backend::FileBackend::open(&path.to_string_lossy(), false).unwrap();
        let mut dev = BlockDevice::new(backend, 512).unwrap();
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
                assert_eq!(r, Err(crate::scsi::backend::BlockStorageError::NotWritable));
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
