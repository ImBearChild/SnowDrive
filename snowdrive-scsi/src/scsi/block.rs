//! SBC block device command set (block.c).
//!
//! Implements the direct-access block device commands (SPC-4 / SBC-3).
//! SPC commands (INQUIRY, MODE SENSE, ...) are delegated to
//! [`crate::scsi::spc`]; READ commands return an empty `immediate` and
//! the target fetches the data via `xfer_out`.

use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::scsi::device::{
    CommandOutcome, DeviceType, Error, PendingXfer, ScsiDevice, XferDir, XferError, XferOutcome,
};
use crate::scsi::sbc::{execute_sbc, parse_sbc, SbcCommand};
use crate::scsi::scsi::{asc, Sense, SenseKey};
use crate::scsi::spc::{
    block_mode_page, execute_spc, DeviceIdentity, SpcDevice, SpcEffect, BLOCK_IDENTITY,
};

const CLEAR_SENSE: Sense = Sense::clear();

/// Direct-access block device (device_internal.h `snowscsi_device`).
pub struct BlockDevice<B: BlockStorage> {
    backend: B,
    sector_size: u32,
    sense: Option<Sense>,
    pending: Option<PendingXfer>,
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
            sense: None,
            pending: None,
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

    pub fn device_type(&self) -> DeviceType {
        DeviceType::Block
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

    pub(crate) fn max_lba(&self) -> u64 {
        let nblocks = self.backend.capacity() / u64::from(self.sector_size);
        nblocks.saturating_sub(1)
    }

    pub(crate) fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Some(Sense::new(key, asc, ascq));
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome<'static> {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<(), BlockStorageError> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(BlockStorageError::OutOfBounds)?;
        if end > self.backend.capacity() {
            return Err(BlockStorageError::OutOfBounds);
        }
        Ok(())
    }

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    /// `transfer_offset` is the byte offset within the transfer.
    pub fn xfer_out(&mut self, transfer_offset: u64, buf: &mut [u8]) -> XferOutcome {
        let (dir, transfer_len, block_size, base_lba) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.block_size, p.base_lba),
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
        let actual = base_lba * u64::from(block_size) + transfer_offset;
        if self.check_bounds(actual, buf.len()).is_err() {
            self.set_sense(SenseKey::MediumError, 0x11, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::OutOfBounds));
        }
        if embedded_io::Seek::seek(&mut self.backend, embedded_io::SeekFrom::Start(actual)).is_err()
        {
            self.set_sense(SenseKey::MediumError, 0x11, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        if embedded_io::Read::read_exact(&mut self.backend, buf).is_err() {
            self.set_sense(SenseKey::MediumError, 0x11, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        XferOutcome::Ok
    }

    /// Write `buf` for the current WRITE transfer (host → device).
    pub fn xfer_in(&mut self, transfer_offset: u64, buf: &[u8]) -> XferOutcome {
        let (dir, transfer_len, block_size, base_lba) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.block_size, p.base_lba),
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
        let actual = base_lba * u64::from(block_size) + transfer_offset;
        if self.check_bounds(actual, buf.len()).is_err() {
            self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::OutOfBounds));
        }
        if embedded_io::Seek::seek(&mut self.backend, embedded_io::SeekFrom::Start(actual)).is_err()
        {
            self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        if embedded_io::Write::write_all(&mut self.backend, buf).is_err() {
            self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
            return XferOutcome::Error(XferError::Storage(BlockStorageError::Io(
                embedded_io::ErrorKind::Other,
            )));
        }
        XferOutcome::Ok
    }

    /// Process one SCSI command (`snowscsi_do_cmd`). `data` must be at
    /// least [`crate::MIN_DATA_LEN`] bytes; `dsl` is the length of data
    /// already received into `data[0..dsl]` (immediate data for WRITE).
    ///
    /// The CDB is parsed by [`parse_sbc`]: SPC commands are dispatched to
    /// [`execute_spc`] (via the `SbcCommand::Spc` fall-through), SBC commands
    /// to [`execute_sbc`]; unknown opcodes yield INVALID COMMAND.
    pub fn do_cmd<'a>(
        &mut self,
        cdb: &[u8],
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        self.pending = None;
        if data.len() < crate::MIN_DATA_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        let Some(cmd) = parse_sbc(cdb) else {
            return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
        };
        let outcome = match cmd {
            SbcCommand::Spc(cmd) => execute_spc(self, cmd, data, dsl),
            cmd => execute_sbc(self, cmd, data, dsl),
        };
        Ok(outcome)
    }

    /// Shared READ(6/10/12/16) handler.
    pub(crate) fn read_cmd<'a>(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        data: &'a mut [u8],
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
        let transfer_len = u64::from(bytes);
        self.pending = Some(PendingXfer {
            base_lba: lba,
            current_lba: lba,
            block_size: self.sector_size,
            dir: XferDir::Out,
            transfer_len,
        });
        CommandOutcome::DataIn {
            transfer_len,
            immediate: &data[0..0],
        }
    }

    /// Shared WRITE(6/10/12/16) handler.
    pub(crate) fn write_cmd<'a>(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        data: &'a mut [u8],
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
        let bytes_usize = bytes as usize;
        let transfer_len = u64::from(bytes);
        let imm = dsl.min(bytes_usize).min(data.len());
        self.pending = Some(PendingXfer {
            base_lba: lba,
            current_lba: lba,
            block_size: self.sector_size,
            dir: XferDir::In,
            transfer_len,
        });
        CommandOutcome::DataOut {
            transfer_len,
            immediate: &data[0..imm],
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
        data: &'a mut [u8],
    ) -> CommandOutcome<'a> {
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sector_size.to_be_bytes());
        data[0..8].copy_from_slice(&buf);
        CommandOutcome::DataIn {
            transfer_len: 8,
            immediate: &data[0..8],
        }
    }

    pub(crate) fn read_capacity_16_cmd<'a>(
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
        buf[8..12].copy_from_slice(&self.sector_size.to_be_bytes());
        let n = 32.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::DataIn {
            transfer_len: n as u64,
            immediate: &data[0..n],
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
        data: &'a mut [u8],
        dsl: usize,
    ) -> Result<CommandOutcome<'a>, Error> {
        self.do_cmd(cdb, data, dsl)
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
        DeviceType::Block
    }

    fn complete_param(&mut self, _cdb: &[u8], _data: &[u8]) -> CommandOutcome<'static> {
        // Block device accepts any MODE SELECT parameter (no-op).
        CommandOutcome::Status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;
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

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    fn ram_dev<'a>(ram: &'a mut [u8]) -> BlockDevice<RamBackend<'a>> {
        BlockDevice::new(RamBackend::new(ram), 512).unwrap()
    }

    /// Extract the DataIn payload (backend read via xfer_out or work-resident).
    /// Returns the number of bytes transferred.
    fn data_in<B: BlockStorage>(
        dev: &mut BlockDevice<B>,
        outcome: CommandOutcome<'_>,
        buf: &mut [u8],
    ) -> usize {
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                immediate,
            } => {
                assert!(transfer_len as usize <= buf.len());
                let n = transfer_len as usize;
                if immediate.is_empty() {
                    assert_eq!(dev.xfer_out(0, &mut buf[..n]), XferOutcome::Ok);
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
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 10, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(immediate, pattern.as_slice());
                assert_eq!(dev.xfer_in(0, immediate), XferOutcome::Ok);
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
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_unknown_opcode() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_COMMAND);
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
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);
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
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb6(op::WRITE_6, 5, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(dev.xfer_in(0, immediate), XferOutcome::Ok);
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
        w[0..1024].copy_from_slice(&pattern);

        let cdb = make_cdb12(op::WRITE_12, 20, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 1024).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert_eq!(dev.xfer_in(0, immediate), XferOutcome::Ok);
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
        w[0..1024].copy_from_slice(&pattern);

        let cdb = make_cdb16(op::WRITE_16, 30, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 1024).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert_eq!(dev.xfer_in(0, immediate), XferOutcome::Ok);
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
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_lba_out_of_range_12() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb12(op::READ_12, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_lba_out_of_range_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb16(op::READ_16, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
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
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::MEDIUM_REMOVAL_PREVENTED);
        assert_eq!(
            dev.peek_sense().unwrap().ascq,
            asc::MEDIUM_REMOVAL_PREVENTED_ASCQ
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
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);
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
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w, 512).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 512);
                assert_eq!(dev.xfer_in(0, immediate), XferOutcome::Ok);
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
            CommandOutcome::DataOut { immediate, .. } => {
                let r = dev.xfer_in(0, immediate);
                assert!(matches!(r, XferOutcome::Error(_)));
                assert_eq!(dev.peek_sense().unwrap().key, SenseKey::MediumError);
                assert_eq!(dev.peek_sense().unwrap().asc, asc::WRITE_FAULT);
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

    #[test]
    fn xfer_non_aligned_split_read() {
        let expected: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut ram = expected.clone();
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 0, 2); // 1024 bytes
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::DataIn {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert!(immediate.is_empty());
                let mut chunk1 = vec![0u8; 600];
                assert_eq!(dev.xfer_out(0, &mut chunk1), XferOutcome::Ok);
                assert_eq!(chunk1, expected[0..600]);
                let mut chunk2 = vec![0u8; 424];
                assert_eq!(dev.xfer_out(600, &mut chunk2), XferOutcome::Ok);
                assert_eq!(chunk2, expected[600..1024]);
            }
            _ => panic!("expected DataIn"),
        }
    }

    #[test]
    fn xfer_non_aligned_split_write() {
        let mut ram = vec![0u8; 4096];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::WRITE_10, 0, 2);
        let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
        match outcome {
            CommandOutcome::DataOut {
                transfer_len,
                immediate,
            } => {
                assert_eq!(transfer_len, 1024);
                assert!(immediate.is_empty());
                let payload: Vec<u8> = (0..1024).map(|i| ((i * 7) % 251) as u8).collect();
                assert_eq!(dev.xfer_in(0, &payload[0..600]), XferOutcome::Ok);
                assert_eq!(dev.xfer_in(600, &payload[600..]), XferOutcome::Ok);
                // Verify via read.
                let cdb = make_cdb10(op::READ_10, 0, 2);
                let outcome = dev.do_cmd(&cdb, &mut w, 0).unwrap();
                match outcome {
                    CommandOutcome::DataIn {
                        transfer_len: _,
                        immediate,
                    } => {
                        assert!(immediate.is_empty());
                        let mut buf = vec![0u8; 1024];
                        assert_eq!(dev.xfer_out(0, &mut buf), XferOutcome::Ok);
                        assert_eq!(buf, payload);
                    }
                    _ => panic!("expected DataIn"),
                }
            }
            _ => panic!("expected DataOut"),
        }
    }
}
