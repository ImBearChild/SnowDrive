//! SCSI core: opcodes, sense keys, sense data and CDB field parsing.
//!
//! Field layouts and sense format follow SBC-3 / SPC-4 (see `__REF_SBC3.pdf.md`,
//! `__REF_SPC3.pdf.md`). Sense data uses the fixed format (response code 70h).

/// SCSI operation codes (SPC-4 §7.3, SBC-3 §5).
pub mod op {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const READ_6: u8 = 0x08;
    pub const WRITE_6: u8 = 0x0A;
    pub const INQUIRY: u8 = 0x12;
    pub const MODE_SELECT_6: u8 = 0x15;
    pub const MODE_SENSE_6: u8 = 0x1A;
    pub const START_STOP_UNIT: u8 = 0x1B;
    pub const RECEIVE_DIAGNOSTIC: u8 = 0x1C;
    pub const SEND_DIAGNOSTIC: u8 = 0x1D;
    pub const PREVENT_ALLOW: u8 = 0x1E;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
    pub const MODE_SELECT_10: u8 = 0x55;
    pub const MODE_SENSE_10: u8 = 0x5A;
    pub const READ_16: u8 = 0x88;
    pub const WRITE_16: u8 = 0x8A;
    pub const SERVICE_ACTION_IN: u8 = 0x9E;
    pub const REPORT_LUNS: u8 = 0xA0;
    pub const READ_12: u8 = 0xA8;
    pub const WRITE_12: u8 = 0xAA;

    // MMC-6 (CD/DVD) opcodes.
    pub const READ_TOC: u8 = 0x43;
}

/// Additional sense codes (SPC-4 §4.5.6).
pub mod asc {
    pub const WRITE_FAULT: u8 = 0x03;
    pub const NOT_READY: u8 = 0x04;
    pub const UNRECOVERED_READ_ERROR: u8 = 0x11;
    pub const INVALID_COMMAND: u8 = 0x20;
    pub const LBA_OUT_OF_RANGE: u8 = 0x21;
    pub const INVALID_FIELD: u8 = 0x24;
    pub const WRITE_PROTECTED: u8 = 0x27;
    pub const MEDIUM_NOT_PRESENT: u8 = 0x3A;
    pub const MEDIUM_REMOVAL_PREVENTED: u8 = 0x53;
}

/// Sense key (SPC-4 §4.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SenseKey {
    None = 0x00,
    NotReady = 0x02,
    MediumError = 0x03,
    IllegalRequest = 0x05,
    UnitAttention = 0x06,
    DataProtect = 0x07,
}

/// Fixed format sense data (SPC-4 §4.5.3).
///
/// Maps C `snowscsi_sense_t` (scsi.h): key in byte2, ASC/ASCQ in
/// bytes 12/13 of the fixed format response (response code 70h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sense {
    pub key: SenseKey,
    pub asc: u8,
    pub ascq: u8,
}

impl Sense {
    pub const fn new(key: SenseKey, asc: u8, ascq: u8) -> Self {
        Self { key, asc, ascq }
    }

    /// Clear sense (no error).
    pub const fn clear() -> Self {
        Self::new(SenseKey::None, 0, 0)
    }

    /// Serialize fixed format sense data (response code 70h) into `buf`.
    ///
    /// Layout (SPC-4 §4.5.3, table 26): byte0=70h, byte2=sense key,
    /// byte7=additional sense length (n-7), byte12=ASC, byte13=ASCQ,
    /// all other bytes zero. Returns the number of bytes written
    /// (min(18, buf.len())), clamped to the caller's buffer.
    pub fn write_fixed(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(18);
        buf[..n].fill(0);
        if n > 0 {
            buf[0] = 0x70;
        }
        if n > 2 {
            buf[2] = self.key as u8;
        }
        if n > 7 {
            buf[7] = (n as u8).wrapping_sub(7);
        }
        if n > 12 {
            buf[12] = self.asc;
        }
        if n > 13 {
            buf[13] = self.ascq;
        }
        n
    }
}

/// CDB operation code: byte 0 (SPC-4 §7.3).
pub fn cdb_opcode(cdb: &[u8]) -> u8 {
    cdb[0]
}

/// READ(6)/WRITE(6) logical block address: byte1[4:0], byte2, byte3.
///
/// LBA is 21 bits: `(cdb[1] & 0x1F) << 16 | cdb[2] << 8 | cdb[3]`
/// (SBC-3 §5.10).
pub fn cdb_lba6(cdb: &[u8]) -> u32 {
    (u32::from(cdb[1] & 0x1F) << 16) | (u32::from(cdb[2]) << 8) | u32::from(cdb[3])
}

/// READ(6)/WRITE(6) transfer length (byte4). A value of 0 means 256
/// logical blocks (SBC-3 §5.10).
pub fn cdb_transfer_len6(cdb: &[u8]) -> u32 {
    let raw = cdb[4];
    if raw == 0 {
        256
    } else {
        u32::from(raw)
    }
}

/// READ(10)/WRITE(10) logical block address: bytes 2..=5 (SBC-3 §5.11).
pub fn cdb_lba10(cdb: &[u8]) -> u32 {
    (u32::from(cdb[2]) << 24)
        | (u32::from(cdb[3]) << 16)
        | (u32::from(cdb[4]) << 8)
        | u32::from(cdb[5])
}

/// READ(10)/WRITE(10) transfer length: bytes 7..=8 (SBC-3 §5.11).
pub fn cdb_transfer_len10(cdb: &[u8]) -> u16 {
    (u16::from(cdb[7]) << 8) | u16::from(cdb[8])
}

/// READ(12)/WRITE(12) logical block address: bytes 2..=5 (SBC-3 §5.12).
pub fn cdb_lba12(cdb: &[u8]) -> u32 {
    cdb_lba10(cdb)
}

/// READ(12)/WRITE(12) transfer length: bytes 6..=9 (SBC-3 §5.12).
pub fn cdb_transfer_len12(cdb: &[u8]) -> u32 {
    (u32::from(cdb[6]) << 24)
        | (u32::from(cdb[7]) << 16)
        | (u32::from(cdb[8]) << 8)
        | u32::from(cdb[9])
}

/// READ(16)/WRITE(16) logical block address: bytes 2..=9 (SBC-3 §5.13).
pub fn cdb_lba16(cdb: &[u8]) -> u64 {
    (u64::from(cdb[2]) << 56)
        | (u64::from(cdb[3]) << 48)
        | (u64::from(cdb[4]) << 40)
        | (u64::from(cdb[5]) << 32)
        | (u64::from(cdb[6]) << 24)
        | (u64::from(cdb[7]) << 16)
        | (u64::from(cdb[8]) << 8)
        | u64::from(cdb[9])
}

/// READ(16)/WRITE(16) transfer length: bytes 10..=13 (SBC-3 §5.13).
pub fn cdb_transfer_len16(cdb: &[u8]) -> u32 {
    (u32::from(cdb[10]) << 24)
        | (u32::from(cdb[11]) << 16)
        | (u32::from(cdb[12]) << 8)
        | u32::from(cdb[13])
}

/// Human-readable opcode name.
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        op::TEST_UNIT_READY => "TEST_UNIT_READY",
        op::REQUEST_SENSE => "REQUEST_SENSE",
        op::READ_6 => "READ_6",
        op::WRITE_6 => "WRITE_6",
        op::INQUIRY => "INQUIRY",
        op::READ_CAPACITY_10 => "READ_CAPACITY_10",
        op::READ_10 => "READ_10",
        op::WRITE_10 => "WRITE_10",
        op::READ_16 => "READ_16",
        op::WRITE_16 => "WRITE_16",
        op::SERVICE_ACTION_IN => "SERVICE_ACTION_IN",
        op::READ_12 => "READ_12",
        op::WRITE_12 => "WRITE_12",
        op::MODE_SENSE_6 => "MODE_SENSE_6",
        op::MODE_SENSE_10 => "MODE_SENSE_10",
        op::MODE_SELECT_6 => "MODE_SELECT_6",
        op::MODE_SELECT_10 => "MODE_SELECT_10",
        op::SYNCHRONIZE_CACHE_10 => "SYNCHRONIZE_CACHE_10",
        op::SEND_DIAGNOSTIC => "SEND_DIAGNOSTIC",
        op::RECEIVE_DIAGNOSTIC => "RECEIVE_DIAGNOSTIC",
        op::REPORT_LUNS => "REPORT_LUNS",
        op::PREVENT_ALLOW => "PREVENT_ALLOW",
        op::START_STOP_UNIT => "START_STOP_UNIT",
        op::READ_TOC => "READ_TOC",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn cdb6_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb6(op::READ_6, 0x0012345, 1);
        assert_eq!(cdb_opcode(&cdb), op::READ_6);
        assert_eq!(cdb_lba6(&cdb), 0x0012345);
        assert_eq!(cdb_transfer_len6(&cdb), 1);
    }

    #[test]
    fn cdb6_lba_masks_upper_bits_of_byte1() {
        let mut cdb = make_cdb6(op::READ_6, 0x1F0000, 0);
        cdb[1] |= 0xE0; /* upper 3 bits are not part of the LBA */
        assert_eq!(cdb_lba6(&cdb), 0x1F0000);
    }

    #[test]
    fn cdb6_transfer_len_zero_means_256() {
        let cdb = make_cdb6(op::READ_6, 0, 0);
        assert_eq!(cdb_transfer_len6(&cdb), 256);
        let cdb = make_cdb6(op::READ_6, 0, 0xFF);
        assert_eq!(cdb_transfer_len6(&cdb), 255);
    }

    #[test]
    fn cdb10_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb10(op::READ_10, 0x89ABCDEF, 0x1234);
        assert_eq!(cdb_opcode(&cdb), op::READ_10);
        assert_eq!(cdb_lba10(&cdb), 0x89ABCDEF);
        assert_eq!(cdb_transfer_len10(&cdb), 0x1234);
    }

    #[test]
    fn cdb12_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb12(op::WRITE_12, 0x89ABCDEF, 0x01020304);
        assert_eq!(cdb_opcode(&cdb), op::WRITE_12);
        assert_eq!(cdb_lba12(&cdb), 0x89ABCDEF);
        assert_eq!(cdb_transfer_len12(&cdb), 0x01020304);
    }

    #[test]
    fn cdb16_opcode_lba_transfer_roundtrip() {
        let lba: u64 = 0x0123456789ABCDEF;
        let cdb = make_cdb16(op::WRITE_16, lba, 0xDEADBEEF);
        assert_eq!(cdb_opcode(&cdb), op::WRITE_16);
        assert_eq!(cdb_lba16(&cdb), lba);
        assert_eq!(cdb_transfer_len16(&cdb), 0xDEADBEEF);
    }

    #[test]
    fn cdb16_lba_full_range() {
        let cdb = make_cdb16(op::READ_16, u64::MAX, 1);
        assert_eq!(cdb_lba16(&cdb), u64::MAX);
    }

    #[test]
    fn sense_new_clear_and_fixed_format() {
        let s = Sense::new(SenseKey::IllegalRequest, asc::INVALID_COMMAND, 0);
        assert_eq!(s.key, SenseKey::IllegalRequest);
        assert_eq!(s.asc, asc::INVALID_COMMAND);
        assert_eq!(s.ascq, 0);

        let mut buf = [0u8; 18];
        let n = s.write_fixed(&mut buf);
        assert_eq!(n, 18);
        assert_eq!(buf[0], 0x70); /* response code */
        assert_eq!(buf[2], 0x05); /* ILLEGAL REQUEST */
        assert_eq!(buf[7], 11); /* additional sense length (n-7) */
        assert_eq!(buf[12], asc::INVALID_COMMAND);
        assert_eq!(buf[13], 0);

        assert_eq!(Sense::clear().key, SenseKey::None);
    }

    #[test]
    fn sense_fixed_format_clamps_to_buffer() {
        let s = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
        let mut buf = [0u8; 4];
        let n = s.write_fixed(&mut buf);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[2], 0x05);
    }

    #[test]
    fn opcode_names() {
        assert_eq!(opcode_name(op::TEST_UNIT_READY), "TEST_UNIT_READY");
        assert_eq!(opcode_name(op::SERVICE_ACTION_IN), "SERVICE_ACTION_IN");
        assert_eq!(opcode_name(0xFF), "UNKNOWN");
    }
}
