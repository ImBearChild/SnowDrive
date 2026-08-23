//! SBC command layer: parsing + execution (SBC-3 §5).
//!
//! The direct-access block device command set. SPC commands fall through to
//! [`crate::scsi::spc`]; this module parses the SBC-specific opcodes and
//! wraps the SPC fall-through as [`SbcCommand::Spc`] so a device's
//! `do_cmd` is a single `parse_sbc` + two-arm dispatch.

use crate::scsi::backend::BlockStorage;
use crate::scsi::block::BlockDevice;
use crate::scsi::device::CommandOutcome;
use crate::scsi::scsi::{
    cdb_lba10, cdb_lba12, cdb_lba16, cdb_lba6, cdb_len_from_opcode, cdb_opcode, cdb_transfer_len10,
    cdb_transfer_len12, cdb_transfer_len16, cdb_transfer_len6, op,
};
use crate::scsi::spc::{parse_spc, SpcCommand};

/// Parsed SBC command (SBC-3 §5). SPC commands are wrapped in
/// [`SbcCommand::Spc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcCommand {
    Read6 {
        lba: u32,
        count: u32,
    },
    Write6 {
        lba: u32,
        count: u32,
    },
    Read10 {
        lba: u32,
        count: u16,
    },
    Write10 {
        lba: u32,
        count: u16,
    },
    Read12 {
        lba: u32,
        count: u32,
    },
    Write12 {
        lba: u32,
        count: u32,
    },
    Read16 {
        lba: u64,
        count: u32,
    },
    Write16 {
        lba: u64,
        count: u32,
    },
    ReadCapacity10 {
        pmi: bool,
        lba: u32,
    },
    /// SERVICE ACTION IN (0x9E); `sa` is the service action field (0x10 =
    /// READ CAPACITY(16)), carried so the executor can reject unknown values
    /// with INVALID FIELD IN CDB.
    ReadCapacity16 {
        sa: u8,
        alloc: u32,
    },
    SynchronizeCache,
    Spc(SpcCommand),
}

/// Parse `cdb` as an SBC command (SPC fall-through included). Returns `None`
/// for unknown opcodes or CDBs truncated below the opcode's fixed group
/// length (SPC-4 §7.3) — this function never panics.
pub fn parse_sbc(cdb: &[u8]) -> Option<SbcCommand> {
    if let Some(cmd) = parse_spc(cdb) {
        return Some(SbcCommand::Spc(cmd));
    }
    // Total: `parse_spc` already rejected CDBs shorter than 6 bytes, but the
    // 10/12/16-byte group opcodes below need their full group length before
    // field access.
    let op = cdb_opcode(cdb)?;
    if cdb.len() < usize::from(cdb_len_from_opcode(op)) {
        return None;
    }
    match op {
        op::READ_6 => Some(SbcCommand::Read6 {
            lba: cdb_lba6(cdb)?,
            count: cdb_transfer_len6(cdb)?,
        }),
        op::WRITE_6 => Some(SbcCommand::Write6 {
            lba: cdb_lba6(cdb)?,
            count: cdb_transfer_len6(cdb)?,
        }),
        op::READ_10 => Some(SbcCommand::Read10 {
            lba: cdb_lba10(cdb)?,
            count: cdb_transfer_len10(cdb)?,
        }),
        op::WRITE_10 => Some(SbcCommand::Write10 {
            lba: cdb_lba10(cdb)?,
            count: cdb_transfer_len10(cdb)?,
        }),
        op::READ_12 => Some(SbcCommand::Read12 {
            lba: cdb_lba12(cdb)?,
            count: cdb_transfer_len12(cdb)?,
        }),
        op::WRITE_12 => Some(SbcCommand::Write12 {
            lba: cdb_lba12(cdb)?,
            count: cdb_transfer_len12(cdb)?,
        }),
        op::READ_16 => Some(SbcCommand::Read16 {
            lba: cdb_lba16(cdb)?,
            count: cdb_transfer_len16(cdb)?,
        }),
        op::WRITE_16 => Some(SbcCommand::Write16 {
            lba: cdb_lba16(cdb)?,
            count: cdb_transfer_len16(cdb)?,
        }),
        op::READ_CAPACITY_10 => Some(SbcCommand::ReadCapacity10 {
            pmi: cdb[1] & 0x01 != 0,
            lba: (u32::from(cdb[2]) << 24)
                | (u32::from(cdb[3]) << 16)
                | (u32::from(cdb[4]) << 8)
                | u32::from(cdb[5]),
        }),
        op::SERVICE_ACTION_IN => Some(SbcCommand::ReadCapacity16 {
            sa: cdb[1],
            alloc: (u32::from(cdb[10]) << 24)
                | (u32::from(cdb[11]) << 16)
                | (u32::from(cdb[12]) << 8)
                | u32::from(cdb[13]),
        }),
        op::SYNCHRONIZE_CACHE_10 => Some(SbcCommand::SynchronizeCache),
        _ => None,
    }
}

/// Execute one parsed SBC command against `dev` (SPC commands never reach
/// here — `do_cmd` dispatches `SbcCommand::Spc` to `execute_spc`).
pub(crate) fn execute_sbc<B: BlockStorage>(
    dev: &mut BlockDevice<B>,
    cmd: SbcCommand,
    data: &mut [u8],
    dsl: usize,
) -> CommandOutcome {
    match cmd {
        SbcCommand::Read6 { lba, count } => {
            dev.read_cmd(dev.max_lba(), u64::from(lba), count, data)
        }
        SbcCommand::Write6 { lba, count } => {
            dev.write_cmd(dev.max_lba(), u64::from(lba), count, data, dsl)
        }
        SbcCommand::Read10 { lba, count } => {
            dev.read_cmd(dev.max_lba(), u64::from(lba), u32::from(count), data)
        }
        SbcCommand::Write10 { lba, count } => {
            dev.write_cmd(dev.max_lba(), u64::from(lba), u32::from(count), data, dsl)
        }
        SbcCommand::Read12 { lba, count } => {
            dev.read_cmd(dev.max_lba(), u64::from(lba), count, data)
        }
        SbcCommand::Write12 { lba, count } => {
            dev.write_cmd(dev.max_lba(), u64::from(lba), count, data, dsl)
        }
        SbcCommand::Read16 { lba, count } => dev.read_cmd(dev.max_lba(), lba, count, data),
        SbcCommand::Write16 { lba, count } => dev.write_cmd(dev.max_lba(), lba, count, data, dsl),
        SbcCommand::ReadCapacity10 { pmi, lba } => dev.read_capacity_10_cmd(pmi, lba, data),
        SbcCommand::ReadCapacity16 { sa, alloc } => dev.read_capacity_16_cmd(sa, alloc, data),
        SbcCommand::SynchronizeCache => {
            let _ = dev.backend().sync();
            CommandOutcome::Status
        }
        SbcCommand::Spc(_) => unreachable!("SPC commands are dispatched by do_cmd"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn parse_read_write_6() {
        let cdb = make_cdb6(op::READ_6, 0x0012345, 0); /* count 0 → 256 */
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Read6 {
                lba: 0x0012345,
                count: 256
            })
        );
        let cdb = make_cdb6(op::WRITE_6, 0x0012345, 7);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Write6 {
                lba: 0x0012345,
                count: 7
            })
        );
    }

    #[test]
    fn parse_read_write_10() {
        let cdb = make_cdb10(op::READ_10, 0x89ABCDEF, 0x1234);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Read10 {
                lba: 0x89ABCDEF,
                count: 0x1234
            })
        );
        let cdb = make_cdb10(op::WRITE_10, 0x89ABCDEF, 0x1234);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Write10 {
                lba: 0x89ABCDEF,
                count: 0x1234
            })
        );
    }

    #[test]
    fn parse_read_write_12() {
        let cdb = make_cdb12(op::READ_12, 0x89ABCDEF, 0x01020304);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Read12 {
                lba: 0x89ABCDEF,
                count: 0x01020304
            })
        );
        let cdb = make_cdb12(op::WRITE_12, 0x89ABCDEF, 0x01020304);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Write12 {
                lba: 0x89ABCDEF,
                count: 0x01020304
            })
        );
    }

    #[test]
    fn parse_read_write_16() {
        let lba: u64 = 0x0123456789ABCDEF;
        let cdb = make_cdb16(op::READ_16, lba, 0xDEADBEEF);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Read16 {
                lba,
                count: 0xDEADBEEF
            })
        );
        let cdb = make_cdb16(op::WRITE_16, lba, 0xDEADBEEF);
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Write16 {
                lba,
                count: 0xDEADBEEF
            })
        );
    }

    #[test]
    fn parse_read_capacity_10() {
        let mut cdb = make_cdb10(op::READ_CAPACITY_10, 0, 0);
        cdb[1] = 0x01; /* PMI */
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::ReadCapacity10 { pmi: true, lba: 0 })
        );
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        cdb[5] = 0x42;
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::ReadCapacity10 {
                pmi: false,
                lba: 0x42
            })
        );
    }

    #[test]
    fn parse_read_capacity_16_and_unknown_sa() {
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0x10; /* READ CAPACITY(16) */
        cdb[13] = 0x40; /* alloc length 64 */
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::ReadCapacity16 {
                sa: 0x10,
                alloc: 64
            })
        );

        cdb[1] = 0xFF; /* unknown service action */
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::ReadCapacity16 {
                sa: 0xFF,
                alloc: 64
            })
        );
    }

    #[test]
    fn parse_synchronize_cache() {
        let cdb = make_cdb10(op::SYNCHRONIZE_CACHE_10, 0, 0);
        assert_eq!(parse_sbc(&cdb), Some(SbcCommand::SynchronizeCache));
    }

    #[test]
    fn parse_spc_fallthrough() {
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Spc(SpcCommand::Inquiry {
                evpd: false,
                page: 0,
                alloc: 96
            }))
        );
        let cdb = [op::TEST_UNIT_READY; 6];
        assert_eq!(
            parse_sbc(&cdb),
            Some(SbcCommand::Spc(SpcCommand::TestUnitReady))
        );
    }

    #[test]
    fn parse_unknown_opcode_returns_none() {
        assert_eq!(parse_sbc(&[0xFF; 10]), None);
        assert_eq!(parse_sbc(&[op::REPORT_LUNS; 12]), None);
    }

    #[test]
    fn parse_is_total_on_empty_and_truncated_cdbs() {
        /* Empty / shorter-than-group CDBs → None, never a panic. */
        assert_eq!(parse_sbc(&[]), None);
        assert_eq!(parse_sbc(&[op::READ_10; 5]), None);
        assert_eq!(parse_sbc(&[op::READ_12; 9]), None);
        assert_eq!(parse_sbc(&[op::WRITE_16; 13]), None);
        /* A truncated group-0 SPC opcode falls through to SBC's None. */
        assert_eq!(parse_sbc(&[op::INQUIRY; 5]), None);
        /* 10-byte SPC opcode needs its full group length. */
        assert_eq!(parse_sbc(&[op::MODE_SENSE_10; 9]), None);
        /* Full-length CDBs still parse. */
        assert_eq!(
            parse_sbc(&make_cdb10(op::READ_10, 0x89ABCDEF, 0x1234)),
            Some(SbcCommand::Read10 {
                lba: 0x89ABCDEF,
                count: 0x1234
            })
        );
    }
}
