//! USB Mass Storage Class, Bulk-Only Transport (BOT) protocol core
//! (feature `usb`).
//!
//! A no_std BOT protocol core, transport-layout independent like the iSCSI
//! module: the CBW/CSW framing ([`bot`]), the platform I/O seams ([`io`],
//! [`gadget`]) and the non-blocking [`target`] session state machine.
//! Platform transports live outside the lib (FunctionFS on Linux, embedded
//! USB device stacks on MCUs) and implement [`BotIo`] / [`Gadget`].
//!
//! The data area handed to the SCSI device layer is a pure data region
//! ([`crate::MIN_DATA_LEN`]); CBWs and CSWs live in `BotSession`'s internal
//! buffers, so protocol frames never share memory with SCSI data.

pub mod bot;
pub mod gadget;
pub mod io;
pub mod target;

pub use bot::{BotDir, Cbw, Csw, CswStatus};
pub use gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
pub use io::{BotIo, BotIoErr};
pub use target::{
    BotSession, BotStepResult, BotTargetError, SessionEvent, SessionNeed, SessionStep,
};

/// Command Block Wrapper signature (`"USBC"`, BOT §5.1) — stored little
/// endian in the raw 31-byte CBW.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// Command Status Wrapper signature (`"USBS"`, BOT §5.2) — stored little
/// endian in the raw 13-byte CSW.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Command Block Wrapper size in bytes (BOT §5.1).
pub const CBW_LEN: usize = 31;
/// Command Status Wrapper size in bytes (BOT §5.2).
pub const CSW_LEN: usize = 13;

/// Mass Storage Class interface class code (USB MSC Overview v1.4 §4.1).
pub const MSC_CLASS: u8 = 0x08;
/// Subclass 0x06 = SCSI transparent command set (USB MSC Overview v1.4
/// Table 1; SFF-8070i is 0x05 and obsolete).
pub const MSC_SUBCLASS: u8 = 0x06;
/// Protocol 0x50 = Bulk-Only Transport (USB MSC Overview v1.4 §4.2).
pub const MSC_PROTOCOL: u8 = 0x50;

/// Bulk-Only Mass Storage Reset class request (`bmRequestType` 0x21, BOT
/// §6.4).
pub const BOT_RESET: u8 = 0xFF;
/// Get Max LUN class request (`bmRequestType` 0xA1, BOT §6.5).
pub const GET_MAX_LUN: u8 = 0xFE;
