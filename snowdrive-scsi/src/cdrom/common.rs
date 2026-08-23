//! CD-ROM common device layer (plan  / ).
//!
//! [`CdromDeviceCommon`] holds the shared SPC-level state (sense, prevent,
//! profile) and implements [`SpcDevice`] so that all three CD-ROM device
//! types (`CdromDevice`, `CdBundleDevice`, `CdLiveFsDevice`) delegate
//! INQUIRY / MODE SENSE / REQUEST SENSE / GET CONFIGURATION common
//! features to a single code path via field embedding (composition).
//!
//! Per, only the *synthesis* of MMC responses is shared here:
//! [`build_get_config_response`] and [`build_read_disc_info`] lay out the
//! bytes for the MMC field structure, taking the device's state as
//! parameters.  The per-device command dispatch (which state it feeds,
//! whether a command is supported) stays in each device's own
//! `execute_mmc_*` — device state never enters this module.

use crate::scsi::device::CommandOutcome;
use crate::scsi::spc::DeviceIdentity;
/// CD-ROM logical block size (Mode 1: 2048 data bytes per sector).
pub const SECTOR_SIZE: u32 = 2048;
/// INQUIRY identity for CD-ROM devices: SCSI family, with
/// SPC-4 and MMC-6 version descriptors.
pub const CDROM_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"HyperMulti DVD  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x05C0], /* SAM-5, iSCSI, SPC-4, MMC-6 */
};
/// Current Profile code for GET CONFIGURATION (MMC-6 §5.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentProfile {
    /// 0x0000 — No media / tray empty.
    Empty,
    /// 0x0008 — CD-ROM (images ≤ 700 MiB).
    CdRom,
    /// 0x0010 — DVD-ROM (images > 700 MiB).
    DvdRom,
    /// 0x0012 — DVD-RAM (random-writable medium).
    DvdRam,
    /// 0x0009 — CD-R — CD-R recordable media.
    CdR,
    /// 0x000A — CD-RW.
    CdRw,
    /// 0x001A — DVD+RW (UdfRw random-writable media).
    DvdRw,
}
impl CurrentProfile {
    /// Numeric profile code (MMC-6 Table 64).
    pub fn code(self) -> u16 {
        match self {
            Self::Empty => 0x0000,
            Self::CdRom => 0x0008,
            Self::DvdRom => 0x0010,
            Self::DvdRam => 0x0012,
            Self::CdR => 0x0009,
            Self::CdRw => 0x000A,
            Self::DvdRw => 0x001A,
        }
    }
    /// Pick the profile from a capacity in bytes.
    pub fn from_capacity(capacity: u64) -> Self {
        if capacity <= 700 * 1024 * 1024 {
            Self::CdRom
        } else {
            Self::DvdRom
        }
    }
}

/// State of the medium currently inserted in a drive. This is deliberately
/// separate from [`CdromCapabilities`], which describes the drive itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaState {
    pub profile: CurrentProfile,
    pub present: bool,
    pub ready: bool,
    pub formatted: bool,
    pub formattable: bool,
    pub erasable: bool,
    pub write_protected: bool,
    pub random_writable: bool,
    pub defect_management: bool,
    pub max_lba: u32,
    pub block_size: u32,
}

impl MediaState {
    pub const fn empty() -> Self {
        Self {
            profile: CurrentProfile::Empty,
            present: false,
            ready: false,
            formatted: false,
            formattable: false,
            erasable: false,
            write_protected: false,
            random_writable: false,
            defect_management: false,
            max_lba: 0,
            block_size: SECTOR_SIZE,
        }
    }
}
// ── CD-ROM MODE SENSE pages ─────────────────────────────────────────
/// Caching page (0x08, SPC-4 ): WCE=0, RCD=0, DRA=1.
const CACHING_PAGE: [u8; 20] = [
    0x88, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0,
];
/// Vendor-specific page (0x00).
const VENDOR_PAGE: [u8; 4] = [0x00, 2, 0x00, 0x08];
/// CD-ROM Parameters page (0x0D, MMC-6 ): page_length=2,
/// sector_size=2048 (big-endian u16).
const CDROM_PARAMS: [u8; 4] = [0x0D, 0x02, 0x08, 0x00];
/// CD-ROM Audio Control page (0x0E, MMC-6 ): page_length=14,
/// no audio.  Total = 2 + 14 = 16 bytes.
const CDROM_AUDIO: [u8; 16] = [
    0x0E, 0x0E, // page code, page length = 14
    0x04, 0x00, // IMMED=1 (bit 2), SOTC=0, reserved
    0x00, 0x00, 0x00, 0x00, // reserved (obsolete LB/AMM format)
    0x01, 0x00, // output port 0: channel selection = 0x01 (channel 0)
    0x00, 0x00, // output port 0: volume = 0
    0x02, 0x00, // output port 1: channel selection = 0x02 (channel 1)
    0x00, 0x00, // output port 1: volume = 0
];
/// Write Parameters page (0x05, MMC-6): page_length=0x32 (50), for `wodim`
/// `check_writemodes` probing. Minimal zeroed page with SAO/TAO defaults;
/// `MODE SELECT` is accepted unconditionally in `spc.rs`, so any
/// `write_type` probe succeeds and `wodim` prints `TAO PACKET SAO …`.
const WRITE_PARAMS_PAGE: [u8; 52] = [
    0x05, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
/// Read/Write Error Recovery page (0x01, SPC-3): AWRE=1 ARRE=1, minimum for
/// Hardware Defect Management Feature (MMC-6 Table 125).
const READ_WRITE_ERROR_RECOVERY_PAGE: [u8; 12] = [
    0x01, 0x0A, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Power Condition page (0x1A, SPC-3): minimal, timers disabled.
const POWER_CONDITION_PAGE: [u8; 12] = [
    0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Timeout and Protect page (0x1D, MMC-6 Table 679): TMOE=0, G3Enable=0, timeouts 0.
const TIMEOUT_PROTECT_PAGE: [u8; 10] = [0x1D, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

pub(crate) fn default_write_params_page() -> &'static [u8] {
    &WRITE_PARAMS_PAGE
}
/// Device-declared capability set — the single model every
/// capability-reporting channel (GET CONFIGURATION features, MODE SENSE
/// 0x2A page) is built from. Devices feed their capabilities;
/// the shared builders only lay out bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdromCapabilities {
    /// Loading mechanism is a tray (MMC-6 Table 99); `false` = caddy/slot.
    pub tray: bool,
    /// Media can be loaded / ejected via START STOP UNIT (LoEj).
    pub load: bool,
    pub eject: bool,
    /// Medium can be locked with PREVENT ALLOW MEDIUM REMOVAL.
    pub lock: bool,
    /// Read-side extras (baseline Mode-1 CD-ROM read is implicit in MMC).
    pub mode2_form1: bool,
    pub mode2_form2: bool,
    pub multi_session: bool,
    pub cd_da: bool,
    pub read_cdr: bool,
    pub read_cdrw: bool,
    pub read_dvd_rom: bool,
    /// Random Writable feature (0x0020): the drive presents a formatted
    /// random-writable media. Set by the UdfRw device.
    pub random_writable: bool,
    /// DVD+RW feature (0x002A): write capable DVD+RW media. Set by the
    /// UdfRw device.
    pub dvd_plus_rw: bool,
    /// Write Protect feature (0x0004): reports the media write-protect
    /// state. Windows treats a drive without this feature as write
    /// protected; the UdfRw drive reports it with all protection bits
    /// clear (not write-protected).
    pub write_protect: bool,
    /// Hardware Defect Management feature (0x0024, MMC-6 Table 123
    /// Ver 0001b AddLen 04h, SSA=0, Mode Page 01h): indicates the
    /// drive/media system provides a defect-free logical space. Windows'
    /// `IOCTL_DISK_IS_WRITABLE` requires this feature Current alongside
    /// RandomWritable to report the media as writable. Real DVD+RW drives
    /// do NOT have this feature (it belongs to DVD-RAM), but the Windows
    /// cdrom class driver gates all optical formatting on it.
    pub defect_management: bool,
    /// Write-side extras (CD-R/CD-RW).
    pub write_cdr: bool,
    pub write_cdrw: bool,
    pub test_write: bool,
    pub burn_proof: bool,
    /// Read DVD-R media.
    pub read_dvd_r: bool,
    /// Read DVD-RAM media.
    pub read_dvd_ram: bool,
    /// Read DVD-RW media.
    pub read_dvd_rw: bool,
    /// Read DVD+R media.
    pub read_dvd_plus_r: bool,
    /// Write DVD-R media.
    pub write_dvd_r: bool,
    /// Write DVD-RAM media.
    pub write_dvd_ram: bool,
    /// Write DVD-RW media.
    pub write_dvd_rw: bool,
    /// Write DVD+R media.
    pub write_dvd_plus_r: bool,
    /// Drive supports dual-layer (DL) media for the disc types it can
    /// handle.  Double-sided media are deliberately NOT supported — the
    /// "changing side of disk" capability stays clear.
    pub dual_layer: bool,
    pub num_volume_levels: u8,
    pub buffer_size: u16,
    pub max_read_speed: u16,  // KB/s
    pub max_write_speed: u16, // KB/s
}
impl CdromCapabilities {
    /// A read-only CD-ROM drive: Mode-1 data read is the implicit baseline,
    /// tray mechanism, eject/lock/load per real device calibration (§6.8).
    pub const fn read_only_cd_rom() -> Self {
        Self {
            tray: true,
            load: true,
            eject: true,
            lock: true,
            mode2_form1: false,
            mode2_form2: false,
            multi_session: false,
            cd_da: false,
            read_cdr: false,
            read_cdrw: false,
            read_dvd_rom: false,
            random_writable: false,
            dvd_plus_rw: false,
            write_protect: false,
            defect_management: false,
            write_cdr: false,
            write_cdrw: false,
            test_write: false,
            burn_proof: false,
            read_dvd_r: false,
            read_dvd_ram: false,
            read_dvd_rw: false,
            read_dvd_plus_r: false,
            write_dvd_r: false,
            write_dvd_ram: false,
            write_dvd_rw: false,
            write_dvd_plus_r: false,
            dual_layer: false,
            num_volume_levels: 0,
            buffer_size: 0,
            max_read_speed: 0,
            max_write_speed: 0,
        }
    }
    /// A full HyperMulti recorder: reads and writes every CD/DVD variant
    /// (CD-R/RW, DVD-ROM/R/RAM/RW/+R/+RW, including dual-layer), backed by a
    /// writable UDFRW plane.  Capabilities are intrinsic to the drive and do
    /// NOT depend on the inserted media or the storage backend.
    pub const fn hyper_multi() -> Self {
        Self {
            tray: true,
            load: true,
            eject: true,
            lock: true,
            mode2_form1: true,
            mode2_form2: true,
            multi_session: true,
            cd_da: true,
            read_cdr: true,
            read_cdrw: true,
            read_dvd_rom: true,
            random_writable: true,
            dvd_plus_rw: true,
            write_protect: true,
            defect_management: true,
            write_cdr: true,
            write_cdrw: true,
            test_write: true,
            burn_proof: true,
            read_dvd_r: true,
            read_dvd_ram: true,
            read_dvd_rw: true,
            read_dvd_plus_r: true,
            write_dvd_r: true,
            write_dvd_ram: true,
            write_dvd_rw: true,
            write_dvd_plus_r: true,
            dual_layer: true,
            num_volume_levels: 0xFF,
            buffer_size: 8192,
            max_read_speed: 22160,  // ≈ DVD 16x
            max_write_speed: 22160, // ≈ DVD 16x
        }
    }
}
/// The capabilities of the read-only CD-ROM devices (flat / livefs).
pub const READ_ONLY_CDROM_CAPS: CdromCapabilities = CdromCapabilities::read_only_cd_rom();
/// Capabilities of the UdfRw device: reads DVD media and presents a
/// formatted, random-writable DVD-RAM (features 0x0024 + 0x0020).
pub const UDFRW_CAPS: CdromCapabilities = CdromCapabilities {
    tray: true,
    load: true,
    eject: true,
    lock: true,
    mode2_form1: true,
    mode2_form2: false,
    multi_session: true,
    cd_da: false,
    read_cdr: true,
    read_cdrw: true,
    read_dvd_rom: true,
    random_writable: true,
    dvd_plus_rw: false,
    write_protect: true,
    defect_management: true,
    write_cdr: true,
    write_cdrw: true,
    test_write: true,
    burn_proof: true,
    read_dvd_r: false,
    read_dvd_ram: true,
    read_dvd_rw: false,
    read_dvd_plus_r: false,
    write_dvd_r: false,
    write_dvd_ram: true,
    write_dvd_rw: false,
    write_dvd_plus_r: false,
    dual_layer: false,
    num_volume_levels: 0,
    buffer_size: 0,
    max_read_speed: 0x2B48,
    max_write_speed: 0x2B48,
};
/// Full HyperMulti recorder capabilities — the default for the SnowDrive
/// CD/DVD device.  Reads and writes every CD/DVD variant including
/// dual-layer; capabilities are intrinsic to the drive and never depend on
/// the mounted media or the storage backend.
pub const HYPER_MULTI_CAPS: CdromCapabilities = CdromCapabilities::hyper_multi();
/// Write-speed performance descriptors advertised in the page 2A table:
/// (read speed KB/s, write speed KB/s).  CD first, then DVD.
pub const HYPER_MULTI_DESCS: [(u16, u16); 8] = [
    (706, 706),     // CD  4x
    (1411, 1411),   // CD  8x
    (2822, 2822),   // CD 16x
    (5645, 5645),   // CD 32x
    (9173, 9173),   // CD 52x
    (5540, 5540),   // DVD  4x
    (11080, 11080), // DVD  8x
    (22160, 22160), // DVD 16x
];
/// DVD-RAM write-speed descriptors used by the UDFRW medium view.
pub const UDFRW_DESCS: [(u16, u16); 1] = [(11080, 11080)];
/// `true` → 1 (const bit packing).
const fn bit(b: bool) -> u8 {
    b as u8
}
/// 3-bit loading mechanism type (MMC-6 Table 99: 000b caddy/slot, 001b tray).
const fn loading_type_bits(tray: bool) -> u8 {
    if tray {
        0b001
    } else {
        0b000
    }
}
/// Build the CD/DVD Capabilities & Mechanical Status mode page (0x2A) from
/// `caps` (MMC-3 / SFF-8090 layout). MMC-6 Appendix E.9 marks this page
/// legacy ("implementing mode page 2Ah is not recommended") — GET
/// CONFIGURATION is the authoritative channel — so this is the 0x2A "view"
/// of the same capability model the features are built from.
///
/// `descs` is the list of (read speed KB/s, write speed KB/s) write-speed
/// performance descriptors advertised in the table.  Each descriptor is
/// 4 bytes (2-byte read speed + 2-byte write speed, MMC-3 Table 105).  The
/// returned page is a fixed 64-byte buffer (max 8 descriptors + 32-byte base);
/// the page-length field at byte 1 reflects the actual populated size and any
/// trailing bytes are zero.
///
/// Layout (MMC-3, the variant `wodim`/`cdrkit` parse, LTOH bit order):
/// - 0   : page code (0x2A)
/// - 1   : page length (= 30 + 4·N)
/// - 2   : read  (R-CD-R@0,R-CD-RW@1,Method2@2,R-DVD-ROM@3,R-DVD-R@4,R-DVD-RAM@5)
/// - 3   : write (W-CD-R@0,W-CD-RW@1,Test@2,W-DVD-R@4,W-DVD-RAM@5)
/// - 4   : misc  (mode2_form1@4,mode2_form2@5,multi@6,BUF@7)
/// - 5   : CD-DA (cd_da@0,accurate@1)
/// - 6   : lock/eject/loading (lock@0,eject@3,loading@5-7)
/// - 7   : changer
/// - 8-9 : maximum read speed (KB/s)
/// - 10-11: number of volume levels
/// - 12-13: buffer size (KB)
/// - 14-15: current read speed (KB/s)
/// - 16  : reserved
/// - 17  : BCK/RCK/LSBF
/// - 18-19: maximum write speed (KB/s)
/// - 20-21: current write speed (MMC-2 legacy slot)
/// - 22-23: Copy Management Revision Supported
/// - 26  : reserved
/// - 27  : Rotation Control (0 = CLV, low 2 bits)
/// - 28-29: current write speed (MMC-3 v3 slot)
/// - 30-31: number of write-speed performance descriptors
/// - 32.. : descriptors, 4 bytes each (res0,rot,speed)
pub const fn build_capabilities_page(caps: &CdromCapabilities, descs: &[(u16, u16)]) -> [u8; 64] {
    let n = descs.len();
    let mut p = [0u8; 64];
    p[0] = 0x2A;
    p[1] = (30 + 4 * n) as u8; // page length (total - 2)
                               // Byte 2: read caps (LTOH low-bit order as cdrkit/wodim expects)
    p[2] = bit(caps.read_cdr)
        | (bit(caps.read_cdrw) << 1)
        | (bit(caps.read_dvd_rom) << 3)
        | (bit(caps.read_dvd_r) << 4)
        | (bit(caps.read_dvd_ram) << 5);
    // Byte 3: write caps
    p[3] = bit(caps.write_cdr)
        | (bit(caps.write_cdrw) << 1)
        | (bit(caps.test_write) << 2)
        | (bit(caps.write_dvd_r) << 4)
        | (bit(caps.write_dvd_ram) << 5);
    // Byte 4: audio/composite/mode2/multi/BUF
    p[4] = (bit(caps.mode2_form1) << 4)
        | (bit(caps.mode2_form2) << 5)
        | (bit(caps.multi_session) << 6)
        | (bit(caps.burn_proof) << 7);
    // Byte 5: CD-DA / subchannel
    p[5] = bit(caps.cd_da) | (bit(caps.cd_da) << 1); // cd_da_accurate follows cd_da
                                                     // Byte 6: lock / eject / loading
    p[6] = bit(caps.lock) | (bit(caps.eject) << 3) | (loading_type_bits(caps.tray) << 5);
    // Byte 7: sep / changer
    p[7] = 0;
    p[8] = (caps.max_read_speed >> 8) as u8;
    p[9] = caps.max_read_speed as u8;
    p[10] = ((caps.num_volume_levels as u16) >> 8) as u8;
    p[11] = caps.num_volume_levels;
    p[12] = (caps.buffer_size >> 8) as u8;
    p[13] = caps.buffer_size as u8;
    p[14] = (caps.max_read_speed >> 8) as u8;
    p[15] = caps.max_read_speed as u8;
    p[16] = 0;
    p[17] = 0;
    p[18] = (caps.max_write_speed >> 8) as u8;
    p[19] = caps.max_write_speed as u8;
    p[20] = (caps.max_write_speed >> 8) as u8;
    p[21] = caps.max_write_speed as u8;
    // 22-23: Copy Management Revision Supported (0x0001 = recorder capable).
    p[22] = 0x00;
    p[23] = 0x01;
    // 24-25 reserved
    // 26: reserved, 27: rot_ctl (low 2 bits = CLV)
    p[26] = 0x00;
    p[27] = 0x00;
    // 28-29: current write speed (MMC-3 v3 slot).
    p[28] = (caps.max_write_speed >> 8) as u8;
    p[29] = caps.max_write_speed as u8;
    // 30-31: number of write-speed performance descriptors.
    p[30] = ((n as u16) >> 8) as u8;
    p[31] = n as u8;
    // 32..: descriptors — single write speed per descriptor (res0, rot, speed)
    let mut i = 0;
    while i < n {
        let base = 32 + i * 4;
        let (_, ws) = descs[i];
        p[base] = 0x00;
        p[base + 1] = 0x00; // rot = CLV/PCAV
        p[base + 2] = (ws >> 8) as u8;
        p[base + 3] = ws as u8;
        i += 1;
    }
    p
}
/// CD/DVD Capabilities & Mechanical Status page (0x2A) for the SnowDrive
/// CD/DVD device.  Built from the fixed HyperMulti capability model — the
/// drive's abilities are intrinsic and never depend on the mounted media.
const CDROM_CAPABILITIES: [u8; 64] = build_capabilities_page(&HYPER_MULTI_CAPS, &HYPER_MULTI_DESCS);
const UDFRW_CAPABILITIES: [u8; 64] = build_capabilities_page(&UDFRW_CAPS, &UDFRW_DESCS);
/// Return the MODE SENSE page data for `page` (`0x3F` = all pages).
#[allow(dead_code)]
pub(crate) fn cdrom_mode_page(page: u8) -> Option<&'static [u8]> {
    cdrom_mode_page_for_caps(page, &HYPER_MULTI_CAPS)
}
/// Return a MODE SENSE page using a particular drive capability model.
pub(crate) fn cdrom_mode_page_for_caps(
    page: u8,
    caps: &CdromCapabilities,
) -> Option<&'static [u8]> {
    match page {
        0x05 => Some(&WRITE_PARAMS_PAGE),
        0x01 => Some(&READ_WRITE_ERROR_RECOVERY_PAGE),
        0x08 => Some(&CACHING_PAGE),
        0x00 => Some(&VENDOR_PAGE),
        0x0D => Some(&CDROM_PARAMS),
        0x0E => Some(&CDROM_AUDIO),
        0x1A => Some(&POWER_CONDITION_PAGE),
        0x1D => Some(&TIMEOUT_PROTECT_PAGE),
        0x2A if caps.random_writable && !caps.dvd_plus_rw => Some(&UDFRW_CAPABILITIES),
        0x2A => Some(&CDROM_CAPABILITIES),
        0x3F => Some(&ALL_CDROM_PAGES),
        _ => None,
    }
}
/// Total byte count of all CD-ROM mode pages (for 0x3F sizing).
pub(crate) const ALL_CDROM_PAGES_LEN: usize = VENDOR_PAGE.len()
    + READ_WRITE_ERROR_RECOVERY_PAGE.len()
    + CACHING_PAGE.len()
    + CDROM_PARAMS.len()
    + CDROM_AUDIO.len()
    + POWER_CONDITION_PAGE.len()
    + TIMEOUT_PROTECT_PAGE.len()
    + CDROM_CAPABILITIES.len();
/// Concatenate `parts` into a `[u8; N]` (const, for building 0x3F).
const fn concat_pages<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    let mut p = 0;
    while p < parts.len() {
        let mut j = 0;
        while j < parts[p].len() {
            out[i] = parts[p][j];
            i += 1;
            j += 1;
        }
        p += 1;
    }
    out
}
/// All CD-ROM mode pages, in MODE SENSE page order (for `0x3F`).
const ALL_CDROM_PAGES: [u8; ALL_CDROM_PAGES_LEN] = concat_pages(&[
    &VENDOR_PAGE,
    &READ_WRITE_ERROR_RECOVERY_PAGE,
    &CACHING_PAGE,
    &CDROM_PARAMS,
    &CDROM_AUDIO,
    &POWER_CONDITION_PAGE,
    &TIMEOUT_PROTECT_PAGE,
    &CDROM_CAPABILITIES,
]);
// ── GET CONFIGURATION common features builder ───────────────────────
/// Build GET CONFIGURATION feature descriptors common to all CD-ROM
/// devices.  Writes into `buf[off..]` and returns the new
/// offset.  `profile` is the current profile; `last_lba` feeds the Random
/// Writable feature (ignored unless `caps.random_writable`).
///
/// Features included when supported by the drive. Media-dependent Current
/// bits are derived from `media`; the Profile List remains drive-derived.
/// - 0x0001 Core (version 2, persistent, additional length 8)
/// - 0x0002 Morphing (Version 0001b, OCEvent)
/// - 0x0003 Removable Medium (tray type)
/// - 0x0004 Write Protect (only if `caps.write_protect`)
/// - 0x0010 Random Readable (block size 2048)
/// - 0x001D Multi-Read
/// - 0x001E CD Read (version 2)
/// - 0x001F DVD Read (only for DVD profiles)
/// - 0x0020 Random Writable (only if `caps.random_writable`)
/// - 0x0021 Incremental Streaming Writable (only if `caps.write_dvd_r`)
/// - 0x0023 Formattable (for DVD+RW media)
/// - 0x0024 Hardware Defect Management (Ver 0001b, SSA=0, Mode Page 01h)
/// - 0x0026 Restricted Overwrite (only if `caps.write_dvd_rw`)
/// - 0x002A DVD+RW (only if `caps.dvd_plus_rw`)
/// - 0x002B DVD+R (only if `caps.read_dvd_plus_r`/`write_dvd_plus_r`)
/// - 0x002F DVD-R/-RW Write (only if `caps.write_dvd_r`/`write_dvd_rw`)
/// - 0x0100 Power Management (Version 0000b)
/// - 0x0105 Timeout (Version 0001b, Group3=0)
/// - 0x0107 Real-Time Streaming (Version 0101b, RBCB/SCS/MP2A)
/// - 0x010A Disc Control Block (for DVD+RW media)
#[allow(clippy::too_many_arguments)]
pub fn build_get_config_features_for_media(
    buf: &mut [u8],
    mut off: usize,
    profile: CurrentProfile,
    caps: &CdromCapabilities,
    _rt: u8,
    start_feature: u16,
    last_lba: u32,
    media: &MediaState,
) -> usize {
    // The kernel's cdrom_is_random_writable() (and cdrom_is_mrw(), which
    // gracefully finds no MRW feature here) issue GET CONFIGURATION with
    // RT=0 (current) plus a starting feature (0x0020 / 0x0028) and read
    // the FIRST descriptor expecting the requested feature — the same
    // behavior real drives exhibit (they honor Starting Feature Number for
    // every RT). So always start the response at the requested feature;
    // RT=0 + start 0 yields everything.
    let include = |code: u16| code >= start_feature;
    // Profile List (0x0000) is required in EVERY GET CONFIGURATION response
    // per MMC-6 §5.4.2. It identifies the profiles supported by the drive;
    // the mounted profile is marked current (or 0000h when no media).
    if include(0x0000) {
        // Build profile list from caps: each supported profile gets a slot.
        // Start with the known profiles from the caps bitmask.
        let mut profiles = heapless::Vec::<u16, 16>::new();
        if caps.read_cdr || caps.write_cdr {
            let _ = profiles.push(0x0009); // CD-R
        }
        if caps.read_cdrw || caps.write_cdrw {
            let _ = profiles.push(0x000A); // CD-RW
        }
        if caps.read_dvd_rom {
            let _ = profiles.push(0x0010); // DVD-ROM
        }
        if caps.read_dvd_r || caps.write_dvd_r {
            let _ = profiles.push(0x0011); // DVD-R
            if caps.dual_layer {
                let _ = profiles.push(0x0016); // DVD-R Dual Layer
            }
        }
        if caps.read_dvd_ram || caps.write_dvd_ram {
            let _ = profiles.push(0x0012); // DVD-RAM
        }
        if caps.read_dvd_rw || caps.write_dvd_rw {
            let _ = profiles.push(0x0013); // DVD-RW
            if caps.dual_layer {
                let _ = profiles.push(0x0017); // DVD-RW Dual Layer
            }
        }
        if caps.read_dvd_plus_r || caps.write_dvd_plus_r {
            let _ = profiles.push(0x001B); // DVD+R
            if caps.dual_layer {
                let _ = profiles.push(0x002B); // DVD+R Dual Layer
            }
        }
        if caps.dvd_plus_rw {
            let _ = profiles.push(0x001A); // DVD+RW
            if caps.dual_layer {
                let _ = profiles.push(0x0018); // DVD+RW Dual Layer
            }
        }
        // Always include CD-ROM as a baseline profile.
        if profiles.iter().all(|&p| p != 0x0008) {
            let _ = profiles.insert(0, 0x0008);
        }
        // Ensure at least CD-ROM is present.
        if profiles.is_empty() {
            let _ = profiles.push(0x0008);
        }
        // Feature header: feature code 0x0000, version 0, persistent + current.
        buf[off] = 0x00;
        buf[off + 1] = 0x00;
        buf[off + 2] = 0x03; // persistent + current
                             // Additional length = number of profiles * 4.
        buf[off + 3] = (profiles.len() * 4) as u8;
        for (i, code) in profiles.iter().enumerate() {
            let p = off + 4 + i * 4;
            buf[p..p + 2].copy_from_slice(&code.to_be_bytes());
            if *code == profile.code() {
                buf[p + 2] = 0x01; // current profile
            }
        }
        off += 4 + profiles.len() * 4;
        // Pad to 4-byte alignment.
        while !off.is_multiple_of(4) {
            off += 1;
        }
    }
    // Core (0x0001)
    if include(0x0001) {
        buf[off] = 0x00;
        buf[off + 1] = 0x01;
        buf[off + 2] = 0x03; // version 2 + persistent + current
        buf[off + 3] = 0x08; // additional length
        buf[off + 4..off + 8].copy_from_slice(&[0, 0, 0, 1]); // SCSI family
        buf[off + 8] = 0x06; // INQ2 | DBE
        off += 12;
    }
    // Morphing (0x0002) — MMC-6 Table 96 Version 0001b Persistent+Current
    if include(0x0002) {
        buf[off] = 0x00;
        buf[off + 1] = 0x02;
        buf[off + 2] = 0x07; // Version 0001b + persistent + current
        buf[off + 3] = 0x04; // additional length
        buf[off + 4] = 0x02; // OCEvent=1 ASYNC=0
        buf[off + 5] = 0x00;
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // Removable Medium (0x0003)
    if include(0x0003) {
        buf[off] = 0x00;
        buf[off + 1] = 0x03;
        buf[off + 2] = 0x01; // current
        buf[off + 3] = 0x04; // additional length
                             // Byte 4: Loading Mechanism Type (bits 7-5) | Load | Eject | Pvnt
                             // Jmpr | DBML | Lock (MMC-6 Table 98) — same model as the 0x2A page.
        buf[off + 4] = (loading_type_bits(caps.tray) << 5)
            | (bit(caps.load) << 4)
            | (bit(caps.eject) << 3)
            | bit(caps.lock);
        off += 8;
    }
    // Write Protect (0x0004) — reports the media write-protect state.
    // Windows expects this feature; without it the disc is treated as
    // write-protected. All protection bits are clear (not protected); the
    // Current bit is 0 because this device does not change write protection.
    // WDCB is also clear: the device can report the DCB, but does not claim
    // support for modifying it with SEND DISC STRUCTURE.
    if caps.write_protect && include(0x0004) {
        buf[off] = 0x00;
        buf[off + 1] = 0x04;
        buf[off + 2] = 0x08; // version 2, current clear
        buf[off + 3] = 0x04; // additional length
        buf[off + 4..off + 8].copy_from_slice(&[0x00, 0, 0, 0]);
        off += 8;
    }
    // Random Readable (0x0010) — persistent+current
    if include(0x0010) {
        buf[off] = 0x00;
        buf[off + 1] = 0x10;
        buf[off + 2] = 0x02 | u8::from(media.present);
        buf[off + 3] = 0x08; // additional length
        buf[off + 4..off + 8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        buf[off + 8] = 0x00;
        buf[off + 9] = 0x01; // blocking = 1
        off += 12;
    }
    // DVD-RAM Read (0x0012)
    if caps.read_dvd_ram && include(0x0012) {
        buf[off] = 0x00;
        buf[off + 1] = 0x12;
        buf[off + 2] = 0x02 | u8::from(media.profile == CurrentProfile::DvdRam);
        buf[off + 3] = 0x00;
        off += 4;
    }
    // Multi-Read (0x001D)
    if include(0x001D) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1D;
        buf[off + 2] = 0x02 | u8::from(media.present);
        off += 4;
    }
    // CD Read (0x001E)
    if include(0x001E) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1E;
        buf[off + 2] = 0x02 | u8::from(media.present);
        buf[off + 3] = 0x04; // additional length
        off += 8;
    }
    // DVD Read (0x001F) — caps-based, persistent+current
    if caps.read_dvd_rom && include(0x001F) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1F;
        buf[off + 2] = 0x02
            | u8::from(matches!(
                media.profile,
                CurrentProfile::DvdRom | CurrentProfile::DvdRam
            ));
        off += 4;
    }
    // Random Writable (0x0020)
    if caps.random_writable && include(0x0020) {
        buf[off] = 0x00;
        buf[off + 1] = 0x20;
        buf[off + 2] = 0x06 | u8::from(media.random_writable);
        buf[off + 3] = 0x0C; // additional length
        buf[off + 4..off + 8].copy_from_slice(&last_lba.to_be_bytes());
        buf[off + 8..off + 12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        buf[off + 12..off + 14].copy_from_slice(&1u16.to_be_bytes()); // blocking
        buf[off + 14] = 0x00; // PP: no error recovery page
        buf[off + 15] = 0x00;
        off += 16;
    }
    // Incremental Streaming Writable (0x0021)
    if caps.write_dvd_r && include(0x0021) {
        buf[off] = 0x00;
        buf[off + 1] = 0x21;
        buf[off + 2] = 0x07; // version 1, persistent+current
        buf[off + 3] = 0x04; // additional length
        buf[off + 4..off + 8].fill(0);
        off += 8;
    }
    // Formattable (0x0023)
    if (caps.dvd_plus_rw || caps.random_writable) && include(0x0023) {
        buf[off] = 0x00;
        buf[off + 1] = 0x23;
        buf[off + 2] = 0x0A | u8::from(media.formattable);
        buf[off + 3] = 0x08;
        buf[off + 4..off + 12].fill(0);
        off += 12;
    }
    // Hardware Defect Management (0x0024) — MMC-6 Table 123 Ver 0001b AddLen 04h
    // Current when defect_management media, SSA=0, Mode Page 01h
    if caps.defect_management && include(0x0024) {
        buf[off] = 0x00;
        buf[off + 1] = 0x24;
        buf[off + 2] = 0x06 | u8::from(media.defect_management);
        buf[off + 3] = 0x04; // additional length
        buf[off + 4] = 0x00; // SSA=0, no spare area
        buf[off + 5] = 0x00;
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // Restricted Overwrite (0x0026)
    if caps.write_dvd_rw && include(0x0026) {
        buf[off] = 0x00;
        buf[off + 1] = 0x26;
        buf[off + 2] = 0x06 | u8::from(media.profile == CurrentProfile::DvdRw);
        buf[off + 3] = 0x00; // additional length
        off += 4;
    }
    // DVD+RW (0x002A)
    if caps.dvd_plus_rw && include(0x002A) {
        buf[off] = 0x00;
        buf[off + 1] = 0x2A;
        buf[off + 2] = 0x06 | u8::from(media.profile == CurrentProfile::DvdRw);
        buf[off + 3] = 0x04; // additional length
        buf[off + 4] = 0x01; // Write
        buf[off + 5] = 0x00; // Quick Start / Close Only clear
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // DVD+R (0x002B)
    if (caps.read_dvd_plus_r || caps.write_dvd_plus_r) && include(0x002B) {
        buf[off] = 0x00;
        buf[off + 1] = 0x2B;
        buf[off + 2] = 0x06 | u8::from(media.profile == CurrentProfile::CdR);
        buf[off + 3] = 0x04; // additional length
        buf[off + 4] = 0x01; // Write
        buf[off + 5] = 0x00;
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // DVD-R/-RW Write (0x002F)
    if (caps.write_dvd_r || caps.write_dvd_rw) && include(0x002F) {
        buf[off] = 0x00;
        buf[off + 1] = 0x2F;
        buf[off + 2] = 0x06 | u8::from(media.profile == CurrentProfile::DvdRw);
        buf[off + 3] = 0x00; // additional length
        off += 4;
    }
    // CD-RW Media Write Support (0x0037) — MMC-4 Table 163.
    if caps.write_cdrw && include(0x0037) {
        buf[off] = 0x00;
        buf[off + 1] = 0x37;
        buf[off + 2] = 0x02 | u8::from(media.profile == CurrentProfile::CdRw);
        buf[off + 3] = 0x04; // additional length 4
        buf[off + 4] = 0x00; // reserved
        buf[off + 5] = 0x0F; // multi|high|ultra|ultra+
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // Power Management (0x0100) — MMC-6 Table 178 Version 0000b
    if include(0x0100) {
        buf[off] = 0x01;
        buf[off + 1] = 0x00;
        buf[off + 2] = 0x03; // Version 0000b + persistent + current
        buf[off + 3] = 0x00; // additional length
        off += 4;
    }
    // Timeout (0x0105) — MMC-6 Table 186 Version 0001b AddLen 04h
    if include(0x0105) {
        buf[off] = 0x01;
        buf[off + 1] = 0x05;
        buf[off + 2] = 0x07; // Version 0001b + persistent + current
        buf[off + 3] = 0x04;
        buf[off + 4] = 0x00; // Group3=0
        buf[off + 5] = 0x00;
        buf[off + 6] = 0x00; // Unit Length
        buf[off + 7] = 0x00;
        off += 8;
    }
    // Real-Time Streaming (0x0107) — MMC-6 Table 190 Version 0101b
    if include(0x0107) {
        buf[off] = 0x01;
        buf[off + 1] = 0x07;
        buf[off + 2] = 0x17; // Version 0101b + persistent + current
        buf[off + 3] = 0x04;
        buf[off + 4] = 0x1C; // RBCB=1 SCS=1 MP2A=1
        buf[off + 5] = 0x00;
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }
    // MRW (Mount Rainier, 0x0028) is deliberately NOT reported
    // Disc Control Block (0x010A)
    if caps.dvd_plus_rw && include(0x010A) {
        buf[off] = 0x01;
        buf[off + 1] = 0x0A;
        buf[off + 2] = 0x02 | u8::from(media.profile == CurrentProfile::DvdRw);
        buf[off + 3] = 0x0C;
        buf[off + 4..off + 16].copy_from_slice(b"FDC\0SDC\0TOC\0");
        off += 16;
    }
    off
}

/// Compatibility wrapper for callers that provide only a profile and a
/// presence flag. New drive code should use the media-state variant.
#[allow(clippy::too_many_arguments)]
pub fn build_get_config_features(
    buf: &mut [u8],
    off: usize,
    profile: CurrentProfile,
    caps: &CdromCapabilities,
    rt: u8,
    start_feature: u16,
    last_lba: u32,
    media_current: bool,
) -> usize {
    let media = MediaState {
        profile,
        present: media_current,
        ready: media_current,
        formatted: media_current,
        formattable: false,
        erasable: false,
        write_protected: !media_current,
        random_writable: media_current && caps.random_writable,
        defect_management: media_current && caps.defect_management,
        max_lba: last_lba,
        block_size: SECTOR_SIZE,
    };
    build_get_config_features_for_media(
        buf,
        off,
        profile,
        caps,
        rt,
        start_feature,
        last_lba,
        &media,
    )
}
/// Build a GET CONFIGURATION response into `data[0..]`.
#[allow(clippy::too_many_arguments)]
pub fn build_get_config_response(
    data: &mut [u8],
    profile: CurrentProfile,
    caps: &CdromCapabilities,
    rt: u8,
    start_feature: u16,
    alloc: u16,
    last_lba: u32,
    media_current: bool,
) -> CommandOutcome {
    // Header (8) + all features: Core(12) Removable(8) WriteProtect(8)
    // RandomReadable(12) MultiRead(4) CDRead(8) DVDRead(4) RandomWritable(16)
    // MRW(8) DVD+RW(8).
    let mut buf = [0u8; 512];
    // Header: bytes 0-3 = data length (placeholder), 6-7 = current profile.
    buf[6] = (profile.code() >> 8) as u8;
    buf[7] = profile.code() as u8;
    let off = build_get_config_features(
        &mut buf,
        8,
        profile,
        caps,
        rt,
        start_feature,
        last_lba,
        media_current,
    );
    // Data length = bytes following the 4-byte data-length field itself.
    let data_len = (off - 4) as u32;
    buf[0..4].copy_from_slice(&data_len.to_be_bytes());
    let n = off.min(alloc as usize);
    data[0..n].copy_from_slice(&buf[..n]);
    CommandOutcome::OutInline { len: n as u64 }
}

/// Build GET CONFIGURATION from separate drive capabilities and medium state.
#[allow(clippy::too_many_arguments)]
pub fn build_get_config_response_for_media(
    data: &mut [u8],
    caps: &CdromCapabilities,
    media: &MediaState,
    rt: u8,
    start_feature: u16,
    alloc: u16,
) -> CommandOutcome {
    let mut buf = [0u8; 512];
    buf[6] = (media.profile.code() >> 8) as u8;
    buf[7] = media.profile.code() as u8;
    let off = build_get_config_features_for_media(
        &mut buf,
        8,
        media.profile,
        caps,
        rt,
        start_feature,
        media.max_lba,
        media,
    );
    let data_len = (off - 4) as u32;
    buf[0..4].copy_from_slice(&data_len.to_be_bytes());
    let n = off.min(alloc as usize);
    data[0..n].copy_from_slice(&buf[..n]);
    CommandOutcome::OutInline { len: n as u64 }
}
/// Build the READ BUFFER CAPACITY response (MMC-6 , Table 342):
/// 12-byte structure with Data Length = 10. `buffer_len` / `blank_len` are
/// the whole / unused buffer bytes (0 for a drive without a write buffer).
pub fn build_read_buffer_capacity(
    data: &mut [u8],
    alloc: u16,
    buffer_len: u32,
    blank_len: u32,
) -> CommandOutcome {
    let mut buf = [0u8; 12];
    buf[1] = 0x0A; // Data Length = 10 (excludes itself), big-endian
    buf[4..8].copy_from_slice(&buffer_len.to_be_bytes());
    buf[8..12].copy_from_slice(&blank_len.to_be_bytes());
    let n = buf.len().min(alloc as usize);
    data[..n].copy_from_slice(&buf[..n]);
    CommandOutcome::OutInline { len: n as u64 }
}
/// Disc state parameters for the Standard Disc Information response
/// (MMC-6 ). Each device feeds its own state — this struct only
/// transports values, it never reads device state.
pub struct DiscInfo {
    /// Disc Status (MMC-6 Table 367): 0=empty, 1=incomplete, 2=finalized.
    pub disc_status: u8,
    /// State of Last Session (MMC-6 Table 366): 0=empty, 1=incomplete,
    /// 3=complete. Valid for `disc_status` = 2/3.
    pub state_of_last_session: u8,
    /// Erasable bit (byte 2 bit 3): set for CD-RW media.
    pub erasable: bool,
    /// Number of sessions (byte 4/9).
    pub sessions: u8,
    /// First / last track number in the last session (bytes 5-6/10-11).
    pub first_track: u8,
    pub last_track: u8,
    /// Disc Type (MMC-6 Table 369): 0x00=CD-DA/CD-ROM, 0x20=CD-ROM XA.
    pub disc_type: u8,
    /// MRW Status (byte 7 bits 0-1): 0=not MRW formatted, 1=bgformat
    /// inactive, 2=bgformat active, 3=MRW formatting complete. The kernel's
    /// `cdrom_mrw_open_write()` refuses a write open when this is 0.
    pub mrw_status: u8,
    /// Last Possible Lead-out Start Address (bytes 20-23, LBA).
    pub lead_out_lba: u32,
}
/// Build the Standard Disc Information response (MMC-6 ) into
/// `data`, bounded by `alloc`. Returns a Data-In outcome carrying the
/// synthesized bytes (`immediate`). An `alloc` of zero is not an error and
/// yields an empty data phase (MMC-6 ).
pub fn build_read_disc_info(data: &mut [u8], alloc: u16, info: &DiscInfo) -> CommandOutcome {
    // Standard block: Disc Information Length = 0x32 (+8×OPC tables, none).
    let mut buf = [0u8; 52];
    buf[0..2].copy_from_slice(&0x0032u16.to_be_bytes());
    // Byte 2: Disc Information Data Type 000b | Erasable | State of last
    // Session | Disc Status (bits 7:5 | 4 | 3:2 | 1:0) — MMC-6 Table 365.
    let state = (info.state_of_last_session & 0b11) << 2;
    let erasable = u8::from(info.erasable) << 4;
    buf[2] = erasable | state | (info.disc_status & 0b11);
    buf[3] = info.first_track;
    buf[4] = info.sessions;
    buf[5] = info.first_track;
    buf[6] = info.last_track;
    // Byte 7: DID_V/DBC_V/DAC_V clear, URU=1 (unrestricted write use,
    // MMC-6  — zero marks the disc "restricted use", which
    // requires a Write Parameters Page app code and makes Windows refuse
    // writes), MRW Status (bits 1:0).
    buf[7] = 0x20 | (info.mrw_status & 0x03);
    buf[8] = info.disc_type;
    // Bytes 9-11: MSB halves of sessions / first / last track (all 0).
    // Bytes 12-19: Disc Identification, Last Session Lead-in Start (0).
    buf[20..24].copy_from_slice(&info.lead_out_lba.to_be_bytes());
    // Bytes 24-51: Disc Bar Code, Disc Application Code, OPC tables (0).
    let n = buf.len().min(alloc as usize).min(data.len());
    data[..n].copy_from_slice(&buf[..n]);
    CommandOutcome::OutInline { len: n as u64 }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::device::{CommandOutcome, DeviceType};
    use crate::scsi::scsi::{op, Sense};
    use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcDevice, SpcEffect};
    /// Minimal test device for exercising SPC commands through execute_spc.
    struct TestDev {
        sense: Sense,
    }
    impl TestDev {
        fn new() -> Self {
            Self {
                sense: Sense::clear(),
            }
        }
    }
    impl SpcDevice for TestDev {
        fn device_type(&self) -> DeviceType {
            DeviceType::Cdrom
        }
        fn identity(&self) -> &DeviceIdentity {
            &CDROM_IDENTITY
        }
        fn id(&self) -> u64 {
            0
        }
        fn mode_page(&self, page: u8) -> Option<&[u8]> {
            cdrom_mode_page(page)
        }
        fn sense(&self) -> &Sense {
            &self.sense
        }
        fn sense_mut(&mut self) -> &mut Sense {
            &mut self.sense
        }
        fn start_stop(&mut self, _loej: bool, _load: bool) -> SpcEffect {
            SpcEffect::Good
        }
        fn set_prevent(&mut self, _prevent: bool) {}
    }
    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }
    fn data_in(outcome: CommandOutcome, work: &[u8], buf: &mut [u8]) -> usize {
        match outcome {
            CommandOutcome::OutInline { len } => {
                let n = len as usize;
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected DataIn"),
        }
    }
    fn run(dev: &mut TestDev, cdb: &[u8], work: &mut [u8]) -> CommandOutcome {
        execute_spc(dev, parse_spc(cdb).unwrap(), work)
    }
    fn run_data(dev: &mut TestDev, cdb: &[u8], buf: &mut [u8]) -> usize {
        let mut w = work();
        data_in(run(dev, cdb, &mut w), &w, buf)
    }
    // ── INQUIRY ─────────────────────────────────────────────────────
    // ── MODE SENSE ──────────────────────────────────────────────────
    #[test]
    fn cdrom_mode_sense_6_cd_params_page() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x0D;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 8); /* 4 header + 4 page */
        assert_eq!(buf[0], 7); /* mode data length (total - 1) */
        assert_eq!(buf[4], 0x0D); /* page code */
        assert_eq!(buf[5], 0x02); /* page length */
        // Sector size = 2048 = 0x0800
        assert_eq!(buf[6], 0x08);
        assert_eq!(buf[7], 0x00);
    }
    #[test]
    fn cdrom_mode_sense_6_audio_control_page() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x0E;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 20); /* 4 header + 16 page */
        assert_eq!(buf[4], 0x0E); /* page code */
        assert_eq!(buf[5], 0x0E); /* page length = 14 */
    }
    #[test]
    fn cdrom_mode_sense_6_capabilities_page() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x2A;
        cdb[4] = 100;
        let mut buf = [0u8; 128];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 4 + 64); /* 4 header + 64 page */
        assert_eq!(buf[4], 0x2A); /* page code */
        assert_eq!(buf[5], 62); /* page length = 62 */
    }
    #[test]
    fn cdrom_mode_sense_10_all_pages() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x3F;
        cdb[8] = 200;
        let mut buf = [0u8; 200];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 8 + ALL_CDROM_PAGES_LEN); /* 8 header + pages */
        assert_eq!(buf[0], ((n - 2) >> 8) as u8);
        assert_eq!(buf[1], (n - 2) as u8); /* mode data length */
        // Walk pages by length fields and collect codes — order: 0x00,0x01,0x08,0x0D,0x0E,0x1A,0x1D,0x2A.
        let mut codes = Vec::new();
        let mut off = 8;
        while off + 2 <= n {
            let page_len = buf[off + 1] as usize;
            codes.push(buf[off] & 0x3F);
            off += page_len + 2;
        }
        assert_eq!(codes, vec![0x00, 0x01, 0x08, 0x0D, 0x0E, 0x1A, 0x1D, 0x2A]);
    }
    #[test]
    fn cdrom_mode_page_all_pages_contains_each_page() {
        let all = cdrom_mode_page(0x3F).expect("0x3F must return all pages");
        assert_eq!(all.len(), ALL_CDROM_PAGES_LEN);
        // Walk pages by their length fields and collect the page codes.
        let mut codes = Vec::new();
        let mut off = 0;
        while off < all.len() {
            let page_len = all[off + 1] as usize;
            codes.push(all[off] & 0x3F);
            off += page_len + 2;
        }
        assert_eq!(codes, vec![0x00, 0x01, 0x08, 0x0D, 0x0E, 0x1A, 0x1D, 0x2A]);
    }
    // ── GET CONFIGURATION common features ───────────────────────────
    #[test]
    fn cdrom_get_config_cd_profile() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &READ_ONLY_CDROM_CAPS,
            0x00,
            0x0000,
            64,
            0,
            true,
        );
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &w, &mut buf);
        assert!(n >= 8);
        // Current profile = CD-ROM (0x0008)
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x08);
    }
    #[test]
    fn cdrom_get_config_dvd_profile() {
        let mut w = work();
        let profile = CurrentProfile::DvdRom;
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &READ_ONLY_CDROM_CAPS,
            0x00,
            0x0000,
            64,
            0,
            true,
        );
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &w, &mut buf);
        assert!(n >= 8);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x10); /* DVD-ROM */
    }
    #[test]
    fn cdrom_get_config_features_present() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &READ_ONLY_CDROM_CAPS,
            0x00,
            0x0000,
            255,
            0,
            true,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &w, &mut buf);
        // Features now include Morphing (0x0002) between Core and Removable,
        // so offsets shifted by 8. Walk descriptors instead of fixed offsets.
        assert!(n >= 56);
        let mut off = 8;
        let mut found = [false; 4]; // 0:0000, 1:0001, 2:0002, 3:0003
        let mut removable_payload = 0;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            match code {
                0x0000 => {
                    assert_eq!(buf[off + 1], 0x00);
                    found[0] = true;
                }
                0x0001 => {
                    assert_eq!(buf[off + 1], 0x01);
                    found[1] = true;
                }
                0x0002 => {
                    assert_eq!(buf[off + 1], 0x02);
                    found[2] = true;
                }
                0x0003 => {
                    assert_eq!(buf[off + 1], 0x03);
                    found[3] = true;
                    removable_payload = buf[off + 4];
                }
                _ => {}
            }
            off += 4 + add_len;
        }
        assert!(found.iter().all(|&b| b));
        // Removable feature byte 4: Loading Mechanism Type (001b tray) << 5
        // | Load << 4 | Eject << 3 | Lock.
        assert_eq!(removable_payload, 0x39);
    }
    #[test]
    fn cdrom_get_config_udfrw_features_no_mrw() {
        let mut w = work();
        let profile = CurrentProfile::DvdRam;
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &UDFRW_CAPS,
            0x02,
            0x0000,
            255,
            0x2800,
            true,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &w, &mut buf);
        // DVD-RAM exposes Random Writable and Formattable, but not DVD+RW
        // or MRW.
        let mut off = 8;
        let mut saw_random = false;
        let mut saw_formattable = false;
        let mut saw_dvdrw = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            saw_random |= code == 0x0020;
            saw_formattable |= code == 0x0023;
            saw_dvdrw |= code == 0x002A;
            off += 4 + add_len;
        }
        assert!(saw_random && saw_formattable && !saw_dvdrw);
    }
    #[test]
    fn cdrom_get_config_udfrw_write_protect_clear() {
        let mut w = work();
        let profile = CurrentProfile::DvdRam;
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &UDFRW_CAPS,
            0x02,
            0x0000,
            255,
            0x2800,
            true,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &w, &mut buf);
        // Find the Write Protect (0x0004) feature descriptor.
        let mut off = 8;
        let mut found = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            if code == 0x0004 {
                found = true;
                // The device reports the status but does not claim that the
                // host can modify the WDCB.
                assert_eq!(buf[off + 4], 0x00, "WDCB is not host-writable");
                break;
            }
            off += 4 + add_len;
        }
        assert!(found, "Write Protect feature must be present for Windows");
    }
    #[test]
    fn cdrom_get_config_starting_feature_filters() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        // RT=10b, start 0x0010 → Random Readable + Multi-Read + CD Read
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &READ_ONLY_CDROM_CAPS,
            0x02,
            0x0010,
            255,
            0,
            true,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &w, &mut buf);
        // Header (8) + Random Readable (12) + Multi-Read (4) + CD Read (8) = 32
        assert!(n >= 32);
        // First feature should be Random Readable (0x0010) at header+0
        assert_eq!(buf[8], 0x00);
        assert_eq!(buf[9], 0x10);
    }
    #[test]
    fn cdrom_get_config_alloc_clamp() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        // Very small alloc — only header returned
        let outcome = build_get_config_response(
            &mut w,
            profile,
            &READ_ONLY_CDROM_CAPS,
            0x00,
            0x0000,
            8,
            0,
            true,
        );
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &w, &mut buf);
        assert_eq!(n, 8); // only header fits
        assert_eq!(buf[7], 0x08); // CD-ROM profile still set
    }
    // ── READ DISC INFORMATION ───────────────────────────────────────
    fn finalized_disc_info(lead_out_lba: u32) -> DiscInfo {
        DiscInfo {
            disc_status: 2,           // finalized
            state_of_last_session: 3, // complete
            erasable: false,
            sessions: 1,
            first_track: 1,
            last_track: 1,
            disc_type: 0x00, // CD-ROM (not XA)
            mrw_status: 0,
            lead_out_lba,
        }
    }
    #[test]
    fn disc_info_finalized_cd_rom_layout() {
        let mut w = work();
        let info = finalized_disc_info(0x10EA);
        let mut buf = [0u8; 52];
        let n = data_in(build_read_disc_info(&mut w, 52, &info), &w, &mut buf);
        assert_eq!(n, 52);
        // Disc Information Length (excludes itself).
        assert_eq!(&buf[0..2], &[0x00, 0x32]);
        // Byte 2: Erasable 0 | State of last Session 11b | Disc Status 10b
        // = 0b00001110 (MMC-6 Table 365: erasable<<4 | state<<2 | status).
        assert_eq!(buf[2], 0x0E);
        assert_eq!(buf[3], 1); // first track
        assert_eq!(buf[4], 1); // sessions LSB
        assert_eq!(buf[5], 1); // first track in last session
        assert_eq!(buf[6], 1); // last track in last session
        assert_eq!(buf[8], 0x00); // disc type: CD-ROM (not XA)
        assert_eq!(&buf[20..24], &0x10EAu32.to_be_bytes()); // lead-out
                                                            // All other fields (bar code, application code, OPC) are zero.
        assert!(buf[24..52].iter().all(|&b| b == 0));
    }
    #[test]
    fn disc_info_alloc_clamps_response() {
        let mut w = work();
        let info = finalized_disc_info(100);
        // Small alloc (sr probe reads 2 bytes first).
        let mut buf = [0u8; 2];
        let n = data_in(build_read_disc_info(&mut w, 2, &info), &w, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf, [0x00, 0x32]);
        // Zero alloc is not an error → empty data phase.
        let outcome = build_read_disc_info(&mut w, 0, &info);
        match outcome {
            CommandOutcome::OutInline { len } => assert_eq!(len, 0),
            other => panic!("expected DataIn, got {other:?}"),
        }
    }
    #[test]
    fn disc_info_cdrw_sets_erasable() {
        let mut w = work();
        let mut info = finalized_disc_info(0);
        info.erasable = true;
        info.disc_status = 1; // appendable
        info.state_of_last_session = 1; // incomplete
        let mut buf = [0u8; 52];
        let n = data_in(build_read_disc_info(&mut w, 52, &info), &w, &mut buf);
        assert_eq!(n, 52);
        // Byte 2: Erasable 1 | State of last Session 01b | Disc Status 01b
        // = 0b00010101.
        assert_eq!(buf[2], 0x15);
    }
    // ── Capabilities page (0x2A) ────────────────────────────────────
    #[test]
    fn capabilities_page_read_only_cd_rom_layout() {
        let p = build_capabilities_page(&READ_ONLY_CDROM_CAPS, &[]);
        assert_eq!(p.len(), 64);
        assert_eq!(p[0], 0x2A);
        assert_eq!(p[1], 30); // page length (32 - 2), tail zeroed
                              // Read-only, Mode-1 baseline only: no extra read/write bits.
        assert_eq!(p[2], 0x00);
        assert_eq!(p[3], 0x00);
        assert_eq!(p[4], 0x00);
        assert_eq!(p[5], 0x00);
        // Loading mechanism = tray (001b<<5) | lock@0 | eject@3 = 0x29
        assert_eq!(p[6], 0x29);
        assert_eq!(p[7], 0x00);
        // max_read/cur_read/max_write/cur_write are at 8-9/14-15/18-19/20-21
        assert_eq!(&p[8..10], &[0, 0]);
        assert_eq!(&p[12..14], &[0, 0]); // buffer
        assert_eq!(&p[14..16], &[0, 0]); // cur_read
        assert_eq!(&p[18..20], &[0, 0]); // max_write
                                         // Copy Management Revision (recorder) and descriptor count = 0.
        assert_eq!(&p[22..24], &[0x00, 0x01]);
        assert_eq!(&p[30..32], &[0x00, 0x00]);
    }
    #[test]
    fn capabilities_page_parameterized_by_model() {
        let mut caps = READ_ONLY_CDROM_CAPS;
        caps.write_cdr = true;
        caps.read_cdr = true;
        caps.cd_da = true;
        caps.eject = true;
        caps.buffer_size = 4096;
        caps.max_read_speed = 3528; // 20x
        let p = build_capabilities_page(&caps, &[]);
        assert_eq!(p[2] & 0x01, 0x01); // CD-R read @bit0
        assert_eq!(p[5] & 0x01, 0x01); // CD-DA
        assert_eq!(p[3] & 0x01, 0x01); // CD-R write @bit0
        assert_eq!(p[6] & 0x08, 0x08); // eject @bit3
        assert_eq!(&p[12..14], &[0x10, 0x00]); // buffer 4096 at 12-13
        assert_eq!(&p[8..10], &[0x0D, 0xC8]); // max read 3528 at 8-9
        assert_eq!(&p[14..16], &[0x0D, 0xC8]); // cur_read mirrored
    }
    // ── READ BUFFER CAPACITY ────────────────────────────────────────
    #[test]
    fn read_buffer_capacity_structure() {
        let mut w = work();
        let mut buf = [0u8; 12];
        let n = data_in(
            build_read_buffer_capacity(&mut w, 12, 4096, 2048),
            &w,
            &mut buf,
        );
        assert_eq!(n, 12);
        assert_eq!(&buf[0..2], &[0x00, 0x0A]); // Data Length = 10
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x10, 0x00]); // buffer 4096
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x08, 0x00]); // blank 2048
                                                            // Allocation clamp and zero-alloc (not an error).
        let mut small = [0u8; 2];
        let n = data_in(build_read_buffer_capacity(&mut w, 2, 0, 0), &w, &mut small);
        assert_eq!(n, 2);
        assert_eq!(&small, &[0x00, 0x0A]);
    }
    // ── Profile selection ───────────────────────────────────────────
    #[test]
    fn current_profile_from_capacity() {
        assert_eq!(CurrentProfile::from_capacity(0), CurrentProfile::CdRom);
        assert_eq!(
            CurrentProfile::from_capacity(700 * 1024 * 1024),
            CurrentProfile::CdRom
        );
        assert_eq!(
            CurrentProfile::from_capacity(700 * 1024 * 1024 + 1),
            CurrentProfile::DvdRom
        );
    }
    #[test]
    fn current_profile_codes() {
        assert_eq!(CurrentProfile::CdRom.code(), 0x0008);
        assert_eq!(CurrentProfile::DvdRom.code(), 0x0010);
        assert_eq!(CurrentProfile::CdR.code(), 0x0009);
        assert_eq!(CurrentProfile::CdRw.code(), 0x000A);
        assert_eq!(CurrentProfile::DvdRam.code(), 0x0012);
        assert_eq!(CurrentProfile::DvdRw.code(), 0x001A);
    }
    #[test]
    fn get_config_dvd_ram_features() {
        let mut w = work();
        let outcome = build_get_config_response(
            &mut w,
            CurrentProfile::DvdRam,
            &UDFRW_CAPS,
            0x00,
            0x0000,
            255,
            0x1234,
            true,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &w, &mut buf);
        assert!(n >= 8 + 12 + 8 + 12 + 4 + 8 + 4 + 16 + 8);
        assert_eq!(buf[7], 0x12); // current profile DVD-RAM
                                  // Walk the feature list and check codes + key fields.
        let mut off = 8usize;
        let mut saw_rw = false;
        let mut saw_dvdram = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            match code {
                0x0020 => {
                    saw_rw = true;
                    assert_eq!(buf[off + 2], 0x07); // version 1, persistent+current
                    assert_eq!(add_len, 12);
                    assert_eq!(&buf[off + 4..off + 8], &0x1234u32.to_be_bytes());
                    assert_eq!(&buf[off + 8..off + 12], &2048u32.to_be_bytes());
                    assert_eq!(&buf[off + 12..off + 14], &1u16.to_be_bytes());
                }
                0x0012 => {
                    saw_dvdram = true;
                    assert_eq!(add_len, 0);
                }
                0x001F => {
                    // DVD Read present for the DVD-RAM profile.
                    assert_eq!(add_len, 0);
                }
                _ => {}
            }
            off += 4 + add_len;
        }
        assert!(saw_rw, "Random Writable feature must be present");
        assert!(saw_dvdram, "DVD-RAM feature must be present");
    }
    #[test]
    fn dvd_ram_mandatory_features_table212() {
        // MMC-6 Table 212 mandatory for DVD-RAM: 0000,0001,0002,0003,0010,001F,0020,0023,0024,0100,0105,0107
        let media = MediaState {
            profile: CurrentProfile::DvdRam,
            present: true,
            ready: true,
            formatted: true,
            formattable: true,
            erasable: true,
            write_protected: false,
            random_writable: true,
            defect_management: true,
            max_lba: 0x1234,
            block_size: SECTOR_SIZE,
        };
        let mut tmp = [0u8; 512];
        // Also test via build_get_config_response_for_media path
        let outcome =
            build_get_config_response_for_media(&mut tmp, &UDFRW_CAPS, &media, 0x00, 0x0000, 512);
        let mut check = [0u8; 512];
        let n = data_in(outcome, &tmp, &mut check);
        assert!(n > 0);
        // Walk and collect codes and header checks
        let mut codes = Vec::new();
        let mut off = 8;
        let mut saw_0024_ver = None;
        let mut saw_0024_len = None;
        let mut saw_0024_ssa = None;
        let mut saw_0002 = false;
        let mut saw_0100 = false;
        let mut saw_0105 = false;
        let mut saw_0107 = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([check[off], check[off + 1]]);
            let ver_pers_cur = check[off + 2];
            let add_len = check[off + 3] as usize;
            codes.push(code);
            match code {
                0x0002 => {
                    saw_0002 = true;
                    assert_eq!(ver_pers_cur, 0x07, "Morphing Version 0001b + P+C");
                    assert_eq!(add_len, 0x04);
                    assert_eq!(check[off + 4], 0x02, "OCEvent=1");
                }
                0x0024 => {
                    saw_0024_ver = Some(ver_pers_cur);
                    saw_0024_len = Some(add_len);
                    saw_0024_ssa = Some(check[off + 4]);
                    assert_eq!(add_len, 0x04);
                    // Version 0001b (0x04) + Persistent 1 (0x02) + Current 1 =0x07
                    assert_eq!(ver_pers_cur, 0x07, "0024 ver 0001b + P + Current");
                    assert_eq!(check[off + 4] & 0x80, 0x00, "SSA=0");
                }
                0x0100 => {
                    saw_0100 = true;
                    assert_eq!(ver_pers_cur, 0x03);
                    assert_eq!(add_len, 0x00);
                }
                0x0105 => {
                    saw_0105 = true;
                    assert_eq!(ver_pers_cur, 0x07);
                    assert_eq!(add_len, 0x04);
                }
                0x0107 => {
                    saw_0107 = true;
                    assert_eq!(ver_pers_cur, 0x17);
                    assert_eq!(add_len, 0x04);
                }
                0x0008 => panic!("old defect code 0x0008 must not be emitted, should be 0x0024"),
                _ => {}
            }
            off += 4 + add_len;
        }
        // Check mandatory presence
        for &need in &[
            0x0000u16, 0x0001, 0x0002, 0x0003, 0x0010, 0x001F, 0x0020, 0x0023, 0x0024, 0x0100,
            0x0105, 0x0107,
        ] {
            assert!(
                codes.contains(&need),
                "mandatory DVD-RAM feature {:04X} missing",
                need
            );
        }
        assert!(saw_0002, "Morphing 0002 missing");
        assert!(saw_0100, "Power Management 0100 missing");
        assert!(saw_0105, "Timeout 0105 missing");
        assert!(saw_0107, "Real-Time Streaming 0107 missing");
        assert_eq!(saw_0024_ver, Some(0x07));
        assert_eq!(saw_0024_len, Some(0x04));
        assert_eq!(saw_0024_ssa, Some(0x00));
        // Defect management must be Current when media defect_management true
        assert!(codes.contains(&0x0024));
        // Also verify not-current case: defect_management false -> Current 0 -> byte2 0x06
        let media_off = MediaState {
            defect_management: false,
            ..media
        };
        let mut tmp2 = [0u8; 512];
        let out2 = build_get_config_response_for_media(
            &mut tmp2,
            &UDFRW_CAPS,
            &media_off,
            0x00,
            0x0000,
            512,
        );
        let mut buf2 = [0u8; 512];
        let n2 = data_in(out2, &tmp2, &mut buf2);
        let mut off2 = 8;
        let mut ver_off = None;
        while off2 + 4 <= n2 {
            let code = u16::from_be_bytes([buf2[off2], buf2[off2 + 1]]);
            let add_len = buf2[off2 + 3] as usize;
            if code == 0x0024 {
                ver_off = Some(buf2[off2 + 2]);
                break;
            }
            off2 += 4 + add_len;
        }
        assert_eq!(
            ver_off,
            Some(0x06),
            "defect_management false -> Current 0 => 0x06"
        );
    }
}
