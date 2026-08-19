//! CD-ROM common device layer (plan §3.2 / §8.2).
//!
//! [`CdromDeviceCommon`] holds the shared SPC-level state (sense, prevent,
//! profile) and implements [`SpcDevice`] so that all three CD-ROM device
//! types (`CdromDevice`, `CdBundleDevice`, `CdLiveFsDevice`) delegate
//! INQUIRY / MODE SENSE / REQUEST SENSE / GET CONFIGURATION common
//! features to a single code path via field embedding (composition).
//!
//! Per plan §5.3, only the *synthesis* of MMC responses is shared here:
//! [`build_get_config_response`] and [`build_read_disc_info`] lay out the
//! bytes for the MMC field structure, taking the device's state as
//! parameters.  The per-device command dispatch (which state it feeds,
//! whether a command is supported) stays in each device's own
//! `execute_mmc_*` — device state never enters this module.

use crate::scsi::device::{CommandOutcome, DeviceType};
use crate::scsi::scsi::Sense;
use crate::scsi::spc::{DeviceIdentity, SpcDevice, SpcEffect};

/// CD-ROM logical block size (Mode 1: 2048 data bytes per sector).
pub const SECTOR_SIZE: u32 = 2048;

/// INQUIRY identity for CD-ROM devices (plan §8.2): SCSI family, with
/// SPC-4 and MMC-6 version descriptors.
pub const CDROM_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"Virtual CD-ROM  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x05C0], /* SAM-5, iSCSI, SPC-4, MMC-6 */
};

/// Current Profile code for GET CONFIGURATION (MMC-6 §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentProfile {
    /// 0x0008 — CD-ROM (images ≤ 700 MiB).
    CdRom,
    /// 0x0010 — DVD-ROM (images > 700 MiB).
    DvdRom,
    /// 0x0009 — CD-R (Phase 3, writable bundle).
    CdR,
    /// 0x000A — CD-RW (Phase 4).
    CdRw,
    /// 0x001A — DVD+RW (UdfRw random-writable media, plan commit 3).
    DvdRw,
}

impl CurrentProfile {
    /// Numeric profile code (MMC-6 Table 64).
    pub fn code(self) -> u16 {
        match self {
            Self::CdRom => 0x0008,
            Self::DvdRom => 0x0010,
            Self::CdR => 0x0009,
            Self::CdRw => 0x000A,
            Self::DvdRw => 0x001A,
        }
    }

    /// Pick the profile from a capacity in bytes (plan §8.2 table).
    pub fn from_capacity(capacity: u64) -> Self {
        if capacity <= 700 * 1024 * 1024 {
            Self::CdRom
        } else {
            Self::DvdRom
        }
    }
}

/// CD-ROM common state shared by all three CD device types (plan §3.2).
///
/// Each concrete device embeds this struct as a field (composition) and
/// delegates SPC commands to `execute_spc(&mut self.common, ...)`.
pub struct CdromDeviceCommon {
    pub sense: Sense,
    pub prevent_removal: bool,
    pub sector_size: u32,
    pub profile: CurrentProfile,
}

impl CdromDeviceCommon {
    pub fn new(profile: CurrentProfile) -> Self {
        Self {
            sense: Sense::clear(),
            prevent_removal: false,
            sector_size: SECTOR_SIZE,
            profile,
        }
    }
}

impl SpcDevice for CdromDeviceCommon {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &CDROM_IDENTITY
    }

    fn id(&self) -> u64 {
        // Concrete devices override this via a wrapper; the common struct
        // alone returns 0.  Identity synthesis in execute_spc uses dev.id().
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
        // CD-ROM: START STOP UNIT accepted and ignored (plan §8.2).
        SpcEffect::Good
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }
}

// ── CD-ROM MODE SENSE pages ─────────────────────────────────────────

/// Caching page (0x08, SPC-4 §7.4.7): WCE=0, RCD=0, DRA=1.
const CACHING_PAGE: [u8; 20] = [
    0x88, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0,
];

/// Vendor-specific page (0x00).
const VENDOR_PAGE: [u8; 4] = [0x00, 2, 0x00, 0x08];

/// CD-ROM Parameters page (0x0D, MMC-6 §6.12.2): page_length=2,
/// sector_size=2048 (big-endian u16).
const CDROM_PARAMS: [u8; 4] = [0x0D, 0x02, 0x08, 0x00];

/// CD-ROM Audio Control page (0x0E, MMC-6 §6.12.3): page_length=14,
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

/// Device-declared capability set — the single model every
/// capability-reporting channel (GET CONFIGURATION features, MODE SENSE
/// 0x2A page) is built from (plan §5.3). Devices feed their capabilities;
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
    /// Defect Management feature (0x0008): indicates the drive performs
    /// hardware-level defect management. Windows' `IOCTL_DISK_IS_WRITABLE`
    /// requires this feature to be Current alongside FeatureRandomWritable
    /// in order to report the media as writable. Real DVD+RW drives do NOT
    /// have this feature (it belongs to DVD-RAM), but the Windows cdrom
    /// class driver gates all optical formatting on it.
    pub defect_management: bool,
    /// Write-side extras (Phase 3+ CD-R/CD-RW).
    pub write_cdr: bool,
    pub write_cdrw: bool,
    pub test_write: bool,
    pub burn_proof: bool,
    pub num_volume_levels: u8,
    pub buffer_size: u16,
    pub max_read_speed: u16,  // KB/s
    pub max_write_speed: u16, // KB/s
}

impl CdromCapabilities {
    /// A read-only CD-ROM drive: Mode-1 data read is the implicit baseline,
    /// tray mechanism, no write / audio / multi-session extras.
    pub const fn read_only_cd_rom() -> Self {
        Self {
            tray: true,
            load: false,
            eject: false,
            lock: false,
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
            num_volume_levels: 0,
            buffer_size: 0,
            max_read_speed: 0,
            max_write_speed: 0,
        }
    }
}

/// The capabilities of the read-only CD-ROM devices (flat / livefs).
pub const READ_ONLY_CDROM_CAPS: CdromCapabilities = CdromCapabilities::read_only_cd_rom();

/// Capabilities of the UdfRw device: reads DVD media and presents a
/// formatted, random-writable DVD+RW (features 0x0020 + 0x002A).
/// FeatureDefectManagement (0x0008) is also reported — while not standard
/// for DVD+RW (it belongs to DVD-RAM), Windows' `IOCTL_DISK_IS_WRITABLE`
/// requires it to be Current alongside FeatureRandomWritable in order to
/// report the media as writable and allow `format.exe` to proceed.
pub const UDFRW_CAPS: CdromCapabilities = CdromCapabilities {
    read_dvd_rom: true,
    read_cdr: true,
    read_cdrw: true,
    mode2_form1: true,
    multi_session: true,
    random_writable: true,
    dvd_plus_rw: true,
    write_protect: true,
    defect_management: true,
    write_cdr: true,
    write_cdrw: true,
    test_write: true,
    burn_proof: true,
    num_volume_levels: 0,
    buffer_size: 0,
    max_read_speed: 0x2B48,  // 11080 KB/s ≈ 32x CD
    max_write_speed: 0x2B48,
    ..CdromCapabilities::read_only_cd_rom()
};

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
/// Returns a 56-byte page: 24-byte base + 32 bytes of CD write speed
/// performance descriptors (16 KB/s granularity per MMC-6 Table 105).
pub const fn build_capabilities_page(caps: &CdromCapabilities) -> [u8; 56] {
    let mut p = [0u8; 56];
    p[0] = 0x2A;
    p[1] = 54; // page length (56 - 2)
    p[2] = (bit(caps.read_cdrw) << 7)
        | (bit(caps.read_cdr) << 6)
        | (bit(caps.mode2_form2) << 5)
        | (bit(caps.mode2_form1) << 4)
        | (bit(caps.multi_session) << 3)
        | (bit(caps.cd_da) << 2);
    p[3] = bit(caps.read_dvd_rom) << 3;
    p[4] = (bit(caps.write_cdrw) << 7)
        | (bit(caps.write_cdr) << 6)
        | (bit(caps.test_write) << 5)
        | (bit(caps.burn_proof) << 4);
    // Byte 8: Loading Mechanism Type (bits 2-0) | Load | Eject.
    p[8] = loading_type_bits(caps.tray) | (bit(caps.load) << 3) | (bit(caps.eject) << 4);
    p[9] = caps.num_volume_levels;
    p[10] = (caps.buffer_size >> 8) as u8;
    p[11] = caps.buffer_size as u8;
    p[14] = (caps.max_read_speed >> 8) as u8;
    p[15] = caps.max_read_speed as u8;
    p[18] = (caps.max_write_speed >> 8) as u8;
    p[19] = caps.max_write_speed as u8;
    // CD write speed performance descriptors (bytes 22-55, MMC-6 Table 105).
    // Each descriptor: 2-byte read speed (KB/s ÷ 16) + 2-byte write speed.
    // Standard CD-RW speeds: 2x(352), 4x(704), 8x(1408), 16x(2816), 32x(5632).
    // Descriptor 1: 2x
    p[22] = (352 / 16) as u8;
    p[23] = 0;
    p[24] = (352 / 16) as u8;
    p[25] = 0;
    // Descriptor 2: 4x
    p[26] = (704 / 16) as u8;
    p[27] = 0;
    p[28] = (704 / 16) as u8;
    p[29] = 0;
    // Descriptor 3: 8x
    p[30] = (1408 / 16) as u8;
    p[31] = 0;
    p[32] = (1408 / 16) as u8;
    p[33] = 0;
    // Descriptor 4: 16x
    p[34] = (2816 / 16) as u8;
    p[35] = 0;
    p[36] = (2816 / 16) as u8;
    p[37] = 0;
    // Descriptor 5: 32x (max)
    p[38] = (5632 / 16) as u8;
    p[39] = 0;
    p[40] = (5632 / 16) as u8;
    p[41] = 0;
    p
}

/// CD/DVD Capabilities & Mechanical Status page (0x2A) for the read-only
/// devices, built from the capability model rather than hardcoded bytes.
const CDROM_CAPABILITIES: [u8; 56] = build_capabilities_page(&READ_ONLY_CDROM_CAPS);

/// MODE SENSE page 0x2A for the UdfRw device, built from the capability
/// model. Includes the base 24-byte page plus CD write speed descriptors.
const UDFRW_CAPABILITIES: [u8; 56] = build_capabilities_page(&UDFRW_CAPS);

/// Total byte count of all UdfRw mode pages (for 0x3F sizing).
pub(crate) const ALL_UDFRW_PAGES_LEN: usize = CACHING_PAGE.len()
    + VENDOR_PAGE.len()
    + CDROM_PARAMS.len()
    + CDROM_AUDIO.len()
    + UDFRW_CAPABILITIES.len();

/// All UdfRw mode pages, in MODE SENSE page order (for `0x3F`).
const ALL_UDFRW_PAGES: [u8; ALL_UDFRW_PAGES_LEN] = concat_pages(&[
    &VENDOR_PAGE,
    &CACHING_PAGE,
    &CDROM_PARAMS,
    &CDROM_AUDIO,
    &UDFRW_CAPABILITIES,
]);

/// MODE SENSE page data for the UdfRw device (`0x3F` = all pages): the
/// writable 0x2A page replaces the read-only one; everything else matches
/// [`cdrom_mode_page`].
pub(crate) fn udfrw_mode_page(page: u8) -> Option<&'static [u8]> {
    match page {
        0x2A => Some(&UDFRW_CAPABILITIES),
        0x3F => Some(&ALL_UDFRW_PAGES),
        _ => cdrom_mode_page(page),
    }
}

/// Return the MODE SENSE page data for `page` (`0x3F` = all pages).
pub(crate) fn cdrom_mode_page(page: u8) -> Option<&'static [u8]> {
    match page {
        0x08 => Some(&CACHING_PAGE),
        0x00 => Some(&VENDOR_PAGE),
        0x0D => Some(&CDROM_PARAMS),
        0x0E => Some(&CDROM_AUDIO),
        0x2A => Some(&CDROM_CAPABILITIES),
        0x3F => Some(&ALL_CDROM_PAGES),
        _ => None,
    }
}

/// Total byte count of all CD-ROM mode pages (for 0x3F sizing).
pub(crate) const ALL_CDROM_PAGES_LEN: usize = CACHING_PAGE.len()
    + VENDOR_PAGE.len()
    + CDROM_PARAMS.len()
    + CDROM_AUDIO.len()
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
    &CACHING_PAGE,
    &CDROM_PARAMS,
    &CDROM_AUDIO,
    &CDROM_CAPABILITIES,
]);

// ── GET CONFIGURATION common features builder ───────────────────────

/// Build GET CONFIGURATION feature descriptors common to all CD-ROM
/// devices (plan §8.2).  Writes into `buf[off..]` and returns the new
/// offset.  `profile` is the current profile; `last_lba` feeds the Random
/// Writable feature (ignored unless `caps.random_writable`).
///
/// Features included (all current):
/// - 0x0001 Core (version 2, persistent, additional length 8)
/// - 0x0003 Removable Medium (tray type)
/// - 0x0004 Write Protect (only if `caps.write_protect`)
/// - 0x0010 Random Readable (block size 2048)
/// - 0x001D Multi-Read
/// - 0x001E CD Read (version 2)
/// - 0x001F DVD Read (only for DVD profiles)
/// - 0x0020 Random Writable (only if `caps.random_writable`)
/// - 0x0023 Formattable (for DVD+RW media)
/// - 0x002A DVD+RW (only if `caps.dvd_plus_rw`)
/// - 0x010A Disc Control Block (for DVD+RW media)
pub fn build_get_config_features(
    buf: &mut [u8],
    mut off: usize,
    profile: CurrentProfile,
    caps: &CdromCapabilities,
    _rt: u8,
    start_feature: u16,
    last_lba: u32,
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
    // per MMC-6 §6.6. It identifies the profiles supported by the drive;
    // the mounted profile is marked current.
    if matches!(profile, CurrentProfile::DvdRw) {
        const PROFILES: [u16; 14] = [
            0x0012, 0x002B, 0x001B, 0x001A, 0x0016, 0x0015, 0x0014, 0x0013, 0x0011, 0x0010, 0x000A,
            0x0009, 0x0008, 0x0002,
        ];
        buf[off] = 0x00;
        buf[off + 1] = 0x00;
        buf[off + 2] = 0x03; // persistent + current
        buf[off + 3] = 56;
        for (i, code) in PROFILES.iter().enumerate() {
            let p = off + 4 + i * 4;
            buf[p..p + 2].copy_from_slice(&code.to_be_bytes());
            if *code == profile.code() {
                buf[p + 2] = 0x01;
            }
        }
        off += 60;
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

    // Random Readable (0x0010)
    if include(0x0010) {
        buf[off] = 0x00;
        buf[off + 1] = 0x10;
        buf[off + 2] = 0x01; // current
        buf[off + 3] = 0x08; // additional length
        buf[off + 4..off + 8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        buf[off + 8] = 0x00;
        buf[off + 9] = 0x01; // blocking = 1
        off += 12;
    }

    // Multi-Read (0x001D)
    if include(0x001D) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1D;
        buf[off + 2] = 0x01; // current
        off += 4;
    }

    // CD Read (0x001E)
    if include(0x001E) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1E;
        buf[off + 2] = 0x03; // version 2 + current
        buf[off + 3] = 0x04; // additional length
        off += 8;
    }

    // DVD Read (0x001F) — only for DVD profiles
    if matches!(profile, CurrentProfile::DvdRom | CurrentProfile::DvdRw) && include(0x001F) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1F;
        buf[off + 2] = 0x01; // current
        off += 4;
    }

    // Random Writable (0x0020) — formatted random-writable media (UdfRw).
    if caps.random_writable && include(0x0020) {
        buf[off] = 0x00;
        buf[off + 1] = 0x20;
        buf[off + 2] = 0x05; // version 1 + current (sg3_utils convention)
        buf[off + 3] = 0x0C; // additional length
        buf[off + 4..off + 8].copy_from_slice(&last_lba.to_be_bytes());
        buf[off + 8..off + 12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        buf[off + 12..off + 14].copy_from_slice(&1u16.to_be_bytes()); // blocking
        buf[off + 14] = 0x00; // PP: no error recovery page
        buf[off + 15] = 0x00;
        off += 16;
    }

    // Formattable (0x0023). DVD+RW drives that report the DVD+RW feature as
    // current also advertise the basic background-format capability.
    if caps.dvd_plus_rw && include(0x0023) {
        buf[off] = 0x00;
        buf[off + 1] = 0x23;
        buf[off + 2] = 0x09; // version 2 + current
        buf[off + 3] = 0x08;
        buf[off + 4..off + 12].fill(0);
        off += 12;
    }

    // Defect Management (0x0008) — required by Windows' `IOCTL_DISK_IS_WRITABLE`
    // to report optical media as writable. Real DVD+RW drives do NOT have this
    // feature (it belongs to DVD-RAM), but the Windows cdrom class driver gates
    // all optical formatting on `ValidationSchema == FeatureDefectManagement`.
    // No additional data beyond the feature header.
    if caps.defect_management && include(0x0008) {
        buf[off] = 0x00;
        buf[off + 1] = 0x08;
        buf[off + 2] = 0x03; // version 0 + current + persistent
        buf[off + 3] = 0x00; // additional length
        off += 4;
    }

    // MRW (Mount Rainier, 0x0028) is deliberately NOT reported: it is a
    // sequential packet-write format with drive-side remapping that this
    // byte-plane emulation does not implement, and Windows treats an
    // MRW-formatted disc as read-only. A DVD+RW with plain UDF needs no MRW
    // claim — the kernel's cdrom_open_write() allows a writable open for
    // profile 0x1A via cdrom_is_dvd_rw()/cdrom_dvdram_open_write().

    // DVD+RW (0x002A) — write capable (UdfRw).
    if caps.dvd_plus_rw && include(0x002A) {
        buf[off] = 0x00;
        buf[off + 1] = 0x2A;
        buf[off + 2] = 0x05; // version 1 + current
        buf[off + 3] = 0x04; // additional length
        buf[off + 4] = 0x01; // Write
        buf[off + 5] = 0x00; // Quick Start / Close Only clear
        buf[off + 6] = 0x00;
        buf[off + 7] = 0x00;
        off += 8;
    }

    // Disc Control Block (0x010A). The WDCB itself is readable through
    // READ DISC STRUCTURE format 30h; advertise the standard FDC/SDC/TOC
    // descriptors used by DVD+RW drives.
    if caps.dvd_plus_rw && include(0x010A) {
        buf[off] = 0x01;
        buf[off + 1] = 0x0A;
        buf[off + 2] = 0x01; // current
        buf[off + 3] = 0x0C;
        buf[off + 4..off + 16].copy_from_slice(b"FDC\0SDC\0TOC\0");
        off += 16;
    }

    off
}

/// Build a GET CONFIGURATION response into `data[0..]`.
pub fn build_get_config_response<'a>(
    data: &'a mut [u8],
    profile: CurrentProfile,
    caps: &CdromCapabilities,
    rt: u8,
    start_feature: u16,
    alloc: u16,
    last_lba: u32,
) -> CommandOutcome<'a> {
    // Header (8) + all features: Core(12) Removable(8) WriteProtect(8)
    // RandomReadable(12) MultiRead(4) CDRead(8) DVDRead(4) RandomWritable(16)
    // MRW(8) DVD+RW(8).
    let mut buf = [0u8; 512];
    // Header: bytes 0-3 = data length (placeholder), 6-7 = current profile.
    buf[6] = (profile.code() >> 8) as u8;
    buf[7] = profile.code() as u8;

    let off = build_get_config_features(&mut buf, 8, profile, caps, rt, start_feature, last_lba);

    // Data length = bytes following the 4-byte data-length field itself.
    let data_len = (off - 4) as u32;
    buf[0..4].copy_from_slice(&data_len.to_be_bytes());

    let n = off.min(alloc as usize);
    data[0..n].copy_from_slice(&buf[..n]);
    CommandOutcome::DataIn {
        transfer_len: n as u64,
        byte_offset: 0,
        immediate: &data[0..n],
    }
}

/// Build the READ BUFFER CAPACITY response (MMC-6 §6.17.3.1, Table 342):
/// 12-byte structure with Data Length = 10. `buffer_len` / `blank_len` are
/// the whole / unused buffer bytes (0 for a drive without a write buffer).
pub fn build_read_buffer_capacity<'a>(
    data: &'a mut [u8],
    alloc: u16,
    buffer_len: u32,
    blank_len: u32,
) -> CommandOutcome<'a> {
    let mut buf = [0u8; 12];
    buf[1] = 0x0A; // Data Length = 10 (excludes itself), big-endian
    buf[4..8].copy_from_slice(&buffer_len.to_be_bytes());
    buf[8..12].copy_from_slice(&blank_len.to_be_bytes());
    let n = buf.len().min(alloc as usize);
    data[..n].copy_from_slice(&buf[..n]);
    CommandOutcome::DataIn {
        transfer_len: n as u64,
        byte_offset: 0,
        immediate: &data[0..n],
    }
}

/// Disc state parameters for the Standard Disc Information response
/// (MMC-6 §6.21.3.1). Each device feeds its own state — this struct only
/// transports values, it never reads device state (plan §5.3).
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

/// Build the Standard Disc Information response (MMC-6 §6.21.3.1) into
/// `data`, bounded by `alloc`. Returns a Data-In outcome carrying the
/// synthesized bytes (`immediate`). An `alloc` of zero is not an error and
/// yields an empty data phase (MMC-6 §6.21.2.2).
pub fn build_read_disc_info<'a>(
    data: &'a mut [u8],
    alloc: u16,
    info: &DiscInfo,
) -> CommandOutcome<'a> {
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
    // MMC-6 §6.21.3.1.12 — zero marks the disc "restricted use", which
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
    CommandOutcome::DataIn {
        transfer_len: n as u64,
        byte_offset: 0,
        immediate: &data[0..n],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::device::CommandOutcome;
    use crate::scsi::scsi::op;
    use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity};

    /// Minimal CD-ROM test device wrapping CdromDeviceCommon.
    struct CdTestDev {
        common: CdromDeviceCommon,
        capacity: u64,
    }

    impl CdTestDev {
        fn new(capacity: u64) -> Self {
            let profile = CurrentProfile::from_capacity(capacity);
            Self {
                common: CdromDeviceCommon::new(profile),
                capacity,
            }
        }
    }

    /// Wrapper implementing SpcDevice that delegates to common but
    /// overrides `id()` with the device capacity.
    struct CdDev<'a>(&'a mut CdTestDev);

    impl SpcDevice for CdDev<'_> {
        fn device_type(&self) -> DeviceType {
            DeviceType::Cdrom
        }
        fn identity(&self) -> &DeviceIdentity {
            &CDROM_IDENTITY
        }
        fn id(&self) -> u64 {
            self.0.capacity
        }
        fn mode_page(&self, page: u8) -> Option<&[u8]> {
            cdrom_mode_page(page)
        }
        fn sense(&self) -> &Sense {
            &self.0.common.sense
        }
        fn sense_mut(&mut self) -> &mut Sense {
            &mut self.0.common.sense
        }
        fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
            self.0.common.start_stop(loej, load)
        }
        fn set_prevent(&mut self, prevent: bool) {
            self.0.common.set_prevent(prevent);
        }
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

    fn run<'a>(dev: &mut CdDev<'_>, cdb: &[u8], work: &'a mut [u8]) -> CommandOutcome<'a> {
        execute_spc(dev, parse_spc(cdb).unwrap(), work, 0)
    }

    fn run_data(dev: &mut CdDev<'_>, cdb: &[u8], buf: &mut [u8]) -> usize {
        let mut w = work();
        data_in(run(dev, cdb, &mut w), buf)
    }

    // ── INQUIRY ─────────────────────────────────────────────────────

    // ── MODE SENSE ──────────────────────────────────────────────────

    #[test]
    fn cdrom_mode_sense_6_cd_params_page() {
        let mut td = CdTestDev::new(1024 * 1024);
        let mut dev = CdDev(&mut td);
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
        let mut td = CdTestDev::new(1024 * 1024);
        let mut dev = CdDev(&mut td);
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
        let mut td = CdTestDev::new(1024 * 1024);
        let mut dev = CdDev(&mut td);
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x2A;
        cdb[4] = 64;
        let mut buf = [0u8; 64];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 60); /* 4 header + 56 page */
        assert_eq!(buf[4], 0x2A); /* page code */
        assert_eq!(buf[5], 54); /* page length = 54 */
    }

    #[test]
    fn cdrom_mode_sense_10_all_pages() {
        let mut td = CdTestDev::new(1024 * 1024);
        let mut dev = CdDev(&mut td);
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x3F;
        cdb[8] = 200;
        let mut buf = [0u8; 200];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 8 + ALL_CDROM_PAGES_LEN); /* 8 header + pages */
        assert_eq!(buf[0], ((n - 2) >> 8) as u8);
        assert_eq!(buf[1], (n - 2) as u8); /* mode data length */
        // Page codes in order: 0x00, 0x08 (caching), 0x0D, 0x0E, 0x2A.
        assert_eq!(buf[8] & 0x3F, 0x00);
        assert_eq!(buf[12] & 0x3F, 0x08);
        assert_eq!(buf[32] & 0x3F, 0x0D);
        assert_eq!(buf[36] & 0x3F, 0x0E);
        assert_eq!(buf[52] & 0x3F, 0x2A);
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
        assert_eq!(codes, vec![0x00, 0x08, 0x0D, 0x0E, 0x2A]);
    }

    // ── GET CONFIGURATION common features ───────────────────────────

    #[test]
    fn cdrom_get_config_cd_profile() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        let outcome =
            build_get_config_response(&mut w, profile, &READ_ONLY_CDROM_CAPS, 0x00, 0x0000, 64, 0);
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &mut buf);
        assert!(n >= 8);
        // Current profile = CD-ROM (0x0008)
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x08);
    }

    #[test]
    fn cdrom_get_config_dvd_profile() {
        let mut w = work();
        let profile = CurrentProfile::DvdRom;
        let outcome =
            build_get_config_response(&mut w, profile, &READ_ONLY_CDROM_CAPS, 0x00, 0x0000, 64, 0);
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &mut buf);
        assert!(n >= 8);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x10); /* DVD-ROM */
    }

    #[test]
    fn cdrom_get_config_features_present() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        let outcome =
            build_get_config_response(&mut w, profile, &READ_ONLY_CDROM_CAPS, 0x00, 0x0000, 255, 0);
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
        // Core (0x0001) at 8, Removable (0x0003, 8 bytes) at 20, Random
        // Readable (0x0010) at 28, Multi-Read (0x001D), CD Read (0x001E).
        assert!(n >= 48);
        assert_eq!(buf[8], 0x00);
        assert_eq!(buf[9], 0x01);
        assert_eq!(buf[20], 0x00);
        assert_eq!(buf[21], 0x03);
        // Removable feature byte 4: Loading Mechanism Type (001b tray) << 5.
        assert_eq!(buf[24], 0x20);
        assert_eq!(buf[28], 0x00);
        assert_eq!(buf[29], 0x10);
    }

    #[test]
    fn cdrom_get_config_udfrw_features_no_mrw() {
        let mut w = work();
        let profile = CurrentProfile::DvdRw;
        let outcome =
            build_get_config_response(&mut w, profile, &UDFRW_CAPS, 0x02, 0x0020, 255, 0x2800);
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
        // RT=10b, start 0x0020: Random Writable, Formattable and DVD+RW;
        // there is still no MRW (0x0028) feature.
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
        assert!(saw_random && saw_formattable && saw_dvdrw);
    }

    #[test]
    fn cdrom_get_config_udfrw_write_protect_clear() {
        let mut w = work();
        let profile = CurrentProfile::DvdRw;
        let outcome =
            build_get_config_response(&mut w, profile, &UDFRW_CAPS, 0x02, 0x0000, 255, 0x2800);
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
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
        let outcome =
            build_get_config_response(&mut w, profile, &READ_ONLY_CDROM_CAPS, 0x02, 0x0010, 255, 0);
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
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
        let outcome =
            build_get_config_response(&mut w, profile, &READ_ONLY_CDROM_CAPS, 0x00, 0x0000, 8, 0);
        let mut buf = [0u8; 64];
        let n = data_in(outcome, &mut buf);
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
            disc_type: 0x20, // CD-ROM XA
            mrw_status: 0,
            lead_out_lba,
        }
    }

    #[test]
    fn disc_info_finalized_cd_rom_layout() {
        let mut w = work();
        let info = finalized_disc_info(0x10EA);
        let mut buf = [0u8; 52];
        let n = data_in(build_read_disc_info(&mut w, 52, &info), &mut buf);
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
        assert_eq!(buf[8], 0x20); // disc type: CD-ROM XA
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
        let n = data_in(build_read_disc_info(&mut w, 2, &info), &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf, [0x00, 0x32]);
        // Zero alloc is not an error → empty data phase.
        let outcome = build_read_disc_info(&mut w, 0, &info);
        match outcome {
            CommandOutcome::DataIn { transfer_len, .. } => assert_eq!(transfer_len, 0),
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
        let n = data_in(build_read_disc_info(&mut w, 52, &info), &mut buf);
        assert_eq!(n, 52);
        // Byte 2: Erasable 1 | State of last Session 01b | Disc Status 01b
        // = 0b00010101.
        assert_eq!(buf[2], 0x15);
    }

    // ── Capabilities page (0x2A) ────────────────────────────────────

    #[test]
    fn capabilities_page_read_only_cd_rom_layout() {
        let p = build_capabilities_page(&READ_ONLY_CDROM_CAPS);
        assert_eq!(p.len(), 56);
        assert_eq!(p[0], 0x2A);
        assert_eq!(p[1], 54); // page length
                              // Read-only, Mode-1 baseline only: no extra read/write bits.
        assert_eq!(p[2], 0x00);
        assert_eq!(p[3], 0x00);
        assert_eq!(p[4], 0x00);
        // Loading mechanism = tray (001b).
        assert_eq!(p[8], 0b001);
        // No buffer, no speeds.
        assert_eq!(&p[10..12], &[0, 0]);
        assert_eq!(&p[14..16], &[0, 0]);
        assert_eq!(&p[18..20], &[0, 0]);
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
        let p = build_capabilities_page(&caps);
        assert_eq!(p[2] & 0x40, 0x40); // CD-R read
        assert_eq!(p[2] & 0x04, 0x04); // CD-DA accurate
        assert_eq!(p[4] & 0x40, 0x40); // CD-R write
        assert_eq!(p[8] & 0x10, 0x10); // eject
        assert_eq!(&p[10..12], &[0x10, 0x00]); // buffer 4096
        assert_eq!(&p[14..16], &[0x0D, 0xC8]); // max read 3528
    }

    // ── READ BUFFER CAPACITY ────────────────────────────────────────

    #[test]
    fn read_buffer_capacity_structure() {
        let mut w = work();
        let mut buf = [0u8; 12];
        let n = data_in(build_read_buffer_capacity(&mut w, 12, 4096, 2048), &mut buf);
        assert_eq!(n, 12);
        assert_eq!(&buf[0..2], &[0x00, 0x0A]); // Data Length = 10
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x10, 0x00]); // buffer 4096
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x08, 0x00]); // blank 2048

        // Allocation clamp and zero-alloc (not an error).
        let mut small = [0u8; 2];
        let n = data_in(build_read_buffer_capacity(&mut w, 2, 0, 0), &mut small);
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
        assert_eq!(CurrentProfile::DvdRw.code(), 0x001A);
    }

    #[test]
    fn get_config_dvd_rw_features() {
        let mut w = work();
        let outcome = build_get_config_response(
            &mut w,
            CurrentProfile::DvdRw,
            &UDFRW_CAPS,
            0x00,
            0x0000,
            255,
            0x1234,
        );
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
        assert!(n >= 8 + 12 + 8 + 12 + 4 + 8 + 4 + 16 + 8);
        assert_eq!(buf[7], 0x1A); // current profile DVD+RW
                                  // Walk the feature list and check codes + key fields.
        let mut off = 8usize;
        let mut saw_rw = false;
        let mut saw_dvdrw = false;
        while off + 4 <= n {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let add_len = buf[off + 3] as usize;
            match code {
                0x0020 => {
                    saw_rw = true;
                    assert_eq!(buf[off + 2], 0x05); // version 1 + current
                    assert_eq!(add_len, 12);
                    assert_eq!(&buf[off + 4..off + 8], &0x1234u32.to_be_bytes());
                    assert_eq!(&buf[off + 8..off + 12], &2048u32.to_be_bytes());
                    assert_eq!(&buf[off + 12..off + 14], &1u16.to_be_bytes());
                }
                0x002A => {
                    saw_dvdrw = true;
                    assert_eq!(add_len, 4);
                    assert_eq!(buf[off + 4], 0x01); // Write
                }
                0x001F => {
                    // DVD Read present for the DVD+RW profile.
                    assert_eq!(add_len, 0);
                }
                _ => {}
            }
            off += 4 + add_len;
        }
        assert!(saw_rw, "Random Writable feature must be present");
        assert!(saw_dvdrw, "DVD+RW feature must be present");
    }
}
