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
}

impl CurrentProfile {
    /// Numeric profile code (MMC-6 Table 64).
    pub fn code(self) -> u16 {
        match self {
            Self::CdRom => 0x0008,
            Self::DvdRom => 0x0010,
            Self::CdR => 0x0009,
            Self::CdRw => 0x000A,
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

/// CD/DVD Capabilities & Mechanical Status page (0x2A, MMC-6 §6.12.4):
/// page_length=22, no mechanical features for virtual drive.  Total = 24 bytes.
const CDROM_CAPABILITIES: [u8; 24] = [
    0x2A, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Return the MODE SENSE page data for `page` (`0x3F` handled specially).
pub(crate) fn cdrom_mode_page(page: u8) -> Option<&'static [u8]> {
    match page {
        0x08 => Some(&CACHING_PAGE),
        0x00 => Some(&VENDOR_PAGE),
        0x0D => Some(&CDROM_PARAMS),
        0x0E => Some(&CDROM_AUDIO),
        0x2A => Some(&CDROM_CAPABILITIES),
        0x3F => None, // caller must use build_cdrom_all_pages()
        _ => None,
    }
}

/// Total byte count of all CD-ROM mode pages (for 0x3F sizing).
#[allow(dead_code)] // used in Phase 2c (CdromDevice)
pub(crate) const ALL_CDROM_PAGES_LEN: usize = CACHING_PAGE.len()
    + VENDOR_PAGE.len()
    + CDROM_PARAMS.len()
    + CDROM_AUDIO.len()
    + CDROM_CAPABILITIES.len();

/// Build the concatenated 0x3F response into `out`.
/// Returns the number of bytes written.
#[allow(dead_code)] // used in Phase 2c (CdromDevice)
pub(crate) fn build_cdrom_all_pages(out: &mut [u8]) -> usize {
    let pages: [&[u8]; 5] = [
        &CACHING_PAGE,
        &VENDOR_PAGE,
        &CDROM_PARAMS,
        &CDROM_AUDIO,
        &CDROM_CAPABILITIES,
    ];
    let mut off = 0;
    for page in &pages {
        let end = off + page.len();
        if end > out.len() {
            break;
        }
        out[off..end].copy_from_slice(page);
        off = end;
    }
    off
}

// ── GET CONFIGURATION common features builder ───────────────────────

/// Build GET CONFIGURATION feature descriptors common to all CD-ROM
/// devices (plan §8.2).  Writes into `buf[off..]` and returns the new
/// offset.  `profile` is the current profile.
///
/// Features included (all current):
/// - 0x0001 Core (version 2, persistent, additional length 8)
/// - 0x0003 Removable Medium (tray type)
/// - 0x0010 Random Readable (block size 2048)
/// - 0x001D Multi-Read
/// - 0x001E CD Read (version 2)
/// - 0x001F DVD Read (only if profile is DVD-ROM)
pub fn build_get_config_features(
    buf: &mut [u8],
    mut off: usize,
    profile: CurrentProfile,
    rt: u8,
    start_feature: u16,
) -> usize {
    let include = |code: u16| rt != 0x02 || code >= start_feature;

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
        off += 4;
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

    // DVD Read (0x001F) — only for DVD-ROM profile
    if matches!(profile, CurrentProfile::DvdRom) && include(0x001F) {
        buf[off] = 0x00;
        buf[off + 1] = 0x1F;
        buf[off + 2] = 0x01; // current
        off += 4;
    }

    off
}

/// Build a GET CONFIGURATION response into `data[0..]`.
pub fn build_get_config_response<'a>(
    data: &'a mut [u8],
    profile: CurrentProfile,
    rt: u8,
    start_feature: u16,
    alloc: u16,
) -> CommandOutcome<'a> {
    let mut buf = [0u8; 64];
    // Header: bytes 0-3 = data length (placeholder), 6-7 = current profile.
    buf[6] = (profile.code() >> 8) as u8;
    buf[7] = profile.code() as u8;

    let off = build_get_config_features(&mut buf, 8, profile, rt, start_feature);

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
    buf[0] = 0x32;
    // Byte 2: Data Type 000b | State of last Session | Erasable | Disc
    // Status (bits 7:6 | 5:4 | 3 | 1:0).
    let state = (info.state_of_last_session & 0b11) << 4;
    let erasable = u8::from(info.erasable) << 3;
    buf[2] = state | erasable | (info.disc_status & 0b11);
    buf[3] = info.first_track;
    buf[4] = info.sessions;
    buf[5] = info.first_track;
    buf[6] = info.last_track;
    // Byte 7: DID_V/DBC_V/URU/DAC_V reserved, BG Format Status 00b.
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
        assert_eq!(n, 28); /* 4 header + 24 page */
        assert_eq!(buf[4], 0x2A); /* page code */
        assert_eq!(buf[5], 0x16); /* page length = 22 */
    }

    // ── GET CONFIGURATION common features ───────────────────────────

    #[test]
    fn cdrom_get_config_cd_profile() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        let outcome = build_get_config_response(&mut w, profile, 0x00, 0x0000, 64);
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
        let outcome = build_get_config_response(&mut w, profile, 0x00, 0x0000, 64);
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
        let outcome = build_get_config_response(&mut w, profile, 0x00, 0x0000, 255);
        let mut buf = [0u8; 256];
        let n = data_in(outcome, &mut buf);
        // Should contain Core (0x0001), Removable (0x0003), Random Readable
        // (0x0010), Multi-Read (0x001D), CD Read (0x001E)
        assert!(n >= 44);
        // Check feature 0x0001 present at offset 8
        assert_eq!(buf[8], 0x00);
        assert_eq!(buf[9], 0x01);
        // Check feature 0x0003 present
        assert_eq!(buf[20], 0x00);
        assert_eq!(buf[21], 0x03);
        // Check feature 0x0010 present
        assert_eq!(buf[24], 0x00);
        assert_eq!(buf[25], 0x10);
    }

    #[test]
    fn cdrom_get_config_starting_feature_filters() {
        let mut w = work();
        let profile = CurrentProfile::CdRom;
        // RT=10b, start 0x0010 → Random Readable + Multi-Read + CD Read
        let outcome = build_get_config_response(&mut w, profile, 0x02, 0x0010, 255);
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
        let outcome = build_get_config_response(&mut w, profile, 0x00, 0x0000, 8);
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
        assert_eq!(buf[0], 0x32); // Disc Information Length (excludes itself)
        assert_eq!(buf[1], 0x00);
        // Byte 2: Data Type 00b | State of last Session 11b | Erasable 0 |
        // Disc Status 10b = 0b00110010.
        assert_eq!(buf[2], 0x32);
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
        assert_eq!(buf, [0x32, 0x00]);
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
        // Byte 2: 00 (type) | 01 (incomplete session) | 1 (erasable) |
        // 01 (incomplete disc) = 0b00011001.
        assert_eq!(buf[2], 0x19);
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
    }
}
