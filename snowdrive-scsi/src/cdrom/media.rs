//! CD-ROM media types and geometry (plan §3.3 / M1).
//!
//! This module hoists the shared type definitions that all media variants
//! (`FlatMedia`, `LiveData`, `BundleMedia`, `UdfRwMedia`) will produce
//! and the drive layer will consume.  **M1 is a pure type-definition step** —
//! no device-model changes, no behaviour modifications.
//!
//! Types defined here:
//! - Geometry constants (`MAX_TRACKS`, `SECTOR_SIZE_DATA`, …)
//! - `TrackKind`, `TrackStatus`, `RecordingMode`, `DiscState`, `DiscType`
//! - `TrackFile`, `Track`, `SessionInfo`
//! - `MediaError` (write-path error model, plan §3.2 A1)
//! - `CdMedia` enum (media slot — plan §2.2; variants added incrementally
//!   as `FlatMedia`/`LiveData`/`BundleMedia`/`UdfRwMedia` land)

// ── Geometry constants (plan §3.3) ─────────────────────────────────

/// Maximum number of tracks on a single disc (MMC limit).
pub const MAX_TRACKS: usize = 99;

/// Maximum number of files that may back a single track (Bundle FAT32 split).
pub const MAX_FILES_PER_TRACK: usize = 16;

/// Maximum number of sessions on a single disc (MMC logical limit).
pub const MAX_SESSIONS: usize = 99;

/// Logical block size for data tracks (Mode 1: 2048 bytes).
pub const SECTOR_SIZE_DATA: u16 = 2048;

/// Logical block size for audio tracks (raw: 2352 bytes).
pub const SECTOR_SIZE_AUDIO: u16 = 2352;

/// Pre-gap sectors before each track's data area (150 = 2 seconds at 75 s/s).
pub const PREGAP_SECTORS: u32 = 150;

/// Default CD capacity for 80 minutes of audio (360 000 sectors).
pub const DEFAULT_CD_CAPACITY: u32 = 360_000;

// ── Track / Session / Disc enums (plan §3.3) ──────────────────────

/// Whether a track carries data or audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackKind {
    Data,
    Audio,
}

/// Track recording status (plan §3.3 / MMC-6 Table 367 analogous).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackStatus {
    /// RESERVE TRACK issued but no data written yet.
    Reserved,
    /// Writing started but CLOSE TRACK not yet issued.
    Incomplete,
    /// Track is closed and readable.
    Complete,
}

/// Recording mode for the disc (plan §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingMode {
    /// CD-R always; CD-RW initial state.
    Sequential,
    /// CD-RW after FORMAT UNIT (restricted overwrite).
    RestrictedOverwrite,
}

/// Overall disc state (plan §3.3 / MMC-6 Table 367).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscState {
    /// No tracks written; disc is empty.
    Blank,
    /// At least one open track; more data may be appended.
    Appendable,
    /// All tracks closed; disc is finalised and read-only.
    Finalized,
}

/// Physical disc type for profile reporting (plan §3.3).
///
/// **Not** the same as `DiscInfo.disc_type: u8` (MMC-6 Table 369 byte 8
/// values like 0x00/0x20).  This enum identifies the *media family*;
/// the disc-info byte is a layout concern of the drive layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscType {
    /// 0x0008 — CD-ROM (read-only pressed/ROM media).
    CdRom,
    /// 0x0009 — CD-R (write-once recordable).
    CdR,
    /// 0x000A — CD-RW (rewritable).
    CdRw,
}

impl DiscType {
    /// Numeric profile code for GET CONFIGURATION (MMC-6 Table 64).
    pub fn profile_code(self) -> u16 {
        match self {
            Self::CdRom => 0x0008,
            Self::CdR => 0x0009,
            Self::CdRw => 0x000A,
        }
    }
}

// ── Track / Session data structures (plan §3.3) ───────────────────

/// A file backing part of a track's data (Bundle multi-file split, plan §7.1).
#[derive(Debug, Clone)]
pub struct TrackFile {
    /// Ordinal within the track (0-based).
    pub idx: u8,
    /// File size in bytes.
    pub size: u64,
}

/// Track descriptor — one per logical track on the disc (plan §3.3).
#[derive(Debug, Clone)]
pub struct Track {
    /// Track number (1-based, MMC convention).
    pub num: u8,
    /// Data or audio.
    pub kind: TrackKind,
    /// Sector size in bytes (2048 for data, 2352 for audio).
    pub block_size: u16,
    /// Recording status (Reserved / Incomplete / Complete).
    pub status: TrackStatus,
    /// Session this track belongs to (1-based).
    pub session: u8,
    /// First LBA of the track (including pre-gap).
    pub start_lba: u32,
    /// First LBA of user data (start_lba + pregap).
    pub data_start_lba: u32,
    /// Number of user-data sectors in the track.
    pub length_sectors: u32,
    /// Number of sectors allocated on the medium (>= length_sectors).
    pub allocated_sectors: u32,
    /// Next Writable Address (only meaningful for Incomplete tracks).
    pub nwa: u32,
    /// Free logical blocks available for writing (Complete: 0).
    pub free_lbas: u32,
    /// Files backing this track's data (Bundle multi-file; empty for flat/live).
    pub files: heapless::Vec<TrackFile, MAX_FILES_PER_TRACK>,
}

/// Session descriptor — one per session on the disc (plan §3.3).
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session number (1-based).
    pub num: u8,
    /// First track number in this session.
    pub first_track: u8,
    /// First LBA of the session (start of lead-in or pre-gap).
    pub start_lba: u32,
    /// Lead-out start LBA (first sector after the session).
    pub lead_out_lba: u32,
    /// Whether the session is closed (lead-in written).
    pub closed: bool,
}

// ── Write-path error model (plan §3.2 A1) ─────────────────────────

/// Errors from the media write path (plan §3.2 A1).
///
/// The drive layer maps these to SCSI sense codes:
/// - `IllegalField` → 24h/00h (INVALID FIELD IN CDB)
/// - `WriteProtected` → 07h/00h (DATA PROTECT) / 27h/00h (WRITE PROTECTED)
/// - `OutOfBounds` → 21h/00h (LOGICAL BLOCK ADDRESS OUT OF RANGE)
/// - `Io` → sense passthrough
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    /// Invalid field in CDB (NWA mismatch, reservation size < 300, etc.).
    IllegalField,
    /// Medium is write-protected or disc is finalized.
    WriteProtected,
    /// Logical block address out of range.
    OutOfBounds,
    /// Underlying storage I/O failure.
    Io,
}

// ── CdMedia enum (plan §2.2) ──────────────────────────────────────

/// The media slot inside a [`CdromDrive`](super::device::CdromDrive).
///
/// `None` means the tray is empty (plan §6.1).  Each variant wraps a
/// concrete media type that provides geometry and a data plane.
///
/// Variants are added incrementally as the media types land:
/// - **M3**: `Flat(…)` and `Live(…)`
/// - **M7**: `Bundle(…)`
/// - **M2**: `UdfRw(…)` (migrated from the standalone `UdfRwDevice`)
///
/// Until the concrete types exist, this enum is defined but not yet
/// constructed anywhere — M1 is purely a type-hoisting step.
pub enum CdMedia<'a> {
    /// Flat ISO/RAM read-only image (plan §5.1).
    /// `FlatMedia<FlatData=BlockBackend<'a>>`
    Flat(/* FlatMedia<BlockBackend<'a>> — M3 */),

    /// Live ISO9660 from a host directory (plan §5.2).
    /// `FlatMedia<FlatData=LiveData<FsBackend>>`
    Live(/* FlatMedia<LiveData<FsBackend>> — M3 */),

    /// Bundle: multi-track, multi-session disc package (plan §7.1).
    /// `BundleMedia<FsBackend>`
    Bundle(/* BundleMedia<FsBackend> — M7 */),

    /// UDF random-writable DVD+RW (plan §5.4, migrated from UdfRwDevice).
    /// `UdfRwMedia<BlockBackend<'a>>`
    UdfRw(/* UdfRwMedia<BlockBackend<'a>> — M2 */),

    /// Marker for lifetime usage.
    _Phantom(core::marker::PhantomData<&'a ()>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_size_constants() {
        assert_eq!(SECTOR_SIZE_DATA, 2048);
        assert_eq!(SECTOR_SIZE_AUDIO, 2352);
    }

    #[test]
    fn disc_type_profile_codes() {
        assert_eq!(DiscType::CdRom.profile_code(), 0x0008);
        assert_eq!(DiscType::CdR.profile_code(), 0x0009);
        assert_eq!(DiscType::CdRw.profile_code(), 0x000A);
    }

    #[test]
    fn track_defaults_construct() {
        let t = Track {
            num: 1,
            kind: TrackKind::Data,
            block_size: SECTOR_SIZE_DATA,
            status: TrackStatus::Complete,
            session: 1,
            start_lba: 0,
            data_start_lba: PREGAP_SECTORS,
            length_sectors: 1000,
            allocated_sectors: 1000,
            nwa: 0,
            free_lbas: 0,
            files: heapless::Vec::new(),
        };
        assert_eq!(t.num, 1);
        assert_eq!(t.data_start_lba, PREGAP_SECTORS);
    }

    #[test]
    fn session_info_construct() {
        let s = SessionInfo {
            num: 1,
            first_track: 1,
            start_lba: 0,
            lead_out_lba: 360_000,
            closed: true,
        };
        assert_eq!(s.num, 1);
        assert!(s.closed);
    }

    #[test]
    fn media_error_variants() {
        let e = MediaError::WriteProtected;
        assert_eq!(e, MediaError::WriteProtected);
        assert_ne!(e, MediaError::OutOfBounds);
    }

    #[test]
    fn default_cd_capacity() {
        assert_eq!(DEFAULT_CD_CAPACITY, 360_000);
    }

    #[test]
    fn pregap_sectors() {
        assert_eq!(PREGAP_SECTORS, 150);
    }
}
