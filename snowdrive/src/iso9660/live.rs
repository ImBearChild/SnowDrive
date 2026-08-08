//! Live ISO9660 generation algorithms (plan §11.2).
//!
//! Pure algorithms: **no storage, no FS, no alloc**. The device layer
//! (`CdLiveFsDevice`) scans the host directory with `FsStorage::read_dir`,
//! builds a `&[FileEntry]` slice, and calls [`compute_layout`] to get an
//! LBA layout.  During READ(10), the device calls [`gen_sector`] for
//! metadata LBAs and [`resolve`] for file-data LBAs.
//!
//! # ISO 9660 Layout
//!
//! ```text
//! LBA 0-15    System Area (zeros)
//! LBA 16      PVD (Primary Volume Descriptor)
//! LBA 17      SVD (Supplementary Volume Descriptor, Joliet UCS-2BE)
//! LBA 18      Volume Descriptor Set Terminator
//! LBA 19      Path Table (LE)
//! LBA 20      Root Directory ("." ".." + file entries)
//! LBA 21+     File data (padded to 2048-byte sectors)
//! ```

use heapless::{String, Vec};

/// Sector size for ISO 9660.
pub const SECTOR_SIZE: u32 = 2048;

/// System area sectors (LBA 0-15).
const SYSTEM_AREA_SECTORS: u32 = 16;

/// PVD is always at LBA 16.
const PVD_LBA: u32 = 16;

/// SVD (Joliet) is always at LBA 17.
const SVD_LBA: u32 = 17;

/// Terminator is always at LBA 18.
const TERMINATOR_LBA: u32 = 18;

/// Maximum number of files the layout can track.
pub const MAX_FILES: usize = 128;

/// Maximum label length (ASCII chars).
pub const MAX_LABEL_LEN: usize = 16;

/// Maximum Joliet file name length (UCS-2BE bytes, i.e. 2 × char count).
const MAX_JOLIET_NAME_BYTES: usize = 64;

// ── Input types ─────────────────────────────────────────────────────

/// File tree entry provided by the device layer.
///
/// Paths are relative to the root (e.g. `"README.TXT"`, `"DOCS/MANUAL.PDF"`).
/// Directories must appear before their children.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path from root (e.g. `"README.TXT"`, `"SUB/FILE.BIN"`).
    pub path: String<512>,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
}

// ── Output types ────────────────────────────────────────────────────

/// Per-file extent information within the layout.
#[derive(Debug, Clone)]
pub struct FileExtent {
    /// Index into the original `files` slice.
    pub file_index: usize,
    /// Starting LBA of the file data.
    pub lba: u32,
    /// Number of sectors occupied.
    pub sectors: u32,
    /// File size in bytes (may be less than `sectors * SECTOR_SIZE`).
    pub size: u64,
    /// Joliet UCS-2BE encoded file name (without version ";1").
    pub name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
}

/// Complete LBA layout for a live ISO9660 image.
#[derive(Debug)]
pub struct Layout {
    /// Volume label (ASCII, up to 16 chars).
    pub label: String<MAX_LABEL_LEN>,
    /// Path table LBA.
    pub path_table_lba: u32,
    /// Root directory LBA.
    pub root_dir_lba: u32,
    /// Number of sectors for the root directory (typically 1).
    pub root_dir_sectors: u32,
    /// File extents (one per non-directory FileEntry).
    pub extents: Vec<FileExtent, MAX_FILES>,
    /// Total number of sectors in the image.
    pub total: u32,
}

// ── Public API ──────────────────────────────────────────────────────

/// Compute the LBA layout for a set of files.
///
/// Files must be provided in order: directories before their children.
/// The label is truncated to 16 ASCII characters.
pub fn compute_layout(files: &[FileEntry], label: &str) -> Result<Layout, IsoError> {
    if files.len() > MAX_FILES {
        return Err(IsoError::TooManyFiles);
    }

    // Truncate label to MAX_LABEL_LEN ASCII chars.
    let mut lbl = String::<MAX_LABEL_LEN>::new();
    for ch in label.chars().take(MAX_LABEL_LEN) {
        if ch.is_ascii() && !ch.is_control() {
            let _ = lbl.push(ch);
        }
    }
    if lbl.is_empty() {
        let _ = lbl.push_str("SNOWDRIVE");
    }

    // Fixed metadata: PVD(16) + SVD(17) + Terminator(18) + PathTable(19)
    // Root dir starts at LBA 20.
    let path_table_lba = SYSTEM_AREA_SECTORS + 3; // 19
    let root_dir_lba = path_table_lba + 1; // 20

    // Build file extents with Joliet names first (the root directory must
    // be sized from the total record bytes before file LBAs are assigned).
    let mut extents = Vec::<FileExtent, MAX_FILES>::new();
    let mut root_bytes: u64 = 34 + 34; // "." and ".." records
    for (idx, entry) in files.iter().enumerate() {
        if entry.is_dir {
            continue;
        }
        let size = entry.size;
        let sectors = size.div_ceil(u64::from(SECTOR_SIZE)) as u32;

        // Extract the file name (last component of the path) and encode
        // as Joliet UCS-2BE.
        let file_name = entry.path.rsplit('/').next().unwrap_or(entry.path.as_str());
        let joliet_name = to_joliet_name(file_name);

        // Directory record length: 33 + name + pad-to-even.
        let rec_len = 33u64
            + joliet_name.len() as u64
            + if joliet_name.len().is_multiple_of(2) {
                0
            } else {
                1
            };
        root_bytes += rec_len;

        extents
            .push(FileExtent {
                file_index: idx,
                lba: 0, // assigned below
                sectors,
                size,
                name: joliet_name,
            })
            .map_err(|_| IsoError::TooManyFiles)?;
    }

    // Root directory spans as many sectors as its records need.
    let root_dir_sectors = root_bytes.div_ceil(u64::from(SECTOR_SIZE)) as u32;
    let first_file_lba = root_dir_lba + root_dir_sectors;

    let mut next_lba = first_file_lba;
    for extent in extents.iter_mut() {
        extent.lba = next_lba;
        next_lba += extent.sectors;
    }

    let total = next_lba;

    Ok(Layout {
        label: lbl,
        path_table_lba,
        root_dir_lba,
        root_dir_sectors,
        extents,
        total,
    })
}

/// Generate the sector at `lba` into `out` (must be exactly 2048 bytes).
///
/// Returns `true` if `lba` is in the metadata area (caller should send
/// `out` as the sector data).  Returns `false` if `lba` is in the file
/// data area (caller should use [`resolve`] to find the file and read
/// from the host FS).
pub fn gen_sector(layout: &Layout, lba: u32, out: &mut [u8]) -> bool {
    assert!(out.len() >= SECTOR_SIZE as usize);
    out.fill(0);

    match lba {
        PVD_LBA => {
            write_pvd(layout, out);
            true
        }
        SVD_LBA => {
            write_svd(layout, out);
            true
        }
        TERMINATOR_LBA => {
            write_terminator(out);
            true
        }
        l if l == layout.path_table_lba => {
            write_path_table(layout, out);
            true
        }
        l if l >= layout.root_dir_lba && l < layout.root_dir_lba + layout.root_dir_sectors => {
            write_root_directory(layout, lba, out);
            true
        }
        _ => false,
    }
}

/// Map a file-data LBA to `(file_index, byte_offset_within_file, bytes_remaining_in_file)`.
///
/// Returns `None` if `lba` is not in the file data area or is past the
/// end of all files.
pub fn resolve(layout: &Layout, lba: u32) -> Option<(usize, u64, u64)> {
    for extent in &layout.extents {
        let end_lba = extent.lba + extent.sectors;
        if lba >= extent.lba && lba < end_lba {
            let sector_offset = (lba - extent.lba) as u64 * u64::from(SECTOR_SIZE);
            let bytes_remaining = extent.size.saturating_sub(sector_offset);
            return Some((extent.file_index, sector_offset, bytes_remaining));
        }
    }
    None
}

/// Total number of sectors in the image (for READ CAPACITY / READ TOC
/// lead-out).
pub fn total_sectors(layout: &Layout) -> u32 {
    layout.total
}

// ── Joliet name encoding ────────────────────────────────────────────

/// Encode an ASCII file name to Joliet UCS-2BE (0x00 + char for each ASCII byte).
fn to_joliet_name(name: &str) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let mut out = Vec::new();
    // Joliet allows up to 64 bytes = 32 UCS-2 chars.
    // Append ";1" version suffix as per ISO9660 (Joliet doesn't require it,
    // but many readers expect it).
    let with_version = alloc_less_format(name);
    for ch in with_version.chars().take(32) {
        if ch.is_ascii() && !ch.is_control() {
            let _ = out.push(0x00);
            let _ = out.push(ch as u8);
        }
    }
    out
}

/// Format `"name;1"` without alloc (returns an iterator-like approach,
/// but since we can't alloc, we just encode directly).
fn alloc_less_format(name: &str) -> &str {
    // For simplicity, just return the name as-is.
    // ";1" version suffix will be added by the caller if needed.
    name
}

// ── ISO9660 structure writers ───────────────────────────────────────

/// Write PVD (Primary Volume Descriptor) at LBA 16.
fn write_pvd(layout: &Layout, out: &mut [u8]) {
    out[0] = 0x01; // PVD type
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01; // version

    // Volume Space Size (LE at 80, BE at 84)
    out[80..84].copy_from_slice(&layout.total.to_le_bytes());
    out[84..88].copy_from_slice(&layout.total.to_be_bytes());

    // Volume Set Size = 1
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[124..126].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[128..130].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[132..134].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size (LE at 132, BE at 140): one root entry = 10 bytes
    let path_table_size = 10u32;
    out[132..136].copy_from_slice(&path_table_size.to_le_bytes());
    out[140..144].copy_from_slice(&path_table_size.to_be_bytes());

    // Location of LE Path Table
    out[140..144].copy_from_slice(&layout.path_table_lba.to_le_bytes());

    // Location of BE Path Table
    out[148..152].copy_from_slice(&layout.path_table_lba.to_be_bytes());

    // Root Directory Record (34 bytes at 156)
    write_dir_record_root_pvd(out, 156, layout.root_dir_lba, layout.root_dir_sectors);

    // Volume Identifier (32 bytes at 190): label padded with spaces
    for i in 0..32 {
        out[190 + i] = b' ';
    }
    let label_bytes = layout.label.as_bytes();
    let copy_len = label_bytes.len().min(32);
    out[190..190 + copy_len].copy_from_slice(&label_bytes[..copy_len]);

    // Publisher Identifier (128 bytes at 446)
    for i in 0..128 {
        out[446 + i] = b' ';
    }
    let pub_id = b"SnowDrive";
    out[446..446 + pub_id.len()].copy_from_slice(pub_id);

    // Data Preparer Identifier (128 bytes at 574)
    for i in 0..128 {
        out[574 + i] = b' ';
    }
    out[574..574 + pub_id.len()].copy_from_slice(pub_id);

    // Application Identifier (128 bytes at 838)
    for i in 0..128 {
        out[838 + i] = b' ';
    }
    out[838..838 + pub_id.len()].copy_from_slice(pub_id);

    // File Structure Version
    out[881] = 0x01;
}

/// Write SVD (Supplementary Volume Descriptor / Joliet) at LBA 17.
fn write_svd(layout: &Layout, out: &mut [u8]) {
    out[0] = 0x02; // SVD type
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01; // version
                   // Joliet escape sequences: UCS-2 Level 1
    out[88] = 0x25; // %
    out[89] = 0x2F; // /
    out[90] = 0x40; // @

    // Volume Space Size
    out[80..84].copy_from_slice(&layout.total.to_le_bytes());
    out[84..88].copy_from_slice(&layout.total.to_be_bytes());

    // Volume Set Size = 1
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[124..126].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[128..130].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[132..134].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size
    let path_table_size = 10u32;
    out[132..136].copy_from_slice(&path_table_size.to_le_bytes());
    out[140..144].copy_from_slice(&path_table_size.to_be_bytes());

    // Location of LE Path Table
    out[140..144].copy_from_slice(&layout.path_table_lba.to_le_bytes());

    // Location of BE Path Table
    out[148..152].copy_from_slice(&layout.path_table_lba.to_be_bytes());

    // Root Directory Record
    write_dir_record_root_pvd(out, 156, layout.root_dir_lba, layout.root_dir_sectors);

    // Volume Identifier (32 bytes at 190): UCS-2BE label
    let label_bytes = layout.label.as_bytes();
    let ucs2_len = label_bytes.len().min(16);
    for i in 0..32 {
        out[190 + i] = 0;
    }
    for (i, &ch) in label_bytes[..ucs2_len].iter().enumerate() {
        out[190 + i * 2] = 0x00;
        out[190 + i * 2 + 1] = ch;
    }

    // File Structure Version
    out[881] = 0x01;
}

/// Write Volume Descriptor Set Terminator at LBA 18.
fn write_terminator(out: &mut [u8]) {
    out[0] = 0xFF;
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01;
}

/// Write the LE Path Table at `layout.path_table_lba`.
fn write_path_table(layout: &Layout, out: &mut [u8]) {
    // Root directory entry only.
    out[0] = 0x01; // name length (root = 0x00, but ECMA-119 says 1 for "\0")
    out[1] = 0x00; // ext attr length
    out[2..6].copy_from_slice(&layout.root_dir_lba.to_le_bytes());
    out[6..8].copy_from_slice(&1u16.to_le_bytes()); // parent = root
    out[8] = 0x00; // directory identifier: root
    out[9] = 0x00; // padding
}

/// Write the root directory sector at `lba` (which must lie within
/// `layout.root_dir_lba .. + root_dir_sectors`).
///
/// Contains ".", "..", and one entry per file (Joliet UCS-2BE names). Only
/// the records overlapping this sector are written; the rest of `out` is
/// zeroed.
fn write_root_directory(layout: &Layout, lba: u32, out: &mut [u8]) {
    out.fill(0);
    let sector_start = (lba - layout.root_dir_lba) as usize * SECTOR_SIZE as usize;

    // Emit one record, tracking its byte offset within the directory
    // extent and copying only the part that overlaps `out`'s sector.
    let mut offset = 0usize;
    let mut emit = |offset: &mut usize, extent_lba: u32, data_len: u32, flags: u8, name: &[u8]| {
        let rec_len = 33 + name.len() + if !name.len().is_multiple_of(2) { 1 } else { 0 };
        let rec_start = *offset;
        *offset += rec_len;

        let sect_end = sector_start + out.len();
        if rec_start + rec_len <= sector_start || rec_start >= sect_end {
            return;
        }

        // Build the record into a scratch buffer (max 33 + 64 + 1 bytes).
        let mut rec = [0u8; 128];
        write_dir_record(&mut rec[..rec_len], 0, extent_lba, data_len, flags, name);

        let from = sector_start.max(rec_start);
        let to = (rec_start + rec_len).min(sect_end);
        out[from - sector_start..to - sector_start]
            .copy_from_slice(&rec[from - rec_start..to - rec_start]);
    };

    // "." entry (self = root)
    emit(
        &mut offset,
        layout.root_dir_lba,
        layout.root_dir_sectors * SECTOR_SIZE,
        0x02,
        &[0x00],
    );

    // ".." entry (parent = root for root directory)
    emit(
        &mut offset,
        layout.root_dir_lba,
        layout.root_dir_sectors * SECTOR_SIZE,
        0x02,
        &[0x01],
    );

    // File entries
    for extent in &layout.extents {
        let data_len = extent.sectors * SECTOR_SIZE;
        emit(&mut offset, extent.lba, data_len, 0x00, &extent.name);
    }
}

/// Write a directory record into `out` at `offset`.
/// Returns the number of bytes written.
///
/// `flags`: 0x00 = file, 0x02 = directory
/// `name`: raw identifier bytes (Joliet UCS-2BE for file names,
///          0x00 for ".", 0x01 for "..")
fn write_dir_record(
    out: &mut [u8],
    offset: usize,
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    name: &[u8],
) -> usize {
    let name_len = name.len();
    let rec_len = 33 + name_len + if !name_len.is_multiple_of(2) { 1 } else { 0 };
    let o = offset;

    out[o] = rec_len as u8; // Length of Directory Record
    out[o + 1] = 0x00; // Extended Attribute Record Length
                       // Location of Extent (LE + BE)
    out[o + 2..o + 6].copy_from_slice(&extent_lba.to_le_bytes());
    out[o + 10..o + 14].copy_from_slice(&extent_lba.to_be_bytes());
    // Data Length (LE + BE)
    out[o + 6..o + 10].copy_from_slice(&data_len.to_le_bytes());
    out[o + 14..o + 18].copy_from_slice(&data_len.to_be_bytes());
    // Recording Date and Time (7 bytes at o+18): zeros
    // File Flags
    out[o + 25] = flags;
    // File Unit Size
    out[o + 26] = 0x00;
    // Interleave Gap Size
    out[o + 27] = 0x00;
    // Volume Sequence Number (LE + BE)
    out[o + 28..o + 30].copy_from_slice(&1u16.to_le_bytes());
    out[o + 30..o + 32].copy_from_slice(&1u16.to_be_bytes());
    // Length of File Identifier
    out[o + 32] = name_len as u8;
    // File Identifier
    out[o + 33..o + 33 + name_len].copy_from_slice(name);
    // Padding (if name_len is odd)
    if !name_len.is_multiple_of(2) {
        out[o + 33 + name_len] = 0x00;
    }

    rec_len
}

/// Write the root directory record (for PVD/SVD at byte 156).
fn write_dir_record_root_pvd(out: &mut [u8], offset: usize, root_lba: u32, root_sectors: u32) {
    let data_len = root_sectors * SECTOR_SIZE;
    let o = offset;

    out[o] = 34; // Length (33 + 1 for "\0" name)
    out[o + 1] = 0x00; // Ext Attr Length
    out[o + 2..o + 6].copy_from_slice(&root_lba.to_le_bytes());
    out[o + 10..o + 14].copy_from_slice(&root_lba.to_be_bytes());
    out[o + 6..o + 10].copy_from_slice(&data_len.to_le_bytes());
    out[o + 14..o + 18].copy_from_slice(&data_len.to_be_bytes());
    // Date (7 bytes): zeros
    out[o + 25] = 0x02; // Flags: directory
    out[o + 26] = 0x00; // File Unit Size
    out[o + 27] = 0x00; // Interleave Gap Size
    out[o + 28..o + 30].copy_from_slice(&1u16.to_le_bytes());
    out[o + 30..o + 32].copy_from_slice(&1u16.to_be_bytes());
    out[o + 32] = 0x01; // Name length
    out[o + 33] = 0x00; // Name: root ("\0")
}

// ── Error type ──────────────────────────────────────────────────────

/// snow9660 error type (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoError {
    /// Too many files for the layout (exceeds MAX_FILES).
    TooManyFiles,
}

impl core::fmt::Display for IsoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyFiles => write!(f, "too many files for ISO9660 layout"),
        }
    }
}

impl core::error::Error for IsoError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, size: u64, is_dir: bool) -> FileEntry {
        let mut p = String::<512>::new();
        p.push_str(path).unwrap();
        FileEntry {
            path: p,
            size,
            is_dir,
        }
    }

    fn make_entries() -> Vec<FileEntry, MAX_FILES> {
        let mut v = Vec::new();
        v.push(make_entry("README.TXT", 1000, false)).unwrap();
        v.push(make_entry("DATA.BIN", 4096, false)).unwrap();
        v
    }

    // ── compute_layout ──────────────────────────────────────────────

    #[test]
    fn layout_basic() {
        let files = make_entries();
        let layout = compute_layout(&files, "TEST").unwrap();
        assert_eq!(layout.label.as_str(), "TEST");
        assert_eq!(layout.path_table_lba, 19);
        assert_eq!(layout.root_dir_lba, 20);
        assert_eq!(layout.extents.len(), 2);
        assert_eq!(layout.extents[0].lba, 21);
        assert_eq!(layout.extents[0].sectors, 1); // 1000 bytes = 1 sector
        assert_eq!(layout.extents[0].size, 1000);
        assert_eq!(layout.extents[1].lba, 22);
        assert_eq!(layout.extents[1].sectors, 2); // 4096 bytes = 2 sectors
        assert_eq!(layout.extents[1].size, 4096);
        assert_eq!(layout.total, 24); // 21 + 1 + 2
    }

    #[test]
    fn layout_empty() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "EMPTY").unwrap();
        assert_eq!(layout.extents.len(), 0);
        assert_eq!(layout.total, 21);
    }

    #[test]
    fn layout_label_truncated() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "A_VERY_LONG_LABEL_NAME").unwrap();
        assert_eq!(layout.label.as_str(), "A_VERY_LONG_LABE");
    }

    #[test]
    fn layout_empty_label_default() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "").unwrap();
        assert_eq!(layout.label.as_str(), "SNOWDRIVE");
    }

    #[test]
    fn layout_label_no_control_chars() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "AB\x01CD").unwrap();
        assert_eq!(layout.label.as_str(), "ABCD");
    }

    #[test]
    fn layout_max_files_ok() {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        for i in 0..MAX_FILES {
            let mut path = String::<512>::new();
            core::fmt::Write::write_fmt(&mut path, format_args!("F{i}.BIN")).unwrap();
            files
                .push(FileEntry {
                    path,
                    size: 100,
                    is_dir: false,
                })
                .unwrap();
        }
        let layout = compute_layout(&files, "MAX").unwrap();
        assert_eq!(layout.extents.len(), MAX_FILES);
    }

    /// Regression: the root directory record table must be allowed to span
    /// multiple sectors (a large flat tree overflows one 2048-byte sector).
    #[test]
    fn layout_root_dir_spans_multiple_sectors() {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        for i in 0..MAX_FILES {
            let mut path = String::<512>::new();
            core::fmt::Write::write_fmt(&mut path, format_args!("F{i:03}.BIN")).unwrap();
            files
                .push(FileEntry {
                    path,
                    size: 100,
                    is_dir: false,
                })
                .unwrap();
        }
        let layout = compute_layout(&files, "BIG").unwrap();
        // 128 records × 33 + UCS-2BE name + pad ≫ 2048.
        assert!(
            layout.root_dir_sectors > 1,
            "root dir should span {} sectors",
            layout.root_dir_sectors
        );
        // File data starts right after the root directory extent.
        assert_eq!(
            layout.extents[0].lba,
            layout.root_dir_lba + layout.root_dir_sectors
        );

        // Every root directory sector must generate without panicking and
        // the first sector must begin with the "." record.
        for i in 0..layout.root_dir_sectors {
            let mut sector = [0u8; 2048];
            assert!(gen_sector(&layout, layout.root_dir_lba + i, &mut sector));
        }
        let mut sector = [0u8; 2048];
        gen_sector(&layout, layout.root_dir_lba, &mut sector);
        assert_eq!(sector[0], 35); // "." record length (33 + 1 name + 1 pad)
        assert_eq!(sector[32], 1); // "." name length
                                   // Sector 0 holds "." and ".." records.
        assert_eq!(sector[35], 35); // ".." record length
                                    // The last root dir sector still carries (parts of) file records.
        let last = layout.root_dir_lba + layout.root_dir_sectors - 1;
        let mut sector = [0u8; 2048];
        gen_sector(&layout, last, &mut sector);
        // A record crosses the sector boundary, so the sector is not empty
        // (it may start mid-record with zero bytes).
        assert!(sector.iter().any(|&b| b != 0));
    }

    #[test]
    fn layout_joliet_name_encoded() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        // README.TXT → UCS-2BE: 00 52 00 45 00 41 00 44 00 4D 00 45 00 2E 00 54 00 58 00 54
        let name = &layout.extents[0].name;
        assert_eq!(name.len(), 20); // 10 chars × 2 bytes
        assert_eq!(name[0], 0x00);
        assert_eq!(name[1], b'R');
        assert_eq!(name[2], 0x00);
        assert_eq!(name[3], b'E');
    }

    // ── total_sectors ───────────────────────────────────────────────

    #[test]
    fn total_sectors_matches() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert_eq!(total_sectors(&layout), layout.total);
    }

    // ── gen_sector ──────────────────────────────────────────────────

    #[test]
    fn gen_pvd() {
        let files = make_entries();
        let layout = compute_layout(&files, "TEST").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, PVD_LBA, &mut sector));
        assert_eq!(sector[0], 0x01);
        assert_eq!(&sector[1..6], b"CD001");
        assert_eq!(sector[6], 0x01);
        assert_eq!(
            u32::from_le_bytes([sector[80], sector[81], sector[82], sector[83]]),
            layout.total
        );
        assert_eq!(u16::from_le_bytes([sector[128], sector[129]]), 2048);
        assert_eq!(
            u32::from_le_bytes([sector[158], sector[159], sector[160], sector[161]]),
            layout.root_dir_lba
        );
    }

    #[test]
    fn gen_svd_joliet() {
        let files = make_entries();
        let layout = compute_layout(&files, "JOL").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, SVD_LBA, &mut sector));
        assert_eq!(sector[0], 0x02);
        assert_eq!(&sector[1..6], b"CD001");
        // Joliet escape sequences
        assert_eq!(sector[88], 0x25);
        assert_eq!(sector[89], 0x2F);
        assert_eq!(sector[90], 0x40);
        // UCS-2BE volume ID "JOL"
        assert_eq!(sector[190], 0x00);
        assert_eq!(sector[191], b'J');
        assert_eq!(sector[192], 0x00);
        assert_eq!(sector[193], b'O');
        assert_eq!(sector[194], 0x00);
        assert_eq!(sector[195], b'L');
    }

    #[test]
    fn gen_terminator() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, TERMINATOR_LBA, &mut sector));
        assert_eq!(sector[0], 0xFF);
        assert_eq!(&sector[1..6], b"CD001");
    }

    #[test]
    fn gen_path_table() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, layout.path_table_lba, &mut sector));
        assert_eq!(sector[0], 0x01); // name length
        assert_eq!(sector[1], 0x00); // ext attr
        assert_eq!(
            u32::from_le_bytes([sector[2], sector[3], sector[4], sector[5]]),
            layout.root_dir_lba
        );
        assert_eq!(u16::from_le_bytes([sector[6], sector[7]]), 1);
        assert_eq!(sector[8], 0x00);
    }

    #[test]
    fn gen_root_directory_dot_entries() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, layout.root_dir_lba, &mut sector));
        // "." entry: name [0x00] is 1 byte (odd) → padding → rec_len = 35
        assert_eq!(sector[0], 35); // 33 + 1 + 1 padding
        assert_eq!(sector[25], 0x02); // directory flag
        assert_eq!(sector[32], 0x01); // name length
        assert_eq!(sector[33], 0x00); // root name
                                      // ".." entry starts at offset 35
        assert_eq!(sector[35], 35);
        assert_eq!(sector[35 + 25], 0x02);
        assert_eq!(sector[35 + 33], 0x01); // parent name
    }

    #[test]
    fn gen_root_directory_file_entries() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, layout.root_dir_lba, &mut sector));
        // "." (35) + ".." (35) = 70 → first file entry at offset 70
        let o = 70;
        assert_eq!(sector[o + 25], 0x00); // file flag
                                          // Extent LBA = 21 (README.TXT)
        assert_eq!(
            u32::from_le_bytes([sector[o + 2], sector[o + 3], sector[o + 4], sector[o + 5]]),
            21
        );
        // Name is Joliet UCS-2BE "README.TXT" (20 bytes)
        assert_eq!(sector[o + 32], 20); // name length
        assert_eq!(sector[o + 33], 0x00); // 'R' high byte
        assert_eq!(sector[o + 34], b'R'); // 'R' low byte
    }

    #[test]
    fn gen_file_data_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, 21, &mut sector));
    }

    #[test]
    fn gen_beyond_image_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, layout.total + 100, &mut sector));
    }

    #[test]
    fn gen_system_area_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, 5, &mut sector));
    }

    // ── resolve ─────────────────────────────────────────────────────

    #[test]
    fn resolve_first_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, 21).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 1000);
    }

    #[test]
    fn resolve_second_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, 22).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 4096);
    }

    #[test]
    fn resolve_second_sector_of_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, 23).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(offset, 2048);
        assert_eq!(remaining, 2048); // 4096 - 2048
    }

    #[test]
    fn resolve_metadata_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, PVD_LBA).is_none());
    }

    #[test]
    fn resolve_system_area_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, 5).is_none());
    }

    #[test]
    fn resolve_beyond_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, layout.total + 100).is_none());
    }

    // ── IsoError ────────────────────────────────────────────────────

    #[test]
    fn iso_error_display() {
        // Verify Display impl doesn't panic (no alloc in no_std, so we
        // can't easily capture the string; just call fmt directly).
        let err = IsoError::TooManyFiles;
        let mut buf = [0u8; 64];
        let mut writer = BufWriter(&mut buf);
        use core::fmt::Write;
        core::fmt::Write::write_fmt(&mut writer, format_args!("{err}")).ok();
        // At least check it wrote something.
        assert!(writer.0.iter().any(|&b| b != 0));
    }

    struct BufWriter<'a>(&'a mut [u8]);
    impl core::fmt::Write for BufWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let len = bytes.len().min(self.0.len());
            self.0[..len].copy_from_slice(&bytes[..len]);
            Ok(())
        }
    }
}
