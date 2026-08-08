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
//! LBA 0-15        System Area (zeros)
//! LBA 16          PVD (Primary Volume Descriptor)
//! LBA 17          SVD (Supplementary Volume Descriptor, Joliet UCS-2BE)
//! LBA 18          Volume Descriptor Set Terminator
//! LBA 19..        Path Table L, then Path Table M (one sector each +
//!                 spillover), sized by the number of directories
//! then            Root directory, sub-directories (breadth-first,
//!                 ECMA-119 §6.9.1 order)
//! then            File data (padded to 2048-byte sectors)
//! ```
//!
//! Every sub-directory becomes its own extent with ".", "..", child
//! directory and file records; the Path Table holds one record per
//! directory (both-endian numeric fields per table type).
//!
//! # Name limits
//!
//! - [`MAX_JOLIET_NAME_CHARS`] — Joliet identifier width (default 32
//!   UCS-2 chars, ECMA-119 Annex J allows 64). Longer names are
//!   truncated in the generated metadata; raise the constant to widen.
//! - [`MAX_PATH_LEN`] — maximum relative host path accepted by the live
//!   scanner (default 512 bytes); deeper paths fail the layout build.
//! - Host FS component names are bounded by `DirEntry.name`
//!   (`String<256>`, the `FsStorage` seam).

use core::cmp::Ordering;
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

/// Maximum number of directories (each `files` entry may be a directory,
/// plus the implicit root).
pub const MAX_DIRS: usize = MAX_FILES + 1;

/// Maximum label length (ASCII chars).
pub const MAX_LABEL_LEN: usize = 16;

/// Maximum length of a Joliet (UCS-2BE) file or directory identifier, in
/// characters.
///
/// ECMA-119 Annex J (Joliet) allows identifiers up to **64** UCS-2
/// characters; this library defaults to **32**. Identifiers longer than
/// this are **truncated** in the generated ISO9660 metadata (the host-side
/// name is untouched). Raise this constant (and rebuild) for wider names;
/// all buffers, record sizes and `Vec` capacities below are derived from
/// it, so no other edit is required.
///
/// The related host-side limits — `DirEntry.name` (`String<256>`, the FS
/// seam) and [`MAX_PATH_LEN`] — sit above this value, so the Joliet
/// identifier width is the binding constraint.
pub const MAX_JOLIET_NAME_CHARS: usize = 32;

/// Byte length of a Joliet identifier (2 bytes per character).
pub const MAX_JOLIET_NAME_BYTES: usize = MAX_JOLIET_NAME_CHARS * 2;

/// Maximum relative path length (bytes) accepted by the live scanner.
///
/// Deeper paths fail to build the layout (`TooManyFiles`) rather than
/// silently truncating. The host `DirEntry.name` capacity (256 bytes)
/// bounds a single component; `MAX_PATH_LEN` bounds the whole relative
/// path.
pub const MAX_PATH_LEN: usize = 512;

/// Largest directory record: 33-byte header + identifier + pad-to-even.
const MAX_DIR_REC_LEN: usize = 33 + MAX_JOLIET_NAME_BYTES + 1;

/// Largest path-table record: 8-byte header + identifier + pad-to-even.
const MAX_PT_REC_LEN: usize = 8 + MAX_JOLIET_NAME_BYTES + 1;

// ── Input types ─────────────────────────────────────────────────────

/// File tree entry provided by the device layer.
///
/// Paths are relative to the root (e.g. `"README.TXT"`, `"DOCS/MANUAL.PDF"`).
/// Directories must appear before their children.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path from root (e.g. `"README.TXT"`, `"SUB/FILE.BIN"`).
    pub path: String<MAX_PATH_LEN>,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
}

// ── Output types ────────────────────────────────────────────────────

/// A directory in the ISO9660 tree (one Path Table record).
#[derive(Debug, Clone)]
pub struct DirNode {
    /// Path table number (1-based; root = 1).
    pub number: u16,
    /// Parent directory's path table number (root's parent = itself, 1).
    pub parent: u16,
    /// Joliet UCS-2BE directory identifier ("" for root).
    pub name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// LBA of this directory's extent.
    pub lba: u32,
    /// Sectors occupied by this directory's records.
    pub sectors: u32,
}

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
    /// Parent directory's path table number.
    pub parent: u16,
}

/// Complete LBA layout for a live ISO9660 image.
#[derive(Debug)]
pub struct Layout {
    /// Volume label (ASCII, up to 16 chars).
    pub label: String<MAX_LABEL_LEN>,
    /// LBA of the Type L path table.
    pub path_table_lba: u32,
    /// Sectors occupied by each path table (L and M have the same size).
    pub path_table_sectors: u32,
    /// Path table size in bytes (one table).
    pub path_table_size: u32,
    /// Root directory LBA.
    pub root_dir_lba: u32,
    /// Number of sectors for the root directory.
    pub root_dir_sectors: u32,
    /// Directories in path-table order (root first, breadth-first).
    pub dirs: Vec<DirNode, MAX_DIRS>,
    /// File extents (one per non-directory FileEntry).
    pub extents: Vec<FileExtent, MAX_FILES>,
    /// LBA where the file data area begins (after all directories).
    pub first_file_lba: u32,
    /// Total number of sectors in the image.
    pub total: u32,
}

// ── Public API ──────────────────────────────────────────────────────

/// Internal directory node during layout construction.
struct DirReg {
    /// Registry index of the parent directory (0 = root's self reference).
    parent: u16,
    /// Joliet UCS-2BE identifier ("" for root).
    name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// Depth in the tree (root = 0).
    depth: u16,
}

/// Number of path components in a relative path ("" → 0, "A/B" → 2).
fn path_depth(path: &str) -> u32 {
    path.split('/').filter(|s| !s.is_empty()).count() as u32
}

/// Last path component ("A/B.txt" → "B.txt", "" → "").
fn last_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

/// Length of a directory record for a name of `name_len` bytes
/// (33 + identifier + pad-to-even, ECMA-119 §9.1.1).
fn record_len(name_len: usize) -> u64 {
    let l = name_len as u64;
    33 + l + (l % 2)
}

/// Compute the LBA layout for a set of files.
///
/// Files must be provided in DFS pre-order: a directory entry before its
/// children, children before the next sibling.  The label is truncated to
/// 16 ASCII characters.  The directory hierarchy is preserved: every
/// sub-directory gets its own extent and a Path Table record.
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

    // ── 1. Build the directory registry (root + every dir entry) ─────
    // The input is DFS pre-order, so the parent of each entry is the top
    // of a stack of open directories, found by popping to the entry's
    // depth.
    let mut regs = Vec::<DirReg, MAX_DIRS>::new();
    regs.push(DirReg {
        parent: 0,
        name: Vec::new(),
        depth: 0,
    })
    .map_err(|_| IsoError::TooManyFiles)?;
    let mut stack = Vec::<u16, MAX_DIRS>::new();
    stack.push(0).map_err(|_| IsoError::TooManyFiles)?;

    let mut extents = Vec::<FileExtent, MAX_FILES>::new();
    // Parent registry index per extent, resolved to a path table number
    // after the directory ordering below.
    let mut ext_parent_reg = Vec::<u16, MAX_FILES>::new();

    for (idx, entry) in files.iter().enumerate() {
        let depth = path_depth(entry.path.as_str());
        let parent_depth = depth.saturating_sub(1) as u16;
        while stack.len() > 1 && regs[*stack.last().unwrap() as usize].depth > parent_depth {
            stack.pop();
        }
        let parent_reg = *stack.last().unwrap();

        if entry.is_dir {
            if regs.len() >= MAX_DIRS {
                return Err(IsoError::TooManyFiles);
            }
            let n = regs.len() as u16;
            let name = to_joliet_name(last_component(entry.path.as_str()));
            regs.push(DirReg {
                parent: parent_reg,
                name,
                depth: depth as u16,
            })
            .map_err(|_| IsoError::TooManyFiles)?;
            stack.push(n).map_err(|_| IsoError::TooManyFiles)?;
        } else {
            let name = to_joliet_name(last_component(entry.path.as_str()));
            extents
                .push(FileExtent {
                    file_index: idx,
                    lba: 0, // assigned below
                    sectors: entry.size.div_ceil(u64::from(SECTOR_SIZE)) as u32,
                    size: entry.size,
                    name,
                    parent: 0, // resolved below
                })
                .map_err(|_| IsoError::TooManyFiles)?;
            ext_parent_reg
                .push(parent_reg)
                .map_err(|_| IsoError::TooManyFiles)?;
        }
    }

    // ── 2. Path table order (ECMA-119 §6.9.1) ────────────────────────
    // Ascending level, then parent directory number, then identifier.
    let max_depth = regs.iter().map(|r| r.depth).max().unwrap_or(0);
    let mut order = Vec::<u16, MAX_DIRS>::new(); // registry indices
    let mut number_of = [0u16; MAX_DIRS]; // registry index → path table number
    for level in 0..=max_depth {
        let mut level_regs = Vec::<u16, MAX_DIRS>::new();
        for (i, r) in regs.iter().enumerate() {
            if r.depth == level {
                level_regs
                    .push(i as u16)
                    .map_err(|_| IsoError::TooManyFiles)?;
            }
        }
        // Insertion sort by (parent number, identifier).
        for i in 1..level_regs.len() {
            let mut j = i;
            while j > 0 {
                let a = level_regs[j - 1] as usize;
                let b = level_regs[j] as usize;
                let pa = number_of[regs[a].parent as usize];
                let pb = number_of[regs[b].parent as usize];
                let cmp = match pa.cmp(&pb) {
                    Ordering::Equal => regs[a].name.cmp(&regs[b].name),
                    other => other,
                };
                if cmp == Ordering::Greater {
                    level_regs.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        for &r in &level_regs {
            number_of[r as usize] = order.len() as u16 + 1;
            order.push(r).map_err(|_| IsoError::TooManyFiles)?;
        }
    }

    // ── 3. Path table size and fixed metadata LBAs ───────────────────
    // Each record: 8 + identifier + pad-to-even (root identifier = 1 byte).
    let mut pt_size: u64 = 0;
    for &r in &order {
        let name_len = if r == 0 {
            1
        } else {
            regs[r as usize].name.len() as u64
        };
        pt_size += 8 + name_len + (name_len % 2);
    }
    let path_table_lba = SYSTEM_AREA_SECTORS + 3; // 19
    let path_table_sectors = pt_size.div_ceil(u64::from(SECTOR_SIZE)) as u32;
    let path_table_m_lba = path_table_lba + path_table_sectors;

    // ── 4. Size each directory, assign directory LBAs ────────────────
    let mut next_lba = path_table_m_lba + path_table_sectors;
    let mut dir_lbas = Vec::<u32, MAX_DIRS>::new();
    let mut dir_sectors = Vec::<u32, MAX_DIRS>::new();
    for (oi, &r) in order.iter().enumerate() {
        let num = oi as u16 + 1;
        let mut bytes: u64 = 70; // "." and ".."
        for &c in &order {
            if c == r {
                continue;
            }
            if number_of[regs[c as usize].parent as usize] == num {
                bytes += record_len(regs[c as usize].name.len());
            }
        }
        for (i, ext) in extents.iter().enumerate() {
            if number_of[ext_parent_reg[i] as usize] == num {
                bytes += record_len(ext.name.len());
            }
        }
        let sectors = bytes.div_ceil(u64::from(SECTOR_SIZE)) as u32;
        dir_lbas
            .push(next_lba)
            .map_err(|_| IsoError::TooManyFiles)?;
        dir_sectors
            .push(sectors)
            .map_err(|_| IsoError::TooManyFiles)?;
        next_lba += sectors;
    }

    // ── 5. File LBAs ─────────────────────────────────────────────────
    for (i, ext) in extents.iter_mut().enumerate() {
        ext.lba = next_lba;
        ext.parent = number_of[ext_parent_reg[i] as usize];
        next_lba += ext.sectors;
    }
    let total = next_lba;
    let first_file_lba = extents.first().map_or(total, |e| e.lba);

    // ── 6. Build the public DirNode list ─────────────────────────────
    let mut dirs = Vec::<DirNode, MAX_DIRS>::new();
    for (oi, &r) in order.iter().enumerate() {
        let is_root = r == 0;
        let name = if is_root {
            Vec::new()
        } else {
            regs[r as usize].name.clone()
        };
        dirs.push(DirNode {
            number: oi as u16 + 1,
            parent: if is_root {
                1
            } else {
                number_of[regs[r as usize].parent as usize]
            },
            name,
            lba: dir_lbas[oi],
            sectors: dir_sectors[oi],
        })
        .map_err(|_| IsoError::TooManyFiles)?;
    }

    let root_dir_lba = dirs[0].lba;
    let root_dir_sectors = dirs[0].sectors;

    Ok(Layout {
        label: lbl,
        path_table_lba,
        path_table_sectors,
        path_table_size: pt_size as u32,
        root_dir_lba,
        root_dir_sectors,
        dirs,
        extents,
        first_file_lba,
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

    let m_lba = layout.path_table_lba + layout.path_table_sectors;
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
        l if l >= layout.path_table_lba && l < m_lba => {
            write_path_table(layout, l, out, false);
            true
        }
        l if l >= m_lba && l < m_lba + layout.path_table_sectors => {
            write_path_table(layout, l, out, true);
            true
        }
        l => {
            for dir in &layout.dirs {
                if l >= dir.lba && l < dir.lba + dir.sectors {
                    write_dir_directory(layout, dir, l, out);
                    return true;
                }
            }
            false
        }
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

/// Encode an ASCII file name to Joliet UCS-2BE (0x00 + char for each ASCII
/// byte). Identifiers longer than [`MAX_JOLIET_NAME_CHARS`] are truncated.
fn to_joliet_name(name: &str) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let mut out = Vec::new();
    for ch in name.chars().take(MAX_JOLIET_NAME_CHARS) {
        if ch.is_ascii() && !ch.is_control() {
            let _ = out.push(0x00);
            let _ = out.push(ch as u8);
        }
    }
    out
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

    // Volume Set Size = 1 (LE 120..122, BE 122..124)
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[122..124].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1 (LE 124..126, BE 126..128)
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[126..128].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048 (LE 128..130, BE 130..132)
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size (LE 132..136, BE 136..140)
    out[132..136].copy_from_slice(&layout.path_table_size.to_le_bytes());
    out[136..140].copy_from_slice(&layout.path_table_size.to_be_bytes());

    // Location of LE Path Table (140..144)
    out[140..144].copy_from_slice(&layout.path_table_lba.to_le_bytes());

    // Location of BE (Type M) Path Table (148..152)
    out[148..152]
        .copy_from_slice(&(layout.path_table_lba + layout.path_table_sectors).to_be_bytes());

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

    // Volume Set Size = 1 (LE 120..122, BE 122..124)
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[122..124].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1 (LE 124..126, BE 126..128)
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[126..128].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048 (LE 128..130, BE 130..132)
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size (LE 132..136, BE 136..140)
    out[132..136].copy_from_slice(&layout.path_table_size.to_le_bytes());
    out[136..140].copy_from_slice(&layout.path_table_size.to_be_bytes());

    // Location of LE Path Table (140..144)
    out[140..144].copy_from_slice(&layout.path_table_lba.to_le_bytes());

    // Location of BE (Type M) Path Table (148..152)
    out[148..152]
        .copy_from_slice(&(layout.path_table_lba + layout.path_table_sectors).to_be_bytes());

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

/// Write one Path Table sector at `lba` (Type L when `is_m` is false,
/// Type M when true).  Only the records overlapping this sector are
/// written; the rest of `out` is zeroed.
fn write_path_table(layout: &Layout, lba: u32, out: &mut [u8], is_m: bool) {
    out.fill(0);
    let table_start = layout.path_table_lba + if is_m { layout.path_table_sectors } else { 0 };
    let sector_start = (lba - table_start) as usize * SECTOR_SIZE as usize;

    let mut offset = 0usize;
    for (i, dir) in layout.dirs.iter().enumerate() {
        let is_root = i == 0;
        // Root identifier is a single 0x00 byte; others use the UCS-2BE name.
        let name: &[u8] = if is_root { &[0x00] } else { &dir.name };
        let name_len = name.len();
        let rec_len = 8 + name_len + (name_len % 2);
        let rec_start = offset;
        offset += rec_len;

        let sect_end = sector_start + out.len();
        if rec_start + rec_len <= sector_start || rec_start >= sect_end {
            continue;
        }

        let mut rec = [0u8; MAX_PT_REC_LEN];
        rec[0] = name_len as u8;
        rec[1] = 0x00; // extended attribute record length
        if is_m {
            rec[2..6].copy_from_slice(&dir.lba.to_be_bytes());
            rec[6..8].copy_from_slice(&dir.parent.to_be_bytes());
        } else {
            rec[2..6].copy_from_slice(&dir.lba.to_le_bytes());
            rec[6..8].copy_from_slice(&dir.parent.to_le_bytes());
        }
        rec[8..8 + name_len].copy_from_slice(name);
        if name_len % 2 == 1 {
            rec[8 + name_len] = 0x00; // pad to even record length
        }

        let from = sector_start.max(rec_start);
        let to = (rec_start + rec_len).min(sect_end);
        out[from - sector_start..to - sector_start]
            .copy_from_slice(&rec[from - rec_start..to - rec_start]);
    }
}

/// Write one directory sector at `lba` (which must lie within `dir`'s
/// extent).
///
/// Contains ".", "..", one record per child directory and one per file
/// (Joliet UCS-2BE names).  Only the records overlapping this sector are
/// written; the rest of `out` is zeroed.
fn write_dir_directory(layout: &Layout, dir: &DirNode, lba: u32, out: &mut [u8]) {
    out.fill(0);
    let sector_start = (lba - dir.lba) as usize * SECTOR_SIZE as usize;

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

        // Build the record into a scratch buffer sized from
        // MAX_JOLIET_NAME_BYTES.
        let mut rec = [0u8; MAX_DIR_REC_LEN];
        write_dir_record(&mut rec[..rec_len], 0, extent_lba, data_len, flags, name);

        let from = sector_start.max(rec_start);
        let to = (rec_start + rec_len).min(sect_end);
        out[from - sector_start..to - sector_start]
            .copy_from_slice(&rec[from - rec_start..to - rec_start]);
    };

    // "." entry (self)
    emit(
        &mut offset,
        dir.lba,
        dir.sectors * SECTOR_SIZE,
        0x02,
        &[0x00],
    );

    // ".." entry (parent; root points to itself)
    let (p_lba, p_sectors) = if dir.number == 1 {
        (dir.lba, dir.sectors)
    } else {
        let parent = layout
            .dirs
            .iter()
            .find(|d| d.number == dir.parent)
            .expect("parent directory present in layout");
        (parent.lba, parent.sectors)
    };
    emit(&mut offset, p_lba, p_sectors * SECTOR_SIZE, 0x02, &[0x01]);

    // Child directories.
    for child in &layout.dirs {
        if child.number != dir.number && child.parent == dir.number {
            emit(
                &mut offset,
                child.lba,
                child.sectors * SECTOR_SIZE,
                0x02,
                &child.name,
            );
        }
    }

    // File entries: data length = actual file size (ECMA-119 §9.1.5).
    for extent in &layout.extents {
        if extent.parent == dir.number {
            emit(
                &mut offset,
                extent.lba,
                extent.size as u32,
                0x00,
                &extent.name,
            );
        }
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
                       // Location of Extent (both-endian: LE 2..6, BE 6..10)
    out[o + 2..o + 6].copy_from_slice(&extent_lba.to_le_bytes());
    out[o + 6..o + 10].copy_from_slice(&extent_lba.to_be_bytes());
    // Data Length (both-endian: LE 10..14, BE 14..18)
    out[o + 10..o + 14].copy_from_slice(&data_len.to_le_bytes());
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
    out[o + 6..o + 10].copy_from_slice(&root_lba.to_be_bytes());
    out[o + 10..o + 14].copy_from_slice(&data_len.to_le_bytes());
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
        let mut p = String::<MAX_PATH_LEN>::new();
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

    /// Nested tree in DFS pre-order: root file, DOCS dir + child, TOOLS
    /// dir + children (one nested SUB).
    fn make_tree() -> Vec<FileEntry, MAX_FILES> {
        let mut v = Vec::new();
        v.push(make_entry("README.TXT", 1000, false)).unwrap();
        v.push(make_entry("DOCS", 0, true)).unwrap();
        v.push(make_entry("DOCS/MANUAL.PDF", 2000, false)).unwrap();
        v.push(make_entry("TOOLS", 0, true)).unwrap();
        v.push(make_entry("TOOLS/SETUP.EXE", 3000, false)).unwrap();
        v.push(make_entry("TOOLS/SUB", 0, true)).unwrap();
        v.push(make_entry("TOOLS/SUB/X.BIN", 100, false)).unwrap();
        v
    }

    // ── compute_layout ──────────────────────────────────────────────

    #[test]
    fn layout_basic() {
        let files = make_entries();
        let layout = compute_layout(&files, "TEST").unwrap();
        assert_eq!(layout.label.as_str(), "TEST");
        assert_eq!(layout.path_table_lba, 19);
        assert_eq!(layout.root_dir_lba, 21); // 16-18 desc, 19 PT-L, 20 PT-M
        assert_eq!(layout.dirs.len(), 1); // root only
        assert_eq!(layout.extents.len(), 2);
        assert_eq!(layout.extents[0].lba, 22);
        assert_eq!(layout.extents[0].sectors, 1); // 1000 bytes = 1 sector
        assert_eq!(layout.extents[0].size, 1000);
        assert_eq!(layout.extents[1].lba, 23);
        assert_eq!(layout.extents[1].sectors, 2); // 4096 bytes = 2 sectors
        assert_eq!(layout.extents[1].size, 4096);
        assert_eq!(layout.total, 25); // 21 + 1 + 2
        assert_eq!(layout.first_file_lba, 22);
    }

    #[test]
    fn layout_empty() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "EMPTY").unwrap();
        assert_eq!(layout.extents.len(), 0);
        assert_eq!(layout.dirs.len(), 1);
        assert_eq!(layout.total, 22); // 16-18 desc, 19 PT-L, 20 PT-M, 21 root
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
            let mut path = String::<MAX_PATH_LEN>::new();
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
            let mut path = String::<MAX_PATH_LEN>::new();
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

    /// Names longer than MAX_JOLIET_NAME_CHARS are truncated in the ISO
    /// metadata (documented limit); shorter names pass through whole.
    #[test]
    fn joliet_name_truncated_at_max_chars() {
        // Exactly MAX_JOLIET_NAME_CHARS 'A's: preserved whole.
        let exact: std::string::String = "A".repeat(MAX_JOLIET_NAME_CHARS);
        let n = to_joliet_name(&exact);
        assert_eq!(n.len(), MAX_JOLIET_NAME_BYTES);
        // One char over: truncated to MAX_JOLIET_NAME_CHARS.
        let over: std::string::String = "B".repeat(MAX_JOLIET_NAME_CHARS + 1);
        let n = to_joliet_name(&over);
        assert_eq!(n.len(), MAX_JOLIET_NAME_BYTES);
        // Non-ASCII characters are skipped (not counted toward the limit).
        let mixed = "AB\u{4e2d}CD";
        let n = to_joliet_name(mixed);
        assert_eq!(n.len(), 8); // 'A','B','C','D'
    }

    // ── sub-directory hierarchy ──────────────────────────────────────

    #[test]
    fn layout_preserves_subdirectories() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        // root + DOCS + TOOLS + SUB = 4 directories.
        assert_eq!(layout.dirs.len(), 4);
        assert_eq!(layout.dirs[0].number, 1); // root
        assert_eq!(layout.dirs[0].parent, 1); // root points to itself
        assert_eq!(layout.dirs[0].lba, 21);
        // Level 1 sorted by name: DOCS (2) before TOOLS (3).
        assert_eq!(layout.dirs[1].number, 2);
        assert_eq!(
            layout.dirs[1].name.as_slice(),
            [0, b'D', 0, b'O', 0, b'C', 0, b'S']
        );
        assert_eq!(layout.dirs[2].number, 3);
        assert_eq!(
            layout.dirs[2].name.as_slice(),
            [0, b'T', 0, b'O', 0, b'O', 0, b'L', 0, b'S']
        );
        // SUB is a level-2 directory whose parent is TOOLS (3).
        assert_eq!(layout.dirs[3].number, 4);
        assert_eq!(layout.dirs[3].parent, 3);
        // Directory LBAs: root 21, DOCS 22, TOOLS 23, SUB 24.
        assert_eq!(layout.dirs[1].lba, 22);
        assert_eq!(layout.dirs[2].lba, 23);
        assert_eq!(layout.dirs[3].lba, 24);
        // Files are assigned after all directories, each under its parent.
        assert_eq!(layout.first_file_lba, 25);
        assert_eq!(layout.extents.len(), 4);
        assert_eq!(layout.extents[0].parent, 1); // README.TXT
        assert_eq!(layout.extents[1].parent, 2); // DOCS/MANUAL.PDF
        assert_eq!(layout.extents[2].parent, 3); // TOOLS/SETUP.EXE
        assert_eq!(layout.extents[3].parent, 4); // TOOLS/SUB/X.BIN
        assert_eq!(layout.extents[0].lba, 25);
        assert_eq!(layout.extents[1].lba, 26);
        assert_eq!(layout.extents[2].lba, 27);
        assert_eq!(layout.extents[2].sectors, 2); // 3000 bytes = 2 sectors
        assert_eq!(layout.extents[3].lba, 29);
        assert_eq!(layout.total, 30);
    }

    #[test]
    fn gen_path_table_has_all_dirs() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        let mut l = [0u8; 2048];
        let mut m = [0u8; 2048];
        assert!(gen_sector(&layout, layout.path_table_lba, &mut l));
        assert!(gen_sector(
            &layout,
            layout.path_table_lba + layout.path_table_sectors,
            &mut m
        ));

        // Type L record 1 (root): name len 1, location = root, parent = 1.
        let o0 = 0usize;
        assert_eq!(l[o0], 1);
        assert_eq!(
            u32::from_le_bytes(l[o0 + 2..o0 + 6].try_into().unwrap()),
            layout.root_dir_lba
        );
        assert_eq!(u16::from_le_bytes(l[o0 + 6..o0 + 8].try_into().unwrap()), 1);
        assert_eq!(l[o0 + 8], 0x00);

        // Type L record 2 (DOCS): name "DOCS" (8 bytes), lba 22, parent 1.
        let o1 = 10usize;
        assert_eq!(l[o1], 8);
        assert_eq!(
            u32::from_le_bytes(l[o1 + 2..o1 + 6].try_into().unwrap()),
            22
        );
        assert_eq!(u16::from_le_bytes(l[o1 + 6..o1 + 8].try_into().unwrap()), 1);
        assert_eq!(&l[o1 + 8..o1 + 16], &[0, b'D', 0, b'O', 0, b'C', 0, b'S']);

        // Type M table holds the same records with big-endian fields.
        assert_eq!(m[0], 1);
        assert_eq!(
            u32::from_be_bytes(m[0 + 2..0 + 6].try_into().unwrap()),
            layout.root_dir_lba
        );
        assert_eq!(u16::from_be_bytes(m[0 + 6..0 + 8].try_into().unwrap()), 1);
        let o1 = 10usize;
        assert_eq!(
            u32::from_be_bytes(m[o1 + 2..o1 + 6].try_into().unwrap()),
            22
        );
        assert_eq!(u16::from_be_bytes(m[o1 + 6..o1 + 8].try_into().unwrap()), 1);
        assert_eq!(&m[o1 + 8..o1 + 16], &[0, b'D', 0, b'O', 0, b'C', 0, b'S']);

        // SUB record (4th; offsets 10 + 16 + 18 = 44): name "SUB", parent 3.
        let o3 = 44usize;
        assert_eq!(l[o3], 6);
        assert_eq!(u16::from_le_bytes(l[o3 + 6..o3 + 8].try_into().unwrap()), 3);
        assert_eq!(&l[o3 + 8..o3 + 14], &[0, b'S', 0, b'U', 0, b'B']);
    }

    #[test]
    fn gen_subdir_directory_records() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        // SUB (number 4, lba 24): ".", ".." (→ TOOLS), X.BIN.
        let sub = layout.dirs[3].clone();
        let tools = layout.dirs[2].clone();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, sub.lba, &mut sector));
        // "." record: lba = SUB's own lba.
        assert_eq!(sector[0], 35);
        assert_eq!(
            u32::from_le_bytes(sector[2..6].try_into().unwrap()),
            sub.lba
        );
        // ".." points to SUB's parent, TOOLS.
        assert_eq!(
            u32::from_le_bytes(sector[37..41].try_into().unwrap()),
            tools.lba
        );
        // X.BIN is a file (flag 0x00) and the only non-dot record.
        let mut off = 70usize;
        let mut saw_file = false;
        while off < 2048 && sector[off] != 0 {
            let flags = sector[off + 25];
            if flags == 0x00 {
                saw_file = true;
            }
            off += sector[off] as usize;
        }
        assert!(saw_file, "expected the X.BIN file record");
        // No child directory records in a leaf directory.
        let mut off = 70usize;
        while off < 2048 && sector[off] != 0 {
            assert_ne!(sector[off + 25], 0x02, "leaf dir must not list a child dir");
            off += sector[off] as usize;
        }
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
                                          // Extent LBA = first file (README.TXT)
        assert_eq!(
            u32::from_le_bytes([sector[o + 2], sector[o + 3], sector[o + 4], sector[o + 5]]),
            layout.extents[0].lba
        );
        // Name is Joliet UCS-2BE "README.TXT" (20 bytes)
        assert_eq!(sector[o + 32], 20); // name length
        assert_eq!(sector[o + 33], 0x00); // 'R' high byte
        assert_eq!(sector[o + 34], b'R'); // 'R' low byte
    }

    /// ECMA-119 §9.1: both-endian extent LBA and data length must sit at
    /// record offsets 2/6 and 10/14 respectively. A previous swap put the
    /// data length at 6..10 and the LBA big-endian half at 10..14, so
    /// readers (kernel/isoinfo) reported garbage sizes and corrupted
    /// directory entries.
    #[test]
    fn dir_record_both_endian_layout() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        gen_sector(&layout, layout.root_dir_lba, &mut sector);
        let o = 70; // first file record ("README.TXT", 1000 B)
                    // LBA: LE at 2..6, BE at 6..10.
        assert_eq!(
            u32::from_le_bytes(sector[o + 2..o + 6].try_into().unwrap()),
            layout.extents[0].lba
        );
        assert_eq!(
            u32::from_be_bytes(sector[o + 6..o + 10].try_into().unwrap()),
            layout.extents[0].lba
        );
        // Data length (actual file size): LE at 10..14, BE at 14..18.
        assert_eq!(
            u32::from_le_bytes(sector[o + 10..o + 14].try_into().unwrap()),
            1000
        );
        assert_eq!(
            u32::from_be_bytes(sector[o + 14..o + 18].try_into().unwrap()),
            1000
        );
    }

    /// PVD/SVD both-endian 16-bit fields must be interleaved (LE then BE
    /// within the same 4-byte slot), not shifted by a full 4 bytes.
    #[test]
    fn pvd_both_endian_16bit_fields() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        gen_sector(&layout, PVD_LBA, &mut sector);
        // Volume set size (120..124), volume seq number (124..128),
        // logical block size (128..132).
        assert_eq!(u16::from_le_bytes(sector[120..122].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(sector[122..124].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(sector[124..126].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(sector[126..128].try_into().unwrap()), 1);
        assert_eq!(
            u16::from_le_bytes(sector[128..130].try_into().unwrap()),
            SECTOR_SIZE as u16
        );
        assert_eq!(
            u16::from_be_bytes(sector[130..132].try_into().unwrap()),
            SECTOR_SIZE as u16
        );
        // Path table size (132..140): 10 bytes.
        assert_eq!(u32::from_le_bytes(sector[132..136].try_into().unwrap()), 10);
        assert_eq!(u32::from_be_bytes(sector[136..140].try_into().unwrap()), 10);
        // SVD uses the same layout.
        gen_sector(&layout, SVD_LBA, &mut sector);
        assert_eq!(
            u16::from_le_bytes(sector[128..130].try_into().unwrap()),
            2048
        );
        assert_eq!(
            u16::from_be_bytes(sector[130..132].try_into().unwrap()),
            2048
        );
    }

    #[test]
    fn gen_file_data_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, layout.first_file_lba, &mut sector));
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
        let (idx, offset, remaining) = resolve(&layout, layout.extents[0].lba).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 1000);
    }

    #[test]
    fn resolve_second_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, layout.extents[1].lba).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 4096);
    }

    #[test]
    fn resolve_second_sector_of_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, layout.extents[1].lba + 1).unwrap();
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
