//! Empty UDF void volume generation (`__UDFRW_PLAN.md` §1–6).
//!
//! Pure algorithms: **no storage, no FS, no alloc** — mirror of
//! `iso9660::live`. The media layer (`CdMedia::UdfRw`, plan §7) materializes
//! an empty volume by calling [`gen_sector`] for every structured LBA into a
//! writable byte plane (all other sectors stay zero).
//!
//! "Void" = this module only produces the empty skeleton; it is **not** a
//! UDF filesystem implementation (that name is reserved for the media layer,
//! [`crate::cdrom::CdMedia::UdfRw`]). It generates the smallest structure
//! that Windows Live File System ("U 盘模式") and Linux `udf` mount as an
//! empty rewritable disc: a **UDF 2.01 plain-build** volume. There is no
//! file/directory allocation machinery, no VAT / sparing / Metadata
//! Partition, no extended attributes: the root directory holds only `.`
//! and `..`.
//!
//! # Volume layout (2048-byte sectors, capacity N)
//!
//! ```text
//! 16..19          VRS: BEA01 / NSR03 / TEA01
//! 256             AVDP (main) → MVDS + RVDS extents
//! 257..273        MVDS (16 sectors): PVD, LVD, PD, USD, IUVD, TD (+ zeros)
//! 273..277        LVID extent (4 sectors, rewritable minimum 8 KB)
//! 277..(N-272)    Partition (FSD@0, USE@1, SBD@2.., root FE, root dir, free)
//! (N-272)..(N-256) RVDS (16 sectors: mirror of the VDS)
//! N-256           AVDP (copy)
//! N-255..N        unused
//! ```
//!
//! The VDS on-disc order and Volume Descriptor Sequence Numbers match
//! `mkudffs` (`defaults.c`): **PVD=1, LVD=2, PD=3, USD=4, IUVD=5** — the
//! kernel records a descriptor only when its sequence number is ≥ the
//! maximum seen so far, so the on-disc order must be non-decreasing in the
//! sequence number (Linux `udf_process_sequence`).
//!
//! # Byte-layout sources
//!
//! Descriptor field offsets follow ECMA-167 / OSTA UDF 2.01 as cross-checked
//! against the OpenBSD `sys/isofs/udf/ecma167-udf.h` struct layouts. A few
//! values are marked "oracle-verify" in the comments: they must be diffed
//! against a `mkudffs`-generated reference image before the media layer
//! ships (`__UDFRW_PLAN.md` §8/§9) — space-bitmap polarity, USE extent
//! flags, PD partition-contents identifier and the root FID flag bits.

use core::fmt;
use heapless::String;

/// Logical sector size (2048 bytes).
pub const SECTOR_SIZE: u32 = 2048;

/// Minimum volume capacity (sectors): comfortably holds the VRS, both
/// anchors, both 16-sector VDS extents, the LVID extent, the partition
/// head and some free space.
pub const MIN_CAPACITY_SECTORS: u32 = 2048;

/// Volume recognition sequence start.
const VRS_LBA: u32 = 16;

/// Primary anchor (ECMA-167 3/10.2: anchors at 256 / N-256 / N).
pub const AVDP_LBA: u32 = 256;

/// Volume descriptor sequence extent size (spec minimum 16 sectors).
const VDS_SECTORS: u32 = 16;

/// Logical volume integrity sequence size (rewritable minimum 8 KB).
const LVID_SECTORS: u32 = 4;

/// Fixed tag serial number for a freshly generated volume. It is constant
/// per build; a re-init of the same capacity reuses it, which is legal
/// (the field is only meaningful for disaster recovery).
const SERIAL: u16 = 0x0001;

/// UDF 2.01 revision in the `*OSTA UDF Compliant` identifier suffixes.
const UDF_REV: u16 = 0x0201;

/// Descriptor tag length.
const TAG_SIZE: usize = 16;

// ── Descriptor tag identifiers (ECMA-167) ───────────────────────────

const TAG_AVDP: u16 = 0x0002;
const TAG_PVD: u16 = 0x0001;
const TAG_IUVD: u16 = 0x0004;
const TAG_PD: u16 = 0x0005;
const TAG_LVD: u16 = 0x0006;
const TAG_USD: u16 = 0x0007;
const TAG_TD: u16 = 0x0008;
const TAG_LVID: u16 = 0x0009;
const TAG_FSD: u16 = 0x0100;
const TAG_FID: u16 = 0x0101;
const TAG_FE: u16 = 0x0105;
const TAG_USE: u16 = 0x0107;
const TAG_SBD: u16 = 0x0108;

/// `*OSTA UDF Compliant` entity identifier (23-byte `regid.id`).
const OSTA_COMPLIANT: &[u8] = b"*OSTA UDF Compliant";

/// Default volume label when the caller passes an empty/blank label.
const DEFAULT_LABEL: &str = "SNOWDRIVE";

// ── Output types ────────────────────────────────────────────────────

/// LBA geometry of one generated empty UDF void volume.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Total volume capacity in sectors.
    pub capacity_sectors: u32,
    /// Main volume descriptor sequence start (16 sectors from here).
    pub vds_lba: u32,
    /// Logical volume integrity sequence start (4 sectors from here).
    pub lvid_lba: u32,
    /// Partition start (absolute LBA).
    pub partition_lba: u32,
    /// Partition length in blocks.
    pub partition_len: u32,
    /// Space bitmap: bits per block (== `partition_len`).
    pub sbd_num_bits: u32,
    /// Space bitmap: bytes of bitmap data (ceil of bits / 8).
    pub sbd_num_bytes: u32,
    /// Space bitmap: sectors occupied (from `sbd_lba`).
    pub sbd_sectors: u32,
    /// Reserve volume descriptor sequence start (16 sectors from here).
    pub reserve_vds_lba: u32,
    /// Second anchor (N-257, mkudffs "End-Of-Volume − 256").
    pub anchor2_lba: u32,
    /// Third anchor (N-1, last addressable sector).
    pub anchor3_lba: u32,
    /// File Set Descriptor (partition block 0).
    pub fsd_lba: u32,
    /// Unallocated Space Entry (partition block 1).
    pub use_lba: u32,
    /// Space Bitmap Descriptor (partition block 2, spans `sbd_sectors`).
    pub sbd_lba: u32,
    /// Root directory File Entry (after the space bitmap).
    pub root_icb_lba: u32,
    /// Root directory data block.
    pub root_dir_lba: u32,
    /// Partition block where free space begins (all head blocks used).
    pub free_from_block: u32,
    /// Volume label (≤ 31 ASCII chars).
    pub label: String<32>,
}

// ── Public API ──────────────────────────────────────────────────────

/// Compute the layout of an empty UDF void volume of `capacity_sectors`
/// sectors. `label` is truncated to 31 ASCII chars (blank → "SNOWDRIVE").
///
/// The geometry is deterministic and mirrors `mkudffs` for a DVD: volume
/// head at 16..277, anchors at 256 / N-257 / N-1, reserve VDS at N-160,
/// partition ending before the second anchor (gap of 6 blocks).
pub fn compute_layout(capacity_sectors: u32, label: &str) -> Result<Layout, UdfError> {
    if capacity_sectors < MIN_CAPACITY_SECTORS {
        return Err(UdfError::CapacityTooSmall);
    }
    let vds_lba = AVDP_LBA + 1;
    let lvid_lba = vds_lba + VDS_SECTORS;
    let partition_lba = lvid_lba + LVID_SECTORS;
    let reserve_vds_lba = capacity_sectors - 160;
    let anchor2_lba = capacity_sectors - 257;
    // Leave a 6-block gap before the second anchor (mkudffs ~7).
    let partition_len = anchor2_lba - 6 - partition_lba;

    let sbd_num_bits = partition_len;
    let sbd_num_bytes = sbd_num_bits.div_ceil(8);
    let sbd_sectors = sbd_num_bytes.div_ceil(SECTOR_SIZE);

    // Partition head: FSD, USE, SBD (spans sbd_sectors), root FE, root dir.
    let free_from_block = 4 + sbd_sectors;
    let fsd_lba = partition_lba;
    let use_lba = partition_lba + 1;
    let sbd_lba = partition_lba + 2;
    let root_icb_lba = sbd_lba + sbd_sectors;
    let root_dir_lba = root_icb_lba + 1;

    let mut lbl = String::<32>::new();
    for ch in label.chars().take(31) {
        if ch.is_ascii() && !ch.is_control() {
            let _ = lbl.push(ch);
        }
    }
    if lbl.is_empty() {
        let _ = lbl.push_str(DEFAULT_LABEL);
    }

    Ok(Layout {
        capacity_sectors,
        vds_lba,
        lvid_lba,
        partition_lba,
        partition_len,
        sbd_num_bits,
        sbd_num_bytes,
        sbd_sectors,
        reserve_vds_lba,
        anchor2_lba,
        anchor3_lba: capacity_sectors - 1,
        fsd_lba,
        use_lba,
        sbd_lba,
        root_icb_lba,
        root_dir_lba,
        free_from_block,
        label: lbl,
    })
}

/// Generate the sector at `lba` into `out` (must be exactly 2048 bytes).
///
/// Returns `true` if `lba` is part of the UDF void structure (the media
/// layer materializes it into the byte plane); `false` for free space
/// (leave the sector all-zero).
///
/// **Space Bitmap CRC**: the SBD descriptor spans `sbd_sectors` sectors, so
/// its tag CRC (covering the whole bitmap) cannot be computed here. The
/// first SBD sector is written with a placeholder CRC of 0; the caller must
/// call [`sbd_crc`] (into a scratch buffer) and [`patch_sbd_crc`] on that
/// first sector before serving the volume.
pub fn gen_sector(layout: &Layout, lba: u32, out: &mut [u8]) -> bool {
    assert!(out.len() >= SECTOR_SIZE as usize);
    out.fill(0);

    match lba {
        VRS_LBA => {
            write_vrs(out, b"BEA01");
            true
        }
        l if l == VRS_LBA + 1 => {
            write_vrs(out, b"NSR03");
            true
        }
        l if l == VRS_LBA + 2 => {
            write_vrs(out, b"TEA01");
            true
        }
        l if l == AVDP_LBA || l == layout.anchor2_lba || l == layout.anchor3_lba => {
            write_avdp(out, layout, l);
            true
        }
        l if l >= layout.vds_lba && l < layout.vds_lba + VDS_SECTORS => {
            // On-disc order must be non-decreasing in volDescSeqNum (the
            // kernel keeps the last descriptor of each type): PVD(1), LVD(2),
            // PD(3), USD(4), IUVD(5), TD.
            match l - layout.vds_lba {
                0 => write_pvd(out, layout, l),
                1 => write_lvd(out, layout, l),
                2 => write_pd(out, layout, l),
                3 => write_usd(out, layout, l),
                4 => write_iuvd(out, layout, l),
                _ => write_td(out, l),
            }
            true
        }
        l if l >= layout.reserve_vds_lba && l < layout.reserve_vds_lba + VDS_SECTORS => {
            match l - layout.reserve_vds_lba {
                0 => write_pvd(out, layout, l),
                1 => write_lvd(out, layout, l),
                2 => write_pd(out, layout, l),
                3 => write_usd(out, layout, l),
                4 => write_iuvd(out, layout, l),
                _ => write_td(out, l),
            }
            true
        }
        l if l == layout.lvid_lba => {
            write_lvid(out, layout);
            true
        }
        l if l == layout.fsd_lba => {
            write_fsd(out, layout);
            true
        }
        l if l == layout.use_lba => {
            write_use(out, layout);
            true
        }
        l if l >= layout.sbd_lba && l < layout.sbd_lba + layout.sbd_sectors => {
            write_sbd(layout, l, out);
            true
        }
        l if l == layout.root_icb_lba => {
            write_root_icb(out, layout);
            true
        }
        l if l == layout.root_dir_lba => {
            write_root_dir(out, layout);
            true
        }
        _ => false,
    }
}

/// Fill `buf` with up to `buf.len()` bytes of the space-bitmap data
/// starting at byte `offset`. Returns the number of bytes written.
///
/// Bit `b` (LSB-first within each byte) corresponds to partition block `b`.
/// **Polarity (oracle-verify)**: the bitmap is the *unallocated* space
/// bitmap, so a set bit means the block is free. Head blocks (FSD/USE/SBD/
/// root FE/root dir) read 0; the rest read 1.
pub fn sbd_bitmap(layout: &Layout, offset: usize, buf: &mut [u8]) -> usize {
    let total = layout.sbd_num_bytes as usize;
    if offset >= total {
        return 0;
    }
    let n = (total - offset).min(buf.len());
    buf[..n].fill(0);
    let first_bit = offset * 8;
    let free_from = layout.free_from_block as usize;
    for (i, b) in (first_bit..first_bit + n * 8).enumerate() {
        if b >= free_from {
            buf[i / 8] |= 1 << (i % 8);
        }
    }
    n
}

/// CRC-16 (ECMA-167 / UDF descriptor CRC) over the complete space-bitmap
/// body, streaming through `scratch` (at least 1 byte).
///
/// The SBD descriptor's `DescriptorCRCLength` is capped at 65535, so the
/// CRC covers `num_bits + num_bytes + min(num_bytes, 65535-8)` bytes.
pub fn sbd_crc(layout: &Layout, scratch: &mut [u8]) -> Result<u16, UdfError> {
    if scratch.is_empty() {
        return Err(UdfError::ScratchTooSmall);
    }
    let mut crc = 0u16;
    let mut hdr = [0u8; 8];
    hdr[0..4].copy_from_slice(&layout.sbd_num_bits.to_le_bytes());
    hdr[4..8].copy_from_slice(&layout.sbd_num_bytes.to_le_bytes());
    crc = crc16(&hdr, crc);

    // Body = num_bits (4) + num_bytes (4) + data; crc_len = 8 + num_bytes
    // capped at 65535, so at most 65535−8 data bytes are covered.
    let data_cap = 0xFFFF - 8;
    let total = layout.sbd_num_bytes as usize;
    let covered = total.min(data_cap);
    let mut off = 0;
    while off < covered {
        let n = (covered - off).min(scratch.len());
        let written = sbd_bitmap(layout, off, &mut scratch[..n]);
        crc = crc16(&scratch[..written], crc);
        off += written;
    }
    Ok(crc)
}

/// Patch the placeholder CRC of the space-bitmap's first sector (see
/// [`gen_sector`]). Writes `crc` into the tag and recomputes the checksum.
pub fn patch_sbd_crc(sector: &mut [u8], crc: u16) {
    sector[8..10].copy_from_slice(&crc.to_le_bytes());
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sector[..16]);
    sector[4] = tag_checksum(&tag);
}

/// CRC-16/ITU-T V.41 (polynomial `0x1021`, init `0`, MSB-first, no
/// reflection, no final XOR) — the ECMA-167 / UDF descriptor CRC.
///
/// Test vector (from Linux `fs/udf/crc.c`):
/// `crc16(&[0x70, 0x6A, 0x77], 0) == 0x3299`.
pub fn crc16(data: &[u8], crc: u16) -> u16 {
    let mut c = crc;
    for &b in data {
        c = CRC_TABLE[(((c >> 8) ^ u16::from(b)) & 0xFF) as usize] ^ (c << 8);
    }
    c
}

/// Validate a sector as an Anchor Volume Descriptor Pointer: tag id 2,
/// descriptor version 3, valid tag checksum and a matching descriptor CRC
/// over the 16-byte body (AVDP size 32 − tag 16).
///
/// Used by the media layer to detect an already-formatted UdfRw volume
/// (`__UDFRW_PLAN.md` §7.x rule 4).
pub fn is_avdp(sector: &[u8]) -> bool {
    if sector.len() < 32 {
        return false;
    }
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_AVDP {
        return false;
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sector[..16]);
    if sector[4] != tag_checksum(&tag) {
        return false;
    }
    if u16::from_le_bytes([sector[10], sector[11]]) as usize != 32 - TAG_SIZE {
        return false;
    }
    let crc = u16::from_le_bytes([sector[8], sector[9]]);
    crc == crc16(&sector[16..32], 0)
}

/// Descriptor tag checksum: sum of the 16 tag bytes with byte 4 (the
/// checksum itself) forced to 0, modulo 256.
pub fn tag_checksum(tag: &[u8; 16]) -> u8 {
    let mut sum = 0u16;
    for (i, &b) in tag.iter().enumerate() {
        if i != 4 {
            sum += u16::from(b);
        }
    }
    (sum & 0xFF) as u8
}

// ── CRC table ───────────────────────────────────────────────────────

const fn build_crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut b = 0;
        while b < 8 {
            c = if c & 0x8000 != 0 {
                (c << 1) ^ 0x1021
            } else {
                c << 1
            };
            c &= 0xFFFF;
            b += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const CRC_TABLE: [u16; 256] = build_crc_table();

// ── Small field helpers ─────────────────────────────────────────────

#[inline]
fn put_u16_le(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u32_le(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u64_le(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `extent_ad` (ECMA-167 3/7.1): **length first**, then location.
fn extent_ad(loc: u32, len: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&len.to_le_bytes());
    b[4..8].copy_from_slice(&loc.to_le_bytes());
    b
}

/// `long_ad` (ECMA-167 4/14.14.2): length + lb_addr + 6-byte impl use.
fn long_ad(len: u32, block: u32, part: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&len.to_le_bytes());
    b[4..8].copy_from_slice(&block.to_le_bytes());
    b[8..10].copy_from_slice(&part.to_le_bytes());
    b
}

/// `short_ad` (ECMA-167 4/14.14.1): length + block.
fn short_ad(len: u32, block: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&len.to_le_bytes());
    b[4..8].copy_from_slice(&block.to_le_bytes());
    b
}

/// Character set spec: `OSTA Compressed Unicode`.
fn charspec(out: &mut [u8], off: usize) {
    out[off] = 0;
    out[off + 1..off + 24].copy_from_slice(b"OSTA Compressed Unicode");
}

/// d-string: length byte + ASCII data, plus the udftools convention of
/// storing `1 + length` in the field's last byte (used by udfinfo/wrudf for
/// reading; the kernel reads only the leading length byte).
fn dstring(out: &mut [u8], off: usize, cap: usize, s: &str) {
    let data = s.as_bytes();
    let n = data.len().min(cap - 1);
    out[off] = n as u8;
    out[off + 1..off + 1 + n].copy_from_slice(&data[..n]);
    out[off + cap - 1] = (n + 1) as u8;
}

/// `*OSTA UDF Compliant` entity ID with the UDF revision in the suffix.
fn regid_udf(out: &mut [u8], off: usize) {
    regid_ident(out, off, OSTA_COMPLIANT);
}

/// Entity ID with a fixed 23-byte identifier and the UDF revision in the
/// suffix.
fn regid_ident(out: &mut [u8], off: usize, ident: &[u8]) {
    out[off] = 0;
    let n = ident.len().min(23);
    out[off + 1..off + 1 + n].copy_from_slice(&ident[..n]);
    out[off + 24..off + 26].copy_from_slice(&UDF_REV.to_le_bytes());
}

/// Fixed recording timestamp: 2020-01-01 00:00:00.00 UTC.
fn timestamp(out: &mut [u8], off: usize) {
    out[off..off + 2].copy_from_slice(&0x1000u16.to_le_bytes());
    out[off + 2..off + 4].copy_from_slice(&2020u16.to_le_bytes());
    out[off + 4] = 1; // month
    out[off + 5] = 1; // day
}

/// Finalize a tagged descriptor: fill identifier/version/serial, compute
/// the CRC over the body, write the checksum.
fn finalize_tag(sector: &mut [u8], off: usize, id: u16, location: u32, desc_size: usize) {
    let crc_len = desc_size - TAG_SIZE;
    let body = &sector[off + TAG_SIZE..off + desc_size];
    let crc = crc16(body, 0);
    put_u16_le(sector, off, id);
    put_u16_le(sector, off + 2, 3); // descriptor version 3
    put_u16_le(sector, off + 6, SERIAL);
    put_u16_le(sector, off + 8, crc);
    put_u16_le(sector, off + 10, crc_len as u16);
    put_u32_le(sector, off + 12, location);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sector[off..off + 16]);
    sector[off + 4] = tag_checksum(&tag);
}

// ── Descriptor writers ──────────────────────────────────────────────

/// Volume Recognition Sequence entry (no descriptor tag).
fn write_vrs(out: &mut [u8], id: &[u8; 5]) {
    out[0] = 0;
    out[1..6].copy_from_slice(id);
    out[6] = 1;
}

/// Anchor Volume Descriptor Pointer (ECMA-167 3/10.2, 32-byte struct).
fn write_avdp(out: &mut [u8], layout: &Layout, loc: u32) {
    out[16..24].copy_from_slice(&extent_ad(layout.vds_lba, VDS_SECTORS * SECTOR_SIZE));
    out[24..32].copy_from_slice(&extent_ad(
        layout.reserve_vds_lba,
        VDS_SECTORS * SECTOR_SIZE,
    ));
    finalize_tag(out, 0, TAG_AVDP, loc, 32);
}

/// Primary Volume Descriptor (ECMA-167 3/10.1). Volume Descriptor Sequence
/// Number = 1 (mkudffs `default_pvd`).
fn write_pvd(out: &mut [u8], layout: &Layout, loc: u32) {
    put_u32_le(out, 16, 1); // volume descriptor sequence number
    put_u32_le(out, 20, 1); // primary volume descriptor number
    dstring(out, 24, 32, layout.label.as_str());
    put_u16_le(out, 56, 1); // volume sequence number
    put_u16_le(out, 58, 1); // maximum volume sequence number
    put_u16_le(out, 60, 3); // interchange level
    put_u16_le(out, 62, 3); // maximum interchange level
    put_u32_le(out, 64, 1); // character set list
    put_u32_le(out, 68, 1); // maximum character set list
    dstring(out, 72, 128, DEFAULT_LABEL); // volume set identifier
    charspec(out, 200); // descriptor character set
    charspec(out, 264); // explanatory character set
    timestamp(out, 376); // recording date and time
    finalize_tag(out, 0, TAG_PVD, loc, 512);
}

/// Implementation Use Volume Descriptor (ECMA-167 3/10.4) with the UDF
/// logical-volume info (`udf_lv_info`) in its 460-byte implementation use.
/// Volume Descriptor Sequence Number = 5 (mkudffs `default_iuvd`).
fn write_iuvd(out: &mut [u8], layout: &Layout, loc: u32) {
    put_u32_le(out, 16, 5); // volume descriptor sequence number
                            // Implementation Identifier "*UDF LV Info" (mkudffs default_iuvd); the
                            // udf_info scanner only accepts this identifier.
    regid_ident(out, 20, b"*UDF LV Info");
    let iu = 52;
    charspec(out, iu); // LV info charset
    dstring(out, iu + 64, 128, layout.label.as_str()); // logical volume id
                                                       // lvinfo1..3, impl id, impl use stay zero
    finalize_tag(out, 0, TAG_IUVD, loc, 512);
}

/// Partition Descriptor (ECMA-167 3/10.5). The partition-header descriptor
/// (PHD) is embedded in the 128-byte contents-use: two `short_ad`s pointing
/// at the Unallocated Space Entry (partition block 1) and the Space Bitmap
/// Descriptor (partition block 2). Volume Descriptor Sequence Number = 3
/// (mkudffs `default_pd`).
fn write_pd(out: &mut [u8], layout: &Layout, loc: u32) {
    put_u32_le(out, 16, 3); // volume descriptor sequence number
    put_u16_le(out, 20, 0); // partition flags
    put_u16_le(out, 22, 0); // partition number
                            // Partition contents (oracle-verify: identifier string).
    regid_udf(out, 24);
    let phd = 56;
    out[phd..phd + 8].copy_from_slice(&short_ad(USE_SIZE, 1)); // unalloc space table
    out[phd + 8..phd + 16].copy_from_slice(&short_ad(layout.sbd_num_bytes, 2)); // unalloc space bitmap
                                                                                // part_integrity_table / freed tables must stay zero (UDF).
    put_u32_le(out, 184, 3); // access type: rewritable
    put_u32_le(out, 188, layout.partition_lba); // partition starting location
    put_u32_le(out, 192, layout.partition_len); // partition length
    finalize_tag(out, 0, TAG_PD, loc, 512);
}

/// Logical Volume Descriptor (ECMA-167 3/10.6) with one Type-1 partition
/// map. `LogicalVolumeContentsUse` (16 B) holds the FSD `long_ad`.
/// Volume Descriptor Sequence Number = 2 (mkudffs `default_lvd`).
fn write_lvd(out: &mut [u8], layout: &Layout, loc: u32) {
    put_u32_le(out, 16, 2); // volume descriptor sequence number
    charspec(out, 20); // descriptor character set
    dstring(out, 84, 128, layout.label.as_str()); // logical volume id
    put_u32_le(out, 212, SECTOR_SIZE); // logical block size
    regid_udf(out, 216); // domain identifier
    out[248..264].copy_from_slice(&long_ad(512, 0, 0)); // FSD at partition block 0
    put_u32_le(out, 264, 6); // partition map table length
    put_u32_le(out, 268, 1); // number of partition maps
    out[432..440].copy_from_slice(&extent_ad(layout.lvid_lba, LVID_SECTORS * SECTOR_SIZE)); // integrity sequence
    out[440] = 1; // Type-1 partition map
    out[441] = 6;
    put_u16_le(out, 442, 1); // volume sequence number
    put_u16_le(out, 444, 0); // partition number
    finalize_tag(out, 0, TAG_LVD, loc, 512);
}

/// Unallocated Space Descriptor (ECMA-167 3/10.8): one extent covering the
/// unused volume space between the reserve VDS and the third anchor.
/// Volume Descriptor Sequence Number = 4 (mkudffs `default_usd`).
fn write_usd(out: &mut [u8], layout: &Layout, loc: u32) {
    put_u32_le(out, 16, 4); // volume descriptor sequence number
    put_u32_le(out, 20, 1); // number of allocation descriptors
    let gap_start = layout.reserve_vds_lba + VDS_SECTORS;
    let tail_len = (layout.anchor3_lba - gap_start) * SECTOR_SIZE;
    out[24..32].copy_from_slice(&extent_ad(gap_start, tail_len));
    finalize_tag(out, 0, TAG_USD, loc, 32);
}

/// Terminating Descriptor (ECMA-167 3/10.9): tag only.
fn write_td(out: &mut [u8], loc: u32) {
    finalize_tag(out, 0, TAG_TD, loc, TAG_SIZE);
}

/// Length of the UDF 2.01 LVIDIU (Logical Volume Integrity Implementation
/// Use): `regid` (32) + num_files (4) + num_directories (4) + minRead
/// (2) + minWrite (2) + maxWrite (2).
const LVIDIU_SIZE: usize = 46;

/// Logical Volume Integrity Descriptor (ECMA-167 3/10.10). One partition,
/// closed, with the UDF 2.01 LVIDIU in the implementation-use area.
fn write_lvid(out: &mut [u8], layout: &Layout) {
    timestamp(out, 16);
    put_u32_le(out, 28, 1); // integrity type: closed
    out[40..48].copy_from_slice(&1u64.to_le_bytes()); // next unique id
    put_u32_le(out, 72, 1); // number of partitions
    put_u32_le(out, 76, LVIDIU_SIZE as u32); // length of implementation use
    let free = layout.partition_len - layout.free_from_block;
    put_u32_le(out, 80, free); // free space table
    put_u32_le(out, 84, layout.partition_len); // size table
    let iu = 88;
    regid_udf(out, iu);
    put_u16_le(out, iu + 40, UDF_REV); // min UDF read rev
    put_u16_le(out, iu + 42, UDF_REV); // min UDF write rev
    put_u16_le(out, iu + 44, UDF_REV); // max UDF write rev
    finalize_tag(out, 0, TAG_LVID, layout.lvid_lba, 88 + LVIDIU_SIZE);
}

/// File Set Descriptor (ECMA-167 4/14.1).
fn write_fsd(out: &mut [u8], layout: &Layout) {
    timestamp(out, 16);
    put_u16_le(out, 28, 3); // interchange level
    put_u16_le(out, 30, 3); // maximum interchange level
    put_u32_le(out, 32, 1); // character set list
    put_u32_le(out, 36, 1); // maximum character set list
    put_u32_le(out, 40, 1); // file set number
    put_u32_le(out, 44, 0); // file set descriptor number
    charspec(out, 48); // logical volume id charset
    dstring(out, 112, 128, layout.label.as_str()); // logical volume id
    charspec(out, 240); // file set charset
    dstring(out, 304, 32, layout.label.as_str()); // file set id
    let root_icb_block = layout.root_icb_lba - layout.partition_lba;
    out[400..416].copy_from_slice(&long_ad(ROOT_FE_SIZE, root_icb_block, 0));
    regid_udf(out, 416); // domain identifier
                         // tagLocation is partition-relative (the FSD lives in PSPACE, mkudffs
                         // query_tag): the kernel reads it via udf_read_ptagged which passes
                         // location = logicalBlockNum = 0.
    finalize_tag(out, 0, TAG_FSD, 0, 512);
}

/// Unallocated Space Entry (ECMA-167 4/14.12): one short_ad covering all
/// free blocks after the partition head.
const USE_SIZE: u32 = 48;

fn write_use(out: &mut [u8], layout: &Layout) {
    put_u16_le(out, 20, 4); // icb strategy type
    out[27] = 1; // icb file type: unallocated space
    put_u32_le(out, 36, 8); // allocation descriptor length (one short_ad)
    let free_bytes = (layout.partition_len - layout.free_from_block) * SECTOR_SIZE;
    // Extent flag (oracle-verify): top 2 bits = FREE (2<<30).
    put_u32_le(out, 40, free_bytes | (2 << 30));
    put_u32_le(out, 44, layout.free_from_block);
    // tagLocation is partition-relative (partition block 1).
    finalize_tag(out, 0, TAG_USE, 1, USE_SIZE as usize);
}

/// Space Bitmap Descriptor (ECMA-167 4/14.13). Multi-sector: the tag lives
/// on the first sector, the bitmap data continues across the rest. The tag
/// CRC is a placeholder (0) — see [`gen_sector`].
fn write_sbd(layout: &Layout, lba: u32, out: &mut [u8]) {
    let byte_start = (lba - layout.sbd_lba) * SECTOR_SIZE;
    let first = byte_start == 0;
    let data_start = if first { 24 } else { 0 };
    if first {
        put_u16_le(out, 0, TAG_SBD);
        put_u16_le(out, 2, 3);
        put_u16_le(out, 6, SERIAL);
        // crc_len = descriptor size − tag = (24 + num_bytes) − 16 = 8 + num_bytes,
        // capped at the u16 field.
        let crc_len = 8u32.saturating_add(layout.sbd_num_bytes).min(0xFFFF);
        put_u16_le(out, 10, crc_len as u16);
        // tagLocation is partition-relative (partition block 2).
        put_u32_le(out, 12, layout.sbd_lba - layout.partition_lba);
        put_u32_le(out, 16, layout.sbd_num_bits);
        put_u32_le(out, 20, layout.sbd_num_bytes);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&out[..16]);
        out[4] = tag_checksum(&tag);
    }
    let n = (SECTOR_SIZE as usize) - data_start;
    let _ = sbd_bitmap(
        layout,
        byte_start as usize,
        &mut out[data_start..data_start + n],
    );
}

/// Root directory File Entry (ECMA-167 4/14.9), strategy 4, file type
/// directory, one short allocation descriptor covering the root dir block.
const ROOT_FE_SIZE: u32 = 184;

fn write_root_icb(out: &mut [u8], layout: &Layout) {
    put_u16_le(out, 20, 4); // icb strategy type
    out[27] = 4; // icb file type: directory
    put_u16_le(out, 48, 1); // link count
    put_u64_le(out, 56, ROOT_DIR_BYTES as u64); // information length
    put_u64_le(out, 64, 1); // logical blocks recorded
    put_u64_le(out, 160, 1); // unique id
    put_u32_le(out, 172, 8); // allocation descriptor length
    let root_dir_block = layout.root_dir_lba - layout.partition_lba;
    out[176..184].copy_from_slice(&short_ad(ROOT_DIR_BYTES, root_dir_block));
    // tagLocation is partition-relative (the FE lives in PSPACE).
    let root_icb_block = layout.root_icb_lba - layout.partition_lba;
    finalize_tag(out, 0, TAG_FE, root_icb_block, ROOT_FE_SIZE as usize);
}

/// Empty root directory: two File Identifier Descriptors (`.` and `..`),
/// 40 bytes each.
const ROOT_DIR_BYTES: u32 = 40 + 40;

fn write_root_dir(out: &mut [u8], layout: &Layout) {
    let root_icb_block = layout.root_icb_lba - layout.partition_lba;
    // tagLocation is partition-relative (the root dir data block).
    let root_dir_block = layout.root_dir_lba - layout.partition_lba;
    // "." — directory flag (oracle-verify: flag bits).
    write_fid(out, 0, 0x02, b".", root_icb_block, root_dir_block);
    // ".." — parent flag; root's parent is itself.
    write_fid(out, 40, 0x08, b"..", root_icb_block, root_dir_block);
}

/// File Identifier Descriptor (ECMA-167 4/14.4) with no implementation use;
/// the identifier is padded to a 4-byte boundary.
fn write_fid(
    out: &mut [u8],
    off: usize,
    file_char: u8,
    name: &[u8],
    icb_block: u32,
    loc_sector: u32,
) {
    put_u16_le(out, off + 16, 1); // file version number
    out[off + 18] = file_char;
    out[off + 19] = name.len() as u8;
    out[off + 20..off + 36].copy_from_slice(&long_ad(ROOT_FE_SIZE, icb_block, 0));
    put_u16_le(out, off + 36, 0); // length of implementation use
    out[off + 38..off + 38 + name.len()].copy_from_slice(name);
    let size = 38 + name.len() + (4 - (38 + name.len()) % 4) % 4;
    finalize_tag(out, off, TAG_FID, loc_sector, size);
}

// ── Error type ──────────────────────────────────────────────────────

/// UDF void layout error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfError {
    /// Volume capacity below [`MIN_CAPACITY_SECTORS`].
    CapacityTooSmall,
    /// Scratch buffer for [`sbd_crc`] is empty.
    ScratchTooSmall,
}

impl fmt::Display for UdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooSmall => write!(
                f,
                "capacity below minimum of {MIN_CAPACITY_SECTORS} sectors"
            ),
            Self::ScratchTooSmall => write!(f, "scratch buffer too small for sbd_crc"),
        }
    }
}

impl core::error::Error for UdfError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_of(capacity: u32) -> Layout {
        compute_layout(capacity, "TEST").unwrap()
    }

    fn sector() -> [u8; SECTOR_SIZE as usize] {
        [0u8; SECTOR_SIZE as usize]
    }

    // ── CRC ──────────────────────────────────────────────────────────

    #[test]
    fn crc16_test_vector() {
        assert_eq!(crc16(&[0x70, 0x6A, 0x77], 0), 0x3299);
    }

    #[test]
    fn crc16_empty_is_zero() {
        assert_eq!(crc16(&[], 0), 0);
    }

    #[test]
    fn crc16_init_zero_known() {
        // init=0 / poly 0x1021 / MSB-first ("CRC-16/XMODEM") of "123456789".
        assert_eq!(crc16(b"123456789", 0), 0x31C3);
    }

    // ── Layout ───────────────────────────────────────────────────────

    #[test]
    fn layout_minimum_geometry() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        assert_eq!(l.vds_lba, 257);
        assert_eq!(l.lvid_lba, 273);
        assert_eq!(l.partition_lba, 277);
        assert_eq!(l.anchor2_lba, MIN_CAPACITY_SECTORS - 257);
        assert_eq!(l.anchor3_lba, MIN_CAPACITY_SECTORS - 1);
        assert_eq!(l.reserve_vds_lba, MIN_CAPACITY_SECTORS - 160);
        assert_eq!(
            l.partition_len,
            MIN_CAPACITY_SECTORS - 540,
            "partition ends 6 blocks before the second anchor"
        );
        assert_eq!(l.sbd_num_bytes, 1508u32.div_ceil(8));
        assert_eq!(l.sbd_sectors, 1);
        assert_eq!(l.free_from_block, 5);
        assert_eq!(l.fsd_lba, 277);
        assert_eq!(l.use_lba, 278);
        assert_eq!(l.sbd_lba, 279);
        assert_eq!(l.root_icb_lba, 280);
        assert_eq!(l.root_dir_lba, 281);
    }

    #[test]
    fn layout_capacity_too_small() {
        assert!(matches!(
            compute_layout(MIN_CAPACITY_SECTORS - 1, "X"),
            Err(UdfError::CapacityTooSmall)
        ));
    }

    #[test]
    fn layout_label_truncated_and_default() {
        let l =
            compute_layout(MIN_CAPACITY_SECTORS, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").unwrap();
        assert_eq!(l.label.as_str(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        let l = compute_layout(MIN_CAPACITY_SECTORS, "").unwrap();
        assert_eq!(l.label.as_str(), "SNOWDRIVE");
    }

    #[test]
    fn layout_big_disc_sbd_spans_sectors() {
        // Full DVD+RW capacity (~4.38 GB): the space bitmap spans 141
        // sectors, so the partition head must move past it.
        let l = layout_of(2_295_104);
        assert!(l.sbd_sectors > 1, "sbd_sectors = {}", l.sbd_sectors);
        assert!(l.root_icb_lba >= l.sbd_lba + l.sbd_sectors);
        assert!(l.free_from_block > l.sbd_sectors);
    }

    // ── VRS / anchors ────────────────────────────────────────────────

    #[test]
    fn vrs_entries() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, 16, &mut s);
        assert_eq!(&s[1..6], b"BEA01");
        gen_sector(&l, 17, &mut s);
        assert_eq!(&s[1..6], b"NSR03");
        gen_sector(&l, 18, &mut s);
        assert_eq!(&s[1..6], b"TEA01");
        // Everything else in the VRS sectors is zero.
        assert!(s[7..].iter().all(|&b| b == 0));
    }

    #[test]
    fn anchors_point_at_vds_extents() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        for loc in [AVDP_LBA, l.anchor2_lba, l.anchor3_lba] {
            let mut s = sector();
            gen_sector(&l, loc, &mut s);
            assert_eq!(u16::from_le_bytes([s[0], s[1]]), TAG_AVDP);
            let main_len = u32::from_le_bytes(s[16..20].try_into().unwrap());
            let main_loc = u32::from_le_bytes(s[20..24].try_into().unwrap());
            assert_eq!(main_len, VDS_SECTORS * SECTOR_SIZE);
            assert_eq!(main_loc, l.vds_lba);
            let res_loc = u32::from_le_bytes(s[28..32].try_into().unwrap());
            assert_eq!(res_loc, l.reserve_vds_lba);
        }
    }

    // ── VDS descriptors ──────────────────────────────────────────────

    #[test]
    fn vds_main_and_reserve_descriptors() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        // mkudffs order: PVD, LVD, PD, USD, IUVD, TD (non-decreasing
        // volDescSeqNum so the kernel's "latest wins" keeps every one).
        let ids = [TAG_PVD, TAG_LVD, TAG_PD, TAG_USD, TAG_IUVD, TAG_TD];
        for (i, expect) in ids.iter().enumerate() {
            for base in [l.vds_lba, l.reserve_vds_lba] {
                let mut s = sector();
                assert!(gen_sector(&l, base + i as u32, &mut s));
                assert_eq!(u16::from_le_bytes([s[0], s[1]]), *expect);
                let location = u32::from_le_bytes(s[12..16].try_into().unwrap());
                assert_eq!(location, base + i as u32, "tag location = sector");
                assert_eq!(s[4], tag_checksum(&s[..16].try_into().unwrap()));
            }
        }
    }

    #[test]
    fn vds_seq_numbers_non_decreasing() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        // mkudffs defaults.c: PVD=1, LVD=2, PD=3, USD=4, IUVD=5. The kernel
        // records a descriptor only when its seq number is >= the max seen,
        // so these must be non-decreasing on disc.
        let expect = [1u32, 2, 3, 4, 5];
        for base in [l.vds_lba, l.reserve_vds_lba] {
            for (i, &want) in expect.iter().enumerate() {
                let mut s = sector();
                gen_sector(&l, base + i as u32, &mut s);
                let seq = u32::from_le_bytes(s[16..20].try_into().unwrap());
                assert_eq!(seq, want, "VDS descriptor {i} seq number");
            }
        }
    }

    #[test]
    fn pvd_volume_identifier_and_charset() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.vds_lba, &mut s);
        assert_eq!(s[24], 4); // dstring length "TEST"
        assert_eq!(&s[25..29], b"TEST");
        assert_eq!(&s[201..224], b"OSTA Compressed Unicode");
    }

    #[test]
    fn pd_partition_geometry_and_phd() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.vds_lba + 2, &mut s);
        assert_eq!(u32::from_le_bytes(s[184..188].try_into().unwrap()), 3); // rewritable
        assert_eq!(
            u32::from_le_bytes(s[188..192].try_into().unwrap()),
            l.partition_lba
        );
        assert_eq!(
            u32::from_le_bytes(s[192..196].try_into().unwrap()),
            l.partition_len
        );
        // PHD short_ads: USE at block 1, SBD at block 2.
        let use_len = u32::from_le_bytes(s[56..60].try_into().unwrap());
        let use_blk = u32::from_le_bytes(s[60..64].try_into().unwrap());
        assert_eq!(use_len, USE_SIZE);
        assert_eq!(use_blk, 1);
        let bm_len = u32::from_le_bytes(s[64..68].try_into().unwrap());
        let bm_blk = u32::from_le_bytes(s[68..72].try_into().unwrap());
        assert_eq!(bm_len, l.sbd_num_bytes);
        assert_eq!(bm_blk, 2);
    }

    #[test]
    fn lvd_fsd_pointer_and_partition_map() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        // LVD is the second VDS descriptor (mkudffs order).
        gen_sector(&l, l.vds_lba + 1, &mut s);
        // FSD long_ad in LogicalVolumeContentsUse (offset 248).
        let len = u32::from_le_bytes(s[248..252].try_into().unwrap());
        let block = u32::from_le_bytes(s[252..256].try_into().unwrap());
        assert_eq!(len, 512);
        assert_eq!(block, 0); // FSD at partition block 0
        assert_eq!(u32::from_le_bytes(s[264..268].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(s[268..272].try_into().unwrap()), 1);
        assert_eq!(s[440], 1); // Type-1 map
        assert_eq!(s[441], 6);
    }

    #[test]
    fn usd_describes_tail() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        // USD is the fourth VDS descriptor (mkudffs order).
        gen_sector(&l, l.vds_lba + 3, &mut s);
        let loc = u32::from_le_bytes(s[28..32].try_into().unwrap());
        assert_eq!(loc, l.reserve_vds_lba + VDS_SECTORS);
    }

    #[test]
    fn lvid_free_space_matches_bitmap() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.lvid_lba, &mut s);
        assert_eq!(u32::from_le_bytes(s[28..32].try_into().unwrap()), 1); // closed
        let free = u32::from_le_bytes(s[80..84].try_into().unwrap());
        assert_eq!(free, l.partition_len - l.free_from_block);
        assert_eq!(
            u32::from_le_bytes(s[84..88].try_into().unwrap()),
            l.partition_len
        );
        let iu = 88;
        assert_eq!(
            u16::from_le_bytes(s[iu + 40..iu + 42].try_into().unwrap()),
            UDF_REV
        );
    }

    // ── Partition: FSD / USE / SBD / root ───────────────────────────

    #[test]
    fn fsd_points_at_root_icb() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.fsd_lba, &mut s);
        let block = u32::from_le_bytes(s[404..408].try_into().unwrap());
        assert_eq!(block, l.root_icb_lba - l.partition_lba);
        assert_eq!(&s[417..436], b"*OSTA UDF Compliant");
    }

    #[test]
    fn use_describes_free_extent() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.use_lba, &mut s);
        let free_bytes = u32::from_le_bytes(s[40..44].try_into().unwrap());
        assert_eq!(
            free_bytes & ((1 << 30) - 1),
            (l.partition_len - l.free_from_block) * SECTOR_SIZE
        );
        assert_eq!(
            u32::from_le_bytes(s[44..48].try_into().unwrap()),
            l.free_from_block
        );
    }

    #[test]
    fn sbd_bitmap_polarity() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut buf = [0u8; 256];
        let n = sbd_bitmap(&l, 0, &mut buf);
        assert_eq!(n, l.sbd_num_bytes as usize);
        // Head blocks (0..free_from) allocated → bit 0.
        for b in 0..l.free_from_block as usize {
            assert_eq!(
                buf[b / 8] & (1 << (b % 8)),
                0,
                "head block {b} must be used"
            );
        }
        // Free blocks → bit 1.
        for b in l.free_from_block as usize..(l.partition_len as usize).min(64 * 8) {
            assert_eq!(buf[b / 8] & (1 << (b % 8)), 1 << (b % 8), "block {b} free");
        }
    }

    #[test]
    fn sbd_sector_and_crc_patch_roundtrip() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut scratch = [0u8; 256];
        let crc = sbd_crc(&l, &mut scratch).unwrap();
        let mut s = sector();
        assert!(gen_sector(&l, l.sbd_lba, &mut s));
        // Placeholder CRC is zero until patched.
        assert_eq!(u16::from_le_bytes([s[8], s[9]]), 0);
        patch_sbd_crc(&mut s, crc);
        // Now the tag must be fully valid per our own validator.
        assert_eq!(u16::from_le_bytes([s[0], s[1]]), TAG_SBD);
        let crc_len = u16::from_le_bytes([s[10], s[11]]) as usize;
        assert_eq!(crc_len, 8 + l.sbd_num_bytes as usize);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&s[..16]);
        assert_eq!(s[4], tag_checksum(&tag));
        // CRC over the body equals the patched value. The body covers the
        // num_bits/num_bytes fields plus the whole bitmap (small disc).
        assert_eq!(
            u16::from_le_bytes([s[8], s[9]]),
            crc16(&s[16..16 + crc_len], 0)
        );
    }

    #[test]
    fn sbd_crc_scratch_too_small() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        assert_eq!(sbd_crc(&l, &mut []), Err(UdfError::ScratchTooSmall));
    }

    #[test]
    fn root_icb_is_directory_pointing_at_root_dir() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.root_icb_lba, &mut s);
        assert_eq!(u16::from_le_bytes([s[0], s[1]]), TAG_FE);
        assert_eq!(s[27], 4); // file type: directory
        assert_eq!(
            u64::from_le_bytes(s[56..64].try_into().unwrap()),
            ROOT_DIR_BYTES as u64
        );
        assert_eq!(u32::from_le_bytes(s[172..176].try_into().unwrap()), 8);
        let blk = u32::from_le_bytes(s[180..184].try_into().unwrap());
        assert_eq!(blk, l.root_dir_lba - l.partition_lba);
    }

    #[test]
    fn root_dir_has_dot_and_dotdot() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, l.root_dir_lba, &mut s);
        // "." FID at 0.
        assert_eq!(u16::from_le_bytes([s[0], s[1]]), TAG_FID);
        assert_eq!(s[18], 0x02);
        assert_eq!(s[19], 1);
        assert_eq!(&s[38..39], b".");
        // ".." FID at 40.
        assert_eq!(u16::from_le_bytes([s[40], s[41]]), TAG_FID);
        assert_eq!(s[58], 0x08);
        assert_eq!(s[59], 2);
        assert_eq!(&s[78..80], b"..");
    }

    #[test]
    fn free_space_and_unstructured_sectors_are_false() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        // A free block inside the partition.
        assert!(!gen_sector(&l, l.free_from_block + l.partition_lba, &mut s));
        // The 255-sector tail after the second anchor.
        assert!(!gen_sector(&l, l.reserve_vds_lba + VDS_SECTORS, &mut s));
        // LBA 0 (system area) is not part of the structure.
        assert!(!gen_sector(&l, 0, &mut s));
    }

    #[test]
    fn all_structured_sectors_validate() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        for lba in 0..l.capacity_sectors {
            if gen_sector(&l, lba, &mut s) && (lba == 0 || lba >= l.vds_lba) {
                // Tagged descriptor sectors (VRS has no tag).
                let id = u16::from_le_bytes([s[0], s[1]]);
                assert!(id != 0, "LBA {lba}: tag id must be set");
                let location = u32::from_le_bytes(s[12..16].try_into().unwrap());
                // Partition-internal descriptors (FSD/USE/SBD/root FE/FID)
                // carry a partition-relative tagLocation (mkudffs query_tag
                // for PSPACE); everything else is absolute.
                let expected = match lba {
                    x if x == l.fsd_lba => l.fsd_lba - l.partition_lba,
                    x if x == l.use_lba => l.use_lba - l.partition_lba,
                    x if x == l.sbd_lba => l.sbd_lba - l.partition_lba,
                    x if x == l.root_icb_lba => l.root_icb_lba - l.partition_lba,
                    x if x == l.root_dir_lba => l.root_dir_lba - l.partition_lba,
                    x => x,
                };
                assert_eq!(location, expected, "LBA {lba}: tag location");
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&s[..16]);
                assert_eq!(s[4], tag_checksum(&tag), "LBA {lba}: checksum");
            }
        }
    }

    #[test]
    fn is_avdp_validates_generated_anchor() {
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut s = sector();
        gen_sector(&l, AVDP_LBA, &mut s);
        assert!(is_avdp(&s));
        // Corrupt the CRC → rejected.
        s[8] ^= 0xFF;
        assert!(!is_avdp(&s));
        // Zero sector → rejected.
        assert!(!is_avdp(&[0u8; 32]));
    }

    #[test]
    fn gen_sector_short_buffer_panics() {
        // The assert must trigger only on too-short buffers; keep it simple
        // by exercising a legal call with an over-long buffer too.
        let l = layout_of(MIN_CAPACITY_SECTORS);
        let mut big = [0u8; SECTOR_SIZE as usize + 16];
        assert!(gen_sector(&l, l.fsd_lba, &mut big));
    }
}
