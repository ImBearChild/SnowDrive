//! UdfRw media layer (UDF RW).
//!
//! A random-writable DVD-RAM over any [`BlockStorage`] backend, built on the
//! pure volume skeleton of [`crate::udf_void`].
//!
//! - **Materialize** an empty UDF 2.01 volume into the backend (only when
//!   `mkfs=true` is specified at CLI open time) by streaming the structured
//!   sectors from [`udf_void::gen_sector`] and patching the multi-sector SBD
//!   CRC.
//! - **Detect** an existing UDF volume (valid AVDP at sector 256) via
//!   [`Self::has_udf`] — used only by CLI `mkfs` policy, not by FORMAT UNIT.
//! - **Data plane**: random byte-plane reads/writes through the backend.
//! - **Geometry**: capacity / last LBA / lead-out for the device layer.
//!
//! FORMAT UNIT clears all logical blocks (zero-fill) without creating or
//! rebuilding any file system. The host OS creates file systems (e.g. UDF)
//! on top of the empty logical blocks.
//!
//! Free space is left as zeros; the OS filesystem (`udf`) allocates and
//! writes it later. This layer never parses UDF contents.

use crate::cdrom::common::SECTOR_SIZE;
use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::udf_void::{
    compute_layout, gen_sector, is_avdp, patch_sbd_crc, sbd_crc, Layout, UdfError,
};

/// A random-writable DVD-RAM (UDF 2.01 plain build) over a byte plane.
pub struct UdfRwMedia<B: BlockStorage> {
    backend: B,
    layout: Layout,
}

impl<B: BlockStorage> UdfRwMedia<B> {
    /// Whether `backend` already holds a formatted UdfRw volume — a valid
    /// AVDP at sector 256 (tag id 2 + checksum + CRC).
    ///
    /// This detects UDF structure presence, not logical format state.
    /// The logical medium is always formatted (logical blocks always exist).
    /// This function is used only by CLI `mkfs` policy to decide whether
    /// to materialize a new UDF volume.
    pub fn has_udf(backend: &mut B) -> bool {
        let mut sector = [0u8; SECTOR_SIZE as usize];
        let off = u64::from(crate::udf_void::AVDP_LBA) * u64::from(SECTOR_SIZE);
        if backend.seek(embedded_io::SeekFrom::Start(off)).is_err()
            || backend.read_exact(&mut sector).is_err()
        {
            return false;
        }
        is_avdp(&sector)
    }

    /// Open an existing volume, or materialize a fresh one into `backend`.
    ///
    /// `force_mkfs` re-formats even when a valid volume is present (the
    /// `mkfs=true` CLI contract). `scratch` (≥ 1 byte) backs the space
    /// bitmap CRC computation.
    ///
    /// When `force_mkfs` is false, the existing backend content is used as-is
    /// (no UDF detection — the layout is computed from capacity). When
    /// `force_mkfs` is true, a new UDF 2.01 volume is materialized
    /// (destructive).
    pub fn open_or_materialize(
        backend: B,
        label: &str,
        force_mkfs: bool,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let b = backend;
        if force_mkfs {
            Self::materialize(b, label, scratch)
        } else {
            let layout =
                compute_layout(sectors_of(b.capacity())?, label).map_err(UdfRwError::Layout)?;
            Ok(Self { backend: b, layout })
        }
    }

    /// Materialize the empty UDF 2.01 volume into `backend` unconditionally
    /// (destructive). Writes only the structured sectors; free space stays
    /// zero. `scratch` (≥ 1 byte) backs the SBD CRC computation.
    pub fn materialize(
        mut backend: B,
        label: &str,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let layout =
            compute_layout(sectors_of(backend.capacity())?, label).map_err(UdfRwError::Layout)?;

        let mut sector = [0u8; SECTOR_SIZE as usize];

        // VRS (3 sectors), main anchor.
        for lba in [16u32, 17, 18, crate::udf_void::AVDP_LBA] {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // Main VDS (PVD, IUVD, PD, LVD, USD, TD).
        for lba in layout.vds_lba..layout.vds_lba + 6 {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // LVID extent.
        write_sector(&mut backend, &layout, layout.lvid_lba, &mut sector)?;
        // Reserve VDS (mirror).
        for lba in layout.reserve_vds_lba..layout.reserve_vds_lba + 6 {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        // Second + third anchors (N-257, N-1).
        write_sector(&mut backend, &layout, layout.anchor2_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.anchor3_lba, &mut sector)?;
        // Partition: FSD, USE, SBD (with the real CRC), root FE, root dir.
        write_sector(&mut backend, &layout, layout.fsd_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.use_lba, &mut sector)?;
        let crc = sbd_crc(&layout, scratch).map_err(UdfRwError::Layout)?;
        gen_sector(&layout, layout.sbd_lba, &mut sector);
        patch_sbd_crc(&mut sector, crc);
        let off = u64::from(layout.sbd_lba) * u64::from(SECTOR_SIZE);
        backend
            .seek(embedded_io::SeekFrom::Start(off))
            .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
        backend
            .write_all(&sector)
            .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
        for lba in (layout.sbd_lba + 1)..(layout.sbd_lba + layout.sbd_sectors) {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        write_sector(&mut backend, &layout, layout.root_icb_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.root_dir_lba, &mut sector)?;

        Ok(Self { backend, layout })
    }

    /// Capacity in bytes (the backend length).
    pub fn capacity(&self) -> u64 {
        BlockStorage::capacity(&self.backend)
    }

    /// Largest readable LBA (`capacity / 2048 − 1`, saturating).
    pub fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    /// Lead-out start LBA (number of data sectors).
    pub fn lead_out_lba(&self) -> u32 {
        (self.capacity() / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32
    }

    /// The underlying UDF void layout geometry.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Raw backend access.
    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Read from the byte plane (target data path).
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        self.backend
            .seek(embedded_io::SeekFrom::Start(offset))
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
        self.backend
            .read_exact(buf)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        self.backend
            .seek(embedded_io::SeekFrom::Start(offset))
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
        self.backend
            .write_all(buf)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// Flush the byte plane.
    pub fn sync(&mut self) -> Result<(), BlockStorageError> {
        BlockStorage::sync(&mut self.backend)
            .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
    }

    /// FORMAT UNIT for the emulated DVD-RAM medium.
    ///
    /// Clears all logical blocks (zero-fill). Does **not** create or rebuild
    /// any file system — UDF volume creation is the host OS's responsibility
    /// and is triggered only by `mkfs=true` at CLI device open time.
    pub fn format_unit(&mut self) -> Result<(), BlockStorageError> {
        self.clear()
    }

    /// Clear the logical medium as the destructive part of FORMAT UNIT.
    /// Formatting is completed logically by the command handler; the host
    /// writes the filesystem structures afterwards.
    #[allow(dead_code)] // called by FORMAT UNIT in CdromDrive
    fn clear(&mut self) -> Result<(), BlockStorageError> {
        let zeroes = [0u8; 8192];
        let mut offset = 0u64;
        while offset < self.capacity() {
            let len = (self.capacity() - offset).min(zeroes.len() as u64) as usize;
            self.backend
                .seek(embedded_io::SeekFrom::Start(offset))
                .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
            self.backend
                .write_all(&zeroes[..len])
                .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
            offset += len as u64;
        }
        Ok(())
    }
}

/// Floor `capacity` to whole 2048-byte sectors, rejecting volumes that do
/// not fit in the UDF void address space.
fn sectors_of(capacity: u64) -> Result<u32, UdfRwError> {
    u32::try_from(capacity / u64::from(SECTOR_SIZE)).map_err(|_| UdfRwError::CapacityTooLarge)
}

/// Generate and write one structured sector at `lba`.
fn write_sector<B: BlockStorage>(
    backend: &mut B,
    layout: &Layout,
    lba: u32,
    sector: &mut [u8; SECTOR_SIZE as usize],
) -> Result<(), UdfRwError> {
    gen_sector(layout, lba, sector);
    let off = u64::from(lba) * u64::from(SECTOR_SIZE);
    backend
        .seek(embedded_io::SeekFrom::Start(off))
        .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))?;
    backend
        .write_all(sector)
        .map_err(|_| UdfRwError::Block(BlockStorageError::Io(embedded_io::ErrorKind::Other)))
}

#[allow(dead_code)]
fn write_at<B: BlockStorage>(
    backend: &mut B,
    lba: u32,
    sector: &[u8; SECTOR_SIZE as usize],
) -> Result<(), BlockStorageError> {
    let off = u64::from(lba) * u64::from(SECTOR_SIZE);
    backend
        .seek(embedded_io::SeekFrom::Start(off))
        .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))?;
    backend
        .write_all(sector)
        .map_err(|_| BlockStorageError::Io(embedded_io::ErrorKind::Other))
}

#[allow(dead_code)]
fn write_sector_io<B: BlockStorage>(
    backend: &mut B,
    layout: &Layout,
    lba: u32,
    sector: &mut [u8; SECTOR_SIZE as usize],
) -> Result<(), BlockStorageError> {
    gen_sector(layout, lba, sector);
    write_at(backend, lba, sector)
}

// ── Error type ──────────────────────────────────────────────────────

/// UdfRw media error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfRwError {
    /// Backend storage failure.
    Block(BlockStorageError),
    /// UDF void layout failure (capacity too small / scratch too small).
    Layout(UdfError),
    /// Backend capacity exceeds the UDF void address space.
    CapacityTooLarge,
}

impl From<BlockStorageError> for UdfRwError {
    fn from(e: BlockStorageError) -> Self {
        Self::Block(e)
    }
}

impl From<UdfError> for UdfRwError {
    fn from(e: UdfError) -> Self {
        Self::Layout(e)
    }
}

impl core::fmt::Display for UdfRwError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Block(e) => write!(f, "storage error: {e}"),
            Self::Layout(e) => write!(f, "layout error: {e}"),
            Self::CapacityTooLarge => {
                write!(f, "backend capacity exceeds the UDF void address space")
            }
        }
    }
}

impl core::error::Error for UdfRwError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;

    fn ram(capacity: u64) -> Vec<u8> {
        vec![0u8; capacity as usize]
    }

    fn materialize_into(img: &mut [u8]) -> UdfRwMedia<RamBackend<'_>> {
        let mut scratch = [0u8; 256];
        UdfRwMedia::materialize(RamBackend::new(img), "TEST", &mut scratch).unwrap()
    }

    #[test]
    fn has_udf_detects_blank() {
        let mut img = ram(2048 * 4096);
        assert!(!UdfRwMedia::has_udf(&mut RamBackend::new(&mut img)));
    }

    #[test]
    fn materialize_creates_valid_volume() {
        let mut img = ram(2048 * 4096);
        let mut m = materialize_into(&mut img);
        assert!(UdfRwMedia::has_udf(m.backend()));
        let mut s = [0u8; 2048];
        m.read_data(16 * 2048, &mut s).unwrap();
        assert_eq!(&s[1..6], b"BEA01");
    }

    #[test]
    fn write_data_read_data_roundtrip() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut m = UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch).unwrap();
        let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
        let data = [0xAB; 2048];
        m.write_data(off, &data).unwrap();
        let mut out = [0u8; 2048];
        m.read_data(off, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn format_unit_clears_medium() {
        let mut img = ram(2048 * 4096);
        let mut m = materialize_into(&mut img);
        m.write_data(300 * 2048, &[0xA5; 2048]).unwrap();
        m.format_unit().unwrap();
        // FORMAT UNIT clears all logical blocks — no UDF structures remain.
        assert!(!UdfRwMedia::has_udf(m.backend()));
        let mut sector = [0u8; 2048];
        m.read_data(16 * 2048, &mut sector).unwrap();
        assert_eq!(sector, [0u8; 2048]);
    }

    #[test]
    fn capacity_too_small_errors() {
        let mut img = ram(2048 * 100);
        let mut scratch = [0u8; 256];
        assert!(matches!(
            UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch),
            Err(UdfRwError::Layout(UdfError::CapacityTooSmall))
        ));
    }
}
