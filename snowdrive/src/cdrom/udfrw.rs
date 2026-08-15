//! UdfRw media layer (`__UDFRW_PLAN.md` §7, commit 2).
//!
//! A random-writable DVD+RW over any [`BlockStorage`] backend, built on the
//! pure volume skeleton of [`crate::udf_void`]. This is the **media** layer
//! only — SCSI/MMC command dispatch lives in the device layer (plan
//! commit 3); when the `CdromDrive`/`CdMedia` rewrite (plan M1–M9) lands,
//! this type becomes `CdMedia::UdfRw`.
//!
//! ## Responsibilities
//! - **Materialize** the empty UDF 2.01 volume into the backend (once, on
//!   first use) by streaming the structured sectors from
//!   [`udf_void::gen_sector`] and patching the multi-sector SBD CRC.
//! - **Detect** an already-formatted volume (valid AVDP at sector 256) so
//!   reopening a persistent image does not rewrite it.
//! - **Data plane**: random byte-plane reads/writes through the backend.
//! - **Geometry**: capacity / last LBA / lead-out for the device layer.
//!
//! Free space is left as zeros; the OS filesystem (`udf`) allocates and
//! writes it later. This layer never parses UDF contents.

use crate::cdrom::common::SECTOR_SIZE;
use crate::scsi::backend::{BlockStorage, BlockStorageError};
use crate::udf_void::{
    compute_layout, gen_sector, is_avdp, patch_sbd_crc, sbd_crc, Layout, UdfError,
};

/// A random-writable DVD+RW (UDF 2.01 plain build) over a byte plane.
pub struct UdfRwMedia<B: BlockStorage> {
    backend: B,
    layout: Layout,
}

impl<B: BlockStorage> UdfRwMedia<B> {
    /// Whether `backend` already holds a formatted UdfRw volume — a valid
    /// AVDP at sector 256 (tag id 2 + checksum + CRC).
    pub fn formatted(backend: &mut B) -> bool {
        let mut sector = [0u8; SECTOR_SIZE as usize];
        let off = u64::from(crate::udf_void::AVDP_LBA) * u64::from(SECTOR_SIZE);
        if backend.read(off, &mut sector).is_err() {
            return false;
        }
        is_avdp(&sector)
    }

    /// Open an existing volume, or materialize a fresh one into `backend`.
    ///
    /// `force_mkfs` re-formats even when a valid volume is present (the
    /// `mkfs=true` CLI contract). `scratch` (≥ 1 byte) backs the space
    /// bitmap CRC computation.
    pub fn open_or_materialize(
        backend: B,
        label: &str,
        force_mkfs: bool,
        scratch: &mut [u8],
    ) -> Result<Self, UdfRwError> {
        let mut b = backend;
        if !force_mkfs && Self::formatted(&mut b) {
            let layout =
                compute_layout(sectors_of(b.capacity())?, label).map_err(UdfRwError::Layout)?;
            return Ok(Self { backend: b, layout });
        }
        Self::materialize(b, label, scratch)
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
        // Second anchor.
        write_sector(&mut backend, &layout, layout.avdp2_lba, &mut sector)?;
        // Partition: FSD, USE, SBD (with the real CRC), root FE, root dir.
        write_sector(&mut backend, &layout, layout.fsd_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.use_lba, &mut sector)?;
        let crc = sbd_crc(&layout, scratch).map_err(UdfRwError::Layout)?;
        gen_sector(&layout, layout.sbd_lba, &mut sector);
        patch_sbd_crc(&mut sector, crc);
        backend
            .write(u64::from(layout.sbd_lba) * u64::from(SECTOR_SIZE), &sector)
            .map_err(UdfRwError::Block)?;
        for lba in (layout.sbd_lba + 1)..(layout.sbd_lba + layout.sbd_sectors) {
            write_sector(&mut backend, &layout, lba, &mut sector)?;
        }
        write_sector(&mut backend, &layout, layout.root_icb_lba, &mut sector)?;
        write_sector(&mut backend, &layout, layout.root_dir_lba, &mut sector)?;

        Ok(Self { backend, layout })
    }

    /// Capacity in bytes (the backend length).
    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
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
        self.backend.read(offset, buf)
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        self.backend.write(offset, buf)
    }

    /// Flush the byte plane.
    pub fn sync(&mut self) -> Result<(), BlockStorageError> {
        self.backend.sync()
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
    backend.write(off, sector).map_err(UdfRwError::Block)
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

    /// Materialize into `img` (kept alive by the caller for the media's
    /// lifetime).
    fn materialize_into<'a>(img: &'a mut [u8]) -> UdfRwMedia<RamBackend<'a>> {
        let mut scratch = [0u8; 256];
        UdfRwMedia::materialize(RamBackend::new(img), "TEST", &mut scratch).unwrap()
    }

    #[test]
    fn formatted_detects_blank() {
        let mut img = ram(2048 * 4096);
        assert!(!UdfRwMedia::formatted(&mut RamBackend::new(&mut img)));
    }

    #[test]
    fn materialize_creates_valid_volume() {
        let mut img = ram(2048 * 4096);
        let mut m = materialize_into(&mut img);
        // Detection now succeeds on the materialized volume.
        assert!(UdfRwMedia::formatted(m.backend()));
        // VRS markers present.
        let mut s = [0u8; 2048];
        m.read_data(16 * 2048, &mut s).unwrap();
        assert_eq!(&s[1..6], b"BEA01");
        m.read_data(17 * 2048, &mut s).unwrap();
        assert_eq!(&s[1..6], b"NSR03");
        // Second anchor at N-256 has a valid AVDP.
        let n = m.layout().capacity_sectors;
        let mut s = [0u8; 2048];
        m.read_data(u64::from(n - 256) * 2048, &mut s).unwrap();
        assert!(is_avdp(&s));
    }

    #[test]
    fn write_data_read_data_roundtrip() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        let mut m = UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch).unwrap();
        // Free block well past the partition head.
        let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
        let data = [0xAB; 2048];
        m.write_data(off, &data).unwrap();
        let mut out = [0u8; 2048];
        m.read_data(off, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn open_preserves_existing_content() {
        let mut img = ram(2048 * 4096);
        let mut scratch = [0u8; 256];
        {
            let mut m =
                UdfRwMedia::materialize(RamBackend::new(&mut img), "T", &mut scratch).unwrap();
            let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
            m.write_data(off, &[0xCD; 2048]).unwrap();
        }
        // Reopen without force: the volume (and the marker) survive.
        let mut m =
            UdfRwMedia::open_or_materialize(RamBackend::new(&mut img), "T", false, &mut scratch)
                .unwrap();
        assert!(UdfRwMedia::formatted(m.backend()));
        let off = (m.layout().free_from_block + m.layout().partition_lba) as u64 * 2048;
        let mut out = [0u8; 2048];
        m.read_data(off, &mut out).unwrap();
        assert_eq!(out, [0xCD; 2048]);
    }

    #[test]
    fn force_mkfs_reformats_structure() {
        let mut img = ram(2048 * 4096);
        {
            let mut m = materialize_into(&mut img);
            // Corrupt the PVD (a structure sector), not the anchor.
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            m.write_data(pvd_off, &[0xEE; 2048]).unwrap();
        }
        // Without force: the AVDP is still valid, so the volume is opened
        // as-is and the corrupted PVD survives.
        {
            let mut scratch = [0u8; 256];
            let mut m = UdfRwMedia::open_or_materialize(
                RamBackend::new(&mut img),
                "TEST",
                false,
                &mut scratch,
            )
            .unwrap();
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            let mut s = [0u8; 2048];
            m.read_data(pvd_off, &mut s).unwrap();
            assert_eq!(s[0], 0xEE, "open must not rewrite a formatted volume");
        }
        // With force: the structure sectors are re-materialized.
        {
            let mut scratch = [0u8; 256];
            let m = UdfRwMedia::open_or_materialize(
                RamBackend::new(&mut img),
                "TEST",
                true,
                &mut scratch,
            )
            .unwrap();
            let pvd_off = u64::from(m.layout().vds_lba) * 2048;
            let mut s = [0u8; 2048];
            let mut m = m;
            m.read_data(pvd_off, &mut s).unwrap();
            assert_eq!(s[24], 4, "PVD dstring length");
            assert_eq!(&s[25..29], b"TEST");
        }
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

    #[test]
    fn unaligned_capacity_floors_to_sectors() {
        let mut img = ram(2048 * 4096 + 100);
        let m = materialize_into(&mut img);
        assert_eq!(m.max_lba(), 4095);
        assert_eq!(m.lead_out_lba(), 4096);
    }
}
