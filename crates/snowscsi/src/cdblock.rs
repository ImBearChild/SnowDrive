//! CDBlock device: a "lazy CD" (Phase 1.5, plan §8.1b).
//!
//! Reports itself as a CD-ROM (PDT=0x05) while reading a flat ISO image
//! through a read-only [`FileBackend`]. Implements a minimal MMC command set
//! (READ TOC, GET CONFIGURATION); SPC commands (INQUIRY, MODE SENSE, ...) are
//! delegated to [`crate::spc`]; all write commands return DATA PROTECT.
//! Because the backing store is always a read-only file, this module is
//! `std`-gated (`RamBackend` images are not supported).

use crate::backend::{BlockStorage, BlockStorageError, FileBackend};
use crate::scsi::Sense;

/// CD-ROM logical block size (Mode 1: 2048 data bytes per sector).
pub const SECTOR_SIZE: u32 = 2048;

/// The CDBlock device: a read-only CD-ROM emulated over a flat file.
pub struct CDBlockDevice {
    backend: FileBackend,
    sector_size: u32,
    sense: Sense,
}

impl CDBlockDevice {
    /// Open `path` read-only as a CD-ROM image (ISO9660, Joliet, ...).
    /// The file must already exist; the device is immutable (every write
    /// command returns DATA PROTECT).
    pub fn new(path: &str) -> Result<Self, BlockStorageError> {
        Ok(Self {
            backend: FileBackend::open(path, false)?,
            sector_size: SECTOR_SIZE,
            sense: Sense::clear(),
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn sense(&self) -> &Sense {
        &self.sense
    }

    /// Raw backend access (target data path reads chunks via
    /// [`BlockStorage::read`]; the device is read-only, so only reads are
    /// meaningful).
    pub fn backend(&mut self) -> &mut FileBackend {
        &mut self.backend
    }

    /// Image size in bytes (from the file opened at construction).
    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temp file of `len` bytes, returning the cleaned-up path
    /// string on drop. Each file gets a unique name (parallel tests).
    struct TempFile {
        path: std::path::PathBuf,
    }

    impl TempFile {
        fn new(len: u64) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir();
            let path = dir.join(format!("snowscsi_cdblock_{}_{}.iso", std::process::id(), n));
            std::fs::write(&path, vec![0u8; len as usize]).unwrap();
            Self { path }
        }

        fn path_str(&self) -> &str {
            self.path.to_str().unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn cdblock_new_reports_capacity() {
        let f = TempFile::new(2048 * 100);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 2048 * 100);
        assert_eq!(dev.sector_size(), SECTOR_SIZE);
        assert_eq!(dev.sector_size(), 2048);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE) - 1, 99);
    }

    #[test]
    fn cdblock_empty_image_has_zero_lba() {
        let f = TempFile::new(0);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 0);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE), 0);
    }

    #[test]
    fn cdblock_partial_sector_counts_as_zero_sectors() {
        let f = TempFile::new(2048);
        let dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(dev.capacity(), 2048);
        assert_eq!(dev.capacity() / u64::from(SECTOR_SIZE) - 1, 0);
    }

    #[test]
    fn cdblock_new_rejects_missing_file() {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_cdblock_missing_{}_{}.iso",
            std::process::id(),
            n
        ));
        let r = CDBlockDevice::new(path.to_str().unwrap());
        assert!(matches!(r, Err(BlockStorageError::Io(_))));
    }

    #[test]
    fn cdblock_backend_is_read_only() {
        let f = TempFile::new(2048);
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        assert_eq!(
            dev.backend().write(0, &[0xAA; 16]),
            Err(BlockStorageError::NotWritable)
        );
    }

    #[test]
    fn cdblock_backend_reads_file_contents() {
        let f = TempFile::new(4096);
        std::fs::write(&f.path, vec![0x42u8; 4096]).unwrap();
        let mut dev = CDBlockDevice::new(f.path_str()).unwrap();
        let mut buf = [0u8; 4];
        dev.backend().read(2048, &mut buf).unwrap();
        assert_eq!(buf, [0x42; 4]);
    }
}
