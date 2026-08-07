//! Block storage backends (`backend_file.c`) + re-exports of the storage
//! seam from [`snowcommon`].
//!
//! The [`BlockStorage`] trait, [`BlockStorageError`], and [`RamBackend`]
//! live in `snowcommon::block_storage` (leaf crate, shared with embedded
//! callers). This module adds the std file backend and the aggregating
//! [`BlockBackend`] enum (`Ram` | `File`) so callers can drive a
//! [`crate::block::BlockDevice`] through a single concrete type.
//! `snowscsi::backend::{BlockStorage, BlockStorageError, RamBackend,
//! FileBackend, BlockBackend}` stays a single import point.

pub use snowcommon::block_storage::{BlockStorage, BlockStorageError, RamBackend};

/// Aggregating block storage enum (the R4 convergence seam).
///
/// Wraps [`RamBackend`] (borrowed memory, no_std) and [`FileBackend`]
/// (std). Implements [`BlockStorage`], so a `BlockBackend` can drive a
/// [`crate::block::BlockDevice`] directly. The `'a` lifetime comes from the
/// RAM variant's borrowed disk image (mock stack RAM, CLI owned `Vec<u8>`);
/// no `'static` / `Box::leak` required.
pub enum BlockBackend<'a> {
    Ram(RamBackend<'a>),
    #[cfg(feature = "std")]
    File(FileBackend),
}

impl BlockStorage for BlockBackend<'_> {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Ram(b) => b.read(offset, buf),
            #[cfg(feature = "std")]
            Self::File(b) => b.read(offset, buf),
        }
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        match self {
            Self::Ram(b) => b.write(offset, buf),
            #[cfg(feature = "std")]
            Self::File(b) => b.write(offset, buf),
        }
    }

    fn sync(&mut self) -> Result<(), BlockStorageError> {
        match self {
            Self::Ram(b) => b.sync(),
            #[cfg(feature = "std")]
            Self::File(b) => b.sync(),
        }
    }

    fn capacity(&self) -> u64 {
        match self {
            Self::Ram(b) => b.capacity(),
            #[cfg(feature = "std")]
            Self::File(b) => b.capacity(),
        }
    }
}

/// File backend (std feature, `std::fs`).
///
/// Capacity is the file length captured at open time (matching the C
/// behavior of sizing at open). `sync` = flush + fsync.
#[cfg(feature = "std")]
pub struct FileBackend {
    file: std::fs::File,
    size: u64,
    writable: bool,
}

#[cfg(feature = "std")]
impl FileBackend {
    /// Open `path`. `writable` = open `r+b` (creating if absent); else
    /// open `rb`. Missing file on a read-only open → error.
    pub fn open(path: &str, writable: bool) -> Result<Self, BlockStorageError> {
        let mut opts = std::fs::OpenOptions::new();
        if writable {
            opts.read(true).write(true).create(true);
        } else {
            opts.read(true);
        }
        let file = opts
            .open(path)
            .map_err(|e| BlockStorageError::Io(e.kind().into()))?;
        let size = file
            .metadata()
            .map_err(|e| BlockStorageError::Io(e.kind().into()))?
            .len();
        Ok(Self {
            file,
            size,
            writable,
        })
    }
}

#[cfg(feature = "std")]
impl BlockStorage for FileBackend {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        use std::io::Read as _;
        use std::io::Seek as _;

        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockStorageError::OutOfBounds)?;
        if end > self.size {
            return Err(BlockStorageError::OutOfBounds);
        }
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| BlockStorageError::Io(e.kind().into()))?;
        self.file
            .read_exact(buf)
            .map_err(|e| BlockStorageError::Io(e.kind().into()))
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        use std::io::Seek as _;
        use std::io::Write as _;

        if !self.writable {
            return Err(BlockStorageError::NotWritable);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockStorageError::OutOfBounds)?;
        if end > self.size {
            return Err(BlockStorageError::OutOfBounds);
        }
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| BlockStorageError::Io(e.kind().into()))?;
        self.file
            .write_all(buf)
            .map_err(|e| BlockStorageError::Io(e.kind().into()))
    }

    fn sync(&mut self) -> Result<(), BlockStorageError> {
        use std::io::Write as _;

        self.file
            .flush()
            .map_err(|e| BlockStorageError::Io(e.kind().into()))?;
        self.file
            .sync_all()
            .map_err(|e| BlockStorageError::Io(e.kind().into()))
    }

    fn capacity(&self) -> u64 {
        self.size
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_backend_ram_roundtrip() {
        let mut ram = [0u8; 4096];
        let mut b = BlockBackend::Ram(RamBackend::new(&mut ram));
        assert_eq!(b.capacity(), 4096);

        b.write(0, &[1, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        b.read(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        b.sync().unwrap();

        assert_eq!(ram[0..4], [1, 2, 3, 4]);
    }

    #[test]
    fn block_backend_ram_out_of_bounds() {
        let mut ram = [0u8; 16];
        let mut b = BlockBackend::Ram(RamBackend::new(&mut ram));
        let mut out = [0u8; 4];
        assert_eq!(b.read(15, &mut out), Err(BlockStorageError::OutOfBounds));
        assert_eq!(b.write(14, &[0u8; 4]), Err(BlockStorageError::OutOfBounds));
    }

    #[test]
    fn block_backend_file_dispatch() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_blockbackend_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let mut b = BlockBackend::File(FileBackend::open(&path.to_string_lossy(), true).unwrap());
        assert_eq!(b.capacity(), 1024 * 1024);
        b.write(0, &[0xAA; 512]).unwrap();
        b.sync().unwrap();
        let mut out = [0u8; 512];
        b.read(0, &mut out).unwrap();
        assert_eq!(out, [0xAA; 512]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn block_backend_read_only_file_rejects_write() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_blockbackend_ro_{}.img",
            std::process::id()
        ));
        std::fs::write(&path, [0u8; 512]).unwrap();

        let mut b = BlockBackend::File(FileBackend::open(&path.to_string_lossy(), false).unwrap());
        assert_eq!(b.write(0, &[1u8; 16]), Err(BlockStorageError::NotWritable));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_roundtrip_and_sync() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_backend_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let mut b = FileBackend::open(&path.to_string_lossy(), true).unwrap();
        assert_eq!(b.capacity(), 1024 * 1024);

        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        b.write(0, &pattern).unwrap();
        let mut out = [0u8; 512];
        b.read(0, &mut out).unwrap();
        assert_eq!(out.to_vec(), pattern);

        b.sync().unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[..512], pattern.as_slice());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_out_of_bounds() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_backend_oob_{}.img", std::process::id()));
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(1024).unwrap();
        drop(f);

        let mut b = FileBackend::open(&path.to_string_lossy(), true).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(b.read(1020, &mut out), Err(BlockStorageError::OutOfBounds));
        assert_eq!(
            b.write(1010, &[0u8; 32]),
            Err(BlockStorageError::OutOfBounds)
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_read_only_rejects_write() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_backend_ro_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 512]).unwrap();

        let mut b = FileBackend::open(&path.to_string_lossy(), false).unwrap();
        assert_eq!(b.capacity(), 512);
        assert_eq!(b.write(0, &[1u8; 16]), Err(BlockStorageError::NotWritable));

        let mut out = [0u8; 16];
        b.read(0, &mut out).unwrap();
        assert_eq!(out, [0u8; 16]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_missing_read_only_open_fails() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_backend_missing_{}.img",
            std::process::id()
        ));
        let r = FileBackend::open(&path.to_string_lossy(), false);
        assert!(matches!(r, Err(BlockStorageError::Io(_))));
    }
}
