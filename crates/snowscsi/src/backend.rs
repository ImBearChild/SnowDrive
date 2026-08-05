//! Block storage backends (backend_ram.c / backend_file.c).
//!
//! [`BlockBackend`] replaces the C function-pointer table
//! (`snowscsi_backend_ops_t`). It models **random-access block storage**
//! (a block device); sequential / append-only media (tape, CD-R burning)
//! will need their own storage abstraction (see `__RUST.md` Appendix D).
//! Errors are no_std ([`BlockBackendError`]).

use embedded_io::ErrorKind as IoErrorKind;

/// BlockBackend error (no_std, `core::error::Error`).
///
/// [`RamBackend`] has no I/O failure mode beyond bounds; the `Io` variant
/// exists for the std-file backend, mapping `std::io::ErrorKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockBackendError {
    /// `offset + len` exceeds the backend capacity.
    OutOfBounds,
    /// BlockBackend opened read-only rejected a write.
    NotWritable,
    /// Underlying I/O failed (file backend).
    Io(IoErrorKind),
}

impl core::fmt::Display for BlockBackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "backend access out of bounds"),
            Self::NotWritable => write!(f, "backend is read-only"),
            Self::Io(kind) => write!(f, "backend I/O error: {kind:?}"),
        }
    }
}

impl core::error::Error for BlockBackendError {}

/// Random-access block storage backend (replaces `snowscsi_backend_ops_t`).
///
/// Models a block device: random access by byte offset, overwrite-writable
/// (or read-only), fixed capacity. Not suited to sequential/append-only
/// media (tape, CD-R) — those need separate storage abstractions.
///
/// All methods take `&mut self` (see `__RUST.md` §5.2): the RAM backend
/// holds a caller-provided `&mut [u8]` and cannot serve `read` through a
/// shared reference. Single-threaded in Phase 1.
pub trait BlockBackend: Send {
    /// Read `buf.len()` bytes at `offset`. `buf.len()` must be 0 ≤ len ≤
    /// capacity; out-of-range access → [`BlockBackendError::OutOfBounds`].
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockBackendError>;

    /// Write `buf` at `offset`. Out-of-range → [`BlockBackendError::OutOfBounds`];
    /// read-only backend → [`BlockBackendError::NotWritable`].
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockBackendError>;

    /// Flush pending writes (disk: flush + fsync). RAM is a no-op.
    fn sync(&mut self) -> Result<(), BlockBackendError>;

    /// Backing store size in bytes (64-bit).
    fn capacity(&self) -> u64;
}

/// RAM backend. Disk image memory is **caller-provided** (`&mut [u8]`);
/// the core never allocates (`__RUST.md` §4.1).
pub struct RamBackend<'a> {
    data: &'a mut [u8],
}

impl<'a> RamBackend<'a> {
    pub fn new(caller_ram: &'a mut [u8]) -> Self {
        Self { data: caller_ram }
    }
}

impl BlockBackend for RamBackend<'_> {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockBackendError> {
        let start = usize::try_from(offset).map_err(|_| BlockBackendError::OutOfBounds)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(BlockBackendError::OutOfBounds)?;
        let slice = self
            .data
            .get(start..end)
            .ok_or(BlockBackendError::OutOfBounds)?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockBackendError> {
        let start = usize::try_from(offset).map_err(|_| BlockBackendError::OutOfBounds)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(BlockBackendError::OutOfBounds)?;
        let slice = self
            .data
            .get_mut(start..end)
            .ok_or(BlockBackendError::OutOfBounds)?;
        slice.copy_from_slice(buf);
        Ok(())
    }

    fn sync(&mut self) -> Result<(), BlockBackendError> {
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.data.len() as u64
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
    pub fn open(path: &str, writable: bool) -> Result<Self, BlockBackendError> {
        let mut opts = std::fs::OpenOptions::new();
        if writable {
            opts.read(true).write(true).create(true);
        } else {
            opts.read(true);
        }
        let file = opts
            .open(path)
            .map_err(|e| BlockBackendError::Io(e.kind().into()))?;
        let size = file
            .metadata()
            .map_err(|e| BlockBackendError::Io(e.kind().into()))?
            .len();
        Ok(Self {
            file,
            size,
            writable,
        })
    }
}

#[cfg(feature = "std")]
impl BlockBackend for FileBackend {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockBackendError> {
        use std::io::Read as _;
        use std::io::Seek as _;

        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockBackendError::OutOfBounds)?;
        if end > self.size {
            return Err(BlockBackendError::OutOfBounds);
        }
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| BlockBackendError::Io(e.kind().into()))?;
        self.file
            .read_exact(buf)
            .map_err(|e| BlockBackendError::Io(e.kind().into()))
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockBackendError> {
        use std::io::Seek as _;
        use std::io::Write as _;

        if !self.writable {
            return Err(BlockBackendError::NotWritable);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockBackendError::OutOfBounds)?;
        if end > self.size {
            return Err(BlockBackendError::OutOfBounds);
        }
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| BlockBackendError::Io(e.kind().into()))?;
        self.file
            .write_all(buf)
            .map_err(|e| BlockBackendError::Io(e.kind().into()))
    }

    fn sync(&mut self) -> Result<(), BlockBackendError> {
        use std::io::Write as _;

        self.file
            .flush()
            .map_err(|e| BlockBackendError::Io(e.kind().into()))?;
        self.file
            .sync_all()
            .map_err(|e| BlockBackendError::Io(e.kind().into()))
    }

    fn capacity(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_roundtrip() {
        let mut ram = [0u8; 512];
        let mut b = RamBackend::new(&mut ram);
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        b.write(0, &pattern).unwrap();
        let mut out = [0u8; 512];
        b.read(0, &mut out).unwrap();
        assert_eq!(out.to_vec(), pattern);
        assert_eq!(b.capacity(), 512);
    }

    #[test]
    fn ram_offset_read() {
        let mut ram = [0u8; 1024];
        let mut b = RamBackend::new(&mut ram);
        b.write(100, &[1u8, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        b.read(100, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn ram_out_of_bounds() {
        let mut ram = [0u8; 512];
        let mut b = RamBackend::new(&mut ram);
        let mut out = [0u8; 16];
        assert_eq!(b.read(504, &mut out), Err(BlockBackendError::OutOfBounds));
        assert_eq!(
            b.write(500, &[0u8; 32]),
            Err(BlockBackendError::OutOfBounds)
        );
    }

    #[test]
    fn ram_sync_is_noop() {
        let mut ram = [0u8; 8];
        let mut b = RamBackend::new(&mut ram);
        assert_eq!(b.sync(), Ok(()));
    }

    #[test]
    fn empty_ram() {
        let mut ram: [u8; 0] = [];
        let mut b = RamBackend::new(&mut ram);
        assert_eq!(b.capacity(), 0);
        let mut out = [0u8; 1];
        assert_eq!(b.read(0, &mut out), Err(BlockBackendError::OutOfBounds));
        assert_eq!(b.write(0, &[0u8]), Err(BlockBackendError::OutOfBounds));
    }

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
    #[test]
    fn file_out_of_bounds() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_backend_oob_{}.img", std::process::id()));
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(1024).unwrap();
        drop(f);

        let mut b = FileBackend::open(&path.to_string_lossy(), true).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(b.read(1020, &mut out), Err(BlockBackendError::OutOfBounds));
        assert_eq!(
            b.write(1010, &[0u8; 32]),
            Err(BlockBackendError::OutOfBounds)
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_read_only_rejects_write() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_backend_ro_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 512]).unwrap();

        let mut b = FileBackend::open(&path.to_string_lossy(), false).unwrap();
        assert_eq!(b.capacity(), 512);
        assert_eq!(b.write(0, &[1u8; 16]), Err(BlockBackendError::NotWritable));

        let mut out = [0u8; 16];
        b.read(0, &mut out).unwrap();
        assert_eq!(out, [0u8; 16]);

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_missing_read_only_open_fails() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "snowscsi_backend_missing_{}.img",
            std::process::id()
        ));
        let r = FileBackend::open(&path.to_string_lossy(), false);
        assert!(matches!(r, Err(BlockBackendError::Io(_))));
    }
}
