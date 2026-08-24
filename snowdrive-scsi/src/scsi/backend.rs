//! Block storage backends + re-exports from [`crate::common`].
//!
//! [`BlockStorage`], [`BlockStorageError`], and [`RamBackend`] live in
//! `crate::common::block_storage`. This module adds the std file backend
//! ([`FileBackend`]) and the aggregating [`BlockBackend`] enum
//! (`Ram` | `File`).

pub use crate::common::block_storage::{BlockStorage, BlockStorageError, RamBackend};

/// Map `std::io::ErrorKind` → `embedded_io::ErrorKind`.
#[cfg(feature = "std")]
pub(crate) fn map_io_err(kind: std::io::ErrorKind) -> embedded_io::ErrorKind {
    match kind {
        std::io::ErrorKind::NotFound => embedded_io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => embedded_io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => embedded_io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::InvalidInput => embedded_io::ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => embedded_io::ErrorKind::InvalidData,
        std::io::ErrorKind::TimedOut => embedded_io::ErrorKind::TimedOut,
        std::io::ErrorKind::Interrupted => embedded_io::ErrorKind::Interrupted,
        std::io::ErrorKind::Unsupported => embedded_io::ErrorKind::Unsupported,
        std::io::ErrorKind::BrokenPipe => embedded_io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionRefused => embedded_io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => embedded_io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted => embedded_io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected => embedded_io::ErrorKind::NotConnected,
        std::io::ErrorKind::AddrInUse => embedded_io::ErrorKind::AddrInUse,
        std::io::ErrorKind::AddrNotAvailable => embedded_io::ErrorKind::AddrNotAvailable,
        _ => embedded_io::ErrorKind::Other,
    }
}

/// Aggregating block storage enum.
///
/// Wraps [`RamBackend`] (borrowed memory, no_std) and [`FileBackend`]
/// (std). Implements [`BlockStorage`] (`Read + Write + Seek + capacity +
/// sync`).
pub enum BlockBackend<'a> {
    Ram(RamBackend<'a>),
    #[cfg(feature = "std")]
    File(FileBackend),
}

impl embedded_io::ErrorType for BlockBackend<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for BlockBackend<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Ram(b) => embedded_io::Read::read(b, buf),
            #[cfg(feature = "std")]
            Self::File(b) => embedded_io::Read::read(b, buf),
        }
    }
}

impl embedded_io::Write for BlockBackend<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Ram(b) => embedded_io::Write::write(b, buf),
            #[cfg(feature = "std")]
            Self::File(b) => embedded_io::Write::write(b, buf),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Ram(b) => embedded_io::Write::flush(b),
            #[cfg(feature = "std")]
            Self::File(b) => embedded_io::Write::flush(b),
        }
    }
}

impl embedded_io::Seek for BlockBackend<'_> {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        match self {
            Self::Ram(b) => embedded_io::Seek::seek(b, pos),
            #[cfg(feature = "std")]
            Self::File(b) => embedded_io::Seek::seek(b, pos),
        }
    }
}

impl BlockStorage for BlockBackend<'_> {
    fn capacity(&self) -> u64 {
        match self {
            Self::Ram(b) => BlockStorage::capacity(b),
            #[cfg(feature = "std")]
            Self::File(b) => BlockStorage::capacity(b),
        }
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Ram(b) => BlockStorage::sync(b),
            #[cfg(feature = "std")]
            Self::File(b) => BlockStorage::sync(b),
        }
    }
}

/// File backend (std feature, `std::fs`).
///
/// Wraps `std::fs::File` with cursor-state random access. Implements
/// [`BlockStorage`] (`Read + Write + Seek + capacity + sync`).
#[cfg(feature = "std")]
pub struct FileBackend {
    file: std::fs::File,
    size: u64,
    writable: bool,
    pos: u64,
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
            .map_err(|e| BlockStorageError::Io(map_io_err(e.kind())))?;
        let size = file
            .metadata()
            .map_err(|e| BlockStorageError::Io(map_io_err(e.kind())))?
            .len();
        Ok(Self {
            file,
            size,
            writable,
            pos: 0,
        })
    }
}

#[cfg(feature = "std")]
impl embedded_io::ErrorType for FileBackend {
    type Error = embedded_io::ErrorKind;
}

#[cfg(feature = "std")]
impl embedded_io::Read for FileBackend {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        use std::os::unix::fs::FileExt;
        let start = self.pos as usize;
        let available = (self.size as usize).saturating_sub(start);
        let to_read = buf.len().min(available);
        if to_read == 0 {
            return Ok(0);
        }
        let n = self
            .file
            .read_at(&mut buf[..to_read], self.pos)
            .map_err(|e| map_io_err(e.kind()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(feature = "std")]
impl embedded_io::Write for FileBackend {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if !self.writable {
            // Write-policy rejection convention (plan §14 D5): report
            // PermissionDenied, which the `WritableFlatData` blanket maps
            // to `BlockStorageError::NotWritable` → SCSI DATA PROTECT
            // instead of a bare I/O error.
            return Err(embedded_io::ErrorKind::PermissionDenied);
        }
        use std::os::unix::fs::FileExt;
        let start = self.pos as usize;
        let available = (self.size as usize).saturating_sub(start);
        let to_write = buf.len().min(available);
        if to_write == 0 {
            return Ok(0);
        }
        let n = self
            .file
            .write_at(&buf[..to_write], self.pos)
            .map_err(|e| map_io_err(e.kind()))?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        std::io::Write::flush(&mut self.file).map_err(|e| map_io_err(e.kind()))
    }
}

#[cfg(feature = "std")]
impl embedded_io::Seek for FileBackend {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        let new_pos = match pos {
            embedded_io::SeekFrom::Start(off) => off,
            embedded_io::SeekFrom::Current(off) => {
                if off >= 0 {
                    self.pos.saturating_add(off as u64)
                } else {
                    self.pos.saturating_sub((-off) as u64)
                }
            }
            embedded_io::SeekFrom::End(off) => {
                if off >= 0 {
                    self.size.saturating_add(off as u64)
                } else {
                    self.size.saturating_sub((-off) as u64)
                }
            }
        };
        self.pos = new_pos.min(self.size);
        Ok(self.pos)
    }
}

#[cfg(feature = "std")]
impl BlockStorage for FileBackend {
    fn capacity(&self) -> u64 {
        self.size
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        use std::io::Write;
        self.file.flush().map_err(|e| map_io_err(e.kind()))?;
        self.file.sync_all().map_err(|e| map_io_err(e.kind()))
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
        assert_eq!(BlockStorage::capacity(&b), 4096);

        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        b.write_all(&[1, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        BlockStorage::sync(&mut b).unwrap();

        assert_eq!(ram[0..4], [1, 2, 3, 4]);
    }

    #[test]
    fn block_backend_ram_out_of_bounds() {
        let mut ram = [0u8; 16];
        let b = BlockBackend::Ram(RamBackend::new(&mut ram));
        assert_eq!(BlockStorage::capacity(&b), 16);
    }

    #[test]
    fn block_backend_file_dispatch() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_bb_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let mut b = BlockBackend::File(FileBackend::open(&path.to_string_lossy(), true).unwrap());
        assert_eq!(BlockStorage::capacity(&b), 1024 * 1024);
        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        b.write_all(&[0xAA; 512]).unwrap();
        BlockStorage::sync(&mut b).unwrap();
        let mut out = [0u8; 512];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, [0xAA; 512]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_backend_roundtrip() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_fb_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let mut b = FileBackend::open(&path.to_string_lossy(), true).unwrap();
        assert_eq!(BlockStorage::capacity(&b), 1024 * 1024);

        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        use embedded_io::Write;
        b.write_all(&pattern).unwrap();
        let mut out = [0u8; 512];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out.to_vec(), pattern);

        BlockStorage::sync(&mut b).unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[..512], pattern.as_slice());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_backend_read_only_rejects_write() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_fb_ro_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 512]).unwrap();

        let mut b = FileBackend::open(&path.to_string_lossy(), false).unwrap();
        assert_eq!(BlockStorage::capacity(&b), 512);
        use embedded_io::Write;
        let r = b.write_all(&[1u8; 16]);
        assert!(r.is_err());

        let mut out = [0u8; 16];
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, [0u8; 16]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_backend_missing_read_only_open_fails() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_fb_miss_{}.img", std::process::id()));
        let r = FileBackend::open(&path.to_string_lossy(), false);
        assert!(r.is_err());
    }
}
