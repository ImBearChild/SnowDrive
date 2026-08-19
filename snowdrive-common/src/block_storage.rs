//! Random-access block storage seam (backend_ram.c).
//!
//! [`BlockStorage`] models **random-access block storage** (a block device);
//! sequential / append-only media (tape, CD-R burning) need their own
//! storage abstraction. Errors are no_std ([`BlockStorageError`]).
//!
//! Supertraits: [`embedded_io::Read`] + [`embedded_io::Write`] +
//! [`embedded_io::Seek`] — random-access byte storage using standard
//! embedded-io cursor semantics.

use embedded_io::ErrorKind as IoErrorKind;

/// Block-storage error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStorageError {
    /// `offset + len` exceeds the backend capacity.
    OutOfBounds,
    /// BlockStorage opened read-only rejected a write.
    NotWritable,
    /// Underlying I/O failed (file backend).
    Io(IoErrorKind),
}

impl core::fmt::Display for BlockStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "backend access out of bounds"),
            Self::NotWritable => write!(f, "backend is read-only"),
            Self::Io(kind) => write!(f, "backend I/O error: {kind:?}"),
        }
    }
}

impl core::error::Error for BlockStorageError {}

impl From<super::fs_storage::FsError> for BlockStorageError {
    fn from(e: super::fs_storage::FsError) -> Self {
        match e {
            super::fs_storage::FsError::NotFound | super::fs_storage::FsError::OutOfBounds => {
                Self::OutOfBounds
            }
            super::fs_storage::FsError::NotWritable => Self::NotWritable,
            super::fs_storage::FsError::Io(kind) => Self::Io(kind),
        }
    }
}

/// Random-access block storage backend.
///
/// Supertraits: [`embedded_io::Read`] + [`embedded_io::Write`] +
/// [`embedded_io::Seek`] — random-access byte storage using standard
/// embedded-io cursor semantics. Extension methods: [`capacity()`] and
/// [`sync()`] (SYNCHRONIZE CACHE needs persistence beyond `flush`).
///
/// Not suited to sequential/append-only media (tape, CD-R) — those need
/// separate storage abstractions. No `Send` supertrait — single-threaded
/// targets never cross threads; call sites that need `Send` add their own
/// bound.
pub trait BlockStorage: embedded_io::Read + embedded_io::Write + embedded_io::Seek {
    /// Backing store size in bytes (64-bit).
    ///
    /// Needed by READ CAPACITY; embedded-io has no size query.
    fn capacity(&self) -> u64;

    /// Persist all pending writes to backing store (disk: flush + fsync).
    ///
    /// `Write::flush` only reaches the OS page cache; `sync()` calls
    /// through to the platform fsync. RAM backends are no-op.
    fn sync(&mut self) -> Result<(), Self::Error>;
}

/// RAM backend. Wraps a caller-provided `&mut [u8]` and implements
/// `embedded_io::Read + Write + Seek` + [`BlockStorage`].
///
/// `embedded_io` does not provide a combined `Read+Write+Seek` impl for
/// bare `&mut [u8]`, so this struct adds cursor state.
pub struct RamBackend<'a> {
    data: &'a mut [u8],
    pos: u64,
}

impl<'a> RamBackend<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl embedded_io::ErrorType for RamBackend<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for RamBackend<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let start = self.pos as usize;
        let available = self.data.len().saturating_sub(start);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl embedded_io::Write for RamBackend<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let start = self.pos as usize;
        let available = self.data.len().saturating_sub(start);
        let n = buf.len().min(available);
        self.data[start..start + n].copy_from_slice(&buf[..n]);
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io::Seek for RamBackend<'_> {
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
                let end = self.data.len() as u64;
                if off >= 0 {
                    end.saturating_add(off as u64)
                } else {
                    end.saturating_sub((-off) as u64)
                }
            }
        };
        self.pos = new_pos.min(self.data.len() as u64);
        Ok(self.pos)
    }
}

impl BlockStorage for RamBackend<'_> {
    fn capacity(&self) -> u64 {
        self.data.len() as u64
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_roundtrip() {
        let mut ram = [0u8; 512];
        let mut b = RamBackend::new(&mut ram);
        let mut pattern = [0u8; 512];
        for (i, byte) in pattern.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        b.write_all(&pattern).unwrap();
        let mut out = [0u8; 512];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, pattern);
        assert_eq!(BlockStorage::capacity(&b), 512);
    }

    #[test]
    fn ram_offset_read() {
        let mut ram = [0u8; 1024];
        let mut b = RamBackend::new(&mut ram);
        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(100)).unwrap();
        b.write_all(&[1u8, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(100)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn ram_sync_is_noop() {
        let mut ram = [0u8; 8];
        let mut b = RamBackend::new(&mut ram);
        assert_eq!(BlockStorage::sync(&mut b), Ok(()));
    }

    #[test]
    fn empty_ram() {
        let mut ram: [u8; 0] = [];
        let b = RamBackend::new(&mut ram);
        assert_eq!(BlockStorage::capacity(&b), 0);
    }
}
