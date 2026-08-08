//! Random-access block storage seam (backend_ram.c).
//!
//! [`BlockStorage`] replaces the C function-pointer table
//! (`snowscsi_backend_ops_t`). It models **random-access block storage**
//! (a block device); sequential / append-only media (tape, CD-R burning)
//! will need their own storage abstraction. Errors are no_std
//! ([`BlockStorageError`]).
//!
//! The trait lives here (leaf crate) so both `snowscsi` and any caller
//! (embedded drivers) can implement it; concrete std backends
//! ([`FileBackend`]) live in `snowscsi`.

use embedded_io::ErrorKind as IoErrorKind;

/// BlockStorage error (no_std, `core::error::Error`).
///
/// [`RamBackend`] has no I/O failure mode beyond bounds; the `Io` variant
/// exists for the std-file backend, mapping `std::io::ErrorKind`.
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

/// Random-access block storage backend (replaces `snowscsi_backend_ops_t`).
///
/// Models a block device: random access by byte offset, overwrite-writable
/// (or read-only), fixed capacity. Not suited to sequential/append-only
/// media (tape, CD-R) — those need separate storage abstractions.
///
/// All methods take `&mut self`: the RAM backend
/// holds a caller-provided `&mut [u8]` and cannot serve `read` through a
/// shared reference. Single-threaded in Phase 1. No `Send` supertrait — the
/// trait does not presume thread affinity; call sites that cross threads
/// add their own `B: BlockStorage + Send` bound.
pub trait BlockStorage {
    /// Read `buf.len()` bytes at `offset`. `buf.len()` must be 0 ≤ len ≤
    /// capacity; out-of-range access → [`BlockStorageError::OutOfBounds`].
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError>;

    /// Write `buf` at `offset`. Out-of-range → [`BlockStorageError::OutOfBounds`];
    /// read-only backend → [`BlockStorageError::NotWritable`].
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError>;

    /// Flush pending writes (disk: flush + fsync). RAM is a no-op.
    fn sync(&mut self) -> Result<(), BlockStorageError>;

    /// Backing store size in bytes (64-bit).
    fn capacity(&self) -> u64;
}

/// RAM backend. Disk image memory is **caller-provided** (`&mut [u8]`);
/// the core never allocates.
pub struct RamBackend<'a> {
    data: &'a mut [u8],
}

impl<'a> RamBackend<'a> {
    pub fn new(caller_ram: &'a mut [u8]) -> Self {
        Self { data: caller_ram }
    }
}

impl BlockStorage for RamBackend<'_> {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), BlockStorageError> {
        let start = usize::try_from(offset).map_err(|_| BlockStorageError::OutOfBounds)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(BlockStorageError::OutOfBounds)?;
        let slice = self
            .data
            .get(start..end)
            .ok_or(BlockStorageError::OutOfBounds)?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockStorageError> {
        let start = usize::try_from(offset).map_err(|_| BlockStorageError::OutOfBounds)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(BlockStorageError::OutOfBounds)?;
        let slice = self
            .data
            .get_mut(start..end)
            .ok_or(BlockStorageError::OutOfBounds)?;
        slice.copy_from_slice(buf);
        Ok(())
    }

    fn sync(&mut self) -> Result<(), BlockStorageError> {
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.data.len() as u64
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
        b.write(0, &pattern).unwrap();
        let mut out = [0u8; 512];
        b.read(0, &mut out).unwrap();
        assert_eq!(out, pattern);
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
        assert_eq!(b.read(504, &mut out), Err(BlockStorageError::OutOfBounds));
        assert_eq!(
            b.write(500, &[0u8; 32]),
            Err(BlockStorageError::OutOfBounds)
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
        assert_eq!(b.read(0, &mut out), Err(BlockStorageError::OutOfBounds));
        assert_eq!(b.write(0, &[0u8]), Err(BlockStorageError::OutOfBounds));
    }
}
