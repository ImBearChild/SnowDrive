//! Filesystem storage seam for CD-ROM bundle / live FS devices.
//!
//! [`FsStorage`] models a file/directory abstraction that embedded callers
//! implement (littlefs, FatFs, etc.). The std implementation
//! ([`StdFsBackend`]) lives in `snowscsi::fs_backend`.

use embedded_io::ErrorKind as IoErrorKind;

/// Directory entry returned by [`FsStorage::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// File or directory name (no path separator).
    pub name: heapless::String<256>,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
}

/// Opaque file handle — concrete impls decide the internal representation.
///
/// Fields are private; use [`FileHandle::new`] (inside an impl) and
/// [`FileHandle::get`] to construct / inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle(usize);

impl FileHandle {
    /// Construct a handle wrapping `idx`. Semantic meaning is impl-defined
    /// (array index, fd, etc.).
    pub const fn new(idx: usize) -> Self {
        Self(idx)
    }

    /// Extract the inner index (impl-internal; external code should not
    /// depend on the numeric value).
    pub const fn get(&self) -> usize {
        self.0
    }
}

/// Filesystem access error (`no_std`, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// File or directory not found.
    NotFound,
    /// Read/write past end of file.
    OutOfBounds,
    /// Write attempted on a read-only handle.
    NotWritable,
    /// Underlying I/O failure (mapped from `embedded_io::ErrorKind`).
    Io(IoErrorKind),
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "file or directory not found"),
            Self::OutOfBounds => write!(f, "access past end of file"),
            Self::NotWritable => write!(f, "file is read-only"),
            Self::Io(kind) => write!(f, "filesystem I/O error: {kind:?}"),
        }
    }
}

impl core::error::Error for FsError {}

/// Options for [`FsStorage::open`].
///
/// Mirrors the no_std subset of `std::fs::OpenOptions`.  Public fields
/// let concrete impls map to their own open semantics (std
/// `OpenOptions` bits; FatFs `fopen` mode strings, etc.).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

impl OpenOptions {
    /// Read-only probe — file must exist (used by `toc_load` buffer scan).
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    /// Open existing or create; read-write, no truncate (RESERVE TRACK /
    /// re-opening track files).
    pub const fn open_or_create() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            truncate: false,
        }
    }

    /// Create or truncate; read-write (writing `toc.N.json` — avoids stale
    /// tail bytes from a longer previous JSON).
    pub const fn create_or_truncate() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            truncate: true,
        }
    }
}

/// Filesystem storage backend (replaces the C function-pointer table).
///
/// Models file/directory operations.  All methods take `&mut self`.
/// No `Send` supertrait — single-threaded targets never cross threads;
/// call sites that need `Send` add their own bound.
pub trait FsStorage {
    /// Open a file at `path` with the given `opts`.
    ///
    /// Returns an opaque [`FileHandle`].  `opts` controls the open mode
    /// (read-only, read-write, create-or-truncate, etc.).
    fn open(&mut self, path: &str, opts: OpenOptions) -> Result<FileHandle, FsError>;

    /// Read from an open file starting at `offset` into `buf`.
    ///
    /// Returns the **actual number of bytes read** (short-read at EOF).
    fn read(&mut self, handle: &FileHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write `buf` to an open file at `offset`.
    ///
    /// Extends the file when writing past current length; does **not**
    /// truncate on short writes (caller tracks length bookkeeping).
    fn write(&mut self, handle: &FileHandle, offset: u64, buf: &[u8]) -> Result<(), FsError>;

    /// Close a file handle.
    fn close(&mut self, handle: FileHandle);

    /// Scan a directory, returning all entries (including sub-directories).
    ///
    /// Writes up to `out.len()` entries into `out`; returns the count
    /// written.
    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError>;

    /// Root directory absolute path (for ISO9660 path table).
    fn root(&self) -> &str;

    /// Persist the entire filesystem (e.g. after writing `toc.N.json`).
    fn sync(&mut self) -> Result<(), FsError>;

    /// Remove a file (BLANK / orphan track cleanup).
    fn remove(&mut self, path: &str) -> Result<(), FsError>;
}
