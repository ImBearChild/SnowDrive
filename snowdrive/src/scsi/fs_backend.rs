//! Filesystem backends (`fs_backend.c` analogue) + re-exports of the FS
//! storage seam from [`snowcommon`].
//!
//! The [`FsStorage`] trait, [`FsError`], [`DirEntry`], [`FileHandle`],
//! and [`OpenOptions`] live in `snowcommon::fs_storage` (leaf crate,
//! shared with embedded callers).  This module adds the std filesystem
//! backend ([`StdFsBackend`]) and the aggregating [`FsBackend`] enum so
//! callers can drive CD-ROM bundle / live FS devices through a single
//! concrete type.
//! `snowscsi::fs_backend::{FsStorage, FsError, DirEntry, FileHandle,
//! OpenOptions, StdFsBackend, FsBackend}` stays a single import point.

pub use crate::common::fs_storage::{DirEntry, FileHandle, FsError, FsStorage, OpenOptions};

/// Aggregating filesystem storage enum.
///
/// Currently only wraps [`StdFsBackend`] (std).  Embedded callers
/// implement [`FsStorage`] directly and use their own concrete type.
pub enum FsBackend {
    #[cfg(feature = "std")]
    Std(StdFsBackend),
}

impl FsStorage for FsBackend {
    fn open(&mut self, path: &str, opts: OpenOptions) -> Result<FileHandle, FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.open(path, opts),
        }
    }

    fn read(&mut self, handle: &FileHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.read(handle, offset, buf),
        }
    }

    fn write(&mut self, handle: &FileHandle, offset: u64, buf: &[u8]) -> Result<(), FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.write(handle, offset, buf),
        }
    }

    fn close(&mut self, handle: FileHandle) {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.close(handle),
        }
    }

    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.read_dir(path, out),
        }
    }

    fn root(&self) -> &str {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.root(),
        }
    }

    fn sync(&mut self) -> Result<(), FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.sync(),
        }
    }

    fn remove(&mut self, path: &str) -> Result<(), FsError> {
        match self {
            #[cfg(feature = "std")]
            Self::Std(b) => b.remove(path),
        }
    }
}

/// Standard library filesystem backend (std feature, `std::fs`).
///
/// Wraps a directory root; all paths are relative to that root.
#[cfg(feature = "std")]
pub struct StdFsBackend {
    root: std::path::PathBuf,
    /// Open file table.  `FileHandle::get()` indexes into this vec.
    files: Vec<Option<std::fs::File>>,
}

#[cfg(feature = "std")]
impl StdFsBackend {
    /// Create a new backend rooted at `root`.
    ///
    /// The directory must exist; it is **not** created automatically.
    pub fn new(root: &str) -> Self {
        Self {
            root: std::path::PathBuf::from(root),
            files: Vec::new(),
        }
    }

    fn full_path(&self, relative: &str) -> std::path::PathBuf {
        self.root.join(relative)
    }
}

#[cfg(feature = "std")]
impl FsStorage for StdFsBackend {
    fn open(&mut self, path: &str, opts: OpenOptions) -> Result<FileHandle, FsError> {
        let full = self.full_path(path);
        let mut oopts = std::fs::OpenOptions::new();
        oopts
            .read(opts.read)
            .write(opts.write)
            .create(opts.create)
            .truncate(opts.truncate);
        let file = oopts.open(&full).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound,
            other => FsError::Io(other.into()),
        })?;
        // Reuse a freed slot or push a new one.
        let idx = if let Some(free) = self.files.iter().position(|f| f.is_none()) {
            self.files[free] = Some(file);
            free
        } else {
            let idx = self.files.len();
            self.files.push(Some(file));
            idx
        };
        Ok(FileHandle::new(idx))
    }

    fn read(&mut self, handle: &FileHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        use std::io::{Read as _, Seek as _};

        let slot = self
            .files
            .get_mut(handle.get())
            .and_then(|s| s.as_mut())
            .ok_or(FsError::NotFound)?;
        slot.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| FsError::Io(e.kind().into()))?;
        let n = slot.read(buf).map_err(|e| FsError::Io(e.kind().into()))?;
        Ok(n)
    }

    fn write(&mut self, handle: &FileHandle, offset: u64, buf: &[u8]) -> Result<(), FsError> {
        use std::io::{Seek as _, Write as _};

        let slot = self
            .files
            .get_mut(handle.get())
            .and_then(|s| s.as_mut())
            .ok_or(FsError::NotFound)?;
        slot.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| FsError::Io(e.kind().into()))?;
        slot.write_all(buf)
            .map_err(|e| FsError::Io(e.kind().into()))
    }

    fn close(&mut self, handle: FileHandle) {
        if let Some(slot) = self.files.get_mut(handle.get()) {
            *slot = None;
        }
    }

    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
        let full = self.full_path(path);
        let entries = std::fs::read_dir(&full).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound,
            other => FsError::Io(other.into()),
        })?;
        let mut count = 0;
        for entry in entries {
            if count >= out.len() {
                break;
            }
            let entry = entry.map_err(|e| FsError::Io(e.kind().into()))?;
            let metadata = entry.metadata().map_err(|e| FsError::Io(e.kind().into()))?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            let mut name = heapless::String::<256>::new();
            // Truncate if name exceeds 256 bytes (shouldn't happen on
            // sane filesystems, but be defensive).
            for ch in name_str.chars().take(256) {
                let _ = name.push(ch);
            }
            out[count] = DirEntry {
                name,
                is_dir: metadata.is_dir(),
                size: metadata.len(),
            };
            count += 1;
        }
        Ok(count)
    }

    fn root(&self) -> &str {
        self.root.to_str().unwrap_or("")
    }

    fn sync(&mut self) -> Result<(), FsError> {
        use std::io::Write as _;

        for file in self.files.iter_mut().flatten() {
            file.flush().map_err(|e| FsError::Io(e.kind().into()))?;
            file.sync_all().map_err(|e| FsError::Io(e.kind().into()))?;
        }
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<(), FsError> {
        let full = self.full_path(path);
        std::fs::remove_file(&full).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound,
            other => FsError::Io(other.into()),
        })
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("snowscsi_fs_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn empty_entries<const N: usize>() -> [DirEntry; N] {
        std::array::from_fn(|_| DirEntry {
            name: heapless::String::new(),
            is_dir: false,
            size: 0,
        })
    }

    #[test]
    fn open_read_only_existing_file() {
        let dir = temp_dir("ro_open");
        std::fs::write(dir.join("test.txt"), b"hello").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h = fs.open("test.txt", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read(&h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        fs.close(h);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_read_only_missing_file() {
        let dir = temp_dir("ro_missing");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let r = fs.open("nope.txt", OpenOptions::read_only());
        assert_eq!(r, Err(FsError::NotFound));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_or_create_creates_new() {
        let dir = temp_dir("oc_create");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h = fs.open("new.txt", OpenOptions::open_or_create()).unwrap();
        fs.write(&h, 0, b"created").unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read(&h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"created");
        fs.close(h);
        // File should exist on disk after sync.
        fs.sync().unwrap();
        assert_eq!(std::fs::read(dir.join("new.txt")).unwrap(), b"created");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn create_or_truncate_overwrites() {
        let dir = temp_dir("ct_trunc");
        std::fs::write(dir.join("old.txt"), b"aaaaaaaaaa").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h = fs
            .open("old.txt", OpenOptions::create_or_truncate())
            .unwrap();
        fs.write(&h, 0, b"new").unwrap();
        fs.close(h);
        fs.sync().unwrap();
        assert_eq!(std::fs::read(dir.join("old.txt")).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_short_at_eof() {
        let dir = temp_dir("short_read");
        std::fs::write(dir.join("short.bin"), b"abc").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h = fs.open("short.bin", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read(&h, 0, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"abc");
        fs.close(h);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_past_eof_returns_zero() {
        let dir = temp_dir("eof_read");
        std::fs::write(dir.join("tiny.bin"), b"ab").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h = fs.open("tiny.bin", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read(&h, 100, &mut buf).unwrap();
        assert_eq!(n, 0);
        fs.close(h);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_dir_lists_entries() {
        let dir = temp_dir("readdir");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"bb").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut entries: [DirEntry; 8] = empty_entries();
        let n = fs.read_dir(".", &mut entries).unwrap();
        assert!(n >= 3); // a.txt, b.txt, sub
        let names: Vec<&str> = entries[..n].iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
        assert!(names.contains(&"sub"));
        // Check sizes.
        let a = entries[..n]
            .iter()
            .find(|e| e.name.as_str() == "a.txt")
            .unwrap();
        assert_eq!(a.size, 1);
        assert!(!a.is_dir);
        let sub = entries[..n]
            .iter()
            .find(|e| e.name.as_str() == "sub")
            .unwrap();
        assert!(sub.is_dir);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_dir_not_found() {
        let dir = temp_dir("readdir_404");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut entries: [DirEntry; 4] = empty_entries();
        assert_eq!(fs.read_dir("nope", &mut entries), Err(FsError::NotFound));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_dir_buffer_limit() {
        let dir = temp_dir("readdir_limit");
        std::fs::write(dir.join("x"), b"").unwrap();
        std::fs::write(dir.join("y"), b"").unwrap();
        std::fs::write(dir.join("z"), b"").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut entries: [DirEntry; 2] = empty_entries();
        let n = fs.read_dir(".", &mut entries).unwrap();
        assert_eq!(n, 2); // buffer too small for 3 entries
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_file() {
        let dir = temp_dir("remove");
        std::fs::write(dir.join("gone.txt"), b"bye").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        fs.remove("gone.txt").unwrap();
        assert!(!dir.join("gone.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_missing_file() {
        let dir = temp_dir("remove_missing");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        assert_eq!(fs.remove("nope.txt"), Err(FsError::NotFound));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn close_and_reopen() {
        let dir = temp_dir("close_reopen");
        std::fs::write(dir.join("f"), b"data").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let h1 = fs.open("f", OpenOptions::read_only()).unwrap();
        fs.close(h1);
        // Reopen — may reuse the same slot.
        let h2 = fs.open("f", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 8];
        let n = fs.read(&h2, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"data");
        fs.close(h2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fs_backend_enum_dispatch() {
        let dir = temp_dir("enum_dispatch");
        std::fs::write(dir.join("f"), b"enum").unwrap();
        let mut fs = FsBackend::Std(StdFsBackend::new(&dir.to_string_lossy()));
        let h = fs.open("f", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 8];
        let n = fs.read(&h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"enum");
        fs.close(h);
        fs.sync().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fs_backend_root() {
        let dir = temp_dir("root");
        let fs = FsBackend::Std(StdFsBackend::new(&dir.to_string_lossy()));
        assert_eq!(fs.root(), dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
