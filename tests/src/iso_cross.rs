//! Cross-validation of the live ISO9660 generator against an independent
//! parser (`hadris-iso`, a pure-Rust ISO 9660 reader).  This is a pure
//! test dependency: it verifies that the image our generator produces is
//! readable by a spec-strict third-party implementation, and that the
//! tree structure, names, sizes and file contents all match the host
//! directory.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use hadris_iso::read::{DirEntry, IsoDir, IsoImage};

use snowdrive::iso9660::live::{MAX_JOLIET_NAME_CHARS, SECTOR_SIZE};
use snowdrive::scsi::cdrom_livefs::CdLiveFsDevice;
use snowdrive::scsi::fs_backend::StdFsBackend;

/// Build a host tree under a fresh temp dir and return `(dir, files)`
/// where `files` is `(relative_path, content)`.
fn build_tree() -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let dir = std::env::temp_dir().join(format!("snowdrive_iso_cross_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir.join("docs/deep")).unwrap();
    std::fs::create_dir_all(&dir.join("images")).unwrap();

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |path: &str, content: Vec<u8>| {
        std::fs::write(dir.join(path), &content).unwrap();
        files.push((path.to_string(), content));
    };
    add("README.TXT", b"hello root".to_vec());
    add("docs/manual.pdf", vec![0x41u8; 2049]); // crosses one sector boundary
    add("docs/deep/notes.txt", vec![0x42u8; 100]);
    add("images/photo.png", vec![0x43u8; 4096]);
    // Exactly MAX_JOLIET_NAME_CHARS characters (including extension):
    // must be preserved whole.
    let exact = format!("{}.TXT", "A".repeat(MAX_JOLIET_NAME_CHARS - 4));
    assert_eq!(exact.chars().count(), MAX_JOLIET_NAME_CHARS);
    add(&exact, b"exact fit".to_vec());
    // One character over: must be truncated to MAX_JOLIET_NAME_CHARS.
    let over = format!("{}.DAT", "B".repeat(MAX_JOLIET_NAME_CHARS + 1));
    add(&over, b"over limit".to_vec());
    (dir, files)
}

/// Dump the whole live image (all sectors) to a `Vec<u8>`.
fn build_image(dir: &Path) -> Vec<u8> {
    let fs = StdFsBackend::new(&dir.to_string_lossy());
    let mut dev = CdLiveFsDevice::new(fs, "CROSS").expect("scan tree");
    let total = dev.layout().total as usize;
    let mut img = vec![0u8; total * SECTOR_SIZE as usize];
    for lba in 0..total as u32 {
        let start = lba as usize * SECTOR_SIZE as usize;
        dev.read_data(
            lba as u64 * SECTOR_SIZE as u64,
            &mut img[start..start + SECTOR_SIZE as usize],
        )
        .expect("read sector");
    }
    img
}

/// Recursively collect (relative path, size, content) from a hadris dir.
fn walk<D: hadris_iso::Read + hadris_iso::Seek>(
    image: &IsoImage<D>,
    dir: &IsoDir<'_, D>,
    prefix: &str,
    out: &mut Vec<(String, u64, Vec<u8>)>,
) {
    for entry in dir.entries() {
        let entry: DirEntry = entry.expect("hadris entry");
        // Skip "." and "..": their identifiers are single bytes 0x00 / 0x01.
        let raw = entry.name();
        if raw.is_empty() || raw == [0x00] || raw == [0x01] {
            continue;
        }
        // Our image is Joliet-only, so names are UCS-2BE; decode them.
        let name = entry.record.joliet_name();
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.is_directory() {
            let dir_ref = entry.as_dir_ref(image).expect("dir ref");
            let sub = image.open_dir(dir_ref);
            walk(image, &sub, &path, out);
        } else if entry.is_file() {
            let content = image.read_file(&entry).expect("read file");
            let size = content.len() as u64;
            out.push((path, size, content));
        }
    }
}

#[test]
fn live_image_reads_back_through_hadris() {
    let (dir, host_files) = build_tree();
    let img = build_image(&dir);
    let image = IsoImage::open(Cursor::new(img)).expect("hadris open image");

    // Volume identifier survives.
    let pvd = image.read_pvd();
    assert_eq!(pvd.volume_identifier.to_str().trim(), "CROSS");

    // Walk the image tree via the Joliet root (our image is Joliet-only:
    // the PVD tree shares the UCS-2 directory, so plain-ISO9660 name
    // interpretation returns raw bytes).
    let root = image.root_dirs().best_choice();
    let mut iso_files: Vec<(String, u64, Vec<u8>)> = Vec::new();
    walk(&image, &root.iter(&image), "", &mut iso_files);

    // Every host file is present with matching size and content (the
    // over-limit file is truncated, so it is checked separately below).
    let over = format!("{}.DAT", "B".repeat(MAX_JOLIET_NAME_CHARS + 1));
    for (path, content) in host_files.iter().filter(|(p, _)| *p != over) {
        let expected = content.len() as u64;
        let found = iso_files
            .iter()
            .find(|(p, _, _)| p == path)
            .unwrap_or_else(|| panic!("file {path} missing from the image; found: {iso_files:#?}"));
        assert_eq!(found.1, expected, "size mismatch for {path}");
        assert_eq!(&found.2, content, "content mismatch for {path}");
    }
    assert_eq!(
        iso_files.len(),
        host_files.len(),
        "the image must not contain extra files"
    );

    // The over-limit name is truncated to MAX_JOLIET_NAME_CHARS in the ISO
    // (the ".DAT" extension is cut off too).
    let over = format!("{}.DAT", "B".repeat(MAX_JOLIET_NAME_CHARS + 1));
    let truncated = "B".repeat(MAX_JOLIET_NAME_CHARS);
    let over_iso = iso_files
        .iter()
        .find(|(p, _, _)| *p == truncated)
        .expect("over-limit file present (truncated)");
    assert_eq!(over_iso.0, truncated);
    assert_ne!(over_iso.0, over);

    let _ = std::fs::remove_dir_all(&dir);
}
