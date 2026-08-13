#![forbid(unsafe_code)]
//! `snowdrive` CLI — SnowDrive SCSI target and ISO9660 image tools
//! (`snowdrive_main.c`).
//!
//! Subcommands:
//! - `serve`: run the iSCSI target (serial accept loop)
//! - `mkisofs`: generate an ISO9660/Joliet image from a host directory
//!   (the live-generation algorithm, dumped sector-by-sector to a file)
//!
//! Device flags come in two planes (QEMU-style `[key=]value[,option...]`
//! specs). `--disk` is the block plane; `--cdrom` is the CD plane.
//!
//! - `--disk` (block plane): `ram=<size>` (K/M/G suffixes), `cd=<path>`
//!   (read-only ISO as a lazy CD-ROM, PDT=0x05), or `[img=]<path>[,ro]`
//!   (file, default key `img=`).
//! - `--cdrom` (CD plane): `img=<iso>` (flat full MMC), `live=<dir>` (live
//!   ISO9660 over a directory); bare `.iso` maps to `img=`. Other bare
//!   values are rejected (no auto-typing by suffix). `bundle=` (Phase 3)
//!   and `ram=` (Phase 4) are reserved.
//!
//! LUN numbering: all `--disk` devices first, then all `--cdrom` devices
//! (the two planes cannot interleave). The same file path may appear on
//! several LUNs; each is an independent SCSI device with its own LBA
//! semantics, so a dual-mount warning is printed to stderr. SIGINT / SIGTERM
//! trigger a graceful shutdown: the blocking `accept()` is woken by a probe
//! connection, `serve()` returns, and every backend is `sync()`ed before
//! exit.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Args, Parser};
use snowdrive::cdrom::CdLiveFsDevice;
use snowdrive::cdrom::CdromDevice;
use snowdrive::iscsi::transport::{serve, DEFAULT_READ_TIMEOUT};
use snowdrive::scsi::backend::{BlockBackend, BlockStorage, FileBackend, RamBackend};
use snowdrive::scsi::block::BlockDevice;
use snowdrive::scsi::cdblock::CDBlockDevice;
use snowdrive::scsi::device::Device;
use snowdrive::scsi::fs_backend::{FsBackend, StdFsBackend};
use snowdrive::MIN_DATA_LEN;

/// Default work buffer size (256 KiB).
const DEFAULT_WORK_BUF_SIZE: usize = 256 * 1024;
/// Sector size for block devices exposed by the CLI (like the C CLI).
const SECTOR_SIZE: u32 = 512;
/// CD-ROM logical sector size (Mode 1 data).
const ISO_SECTOR_SIZE: u32 = 2048;

#[derive(Debug, Parser)]
#[command(
    name = "snowdrive",
    about = "SnowDrive SCSI target and ISO9660 tools",
    version
)]
enum Cli {
    /// Start the iSCSI target server
    Serve(ServeArgs),
    /// Generate an ISO9660/Joliet image from a directory
    Mkisofs(MkisofsArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Block plane device: `[img=]<path>[,ro]` (file, `img=` default),
    /// `ram=<size>` (K/M/G suffixes), or `cd=<path>` (read-only ISO as a
    /// lazy CD-ROM). Repeatable; `--disk` LUNs come first in order.
    #[arg(long = "disk", value_name = "SPEC")]
    disk: Vec<String>,

    /// CD-ROM device: `img=<path>.iso` (flat, full MMC) or `live=<dir>`
    /// (live ISO9660); a bare `.iso` also maps to `img=`. `bundle=` (Phase
    /// 3) and `ram=` (Phase 4) are reserved. Repeatable; these LUNs follow
    /// the `--disk` LUNs.
    #[arg(long = "cdrom", value_name = "SPEC")]
    cdrom: Vec<String>,

    /// iSCSI listen address (required).
    #[arg(long = "iscsi", value_name = "ADDR:PORT")]
    iscsi: Option<String>,

    /// Verbose logging: -v = debug, -vv = trace.
    #[arg(long, short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Work buffer size in bytes (accepts K/M/G suffixes; default 256K).
    #[arg(long = "work-buf-size", value_name = "BYTES")]
    work_buf_size: Option<String>,
}

/// Arguments for `snowdrive mkisofs`: build an ISO9660/Joliet image from a
/// host directory (the live-generation algorithm dumped to a file).
#[derive(Args, Debug)]
struct MkisofsArgs {
    /// Source directory to scan into the image.
    #[arg(value_name = "DIR")]
    dir: String,
    /// Output ISO image file path.
    #[arg(value_name = "OUT.iso")]
    out: String,
    /// Volume label (default: the source directory name, max 16 chars).
    #[arg(long, value_name = "NAME")]
    label: Option<String>,
    /// Verbose logging: -v = debug, -vv = trace.
    #[arg(long, short, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    match Cli::parse() {
        Cli::Serve(args) => run_serve(args),
        Cli::Mkisofs(args) => run_mkisofs(args),
    }
}

fn run_serve(args: ServeArgs) -> ExitCode {
    init_logging(args.verbose);

    let addr = match args.iscsi.as_deref() {
        None => {
            eprintln!("snowdrive: --iscsi is required");
            return ExitCode::FAILURE;
        }
        Some(s) => match s.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("snowdrive: invalid --iscsi address: {s}");
                return ExitCode::FAILURE;
            }
        },
    };

    if args.disk.is_empty() && args.cdrom.is_empty() {
        eprintln!("snowdrive: --disk or --cdrom is required (at least one device)");
        return ExitCode::FAILURE;
    }

    let work_size = match parse_work_size(args.work_buf_size.as_deref()) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("snowdrive: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let mut disk_specs = Vec::with_capacity(args.disk.len());
    for spec in &args.disk {
        let parsed = match parse_disk_spec(spec) {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("snowdrive: invalid --disk spec '{spec}': {msg}");
                return ExitCode::FAILURE;
            }
        };
        disk_specs.push(parsed);
    }

    let mut cdrom_specs = Vec::with_capacity(args.cdrom.len());
    for spec in &args.cdrom {
        let parsed = match parse_cdrom_spec(spec) {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("snowdrive: invalid --cdrom spec '{spec}': {msg}");
                return ExitCode::FAILURE;
            }
        };
        cdrom_specs.push(parsed);
    }

    // Reject missing sources up front (FileBackend would otherwise create a
    // fresh empty file when opened writable; CdromDevice/CdLiveFs would
    // otherwise fail later).
    for spec in &disk_specs {
        match spec {
            DiskSpec::Img { path, .. } | DiskSpec::Cdrom { path } => {
                if !Path::new(path).is_file() {
                    eprintln!("snowdrive: file not found: {path}");
                    return ExitCode::FAILURE;
                }
            }
            DiskSpec::Ram(_) => {}
        }
    }
    for spec in &cdrom_specs {
        match spec {
            CdromSpec::Flat { path } => {
                if !Path::new(path).is_file() {
                    eprintln!("snowdrive: file not found: {path}");
                    return ExitCode::FAILURE;
                }
            }
            CdromSpec::Live { dir } => {
                if !Path::new(dir).is_dir() {
                    eprintln!("snowdrive: directory not found: {dir}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    for w in check_dual_mount(&dual_mount_specs(&disk_specs, &cdrom_specs)) {
        eprintln!("{w}");
    }

    // Allocate every RAM disk first so the Device array can borrow them
    // without 'static / Box::leak — disjoint borrows via split_first_mut.
    let mut ram_disks: Vec<Vec<u8>> = Vec::with_capacity(disk_specs.len());
    for spec in &disk_specs {
        if let DiskSpec::Ram(size) = spec {
            let bytes = match usize::try_from(*size) {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("snowdrive: RAM size {size} too large for this platform");
                    return ExitCode::FAILURE;
                }
            };
            ram_disks.push(vec![0u8; bytes]);
        }
    }

    // LUN order: all --disk devices first, then all --cdrom devices (clap
    // collects each flag separately, so the interleaved appearance order
    // cannot be restored; the two planes do not interleave).
    let mut devices: Vec<Device<'_>> = Vec::with_capacity(disk_specs.len() + cdrom_specs.len());
    let mut ram_rest: &mut [Vec<u8>] = &mut ram_disks;
    let mut lun = 0usize;
    for spec in &disk_specs {
        match spec {
            DiskSpec::Ram(_) => {
                let (slot, tail) = ram_rest.split_first_mut().unwrap();
                ram_rest = tail;
                let backend = BlockBackend::Ram(RamBackend::new(slot));
                let mut dev =
                    BlockDevice::new(backend, SECTOR_SIZE).expect("SECTOR_SIZE is nonzero");
                log::debug!("LUN {lun}: {} bytes block device", dev.backend().capacity());
                devices.push(Device::Block(dev));
            }
            DiskSpec::Img { path, read_only } => {
                // Existence was checked by parse; FileBackend would otherwise
                // create a fresh file when opened writable.
                match FileBackend::open(path, !*read_only) {
                    Ok(b) => {
                        let mut dev = BlockDevice::new(BlockBackend::File(b), SECTOR_SIZE)
                            .expect("SECTOR_SIZE is nonzero");
                        log::debug!(
                            "LUN {lun}: {path} block device ({}{} bytes)",
                            if *read_only { "read-only, " } else { "" },
                            dev.backend().capacity()
                        );
                        devices.push(Device::Block(dev));
                    }
                    Err(e) => {
                        eprintln!("snowdrive: failed to open file block device {path}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            DiskSpec::Cdrom { path } => {
                let dev = match CDBlockDevice::new(path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("snowdrive: failed to open CD-ROM image {path}: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                log::debug!("LUN {lun}: {path} CD-ROM image");
                devices.push(Device::CdBlock(dev));
            }
        }
        lun += 1;
    }
    for spec in &cdrom_specs {
        match spec {
            CdromSpec::Flat { path } => {
                let backend = match FileBackend::open(path, false) {
                    Ok(b) => BlockBackend::File(b),
                    Err(e) => {
                        eprintln!("snowdrive: failed to open CD-ROM image {path}: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                let mut dev = CdromDevice::new(backend);
                log::debug!(
                    "LUN {lun}: {path} flat CD-ROM ({} bytes)",
                    dev.backend().capacity()
                );
                devices.push(Device::CdFlat(dev));
            }
            CdromSpec::Live { dir } => {
                let fs = FsBackend::Std(StdFsBackend::new(dir));
                let label = Path::new(dir)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("SNOWDRIVE");
                match CdLiveFsDevice::new(fs, label) {
                    Ok(dev) => {
                        log::debug!(
                            "LUN {lun}: {dir} live ISO9660 CD-ROM ({} sectors)",
                            dev.layout().total
                        );
                        devices.push(Device::CdLiveFs(dev));
                    }
                    Err(e) => {
                        eprintln!("snowdrive: failed to scan live directory {dir}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
        lun += 1;
    }

    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("snowdrive: failed to bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Graceful shutdown: SIGINT/SIGTERM set `stop`;
    // a probe connection wakes the blocking accept() so serve() can observe
    // it and return (transport serves one connection at a time).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        let probe = listener.local_addr().ok();
        if let Err(e) = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
            if let Some(addr) = probe {
                let _ = std::net::TcpStream::connect(addr);
            }
        }) {
            eprintln!("snowdrive: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut work = vec![0u8; work_size];
    // Report the actual bound address: `--iscsi 127.0.0.1:0` picks an
    // ephemeral port, so callers (tests) must learn it from this line.
    let bound = listener.local_addr().unwrap_or(addr);
    log::info!("listening on {bound} with {} LUN(s)", devices.len());

    if let Err(e) = serve(
        listener,
        &stop,
        &mut work,
        &mut devices,
        Some(DEFAULT_READ_TIMEOUT),
    ) {
        eprintln!("snowdrive: server error: {e}");
        return ExitCode::FAILURE;
    }

    // Graceful exit: flush backends.
    for (i, dev) in devices.iter_mut().enumerate() {
        let result = match dev {
            Device::Block(d) => d.backend().sync(),
            Device::CdBlock(d) => d.backend().sync(),
            Device::CdFlat(d) => d.backend().sync(),
            Device::CdLiveFs(d) => d.sync().map_err(Into::into),
        };
        if let Err(e) = result {
            eprintln!("snowdrive: sync failed for LUN {i}: {e}");
        }
    }
    log::info!("shutting down");
    ExitCode::SUCCESS
}

/// `snowdrive mkisofs <DIR> <OUT.iso>` — scan a host directory and write a
/// standalone ISO9660/Joliet image to disk.
///
/// Reuses the live-generation pipeline (`CdLiveFsDevice`: scan → layout →
/// sector synthesis) and dumps every sector through `read_data`, so the
/// on-disk image is byte-identical to what `serve --cdrom live=<dir>`
/// would expose. The image is padded to whole 2048-byte sectors.
fn run_mkisofs(args: MkisofsArgs) -> ExitCode {
    init_logging(args.verbose);

    let dir = Path::new(&args.dir);
    if !dir.is_dir() {
        eprintln!("snowdrive: directory not found: {}", args.dir);
        return ExitCode::FAILURE;
    }
    if args.out.is_empty() {
        eprintln!("snowdrive: empty output path");
        return ExitCode::FAILURE;
    }
    if Path::new(&args.out).is_dir() {
        eprintln!("snowdrive: output path is a directory: {}", args.out);
        return ExitCode::FAILURE;
    }

    let label = match &args.label {
        Some(l) => l.clone(),
        None => dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("SNOWDRIVE")
            .to_string(),
    };

    let fs = FsBackend::Std(StdFsBackend::new(&args.dir));
    let dev = match CdLiveFsDevice::new(fs, &label) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("snowdrive: failed to scan {}: {e}", args.dir);
            return ExitCode::FAILURE;
        }
    };
    let total_sectors = dev.layout().total;
    let mut dev = dev;

    let file = match File::create(&args.out) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("snowdrive: failed to create {}: {e}", args.out);
            return ExitCode::FAILURE;
        }
    };
    let mut writer = BufWriter::new(file);
    let mut sector = [0u8; ISO_SECTOR_SIZE as usize];
    for lba in 0..total_sectors {
        if dev
            .read_data(u64::from(lba) * u64::from(ISO_SECTOR_SIZE), &mut sector)
            .is_err()
        {
            eprintln!("snowdrive: failed to read sector {lba}");
            return ExitCode::FAILURE;
        }
        if writer.write_all(&sector).is_err() {
            eprintln!("snowdrive: failed to write {}", args.out);
            return ExitCode::FAILURE;
        }
    }
    if writer.flush().is_err() {
        eprintln!("snowdrive: failed to flush {}", args.out);
        return ExitCode::FAILURE;
    }

    log::info!(
        "wrote {} sectors ({} bytes) to {}",
        total_sectors,
        u64::from(total_sectors) * u64::from(ISO_SECTOR_SIZE),
        args.out
    );
    ExitCode::SUCCESS
}

/// Install the CLI log output: a plain `log` backend (env_logger) writing
/// to stderr. `-v` selects the debug level, `-vv` (or more) the trace
/// level; `RUST_LOG` overrides both.
fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.parse_default_env();
    // try_init: a logger may already be set when tests drive the handlers
    // in-process (parallel test threads share the process logger).
    let _ = builder.try_init();
}

/// A parsed `--disk` spec (block plane).
#[derive(Debug)]
enum DiskSpec {
    /// `ram=<size>` → RAM-backed block device.
    Ram(u64),
    /// `[img=]<path>[,ro]` → file-backed block device (`img=` is default).
    Img { path: String, read_only: bool },
    /// `cd=<path>` → lazy CD-ROM (PDT=0x05, 2048B sectors, read-only).
    Cdrom { path: String },
}

/// A parsed `--cdrom` spec (CD plane).
#[derive(Debug)]
enum CdromSpec {
    /// `img=<iso>` → flat ISO9660, full MMC (`CdromDevice<FileBackend>`).
    Flat { path: String },
    /// `live=<dir>` → live ISO9660 over a directory
    /// (`CdLiveFsDevice<FsBackend>`).
    Live { dir: String },
}

/// How a path is exposed as a SCSI device (dual-mount detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Block,
    CdBlock,
    CdFlat,
    CdLiveFs,
}

/// Collect the file-backed specs as `(kind, path)` pairs for dual-mount
/// detection (RAM disks have no path). All slices live in the caller; the
/// returned paths borrow from them.
fn dual_mount_specs<'a>(
    disk_specs: &'a [DiskSpec],
    cdrom_specs: &'a [CdromSpec],
) -> Vec<(DeviceKind, &'a str)> {
    let mut out: Vec<(DeviceKind, &'a str)> = disk_specs
        .iter()
        .filter_map(|s| match s {
            DiskSpec::Img { path, .. } => Some((DeviceKind::Block, path.as_str())),
            DiskSpec::Cdrom { path } => Some((DeviceKind::CdBlock, path.as_str())),
            DiskSpec::Ram(_) => None,
        })
        .collect();
    out.extend(cdrom_specs.iter().map(|s| match s {
        CdromSpec::Flat { path } => (DeviceKind::CdFlat, path.as_str()),
        CdromSpec::Live { dir } => (DeviceKind::CdLiveFs, dir.as_str()),
    }));
    out
}

/// Detect the same path mounted as multiple independent SCSI devices and
/// return the stderr warning lines. A path appearing more than once in total
/// (same or different device kinds) is warned: each occurrence is a distinct
/// LUN with its own LBA semantics (e.g. `--disk cd=f.iso --cdrom img=f.iso`).
fn check_dual_mount(specs: &[(DeviceKind, &str)]) -> Vec<String> {
    let mut seen: std::collections::HashMap<&str, Vec<DeviceKind>> =
        std::collections::HashMap::new();
    for (kind, path) in specs {
        seen.entry(path).or_default().push(*kind);
    }
    let mut warnings = Vec::new();
    for (path, kinds) in seen {
        if kinds.len() > 1 {
            warnings.push(format!(
                "warning: path '{path}' is mounted as {kinds:?}; these are \
                 independent SCSI devices with different LBA semantics"
            ));
        }
    }
    warnings
}

/// Parse a `--disk` spec: `ram=<size>`, `ram=<size>`/`<path>[,ro]`.
///
/// - `ram=<size>` → RAM disk.
/// - `cd=<path>` → lazy CD-ROM image.
/// - `img=<path>`, `[img=]<path>[,ro]` → file block device (`img=` default).
///
/// Unknown options are ignored with a warning (C behavior).
fn parse_disk_spec(spec: &str) -> Result<DiskSpec, String> {
    if let Some(size) = spec.strip_prefix("ram=") {
        return match parse_size(size) {
            Some(n) => Ok(DiskSpec::Ram(n)),
            None => Err(format!("invalid RAM size: {size}")),
        };
    }
    if let Some(path) = spec.strip_prefix("cd=") {
        if path.is_empty() {
            return Err("empty `cd=` path".to_string());
        }
        return Ok(DiskSpec::Cdrom {
            path: path.to_string(),
        });
    }
    // Default key: `img=`. Strip it if present.
    let rest = spec.strip_prefix("img=").unwrap_or(spec);
    let (path, opt) = match rest.split_once(',') {
        Some((p, o)) => (p, Some(o)),
        None => (rest, None),
    };
    let read_only = match opt {
        Some("ro") => true,
        Some(o) => {
            log::warn!("unknown disk option '{o}', ignoring");
            false
        }
        None => false,
    };
    if path.is_empty() {
        return Err("empty file path".to_string());
    }
    Ok(DiskSpec::Img {
        path: path.to_string(),
        read_only,
    })
}

/// Parse a `--cdrom` spec (QEMU-style keyed value).
///
/// - `img=<iso>` → flat ISO9660 CD-ROM (full MMC).
/// - `live=<dir>` → live ISO9660 CD-ROM over the directory.
/// - `<path>.iso` → same as `img=<path>` (bare value: only `.iso` is
///   auto-typed; anything else is rejected — no bundle auto-detection).
/// - `bundle=` / `ram=` → reserved for Phase 3 / Phase 4.
fn parse_cdrom_spec(spec: &str) -> Result<CdromSpec, String> {
    if let Some(path) = spec.strip_prefix("bundle=") {
        return Err(format!(
            "{path}: bundle cdrom mode is not yet supported (Phase 3)"
        ));
    }
    if spec.starts_with("ram=") {
        return Err("ram= cdrom mode is not yet supported (Phase 4)".to_string());
    }
    let (value, opts) = match spec.split_once(',') {
        Some((v, o)) => (v, o),
        None => (spec, ""),
    };
    let (path, live) = if let Some(p) = value.strip_prefix("live=") {
        (p, true)
    } else if let Some(p) = value.strip_prefix("img=") {
        (p, false)
    } else {
        // Bare value: only `.iso` is auto-typed to `img=`; anything else is
        // rejected rather than guessed (no live/bundle/ram by suffix).
        (value, false)
    };
    if path.is_empty() {
        return Err("empty path".to_string());
    }
    for opt in opts.split(',') {
        if opt.starts_with("recovery=") {
            return Err("bundle recovery mode is not yet supported".to_string());
        }
        if !opt.is_empty() {
            log::warn!("unknown cdrom option '{opt}', ignoring");
        }
    }
    if live {
        return Ok(CdromSpec::Live {
            dir: path.to_string(),
        });
    }
    if value.starts_with("img=") {
        return Ok(CdromSpec::Flat {
            path: path.to_string(),
        });
    }
    if path.to_ascii_lowercase().ends_with(".iso") {
        return Ok(CdromSpec::Flat {
            path: path.to_string(),
        });
    }
    Err(format!(
        "{path}: not a .iso file and no explicit cdrom key; use \
         `--cdrom img=<iso>` / `--cdrom live=<dir>` / `--cdrom <file>.iso`"
    ))
}

/// Resolve the work buffer size (default 256K), validating it against
/// [`MIN_DATA_LEN`].
fn parse_work_size(s: Option<&str>) -> Result<usize, String> {
    let bytes = match s {
        None => DEFAULT_WORK_BUF_SIZE as u64,
        Some(v) => parse_size(v).ok_or_else(|| format!("invalid --work-buf-size: {v}"))?,
    };
    let n = usize::try_from(bytes).map_err(|_| format!("--work-buf-size {bytes} is too large"))?;
    if n < MIN_DATA_LEN {
        return Err(format!(
            "--work-buf-size {n} is below the minimum {MIN_DATA_LEN}"
        ));
    }
    Ok(n)
}

/// Parse a size with an optional K/M/G suffix (C `parse_size`).
/// Returns `None` for empty, non-numeric, unsupported-suffix, zero, or
/// overflowing input (C's convention: 0 == invalid).
fn parse_size(s: &str) -> Option<u64> {
    let digit_len = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    let digits = &s[..digit_len];
    if digits.is_empty() {
        return None;
    }
    let mut val: u64 = digits.parse().ok()?;
    let suffix = &s[digit_len..];
    match suffix {
        "" => {}
        "K" | "k" => val = val.checked_mul(1 << 10)?,
        "M" | "m" => val = val.checked_mul(1 << 20)?,
        "G" | "g" => val = val.checked_mul(1 << 30)?,
        _ => return None,
    }
    (val != 0).then_some(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_plain_and_suffixes() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("1K"), Some(1024));
        assert_eq!(parse_size("1k"), Some(1024));
        assert_eq!(parse_size("2M"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("256M"), Some(256 * 1024 * 1024));
    }

    #[test]
    fn parse_size_invalid() {
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("12X"), None);
        assert_eq!(parse_size("0"), None); // C: size 0 → invalid
        assert_eq!(parse_size("0M"), None);
        assert_eq!(parse_size("-5"), None);
        assert_eq!(parse_size("18446744073709551615G"), None); // overflow
    }

    #[test]
    fn parse_disk_spec_ram() {
        match parse_disk_spec("ram=8M").unwrap() {
            DiskSpec::Ram(n) => assert_eq!(n, 8 * 1024 * 1024),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_disk_spec("ram=bogus").is_err());
        assert!(parse_disk_spec("ram=").is_err());
        assert!(parse_disk_spec("ram=0").is_err());
    }

    #[test]
    fn parse_disk_spec_img() {
        let DiskSpec::Img { path, read_only } = parse_disk_spec("disk.img").unwrap() else {
            panic!("unexpected spec")
        };
        assert_eq!(path, "disk.img");
        assert!(!read_only);
        // Bare value and explicit `img=` are equivalent (default key).
        match parse_disk_spec("img=cool.img").unwrap() {
            DiskSpec::Img { path, .. } => assert_eq!(path, "cool.img"),
            other => panic!("unexpected spec: {other:?}"),
        }
        // `.ro`, unknown option ignored (C behavior), empty path rejected.
        match parse_disk_spec("disk.img,ro").unwrap() {
            DiskSpec::Img { read_only, .. } => assert!(read_only),
            other => panic!("unexpected spec: {other:?}"),
        }
        match parse_disk_spec("disk.img,bogus").unwrap() {
            DiskSpec::Img { read_only, .. } => assert!(!read_only),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_disk_spec(",ro").is_err());
    }

    #[test]
    fn parse_disk_spec_cdrom_key() {
        match parse_disk_spec("cd=disc.iso").unwrap() {
            DiskSpec::Cdrom { path } => assert_eq!(path, "disc.iso"),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_disk_spec("cd=").is_err());
    }

    #[test]
    fn parse_cdrom_spec_flat_iso() {
        match parse_cdrom_spec("boot.iso").unwrap() {
            CdromSpec::Flat { path } => assert_eq!(path, "boot.iso"),
            other => panic!("unexpected spec: {other:?}"),
        }
        // Case-insensitive suffix.
        match parse_cdrom_spec("BOOT.ISO").unwrap() {
            CdromSpec::Flat { path } => assert_eq!(path, "BOOT.ISO"),
            other => panic!("unexpected spec: {other:?}"),
        }
    }

    #[test]
    fn parse_cdrom_spec_explicit_keys() {
        match parse_cdrom_spec("img=boot.iso").unwrap() {
            CdromSpec::Flat { path } => assert_eq!(path, "boot.iso"),
            other => panic!("unexpected spec: {other:?}"),
        }
        match parse_cdrom_spec("live=tree").unwrap() {
            CdromSpec::Live { dir } => assert_eq!(dir, "tree"),
            other => panic!("unexpected spec: {other:?}"),
        }
    }

    #[test]
    fn parse_cdrom_spec_unsupported_modes() {
        // Bundle: explicit keys and old-style plain directory / `.d` suffix.
        assert!(parse_cdrom_spec("bundle=rw.d").is_err());
        assert!(parse_cdrom_spec("rw.d").is_err());
        assert!(parse_cdrom_spec("tree").is_err());
        assert!(parse_cdrom_spec("tree,recovery=delete").is_err());
        // RAM mode (Phase 4).
        assert!(parse_cdrom_spec("ram=64M").is_err());
    }

    #[test]
    fn parse_cdrom_spec_ignores_unknown_option() {
        match parse_cdrom_spec("boot.iso,whatever").unwrap() {
            CdromSpec::Flat { path } => assert_eq!(path, "boot.iso"),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_cdrom_spec("").is_err());
        assert!(parse_cdrom_spec(",live").is_err());
    }

    #[test]
    fn parse_work_size_defaults_and_validation() {
        assert_eq!(parse_work_size(None).unwrap(), DEFAULT_WORK_BUF_SIZE);
        assert_eq!(parse_work_size(Some("128K")).unwrap(), 128 * 1024);
        assert!(parse_work_size(Some("1000")).is_err()); // below MIN_DATA_LEN
        assert!(parse_work_size(Some("bogus")).is_err());
    }

    #[test]
    fn dual_mount_same_path_twice_warns() {
        let w = check_dual_mount(&[(DeviceKind::Block, "a.img"), (DeviceKind::Block, "a.img")]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("a.img"));
        assert!(w[0].starts_with("warning:"));
    }

    #[test]
    fn dual_mount_distinct_paths_do_not_warn() {
        let w = check_dual_mount(&[(DeviceKind::Block, "a.img"), (DeviceKind::Block, "b.img")]);
        assert!(w.is_empty());
    }

    #[test]
    fn dual_mount_single_spec_does_not_warn() {
        let w = check_dual_mount(&[(DeviceKind::Block, "a.img")]);
        assert!(w.is_empty());
    }

    #[test]
    fn dual_mount_specs_collects_disk_paths_only() {
        let specs = [
            DiskSpec::Ram(1024),
            DiskSpec::Img {
                path: "a.img".to_string(),
                read_only: false,
            },
            DiskSpec::Img {
                path: "a.img".to_string(),
                read_only: true,
            },
        ];
        let d = dual_mount_specs(&specs, &[]);
        assert_eq!(
            d,
            vec![(DeviceKind::Block, "a.img"), (DeviceKind::Block, "a.img")]
        );
        let w = check_dual_mount(&d);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn dual_mount_cdrom_key_paths_are_collected() {
        let disk = [DiskSpec::Cdrom {
            path: "boot.iso".to_string(),
        }];
        let d = dual_mount_specs(&disk, &[]);
        assert_eq!(d, vec![(DeviceKind::CdBlock, "boot.iso")]);
        assert!(check_dual_mount(&d).is_empty());
    }

    #[test]
    fn dual_mount_img_and_cdrom_same_path_warns() {
        let disk = [DiskSpec::Img {
            path: "boot.iso".to_string(),
            read_only: false,
        }];
        let cd = [DiskSpec::Cdrom {
            path: "boot.iso".to_string(),
        }];
        let d = dual_mount_specs(&disk, &[]);
        let e = dual_mount_specs(&cd, &[]);
        let mut all = d;
        all.extend(e);
        let w = check_dual_mount(&all);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("boot.iso"));
        assert!(w[0].starts_with("warning:"));
    }

    #[test]
    fn dual_mount_cdrom_specs_are_collected() {
        let cdrom = vec![
            CdromSpec::Flat {
                path: "boot.iso".to_string(),
            },
            CdromSpec::Live {
                dir: "tree".to_string(),
            },
        ];
        let d = dual_mount_specs(&[], &cdrom);
        assert_eq!(
            d,
            vec![
                (DeviceKind::CdFlat, "boot.iso"),
                (DeviceKind::CdLiveFs, "tree")
            ]
        );
        assert!(check_dual_mount(&d).is_empty());
    }

    #[test]
    fn dual_mount_disk_and_cdrom_same_path_warns() {
        let disk = [DiskSpec::Img {
            path: "boot.iso".to_string(),
            read_only: false,
        }];
        let cdrom = vec![CdromSpec::Flat {
            path: "boot.iso".to_string(),
        }];
        let d = dual_mount_specs(&disk, &cdrom);
        let w = check_dual_mount(&d);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("boot.iso"));
        assert!(w[0].starts_with("warning:"));
    }

    #[test]
    fn cli_accepts_multiple_disk_and_cdrom_specs() {
        let cli = Cli::try_parse_from([
            "snowdrive",
            "serve",
            "--disk",
            "ram=1M",
            "--disk",
            "img=disk.img,ro",
            "--disk",
            "cd=legacy.iso",
            "--cdrom",
            "img=boot.iso",
            "--cdrom",
            "live=tree",
            "--iscsi",
            "127.0.0.1:3260",
            "--work-buf-size",
            "256K",
            "--verbose",
        ])
        .unwrap();
        match cli {
            Cli::Serve(a) => {
                assert_eq!(
                    a.disk,
                    vec![
                        "ram=1M".to_string(),
                        "img=disk.img,ro".to_string(),
                        "cd=legacy.iso".to_string()
                    ]
                );
                assert_eq!(
                    a.cdrom,
                    vec!["img=boot.iso".to_string(), "live=tree".to_string()]
                );
                assert_eq!(a.iscsi.as_deref(), Some("127.0.0.1:3260"));
                assert_eq!(a.work_buf_size.as_deref(), Some("256K"));
                assert_eq!(a.verbose, 1);
            }
            Cli::Mkisofs(_) => panic!("expected Serve, got Mkisofs"),
        }
    }

    #[test]
    fn cli_rejects_legacy_flags() {
        // `--block` / `--cdblock` were removed in the dual-plane redesign.
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--block", "ram=1M"]).is_err());
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--cdblock", "x.iso"]).is_err());
    }

    #[test]
    fn cli_help_is_displayed() {
        match Cli::try_parse_from(["snowdrive", "--help"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {}
            other => panic!("expected DisplayHelp, got {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_parses_positional_and_label() {
        match Cli::try_parse_from(["snowdrive", "mkisofs", "tree", "out.iso", "--label", "DISC"])
            .unwrap()
        {
            Cli::Mkisofs(a) => {
                assert_eq!(a.dir, "tree");
                assert_eq!(a.out, "out.iso");
                assert_eq!(a.label.as_deref(), Some("DISC"));
            }
            other => panic!("unexpected CLI: {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_label_optional() {
        match Cli::try_parse_from(["snowdrive", "mkisofs", "tree", "out.iso"]).unwrap() {
            Cli::Mkisofs(a) => assert_eq!(a.label, None),
            other => panic!("unexpected CLI: {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_requires_two_positionals() {
        assert!(Cli::try_parse_from(["snowdrive", "mkisofs", "tree"]).is_err());
        assert!(Cli::try_parse_from(["snowdrive", "mkisofs"]).is_err());
    }

    #[test]
    fn run_mkisofs_writes_whole_sectors() {
        let dir = std::env::temp_dir().join(format!("snowdrive_mkisofs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();

        let out =
            std::env::temp_dir().join(format!("snowdrive_mkisofs_{}.iso", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let args = MkisofsArgs {
            dir: dir.to_string_lossy().to_string(),
            out: out.to_string_lossy().to_string(),
            label: Some("TEST".to_string()),
            verbose: 0,
        };
        assert_eq!(run_mkisofs(args), ExitCode::SUCCESS);

        let meta = std::fs::metadata(&out).unwrap();
        assert_eq!(meta.len() % u64::from(ISO_SECTOR_SIZE), 0);
        assert!(meta.len() >= u64::from(ISO_SECTOR_SIZE) * 16);

        let bytes = std::fs::read(&out).unwrap();
        // PVD at sector 16: "CD001" at bytes 1..6 (ISO9660 signature).
        assert_eq!(&bytes[16 * 2048 + 1..16 * 2048 + 6], b"CD001");

        // The file data extent must carry the source content.
        assert!(bytes.windows(4).any(|w| w == [0x42, 0x42, 0x42, 0x42]));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn run_mkisofs_missing_dir_fails() {
        let args = MkisofsArgs {
            dir: "/nonexistent/snowdrive-mkisofs".to_string(),
            out: "/tmp/out.iso".to_string(),
            label: None,
            verbose: 0,
        };
        assert_eq!(run_mkisofs(args), ExitCode::FAILURE);
    }
}
