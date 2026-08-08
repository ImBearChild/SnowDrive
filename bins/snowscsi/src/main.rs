#![forbid(unsafe_code)]
//! `snowscsi` CLI — starts the SnowDrive iSCSI target (`snowscsi_main.c`).
//!
//! Subcommands:
//! - `serve`: run the iSCSI target (serial accept loop)
//!
//! `--block` is repeatable; each spec becomes a LUN in order (the first
//! `--block` is LUN 0, and so on). Specs are `ram=<size>` (K/M/G suffixes)
//! or `<path>` (optionally `,ro` for a read-only file backend). `--cdblock`
//! is also repeatable and exposes a read-only CD-ROM image (PDT=0x05) per
//! file. LUN numbering: all `--block` devices first, then all `--cdblock`
//! devices. The same file path may appear on several LUNs; each is an
//! independent SCSI device with its own LBA semantics, so a dual-mount
//! warning is printed to stderr. SIGINT / SIGTERM trigger a graceful
//! shutdown: the blocking `accept()` is woken by a probe connection,
//! `serve()` returns, and every backend is `sync()`ed before exit.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Args, Parser};
use snowdrive::iscsi::transport::{serve, DEFAULT_READ_TIMEOUT};
use snowdrive::scsi::backend::{BlockBackend, BlockStorage, FileBackend, RamBackend};
use snowdrive::scsi::block::BlockDevice;
use snowdrive::scsi::cdblock::CDBlockDevice;
use snowdrive::scsi::device::Device;
use snowdrive::MIN_WORK_LEN;

/// Default work buffer size (256 KiB).
const DEFAULT_WORK_BUF_SIZE: usize = 256 * 1024;
/// Sector size for block devices exposed by the CLI (like the C CLI).
const SECTOR_SIZE: u32 = 512;

#[derive(Debug, Parser)]
#[command(name = "snowscsi", about = "SnowDrive iSCSI target", version)]
enum Cli {
    /// Start the iSCSI target server
    Serve(ServeArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Block device: file path, `path,ro`, or `ram=<size>` (K/M/G suffixes).
    /// Repeatable; the first --block is LUN 0, and so on.
    #[arg(long = "block", value_name = "PATH|ram=SIZE")]
    block: Vec<String>,

    /// Read-only CD-ROM image (ISO9660 file). Repeatable; CD-ROM LUNs follow
    /// the --block LUNs.
    #[arg(long = "cdblock", value_name = "PATH")]
    cdblock: Vec<String>,

    /// iSCSI listen address (required).
    #[arg(long = "iscsi", value_name = "ADDR:PORT")]
    iscsi: Option<String>,

    /// Verbose logging (debug level).
    #[arg(long, short)]
    verbose: bool,

    /// Work buffer size in bytes (accepts K/M/G suffixes; default 256K).
    #[arg(long = "work-buf-size", value_name = "BYTES")]
    work_buf_size: Option<String>,
}

fn main() -> ExitCode {
    match Cli::parse() {
        Cli::Serve(args) => run_serve(args),
    }
}

fn run_serve(args: ServeArgs) -> ExitCode {
    init_logging(args.verbose);

    let addr = match args.iscsi.as_deref() {
        None => {
            eprintln!("snowscsi: --iscsi is required");
            return ExitCode::FAILURE;
        }
        Some(s) => match s.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("snowscsi: invalid --iscsi address: {s}");
                return ExitCode::FAILURE;
            }
        },
    };

    if args.block.is_empty() && args.cdblock.is_empty() {
        eprintln!("snowscsi: --block or --cdblock is required (at least one device)");
        return ExitCode::FAILURE;
    }

    let work_size = match parse_work_size(args.work_buf_size.as_deref()) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("snowscsi: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let mut block_specs = Vec::with_capacity(args.block.len());
    for spec in &args.block {
        let parsed = match parse_block_spec(spec) {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("snowscsi: invalid --block spec '{spec}': {msg}");
                return ExitCode::FAILURE;
            }
        };
        block_specs.push(parsed);
    }

    // CD-ROM images are plain paths; reject missing files up front.
    for path in &args.cdblock {
        if !Path::new(path).is_file() {
            eprintln!("snowscsi: file not found: {path}");
            return ExitCode::FAILURE;
        }
    }
    // Reject missing block files up front (FileBackend would otherwise
    // create a fresh empty file when opened writable).
    for spec in &block_specs {
        if let BlockSpec::File { path, .. } = spec {
            if !Path::new(path).is_file() {
                eprintln!("snowscsi: file not found: {path}");
                return ExitCode::FAILURE;
            }
        }
    }

    for w in check_dual_mount(&dual_mount_specs(&block_specs, &args.cdblock)) {
        eprintln!("{w}");
    }

    // Allocate every RAM disk first so the Device array can borrow them
    // without 'static / Box::leak — disjoint borrows via split_first_mut.
    let mut ram_disks: Vec<Vec<u8>> = Vec::with_capacity(block_specs.len());
    for spec in &block_specs {
        if let BlockSpec::Ram(size) = spec {
            let bytes = match usize::try_from(*size) {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("snowscsi: RAM size {size} too large for this platform");
                    return ExitCode::FAILURE;
                }
            };
            ram_disks.push(vec![0u8; bytes]);
        }
    }

    // LUN order: all --block devices first, then all --cdblock devices.
    let mut devices: Vec<Device<'_>> = Vec::with_capacity(block_specs.len() + args.cdblock.len());
    let mut ram_rest: &mut [Vec<u8>] = &mut ram_disks;
    let mut lun = 0usize;
    for spec in &block_specs {
        let backend = match spec {
            BlockSpec::Ram(_) => {
                let (slot, tail) = ram_rest.split_first_mut().unwrap();
                ram_rest = tail;
                BlockBackend::Ram(RamBackend::new(slot))
            }
            BlockSpec::File { path, read_only } => {
                // Existence was checked by parse; FileBackend would otherwise
                // create a fresh file when opened writable.
                match FileBackend::open(path, !*read_only) {
                    Ok(b) => BlockBackend::File(b),
                    Err(e) => {
                        eprintln!("snowscsi: failed to open file block device {path}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        };
        let mut dev = BlockDevice::new(backend, SECTOR_SIZE).expect("SECTOR_SIZE is nonzero");
        log::debug!("LUN {lun}: {} bytes block device", dev.backend().capacity());
        devices.push(Device::Block(dev));
        lun += 1;
    }
    for path in &args.cdblock {
        let dev = match CDBlockDevice::new(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("snowscsi: failed to open CD-ROM image {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        log::debug!("LUN {lun}: {path} CD-ROM image");
        devices.push(Device::CdBlock(dev));
        lun += 1;
    }

    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("snowscsi: failed to bind {addr}: {e}");
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
            eprintln!("snowscsi: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut work = vec![0u8; work_size];
    log::info!("listening on {addr} with {} LUN(s)", devices.len());

    if let Err(e) = serve(
        listener,
        &stop,
        &mut work,
        &mut devices,
        Some(DEFAULT_READ_TIMEOUT),
    ) {
        eprintln!("snowscsi: server error: {e}");
        return ExitCode::FAILURE;
    }

    // Graceful exit: flush backends.
    for (i, dev) in devices.iter_mut().enumerate() {
        let result = match dev {
            Device::Block(d) => d.backend().sync(),
            Device::CdBlock(d) => d.backend().sync(),
        };
        if let Err(e) = result {
            eprintln!("snowscsi: sync failed for LUN {i}: {e}");
        }
    }
    log::info!("shutting down");
    ExitCode::SUCCESS
}

/// Install the CLI log output: a plain `log` backend (env_logger) writing
/// to stderr. `--verbose` selects the debug level; `RUST_LOG` overrides it.
fn init_logging(verbose: bool) {
    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.parse_default_env();
    builder.init();
}

/// A parsed `--block` spec.
#[derive(Debug)]
enum BlockSpec {
    Ram(u64),
    File { path: String, read_only: bool },
}

/// How a path is exposed as a SCSI device (dual-mount detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Block,
    CdBlock,
}

/// Collect the file-backed specs as `(kind, path)` pairs for dual-mount
/// detection (RAM disks have no path). Both slices live in the caller; the
/// returned paths borrow from them.
fn dual_mount_specs<'a>(
    block_specs: &'a [BlockSpec],
    cdblock_specs: &'a [String],
) -> Vec<(DeviceKind, &'a str)> {
    let mut out: Vec<(DeviceKind, &'a str)> = block_specs
        .iter()
        .filter_map(|s| match s {
            BlockSpec::File { path, .. } => Some((DeviceKind::Block, path.as_str())),
            BlockSpec::Ram(_) => None,
        })
        .collect();
    out.extend(
        cdblock_specs
            .iter()
            .map(|p| (DeviceKind::CdBlock, p.as_str())),
    );
    out
}

/// Detect the same path mounted as multiple independent SCSI devices and
/// return the stderr warning lines. A path appearing more than once in total
/// (same or different device kinds) is warned: each occurrence is a distinct
/// LUN with its own LBA semantics (e.g. `--block f.iso --cdblock f.iso`).
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

/// Parse a `--block` spec: `ram=<size>` or `<path>[,ro]`.
fn parse_block_spec(spec: &str) -> Result<BlockSpec, String> {
    if let Some(size) = spec.strip_prefix("ram=") {
        match parse_size(size) {
            Some(n) => Ok(BlockSpec::Ram(n)),
            None => Err(format!("invalid RAM size: {size}")),
        }
    } else {
        let (path, opt) = match spec.split_once(',') {
            Some((p, o)) => (p, Some(o)),
            None => (spec, None),
        };
        let read_only = match opt {
            Some("ro") => true,
            Some(o) => {
                log::warn!("unknown block option '{o}', ignoring");
                false
            }
            None => false,
        };
        if path.is_empty() {
            return Err("empty file path".to_string());
        }
        Ok(BlockSpec::File {
            path: path.to_string(),
            read_only,
        })
    }
}

/// Resolve the work buffer size (default 256K), validating it against
/// [`MIN_WORK_LEN`].
fn parse_work_size(s: Option<&str>) -> Result<usize, String> {
    let bytes = match s {
        None => DEFAULT_WORK_BUF_SIZE as u64,
        Some(v) => parse_size(v).ok_or_else(|| format!("invalid --work-buf-size: {v}"))?,
    };
    let n = usize::try_from(bytes).map_err(|_| format!("--work-buf-size {bytes} is too large"))?;
    if n < MIN_WORK_LEN {
        return Err(format!(
            "--work-buf-size {n} is below the minimum {MIN_WORK_LEN}"
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
    fn parse_block_spec_ram() {
        match parse_block_spec("ram=8M").unwrap() {
            BlockSpec::Ram(n) => assert_eq!(n, 8 * 1024 * 1024),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_block_spec("ram=bogus").is_err());
        assert!(parse_block_spec("ram=").is_err());
        assert!(parse_block_spec("ram=0").is_err());
    }

    #[test]
    fn parse_block_spec_file() {
        match parse_block_spec("disk.img").unwrap() {
            BlockSpec::File { path, read_only } => {
                assert_eq!(path, "disk.img");
                assert!(!read_only);
            }
            other => panic!("unexpected spec: {other:?}"),
        }
        match parse_block_spec("disk.img,ro").unwrap() {
            BlockSpec::File { read_only, .. } => assert!(read_only),
            other => panic!("unexpected spec: {other:?}"),
        }
        // Unknown options are ignored with a warning (C behavior).
        match parse_block_spec("disk.img,bogus").unwrap() {
            BlockSpec::File { read_only, .. } => assert!(!read_only),
            other => panic!("unexpected spec: {other:?}"),
        }
        assert!(parse_block_spec(",ro").is_err());
    }

    #[test]
    fn parse_work_size_defaults_and_validation() {
        assert_eq!(parse_work_size(None).unwrap(), DEFAULT_WORK_BUF_SIZE);
        assert_eq!(parse_work_size(Some("128K")).unwrap(), 128 * 1024);
        assert!(parse_work_size(Some("1000")).is_err()); // below MIN_WORK_LEN
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
    fn dual_mount_specs_collects_file_paths_only() {
        let specs = [
            BlockSpec::Ram(1024),
            BlockSpec::File {
                path: "a.img".to_string(),
                read_only: false,
            },
            BlockSpec::File {
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
    fn dual_mount_cdblock_paths_are_collected() {
        let cd = vec!["boot.iso".to_string()];
        let d = dual_mount_specs(&[], &cd);
        assert_eq!(d, vec![(DeviceKind::CdBlock, "boot.iso")]);
        assert!(check_dual_mount(&d).is_empty());
    }

    #[test]
    fn dual_mount_block_and_cdblock_same_path_warns() {
        let block = [BlockSpec::File {
            path: "boot.iso".to_string(),
            read_only: false,
        }];
        let cd = vec!["boot.iso".to_string()];
        let d = dual_mount_specs(&block, &cd);
        assert_eq!(
            d,
            vec![
                (DeviceKind::Block, "boot.iso"),
                (DeviceKind::CdBlock, "boot.iso")
            ]
        );
        let w = check_dual_mount(&d);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("boot.iso"));
        assert!(w[0].starts_with("warning:"));
    }

    #[test]
    fn cli_accepts_multiple_block_specs_and_flags() {
        let cli = Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--block",
            "ram=1M",
            "--block",
            "disk.img,ro",
            "--cdblock",
            "boot.iso",
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
                    a.block,
                    vec!["ram=1M".to_string(), "disk.img,ro".to_string()]
                );
                assert_eq!(a.cdblock, vec!["boot.iso".to_string()]);
                assert_eq!(a.iscsi.as_deref(), Some("127.0.0.1:3260"));
                assert_eq!(a.work_buf_size.as_deref(), Some("256K"));
                assert!(a.verbose);
            }
        }
    }

    #[test]
    fn cli_help_is_displayed() {
        match Cli::try_parse_from(["snowscsi", "--help"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {}
            other => panic!("expected DisplayHelp, got {other:?}"),
        }
    }
}
