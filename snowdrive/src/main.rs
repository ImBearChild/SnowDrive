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

#[cfg(target_os = "linux")]
use std::time::Duration;

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

#[cfg(target_os = "linux")]
use snowdrive::usb::{
    BotEvent, BotIo, BotIoErr, BotNeed, BotSession, BotStep, BotStepResult, CtrlAck, CtrlReply,
    CtrlReq, Gadget,
};
#[cfg(target_os = "linux")]
use usb_gadget::function::custom::{
    CtrlReceiver, CtrlSender, Custom, Endpoint, EndpointDirection, EndpointReceiver,
    EndpointSender, Event, Interface,
};
#[cfg(target_os = "linux")]
use usb_gadget::{default_udc, udcs, Class, Config, Gadget as UsbGadget, Id, Strings, Udc};

/// Default work buffer size (256 KiB).
const DEFAULT_WORK_BUF_SIZE: usize = 256 * 1024;
/// Sector size for block devices exposed by the CLI (like the C CLI).
const SECTOR_SIZE: u32 = 512;
/// CD-ROM logical sector size (Mode 1 data).
const ISO_SECTOR_SIZE: u32 = 2048;
/// Serve loop re-checks the control pipe / stop flag at this granularity
/// (bounds Bulk-Only Reset / Get Max LUN response latency, §6.3).
#[cfg(target_os = "linux")]
const BOT_POLL_GRANULARITY: Duration = Duration::from_millis(50);

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
#[command(group = clap::ArgGroup::new("transport").required(true).multiple(false))]
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

    /// iSCSI listen address (ADDR:PORT). Mutually exclusive with `--usb`;
    /// exactly one transport is required.
    #[arg(long = "iscsi", value_name = "ADDR:PORT", group = "transport")]
    iscsi: Option<String>,

    /// Serve the devices over USB Mass Storage (Bulk-Only Transport) by
    /// binding a FunctionFS gadget to a UDC (Linux only). Mutually
    /// exclusive with `--iscsi`.
    #[arg(long = "usb", group = "transport")]
    usb: bool,

    /// UDC name to bind the USB gadget to (default: the first UDC).
    #[arg(long = "udc", value_name = "NAME")]
    udc: Option<String>,

    /// USB vendor ID (hex).
    #[arg(long = "vid", value_name = "VID", default_value = "1209", value_parser = parse_hex_u16)]
    vid: u16,

    /// USB product ID (hex).
    #[arg(long = "pid", value_name = "PID", default_value = "0001", value_parser = parse_hex_u16)]
    pid: u16,

    /// USB serial number.
    #[arg(long = "serial", value_name = "SERIAL", default_value = "SNOWSCSI")]
    serial: String,

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

    let work_size = match parse_work_size(args.work_buf_size.as_deref()) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("snowdrive: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // The device pipeline is shared by both transports: parse the specs,
    // validate sources, allocate RAM disks and build the LUN list.
    let mut ram_disks: Vec<Vec<u8>> = Vec::new();
    let mut devices: Vec<Device<'_>> = Vec::new();
    if build_devices(&args, &mut ram_disks, &mut devices).is_err() {
        return ExitCode::FAILURE;
    }

    if args.usb {
        #[cfg(target_os = "linux")]
        {
            return run_serve_usb(&args, &mut devices, work_size);
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("snowdrive: --usb is only supported on Linux");
            return ExitCode::FAILURE;
        }
    }

    // iSCSI transport: the ArgGroup guarantees --iscsi when --usb is absent.
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
    sync_devices(&mut devices);
    log::info!("shutting down");
    ExitCode::SUCCESS
}

/// Flush every backend; errors are reported to stderr but not fatal.
fn sync_devices(devices: &mut [Device<'_>]) {
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
}

/// Shared device pipeline: parse the `--disk` / `--cdrom` specs, validate
/// the sources, allocate the RAM disks and build the LUN list in order
/// (all `--disk` devices first, then all `--cdrom` devices).
///
/// `devices` borrows `ram_disks` (RAM-backed LUNs), which must therefore
/// outlive it. On failure prints the error and returns `Err(())`.
fn build_devices<'a>(
    args: &ServeArgs,
    ram_disks: &'a mut Vec<Vec<u8>>,
    devices: &mut Vec<Device<'a>>,
) -> Result<(), ()> {
    if args.disk.is_empty() && args.cdrom.is_empty() {
        eprintln!("snowdrive: --disk or --cdrom is required (at least one device)");
        return Err(());
    }

    let mut disk_specs = Vec::with_capacity(args.disk.len());
    for spec in &args.disk {
        let parsed = match parse_disk_spec(spec) {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("snowdrive: invalid --disk spec '{spec}': {msg}");
                return Err(());
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
                return Err(());
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
                    return Err(());
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
                    return Err(());
                }
            }
            CdromSpec::Live { dir } => {
                if !Path::new(dir).is_dir() {
                    eprintln!("snowdrive: directory not found: {dir}");
                    return Err(());
                }
            }
        }
    }

    for w in check_dual_mount(&dual_mount_specs(&disk_specs, &cdrom_specs)) {
        eprintln!("{w}");
    }

    // Allocate every RAM disk first so the Device array can borrow them
    // without 'static / Box::leak — disjoint borrows via split_first_mut.
    ram_disks.clear();
    for spec in &disk_specs {
        if let DiskSpec::Ram(size) = spec {
            let bytes = match usize::try_from(*size) {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("snowdrive: RAM size {size} too large for this platform");
                    return Err(());
                }
            };
            ram_disks.push(vec![0u8; bytes]);
        }
    }

    // LUN order: all --disk devices first, then all --cdrom devices (clap
    // collects each flag separately, so the interleaved appearance order
    // cannot be restored; the two planes do not interleave).
    devices.clear();
    let mut ram_rest: &mut [Vec<u8>] = ram_disks;
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
                        return Err(());
                    }
                }
            }
            DiskSpec::Cdrom { path } => {
                let dev = match CDBlockDevice::new(path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("snowdrive: failed to open CD-ROM image {path}: {e}");
                        return Err(());
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
                        return Err(());
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
                        return Err(());
                    }
                }
            }
        }
        lun += 1;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// `snowdrive serve --usb`: assemble the MSC FunctionFS gadget, bind it to a
/// UDC and run the BOT poll loop (§6).
fn run_serve_usb(args: &ServeArgs, devices: &mut [Device<'_>], work_size: usize) -> ExitCode {
    // Gadget assembly (§6.1): a single MSC interface (class 08/06/50) with
    // one bulk OUT + one bulk IN endpoint.
    let (ep_out, out_dir) = EndpointDirection::host_to_device();
    let (ep_in, in_dir) = EndpointDirection::device_to_host();

    let (custom, handle) = Custom::builder()
        .with_interface(
            Interface::new(Class::MASS_STORAGE_SCSI_BULK, "snowdrive msc")
                .with_endpoint(Endpoint::bulk(out_dir))
                .with_endpoint(Endpoint::bulk(in_dir)),
        )
        .build();

    let udc = match select_udc(args.udc.as_deref()) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("snowdrive: {e}");
            return ExitCode::FAILURE;
        }
    };
    log::info!("binding USB gadget to UDC {:?}", udc.name());
    let reg = match UsbGadget::new(
        Class::INTERFACE_SPECIFIC,
        Id::new(args.vid, args.pid),
        Strings::new("SnowDrive", "SnowDrive USB Disk", &args.serial),
    )
    .with_config(Config::new("config").with_function(handle))
    .bind(&udc)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("snowdrive: failed to bind USB gadget: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        if let Err(e) = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)) {
            eprintln!("snowdrive: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut ffs_bot = FfsBot::new(ep_out, ep_in);
    let mut ffs_gadget = FfsGadget { custom };
    let mut session = BotSession::with_luns(devices.len());
    let mut work = vec![0u8; work_size];
    let mut recv = vec![0u8; work_size];

    log::info!("serving {} LUN(s) over USB", devices.len());
    if let Err(e) = serve_bot(
        &mut ffs_bot,
        &mut ffs_gadget,
        &mut session,
        &mut recv,
        &mut work,
        devices,
        &stop,
    ) {
        eprintln!("snowdrive: usb serve error: {e}");
        return ExitCode::FAILURE;
    }

    // Graceful exit: flush backends, then unregister the gadget (RAII).
    sync_devices(devices);
    drop(reg);
    log::info!("shutting down");
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
/// Pick the UDC to bind: `--udc NAME` or the system default.
fn select_udc(name: Option<&str>) -> Result<Udc, String> {
    match name {
        None => default_udc()
            .map_err(|e| format!("no USB device controller (is dummy_hcd loaded?): {e}")),
        Some(n) => udcs()
            .map_err(|e| format!("failed to enumerate UDCs: {e}"))?
            .into_iter()
            .find(|u| u.name().to_str() == Some(n))
            .ok_or_else(|| format!("UDC not found: {n}")),
    }
}

#[cfg(target_os = "linux")]
/// bulk I/O bridge: FunctionFS endpoint <-> [`BotIo`].
///
/// The crate's bulk endpoints use Linux native aio with `Bytes`/`BytesMut`
/// buffers; each receive copies the aio buffer into the caller's slice
/// (§6.2). `halt()` reports success as `Err(-EBADMSG)` (errno 74), so
/// `stall_both` treats it as success and ignores the error.
struct FfsBot {
    out: EndpointReceiver,
    in_: EndpointSender,
}

#[cfg(target_os = "linux")]
impl FfsBot {
    fn new(out: EndpointReceiver, in_: EndpointSender) -> Self {
        Self { out, in_ }
    }
}

#[cfg(target_os = "linux")]
impl BotIo for FfsBot {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        let d = self
            .out
            .recv_timeout(bytes::BytesMut::zeroed(buf.len()), Duration::ZERO)
            .map_err(|_| BotIoErr::Io)?
            .ok_or(BotIoErr::WouldBlock)?;
        let n = d.len();
        buf[..n].copy_from_slice(&d);
        Ok(n)
    }

    fn recv_out(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        let d = match timeout {
            Some(t) => self
                .out
                .recv_timeout(bytes::BytesMut::zeroed(buf.len()), t)
                .map_err(|_| BotIoErr::Io)?
                .ok_or(BotIoErr::WouldBlock)?,
            None => self
                .out
                .recv_and_fetch(bytes::BytesMut::zeroed(buf.len()))
                .map_err(|_| BotIoErr::Io)?,
        };
        let n = d.len();
        buf[..n].copy_from_slice(&d);
        Ok(n)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.in_
            .send(bytes::Bytes::copy_from_slice(buf))
            .map_err(|_| BotIoErr::Io)
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        // halt() succeeds by returning Err(-EBADMSG) (errno 74) — treated as
        // success; discard in-flight aio first (§4.7).
        let _ = self.out.control().and_then(|c| {
            let _ = c.discard_fifo();
            c.halt()
        });
        let _ = self.in_.control().and_then(|c| {
            let _ = c.discard_fifo();
            c.halt()
        });
        Ok(())
    }
}

#[cfg(target_os = "linux")]
/// Bulk-Only Reset ack handle: completing the control status stage is the
/// drop of the FunctionFS receiver (§6.2).
struct FfsAck<'a> {
    /// Held for its drop side-effect; never read.
    #[allow(dead_code)]
    receiver: Option<CtrlReceiver<'a>>,
}

#[cfg(target_os = "linux")]
impl CtrlAck for FfsAck<'_> {
    fn ack(self) {}
}

#[cfg(target_os = "linux")]
/// Get Max LUN reply handle.
struct FfsReply<'a> {
    sender: Option<CtrlSender<'a>>,
}

#[cfg(target_os = "linux")]
impl CtrlReply for FfsReply<'_> {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        // CtrlSender::send consumes itself; the short write (≤ wLength) is
        // tolerated. Never STALL Get Max LUN (§4.3).
        self.sender
            .take()
            .map(|s| s.send(data))
            .unwrap_or(Ok(0))
            .map(|_| ())
            .map_err(|_| ())
    }
}

#[cfg(target_os = "linux")]
/// Control-plane bridge: FunctionFS ep0 setup events -> [`CtrlReq`].
struct FfsGadget {
    custom: Custom,
}

#[cfg(target_os = "linux")]
impl<'a> Gadget<'a> for FfsGadget {
    type Ack = FfsAck<'a>;
    type Reply = FfsReply<'a>;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<Self::Ack, Self::Reply>> {
        let ev = self.custom.try_event().ok()??;
        match ev {
            Event::SetupHostToDevice(receiver)
                if receiver.ctrl_req().request == snowdrive::usb::BOT_RESET =>
            {
                Some(CtrlReq::BotReset {
                    ack: FfsAck {
                        receiver: Some(receiver),
                    },
                })
            }
            Event::SetupDeviceToHost(sender)
                if sender.ctrl_req().request == snowdrive::usb::GET_MAX_LUN =>
            {
                Some(CtrlReq::GetMaxLun {
                    reply: FfsReply {
                        sender: Some(sender),
                    },
                })
            }
            Event::Bind | Event::Enable | Event::Disable => Some(CtrlReq::LinkReset),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
/// The PC poll driver (§6.3): control requests first, then one bulk step of
/// the non-blocking `BotSession` core, bounded by the stop flag.
fn serve_bot(
    ffs_bot: &mut FfsBot,
    ffs_gadget: &mut FfsGadget,
    session: &mut BotSession,
    recv: &mut [u8],
    work: &mut [u8],
    devs: &mut [Device<'_>],
    stop: &AtomicBool,
) -> Result<(), String> {
    if work.len() < MIN_DATA_LEN {
        return Err(format!("work buffer smaller than {MIN_DATA_LEN}"));
    }
    let mut stalled = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        // 1) Control requests first (arrive at any time, even mid data phase).
        if let Some(req) = ffs_gadget.try_next_ctrl() {
            match req {
                CtrlReq::BotReset { ack } => {
                    session.reset();
                    ack.ack();
                    stalled = false;
                }
                CtrlReq::GetMaxLun { mut reply } => {
                    reply
                        .send(&[session.max_lun()])
                        .map_err(|_| "Get Max LUN reply failed".to_string())?;
                }
                CtrlReq::LinkReset => {
                    session.reset();
                    stalled = false;
                }
            }
            continue;
        }
        // 2) STALLed: only control events until the host resets (§4.5).
        if stalled {
            continue;
        }
        match session.need() {
            BotNeed::NeedOut { len, probe } => {
                // probe = non-blocking overrun drain (no wait); everything
                // else bounds the ctrl/stop check latency.
                let timeout = if probe {
                    Duration::ZERO
                } else {
                    BOT_POLL_GRANULARITY
                };
                match ffs_bot.recv_out(&mut recv[..len], Some(timeout)) {
                    Ok(n) => {
                        let step = session.poll(BotEvent::OutRecv { data: &recv[..n] }, work, devs);
                        if let BotStep::Done(r) = step {
                            handle_done(r, &mut stalled, ffs_bot)?;
                        }
                    }
                    Err(BotIoErr::WouldBlock) => {
                        if probe {
                            let step = session.poll(BotEvent::OutIdle, work, devs);
                            if let BotStep::Done(r) = step {
                                handle_done(r, &mut stalled, ffs_bot)?;
                            }
                        }
                    }
                    Err(BotIoErr::Io) => return Err("bulk OUT I/O failure".to_string()),
                }
            }
            BotNeed::NeedIn { len } => {
                let data = session.out_slice(&work[..]);
                if data.len() != len {
                    return Err("internal: out_slice length mismatch".to_string());
                }
                ffs_bot
                    .send_in(data)
                    .map_err(|_| "bulk IN send failed".to_string())?;
                let step = session.poll(BotEvent::InSent, work, devs);
                if let BotStep::Done(r) = step {
                    handle_done(r, &mut stalled, ffs_bot)?;
                }
            }
            BotNeed::Done(r) => handle_done(r, &mut stalled, ffs_bot)?,
        }
    }
}

#[cfg(target_os = "linux")]
/// React to a transaction-end result from the core.
fn handle_done(
    result: BotStepResult,
    stalled: &mut bool,
    ffs_bot: &mut FfsBot,
) -> Result<(), String> {
    match result {
        BotStepResult::Stalled => {
            if !*stalled {
                let _ = ffs_bot.stall_both();
                *stalled = true;
            }
            Ok(())
        }
        BotStepResult::Error(e) => Err(format!("BOT core error: {e}")),
        BotStepResult::Processed | BotStepResult::Closed => Ok(()),
    }
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

/// Parse a hexadecimal u16 (with optional `0x` prefix) for `--vid`/`--pid`.
fn parse_hex_u16(s: &str) -> Result<u16, String> {
    let body = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(body, 16).map_err(|_| format!("invalid hex value: {s}"))
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
    fn cli_usb_transport_parses() {
        match Cli::try_parse_from(["snowdrive", "serve", "--usb", "--disk", "ram=1M"]).unwrap() {
            Cli::Serve(a) => {
                assert!(a.usb);
                assert_eq!(a.iscsi, None);
                assert_eq!(a.vid, 0x1209);
                assert_eq!(a.pid, 0x0001);
                assert_eq!(a.serial, "SNOWSCSI");
                assert_eq!(a.udc, None);
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_both_transports() {
        // `--iscsi` + `--usb` are mutually exclusive (ArgGroup).
        assert!(
            Cli::try_parse_from(["snowdrive", "serve", "--usb", "--iscsi", "127.0.0.1:3260"])
                .is_err()
        );
    }

    #[test]
    fn cli_requires_a_transport() {
        // serve without `--iscsi`/`--usb` fails at parse time.
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--disk", "ram=1M"]).is_err());
    }

    #[test]
    fn cli_usb_descriptor_overrides() {
        match Cli::try_parse_from([
            "snowdrive",
            "serve",
            "--usb",
            "--udc",
            "dummy_udc.0",
            "--vid",
            "1d6b",
            "--pid",
            "0105",
            "--serial",
            "SNOWSCSI-1",
        ])
        .unwrap()
        {
            Cli::Serve(a) => {
                assert!(a.usb);
                assert_eq!(a.udc.as_deref(), Some("dummy_udc.0"));
                assert_eq!(a.vid, 0x1d6b);
                assert_eq!(a.pid, 0x0105);
                assert_eq!(a.serial, "SNOWSCSI-1");
            }
            other => panic!("expected Serve, got {other:?}"),
        }
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
