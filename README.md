# SnowDrive

SCSI device emulation toolkit — Rust workspace (cargo).

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, CD-R, CD-RW)
and exposes them to a host machine over iSCSI (TCP) or USB Mass Storage
(Bulk-Only Transport, FunctionFS gadget on Linux).

| Component | Crate | Description |
|-----------|-------|-------------|
| **Unified lib** | `snowdrive` | SCSI emulation, block/CD-ROM devices, iSCSI target, USB MSC (BOT) core, ISO9660 algorithms (`no_std` + `std` feature; module-gated) |
| — storage seams | `snowdrive::common` | Zero-alloc `BlockStorage` / `FsStorage` + unified logging macros |
| — SCSI | `snowdrive::scsi` | Block/CD-ROM devices (SBC/SPC/MMC), SCSI core |
| — iSCSI | `snowdrive::iscsi` | iSCSI PDU + target |
| — USB MSC | `snowdrive::usb` | Bulk-Only Transport core: CBW/CSW codec, `BotIo`/`Gadget` seams, non-blocking `BotSession` state machine |
| — ISO9660 | `snowdrive::iso9660` | ISO9660 + Joliet live-generation algorithms |
| **CLI** | `snowdrive` bin (`src/main.rs`) | `snowdrive serve` starts the iSCSI target or the USB MSC gadget; `snowdrive mkisofs` generates an ISO image from a directory |
| **Tests** | `snowdrive-tests` | Mock + libiscsi whitebox integration tests |

## Build

```bash
cargo build --workspace
```

## Test

```bash
cargo test --workspace
```

## Usage

### Block device (iSCSI)

```bash
snowdrive serve --disk disk.img --iscsi 0.0.0.0:3260
```

### Multi-LUN

```bash
snowdrive serve --disk disk.img --disk ram=16M --iscsi 0.0.0.0:3260
```

### USB Mass Storage gadget (Linux, `dummy_hcd` or real UDC)

`serve --usb` binds a FunctionFS MSC gadget to a UDC; the host kernel's
`usb-storage` driver attaches and creates `/dev/sdX` (or `/dev/srX` for
CD-ROM LUNs). Requires root (gadget + configfs + aio) — with `dummy_hcd`
loaded this needs no USB hardware:

```bash
# as root: expose a 16 MiB RAM disk as /dev/sdX
sudo snowdrive serve --usb --disk ram=16M

# expose a read-only ISO as a USB CD-ROM
sudo snowdrive serve --usb --cdrom img=out.iso
```

`--iscsi` and `--usb` are mutually exclusive; exactly one transport is
required. `--udc NAME`, `--vid`, `--pid`, `--serial` (defaults
`0x1209:0x0001` / "SNOWSCSI") override the gadget identity.

### ISO image generation

```bash
snowdrive mkisofs src_dir out.iso --label MYDISC
```

### Connect from host

```bash
# Linux (open-iscsi)
iscsiadm -m node -T iqn.2025-01.local.snowdrive:target -p 127.0.0.1:3260 --login
```

## Project Status

- [x] Unified `snowdrive` lib crate: SCSI core + block/CD-ROM devices (SBC/SPC/MMC) + iSCSI target + USB MSC (BOT) core + ISO9660 algorithms
- [x] `snowdrive serve` CLI: `--disk` / `--cdrom` device planes + multi-LUN + graceful shutdown
- [x] USB Mass Storage transport (`serve --usb`, FunctionFS gadget): verified end-to-end against the real kernel (`dummy_hcd` + `usb-storage`, ext4 format/mount/fsck)
- [x] ISO9660 image generation (`mkisofs`): cross-validated by `file`, `isoinfo`, `7z`, `bsdtar`
- [ ] C ABI (`snowdrive::capi`, feature-gated) — postponed
- [ ] Phase 3: Writable optical drive (CD-R) + disc bundle export
- [ ] Phase 4: Rewritable optical drive (CD-RW)
- [ ] Phase 5: Advanced features (audio tracks, multi-session, READ CD)

## Project Structure

```
snowdrive/
├── Cargo.toml            # workspace: lib + bin + tests
├── snowdrive/            # unified lib crate + CLI (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # common, scsi, iscsi, iso9660, usb
│   │   ├── main.rs       # CLI: serve (iSCSI / USB) + mkisofs (ISO generator)
│   │   ├── common/       # storage seams + logging macros (always on)
│   │   ├── scsi/         # SCSI core, block/cdblock/cdrom, spc/sbc, backends
│   │   ├── iscsi/        # PDU codec, Conn, target, transport
│   │   ├── usb/          # MSC Bulk-Only Transport core (CBW/CSW, BotSession)
│   │   └── iso9660/      # ISO9660/Joliet live-generation algorithms
├── tests/                # integration tests (mock + libiscsi whitebox)
├── LICENSE-APACHE        # Apache-2.0
└── LICENSE-MIT           # MIT
```

## Library Usage

The `snowdrive` lib is feature-gated — pick only what you need:

```toml
# SCSI core only (embedded block device)
snowdrive = { version = "0.1", default-features = false, features = ["scsi"] }

# SCSI + iSCSI over TCP (network block device)
snowdrive = { version = "0.1", default-features = false, features = ["std", "scsi", "iscsi"] }

# USB MSC Bulk-Only Transport core (no platform I/O; drives plug a BotIo/Gadget)
snowdrive = { version = "0.1", default-features = false, features = ["usb"] }

# Full desktop build (default)
snowdrive = { version = "0.1" }
```

## Legacy C Code

The original C implementation (CMake + Unity) is archived on the `legacy` branch:

```bash
git checkout legacy
cmake -B build && cmake --build build
```

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
