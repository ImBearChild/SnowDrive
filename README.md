# SnowDrive

SCSI device emulation toolkit — Rust workspace (cargo).

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, writable
DVD-RAM) and exposes them to a host machine over iSCSI (TCP) or USB Mass
Storage (Bulk-Only Transport, FunctionFS gadget on Linux).

| Component | Crate | Description |
|-----------|-------|-------------|
| **Common** | `snowdrive-common` | Zero-alloc `BlockStorage` / `FsStorage` seams + unified logging macros |
| **Disc** | `snowdrive-disc` | ISO9660 + Joliet live-generation algorithms (`live.rs`) |
| **SCSI core** | `snowdrive-scsi` | SCSI emulation, block/CD-ROM devices, iSCSI target, USB MSC (BOT) core, UDF skeleton |
| **CLI** | `snowdrive-cli` | `snowdrive serve` runs the iSCSI target or the USB MSC gadget; `snowdrive mkisofs` generates an ISO image from a directory |
| **Tests** | `snowdrive-tests` | Mock + libiscsi whitebox + ISO cross-validation integration tests |

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
CD-ROM LUNs). The UDC is chosen by the `--usb` selector (`auto` default,
`dummy`, a UDC name, or a driver prefix). Requires root (gadget + configfs +
aio) — with `dummy_hcd` loaded this needs no USB hardware:

```bash
# as root: expose a 16 MiB RAM disk as /dev/sdX
sudo snowdrive serve --usb --disk ram=16M

# expose a read-only ISO as a USB CD-ROM
sudo snowdrive serve --usb --cdrom img=out.iso
```

`--iscsi` and `--usb` are mutually exclusive; exactly one transport is
required. `--vid` / `--pid` / `--serial` (defaults `0x1209:0x0001` /
"SNOWSCSI") override the gadget identity.

### ISO image generation

```bash
snowdrive mkisofs src_dir out.iso --label MYDISC
```

### Connect from host

```bash
# Linux (open-iscsi)
iscsiadm -m node -T iqn.1970-01.local.snowscsi:target -p 127.0.0.1:3260 --login
```

(Or pass `--iscsi auto` to `serve` and let it perform the open-iscsi
login/logout itself.)

## Project Status

- [x] `snowdrive-scsi` lib: SCSI core + block/CD-ROM devices (SBC/SPC/MMC) + iSCSI target + USB MSC (BOT) core + UDF volume skeleton
- [x] `snowdrive-cli serve`: `--disk` / `--cdrom` device planes + multi-LUN + graceful shutdown
- [x] USB Mass Storage transport (`serve --usb`, FunctionFS gadget): verified end-to-end against the real kernel (`dummy_hcd` + `usb-storage`, ext4 format/mount/fsck)
- [x] ISO9660 image generation (`mkisofs`): cross-validated by `file`, `isoinfo`, `7z`, `bsdtar`
- [x] Writable DVD-RAM (`--cdrom udfrw=`, feature `udf_void`): random-writable UDF-backed medium
- [ ] Phase 3: Writable optical drive (CD-R) + disc bundle export
- [ ] Phase 4: Rewritable optical drive (CD-RW)
- [ ] Phase 5: Advanced features (audio tracks, multi-session, READ CD)

## Project Structure

```
SnowDrive/                          # cargo workspace (resolver = "2")
├── Cargo.toml                      # workspace members
├── snowdrive-common/               # storage seams + logging macros
├── snowdrive-disc/                 # ISO9660/Joliet live-generation algorithms
├── snowdrive-scsi/                 # SCSI core + iSCSI + USB MSC + CD-ROM + UDF
│   └── src/{scsi, cdrom, iscsi, usb, udf_void.rs}
├── snowdrive-cli/                  # `snowdrive` binary (src/main.rs)
├── tests/                          # snowdrive-tests (integration tests)
├── tools/                          # NOT a cargo member: ext-test/ + libvirt-usb-helper
├── LICENSE-APACHE                  # Apache-2.0
└── LICENSE-MIT                    # MIT
```

## Library Usage

The SCSI emulation core lives in the `snowdrive-scsi` crate; pick only the
features you need:

```toml
# SCSI core only (embedded block device)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["scsi"] }

# SCSI + iSCSI over TCP (network block device)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["std", "scsi", "iscsi"] }

# USB MSC Bulk-Only Transport core (no platform I/O; drivers plug a BotIo/Gadget)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["usb"] }

# Live ISO9660 directory backend (CD-ROM)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["std", "cdrom", "livefs"] }

# Full feature set (note: `snowdrive-scsi` default is just `std`; opt in explicitly)
snowdrive-scsi = { version = "0.1", features = ["std", "scsi", "iscsi", "iso9660", "udf_void", "cdrom", "livefs", "usb"] }
```

## Legacy C Code

The original C implementation (CMake + Unity) is archived on the `legacy` branch:

```bash
git checkout legacy
cmake -B build && cmake --build build
```

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
