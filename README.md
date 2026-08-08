# SnowDrive

> **WARNING**: This project is being rewritten in Rust. Skeleton is in place;
> implementation is pending. The original C code lives on the `legacy` branch.

SCSI device emulation toolkit — Rust workspace (cargo).

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, CD-R, CD-RW)
and exposes them to a host machine via iSCSI.

| Component | Crate | Description |
|-----------|-------|-------------|
| **Unified lib** | `snowdrive` | SCSI emulation, block/CD-ROM devices, iSCSI target, ISO9660 algorithms (`no_std` + `std` feature; module-gated) |
| — storage seams | `snowdrive::common` | Zero-alloc `BlockStorage` / `FsStorage` + unified logging macros |
| — SCSI + iSCSI | `snowdrive::scsi` / `::iscsi` | Block/CD-ROM devices (SBC/SPC/MMC), iSCSI PDU + target |
| — ISO9660 | `snowdrive::iso9660` | ISO9660 + Joliet live-generation algorithms |
| **CLI — serve** | `bins/snowscsi` | `snowscsi serve` starts iSCSI target |
| **CLI — list** | `bins/snow9660` | `snow9660 list` prints ISO directory tree (stub) |
| **Tests** | `snowdrive-tests` | Mock + libiscsi whitebox integration tests |

## Build

```bash
cargo build --workspace
```

## Test

```bash
cargo test --workspace
```

## Usage (planned)

### Block device (virtual USB drive)

```bash
snowscsi serve --block disk.img --iscsi 0.0.0.0:3260
```

### Multi-LUN

```bash
snowscsi serve --block disk.img --block ram=16M --iscsi 0.0.0.0:3260
```

### ISO file tree listing

```bash
snow9660 list disc.iso
```

### Connect from host

```bash
# Linux (open-iscsi)
iscsiadm -m node -T iqn.2025-01.local.snowscsi:target -p 127.0.0.1:3260 --login
```

## Project Status

- [x] Unified `snowdrive` lib crate: SCSI core + block/CD-ROM devices (SBC/SPC/MMC) + iSCSI target + ISO9660 algorithms
- [x] `snowscsi serve` CLI: `--block` (ram/path,ro) + `--cdblock` + multi-LUN + graceful shutdown
- [ ] C ABI (`snowdrive::capi`, feature-gated) — postponed
- [ ] Phase 3: Writable optical drive (CD-R) + disc bundle export
- [ ] Phase 4: Rewritable optical drive (CD-RW)
- [ ] Phase 5: Advanced features (audio tracks, multi-session, READ CD)

## Project Structure

```
snowdrive/
├── Cargo.toml            # workspace: lib + 2 bins + tests
├── snowdrive/            # unified lib crate (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # common, scsi, iscsi, iso9660
│   │   ├── common/       # storage seams + logging macros (always on)
│   │   ├── scsi/         # SCSI core, block/cdblock/cdrom, spc/sbc, backends
│   │   └── iscsi/        # PDU codec, Conn, target, transport
├── bins/
│   ├── snowscsi/         # iSCSI target CLI (binary)
│   └── snow9660/         # ISO9660 CLI (binary, stub)
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
