# SnowDrive

> **WARNING**: This project is being rewritten in Rust. Skeleton is in place;
> implementation is pending. The original C code lives on the `legacy` branch.

SCSI device emulation toolkit — Rust workspace (cargo).

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, CD-R, CD-RW)
and exposes them to a host machine via iSCSI.

| Component | Crate | Description |
|-----------|-------|-------------|
| **snowcommon** | `snowcommon` | Zero-alloc logging and hex formatting (`no_std`) |
| **SCSI core + iSCSI** | `snowscsi` | SCSI device emulation, block device (SBC), iSCSI target (`no_std` + `std` feature) |
| **ISO9660** | `snow9660` | ISO9660 + Joliet filesystem library (`no_std`) |
| **C API** | `snowscsi-capi` | C ABI bindings (unsafe-allowed, cbindgen) |
| **CLI — serve** | `snowscsi-cli` | `snowscsi serve` starts iSCSI target |
| **CLI — list** | `snow9660-cli` | `snow9660 list` prints ISO directory tree |
| **Mock** | `snowscsi-mock` | Deterministic mock `Conn` for testing |

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

- [x] Phase 1 skeleton: Rust workspace, crate stubs, build system
- [ ] Phase 1: SCSI core + block device (SBC) + iSCSI target (port from C)
- [ ] Phase 1: C ABI (`snowscsi-capi`)
- [ ] Phase 2: Read-only optical drive (CD-ROM) + Live ISO mode
- [ ] Phase 3: Writable optical drive (CD-R) + disc bundle export
- [ ] Phase 4: Rewritable optical drive (CD-RW)
- [ ] Phase 5: Advanced features (audio tracks, multi-session, READ CD)

## Project Structure

```
snowdrive/
├── Cargo.toml            # virtual workspace
├── crates/
│   ├── snowcommon/       # [no_std] logging + hex
│   ├── snowscsi/         # [no_std + std] SCSI + iSCSI
│   ├── snow9660/         # [no_std] ISO9660 stub
│   ├── snowscsi-capi/    # C ABI (unsafe-allowed)
│   ├── snowscsi-cli/     # binary: serve
│   ├── snow9660-cli/     # binary: list
│   └── snowscsi-mock/    # mock Conn
├── tests/                # integration tests (snowdrive-tests)
├── LICENSE-APACHE        # Apache-2.0
└── LICENSE-MIT           # MIT
```

## Legacy C Code

The original C implementation (CMake + Unity) is archived on the `legacy` branch:

```bash
git checkout legacy
cmake -B build && cmake --build build
```

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
