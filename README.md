# SnowDrive

> **WARNING**: This project is in early development and is **not yet functional**.
> The build system and directory structure are in place, but no implementation code exists yet.
> Nothing here compiles, runs, or does anything useful at this point.

SCSI device emulation toolkit — two C libraries and two CLI tools.

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, CD-R, CD-RW) and exposes them to a host machine via iSCSI.

| Component | Description |
|-----------|-------------|
| **libsnow9660** | ISO9660 + Joliet filesystem library — parse, generate, live mode (directory → LBA lookup) |
| **libsnowscsi** | SCSI device emulation library — block device (SBC), optical drive (MMC), iSCSI target protocol stack |
| **snow9660** | CLI tool — `list` command prints ISO file/directory tree |
| **snowscsi** | CLI tool — `serve` command starts iSCSI target, exposing block device or optical drive to host |

## Dependencies

* cJSON 
* Unity (Test Library)

## Project Status

- [x] Project skeleton (directory structure, CMake build system, license)
- [ ] Phase 0: Core data structures, empty API shells, CLI shows help
- [ ] Phase 1: Block device (SBC) + iSCSI target
- [ ] Phase 2: Read-only optical drive (CD-ROM) + Live ISO mode
- [ ] Phase 3: Writable optical drive (CD-R) + disc bundle export
- [ ] Phase 4: Rewritable optical drive (CD-RW)
- [ ] Phase 5: Advanced features (audio tracks, multi-session, READ CD)

## Project Structure

```
snowdrive/
├── include/
│   ├── snow9660/          # libsnow9660 public headers
│   └── snowscsi/          # libsnowscsi public headers
├── lib/
│   ├── snow9660/          # libsnow9660 implementation
│   └── snowscsi/          # libsnowscsi implementation
├── src/                   # CLI tools (snowscsi, snow9660)
├── tests/                 # Unit tests (Unity + CTest)
├── CMakeLists.txt         # Top-level build
└── LICENSE
```

## Build (not yet available)

The CMake build system is configured but source files do not exist yet. This section documents the intended build process for when implementation begins.

```bash
cmake -B build
cmake --build build
```

With tests:

```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage (not yet available)

### Block device (virtual USB drive)

```bash
snowscsi serve --block disk.img --iscsi 0.0.0.0:3260
```

### Read-only optical drive (ISO file)

```bash
snowscsi serve --cdrom disc.iso --iscsi 0.0.0.0:3260
```

### Live ISO optical drive (directory → ISO9660/Joliet disc, no intermediate file)

```bash
snowscsi serve --cdrom /home/user/share,live --iscsi 0.0.0.0:3260
```

### Writable optical drive (disc bundle directory)

```bash
snowscsi serve --cdrom mydisc.d --iscsi 0.0.0.0:3260
```

### Multi-LUN

```bash
snowscsi serve --block disk.img --cdrom disc.iso --cdrom mydisc.d --iscsi 0.0.0.0:3260
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

## API (planned)

```c
#include <snow9660/snow9660.h>   // ISO9660 filesystem operations
#include <snowscsi/snowscsi.h>   // SCSI device emulation
#include <snowscsi/cdrom.h>      // Optical drive
#include <snowscsi/block.h>      // Block device
#include <snowscsi/iscsi.h>      // iSCSI target
```

## Requirements

- C11 compiler
- CMake >= 3.18
- cJSON (for TOC JSON parsing in libsnowscsi)
- POSIX or WinSock (for iSCSI transport layer)

## License

MPL-2.0 — see [LICENSE](LICENSE).
