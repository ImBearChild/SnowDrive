# Contributing to SnowDrive

## Project Structure

SCSI device emulation toolkit — unified Rust lib crate + two binaries.

| Component | Location | Description |
|-----------|----------|-------------|
| **snowdrive** | `snowdrive/` | Unified lib crate (`no_std` + `std` feature) |
| — `common` | `snowdrive/src/common/` | Zero-alloc storage seams (`BlockStorage` / `FsStorage`) + unified logging macros |
| — `scsi` | `snowdrive/src/scsi/` | SCSI core, block/CDBlock devices (SBC/SPC), file/fs backends |
| — `cdrom` | `snowdrive/src/cdrom/` | CD-ROM device emulation — flat (`CdromDevice`) / live (`CdLiveFsDevice`), full MMC |
| — `iscsi` | `snowdrive/src/iscsi/` | iSCSI PDU codec, connection, target state machine, TCP transport |
| — `iso9660` | `snowdrive/src/iso9660/` | ISO9660 + Joliet live-generation algorithms |
| **snowscsi** | `bins/snowscsi/` | Binary — `snowscsi serve` starts iSCSI target |
| **snow9660** | `bins/snow9660/` | Binary — `snow9660 list` prints ISO directory tree (stub) |
| **snowdrive-tests** | `tests/` | Integration tests crate (MockConn folded in + libiscsi whitebox) |

```
snowdrive/
├── Cargo.toml            # workspace: lib + 2 bins + tests
├── Cargo.lock
├── snowdrive/            # unified lib crate (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # common, scsi, cdrom, iscsi, iso9660 (feature-gated)
│   │   ├── common/       # BlockStorage / FsStorage seams + logging macros
│   │   ├── scsi/         # SCSI core, block/cdblock devices, spc/sbc, backends
│   │   ├── cdrom/        # CD-ROM device emulation (flat / live, full MMC)
│   │   ├── iscsi/        # PDU codec, Conn, target, transport
│   │   └── iso9660/      # ISO9660/Joliet live-generation algorithms
├── bins/
│   ├── snowscsi/         # iSCSI target CLI (binary)
│   └── snow9660/         # ISO9660 CLI (binary, stub)
├── tests/                # integration tests crate (mock + libiscsi whitebox)
└── HACKING.md
```

Dependency chain:

```
bins/snowscsi ──┐
bins/snow9660 ──┤── snowdrive
snowdrive-tests ┘
```

Feature map (`snowdrive/Cargo.toml`): `std`, `scsi`, `iscsi` (→ `scsi`),
`iso9660`, `cdrom` (→ `scsi`), `livefs` (→ `cdrom`+`iso9660`), `capi`,
`log` / `defmt`. The lib's default is `["std", "scsi", "iscsi", "iso9660"]`;
the `snowscsi` bin enables `cdrom` + `livefs` on top (the `--cdrom` option
needs them; `--cdblock` needs only `scsi`).

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or correcting tests |
| `chore` | Other changes that don't modify src or test files |

### Examples

```
feat(block): add WRITE(10) command support
fix(iscsi): correct StatSN sequence numbering
docs: update API usage examples
test(cdrom): add READ TOC format 0 tests
```

### Breaking Changes

Append `!` after the type/scope and add `BREAKING CHANGE:` in the footer:

```
feat(api)!: change do_cmd return type

BREAKING CHANGE: do_cmd now returns CommandOutcome instead of int.
```

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

## Pre-commit Workflow

1. `cargo build --workspace`
2. `cargo test --workspace`
3. `cargo fmt --check`
4. `cargo clippy --workspace -- -D warnings`
5. `cargo build -p snowdrive --no-default-features` — the lib must stay
   `no_std`-clean (feature-gated std surface only)

## Code Formatting

This project uses `rustfmt` (via `cargo fmt`). No configuration file is required — the default Rust style is used.

## Versioning

This project follows [Semantic Versioning](https://semver.org/).

- **MAJOR** (`X.0.0`) — incompatible API changes
- **MINOR** (`0.X.0`) — new functionality, backward compatible
- **PATCH** (`0.0.X`) — backward compatible bug fixes

## Legacy C Code

The original C implementation is archived on the `legacy` branch (CMake + Unity).
Check it out for reference:

```bash
git checkout legacy
```
