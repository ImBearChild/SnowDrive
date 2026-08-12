# Contributing to SnowDrive

## Project Structure

SCSI device emulation toolkit — unified Rust lib crate + one binary.

| Component | Location | Description |
|-----------|----------|-------------|
| **snowdrive** | `snowdrive/` | Unified lib crate + CLI (`no_std` + `std` feature) |
| — `common` | `snowdrive/src/common/` | Zero-alloc storage seams (`BlockStorage` / `FsStorage`) + unified logging macros |
| — `scsi` | `snowdrive/src/scsi/` | SCSI core, block/CDBlock devices (SBC/SPC), file/fs backends |
| — `cdrom` | `snowdrive/src/cdrom/` | CD-ROM device emulation — flat (`CdromDevice`) / live (`CdLiveFsDevice`), full MMC |
| — `iscsi` | `snowdrive/src/iscsi/` | iSCSI PDU codec, connection, target state machine, TCP transport |
| — `iso9660` | `snowdrive/src/iso9660/` | ISO9660 + Joliet live-generation algorithms |
| **snowdrive bin** | `snowdrive/src/main.rs` | Binary — `snowdrive serve` starts the iSCSI target; `snowdrive mkisofs` generates an ISO image from a directory |
| **snowdrive smoke** | `snowdrive/tests/smoke.rs` | Process-level CLI smoke tests (`CARGO_BIN_EXE_snowdrive`) |
| **snowdrive-tests** | `tests/` | Integration tests crate (MockConn folded in + libiscsi whitebox) |

```
snowdrive/
├── Cargo.toml            # workspace: lib + bin + tests
├── Cargo.lock
├── snowdrive/            # unified lib crate + CLI (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # common, scsi, cdrom, iscsi, iso9660 (feature-gated)
│   │   ├── main.rs       # CLI: serve (iSCSI target) + mkisofs (ISO generator)
│   │   ├── common/       # BlockStorage / FsStorage seams + logging macros
│   │   ├── scsi/         # SCSI core, block/cdblock devices, spc/sbc, backends
│   │   ├── cdrom/        # CD-ROM device emulation (flat / live, full MMC)
│   │   ├── iscsi/        # PDU codec, Conn, target, transport
│   │   └── iso9660/      # ISO9660/Joliet live-generation algorithms
│   ├── tests/smoke.rs    # process-level CLI smoke tests
├── tests/                # integration tests crate (mock + libiscsi whitebox)
└── HACKING.md
```

Dependency chain:

```
snowdrive/src/main.rs ──┬── snowdrive (lib)
snowdrive-tests         ┘
```

Feature map (`snowdrive/Cargo.toml`): `std`, `scsi`, `iscsi` (→ `scsi`),
`iso9660`, `cdrom` (→ `scsi`), `livefs` (→ `cdrom`+`iso9660`), `cli`
(→ `std`+all core features+std-only deps), `capi`, `log` / `defmt`. The
lib's default is `["std", "scsi", "iscsi", "iso9660", "cdrom", "livefs",
"cli"]`; the `snowdrive` bin (`src/main.rs`) builds only with
`required-features = ["cli"]`, so `--no-default-features` skips the CLI
entirely and the lib stays `no_std`-clean.

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

## Code Coverage

Coverage is measured with [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
(LLVM source-based instrumentation — the compiler's own counters, no ptrace).

```bash
# One-time setup
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked

# Whole workspace (lib + bin + tests)
cargo llvm-cov --workspace

# Lib-only coverage (exclude the thin bin shell)
cargo llvm-cov --workspace --ignore-filename-regex 'snowdrive/src/main.rs'

# HTML report (writes target/llvm-cov-html/)
cargo llvm-cov --workspace --html --output-dir target/llvm-cov-html

# lcov for CI / Codecov (writes target/coverage.lcov)
cargo llvm-cov --workspace --lcov --output-path target/coverage.lcov
```

Baseline (Aug 2026, `cargo llvm-cov --workspace`): **TOTAL ~90% lines**,
with `iso9660/live.rs` (99%), `spc.rs` (99%), `pdu.rs` (97%) the strongest
modules.

Notes:

- `--no-default-features` builds only the always-on `common` module (~3%);
  meaningful feature-matrix runs must enable `--features scsi` etc.
- **Pre-existing gap**: `cargo test -p snowdrive --no-default-features
  --features scsi` does not compile (unit tests use `Vec`/`String` without
  pulling in `std`). This predates coverage tooling and is a separate bug.
- Coverage artifacts land under `target/` (already gitignored).

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
