# Contributing to SnowDrive

## Project Structure

SCSI device emulation toolkit — Rust workspace (cargo).

| Component | Description |
|-----------|-------------|
| **snowcommon** | Zero-alloc logging and hex formatting (`no_std`) |
| **snowscsi** | SCSI device emulation + iSCSI target protocol (`no_std` + optional `std` feature) |
| **snow9660** | ISO9660 + Joliet filesystem library (Phase 1 stub, `no_std`) |
| **snowscsi-capi** | C ABI bindings for snowscsi |
| **snowscsi-cli** | CLI — `serve` command starts iSCSI target |
| **snow9660-cli** | CLI — `list` command prints ISO directory tree (stub) |
| **snowdrive-tests** | Integration tests crate (MockConn folded in + libiscsi whitebox) |

```
snowdrive/
├── Cargo.toml            # virtual workspace
├── Cargo.lock
├── crates/
│   ├── snowcommon/       # [no_std 零 alloc]
│   ├── snowscsi/         # [no_std 零 alloc; std feature]
│   ├── snow9660/         # [no_std 零 alloc] stub
│   ├── snowscsi-capi/    # C ABI
│   ├── snowscsi-cli/     # binary
│   └── snow9660-cli/     # binary
├── tests/                # integration tests crate (mock + libiscsi)
└── HACKING.md
```

Crate dependency chain:

```
snow9660-cli ── snow9660
snowscsi-cli ── snowscsi ── snowcommon
snowscsi-capi ── snowscsi
snowdrive-tests ── snowscsi
```

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
