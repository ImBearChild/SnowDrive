# Agents

This file contains instructions **exclusively for AI agents**. Human-oriented
documentation (build, test, format, commit conventions) lives in `HACKING.md` —
agents must read it before making changes.

## Cross-session Memory

Agent can create, write and modify `__*.md` as notice, reference or any other
things required for cross session memory. These files are ephemeral — clean them
up when they are no longer relevant to active work, and must never appear in
staged changes or commits.

Agent should download standard files (RFC, ISO9660, etc) to `__REF_XXX.*` and
refer to them when necessary. Those files can be downloaded even when agent is
required not to modify any files, since they are reference and will not be
tracked by git.

### Current Reference Files

| File | Standard | Description | Source |
|------|----------|-------------|--------|
| `__REF_RFC3720.txt` | RFC 3720 | iSCSI Protocol (mandatory, DO NOT follow RFC 7143) | https://www.rfc-editor.org/rfc/rfc3720.txt |
| `__REF_ECMA119.pdf.md` | ECMA-119 / ISO 9660 | Volume and File Structure of CD-ROM (Annex J covers Joliet) | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf |
| `__REF_SPC3.pdf.md` | T10/INCITS 513 (SPC-3) | SCSI Primary Commands - 3: INQUIRY, MODE SENSE, REQUEST SENSE, REPORT LUNS (closest public draft; SPC-4 r37 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/spc3r23.pdf |
| `__REF_SBC3.pdf.md` | T10/INCITS 514 (SBC-3) | SCSI Block Commands - 3: READ(10), WRITE(10), READ CAPACITY, etc. (r25; r28 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/sbc3r25.pdf |
| `__REF_MMC6.pdf.md` | T10/INCITS 522 (MMC-6) | SCSI Multi-Media Commands - 6: READ TOC, GET CONFIGURATION, CD-R/RW commands | http://www.13thmonkey.org/documentation/SCSI/mmc6r02g.pdf |
| `__REF_ELTORITO.pdf.md` | El Torito | Bootable CD-ROM BIOS specification | http://www.13thmonkey.org/documentation/SCSI/el-torito.pdf |

## Critical Rules

- DO NOT implement iSCSI per RFC 7143 — it is not widely accepted. Follow
  RFC 3720 instead.


## Rust Workspace Layout

```
snowdrive/
├── Cargo.toml            # virtual workspace
├── crates/
│   ├── snowcommon/       # [no_std 零 alloc] logging + hex formatting
│   ├── snowscsi/         # [no_std 零 alloc; std feature] SCSI core + iSCSI target
│   ├── snow9660/         # [no_std 零 alloc] ISO9660 stub
│   ├── snowscsi-capi/    # C ABI bindings (unsafe-allowed)
│   ├── snowscsi-cli/     # binary: serve command
│   ├── snow9660-cli/     # binary: list command (stub)
│   └── snowscsi-mock/    # MockConn for deterministic testing
├── tests/                # Integration tests crate (snowdrive-tests)
└── ...
```

## Implementation Status

| Component | Status |
|-----------|--------|
| `snowscsi` | Pending: SBC + RAM backend + iSCSI PDU/target loop to be ported from C |
| `snow9660` | Stub (version string only) |
| `snowscsi-cli` | Stub (help text only) |
| `snow9660-cli` | Stub (help text only) |
| `snowscsi-capi` | Stub (cbindgen configured, no exported functions yet) |

## Legacy C Code

The original C implementation lives on the `legacy` branch:
```bash
git checkout legacy
```

## Agent-Only Context

- **Logging**: `snowcommon` provides zero-alloc `LogBuf` + `core::fmt::Write`.
  `tracing` available as optional `std` feature for CLI output.
- **Tests**: `cargo test --workspace`. Integration tests (mock + libiscsi
  whitebox) live in `tests/` crate.
- **no_std verification**: `cargo build -p snowscsi -p snowcommon -p snowscsi-capi --no-default-features`
- **Transport layer**: `Conn` trait = blanket impl of `embedded_io::Read + Write`.
  BSD transport (`TcpStream`) behind `std` feature in `snowscsi`.
- **C ABI**: `snowscsi-capi` wraps borrow-based core with `OpaqueHandle` +
  C-style mirror API. `cbindgen` generates `snowscsi.h` via build.rs.
- **Red lines**: `#![forbid(unsafe_code)]` on all crates except `snowscsi-capi`
  and `snowdrive-tests`. RFC 3720 only, no RFC 7143. `__*` files never committed.
