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
├── Cargo.toml            # workspace: snowdrive lib + 2 bins + tests
├── snowdrive/            # unified lib crate (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # #![no_std] (unless std feature); deny(unsafe_code)
│   │   ├── common/       # always on: BlockStorage/FsStorage seams + logging macros
│   │   ├── scsi/         # feature "scsi": SCSI core, block/cdblock/cdrom, spc/sbc
│   │   ├── iscsi/        # feature "iscsi": PDU codec, Conn, target, transport
│   │   └── iso9660/      # feature "iso9660": ISO9660/Joliet live-generation
│   ├── build.rs          # cbindgen (feature "capi")
│   └── cbindgen.toml
├── bins/
│   ├── snowscsi/         # binary: serve command (std)
│   └── snow9660/         # binary: list command (stub)
├── tests/                # integration tests crate (snowdrive-tests; MockConn folded in)
└── ...
```

## Implementation Status

| Component | Status |
|-----------|--------|
| `snowdrive::scsi` | Done — SBC + RAM/File backends + SPC/SBC layers + block/cdblock/cdrom devices + iSCSI PDU/target loop |
| `snowdrive::iscsi` | Done — PDU codec, Conn trait, Session state machine, BSD transport |
| `snowdrive::iso9660` | Done — live ISO9660/Joliet generation algorithms (`live.rs`) |
| `snowdrive::capi` | Postponed — C ABI (`feature = "capi"` declared, no exports yet) |
| `bins/snowscsi` | Done — `serve` subcommand (--block / --cdblock / --iscsi) |
| `bins/snow9660` | Stub — `list` subcommand (help text only) |

## Legacy C Code

The original C implementation lives on the `legacy` branch:
```bash
git checkout legacy
```

## Agent-Only Context

- **Logging**: `snowdrive::common` provides unified logging macros (`trace!`/
  `debug!`/`info!`/`warn!`/`error!`) that dispatch to `log` or `defmt` via
  features. Log output routing is the caller's responsibility.
- **Tests**: `cargo test --workspace`. Integration tests (mock + libiscsi
  whitebox) live in `tests/` crate.
- **no_std verification**: `cargo build -p snowdrive --no-default-features`
- **Transport layer**: `Conn` trait = blanket impl of `embedded_io::Read + Write`.
  BSD transport (`TcpStream`) behind `std` feature in `snowdrive::iscsi`.
- **C ABI**: postponed. When resumed, `snowdrive::capi` (`feature = "capi"`)
  wraps the borrow-based core with `OpaqueHandle` + C-style mirror API;
  `cbindgen` generates `snowscsi.h` via build.rs.
- **Red lines**: `#![deny(unsafe_code)]` on the snowdrive lib (forbid would
  block the future `capi` module, which opts back in via `#[allow(unsafe_code)]`).
  `snowdrive-tests` allows unsafe (libiscsi FFI). RFC 3720 only, no RFC 7143.
  `__*` files never committed.
