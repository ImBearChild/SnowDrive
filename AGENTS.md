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
| `__REF_USB_MSC_Overview_v1.4.pdf.md` | USB MSC Overview 1.4 | USB Mass Storage Class overview (all transports, command sets) | https://www.usb.org/sites/default/files/Mass_Storage_Specification_Overview_v1.4_2-19-2010.pdf |
| `__REF_USB_MSC_BulkOnly_v1.0.pdf.md` | USB MSC Bulk-Only 1.0 | Bulk-Only Transport (BBB) — primary MSC transport | https://www.usb.org/sites/default/files/usbmassbulk_10.pdf |
| `__REF_USB_MSC_CBI_v1.1.pdf.md` | USB MSC CBI 1.1 | Control/Bulk/Interrupt Transport (legacy, floppy only) | https://www.usb.org/sites/default/files/usb_msc_cbi_1.1.pdf |
| `__REF_USB_MSC_UFI_v1.0.pdf.md` | USB MSC UFI 1.0 | USB Floppy Interface command set (based on SCSI-2) | https://www.usb.org/sites/default/files/usbmass-ufi10.pdf |
| `__REF_USB_MSC_Bootability_v1.0.pdf.md` | USB MSC Bootability 1.0 | Bootable USB mass storage device specification | https://www.usb.org/sites/default/files/usb_msc_boot_1.0.pdf |
| `__REF_T10_UAS_r0.pdf.md` | T10/08-221r0 (UAS) | USB Attached SCSI transport protocol (T10 draft) | https://www.t10.org/ftp/t10/document.08/08-221r0.pdf |
| `__REF_USB_UASP_v1.0.pdf.md` | USB UASP 1.0 | UAS implementation guide for USB 2.0/3.0 (USB-IF) | https://www.usb.org/sites/default/files/uasp_1_0.zip |

## Critical Rules

- DO NOT implement iSCSI per RFC 7143 — it is not widely accepted. Follow
  RFC 3720 instead.


## Rust Workspace Layout

```
snowdrive/
├── Cargo.toml            # workspace: snowdrive lib + bin + tests
├── snowdrive/            # unified lib crate + CLI (feature-gated modules)
│   ├── src/
│   │   ├── lib.rs        # #![no_std] (unless std feature); deny(unsafe_code)
│   │   ├── main.rs       # CLI: serve + mkisofs subcommands (std; required-features=["cli"])
│   │   ├── common/       # always on: BlockStorage/FsStorage seams + logging macros
│   │   ├── scsi/         # feature "scsi": SCSI core, block/cdblock, spc/sbc
│   │   ├── cdrom/        # feature "cdrom": CD-ROM device emulation (flat/live, full MMC)
│   │   ├── iscsi/        # feature "iscsi": PDU codec, Conn, target, transport
│   │   ├── iso9660/      # feature "iso9660": ISO9660/Joliet live-generation
│   │   └── usb/          # feature "usb": USB MSC Bulk-Only Transport core (CBW/CSW, BotSession)
│   ├── tests/smoke.rs    # process-level CLI smoke tests (CARGO_BIN_EXE_snowdrive)
│   ├── build.rs          # cbindgen (feature "capi")
│   └── cbindgen.toml
├── tests/                # integration tests crate (snowdrive-tests; MockConn folded in)
└── ...
```

## Implementation Status

| Component | Status |
|-----------|--------|
| `snowdrive::scsi` | Done — SBC + RAM/File backends + SPC/SBC layers + block/cdblock devices + iSCSI PDU/target loop |
| `snowdrive::cdrom` | Done — flat (`CdromDevice`) + live (`CdLiveFsDevice`) CD-ROM, full MMC surface (README TOC, GET CONFIGURATION, READ BUFFER CAPACITY, …) |
| `snowdrive::iscsi` | Done — PDU codec, Conn trait, Session state machine, BSD transport |
| `snowdrive::iso9660` | Done — live ISO9660/Joliet generation algorithms (`live.rs`) |
| `snowdrive::usb` | Done — MSC Bulk-Only Transport core: `bot.rs` (CBW/CSW codec), `io.rs` (`BotIo` + `recv_exact`), `gadget.rs` (`Gadget` + `CtrlReq`), `target.rs` (non-blocking `BotSession::poll` state machine) |
| `snowdrive::capi` | Postponed — C ABI (`feature = "capi"` declared, no exports yet) |
| `snowdrive` bin | Done — `src/main.rs` (lib + CLI in one crate); `serve` subcommand (`--disk`/`--cdrom` device planes + `--iscsi` / `--usb` transports, mutually exclusive) + `mkisofs` subcommand (directory → ISO image) |
| `snow9660` | Removed — folded into the `snowdrive` CLI as `mkisofs` (the lib generates ISOs, it does not parse them) |

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
  USB MSC transport: `BotIo`/`Gadget` seams in `snowdrive::usb` — the
  non-blocking `BotSession` core never does platform I/O; the Linux FunctionFS
  bridge (`FfsBot`/`FfsGadget`, `usb-gadget` crate) lives only in the bin under
  `cfg(target_os = "linux")`.
- **C ABI**: postponed. When resumed, `snowdrive::capi` (`feature = "capi"`)
  wraps the borrow-based core with `OpaqueHandle` + C-style mirror API;
  `cbindgen` generates `snowdrive.h` via build.rs.
- **Red lines**: `#![deny(unsafe_code)]` on the snowdrive lib (forbid would
  block the future `capi` module, which opts back in via `#[allow(unsafe_code)]`).
  `snowdrive-tests` allows unsafe (libiscsi FFI). RFC 3720 only, no RFC 7143.
  `__*` files never committed.
