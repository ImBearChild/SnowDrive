# Agents

This file contains instructions **exclusively for AI agents**. Human-oriented
documentation (build, test, format, commit conventions) lives in `HACKING.md` —
read it before making changes.

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
| `__REF_ECMA119.pdf` | ECMA-119 / ISO 9660 | Volume and File Structure of CD-ROM (Annex J covers Joliet) | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf |
| `__REF_SPC3.pdf` | T10/INCITS 513 (SPC-3) | SCSI Primary Commands - 3: INQUIRY, MODE SENSE, REQUEST SENSE, REPORT LUNS (closest public draft; SPC-4 r37 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/spc3r23.pdf |
| `__REF_SBC3.pdf` | T10/INCITS 514 (SBC-3) | SCSI Block Commands - 3: READ(10), WRITE(10), READ CAPACITY, etc. (r25; r28 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/sbc3r25.pdf |
| `__REF_MMC6.pdf` | T10/INCITS 522 (MMC-6) | SCSI Multi-Media Commands - 6: READ TOC, GET CONFIGURATION, CD-R/RW commands | http://www.13thmonkey.org/documentation/SCSI/mmc6r02g.pdf |
| `__REF_ELTORITO.pdf` | El Torito | Bootable CD-ROM BIOS specification | http://www.13thmonkey.org/documentation/SCSI/el-torito.pdf |

## Critical Rules

- DO NOT implement iSCSI per RFC 7143 — it is not widely accepted. Follow
  RFC 3720 instead. Note: `lib/snowscsi/iscsi_pdu.c` comments reference RFC 7143
  byte offsets for field documentation only; the wire protocol and BHS layout are
  identical between the two RFCs.

## Implementation Status

The README warns "not yet functional / skeleton only", but partial implementation
exists:

| Component | Status |
|-----------|--------|
| `libsnowscsi` | Phase 1.a (SBC + RAM backend) + 1.b1 (iSCSI PDU/target loop) done |
| `libsnow9660` | Stub (version string only) |
| `snowscsi` CLI | Hardcoded 16MB RAM disk on `0.0.0.0:3260` — no arg parsing |
| `snow9660` CLI | Stub (help text only) |

## Agent-Only Context

- **Logging**: Set `SNOWLOG_LEVEL` env var (0=none, 5=verbose). Default 3 (info).
  Output goes to stderr as `[LEVEL][tag] message`.
- **Tests**: Unity framework auto-fetched by CMake (tag v2.6.1 from
  github.com/ThrowTheSwitch/Unity). See `tests/CMakeLists.txt`.
- **No CI**: No `.github/` workflows. Run build/test manually.
- **No opencode.json**: No OpenCode-specific configuration.
- **Transport layer**: Pluggable via `snowscsi_transport_ops_t`
  (`include/snowscsi/iscsi.h:161`). Default: BSD sockets (`transport_bsd.c`).
- **Device struct**: Internal layout in `lib/snowscsi/device_internal.h` —
  extends via `handle_cmd` function pointer.