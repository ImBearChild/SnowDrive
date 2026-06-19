# Agents

This file contains instructions **exclusively for AI agents** working on this codebase.
`HACKING.md` applies to both humans and agents; it must be read before making any changes.

## Cross-session Memory

Agent can create, write and modify `__*.md` as notice, reference or any other things
required for cross session memory. These files are ephemeral — clean them up when
they are no longer relevant to active work, and must never appear in staged changes or commits.

Agent should download standard files (RFC, ISO9960, etc) to `__REF_XXX.md` or `__REF_XXX.md` and refer
to them when necessary. Those files can be download even agent is required not to modify any files,
since those files are reference and will not track by git.

### Current Reference Files

| File | Standard | Description | Source |
|------|----------|-------------|--------|
| `__REF_RFC3720.txt` | RFC 3720 | iSCSI Protocol (mandatory, DO NOT follow RFC 7143) | https://www.rfc-editor.org/rfc/rfc3720.txt |
| `__REF_ECMA119.pdf` | ECMA-119 / ISO 9660 | Volume and File Structure of CD-ROM (Annex J covers Joliet) | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf |
| `__REF_SPC3.pdf` | T10/INCITS 513 (SPC-3) | SCSI Primary Commands - 3: INQUIRY, MODE SENSE, REQUEST SENSE, REPORT LUNS (closest public draft, SPC-4 r37 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/spc3r23.pdf |
| `__REF_SBC3.pdf` | T10/INCITS 514 (SBC-3) | SCSI Block Commands - 3: READ(10), WRITE(10), READ CAPACITY, etc. (r25; r28 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/sbc3r25.pdf |
| `__REF_MMC6.pdf` | T10/INCITS 522 (MMC-6) | SCSI Multi-Media Commands - 6: READ TOC, GET CONFIGURATION, CD-R/RW commands | http://www.13thmonkey.org/documentation/SCSI/mmc6r02g.pdf |
| `__REF_ELTORITO.pdf` | El Torito | Bootable CD-ROM BIOS specification | http://www.13thmonkey.org/documentation/SCSI/el-torito.pdf |


## Critical Rules

- Commit messages must follow the Conventional Commits format documented in
  `HACKING.md`.
- DO NOT FOLLOW RFC 7143, which is not accept by mainstream, follow RFC 3720 instead.

## Pre-commit Workflow

Run the following before every commit:

1. Build (`cmake --build build`)
2. Run tests (`ctest --test-dir build --output-on-failure`)
3. Format code (see `HACKING.md` for the clang-format command)