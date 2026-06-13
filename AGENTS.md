# Agents

This file contains instructions **exclusively for AI agents** working on this codebase.
`HACKING.md` applies to both humans and agents; it must be read before making any changes.

## Cross-session Memory

Agent can create, write and modify `__*.md` as notice, reference or any other things
required for cross session memory. These files are ephemeral — clean them up when
they are no longer relevant to active work, and must never appear in staged changes or commits.

Agent should download standard files (RFC, ISO9960, etc) to `__REF_XXX.md` and refer
to them when necessary. As an instance, agent should download
[RFC7143](https://www.rfc-editor.org/rfc/rfc7143.txt) to `__REF_RFC7143.md` and refer
to it when writing code on iSCSI parts.

## Critical Rules

- Commit messages must follow the Conventional Commits format documented in
  `HACKING.md`.

## Pre-commit Workflow

Run the following before every commit:

1. Build (`cmake --build build`)
2. Run tests (`ctest --test-dir build --output-on-failure`)
3. Format code (see `HACKING.md` for the clang-format command)