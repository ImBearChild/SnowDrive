# Contributing to SnowDrive

## Project Structure

SCSI device emulation toolkit — two C libraries and two CLI tools.

| Component | Description |
|-----------|-------------|
| **libsnow9660** | ISO9660 + Joliet filesystem library |
| **libsnowscsi** | SCSI device emulation + iSCSI target protocol |
| **snow9660** | CLI — `list` command prints ISO directory tree |
| **snowscsi** | CLI — `serve` command starts iSCSI target |

```
snowdrive/
├── include/
│   ├── snow9660/          # libsnow9660 public headers
│   └── snowscsi/          # libsnowscsi public headers
├── lib/
│   ├── snow9660/          # libsnow9660 implementation
│   ├── snowscsi/          # libsnowscsi implementation
│   └── common/            # Shared utilities (snowlog, snowhex)
├── src/                   # CLI tools
├── tests/                 # Unit tests (Unity)
├── CMakeLists.txt         # Top-level build
└── HACKING.md
```

Library dependency chain:

```
snow9660 CLI ── libsnow9660 ── snowcommon
snowscsi CLI ── libsnowscsi ── snowcommon
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
feat(api)!: change snowscsi_do_cmd return type

BREAKING CHANGE: snowscsi_do_cmd now returns snowscsi_result_t instead of int.
```

## Building

```bash
cmake -B build && cmake --build build
```

To build with tests:

```bash
cmake -B build -DBUILD_TESTS=ON && cmake --build build
```

## Testing

```bash
cd build && ctest --output-on-failure
```

Run a specific test:

```bash
cd build && ./tests/test_block
```

## Pre-commit Workflow

1. Build: `cmake --build build`
2. Run all tests: `cd build && ctest --output-on-failure`
3. Format code (see Code Formatting section)

## Versioning

This project follows [Semantic Versioning](https://semver.org/).

- **MAJOR** (`X.0.0`) — incompatible API changes
- **MINOR** (`0.X.0`) — new functionality, backward compatible
- **PATCH** (`0.0.X`) — backward compatible bug fixes

## Code Formatting

This project uses `clang-format` for C code formatting. The default style is LLVM, which requires no additional configuration.

### Usage

Format all C source and header files:

```bash
find ./include/ ./src/ ./lib/ ./tests/ \( -name '*.c' -o -name '*.h' \) -exec clang-format -i --verbose {} +
```

Format a specific file:

```bash
clang-format -i filename.c
```
