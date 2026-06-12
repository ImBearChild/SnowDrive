# Agents

All agents working on this codebase must read `HACKING.md` before making any changes. It contains coding conventions, development guidelines, and project-specific knowledge essential for contributing.

Run `find ./tests ./src ./include ./lib -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format --verbose -i {} +` before committing code to format them.