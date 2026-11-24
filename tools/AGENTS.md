<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# tools/

Native command handlers (`command/`, entry `command/native_command.c`), lint gates (`lint/`: C23 gates and the `z23-lint run` driver in `lint/lintc/`, `z23-lint check-doc-claims`, `z23-lint check-architecture-tree`), development tooling (`dev/`, `scripts/`, `agent/`) and standalone C23 programs at the top level.

Rules:
- C23 only. Do not add Python or new bash; small POSIX sh stays a shim.
- Files named `*baseline*` are generated ratchets: regenerate with the command in their header, never hand-edit.
- For `command/*.c` changes or new `.c` files, run `make lint-fast-preflight` once; it includes `lint-fast`. Otherwise run `lint-fast`, unless the guide requires more.
- A new gate is wired through a `LINT_ROW` in `lint/lintc/gate_commands.def`.

Tests: `make lint-fast` for gates; `make t-fast ONLY=<group>` for handlers; derive the group with `build/bin/z23 code cost <file>`.
