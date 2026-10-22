<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# tools/

Native command handlers (`command/`, entry `command/native_command.c`), lint gates (`lint/`: `run_lint.sh`, C23 gates in `lint/lintc/`, `check_doc_claims.sh`, `z23-lint check-architecture-tree`), development tooling (`dev/`, `scripts/`, `agent/`) and standalone C23 programs at the top level.

Rules:
- C23 only. Do not add Python or new bash; small POSIX sh stays a shim.
- Files named `*baseline*` are generated ratchets: regenerate with the command in their header, never hand-edit.
- A change under `command/*.c` or a new `.c` routinely passes `lint-fast` and fails full lint: run `make lint-preflight`.
- A new gate is wired through `lint/run_lint.sh`.

Tests: `make lint-fast` for gates; `make t-fast ONLY=<group>` for handlers; derive the group with `build/bin/z23 code cost <file>`.
