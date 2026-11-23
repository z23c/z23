<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# apps/

Separate C23 programs: `skycombat/`, `z23wallet/` (the lightweight wallet window, `make z23-wallet`), `z23kernel/` (`build.sh`, `main.c`), `zcl-ledger/` (`CMakeLists.txt`, `DEVELOPMENT.md`). They link neither `core/` nor `engine/`.

Rules:
- Keep strict warnings and portability; the node architecture gates do not scan this tree.
- Do not include node headers or add a dependency on `core/` or `engine/`.
- Read the program's own README.md or DEVELOPMENT.md for its build; the node Makefile does not own it.
- `zcl-ledger` signing and device material is custody-adjacent: no real keys or seeds in fixtures.

Tests: each program documents its own; run `make lint-fast` for repository-level gates.
For Android, run `make -C apps/z23android test-fast` for SDK-free development-loop checks and `make -C apps/z23android test` for the full Linux host suite.
With a selected device, `make -C apps/z23android preview-dev` runs the fast checks before building, installing and launching the isolated preview.
