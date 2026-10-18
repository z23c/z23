<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# engine/

Composes and runs the node. Shapes: `controllers/`, `services/`, `models/`, `jobs/`, `supervisors/`, `conditions/`, `application/`, `modules/`. `engine/reducer/` alone advances chain state; no other path may.

Entry files: `entry/main.c`, `entry/cli.c`. The command catalog is `composition/commands/*.def` (for example `root.def`, `code.def`, `dev.def`); other registries are `composition/*.def`.

Rules:
- A new or changed command edits its `.def` and regenerates `docs/API_REFERENCE.md` with `make docs-api-reference`.
- Models own all reads; writes follow the ActiveRecord save lifecycle.
- A `.def` or new `.c` change can pass `lint-fast` and fail full lint: run `make lint-preflight`.
- Reducer or consensus-adjacent edits need the sealed-core and consensus review in the root `AGENTS.md`.

Tests: find the group with `build/bin/z23 code cost <file>`, then `make t-fast ONLY=<group>` or `make -j"$(getconf _NPROCESSORS_ONLN)" agent-verify ONLY=<g,g>`. Example group: `engine`.
