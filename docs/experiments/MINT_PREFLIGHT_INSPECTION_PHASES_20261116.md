<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Mint preflight inspection phases

The copied snapshot inspection records durations for the SQLite open, query-only setup, normal-boot gate and close alongside the existing aggregate inspection duration. A phase is recorded only after its operation is attempted; a gate duration does not assert acceptance. The aggregate remains unchanged. Source-family stability checks and WAL-aware inspection remain unchanged.

<!-- claim: symbol-present inspect_open_and_gate engine/composition/src/boot_mint_anchor_preflight.c -->

A retained warm restart recorded 26,453 ms for aggregate copy inspection. This measurement does not identify which operation caused the delay. A separate synthetic SQL fixture on 2026-11-16 UTC used GCC 14.2 C23 -O2, SQLite 3.49.0 and AMD Ryzen 9 7950X3D; it measured 77–110 ms for a warm one-million-row scan; it does not reproduce the complete boot, WAL recovery or production data. Its result log has SHA-256 `d44dc17053fe0f37ba7055760c84baeced52d75713626f48064753922059fd61`. Its probe source SHA-256 is `9b5635e06c3239bdcabca1c6a60b7c459c38c9128676d16ae2dde23673c4a7cd`. Wall and CPU times cover the first SQLite step; positive-case counters include the subsequent step to completion. No speedup is claimed.

Focused check:

```sh
DEVBUILD_CLASS=light devbuild --wait make -j2 t-fast-exact ONLY=mint_anchor_preflight T_FAST_EXACT_ARGS=--no-cache
```

Initial three-phase check: 1 group passed, zero skipped. Final four-phase check: 1 group passed, zero failures, skips, environment-unobserved or load-flaky cases; test body 206 ms.
