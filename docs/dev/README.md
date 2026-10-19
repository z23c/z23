<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Developer references

Build and test loop, hot-swap, test-result cache, lab, plugins, services, flags and host maintenance for people changing Z23. Procedure lives in [DEVELOPING.md](DEVELOPING.md).

## Build and test loop

| Document | Purpose |
|---|---|
| [BUILD_BENCH.md](./BUILD_BENCH.md) | `make build-bench` scenario harness and its measured baseline |
| [BUILD_HOST_ACCELERATOR.md](./BUILD_HOST_ACCELERATOR.md) | disposable RAM workspace for rotating-disk hosts |
| [C23_DEV_LOOP_PERFORMANCE.md](./C23_DEV_LOOP_PERFORMANCE.md) | coverage and latency ledger for live reload, fast restart, affected proofs and cache reuse |
| [HOTSWAP.md](./HOTSWAP.md) | the dev-only hot-swap mechanisms |
| [REFLEX_REACTOR.md](./REFLEX_REACTOR.md) | local zero-wait reflex reactor: edit C23, receive the first exact next-build result |
| [test-result-cache.md](./test-result-cache.md) | content-addressed per-group test result cache |
| [fast-path.md](./fast-path.md) | the information algorithm and fast inner-loop commands for any change |
| [NATIVE_MACOS_RUNBOOK.md](./NATIVE_MACOS_RUNBOOK.md) | native arm64 macOS maintenance and known host quirks |
| [HOST_GC.md](./HOST_GC.md) | host garbage collector for worktrees, proof generations and compiler caches |

## Code navigation and lint

| Document | Purpose |
|---|---|
| [MIND.md](./MIND.md) | the per-node resident that owns rebuilding the code index |
| [DATA_INDEX.md](./DATA_INDEX.md) | local data-source ingest and search (`z23-dev dev index`) |
| [palace-design.md](./palace-design.md) | code-legibility layer: file and group purpose, `code room`, gates P1 to P3 |
| [lint-gate-hollowness-audit.md](./lint-gate-hollowness-audit.md) | the fail-loud scan-floor lint-gate pattern |

## Extension points

| Document | Purpose |
|---|---|
| [FLAGS.md](./FLAGS.md) | the closed catalog of environment flags |
| [LAB.md](./LAB.md) | the one-file lab: compile, run confined, return a JSON receipt |
| [PLUGINS.md](./PLUGINS.md) | signed plugin store |
| [SERVICES.md](./SERVICES.md) | declaring a service binding |

## Contributors

[CONTRIBUTORS.md](./CONTRIBUTORS.md) recognizes contributors and states the licensing terms.

## Also in this directory

- [`BUILD.md`](./BUILD.md): Building z23
- [`CODEBASE_MAP.md`](./CODEBASE_MAP.md): CODEBASE_MAP.md — where things live + how to do each thing
- [`COOKBOOK.md`](./COOKBOOK.md): Z23 cookbook
- [`NATIVE_COMMAND_INTERFACE.md`](./NATIVE_COMMAND_INTERFACE.md): Z23 Native Command Interface
- [`PROMOTION_RECEIPTS.md`](./PROMOTION_RECEIPTS.md): Promotion receipts — evidence that outlives the machine that made it
