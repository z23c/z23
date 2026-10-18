<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# platform/

Portable base and outside-world seams: `platform/modules/` (`base`, `json`, `util`, and others), `platform/ports/include/` (interfaces), `platform/adapters/outbound/` (implementations for outside systems), `domain/`, `packaging/`, `deploy/`.

Rules:
- Outside systems are reached only through `platform/ports/` and `platform/adapters/`.
- `deploy/` and `packaging/release/` describe production deployment and release; running or changing their effect on a live host is owner-gated.
- `LOG_FAIL`, `LOG_ERR` and `LOG_NULL` return; never discard their value.
- After moving files run `make check-architecture-tree`.

Tests: `make t-fast ONLY=<group>`, for example `json` for `modules/json`; derive others with `build/bin/z23 code cost <file>`.
