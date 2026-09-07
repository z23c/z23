#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_raw_malloc.sh - ensure code outside vendored/test paths does not use
# raw malloc/calloc/realloc — every production allocation must route through
# zcl_malloc / zcl_calloc / zcl_realloc (see platform/modules/util/include/util/safe_alloc.h).
#
# Scans app/, lib/, tools/, and config/ for `malloc(`, `calloc(`, `realloc(`
# (whole-word) outside:
#   - vendor/
#   - any test/ directory or test_*.c file
#   - the safe_alloc.h header itself (which defines the wrappers)
#   - the zcl_malloc / zcl_calloc / zcl_realloc identifiers themselves
#   - lines annotated with `// raw-alloc-ok:<reason-slug>` — no space after the
#     colon, and the slug is one word ([A-Za-z][A-Za-z0-9_-]+). A prose reason
#     with spaces does NOT match, so write `raw-alloc-ok:plain-libc-fixture`.
#
# Files listed in tools/scripts/raw_malloc_allowlist.txt are grandfathered.
# The list is a ratchet: entries come off as each subsystem completes
# migration. Once empty, the allowlist is removed and the lint becomes
# unconditional.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-raw-malloc "$@"
