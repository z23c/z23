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

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

ALLOWLIST="$SCRIPT_DIR/raw_malloc_allowlist.txt"

declare -A ALLOWED=()
gate_load_list_file "$ALLOWLIST" ALLOWED

mapfile -t RAW_SCAN_DIRS < <(
    repo_shape_dirs app
    repo_shape_dirs lib
    printf '%s\n' engine/composition tools
)

raw_hits=$(grep -rnE '\b(malloc|calloc|realloc)[[:space:]]*\(' \
    "${RAW_SCAN_DIRS[@]}" \
    --include='*.c' --include='*.h' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
    | grep -v 'vendor/\|/test/\|test_.*\.c:\|safe_alloc' \
    | grep -v 'zcl_malloc\|zcl_calloc\|zcl_realloc' \
    | grep -vE '(//|/\*) raw-alloc-ok:[A-Za-z][A-Za-z0-9_-]+' \
    | grep -vE '".*(malloc|calloc|realloc)' \
    | grep -vE '(^|[^*])(/\*|\*[[:space:]]).*(malloc|calloc|realloc)' \
    || true)

violations=""
allowed_total=0
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"
    if [[ -n "${ALLOWED[$path]:-}" ]]; then
        allowed_total=$((allowed_total + 1))
        continue
    fi
    violations="${violations}${hit}"$'\n'
done <<< "$raw_hits"

if [[ -n "${violations//[[:space:]]/}" ]]; then
    echo "$violations"
    echo "FAIL: raw malloc/calloc/realloc in production code"
    echo "  Use zcl_malloc / zcl_calloc / zcl_realloc (see"
    echo "  platform/modules/util/include/util/safe_alloc.h) — the wrappers log + emit an"
    echo "  EV_OOM event on failure. For unavoidable cases, add a"
    echo "  // raw-alloc-ok:<reason-slug> comment on the line — no space"
    echo "  after the colon, slug is one word, e.g. raw-alloc-ok:build-tool."
    if (( allowed_total > 0 )); then
        echo "  Allowlisted (still pending migration):"
        echo "    $allowed_total raw call sites"
    fi
    exit 1
fi

if (( allowed_total > 0 )); then
    file_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$ALLOWLIST" 2>/dev/null || echo 0)
    echo "check_raw_malloc: clean outside allowlist"
    echo "  Allowlisted: $allowed_total raw call sites across $file_count files"
else
    echo "OK: check_raw_malloc - no raw malloc/calloc/realloc in production code"
fi
exit 0
