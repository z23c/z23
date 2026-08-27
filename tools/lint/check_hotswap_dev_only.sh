#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_dev_only.sh — release purity for the Tier-1 hot-swap loader
# (HARD; Makefile `check-hotswap-dev-only` gate). Two invariants:
#   (1) no dlopen/dlsym/dlclose CALL in any .c outside lib/hotswap/ + vendor/;
#   (2) inside lib/hotswap sources, every such call sits within a
#       `#ifdef ZCL_DEV_BUILD` region (a pragmatic toggle scan),
# so a release build links zero dynamic-loading code. Extracted verbatim from
# the former inline Makefile recipe for tools/lint/run_lint.sh + standalone use.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

HITS=$(grep -rnE --include='*.c' \
    'dlopen[[:space:]]*\(|dlsym[[:space:]]*\(|dlclose[[:space:]]*\(' \
    app tools lib config src domain application adapters 2>/dev/null \
    | grep -v '^lib/hotswap/' || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: dlopen/dlsym/dlclose outside lib/hotswap/ (release must be static)"
    exit 1
fi
for f in $(ls lib/hotswap/src/*.c 2>/dev/null); do
    # Nesting-aware toggle scan. The old one-line matcher treated every
    # `#endif` as the end of the dev region, so a per-host `#if defined(...)`
    # pair INSIDE the dev half silently switched it off. Counting conditional
    # depth keeps the region open across such inner branches while preserving
    # the old behavior: `#else` or full unwind at depth 0 closes it.
    BAD=$(awk '
        /^[ \t]*#[ \t]*ifdef[ \t]+ZCL_DEV_BUILD/ { depth++; dev = 1; next }
        /^[ \t]*#[ \t]*if/                       { depth++; next }
        /^[ \t]*#[ \t]*elif/                     { next }
        /^[ \t]*#[ \t]*else/                     { if (depth == 0) dev = 0; next }
        /^[ \t]*#[ \t]*endif/                    { if (depth > 0) depth--
                                                   if (depth == 0) dev = 0; next }
        /dl(open|sym|close)[[:space:]]*\(/       { if (dev != 1) print FILENAME ":" NR ": " $0 }
    ' "$f")
    if [ -n "$BAD" ]; then
        echo "$BAD"
        echo "FAIL: dl* call outside a #ifdef ZCL_DEV_BUILD region in $f"
        exit 1
    fi
done
echo "  OK: hot-swap dynamic loading is dev-only"
