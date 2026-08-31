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

DL_CALL_RE='(^|[^[:alnum:]_])dl(open|sym|close)[[:space:]]*[(]'
HITS=$(grep -rnE --include='*.c' \
    "$DL_CALL_RE" \
    app tools lib config src domain application adapters 2>/dev/null \
    | grep -v '^lib/hotswap/' || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: dlopen/dlsym/dlclose outside lib/hotswap/ (release must be static)"
    exit 1
fi

scan_dev_regions() {
    awk -v dl_call_re="$DL_CALL_RE" '
        /^[ \t]*#[ \t]*ifdef[ \t]+ZCL_DEV_BUILD/ {
            depth++; dev_frame[depth] = 1; dev_branch[depth] = 1;
            dev_active++; next
        }
        /^[ \t]*#[ \t]*if/ {
            depth++; dev_frame[depth] = 0; dev_branch[depth] = 0; next
        }
        /^[ \t]*#[ \t]*elif/ || /^[ \t]*#[ \t]*else/ {
            if (depth > 0 && dev_frame[depth] && dev_branch[depth]) {
                dev_active--; dev_branch[depth] = 0
            }
            next
        }
        /^[ \t]*#[ \t]*endif/ {
            if (depth > 0) {
                if (dev_frame[depth] && dev_branch[depth]) dev_active--
                delete dev_frame[depth]; delete dev_branch[depth]; depth--
            }
            next
        }
        $0 ~ dl_call_re {
            if (dev_active < 1) print FILENAME ":" NR ": " $0
        }
    ' "$@"
}

# The scanner is itself a security boundary. Pin both historical failure
# modes: a nested host conditional stays inside the dev branch, while the
# matching top-level #else immediately returns to release code.
NESTED_BAD=$(printf '%s\n' '#ifdef ZCL_DEV_BUILD' '#if defined(__APPLE__)' \
    'dlopen("dev", 0);' '#endif' '#endif' | scan_dev_regions -)
ELSE_BAD=$(printf '%s\n' '#ifdef ZCL_DEV_BUILD' 'dlopen("dev", 0);' \
    '#else' 'dlopen("release", 0);' '#endif' | scan_dev_regions -)
PREFIXED_BAD=$(printf '%s\n' \
    'static void *vfs_dir_xdlopen(void);' \
    'static void *vfs_dir_xdlsym(void);' \
    'static void vfs_dir_xdlclose(void);' \
    | grep -E "$DL_CALL_RE" || true)
DIRECT_COUNT=$(printf '%s\n' \
    'void *p = dlopen("fixture", 0);' \
    'p = dlsym (h, "fixture");' \
    '(void)dlclose(h);' \
    | grep -cE "$DL_CALL_RE" || true)
if [ -n "$NESTED_BAD" ] || [ -z "$ELSE_BAD" ] || \
   [ -n "$PREFIXED_BAD" ] || [ "$DIRECT_COUNT" -ne 3 ]; then
    echo "FAIL: hot-swap dev-region scanner selftest" >&2
    exit 1
fi

for f in $(ls lib/hotswap/src/*.c 2>/dev/null); do
    # Nesting-aware toggle scan. The old one-line matcher treated every
    # `#endif` as the end of the dev region, so a per-host `#if defined(...)`
    # pair INSIDE the dev half silently switched it off. Counting conditional
    # depth keeps the region open across such inner branches while preserving
    # the old behavior: `#else` or full unwind at depth 0 closes it.
    BAD=$(scan_dev_regions "$f")
    if [ -n "$BAD" ]; then
        echo "$BAD"
        echo "FAIL: dl* call outside a #ifdef ZCL_DEV_BUILD region in $f"
        exit 1
    fi
done
echo "  OK: hot-swap dynamic loading is dev-only"
