#!/usr/bin/env bash
# Controller private-header ownership gate (shrink-only ratchet).
#
# A header named controllers/<owner>_internal.h or <owner>_private.h belongs
# to the dynamically-derived <owner> source family. It may be included by:
#   - a context/authority controllers/src/<owner>.c or <owner>_*.c;
#   - another *_internal.h / *_private.h controller header;
#   - test code.
# Every other production include is an external private dependency and must
# match the exact shrink-only baseline. New and stale rows fail. The scan is
# over tracked C headers/sources, so generated build output and untracked
# selftest files cannot create false positives in production mode.
set -euo pipefail

cd "$(dirname "$0")/../.."

GATE=check_controller_private_headers
SCAN_ROOT="${ZCL_CONTROLLER_PRIVATE_SCAN_ROOT:-.}"
HEADER_ROOT="${ZCL_CONTROLLER_PRIVATE_HEADER_ROOT:-}"
BASELINE="${ZCL_CONTROLLER_PRIVATE_BASELINE:-tools/lint/controller_private_header_baseline.txt}"

collect_files() {
    if [ "$SCAN_ROOT" = "." ]; then
        git ls-files -- '*.c' '*.h'
    else
        find "$SCAN_ROOT" -type f \( -name '*.c' -o -name '*.h' \) | sort
    fi
}

display_path() {
    local file="$1"
    if [ "$SCAN_ROOT" = "." ]; then
        printf '%s' "$file"
    else
        printf '%s' "${file#"$SCAN_ROOT"/}"
    fi
}

is_test_path() {
    case "$1" in
        tests/*|lib/test/*|*/test/*|*/tests/*|*/test_*.c|*/test_*.h) return 0 ;;
        *) return 1 ;;
    esac
}

scan_external_edges() {
    local file path line include leaf owner base
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        path="$(display_path "$file")"
        is_test_path "$path" && continue
        while IFS= read -r line; do
            include=$(printf '%s\n' "$line" | sed -nE \
                's@^[0-9]+:[[:space:]]*#include[[:space:]]+["<](controllers/[^">]+_(internal|private)\.h)[">].*@\1@p')
            [ -n "$include" ] || continue
            leaf=${include##*/}
            owner=${leaf%_internal.h}
            owner=${owner%_private.h}
            base=${path##*/}
            base=${base%.*}

            # Private controller headers may compose other private headers.
            case "$base" in *_internal|*_private) continue ;; esac

            # The owning source family may consume its own private header.
            case "$path" in
                */controllers/src/*)
                    case "$base" in "$owner"|"$owner"_*) continue ;; esac
                    ;;
            esac
            printf '%s:#include "%s"\n' "$path" "$include"
        done < <(grep -nE '^[[:space:]]*#include[[:space:]]+["<]controllers/[^">]+_(internal|private)\.h[">]' \
            "$file" || true)
    done < <(collect_files)
}

if [ "${1:-}" = "--selftest" ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-controller-private.XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    mkdir -p "$tmp/app/controllers/src" \
        "$tmp/app/controllers/include/controllers" \
        "$tmp/app/views/src" "$tmp/config/src" "$tmp/lib/test/src"
    : > "$tmp/app/controllers/include/controllers/alpha_internal.h"
    : > "$tmp/empty-baseline.txt"
    self="$PWD/tools/lint/$GATE.sh"

    run_fixture() {
        env ZCL_CONTROLLER_PRIVATE_SCAN_ROOT="$tmp" \
            ZCL_CONTROLLER_PRIVATE_HEADER_ROOT="$tmp/app/controllers/include/controllers" \
            ZCL_CONTROLLER_PRIVATE_BASELINE="$tmp/empty-baseline.txt" \
            "$self"
    }
    expect_fail() {
        local label="$1" rc=0
        run_fixture >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $label passed" >&2
            exit 2
        fi
    }

    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/app/controllers/src/alpha_worker.c"
    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/app/controllers/src/beta_private.h"
    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/lib/test/src/test_private.c"
    run_fixture >/dev/null

    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/config/src/wire.c"
    expect_fail "config private-header violation"
    rm -f -- "$tmp/config/src/wire.c"
    printf '%s\n' '#include <controllers/alpha_internal.h>' \
        > "$tmp/config/src/wire.c"
    expect_fail "angle-form private-header violation"
    rm -f -- "$tmp/config/src/wire.c"
    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/app/views/src/view.c"
    expect_fail "view private-header violation"
    rm -f -- "$tmp/app/views/src/view.c"
    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/app/controllers/include/controllers/public.h"
    expect_fail "public controller-header violation"
    rm -f -- "$tmp/app/controllers/include/controllers/public.h"

    printf '%s\n' '#include "controllers/alpha_internal.h"' \
        > "$tmp/config/src/wire.c"
    printf '%s\n' 'config/src/wire.c:#include "controllers/alpha_internal.h"' \
        > "$tmp/empty-baseline.txt"
    run_fixture >/dev/null
    rm -f -- "$tmp/config/src/wire.c"
    expect_fail "stale baseline row"
    : > "$tmp/empty-baseline.txt"

    rc=0
    env ZCL_CONTROLLER_PRIVATE_SCAN_ROOT="$tmp/missing" \
        ZCL_CONTROLLER_PRIVATE_HEADER_ROOT="$tmp/app/controllers/include/controllers" \
        ZCL_CONTROLLER_PRIVATE_BASELINE="$tmp/empty-baseline.txt" \
        "$self" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — missing root returned $rc, expected 2" >&2
        exit 2
    fi
    mkdir -p "$tmp/empty-root"
    rc=0
    env ZCL_CONTROLLER_PRIVATE_SCAN_ROOT="$tmp/empty-root" \
        ZCL_CONTROLLER_PRIVATE_HEADER_ROOT="$tmp/app/controllers/include/controllers" \
        ZCL_CONTROLLER_PRIVATE_BASELINE="$tmp/empty-baseline.txt" \
        "$self" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — empty root returned $rc, expected 2" >&2
        exit 2
    fi
    run_fixture >/dev/null
    echo "[$GATE] SELFTEST PASS (owner/private/test allowed; quoted/angle config, view, and public-header edges rejected; stale baseline and missing/empty roots fail closed)"
    exit 0
fi

if [ ! -d "$SCAN_ROOT" ]; then
    echo "[$GATE] UNPROVEN: scan root missing: $SCAN_ROOT" >&2
    exit 2
fi
mapfile -t scan_files < <(collect_files)
if [ "${#scan_files[@]}" -eq 0 ]; then
    echo "[$GATE] UNPROVEN: scan root has no C/H inputs: $SCAN_ROOT" >&2
    exit 2
fi
if [ -n "$HEADER_ROOT" ]; then
    if [ ! -d "$HEADER_ROOT" ]; then
        echo "[$GATE] UNPROVEN: controller header root missing: $HEADER_ROOT" >&2
        exit 2
    fi
    mapfile -t private_headers < <(find "$HEADER_ROOT" -maxdepth 1 -type f \
        \( -name '*_internal.h' -o -name '*_private.h' \) -print)
else
    mapfile -t private_headers < <(printf '%s\n' "${scan_files[@]}" | \
        grep -E '(^|/)controllers/include/controllers/[^/]+_(internal|private)\.h$' || true)
fi
if [ "${#private_headers[@]}" -eq 0 ]; then
    echo "[$GATE] UNPROVEN: no controller private headers in maintained source" >&2
    exit 2
fi
if [ ! -r "$BASELINE" ]; then
    echo "[$GATE] UNPROVEN: baseline missing: $BASELINE" >&2
    exit 2
fi

declare -A baseline=()
declare -A seen=()
baseline_count=0
while IFS= read -r row; do
    [[ -z "$row" || "$row" =~ ^[[:space:]]*# ]] && continue
    if [ -n "${baseline[$row]+x}" ]; then
        echo "[$GATE] UNPROVEN: duplicate baseline row: $row" >&2
        exit 2
    fi
    baseline["$row"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

mapfile -t measured < <(scan_external_edges | sort -u)
new_edges=()
for edge in "${measured[@]}"; do
    if [ -n "${baseline[$edge]+x}" ]; then
        seen["$edge"]=1
    else
        new_edges+=("$edge")
    fi
done
stale=()
for edge in "${!baseline[@]}"; do
    [ -n "${seen[$edge]+x}" ] || stale+=("$edge")
done

if [ "${#new_edges[@]}" -eq 0 ] && [ "${#stale[@]}" -eq 0 ]; then
    echo "[$GATE] PASS (${#measured[@]} exact external edge(s), all in shrink-only baseline)"
    exit 0
fi
if [ "${#new_edges[@]}" -gt 0 ]; then
    echo "[$GATE] FAIL: new controller-private dependency edge(s):" >&2
    printf '  %s\n' "${new_edges[@]}" >&2
fi
if [ "${#stale[@]}" -gt 0 ]; then
    echo "[$GATE] FAIL: stale baseline row(s); remove paid-down debt:" >&2
    printf '  %s\n' "${stale[@]}" >&2
fi
exit 1
