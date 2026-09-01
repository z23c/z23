#!/usr/bin/env bash
# Lint gate — service-shape SHRINKING-FLOOR ratchet for legacy bool exports
# (Phase 3 of the framework refactor; sibling to E2 check_one_result_type.sh).
#
# E2 (check_one_result_type.sh) ratchets at FILE granularity: a file is
# "clean" the moment it references `struct zcl_result` ANYWHERE, even if it
# still exports other bare-bool top-level functions alongside that one
# converted surface. That lets a file sit "mixed" forever — E2 goes green
# and nothing forces the rest of the file to converge. This gate closes
# that gap by counting the exported (non-static, top-level) bool-returning
# function DEFINITIONS in each engine/services/src/*.c file and ratcheting
# that count down to zero, file by file:
#
#   - A pre-existing legacy file is recorded in the baseline as
#     '<path> <count>' (count = its legacy bool-export count when
#     baselined).
#   - The gate FAILS when:
#       1. a baselined file's live count is GREATER than its recorded
#          count (regression — new legacy exports added), OR
#       2. a baselined file's live count is 0, OR the file now carries a
#          `// one-result-type-ok:<tag>` marker (deliberately exempt) —
#          either way it is CLEAN and must be deleted from the baseline
#          (this is the "shrinking floor": a clean file may not stay
#          listed), OR
#       3. a baselined file no longer exists on disk (stale path —
#          renamed/deleted without updating the baseline), OR
#       4. a NEW (non-baselined, non-marker) engine/services/src/*.c file has
#          ANY legacy bool export (a regression: new service code must be
#          written with struct zcl_result from the start).
#     Shrinking a baselined count while it stays > 0 is fine and earns an
#     advisory suggestion to tighten the baseline entry (not a failure).
#
# Marker (reused EXACTLY as E2 defines it — see check_one_result_type.sh):
# a file carrying a top-of-file `// one-result-type-ok:<tag>` comment owns
# no fallible service surface worth converting (pure classifiers,
# recovery-primitive int/bool contracts, etc). Such a file is fully exempt
# from this gate: its legacy bool exports (however many) are never counted
# as a violation and it must NOT appear in the baseline.
#
# "Legacy bool export" = a function DEFINITION (not a forward declaration)
# whose signature starts in column 0 with `bool <name>(` (i.e. non-static,
# non-inline, top-level — a real exported symbol) in an engine/services/src/
# .c file, whether the opening brace sits alone on its own line (this
# project's usual style) or shares the (possibly wrapped) signature's last
# line, e.g. `bool foo(void) {`. A same-signature forward declaration (ends
# in `;` before the body) is not counted.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

BASELINE="${ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE:-tools/scripts/service_result_convergence_baseline.txt}"
[ -f "$BASELINE" ] || touch "$BASELINE"
# Scan-dir override (test-only): lets the self-test point the gate at an
# isolated test-tmp/ fixture directory instead of the real engine/services/src
# tree, so a self-test can prove grown/new/stale behavior without ever
# touching the real baseline or the real service files. Mirrors
# ZCL_COINS_LOOKUP_SCAN_DIR in check_coins_lookup_nullcheck.sh.
SCAN_DIR="${ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR:-engine/services/src}"

# Count exported (non-static, top-level) bool-returning function
# DEFINITIONS in a file. A signature is a definition when its header
# (possibly wrapped across lines for multi-arg functions) is followed by a
# line that ENDS with `{` (after trimming trailing whitespace) with no `;`
# seen first (a `;` first means it was a forward declaration, not a body).
# This counts both the project's usual "brace alone on its own line" style
# AND a brace sharing the (possibly wrapped) signature's last line, e.g.
# `bool foo(void) {` or a multi-arg wrap whose final line ends `) {`.
count_legacy_bool_exports() {
    awk '
    BEGIN { in_sig = 0; count = 0 }
    {
        line = $0
        if (!in_sig) {
            # *_dump_state_json(struct json_value*, const char*) is the
            # documented bool CONTRACT for native dumpstate introspection
            # (CLAUDE.md "Adding state introspection") — never a legacy
            # export; adding a dumper must not force a file marker.
            if (line ~ /^bool[ \t]+[A-Za-z_][A-Za-z0-9_]*_dump_state_json\(/) {
                next
            }
            if (line ~ /^bool[ \t]+[A-Za-z_][A-Za-z0-9_]*\(/) {
                in_sig = 1
            } else {
                next
            }
        }
        if (index(line, ";") > 0) {
            in_sig = 0
            next
        }
        trimmed = line
        gsub(/^[ \t]+/, "", trimmed)
        gsub(/[ \t]+$/, "", trimmed)
        if (trimmed ~ /\{$/) {
            count++
            in_sig = 0
        }
    }
    END { print count + 0 }
    ' "$1"
}

has_override_marker() {
    grep -qE '//[[:space:]]*one-result-type-ok:[A-Za-z][A-Za-z0-9_-]*' "$1"
}

# Load baseline into an associative array: path -> recorded legacy count.
declare -A baseline
gate_load_kv_file "$BASELINE" baseline
baseline_count="${#baseline[@]}"

# Fail-loud preflight: the scan set MUST be non-empty.
mapfile -t scan_files < <(find "$SCAN_DIR" -type f -name '*.c' 2>/dev/null | sort)
gate_require_scanned "${#scan_files[@]}" 1 check_service_result_convergence \
    "no *.c under $SCAN_DIR — was the services shape dir renamed/moved?"

fail=0
grown_violations=()
new_violations=()
stale_clean=()
stale_marked=()
shrink_suggestions=()

declare -A seen
for f in "${scan_files[@]}"; do
    seen["$f"]=1
    live=$(count_legacy_bool_exports "$f")
    marked=0
    has_override_marker "$f" && marked=1

    if [ -n "${baseline[$f]+x}" ]; then
        recorded="${baseline[$f]}"
        if [ "$marked" = "1" ]; then
            stale_marked+=("$f now carries a one-result-type-ok marker (baseline said $recorded) — delete its baseline line")
            fail=1
            continue
        fi
        if [ "$live" -gt "$recorded" ]; then
            grown_violations+=("$f grew to $live legacy bool export(s) (baseline $recorded)")
            fail=1
        elif [ "$live" -eq 0 ]; then
            stale_clean+=("$f is now fully converted (0 legacy bool exports) — delete its baseline line")
            fail=1
        elif [ "$live" -lt "$recorded" ]; then
            shrink_suggestions+=("$f is now $live legacy bool export(s) (baseline $recorded) — tighten the baseline entry to $live")
        fi
        continue
    fi

    # Not baselined.
    if [ "$marked" = "1" ]; then
        continue
    fi
    if [ "$live" -gt 0 ]; then
        new_violations+=("$f has $live legacy bool export(s) (not in baseline, no marker)")
        fail=1
    fi
done

# Baseline entries for files that no longer exist on disk.
missing_paths=()
for path in "${!baseline[@]}"; do
    if [ -z "${seen[$path]+x}" ]; then
        missing_paths+=("$path")
        fail=1
    fi
done

if [ "$fail" != "0" ]; then
    echo ""
    echo "check_service_result_convergence: FAIL — shrinking-floor violations"
    echo ""
    for v in "${new_violations[@]}"; do
        echo "  NEW file with legacy bool exports (not in baseline): $v"
    done
    for v in "${grown_violations[@]}"; do
        echo "  REGRESSION (legacy exports grew past baseline): $v"
    done
    for v in "${stale_clean[@]}"; do
        echo "  STALE baseline entry (file is clean): $v"
    done
    for v in "${stale_marked[@]}"; do
        echo "  STALE baseline entry (file is now marker-exempt): $v"
    done
    if [ "${#missing_paths[@]}" -gt 0 ]; then
        printf '%s\n' "${missing_paths[@]}" | sort | while IFS= read -r p; do
            echo "  STALE baseline entry (file no longer exists): $p"
        done
    fi
    echo ""
    echo "Fix options:"
    echo "  1. Migrate the file's legacy bool-returning top-level functions to"
    echo "     struct zcl_result (ZCL_OK / ZCL_ERR)."
    echo "  2. If the file genuinely owns no fallible service surface, add a"
    echo "     top-of-file marker '// one-result-type-ok:<tag>' (same marker"
    echo "     E2 uses) — then remove any stale baseline line for it."
    echo "  3. A newly-baselined file's count may only be recorded at its"
    echo "     CURRENT count (a reviewable line); raising an existing"
    echo "     baseline entry needs an ADR, not this gate."
    echo "  4. Remove stale baseline lines for files that are now clean,"
    echo "     marker-exempt, or deleted — $BASELINE must only shrink."
    exit 1
fi

echo "check_service_result_convergence: clean — ${baseline_count} baselined legacy service file(s), no new/grown/stale entries"
if [ "${#shrink_suggestions[@]}" -gt 0 ]; then
    echo ""
    echo "  Baseline can tighten (files shrank but still have legacy exports):"
    for s in "${shrink_suggestions[@]}"; do
        echo "    $s"
    done
fi
exit 0
