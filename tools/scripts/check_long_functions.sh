#!/usr/bin/env bash
# Lint gate #12 — long functions (god-function ratchet).
#
# Long functions are hard to reason about, hard to test, and a sign that a
# single C function is doing too many things. This gate flags any function
# whose body (signature line through its closing brace) spans more than
# LIMIT lines.
#
# Two tiers, same mechanics, different consequence (E1's file-size gate
# dropped its own tier split in 2026-08; this one keeps it):
#
#   ENFORCED (fails the build) — engine/controllers/src/*.c,
#   engine/services/src/*.c, and engine/composition/src/*.c (the composition root — same
#   tier engine/composition/src/*.c sits in for E1). RATCHET-mode: grandfathered
#   offenders (e.g. engine/composition/src/boot.c's app_init, a pre-existing
#   single-function boot sequence) are recorded in
#   tools/scripts/check_long_functions_baseline.txt at their current length
#   so the gate stays green on today's tree; new/grown functions fail.
#
#   WARN (prints, never fails) — lib/**/*.c, excluding tests/harness/include/test/ (fixtures
#   and test registrations, legitimately long and not a "god function"
#   signal). lib/ is primitives, not the app-shape surfaces this gate was
#   written to police, so a violation here is a heads-up, not a build
#   break. Baseline: tools/scripts/check_long_functions_lib_baseline.txt.
#
# Baseline format (both tiers): '<path> <function-name> <max-lines>' per
# line, lines starting with # are comments. A tier's gate flags when:
#   - a function NOT in that tier's baseline exceeds LIMIT lines, OR
#   - a baselined function grows ABOVE its recorded max-lines.
# Shrinking a baselined function below LIMIT lets you delete its baseline
# line; shrinking it while still over LIMIT earns an auto-suggestion to
# tighten (lower) the recorded number. The ENFORCED baseline is shrink-only
# — raising an existing entry needs an ADR, not this gate.
#
# Override (either tier): add `// long-function-ok:<tag>` to the function's
# signature line if a single state-machine truly belongs as one function.
# The tag must explain WHY. A tagged function is exempt entirely — no
# baseline entry needed, and it is invisible to the growth ratchet.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/repo_shape.sh
. tools/lint/repo_shape.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

LIMIT=500

# Scan roots are overridable via ZCL_LONGFN_ENFORCED_ROOTS /
# ZCL_LONGFN_LIB_ROOTS so the lint-gate self-test can point either tier at
# an empty dir and prove the non-empty-scan-set preflight trips (exit 2)
# instead of reporting "clean" off a hollow scan.
ENFORCED_ROOTS_DEFAULT="$(repo_shape_room_dirs controllers | sed 's@$@/src@' | tr '\n' ' ')$(repo_shape_room_dirs services | sed 's@$@/src@' | tr '\n' ' ')engine/composition/src"
LIB_ROOTS_DEFAULT="${ZCL_MODULE_DIRS[*]}"
ENFORCED_ROOTS="${ZCL_LONGFN_ENFORCED_ROOTS:-$ENFORCED_ROOTS_DEFAULT}"
LIB_ROOTS="${ZCL_LONGFN_LIB_ROOTS:-$LIB_ROOTS_DEFAULT}"

# ── --selftest: the coverage check, exercised on every `make lint` ──────────
# Three answers, not two. Each case re-invokes this gate for real with
# ZCL_LONGFN_COVERAGE_ONLY=1, so it stops the moment BOTH tiers' coverage
# verdicts are in and the umbrella never pays for a second full awk pass (the
# real, complete run follows immediately in the same `--selftest && <gate>`
# command).
if [ "${1:-}" = "--selftest" ]; then
    self="$PWD/tools/scripts/check_long_functions.sh"
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL env assignments
        local want="$1" msg="$2" rc=0
        shift 2
        env "$@" "$self" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "check_long_functions: SELFTEST FAILED — $msg (wanted exit $want, got $rc)" >&2
            exit 2
        fi
    }
    # (1) the full, real scan clears both tiers' expectations.
    cov_case 0 "the complete scan did not pass its coverage expectation" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_LONGFN_COVERAGE_ONLY=1
    # (2a) the ENFORCED tier missing a whole declared root is UNPROVEN exit 2 —
    #      never 0, never 1. The old floor of 1 could not see this: 742 of 743
    #      files could vanish and the floor still cleared.
    cov_case 2 "an ENFORCED scan missing a whole declared root was not UNPROVEN" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_LONGFN_COVERAGE_ONLY=1 \
        ZCL_LONGFN_ENFORCED_ROOTS="engine/controllers/src engine/services/src"
    # (2b) the WARN tier narrowed to one subtree of lib/ is UNPROVEN too. A
    #      WARN tier that never fails the build is exactly where a silently
    #      shrunk scan would go unnoticed forever.
    cov_case 2 "a WARN-tier scan narrowed below lib/ was not UNPROVEN" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_LONGFN_COVERAGE_ONLY=1 \
        ZCL_LONGFN_LIB_ROOTS="platform/modules/util"
    # (3) a shortfall SMALLER than the recorded allowance is a stale ratchet,
    #     exit 1 — an allowance that may only ever rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_LONGFN_COVERAGE_ONLY=1 \
        ZCL_LONGFN_COVERAGE_ALLOWANCE=1
    echo "[check_long_functions] SELFTEST PASS (a full scan passes coverage in" \
         "both tiers, an ENFORCED scan short one declared root and a WARN scan" \
         "narrowed below lib/ are each UNPROVEN exit 2, and an allowance above" \
         "the true shortfall is a stale-ratchet exit 1)"
    exit 0
fi

# Print every over-LIMIT, non-tagged function in $1 as "<name>\t<start>\t<len>".
scan_functions() {
    local f="$1"
    awk -v limit="$LIMIT" '
        function extract_name(s,    n, cand) {
            n = ""
            while (match(s, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
                cand = substr(s, RSTART, RLENGTH)
                sub(/[ \t]*\($/, "", cand)
                n = cand
                s = substr(s, RSTART + RLENGTH)
            }
            return n
        }
        /^[a-zA-Z_].*\(.*\)/ && !/;/ && !/^\s/ { sig=$0; start=NR; long_ok=0 }
        sig && /\/\/ *long-function-ok:[A-Za-z][A-Za-z0-9_-]*/ { long_ok=1 }
        /^\}[[:space:]]*(\/\/.*|\/\*.*)?$/ && start {
            len = NR - start
            if (len > limit && !long_ok) {
                name = extract_name(sig)
                if (name != "") printf "%s\t%d\t%d\n", name, start, len
            }
            start=0; sig=""; long_ok=0
        }
    ' "$f"
}

# Load a baseline file into the nameref'd associative array: "path::func" ->
# max-lines.
load_function_baseline() {
    local -n out="$1"
    local file="$2" line path fname loc
    out=()
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "$line" ] && continue
        read -r path fname loc <<<"$line"
        out["$path::$fname"]="$loc"
    done < "$file"
}

# Check one tier's scan set against its baseline. Populates the nameref'd
# `new_out` / `grown_out` / `shrink_out` arrays (all cleared first).
check_functions_tier() {
    local -n files="$1" base="$2" new_out="$3" grown_out="$4" shrink_out="$5"
    local limit="$6"
    local f fname start len key recorded
    new_out=()
    grown_out=()
    shrink_out=()
    for f in "${files[@]}"; do
        while IFS=$'\t' read -r fname start len; do
            [ -z "$fname" ] && continue
            key="$f::$fname"
            if [ -n "${base[$key]+x}" ]; then
                recorded="${base[$key]}"
                if [ "$len" -gt "$recorded" ]; then
                    grown_out+=("$f:$start  $fname() grew to $len lines (baseline $recorded)")
                elif [ "$len" -lt "$recorded" ] && [ "$len" -gt "$limit" ]; then
                    shrink_out+=("$f $fname is now $len lines (baseline $recorded, cap $limit) — tighten the baseline entry to $len")
                fi
                continue
            fi
            new_out+=("$f:$start  $fname() spans $len lines (cap $limit)")
        done < <(scan_functions "$f")
    done
}

overall_fail=0

# ── ENFORCED tier: controllers/services + engine/composition/src/ ────────────────────

ENFORCED_BASELINE="${ZCL_LONGFN_BASELINE:-tools/scripts/check_long_functions_baseline.txt}"
[ -f "$ENFORCED_BASELINE" ] || touch "$ENFORCED_BASELINE"
declare -A enforced_baseline=()
load_function_baseline enforced_baseline "$ENFORCED_BASELINE"
enforced_baseline_count="${#enforced_baseline[@]}"

# Fail-loud preflight: the scan set MUST be non-empty. A gate that silently
# iterates zero files (a renamed/moved controllers or engine/composition/src dir) would
# otherwise report "clean" while blind.
mapfile -t enforced_files < <(find $ENFORCED_ROOTS -maxdepth 1 -type f -name '*.c' \
    "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
gate_require_scanned "${#enforced_files[@]}" 1 check_long_functions \
    "roots: $ENFORCED_ROOTS — was engine/controllers/src, engine/services/src, or engine/composition/src renamed/moved?"

# ── Coverage: did each tier reach everything it claims to cover? ────────────
# The two floors answer "did the scan produce anything at all" — and both were
# set to 1, i.e. either tier reported clean off a single file. Measured
# 2026-08-30 the ENFORCED tier scans 743 .c files and the WARN tier 866, so the
# floors were 0.1% of each surface: a scan that silently lost 742 (or 865) of
# them still passed. This gate decides per FUNCTION inside a file, so a dropped
# file drops every long function in it while the file COUNT stays large — and
# the WARN tier never fails the build, so nobody would have noticed. These ask
# the right question: did each tier reach every file an INDEPENDENT oracle —
# the git index, which knows nothing about the finds above, so the two cannot
# fail together — says it should have?
#
# Derived from ENFORCED_ROOTS_DEFAULT / LIB_ROOTS_DEFAULT, never from the
# (overridable) roots actually in use, so pointing a tier at a subset reads as
# a shortfall rather than as a quiet redefinition of what "covered" means.
#
# Scope, unchanged. ENFORCED: each declared root is scanned NON-recursively
# (`-maxdepth 1`), so its pathspecs carry `:(glob)`, which stops `*` at a `/`,
# instead of git's default cross-directory `*`. WARN: all of lib/ recursively
# EXCEPT tests/harness/include/test/ (fixtures and test registrations are legitimately long and
# are excluded by the find, so the expectation excludes them too).
#
# Allowance 0 for both tiers, shrink-only: measured ENFORCED expected 743,
# scanned 743, missing 0; WARN expected 866, scanned 866, missing 0.
LONGFN_COVERAGE_ALLOWANCE="${ZCL_LONGFN_COVERAGE_ALLOWANCE:-0}"

# WARN-tier scan set, discovered here (next to the ENFORCED one) so BOTH
# coverage verdicts land before either tier's analysis runs — a partial scan is
# not something to report a WARN off.
mapfile -t lib_files < <(find $LIB_ROOTS -type f -name '*.c' -not -path 'tests/harness/include/test/*' \
    "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
gate_require_scanned "${#lib_files[@]}" 1 check_long_functions \
    "roots: $LIB_ROOTS (excl. tests/harness/include/test/) — was lib/ renamed/moved?"

if [ "${ZCL_LONGFN_COVERAGE:-1}" = "1" ]; then
    longfn_cov_specs=()
    longfn_lib_specs=()
    for longfn_cov_root in $ENFORCED_ROOTS_DEFAULT; do
        longfn_cov_specs+=(":(glob)$longfn_cov_root/*.c")
    done
    for longfn_cov_root in $LIB_ROOTS_DEFAULT; do
        longfn_lib_specs+=("$longfn_cov_root/*.c")
    done
    # Per-root non-emptiness. KNOWN LIMIT of any git-oracle coverage check over
    # hardcoded roots: the oracle is independent of the gate's FIND, not of its
    # ROOT LIST. A renamed root empties the find and the pathspec together, so
    # the shortfall cancels out and reads as clean. Ask git directly, root by
    # root, and refuse to grade if one has gone silent.
    for longfn_cov_root in $ENFORCED_ROOTS_DEFAULT $LIB_ROOTS_DEFAULT; do
        if [ -z "$(git ls-files --cached -- "$longfn_cov_root/*.c" 2>/dev/null || true)" ]; then
            echo "check_long_functions: UNPROVEN — declared scan root" >&2
            echo "  '$longfn_cov_root' tracks no *.c at all. A renamed/emptied" >&2
            echo "  root removes its surface from BOTH the find and the" >&2
            echo "  expectation, so the shortfall cancels and reads clean." >&2
            echo "  Refusing to grade. Fix ENFORCED_ROOTS_DEFAULT /" >&2
            echo "  LIB_ROOTS_DEFAULT, or drop the root if the code is gone." >&2
            exit 2
        fi
    done
    gate_require_git_coverage - "$LONGFN_COVERAGE_ALLOWANCE" check_long_functions \
        ZCL_LONGFN_COVERAGE_ALLOWANCE \
        "ENFORCED tier. Re-run from a clean checkout. If a listed file genuinely left this gate's scope, move it out of $ENFORCED_ROOTS_DEFAULT — raising ZCL_LONGFN_COVERAGE_ALLOWANCE is a last resort and needs the reason written down." \
        -- "${longfn_cov_specs[@]}" < <(printf '%s\n' "${enforced_files[@]}")
    gate_require_git_coverage - "$LONGFN_COVERAGE_ALLOWANCE" check_long_functions \
        ZCL_LONGFN_COVERAGE_ALLOWANCE \
        "WARN tier. Re-run from a clean checkout. If a listed file genuinely left this gate's scope, move it out of $LIB_ROOTS_DEFAULT — raising ZCL_LONGFN_COVERAGE_ALLOWANCE is a last resort and needs the reason written down." \
        -- "${longfn_lib_specs[@]}" \
        < <(printf '%s\n' "${lib_files[@]}")
fi
if [ "${ZCL_LONGFN_COVERAGE_ONLY:-0}" = "1" ]; then
    echo "check_long_functions: coverage-only PASS (${#enforced_files[@]} ENFORCED" \
         "+ ${#lib_files[@]} WARN files reached)"
    exit 0
fi

check_functions_tier enforced_files enforced_baseline \
    enforced_new enforced_grown enforced_shrink "$LIMIT"

if [ "${#enforced_new[@]}" -gt 0 ] || [ "${#enforced_grown[@]}" -gt 0 ]; then
    overall_fail=1
    echo ""
    echo "check_long_functions: FAIL — long-function violations (gate #12, ratchet, controllers/services/config-src)"
    echo ""
    for v in "${enforced_new[@]}"; do
        echo "  NEW long function (not in baseline): $v"
    done
    for v in "${enforced_grown[@]}"; do
        echo "  REGRESSION (grew past its baselined length): $v"
    done
    echo ""
    echo "Fix options (preferred -> fallback):"
    echo "  1. Split the function along its seams (named helpers per phase/case)"
    echo "     so it stays under $LIMIT lines."
    echo "  2. For a baselined function that grew, shrink it back at or below its"
    echo "     recorded baseline length in $ENFORCED_BASELINE."
    echo "  3. Tag the signature line '// long-function-ok:<tag>' if it is truly"
    echo "     one state machine, explaining why in the tag."
    echo "  4. As last resort, record a NEW function in $ENFORCED_BASELINE at its"
    echo "     current length (a reviewable line; shrink-only over time —"
    echo "     raising an existing entry needs an ADR, not this gate)."
else
    echo "check_long_functions: clean — ${enforced_baseline_count} baselined, no new/grown long functions (cap $LIMIT, controllers/services/config-src)"
fi
if [ "${#enforced_shrink[@]}" -gt 0 ]; then
    echo ""
    echo "  Baseline can tighten (functions shrank but are still over cap):"
    for s in "${enforced_shrink[@]}"; do
        echo "    $s"
    done
fi

# ── WARN tier: lib/ (excluding tests/harness/include/test/) ─────────────────────────────────

LIB_BASELINE="${ZCL_LONGFN_LIB_BASELINE:-tools/scripts/check_long_functions_lib_baseline.txt}"
[ -f "$LIB_BASELINE" ] || touch "$LIB_BASELINE"
declare -A lib_baseline=()
load_function_baseline lib_baseline "$LIB_BASELINE"
lib_baseline_count="${#lib_baseline[@]}"

check_functions_tier lib_files lib_baseline lib_new lib_grown lib_shrink "$LIMIT"

if [ "${#lib_new[@]}" -gt 0 ] || [ "${#lib_grown[@]}" -gt 0 ]; then
    echo ""
    echo "check_long_functions: WARN — long-function watch (gate #12, lib/, non-blocking)"
    echo ""
    for v in "${lib_new[@]}"; do
        echo "  NEW long function (not in $LIB_BASELINE): $v"
    done
    for v in "${lib_grown[@]}"; do
        echo "  grew past its baselined length in $LIB_BASELINE: $v"
    done
    echo ""
    echo "  This tier is WARN-only — it does not fail the build. Consider"
    echo "  splitting the function, tagging it '// long-function-ok:<tag>', or"
    echo "  if it's baselined intentionally, add/adjust its line in $LIB_BASELINE."
else
    echo "check_long_functions: clean — ${lib_baseline_count} baselined, no new/grown long functions (cap $LIMIT, lib/, WARN tier)"
fi
if [ "${#lib_shrink[@]}" -gt 0 ]; then
    echo ""
    echo "  lib/ baseline can tighten (functions shrank but are still over cap):"
    for s in "${lib_shrink[@]}"; do
        echo "    $s"
    done
fi

exit "$overall_fail"
