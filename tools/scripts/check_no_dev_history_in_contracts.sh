#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no dev-history phrasing in production contract files.
#
# A header under any **/include/** dir, or a command .def table, IS the
# contract an operator or an LLM agent reads to learn what a module
# currently does. A stale "STEP-0 STATUS: contract + stub bodies; lane 2A
# lands the real thing" comment left behind after the real body landed is
# INCORRECT MODEL CONTEXT, not a style nit — an agent (or a human) reading
# the header trusts it over the .c body and reasonably concludes the
# feature is still unimplemented, re-proposing already-shipped work or
# distrusting a real, working call site. This gate rejects a narrow,
# high-signal set of dev-history phrases from those two production-contract
# surfaces so the pattern cannot creep back in once cleaned up.
#
# Scope: every tracked-shape *.h file under any **/include/** directory,
# and every *.def table, anywhere in the tree. Allowlisted OUT: docs/
# (narrative is its whole point), vendor/ (third-party), and anything under
# a "test"/"tests" path component or named *_test.* (fixtures/tests narrate
# lane history and stub scaffolding on purpose).
#
# Phrase set is deliberately NARROW (high-signal only): generic phrases
# like "in flight" / "not done" false-positive on legitimate present-tense
# state descriptions elsewhere in the tree and are intentionally NOT
# included.
#
# Hollow-gate guard: gate_require_scanned aborts (exit 2) if the scan set
# is empty (a renamed/moved include/ dir or emptied .def population would
# otherwise silently report "clean" while blind).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

GATE_NAME=check-no-dev-history-in-contracts

# ── Allowlist predicate ──────────────────────────────────────────────────
is_allowlisted_path() {
    local p="$1" part base
    case "$p" in
        docs/*|*/docs/*) return 0 ;;
        vendor/*|*/vendor/*) return 0 ;;
    esac
    IFS='/' read -ra _nda_parts <<< "$p"
    for part in "${_nda_parts[@]}"; do
        if [[ "$part" == "test" || "$part" == "tests" ]]; then
            return 0
        fi
    done
    base="${p##*/}"   # not `basename`: 1500+ forks per run, same result
    [[ "$base" == *_test.* ]] && return 0
    return 1
}

# The scan root is overridable via ZCL_NDH_SCAN_ROOT so --selftest can point
# the gate at a SUBSET of the tree and prove the coverage check below sees the
# shortfall. Production scans the whole checkout.
NDH_SCAN_ROOT="${ZCL_NDH_SCAN_ROOT:-.}"

# ── --selftest: the coverage check, exercised on every `make lint` ──────────
# Three answers, not two. Each case re-invokes this gate for real with
# ZCL_NDH_COVERAGE_ONLY=1, so it stops the moment the coverage verdict is in
# and the umbrella never pays for a second full phrase-grep pass over 1500
# files (the real, complete run follows immediately in the same
# `--selftest && <gate>` command).
if [ "${1:-}" = "--selftest" ]; then
    self="$PWD/tools/scripts/check_no_dev_history_in_contracts.sh"
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL env assignments
        local want="$1" msg="$2" rc=0
        shift 2
        env "$@" "$self" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "$GATE_NAME: SELFTEST FAILED — $msg (wanted exit $want, got $rc)" >&2
            exit 2
        fi
    }
    # (1) the full, real scan clears its own expectation.
    cov_case 0 "the complete scan did not pass its coverage expectation" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_NDH_COVERAGE_ONLY=1
    # (2) a scan narrowed to one subtree is UNPROVEN exit 2 — never 0, never 1.
    #     The old floor of 1 could not see this: 1513 of 1514 in-scope contract
    #     files could vanish from the scan and the floor still cleared.
    cov_case 2 "a scan narrowed to one subtree was not UNPROVEN" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_NDH_COVERAGE_ONLY=1 \
        ZCL_NDH_SCAN_ROOT=lib
    # (3) a shortfall SMALLER than the recorded allowance is a stale ratchet,
    #     exit 1 — an allowance that may only ever rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_NDH_COVERAGE_ONLY=1 \
        ZCL_NDH_COVERAGE_ALLOWANCE=1
    echo "[$GATE_NAME] SELFTEST PASS (a full scan passes coverage, a scan" \
         "narrowed to one subtree is UNPROVEN exit 2, and an allowance above" \
         "the true shortfall is a stale-ratchet exit 1)"
    exit 0
fi

# Directory prune, production scans only. `-not -path '*/build/*'` FILTERS a
# path only AFTER find has already walked into it; on this checkout that walk
# costs ~11 s (90 agent worktrees under .claude/, plus build/ and vendor/),
# and it was the whole reason this gate was the slowest in the umbrella.
# Pruning exactly the directories the exclusion set already discards is
# byte-for-byte equivalent — a file under them was never in the scan set —
# and takes the two walks from ~11.5 s to ~0.17 s (verified: both listings
# identical, 1435 *.h + 110 *.def). Empty when ZCL_LINT_PRODUCTION_SCAN is
# unset, exactly like LINT_FIND_PRUNE_ARGS itself, so a selftest that execs
# this script directly still sees the unfiltered tree.
NDH_PRUNE_ARGS=()
if [[ "${ZCL_LINT_PRODUCTION_SCAN:-0}" == "1" ]]; then
    NDH_PRUNE_ARGS=( '(' -path '*/build' -o -path '*/vendor' -o -path '*/.claude' \
                     -o -path '*/test-tmp' -o -path "*/$LINT_PLANTED_DIR" ')' -prune -o )
fi
# ── Scan set ──────────────────────────────────────────────────────────────
mapfile -t h_candidates < <(find "$NDH_SCAN_ROOT" "${NDH_PRUNE_ARGS[@]}" \
    -type f -name '*.h' -path '*/include/*' \
    "${LINT_FIND_PRUNE_ARGS[@]}" -print 2>/dev/null | sed 's|^\./||' | sort)
mapfile -t def_candidates < <(find "$NDH_SCAN_ROOT" "${NDH_PRUNE_ARGS[@]}" \
    -type f -name '*.def' \
    "${LINT_FIND_PRUNE_ARGS[@]}" -print 2>/dev/null | sed 's|^\./||' | sort)

files=()
for f in "${h_candidates[@]}" "${def_candidates[@]}"; do
    is_allowlisted_path "$f" && continue
    files+=("$f")
done

gate_require_scanned "${#files[@]}" 1 "$GATE_NAME" \
    "no in-scope *.h (**/include/**) or *.def file found -- was a dir renamed/moved?"

# ── Coverage: did the scan reach everything it claims to cover? ─────────────
# The floor above answers "did the scan produce anything at all" — and it was
# set to 1, i.e. this gate reported clean off a single file. Measured
# 2026-08-30 the realized scan is 1514 in-scope files, so the floor was 0.07%
# of the surface: a scan that silently lost 1513 of 1514 contract files still
# passed. This gate greps each file for a fixed phrase set, so a dropped file
# drops its whole verdict while the file COUNT stays large. This asks the right
# question: did the scan reach every file an INDEPENDENT oracle — the git
# index, which knows nothing about the two finds above, so the two cannot fail
# together — says it should have?
#
# The oracle is NOT root-anchored (unlike the *.c gates): it asks git for every
# tracked *.h under an include/ dir and every tracked *.def, ANYWHERE. So a
# renamed subtree does not cancel out of both sides — the files simply move and
# the find must still reach them.
#
# Scope, unchanged: the expectation is passed through the SAME
# is_allowlisted_path predicate the scan uses, so docs/, vendor/, any
# test/tests path component and any *_test.* basename are out of both. A
# coverage check that fired on files this gate deliberately never reads would
# only teach people to ignore it. Untracked files (build debris, a planted
# fixture) are EXTRA in the scan and never missing from it, so they cannot
# manufacture a pass.
#
# Allowance 0, shrink-only: measured expected 1510 tracked in-scope files,
# scanned 1514 (the 4 extra are untracked build-work debris), missing 0.
NDH_COVERAGE_ALLOWANCE="${ZCL_NDH_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_NDH_COVERAGE:-1}" = "1" ]; then
    ndh_cov_dir="$(mktemp -d "${TMPDIR:-/tmp}/zcl-ndh-cov.XXXXXX")" || {
        echo "$GATE_NAME: FATAL — mktemp failed for the coverage check." >&2
        exit 2; }
    trap 'rm -rf "$ndh_cov_dir"' EXIT
    gate_git_oracle "$ndh_cov_dir/tracked.txt" "$GATE_NAME" \
        '*/include/*.h' 'include/*.h' '*.def'
    : > "$ndh_cov_dir/expected.txt"
    while IFS= read -r ndh_cov_path; do
        is_allowlisted_path "$ndh_cov_path" && continue
        printf '%s\n' "$ndh_cov_path" >> "$ndh_cov_dir/expected.txt"
    done < "$ndh_cov_dir/tracked.txt"
    gate_require_coverage - "$ndh_cov_dir/expected.txt" "$NDH_COVERAGE_ALLOWANCE" \
        "$GATE_NAME" ZCL_NDH_COVERAGE_ALLOWANCE \
        "Re-run from a clean checkout. If a listed file genuinely left this gate's scope, move it under an allowlisted path (docs/, vendor/, a test/tests component, a *_test.* name) — raising ZCL_NDH_COVERAGE_ALLOWANCE is a last resort and needs the reason written down." \
        < <(printf '%s\n' "${files[@]}")
    rm -rf "$ndh_cov_dir"
    trap - EXIT
fi
if [ "${ZCL_NDH_COVERAGE_ONLY:-0}" = "1" ]; then
    echo "$GATE_NAME: coverage-only PASS (${#files[@]} in-scope file(s) reached)"
    exit 0
fi

# ── Phrase set (high-signal only). Each entry is "grep-flag|pattern". ────
PHRASES=(
    '-F|STEP-0 STATUS'
    '-F|stub bodies'
    '-F|stub body'
    '-E|lane [0-9][A-Z]?'
    '-F|future slice'
)

# One grep invocation PER PHRASE over the whole file list, instead of one
# grep per (file, phrase) pair (was 1,514 files x 5 phrases = ~7,570 forks).
# Multi-file grep -n already prefixes each hit with "<path>:<lnum>:<text>",
# byte-identical to the "$f:$hitline" this loop used to build by hand, so
# each batched hit line is used as-is. Results are bucketed by (phrase
# index, file) with no extra forks (associative-array/bash-builtin lookups
# only), then replayed in the ORIGINAL file-major, phrase-minor, line order
# so violation text and order are unchanged.
exist_files=()
for f in "${files[@]}"; do
    [[ -f "$f" ]] && exist_files+=("$f")
done

declare -A HITS=()
if [ "${#exist_files[@]}" -gt 0 ]; then
    p=0
    for spec in "${PHRASES[@]}"; do
        flag="${spec%%|*}"
        pattern="${spec#*|}"
        out=$(gate_grep -n -I "$flag" "$pattern" "${exist_files[@]}") && {
            while IFS= read -r line; do
                [ -n "$line" ] || continue
                hf="${line%%:*}"
                HITS["$p|$hf"]+="$line"$'\n'
            done <<< "$out"
        }
        p=$((p + 1))
    done
fi

violations=()
for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    p=0
    for spec in "${PHRASES[@]}"; do
        pattern="${spec#*|}"
        entry="${HITS["$p|$f"]-}"
        if [ -n "$entry" ]; then
            while IFS= read -r hitline; do
                [ -n "$hitline" ] && violations+=("$hitline  [/$pattern/]")
            done <<< "$entry"
        fi
        p=$((p + 1))
    done
done

if [ "${#violations[@]}" -gt 0 ]; then
    echo "$GATE_NAME: FAIL — dev-history phrasing in ${#violations[@]} production contract line(s)"
    echo ""
    for v in "${violations[@]}"; do
        echo "  $v"
    done
    echo ""
    echo "Dev-history phrasing (\"STEP-0 STATUS\", \"stub bod(y|ies)\", \"lane <N><letter>\","
    echo "\"future slice\") is INCORRECT MODEL CONTEXT once the real work has landed —"
    echo "an agent or operator reading the header trusts it over the .c body. Rewrite"
    echo "the comment to describe the CURRENT contract plus any remaining invariant,"
    echo "without lane numbers / STEP-N status / 'future slice' phrasing. Dated"
    echo "narrative belongs in git history or docs/work/*, never in a production"
    echo "header or .def table."
    exit 1
fi

echo "$GATE_NAME: clean — ${#files[@]} in-scope file(s) (*.h under **/include/**, *.def), no dev-history phrasing"
exit 0
