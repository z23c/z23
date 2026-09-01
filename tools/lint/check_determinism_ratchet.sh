#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_determinism_ratchet.sh — the NONDETERMINISTIC set may only shrink.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# A receipt saying "I ran this group at this commit and it passed" is worth
# nothing if re-running the same thing gives a different answer. So the set of
# groups known NOT to reproduce is a debt, and it is written down in
# tools/lint/determinism_baseline.txt. Debt may be paid off. It may not grow.
#
# ── WHAT THIS GATE DOES AND DOES NOT DO ─────────────────────────────────────
# It does NOT re-measure. Measuring is `make determinism-scan` driving
# build/bin/test_parallel once per perturbation — hours of wall clock, one full
# suite run per perturbation. Putting that in `make lint` would mean nobody
# ever runs `make lint`. This gate guards the RECORD of that measurement, which
# is cheap and is where the ratchet actually lives:
#
#   A. SHRINK-ONLY. Every group in the working-tree baseline must already be in
#      the baseline as of HEAD. A new entry fails. There is no flag, no
#      allowlist and no environment variable that admits one: adding a group
#      here means a test stopped reproducing, and the fix is the test.
#   B. EVERY ENTRY NAMES ITS CAUSE. "It varies" is not a finding. Each line is
#      "<group> <PERTURBATION>[+<PERTURBATION>...]", and each perturbation must
#      be one build/bin/determinism_scan actually applies. A line with no cause
#      is rejected.
#   C. EVERY ENTRY NAMES A REAL GROUP. A baseline row for a group that no
#      longer exists is stale debt that makes the number look worse than the
#      tree is, and it hides a rename.
#   D. THE DECLARED COUNT MATCHES. The header carries "# count: N". A row added
#      without touching the header, or a header edited without the rows, is
#      rejected — so the number in a report cannot drift from the file.
#   E. A MISSING OR UNREADABLE BASELINE FAILS CLOSED. A gate that cannot see
#      its input must never report clean.
#
# ── SOURCES OF TRUTH (never re-derived by hand) ─────────────────────────────
#   groups        : tools/dev/test_group_catalog.def, the one canonical
#                   registry. The rows are ZCL_TEST_GROUP(x)/ZCL_SPEC_GROUP(x)
#                   and the full id is test_x / spec_x.
#   perturbations : build/bin/determinism_scan list-profiles when it is built;
#                   otherwise the enum in
#                   engine/modules/determinism/include/determinism/perturbation.h. Never a
#                   third hand-kept list.
#
# Usage:
#   tools/lint/check_determinism_ratchet.sh            # the gate
#   tools/lint/check_determinism_ratchet.sh --selftest # prove it can FAIL
# Env:
#   ZCL_DETERMINISM_ROOT  repo root to inspect (default: this script's repo).
#                         The selftest points it at a mktemp git fixture.
#
# Exit: 0 clean, 1 on any violation, 2 on misuse.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"

BASELINE_REL="tools/lint/determinism_baseline.txt"
CATALOG_REL="tools/dev/test_group_catalog.def"
PERTURBATION_HEADER_REL="engine/modules/determinism/include/determinism/perturbation.h"

# ── the registry, from the catalog ──────────────────────────────────────────
registered_groups() {
    local root="$1"
    sed -n \
        -e 's/^ZCL_TEST_GROUP(\([A-Za-z0-9_]*\)).*/test_\1/p' \
        -e 's/^ZCL_SPEC_GROUP(\([A-Za-z0-9_]*\)).*/spec_\1/p' \
        "$root/$CATALOG_REL" 2>/dev/null | sort -u
}

# ── the perturbation vocabulary ─────────────────────────────────────────────
# Prefer the built tool (it IS the applier). Fall back to the enum in the
# header, which the tool is generated from, so the two cannot diverge without
# the build breaking first.
known_perturbations() {
    local root="$1"
    if [ -x "$root/build/bin/determinism_scan" ]; then
        "$root/build/bin/determinism_scan" list-profiles 2>/dev/null \
            | awk '{print $1}' | grep -E '^[A-Z_]+$' | sort -u
        return
    fi
    sed -n 's/^[[:space:]]*ZCL_DET_P_\([A-Z_]*\),\?[[:space:]]*$/\1/p' \
        "$root/$PERTURBATION_HEADER_REL" 2>/dev/null \
        | grep -v '^_COUNT$' | sort -u
}

# ── the check ───────────────────────────────────────────────────────────────
check_root() {
    local root="$1"
    local baseline="$root/$BASELINE_REL"
    local fail=0

    if [ ! -f "$baseline" ] || [ ! -r "$baseline" ]; then
        echo "FAIL: no readable determinism baseline at $baseline"
        echo "  A ratchet with no record is not a ratchet. Produce one with"
        echo "  'make determinism-scan' and commit it."
        return 1
    fi

    local groups perturbations
    groups="$(registered_groups "$root")"
    if [ -z "${groups//[[:space:]]/}" ]; then
        echo "FAIL: no registered groups found in $root/$CATALOG_REL"
        echo "  This gate cannot validate a baseline against a registry it"
        echo "  cannot read. Fail closed rather than pass vacuously."
        return 1
    fi
    perturbations="$(known_perturbations "$root")"
    if [ -z "${perturbations//[[:space:]]/}" ]; then
        echo "FAIL: no perturbation names found (neither the built"
        echo "      determinism_scan nor $PERTURBATION_HEADER_REL)."
        return 1
    fi

    # ── D. the declared count ───────────────────────────────────────────────
    local declared rows
    declared="$(sed -n 's/^# count:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
                    "$baseline" | head -1)"
    rows="$(grep -cE '^[a-z]' "$baseline")"
    if [ -z "$declared" ]; then
        fail=1
        echo "FAIL: $BASELINE_REL has no '# count: N' header line."
        echo "  The header is what stops the number in a report from drifting"
        echo "  away from the rows in the file. Add it."
    elif [ "$declared" != "$rows" ]; then
        fail=1
        echo "FAIL: $BASELINE_REL declares '# count: $declared' but has $rows row(s)."
        echo "  Update the header in the same commit as the rows."
    fi

    # ── B and C, row by row ─────────────────────────────────────────────────
    # Row format: <group> <CLASS> <CAUSE>[+<CAUSE>...]
    #
    # The CLASS column exists because two very different defects were being
    # recorded as one number. A group that answers differently on a re-run at
    # identical load has genuine internal nondeterminism. A group that answers
    # differently only when the machine is busier is grading a real assertion
    # against a wall clock. Both make a receipt worthless, but only the first
    # is a bug in the test's logic, so they must not share a bucket.
    #
    # NOTE ON grep BELOW: these are here-strings, not `printf ... | grep -q`
    # pipelines. Under `set -o pipefail` a `grep -q` MATCH closes the pipe
    # early, printf takes SIGPIPE, and the pipeline's status becomes 141 —
    # so the success case reports failure and the check silently inverts.
    # This gate shipped with that bug and announced it by rejecting CC_SET on
    # exactly one of the three rows naming it. A gate that polices determinism
    # must not itself be non-deterministic.
    local line group rest class cause tok
    local bad_group="" no_cause="" bad_pert="" bad_class=""
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        group="${line%% *}"
        rest="${line#* }"
        if [ "$rest" = "$line" ] || [ -z "${rest//[[:space:]]/}" ]; then
            no_cause="$no_cause$group"$'\n'
            continue
        fi
        class="${rest%% *}"
        cause="${rest#* }"
        if [ "$cause" = "$rest" ] || [ -z "${cause//[[:space:]]/}" ]; then
            no_cause="$no_cause$group"$'\n'
            continue
        fi
        if ! grep -qxF -- "$group" <<<"$groups"; then
            bad_group="$bad_group$group"$'\n'
        fi
        case "$class" in
            NONDETERMINISTIC|TIMING_SENSITIVE) ;;
            *) bad_class="$bad_class$group -> $class"$'\n' ;;
        esac
        local IFS_SAVE="$IFS"
        IFS='+'
        for tok in $cause; do
            [ -n "$tok" ] || continue
            if ! grep -qxF -- "$tok" <<<"$perturbations"; then
                bad_pert="$bad_pert$group -> $tok"$'\n'
            fi
        done
        IFS="$IFS_SAVE"
    done < "$baseline"

    if [ -n "${bad_class//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: $BASELINE_REL names a class that is not a recorded verdict:"
        printf '%s' "$bad_class" | sed 's/^/    /'
        echo "  The second column must be NONDETERMINISTIC or TIMING_SENSITIVE."
        echo "  A row exists to say WHICH kind of unreproducibility was measured;"
        echo "  a class the classifier never emits means the row was hand-written."
    fi

    if [ -n "${no_cause//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: baseline row(s) that name no splitting perturbation:"
        printf '%s' "$no_cause" | sed 's/^/    /'
        echo ""
        echo "  \"It varies\" is not a finding; \"it varies when CC is set\" is."
        echo "  Each row is '<group> <CLASS> <PERTURBATION>[+<PERTURBATION>...]'."
    fi
    if [ -n "${bad_group//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: baseline row(s) naming a group that is not registered:"
        printf '%s' "$bad_group" | sed 's/^/    /'
        echo ""
        echo "  Stale debt makes the tree look worse than it is and hides a"
        echo "  rename. Delete the row, or fix the name."
    fi
    if [ -n "${bad_pert//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: baseline row(s) naming an unknown perturbation:"
        printf '%s' "$bad_pert" | sed 's/^/    /'
        echo ""
        echo "  Valid names come from 'determinism_scan list-profiles'."
    fi

    # ── A. shrink-only against the integration point ────────────────────────
    # git is the only witness of what we owed before this change. Compare
    # against the merge-base with origin/main when there is one — comparing
    # only against HEAD would let a growth pass the moment it was committed,
    # which is exactly when a push gate runs. Fall back to HEAD where no
    # origin/main exists (a fresh clone, or the selftest fixture). A baseline
    # with no ancestor at all is the first commit of the record and is
    # accepted; every later commit may only remove rows.
    local head_rows="" have_ancestor=0 anchor="HEAD" mb=""
    if git -C "$root" rev-parse --verify -q origin/main >/dev/null 2>&1; then
        mb="$(git -C "$root" merge-base HEAD origin/main 2>/dev/null)"
        [ -n "$mb" ] && anchor="$mb"
    fi
    if git -C "$root" rev-parse --verify -q "$anchor" >/dev/null 2>&1; then
        if head_rows="$(git -C "$root" show "$anchor:$BASELINE_REL" 2>/dev/null)"; then
            have_ancestor=1
        fi
    fi
    if [ "$have_ancestor" = 1 ]; then
        local now_groups old_groups added
        now_groups="$(grep -E '^[a-z]' "$baseline" | awk '{print $1}' | sort -u)"
        old_groups="$(printf '%s\n' "$head_rows" | grep -E '^[a-z]' \
                          | awk '{print $1}' | sort -u)"
        added="$(comm -23 <(printf '%s\n' "$now_groups") \
                          <(printf '%s\n' "$old_groups"))"
        if [ -n "${added//[[:space:]]/}" ]; then
            fail=1
            echo "FAIL: the determinism baseline GREW. New non-reproducing group(s):"
            printf '%s\n' "$added" | sed 's/^/    /'
            echo ""
            echo "  This baseline is shrink-only. A group appearing here means a"
            echo "  test stopped giving the same answer twice, and the fix is the"
            echo "  test, not the baseline. There is no flag that admits a new row."
        fi
    else
        echo "note: no ancestor $BASELINE_REL at HEAD — treating this as the"
        echo "      first commit of the record. Every later commit may only shrink it."
    fi

    [ "$fail" = 0 ] || return 1
    echo "OK: determinism baseline is well formed and did not grow — $rows non-reproducing group(s)."
    return 0
}

# ── selftest ────────────────────────────────────────────────────────────────
# A gate nobody has seen fail is a gate nobody should trust. Each case plants
# ONE defect in a throwaway git fixture and asserts this script rejects it AND
# names the offender; the last case asserts the clean fixture passes, so an
# unconditionally-failing script could not sneak through.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

# make_fixture <dir> [baseline-body...] — a minimal REAL tree with a real git
# history, because prong A reads `git show HEAD:<baseline>`.
make_fixture() {
    local d="$1"; shift
    mkdir -p "$d/tools/lint" "$d/tools/dev" \
             "$d/engine/modules/determinism/include/determinism"
    cat > "$d/$CATALOG_REL" <<'CATALOG'
ZCL_TEST_GROUP(alpha)
ZCL_TEST_GROUP(bravo)
ZCL_SPEC_GROUP(charlie)
CATALOG
    cat > "$d/$PERTURBATION_HEADER_REL" <<'HEADER'
enum zcl_det_perturbation {
    ZCL_DET_P_BASE,
    ZCL_DET_P_CC_SET,
    ZCL_DET_P_ENV_PAD,
    ZCL_DET_P__COUNT
};
HEADER
    {
        echo "# fixture baseline"
        echo "# count: 1"
        echo "test_alpha NONDETERMINISTIC CC_SET"
    } > "$d/$BASELINE_REL"
    git -C "$d" init -q 2>/dev/null
    git -C "$d" -c user.email=fixture@example.invalid \
                -c user.name=fixture add -A >/dev/null 2>&1
    git -C "$d" -c user.email=fixture@example.invalid \
                -c user.name=fixture commit -q -m "fixture baseline" \
                >/dev/null 2>&1
}

write_baseline() {
    local d="$1"; shift
    : > "$d/$BASELINE_REL"
    local l
    for l in "$@"; do printf '%s\n' "$l" >> "$d/$BASELINE_REL"; done
}

expect_reject() {
    local label="$1" needle="$2" d="$3" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected rejection, got a PASS."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELFTEST FAIL: $label — rejected, but never named '$needle'."
        echo "  A gate that fails without naming the offender is unactionable."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

expect_accept() {
    local label="$1" d="$2" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELFTEST FAIL: $label — expected a PASS, got rejection."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/determinism-ratchet-selftest.XXXXXX")"
    trap selftest_cleanup EXIT
    local rc=0 d

    echo "══ check-determinism-ratchet selftest ══"

    # A. the baseline GREW — THE defect this gate exists for.
    d="$FIXTURE_ROOT/a"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 2" "test_alpha NONDETERMINISTIC CC_SET" "test_bravo TIMING_SENSITIVE ENV_PAD"
    expect_reject "A: a baseline that grew is caught" "test_bravo" "$d" || rc=1

    # B. a row with no cause.
    d="$FIXTURE_ROOT/b"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 1" "test_alpha"
    expect_reject "B: a row naming no perturbation is caught" \
                  "name no splitting perturbation" "$d" || rc=1

    # C. a row naming a group that is not registered.
    d="$FIXTURE_ROOT/c"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 1" "test_ghost NONDETERMINISTIC CC_SET"
    expect_reject "C: a row naming an unregistered group is caught" \
                  "test_ghost" "$d" || rc=1

    # D. a row naming an unknown perturbation.
    d="$FIXTURE_ROOT/d"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 1" "test_alpha NONDETERMINISTIC VIBES"
    expect_reject "D: a row naming an unknown perturbation is caught" \
                  "VIBES" "$d" || rc=1

    # E. the declared count and the rows disagree.
    d="$FIXTURE_ROOT/e"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 7" "test_alpha NONDETERMINISTIC CC_SET"
    expect_reject "E: a count header that disagrees with the rows is caught" \
                  "declares" "$d" || rc=1

    # F. a missing baseline must FAIL, never pass vacuously.
    d="$FIXTURE_ROOT/f"; mkdir -p "$d"; make_fixture "$d"
    rm -f "$d/$BASELINE_REL"
    expect_reject "F: a missing baseline fails closed" \
                  "no readable determinism baseline" "$d" || rc=1

    # G. an unreadable REGISTRY must FAIL, never pass vacuously.
    d="$FIXTURE_ROOT/g"; mkdir -p "$d"; make_fixture "$d"
    : > "$d/$CATALOG_REL"
    expect_reject "G: an empty registry fails closed" \
                  "no registered groups" "$d" || rc=1

    # H. positive control, unchanged baseline — a clean tree PASSES, so none of
    #    the above can be an unconditional failure.
    d="$FIXTURE_ROOT/h"; mkdir -p "$d"; make_fixture "$d"
    expect_accept "H: an unchanged, well-formed baseline passes" "$d" || rc=1

    # I. positive control, SHRUNK baseline — paying debt off must be allowed,
    #    or the ratchet would forbid the only direction it exists to permit.
    d="$FIXTURE_ROOT/i"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 0"
    expect_accept "I: shrinking the baseline to empty passes" "$d" || rc=1

    # J. a row naming a class the classifier never emits. A hand-edited row is
    #    the failure mode here: someone widening the record by inventing a
    #    softer-sounding verdict rather than by measuring one.
    d="$FIXTURE_ROOT/j"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 1" "test_alpha FLAKY CC_SET"
    expect_reject "J: a row naming an unrecorded class is caught" \
                  "FLAKY" "$d" || rc=1

    # K. a row with a class but no cause. The three-column format must not let
    #    a two-token row through by reading the class as the cause.
    d="$FIXTURE_ROOT/k"; mkdir -p "$d"; make_fixture "$d"
    write_baseline "$d" "# count: 1" "test_alpha NONDETERMINISTIC"
    expect_reject "K: a row with a class but no perturbation is caught" \
                  "name no splitting perturbation" "$d" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (11/11) ══"
    else
        echo "══ selftest: FAIL ══"
    fi
    return "$rc"
}

main() {
    case "${1:-}" in
        --selftest) run_selftest; exit $? ;;
        "") ;;
        *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
    esac
    check_root "${ZCL_DETERMINISM_ROOT:-$REPO_ROOT}"
    exit $?
}

main "$@"
