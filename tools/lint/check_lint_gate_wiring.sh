#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_lint_gate_wiring.sh — the lint umbrella's two files must agree.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# Adding a lint gate is a TWO-FILE operation and nothing enforced the second
# file:
#
#   1. Makefile      — a `check-<name>:` target plus a line in LINT_GATES.
#   2. run_lint.sh   — an entry in gate_command()'s case table, because the
#                      parallel driver execs each gate's script DIRECTLY and
#                      never reads the Make recipe.
#
# On 2026-08-26 three gates landed with step 1 and without step 2 in a single
# session — check-tu-random-seed, check-source-identity-authority and
# check-no-unattended-publish — and `make lint` was FATAL (exit 2) on the
# whole tree until they were wired. Every lane that added a gate that session
# forgot the same file. That is not three mistakes; it is one missing rail.
#
# run_lint.sh already fails loud on a missing entry — but only at the moment
# somebody runs the umbrella, and it takes the WHOLE umbrella down with it
# (exit 2, no gate results at all), so the tree is red for everyone until a
# human notices. This gate is the same invariant checked as a gate: it is
# itself in LINT_GATES, so the parity is asserted on every commit, and the
# failure names the exact line to add instead of bricking the run.
#
# ── WHAT IS ASSERTED (all fail-closed) ──────────────────────────────────────
#   A. Every member of LINT_GATES and LINT_FAST_GATES has a gate_command()
#      case entry. This is the defect above.
#   B. Every gate_command() case entry belongs to one of those two lists.
#      A table entry nothing runs is the same rot in the other file — the
#      Makefile already carries a dozen orphan check-* targets no list names,
#      and that is how they got there. Symmetric or it is not a rail.
#   C. Every listed gate has a real `check-<name>:` target in the Makefile.
#      ZCL_LINT_SERIAL=1 runs the list as Make prerequisites, so a typo in the
#      list is a broken fallback path that the default path cannot see.
#   D. Every script path named by a table entry exists and is readable. The
#      entry is a STRING; a typo'd path is only discovered when that gate runs.
#
# ── SOURCES OF TRUTH (never re-parsed by hand) ──────────────────────────────
#   gate lists : the LINT_GATES / LINT_FAST_GATES backslash-continued blocks in
#                Makefile, read with the same awk extractor
#                tools/scripts/check_doc_accuracy.sh and tools/dev/agent-baseline.sh
#                already use. One idiom, three readers.
#   case table : `tools/lint/run_lint.sh --list`, which greps its OWN case
#                labels out of itself precisely so reformatting cannot desync a
#                probe. Do NOT write a second parser of that file here.
#
# Usage:
#   tools/lint/check_lint_gate_wiring.sh            # the gate
#   tools/lint/check_lint_gate_wiring.sh --selftest # prove it catches each
#                                                   # class before trusting it
# Env:
#   ZCL_GATE_WIRING_ROOT  repo root to inspect (default: this script's repo).
#                         The selftest points it at a mktemp fixture; nothing
#                         else should set it.
#
# Exit: 0 clean, 1 on any violation or a malformed tree.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"

# ── list extraction ─────────────────────────────────────────────────────────
# The established idiom: start at the `NAME :=` line, print until a line that
# does not end in a backslash. Returns nothing (not an error) if absent.
extract_gate_list() {
    local makefile="$1" var="$2"
    awk -v v="$var" '
        $0 ~ "^" v "[[:space:]]*:=" { inb = 1 }
        inb { print; if ($0 !~ /\\[[:space:]]*$/) exit }
    ' "$makefile" | grep -oE 'check-[a-z0-9-]+' | sort -u
}

# ── the check ───────────────────────────────────────────────────────────────
# Runs entirely against $root, so the selftest can aim it at a fixture.
check_root() {
    local root="$1"
    local makefile="$root/Makefile" driver="$root/tools/lint/run_lint.sh"
    local fail=0

    [ -f "$makefile" ] || { echo "FAIL: no Makefile at $makefile"; return 1; }
    [ -f "$driver" ]   || { echo "FAIL: no run_lint.sh at $driver"; return 1; }

    local umbrella fast listed table
    umbrella="$(extract_gate_list "$makefile" LINT_GATES)"
    fast="$(extract_gate_list "$makefile" LINT_FAST_GATES)"

    if [ -z "${umbrella//[[:space:]]/}" ]; then
        echo "FAIL: LINT_GATES is empty or unparseable in $makefile"
        echo "      This gate cannot verify wiring it cannot read. Fix the list shape"
        echo "      (a 'LINT_GATES := \\' block of backslash-continued check-* names)."
        return 1
    fi

    listed="$(printf '%s\n%s\n' "$umbrella" "$fast" | grep -E '^check-' | sort -u)"

    # The driver's own self-grep is the ONLY reader of its case labels.
    table="$("$driver" --list 2>/dev/null | grep -E '^check-' | sort -u)"
    if [ -z "${table//[[:space:]]/}" ]; then
        echo "FAIL: '$driver --list' produced no gate names."
        echo "      Either the driver is broken or its --list self-grep no longer"
        echo "      matches its case labels. Both are worse than a missing entry."
        return 1
    fi

    # ── A. listed but unwired ───────────────────────────────────────────────
    local unwired
    unwired="$(comm -23 <(printf '%s\n' "$listed") <(printf '%s\n' "$table"))"
    if [ -n "${unwired//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: gate(s) in LINT_GATES/LINT_FAST_GATES with NO gate_command() entry:"
        printf '%s\n' "$unwired" | sed 's/^/    /'
        echo ""
        echo "  Adding a lint gate is a TWO-FILE operation. You did the Makefile half."
        echo "  Add the other half to gate_command() in tools/lint/run_lint.sh, one line"
        echo "  per gate, reproducing the Make recipe EXACTLY (script path, args, any"
        echo "  ZCL_LINT_MODE prefix). A recipe with two steps is joined with &&:"
        echo ""
        echo "        <gate>)   echo './tools/lint/<script>.sh --selftest && ./tools/lint/<script>.sh' ;;"
        echo ""
        echo "  Without it 'make lint' exits 2 for everyone and reports NO gate results."
    fi

    # ── B. wired but unlisted ───────────────────────────────────────────────
    local orphan
    orphan="$(comm -13 <(printf '%s\n' "$listed") <(printf '%s\n' "$table"))"
    if [ -n "${orphan//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: gate_command() entries that NO gate list names (dead wiring):"
        printf '%s\n' "$orphan" | sed 's/^/    /'
        echo ""
        echo "  Nothing runs these. Either add them to LINT_GATES (or LINT_FAST_GATES)"
        echo "  in Makefile, or delete the table entry. A gate that never runs is a"
        echo "  gate that is not protecting anything."
    fi

    # ── C. listed but no Make target ────────────────────────────────────────
    # ZCL_LINT_SERIAL=1 runs the list as Make prerequisites; a name with no
    # rule breaks that path silently while the default path stays green.
    local g notarget=""
    while read -r g; do
        [ -n "$g" ] || continue
        grep -qE "^$g:" "$makefile" || notarget="$notarget$g"$'\n'
    done <<< "$listed"
    if [ -n "${notarget//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: listed gate(s) with no 'check-...:' target in $makefile:"
        printf '%s' "$notarget" | sed 's/^/    /'
        echo ""
        echo "  ZCL_LINT_SERIAL=1 runs the gate list as Make prerequisites. A listed"
        echo "  name with no rule makes that fallback fail with 'No rule to make target'"
        echo "  while the parallel path stays green — check a typo in the list first."
    fi

    # ── D. table entries naming a script that is not there ──────────────────
    # A case entry is just a string; a wrong path is only found when that gate
    # runs, which for a rarely-tripped gate can be a long time.
    local missing_script="" cmd tok path
    while read -r g; do
        [ -n "$g" ] || continue
        # gate_command lives in the driver; ask the driver, do not re-parse it.
        cmd="$("$driver" --print-command "$g" 2>/dev/null)" || continue
        [ -n "$cmd" ] || continue
        for tok in $cmd; do
            # Skip anything the shell will expand at run time, and the
            # pseudo-commands the driver handles internally.
            str_lacks "$tok" '$' || continue
            case "$tok" in
                *.sh) ;;
                *)    continue ;;
            esac
            path="${tok#./}"
            [ -f "$root/$path" ] || missing_script="$missing_script$g -> $path"$'\n'
        done
    done <<< "$table"
    if [ -n "${missing_script//[[:space:]]/}" ]; then
        fail=1
        echo "FAIL: gate_command() entries naming a script that does not exist:"
        printf '%s' "$missing_script" | sed 's/^/    /'
        echo ""
        echo "  The case table is a string table — nothing type-checks these paths."
        echo "  Fix the path, or add the script."
    fi

    if [ "$fail" != 0 ]; then
        return 1
    fi

    local n_listed n_table
    n_listed="$(printf '%s\n' "$listed" | grep -c .)"
    n_table="$(printf '%s\n' "$table" | grep -c .)"
    echo "OK: lint gate wiring is complete — $n_listed listed gate(s), $n_table table entry(ies), exact parity."
    return 0
}

# ── selftest ────────────────────────────────────────────────────────────────
# A gate nobody has seen fail is a gate nobody should trust. Each case below
# plants ONE defect in a throwaway fixture and asserts this script rejects it
# AND names the offender; the last case asserts the clean fixture passes, so a
# script that failed unconditionally could not sneak through.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

# make_fixture <dir> — a minimal but REAL tree: the actual driver (so --list
# and --print-command are the code under test, not a mock) and a Makefile whose
# LINT_GATES block has the same shape as the real one.
make_fixture() {
    local d="$1"
    mkdir -p "$d/tools/lint" "$d/tools/scripts"
    cp "$REPO_ROOT/tools/lint/run_lint.sh"   "$d/tools/lint/run_lint.sh"
    cp "$REPO_ROOT/tools/lint/lint_cache.sh" "$d/tools/lint/lint_cache.sh"
    cp "$REPO_ROOT/tools/scripts/sh_str.sh"  "$d/tools/scripts/sh_str.sh"
    chmod +x "$d/tools/lint/run_lint.sh"
    # Strip the real table down to nothing so only the sentinels below are in
    # it — otherwise every real gate would read as an orphan in the fixture.
    # The pattern must be the SAME one --list uses, or a reformatted entry
    # survives the strip and shows up as a phantom orphan in the fixture (an
    # earlier fixed-8-space version let exactly that happen).
    awk '
        /^[[:space:]]+check-[a-z0-9-]+\)[[:space:]]+echo[[:space:]]/ { next }
        { print }
    ' "$REPO_ROOT/tools/lint/run_lint.sh" > "$d/tools/lint/run_lint.sh.tmp"
    mv "$d/tools/lint/run_lint.sh.tmp" "$d/tools/lint/run_lint.sh"
    chmod +x "$d/tools/lint/run_lint.sh"
    : > "$d/tools/lint/sentinel_a.sh"
    : > "$d/tools/lint/sentinel_b.sh"
}

# fixture_list <dir> <gate>... — write the Makefile half.
fixture_list() {
    local d="$1"; shift
    {
        printf 'LINT_GATES := \\\n'
        local g last="$#"
        local i=0
        for g in "$@"; do
            i=$((i + 1))
            if [ "$i" -eq "$last" ]; then printf '    %s\n' "$g"
            else                          printf '    %s \\\n' "$g"; fi
        done
        printf '\n'
        for g in "$@"; do
            printf '%s:\n' "$g"
            printf '\t@true\n'
        done
    } > "$d/Makefile"
}

# fixture_wire <dir> <gate> <command> — write the run_lint.sh half.
fixture_wire() {
    local d="$1" gate="$2" cmd="$3"
    local tmp="$d/.wire.tmp"
    awk -v gate="$gate" -v cmd="$cmd" '
        $0 ~ /^        \*\) return 1 ;;$/ && !done {
            printf "        %s)   echo %c%s%c ;;\n", gate, 39, cmd, 39
            done = 1
        }
        { print }
    ' "$d/tools/lint/run_lint.sh" > "$tmp"
    mv "$tmp" "$d/tools/lint/run_lint.sh"
    chmod +x "$d/tools/lint/run_lint.sh"
}

# expect_reject <label> <needle> <dir>
expect_reject() {
    local label="$1" needle="$2" d="$3" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected rejection, got a PASS."
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELFTEST FAIL: $label — rejected, but never named '$needle'."
        echo "  A gate that fails without naming the offender is a gate nobody can act on."
        echo "$out" | sed 's/^/    /'
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
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lint-gate-wiring-selftest.XXXXXX")"
    trap selftest_cleanup EXIT
    local rc=0 d

    echo "══ check-lint-gate-wiring selftest ══"

    # A. listed but unwired — THE defect this gate exists for.
    d="$FIXTURE_ROOT/a"; mkdir -p "$d"; make_fixture "$d"
    fixture_list "$d" check-sentinel-wired check-sentinel-unwired
    fixture_wire "$d" check-sentinel-wired './tools/lint/sentinel_a.sh'
    expect_reject "A: a listed gate with no case-table entry is caught" \
                  "check-sentinel-unwired" "$d" || rc=1

    # B. wired but unlisted — the same rot in the other file.
    d="$FIXTURE_ROOT/b"; mkdir -p "$d"; make_fixture "$d"
    fixture_list "$d" check-sentinel-wired
    fixture_wire "$d" check-sentinel-wired  './tools/lint/sentinel_a.sh'
    fixture_wire "$d" check-sentinel-orphan './tools/lint/sentinel_b.sh'
    expect_reject "B: a case-table entry no gate list names is caught" \
                  "check-sentinel-orphan" "$d" || rc=1

    # C. listed with no Make target — breaks ZCL_LINT_SERIAL=1 only.
    d="$FIXTURE_ROOT/c"; mkdir -p "$d"; make_fixture "$d"
    fixture_list "$d" check-sentinel-wired
    fixture_wire "$d" check-sentinel-wired  './tools/lint/sentinel_a.sh'
    fixture_wire "$d" check-sentinel-notgt  './tools/lint/sentinel_b.sh'
    # Append the name to the list WITHOUT giving it a rule.
    sed -i 's|^    check-sentinel-wired$|    check-sentinel-wired \\\n    check-sentinel-notgt|' "$d/Makefile"
    expect_reject "C: a listed gate with no Make target is caught" \
                  "check-sentinel-notgt" "$d" || rc=1

    # D. wired to a script that is not there.
    d="$FIXTURE_ROOT/d"; mkdir -p "$d"; make_fixture "$d"
    fixture_list "$d" check-sentinel-wired
    fixture_wire "$d" check-sentinel-wired './tools/lint/does_not_exist.sh'
    expect_reject "D: a case entry naming a missing script is caught" \
                  "does_not_exist.sh" "$d" || rc=1

    # E. an unreadable LINT_GATES must FAIL, never pass vacuously. This is the
    #    direction that matters: a gate that cannot see its input must not
    #    report clean.
    d="$FIXTURE_ROOT/e"; mkdir -p "$d"; make_fixture "$d"
    printf '# no gate list here at all\n' > "$d/Makefile"
    expect_reject "E: an empty/unparseable LINT_GATES fails closed" \
                  "LINT_GATES is empty" "$d" || rc=1

    # F. positive control — a correctly wired fixture PASSES, so none of the
    #    above can be an unconditional failure.
    d="$FIXTURE_ROOT/f"; mkdir -p "$d"; make_fixture "$d"
    fixture_list "$d" check-sentinel-wired check-sentinel-unwired
    fixture_wire "$d" check-sentinel-wired   './tools/lint/sentinel_a.sh'
    fixture_wire "$d" check-sentinel-unwired './tools/lint/sentinel_b.sh --selftest && ./tools/lint/sentinel_b.sh'
    expect_accept "F: a fully wired tree passes (positive control)" "$d" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (6/6) ══"
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
    check_root "${ZCL_GATE_WIRING_ROOT:-$REPO_ROOT}"
    exit $?
}

main "$@"
