#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_live_datadir_isolation.sh — nothing under test, and no command an
# agent is told to copy, may be aimed at the OPERATOR'S LIVE NODE.
#
# ── THE TWO BUGS THIS EXISTS TO CATCH, BOTH REPRODUCED ─────────────────────
#
# (1) A GREEN TEST THAT WAS GREEN BECAUSE OF THE LIVE NODE. On 2026-07-30 the
#     first hosted-CI run of the full suite failed 6 of 842 groups that are
#     green here. `test_chain_integrity_failed_condition` was one: it never
#     called SetDataDir, so GetDataDir() resolved to the default
#     ~/.zclassic-c23, and on this host — which runs a node there —
#     chain_restore_quarantine_synthetic_tip() pread() the LIVE
#     blocks/blk00000.dat and the assertion passed off real, unrelated block
#     bytes. On a runner with no node the same test failed honestly. THIS HOST
#     STRUCTURALLY CANNOT FIND THAT CLASS BY RUNNING TESTS — a passing suite
#     is exactly the symptom. It can only be found by reading the source, which
#     is what this gate does.
#
# (2) A "READ" COMMAND THAT WROTE TO THE LIVE DATADIR. `z23 app service
#     access --input='{"service":"reference"}'` is declared READ / PUBLIC /
#     IDEMPOTENT and its handler called node_db_open() — the boot ceremony:
#     OPEN_CREATE, quick_check with a rename-aside on failure, create_schema,
#     migrate, then two DELETEs. `datadir` falls back to the process datadir
#     when the caller passes none, so a bare invocation did all of that to the
#     operator's live node.db. Six leaves had it. An auditor tripped it while
#     being deliberately careful, because THE DOCUMENTED EXAMPLE OMITS THE
#     DATADIR — docs/SERVICES.md still says `z23 app service access
#     <name>`. The property is enforced at runtime by
#     test_read_leaf_no_datadir_write; what nothing enforced is that the
#     examples an agent copies name a throwaway datadir.
#
# ── THE THREE PRONGS ───────────────────────────────────────────────────────
#
# A. LIVE-DATADIR PATH CONSTRUCTED IN A TEST (ratchet, per-file count).
#    A test source that builds `<something>/.zclassic` or
#    `<something>/.zclassic-c23` — the two real datadir names, EXACTLY, with
#    no suffix. A suffixed sibling (`-dev`, `-test`, `-COPY-…`) is a
#    deliberately distinct scratch directory and is NOT counted; the exact
#    names are the operator's live ones.
#
#    HONEST LIMIT, stated because it decides how to read the number: this is
#    a textual test, and roughly half the current rows build the path from a
#    SANDBOX home (a mkdtemp result, a `$root/gate-home`) rather than the real
#    $HOME, so they are harmless today. Distinguishing them needs intra-file
#    dataflow — the same identifier `home` is the sandbox in one file and
#    `getenv("HOME")` in the next — and a gate that guesses at that would be
#    worse than one that counts honestly. Every current row is therefore
#    classified BY HAND in the baseline with its reason, and the ratchet is
#    count-only: the property enforced is "no NEW test learns to spell the
#    live datadir", which is cheap, exact, and the thing that actually
#    regresses.
#
# B. A TEST THAT RESOLVES THE DATADIR WITHOUT PINNING IT (HARD, zero debt).
#    A test source that names GetDataDir()/GetDefaultDataDir() but never calls
#    SetDataDir() is bug (1) in its directly-visible form. Zero files do this
#    today, so this prong is HARD with no baseline — the first one to appear
#    fails the build.
#
#    HONEST LIMIT: bug (1)'s actual instance is NOT visible to this prong.
#    test_chain_integrity_failed_condition never wrote `GetDataDir` itself; it
#    called condition_engine_tick(), which reached GetDataDir several frames
#    down. Catching that needs a whole-program call graph, not a grep. Prong B
#    catches the direct spelling and says so; it is a floor, not the class.
#
# C. A COPYABLE INVOCATION OF A datadir-TAKING LEAF WITH NO --datadir
#    (ratchet, per-file count). The leaf set is DERIVED from argument 10
#    (`input_keys`) of the leaf macros in engine/composition/commands/*.def — 69 leaves
#    today — never from a hand list, so a leaf that gains a `datadir` input is
#    covered the day it lands. Scanned: tracked *.md (where an agent copies
#    its commands from) and tracked *.sh with comments stripped. A hit is a
#    line that invokes such a leaf and carries no `-datadir=`/`--datadir=`
#    and no `"datadir"` JSON key: exactly the shape that silently falls back
#    to the operator's live node.
#
#    NOT GATED, and named here so the decision is visible rather than
#    invisible: ~20 further sites pass a datadir whose VALUE is the live path
#    (`-datadir=/home/you/.zclassic-c23`, `-datadir="$HOME/.zclassic-c23"`),
#    mostly generated API_REFERENCE rows mirroring .def `example` fields, plus
#    node-start command lines that are not native-command invocations at all
#    and are legitimately aimed at a real node. Gating those needs a
#    per-example judgement about whether the doc is for an operator or for an
#    agent; it is a real follow-up, not something to fold in silently here.
#
# ── MODES ──────────────────────────────────────────────────────────────────
# ZCL_LINT_MODE: FAIL (default) | WARN | UPDATE (rewrite the baselines).
# Ratchet ceilings are constants in THIS FILE, so raising one is a source diff
# in review, never a quiet data-file edit. They may only go down.
#
# NO PER-LINE ESCAPE HATCH EXISTS, deliberately. The one thing an `# ok`
# marker would be used for is the case that needs a human to look.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# Pipeline-free substring predicates: this gate must not contain the
# printf|grep -q inversion that has already produced hollow PASSes here.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh || {
    echo "check_live_datadir_isolation: cannot source tools/scripts/sh_str.sh" >&2
    exit 2
}

GATE=check_live_datadir_isolation
MODE="${ZCL_LINT_MODE:-FAIL}"

# Ratchet ceilings — the totals measured when this gate landed. DOWN ONLY.
CEILING_A="${ZCL_LDI_CEILING_A:-8}"
CEILING_C="${ZCL_LDI_CEILING_C:-13}"

BASELINE_A="${ZCL_LDI_BASELINE_A:-tools/lint/live_datadir_test_paths_baseline.txt}"
BASELINE_C="${ZCL_LDI_BASELINE_C:-tools/lint/live_datadir_examples_baseline.txt}"

# Scan roots (overridable so --selftest can run against a sandbox tree).
TEST_GLOBS_DEFAULT='tests/harness/src/*.c tests/harness/src/*.h tests/harness/include/test/*.h'
TEST_GLOBS="${ZCL_LDI_TEST_GLOBS:-$TEST_GLOBS_DEFAULT}"
DEF_DIR="${ZCL_LDI_DEF_DIR:-engine/composition/commands}"
DOC_GLOBS="${ZCL_LDI_DOC_GLOBS:-}"     # empty => git ls-files '*.md' '*.sh'

TEST_FLOOR="${ZCL_LDI_TEST_FLOOR:-300}"
DOC_FLOOR="${ZCL_LDI_DOC_FLOOR:-200}"
LEAF_FLOOR="${ZCL_LDI_LEAF_FLOOR:-20}"

# ── scan sets ─────────────────────────────────────────────────────────────
collect_test_files() {
    # shellcheck disable=SC2086  # globs are intentional
    ls -1 $TEST_GLOBS 2>/dev/null || true
}
collect_doc_files() {
    if [ -n "$DOC_GLOBS" ]; then
        # shellcheck disable=SC2086
        ls -1 $DOC_GLOBS 2>/dev/null || true
    else
        git ls-files '*.md' '*.sh'
    fi
}

# ── PRONG A ───────────────────────────────────────────────────────────────
# The two live datadir names, exactly, at the END of a string literal, rooted
# at a RUNTIME value — a `%s` format slot, `$HOME`, or `~`.
#
# Two exclusions, both load-bearing:
#   * `-dev` / `-test` / `-soak` / `-COPY-…` do not match: the closing quote
#     must come immediately after the name, so a suffixed sibling (a
#     deliberately distinct scratch directory) is not a hit.
#   * A CONSTANT root does not match. `"/tmp/alt-zcl-home/.zclassic"`,
#     `"./.zclassic-c23"` and `"/home/.zclassic"` are fixed strings that
#     cannot be the operator's home; a first cut of this regex counted all
#     nine of them and turned a 8-site finding into a 17-site one, over half
#     of it noise. Only a runtime-rooted path can resolve to the live datadir.
prong_a_scan() {
    local files=("$@")
    [ "${#files[@]}" -gt 0 ] || return 0
    gate_grep -nE '(%s|\$HOME|~)/\.zclassic(-c23)?"' "${files[@]}" || true
}

# ── PRONG B ───────────────────────────────────────────────────────────────
prong_b_scan() {
    local f
    for f in "$@"; do
        if gate_grep -qE '\bGet(Default)?DataDir[[:space:]]*\(' "$f"; then
            if ! gate_grep -qE '\bSetDataDir[[:space:]]*\(' "$f"; then
                echo "$f"
            fi
        fi
    done
}

# ── PRONG C ───────────────────────────────────────────────────────────────
# Derive the leaves that accept a `datadir` input from the .def macros.
# `input_keys` is argument 10 in every leaf macro shape (engine/composition/src/
# command_catalog.c); a row with fewer than 10 top-level arguments is not a
# leaf macro and is skipped rather than read at the wrong slot.
derive_datadir_leaves() {
    local defs=()
    mapfile -t defs < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null | sort)
    gate_require_scanned "${#defs[@]}" 1 "$GATE" "no *.def under $DEF_DIR"
    awk '
    function flush(   i, n, args, ch, depth, inq, esc, cur, name, keys, k, kn) {
        if (rec == "") return
        n = 0; depth = 0; inq = 0; esc = 0; cur = ""
        for (i = 1; i <= length(rec); i++) {
            ch = substr(rec, i, 1)
            if (esc) { cur = cur ch; esc = 0; continue }
            if (inq) {
                if (ch == "\\") { cur = cur ch; esc = 1; continue }
                cur = cur ch; if (ch == "\"") inq = 0; continue
            }
            if (ch == "\"") { inq = 1; cur = cur ch; continue }
            if (ch == "(") { depth++; cur = cur ch; continue }
            if (ch == ")") { depth--; cur = cur ch; continue }
            if (ch == "," && depth == 0) { args[++n] = cur; cur = ""; continue }
            cur = cur ch
        }
        if (cur != "") args[++n] = cur
        if (n >= 10) {
            name = args[1]; keys = args[10]
            gsub(/\\"/, "", name); gsub(/"/, "", name); gsub(/[ \t\r\n]/, "", name)
            gsub(/\\"/, "", keys); gsub(/"/, "", keys); gsub(/[ \t\r\n]/, "", keys)
            kn = split(keys, k, ",")
            for (i = 1; i <= kn; i++)
                if (k[i] == "datadir") { print name; break }
        }
        rec = ""
    }
    /^ZCL_COMMAND_[A-Z_]+\(/ {
        flush(); collecting = 1; rec = ""; sub(/^ZCL_COMMAND_[A-Z_]+\(/, "")
    }
    collecting {
        line = $0
        sub(/[ \t]*\/\*.*\*\/[ \t]*/, " ", line)
        rec = rec " " line
        d = 0; q = 0; e = 0
        for (i = 1; i <= length(rec); i++) {
            c = substr(rec, i, 1)
            if (e) { e = 0; continue }
            if (q) { if (c == "\\") { e = 1; continue }
                     if (c == "\"") q = 0; continue }
            if (c == "\"") { q = 1; continue }
            if (c == "(") d++
            if (c == ")") d--
        }
        if (d < 0) { sub(/\)[^)]*$/, "", rec); flush(); collecting = 0 }
    }
    END { flush() }
    ' "${defs[@]}" | sort -u
}

# ── --selftest ────────────────────────────────────────────────────────────
# Plants each violation in a sandbox tree and proves the gate FAILS; removes
# it and proves PASS. Also asserts each fixture really carries the shape it
# claims, so a fixture that silently stopped containing its violation cannot
# make this self-test hollow.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/t" "$tmp/d" "$tmp/defs"

    # A minimal .def carrying one datadir leaf and one that is not.
    cat > "$tmp/defs/sand.def" <<'DEF'
ZCL_COMMAND_READY_READ(
    "sand.thing.peek", "sand.thing", "", "Peek",
    "Semantics.", 0,
    "tag", "zcl.in.v1", "zcl.out.v1", "datadir", "",
    "z23 sand thing peek --input='{\"datadir\":\"/tmp/x\"}'",
    ZCL_COMMAND_LAYER_CORE, ZCL_COMMAND_SCOPE_NODE, ZCL_COMMAND_AUTH_OPERATOR,
    ZCL_COMMAND_LATENCY_FAST, ZCL_COMMAND_COST_LOW,
    ZCL_COMMAND_LANE_LOCAL, ZCL_COMMAND_CAP_CHAIN_READ,
    ZCL_COMMAND_TRAIT_IDEMPOTENT, ZCL_COMMAND_TRANSPORT_NATIVE, h_peek)
ZCL_COMMAND_READY_READ(
    "sand.other.poke", "sand.other", "", "Poke",
    "Semantics.", 0,
    "tag", "zcl.in.v1", "zcl.out.v1", "service", "",
    "z23 sand other poke",
    ZCL_COMMAND_LAYER_CORE, ZCL_COMMAND_SCOPE_NODE, ZCL_COMMAND_AUTH_OPERATOR,
    ZCL_COMMAND_LATENCY_FAST, ZCL_COMMAND_COST_LOW,
    ZCL_COMMAND_LANE_LOCAL, ZCL_COMMAND_CAP_CHAIN_READ,
    ZCL_COMMAND_TRAIT_IDEMPOTENT, ZCL_COMMAND_TRANSPORT_NATIVE, h_poke)
DEF

    clean_test='#include <stdio.h>
int t(void) {
    char p[64];
    const char *home = getenv("HOME");
    snprintf(p, sizeof(p), "%s/.zclassic-c23-dev", home);   /* suffixed sibling */
    SetDataDir(p);
    GetDataDir(true, p, sizeof(p));
    return 0;
}'
    a_test='#include <stdio.h>
int t(void) {
    char p[64];
    const char *home = getenv("HOME");
    snprintf(p, sizeof(p), "%s/.zclassic-c23", home);
    return 0;
}'
    b_test='#include <stdio.h>
int t(void) {
    char p[64];
    GetDataDir(true, p, sizeof(p));
    return 0;
}'
    clean_doc='Run it like this:

    z23 sand thing peek --datadir=/tmp/fixture
    z23 sand other poke
'
    c_doc='Run it like this:

    z23 sand thing peek
'

    # ── fixture hollowness guards ────────────────────────────────────────
    if str_lacks "$a_test" '/.zclassic-c23"'; then
        echo "$GATE: SELFTEST FAILED — prong-A fixture no longer spells the exact live datadir" >&2; exit 2
    fi
    if str_contains "$clean_test" '/.zclassic-c23"'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture now spells the exact live datadir; it cannot prove the suffixed sibling is exempt" >&2; exit 2
    fi
    if str_lacks "$clean_test" '.zclassic-c23-dev'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture lost its suffixed-sibling path" >&2; exit 2
    fi
    if str_contains "$b_test" 'SetDataDir'; then
        echo "$GATE: SELFTEST FAILED — the prong-B fixture pins the datadir; it cannot test the unpinned case" >&2; exit 2
    fi
    if str_lacks "$b_test" 'GetDataDir'; then
        echo "$GATE: SELFTEST FAILED — the prong-B fixture no longer resolves the datadir" >&2; exit 2
    fi
    if str_contains "$c_doc" 'datadir='; then
        echo "$GATE: SELFTEST FAILED — the prong-C fixture already passes a datadir" >&2; exit 2
    fi
    if str_lacks "$clean_doc" 'datadir=/tmp/fixture'; then
        echo "$GATE: SELFTEST FAILED — the clean doc fixture lost its explicit tmp datadir" >&2; exit 2
    fi

    : > "$tmp/empty_a.txt"
    : > "$tmp/empty_c.txt"
    self="$ROOT/tools/lint/$GATE.sh"

    run_sandbox() {
        ZCL_LDI_TEST_GLOBS="$tmp/t/*.c" \
        ZCL_LDI_DOC_GLOBS="$tmp/d/*.md" \
        ZCL_LDI_DEF_DIR="$tmp/defs" \
        ZCL_LDI_BASELINE_A="$tmp/empty_a.txt" \
        ZCL_LDI_BASELINE_C="$tmp/empty_c.txt" \
        ZCL_LDI_CEILING_A=0 ZCL_LDI_CEILING_C=0 \
        ZCL_LDI_TEST_FLOOR=1 ZCL_LDI_DOC_FLOOR=1 ZCL_LDI_LEAF_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }
    plant() { printf '%s\n' "$1" > "$tmp/t/sand.c"; printf '%s\n' "$2" > "$tmp/d/sand.md"; }
    expect() { # want msg test_body doc_body
        local want="$1" msg="$2" rc=0
        plant "$3" "$4"
        run_sandbox || rc=$?
        if [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg (rc=$rc)" >&2; exit 2
        fi
    }

    expect pass "a clean tree was reported as violating (a suffixed sibling datadir and a pinned GetDataDir are both legal)" \
        "$clean_test" "$clean_doc"
    expect fail "prong A: a test constructing the EXACT live datadir did not fail the gate" \
        "$a_test" "$clean_doc"
    expect pass "prong A: removing the violation did not clear it" \
        "$clean_test" "$clean_doc"
    expect fail "prong B: a test resolving GetDataDir with no SetDataDir did not fail the gate" \
        "$b_test" "$clean_doc"
    expect pass "prong B: removing the violation did not clear it" \
        "$clean_test" "$clean_doc"
    expect fail "prong C: a documented invocation of a datadir-taking leaf with no --datadir did not fail the gate" \
        "$clean_test" "$c_doc"
    expect pass "prong C: adding an explicit --datadir cleared it" \
        "$clean_test" "$clean_doc"

    # The leaf derivation must actually distinguish the two sandbox leaves; if
    # it returned everything or nothing, prong C proves nothing above.
    # DEF_DIR is snapshotted from ZCL_LDI_DEF_DIR at parse time, so overriding
    # the env var here would NOT reach the function — set the variable the
    # function actually reads. (The sandbox runs above re-exec this script, so
    # for those the env var is the right knob.)
    got="$(DEF_DIR="$tmp/defs" derive_datadir_leaves)"
    if [ "$got" != "sand.thing.peek" ]; then
        echo "$GATE: SELFTEST FAILED — leaf derivation returned '$got', expected exactly 'sand.thing.peek' (arg-10 input_keys parsing is wrong)" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASS (prongs A/B/C each fail on a planted violation and clear when it is removed; a suffixed sibling datadir, a pinned GetDataDir and an explicit --datadir are all legal; arg-10 leaf derivation isolates the datadir-taking leaf)"
    exit 0
fi

# ── run ───────────────────────────────────────────────────────────────────
mapfile -t test_files < <(collect_test_files)
gate_require_scanned "${#test_files[@]}" "$TEST_FLOOR" "$GATE" \
    "test scan set is empty — did tests/harness/src move? (globs: $TEST_GLOBS)"

mapfile -t doc_files < <(collect_doc_files)
gate_require_scanned "${#doc_files[@]}" "$DOC_FLOOR" "$GATE" \
    "doc/script scan set is empty — did git ls-files '*.md' '*.sh' stop matching?"

mapfile -t dd_leaves < <(derive_datadir_leaves)
gate_require_scanned "${#dd_leaves[@]}" "$LEAF_FLOOR" "$GATE" \
    "no datadir-taking leaves derived from $DEF_DIR — the .def macro arity or the input_keys slot changed"

fail=0

# ── prong A ───────────────────────────────────────────────────────────────
declare -A A_COUNT=()
while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    p="${hit%%:*}"
    A_COUNT["$p"]=$(( ${A_COUNT[$p]:-0} + 1 ))
done < <(prong_a_scan "${test_files[@]}")

declare -A A_BASE=()
gate_load_kv_file "$BASELINE_A" A_BASE
a_total=0
a_base_sum=0
for p in "${!A_COUNT[@]}"; do a_total=$(( a_total + ${A_COUNT[$p]} )); done
for p in "${!A_BASE[@]}"; do
    case "${A_BASE[$p]}" in
        ''|*[!0-9]*) echo "[$GATE] FATAL — baseline row '$p' has non-numeric count '${A_BASE[$p]}' in $BASELINE_A" >&2; exit 2 ;;
    esac
    a_base_sum=$(( a_base_sum + ${A_BASE[$p]} ))
done

a_violations=()
for p in "${!A_COUNT[@]}"; do
    allowed="${A_BASE[$p]:-0}"
    if [ "${A_COUNT[$p]}" -gt "$allowed" ]; then
        a_violations+=("$p — ${A_COUNT[$p]} live-datadir path(s), baseline allows $allowed")
    fi
done
a_stale=()
for p in "${!A_BASE[@]}"; do
    [ -z "${A_COUNT[$p]+x}" ] && a_stale+=("$p (baseline says ${A_BASE[$p]}, actual 0)")
done
if [ "$a_base_sum" -gt "$CEILING_A" ]; then
    a_violations+=("$BASELINE_A — baseline sum $a_base_sum exceeds ceiling $CEILING_A")
fi

# ── prong B ───────────────────────────────────────────────────────────────
mapfile -t b_violations < <(prong_b_scan "${test_files[@]}")

# ── prong C ───────────────────────────────────────────────────────────────
# One fixed-string needle per leaf: the CLI spelling (dots -> spaces).
declare -A C_COUNT=()
c_hits=()
# Both binary spellings: the product name is z23 (z23-dev in the dev lane), and
# `zclassic23` remains a migration alias, so a copyable example under either
# spelling still points a reader at the live node.
needles="$(printf '%s\n' "${dd_leaves[@]}" | tr '.' ' ' \
    | sed -e 's/^/z23 /' -e 'p' -e 's/^z23 /z23-dev /' -e 'p' -e 's/^z23-dev /zclassic23 /' \
    | sort -u)"

# Shortlist first. 69 needles x 422 files of bash-level substring testing cost
# 14 s; one fixed-string multi-pattern grep narrows it to the handful of files
# that mention any datadir-taking leaf at all, and the expensive per-line work
# then runs only on those. `grep -l` cannot report a false NEGATIVE here (it is
# the same fixed strings), so the shortlist cannot hide a violation — and the
# floor above still guards against the scan set itself emptying.
needle_file="$(mktemp)"
trap 'rm -f "$needle_file"' EXIT
printf '%s\n' "$needles" > "$needle_file"
mapfile -t candidate_files < <(
    printf '%s\0' "${doc_files[@]}" \
        | xargs -0 grep -lF -f "$needle_file" -- 2>/dev/null || true
)

for f in ${candidate_files[@]+"${candidate_files[@]}"}; do
    [ -f "$f" ] || continue
    case "$f" in
        # This gate and its baselines quote the violating shapes in prose.
        tools/lint/check_live_datadir_isolation.sh|tools/lint/live_datadir_*_baseline.txt) continue ;;
    esac
    # Comments are prose, not a copyable command, in shell. Markdown has no
    # comment syntax that matters here, so it is scanned whole.
    if [ "${f##*.}" = "sh" ]; then
        body="$(sed 's/^[[:space:]]*#.*//' "$f")"
    else
        body="$(cat "$f")"
    fi
    while IFS= read -r needle; do
        [ -n "$needle" ] || continue
        str_contains "$body" "$needle" || continue
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            str_contains "$line" "datadir" && continue
            n="${line%%:*}"
            c_hits+=("$f:$n")
            C_COUNT["$f"]=$(( ${C_COUNT[$f]:-0} + 1 ))
        done < <(printf '%s\n' "$body" | grep -nF -- "$needle" || true)
    done <<< "$needles"
done

declare -A C_BASE=()
gate_load_kv_file "$BASELINE_C" C_BASE
c_total=0
c_base_sum=0
for p in "${!C_COUNT[@]}"; do c_total=$(( c_total + ${C_COUNT[$p]} )); done
for p in "${!C_BASE[@]}"; do
    case "${C_BASE[$p]}" in
        ''|*[!0-9]*) echo "[$GATE] FATAL — baseline row '$p' has non-numeric count '${C_BASE[$p]}' in $BASELINE_C" >&2; exit 2 ;;
    esac
    c_base_sum=$(( c_base_sum + ${C_BASE[$p]} ))
done

c_violations=()
for p in "${!C_COUNT[@]}"; do
    allowed="${C_BASE[$p]:-0}"
    if [ "${C_COUNT[$p]}" -gt "$allowed" ]; then
        c_violations+=("$p — ${C_COUNT[$p]} datadir-leaf invocation(s) with no --datadir, baseline allows $allowed")
    fi
done
c_stale=()
for p in "${!C_BASE[@]}"; do
    [ -z "${C_COUNT[$p]+x}" ] && c_stale+=("$p (baseline says ${C_BASE[$p]}, actual 0)")
done
if [ "$c_base_sum" -gt "$CEILING_C" ]; then
    c_violations+=("$BASELINE_C — baseline sum $c_base_sum exceeds ceiling $CEILING_C")
fi

# ── UPDATE ────────────────────────────────────────────────────────────────
# Per-row trailing comments in a baseline are HAND ANALYSIS — which of these
# rows builds the path from the real $HOME and which from a sandbox root is
# not derivable, so somebody had to read them. A regeneration that dropped
# those comments would silently destroy the only record of that reading and
# the next person would have to redo it. So UPDATE carries them across.
declare -A ROW_COMMENT=()
load_row_comments() {
    local file="$1" line key rest
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        case "$line" in \#*|'') continue ;; esac
        str_contains "$line" "#" || continue
        key="${line%% *}"
        rest="#${line#*#}"
        ROW_COMMENT["$key"]="$rest"
    done < "$file"
}
emit_row() { # <path> <count>
    if [ -n "${ROW_COMMENT[$1]:-}" ]; then
        printf '%s %s   %s\n' "$1" "$2" "${ROW_COMMENT[$1]}"
    else
        printf '%s %s\n' "$1" "$2"
    fi
}

if [ "$MODE" = "UPDATE" ]; then
    load_row_comments "$BASELINE_A"
    load_row_comments "$BASELINE_C"
    {
        echo "# $GATE — prong A baseline."
        echo "# Test sources that construct the operator's EXACT live datadir"
        echo "# path (<x>/.zclassic or <x>/.zclassic-c23, no suffix)."
        echo "#"
        echo "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK."
        echo "# The trailing comment on each row is hand analysis (whose \$HOME"
        echo "# the path is built from); regeneration preserves it."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for p in $(printf '%s\n' "${!A_COUNT[@]}" | sort); do
            emit_row "$p" "${A_COUNT[$p]}"
        done
    } > "$BASELINE_A"
    {
        echo "# $GATE — prong C baseline."
        echo "# Tracked docs/scripts that show an invocation of a leaf which"
        echo "# ACCEPTS a datadir input, without naming one — so a reader who"
        echo "# copies the line points it at the live node."
        echo "#"
        echo "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK."
        echo "# Fix a row by adding --datadir=/tmp/<fixture> to the example."
        echo "# Trailing per-row comments are hand analysis; regeneration keeps them."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for p in $(printf '%s\n' "${!C_COUNT[@]}" | sort); do
            emit_row "$p" "${C_COUNT[$p]}"
        done
    } > "$BASELINE_C"
    echo "[$GATE] baselines UPDATED: $BASELINE_A ($a_total), $BASELINE_C ($c_total)"
    exit 0
fi

# ── report ────────────────────────────────────────────────────────────────
if [ "${#a_violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] PRONG A — ${#a_violations[@]} new/grown live-datadir path(s) in test sources:"
    printf '  %s\n' "${a_violations[@]}" | sort
    echo "  A test must never spell the operator's live datadir. Build the path"
    echo "  under a tmp root (test_make_tmpdir) and pin it with SetDataDir()."
    echo "  Raising a number in $BASELINE_A is not a fix; counts may only shrink."
    fail=1
fi
if [ "${#a_stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] PRONG A — ${#a_stale[@]} stale baseline row(s); delete them from $BASELINE_A:"
    printf '  %s\n' "${a_stale[@]}" | sort
    fail=1
fi

if [ "${#b_violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] PRONG B — ${#b_violations[@]} test file(s) resolve the datadir but never pin it:"
    printf '  %s\n' "${b_violations[@]}" | sort
    echo "  GetDataDir()/GetDefaultDataDir() with no SetDataDir() resolves to"
    echo "  ~/.zclassic-c23. On a host running a node there, the test reads the"
    echo "  LIVE datadir and can pass off real, unrelated bytes — this host"
    echo "  cannot detect that by running the test. Pin it:"
    echo "    char dd[256]; test_make_tmpdir(dd, sizeof dd, \"<group>\", \"datadir\");"
    echo "    SetDataDir(dd);"
    echo "  This prong is HARD and has no baseline: today the count is zero."
    fail=1
fi

if [ "${#c_violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] PRONG C — ${#c_violations[@]} new/grown copyable invocation(s) of a"
    echo "        datadir-taking leaf with no --datadir:"
    printf '  %s\n' "${c_violations[@]}" | sort
    echo "  A leaf that accepts \`datadir\` falls back to the process datadir when"
    echo "  none is given, which is the operator's live node. Show the datadir in"
    echo "  the example: --datadir=/tmp/<fixture> (or a \"datadir\" input key)."
    echo "  Raising a number in $BASELINE_C is not a fix; counts may only shrink."
    fail=1
fi
if [ "${#c_stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] PRONG C — ${#c_stale[@]} stale baseline row(s); delete them from $BASELINE_C:"
    printf '  %s\n' "${c_stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#test_files[@]} test file(s): prong A $a_total site(s) in ${#A_COUNT[@]} file(s), all baselined ($a_base_sum/$CEILING_A); prong B ${#b_violations[@]} unpinned GetDataDir caller(s), HARD; ${#doc_files[@]} doc/script file(s) vs ${#dd_leaves[@]} datadir-taking leaves: prong C $c_total site(s) in ${#C_COUNT[@]} file(s), all baselined ($c_base_sum/$CEILING_C))"
