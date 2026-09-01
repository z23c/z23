#!/usr/bin/env bash
# check_status_reason_single.sh — stop a third inline copy of the
# operator-needed ladder from growing back. Mode: shrink-only ratchet
# (ZCL_LINT_MODE: FAIL default | WARN | UPDATE — same shape as
# check_identity_parser_single.sh).
#
# WHY THIS EXISTS: two operator surfaces each carried their OWN if/else-if
# ladder assigning `operator_needed`, plus their own copies of every rung's
# `status` and `summary` string:
#   engine/controllers/src/api_controller_status.c   (public REST /api/status)
#   cognition/controllers/src/event_agent_summary.c     (agent first-call summary)
# The node could therefore give TWO different answers to "does an operator
# need to intervene", and the two had already drifted — the agent ladder
# observed four signals the REST ladder did not (peer-telemetry availability,
# catch-up stall, download-dispatch stall, projection lag).
# engine/controllers/include/controllers/operator_needed_policy.def is now the
# one table that decides it; both surfaces select an
# `enum node_status_reason` and read the verdict back. This gate is the
# anti-rot check that keeps a third ladder from being pasted in.
#
# WHAT IS COUNTED, per scanned *.c file: an inline operator-verdict ladder,
# matched by SHAPE and NOT by any name — because a gate keyed on the name
# `operator_needed` is dodged by one rename, and that exact dodge has already
# been demonstrated against a sibling gate in this repo (see
# check_identity_parser_single.sh's header). A match needs BOTH halves:
#
#   1. STRUCTURE (name-independent). Inside one function body, a locally
#      declared `bool <IDENT> = false;` (or `= true;`) that is re-assigned on
#      LADDER_ASSIGN_MIN or more later lines, in a body that also contains
#      LADDER_ELSEIF_MIN or more `else if (` branches. That is the ladder
#      shape: one boolean verdict decided across many prioritized branches.
#      <IDENT> can be called anything at all.
#
#   2. ROLE. The same function body must ALSO either
#        a. publish a boolean to an operator-facing JSON document
#           (json_push_kv_bool), or
#        b. contain a literal from the closed operator status vocabulary
#           ("blocked" / "catching_up" / "degraded").
#      This is what separates the verdict ladder from the many innocuous
#      multi-branch boolean flags in this tree (a budget-exhaustion flag, a
#      parse-ok flag, a chart-data-availability flag). It is a role test on
#      what the function DOES, not a list of variable or function names, so a
#      rename still cannot dodge it. The status vocabulary is itself pinned
#      closed by test_operator_needed_policy's
#      case_status_vocabulary_is_closed, so a fifth status word cannot appear
#      on a shared surface without that test failing first.
#
# NO ALLOW-COMMENT ESCAPE HATCH EXISTS, on purpose. An in-place marker that
# exempts a match is an unbounded bypass unless it is both counted and pinned
# to named files, and the simplest way to have neither hole is to not offer
# the mechanism: the baseline file below is the only route, it is shrink-only,
# and every change to it is a visible diff in review. If a future case truly
# needs tolerating, it gets a baseline row with a written reason — not a
# comment nobody reviews.
#
# RATCHET_CEILING below is the total measured across the baseline: 1, in 1
# file (see tools/lint/status_reason_baseline.txt for exactly which and
# why — it is a detector false positive, not a real copy, and it is recorded
# rather than name-excluded because an exclusion is a permanent hole while a
# baseline row is visible, reviewable, shrink-only debt). The ceiling may
# only go DOWN.
#
# --selftest plants a fresh inline ladder in a sandboxed C tree — once with
# the original variable name, once RENAMED to prove the name-list dodge is
# closed, and once with each half of the role test — proves the gate FAILS on
# each, then removes them and proves PASS. A ratchet that cannot be shown to
# fail is worse than no gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

GATE=check_status_reason_single
RATCHET_CEILING=1
LADDER_ASSIGN_MIN=3
# 2, not 3: an `if / else if / else if` chain — the smallest thing that is
# recognisably this ladder — has exactly two `else if` branches. Measured
# 2026-07-30 across all 2089 tracked *.c files: thresholds 2 and 3 produce
# IDENTICAL results (one hit, the baselined false positive), so 2 is free
# tightening. Dropping to 1 adds a real false positive
# (engine/conditions/src/block_failed_mask_at_tip.c), which is where the line is.
LADDER_ELSEIF_MIN=2

# ── the detector ─────────────────────────────────────────────────────────
# Emits: path<TAB>count. Function bodies are delimited by a `{` alone on a
# line at column 0 and a `}` at column 0 — this tree's universal style for a
# function definition, and the only place a top-level brace appears
# unindented. Anything indented is inside a body already.
scan_counts() {
    awk -v amin="$LADDER_ASSIGN_MIN" -v emin="$LADDER_ELSEIF_MIN" '
        function reset_body() {
            delete assigns; delete decl
            elseifs = 0; haspub = 0; hasvocab = 0
        }
        function close_body() {
            if (!infunc) return
            if ((haspub || hasvocab) && elseifs >= emin) {
                for (v in decl)
                    if (assigns[v] >= amin) count++
            }
            infunc = 0
            reset_body()
        }
        FNR == 1 {
            if (NR > 1) emit()
            path = FILENAME; count = 0; infunc = 0
            reset_body()
        }
        /^\{[ \t]*$/ { close_body(); infunc = 1; reset_body(); next }
        /^\}/        { close_body(); next }
        infunc {
            line = $0
            # A locally declared bool seeded with a literal — the ladder
            # accumulator. Name is captured, never compared to a list.
            if (line ~ /^[ \t]+bool[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(false|true)[ \t]*;[ \t]*$/) {
                t = line
                sub(/^[ \t]+bool[ \t]+/, "", t)
                sub(/[ \t]*=.*$/, "", t)
                decl[t] = 1
            }
            # A later plain assignment to one of those locals. The line is
            # split on `{` and `;` first and every fragment is tested, so an
            # assignment written on the same line as its branch —
            # `if (a) { word = "blocked"; flag = true; }` — counts exactly
            # like one on its own line. Anchoring at start-of-line only was a
            # demonstrated dodge: a real renamed ladder in that brace style
            # passed this gate while the identical ladder in the usual style
            # of this tree failed it, and no formatting gate here forbids the
            # style (5 tracked *.c files already write it). A gate a reindent
            # can defeat is not a gate.
            nfrag = split(line, frag, /[{;]/)
            for (fi = 1; fi <= nfrag; fi++) {
                t = frag[fi]
                sub(/^[ \t]+/, "", t)
                if (t !~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*[^=]/) continue
                sub(/[ \t]*=.*$/, "", t)
                if (t in decl) assigns[t]++
            }
            if (line ~ /else[ \t]+if[ \t]*\(/) elseifs++
            if (line ~ /json_push_kv_bool[ \t]*\(/) haspub = 1
            if (line ~ /"(blocked|catching_up|degraded)"/) hasvocab = 1
        }
        END { close_body(); emit() }
        function emit() {
            if (path != "" && count > 0) printf "%s\t%d\n", path, count
        }
    ' "$@"
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    # A ladder written with the ORIGINAL name.
    named_ladder="$(cat <<'FIXTURE'
size_t surface_status(struct json_value *out)
{
    bool operator_needed = false;
    if (a) {
        operator_needed = true;
    } else if (b) {
        operator_needed = true;
    } else if (c) {
        operator_needed = true;
    }
    json_push_kv_bool(out, "operator_needed", operator_needed);
    return 0;
}
FIXTURE
)"
    # The SAME ladder, variable renamed to something on no list anywhere.
    renamed_ladder="${named_ladder//operator_needed/wants_a_human}"
    # Role half (b): no json_push_kv_bool, but it publishes the status
    # vocabulary, so it is still an operator-verdict ladder.
    vocab_ladder="$(cat <<'FIXTURE'
const char *surface_word(void)
{
    bool needs_hands = false;
    const char *word = "healthy";
    if (a) {
        needs_hands = true; word = "blocked";
    } else if (b) {
        needs_hands = true; word = "degraded";
    } else if (c) {
        needs_hands = true; word = "catching_up";
    }
    return needs_hands ? word : "healthy";
}
FIXTURE
)"
    # NEITHER role signal: a multi-branch flag that publishes nothing an
    # operator reads. Must NOT count, or the gate is noise.
    innocuous_flag="$(cat <<'FIXTURE'
int parse_thing(const char *s)
{
    bool bad = false;
    if (a) {
        bad = true;
    } else if (b) {
        bad = true;
    } else if (c) {
        bad = true;
    }
    return bad ? -1 : 0;
}
FIXTURE
)"
    # Structure half: the role signals are present but there is no ladder —
    # one branch only. Must NOT count.
    no_ladder="$(cat <<'FIXTURE'
size_t one_branch(struct json_value *out)
{
    bool flag = false;
    if (a)
        flag = true;
    json_push_kv_bool(out, "flag", flag);
    return 0;
}
FIXTURE
)"
    # Structure half, the other side: a long enough chain, role signals
    # present, but the bool is only touched TWICE — under LADDER_ASSIGN_MIN.
    # Must NOT count, or the assignment threshold is decorative.
    short_ladder="$(cat <<'FIXTURE'
size_t two_assigns(struct json_value *out)
{
    bool flag = false;
    if (a) {
        flag = true;
    } else if (b) {
        other = 1;
    } else if (c) {
        flag = true;
    }
    json_push_kv_bool(out, "flag", flag);
    return 0;
}
FIXTURE
)"

    # The SAME ladder again, written with each branch's assignments on the
    # same line as its brace. Semantically identical to named_ladder; only the
    # whitespace differs. Must count, or the gate is defeated by a reindent.
    sameline_ladder="$(cat <<'FIXTURE'
size_t surface_status_compact(struct json_value *out)
{
    bool wants_hands = false;
    const char *word = "healthy";
    if (a) { word = "blocked"; wants_hands = true; }
    else if (b) { word = "degraded"; wants_hands = true; }
    else if (c) { word = "catching_up"; wants_hands = true; }
    json_push_kv_bool(out, "wants_hands", wants_hands);
    return 0;
}
FIXTURE
)"

    plant() { # $1 = C body to write into the sandbox file
        {
            echo '/* sandbox fixture, not real code */'
            echo "$1"
        } > "$tmp/src/sandbox_surface.c"
    }
    mkdir -p "$tmp/src"

    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    run_sandbox() {
        ZCL_STATUS_REASON_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_STATUS_REASON_GATE_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_STATUS_REASON_GATE_CEILING=0 \
        ZCL_STATUS_REASON_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = pass|fail, $2 = message, $3 = C body
        local want="$1" msg="$2" body="$3" rc=0
        plant "$body"
        run_sandbox || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    expect pass "a clean file with no ladder was reported as a violation" \
        'int nothing(void) { return 0; }'
    expect fail "an inline operator_needed ladder did not fail the gate" \
        "$named_ladder"
    expect pass "reverting the named ladder did not clear the violation" \
        'int nothing(void) { return 0; }'
    expect fail "a RENAMED ladder (no name on any list) did not fail the gate; the rename dodge is not closed" \
        "$renamed_ladder"
    expect pass "reverting the renamed ladder did not clear the violation" \
        'int nothing(void) { return 0; }'
    expect fail "a ladder detected only through the status vocabulary did not fail the gate" \
        "$vocab_ladder"
    expect pass "reverting the vocabulary ladder did not clear the violation" \
        'int nothing(void) { return 0; }'
    expect fail "a ladder whose assignments sit on the same line as their braces did not fail the gate; the reindent dodge is not closed" \
        "$sameline_ladder"
    expect pass "reverting the same-line ladder did not clear the violation" \
        'int nothing(void) { return 0; }'
    expect pass "an innocuous multi-branch flag with no operator role was miscounted as a ladder" \
        "$innocuous_flag"
    expect pass "a single-branch flag that publishes to JSON was miscounted as a ladder" \
        "$no_ladder"
    expect pass "a long chain touching the bool only twice was miscounted as a ladder" \
        "$short_ladder"

    # The rename fixture must actually differ from the named one, or the
    # rename assertion above proved nothing. This is the mutation-applied
    # check the repo learned to demand: an edit that silently did not apply
    # reads exactly like "not detected".
    if [ "$renamed_ladder" = "$named_ladder" ]; then
        echo "$GATE: SELFTEST FAILED — the rename fixture is byte-identical to the named one; the rename-dodge assertion is hollow" >&2
        exit 2
    fi
    case "$renamed_ladder" in
        *operator_needed*)
            echo "$GATE: SELFTEST FAILED — the rename fixture still contains 'operator_needed'; the rename-dodge assertion is hollow" >&2
            exit 2 ;;
    esac
    # Same demand for the reindent fixture: it must actually be in the
    # same-line brace style, or that assertion is proving the ordinary case
    # twice over.
    case "$sameline_ladder" in
        *'{ word = '*) : ;;
        *)
            echo "$GATE: SELFTEST FAILED — the same-line fixture is not in the same-line brace style; the reindent-dodge assertion is hollow" >&2
            exit 2 ;;
    esac

    # The real consolidated surfaces must be clean, or this gate would be
    # passing only because its scan set does not reach them.
    for f in engine/controllers/src/api_controller_status.c \
             cognition/controllers/src/event_agent_summary.c; do
        if [ ! -f "$f" ]; then
            echo "$GATE: SELFTEST FAILED — $f is missing; the consolidated surfaces moved and this gate no longer watches them" >&2
            exit 2
        fi
        if [ -n "$(scan_counts "$f")" ]; then
            echo "$GATE: SELFTEST FAILED — $f still carries an inline ladder" >&2
            exit 2
        fi
    done

    echo "[$GATE] SELFTEST PASS (clean passes; named, renamed and same-line-brace ladders all fail; a vocabulary-only ladder fails; an innocuous multi-branch flag and a single-branch flag do not count; both consolidated surfaces are clean)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_STATUS_REASON_GATE_BASELINE:-tools/lint/status_reason_baseline.txt}"
CEILING="${ZCL_STATUS_REASON_GATE_CEILING:-$RATCHET_CEILING}"

# The canonical policy implementation, its table, and the test that pins it
# are excluded: they are the thing every other file is compared against, and
# their text necessarily names the vocabulary and the verdicts they own.
EXCLUDE_RE='(^|/)operator_needed_policy\.c$|(^|/)test_operator_needed_policy\.c$'

if [ -n "${ZCL_STATUS_REASON_GATE_SCAN_GLOB:-}" ]; then
    # Sandbox path (--selftest): a literal glob over a temp tree.
    # shellcheck disable=SC2206
    mapfile -t scan_files < <(ls -1 ${ZCL_STATUS_REASON_GATE_SCAN_GLOB} 2>/dev/null || true)
    FILE_FLOOR="${ZCL_STATUS_REASON_GATE_FILE_FLOOR:-1}"
else
    mapfile -t scan_files < <(git ls-files core engine contexts cognition platform \
        | grep -E '\.c$' | grep -Ev "$EXCLUDE_RE" || true)
    FILE_FLOOR="${ZCL_STATUS_REASON_GATE_FILE_FLOOR:-1500}"
fi

gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "no *.c files found under the five production authorities"

mapfile -t COUNT_ROWS < <(scan_counts "${scan_files[@]}")

declare -A BASELINED=()
gate_load_kv_file "$BASELINE" BASELINED
baseline_count="${#BASELINED[@]}"
baseline_sum=0
for path in "${!BASELINED[@]}"; do
    # Reject a non-numeric baseline value with `case` rather than a
    # line-based regex test: a stray value must not arithmetically expand.
    case "${BASELINED[$path]}" in
        ''|*[!0-9]*)
            echo "[$GATE] FATAL — baseline row '$path' has a non-numeric count '${BASELINED[$path]}' in $BASELINE" >&2
            exit 2 ;;
    esac
    baseline_sum=$(( baseline_sum + ${BASELINED[$path]} ))
done

declare -A HIT=()
violations=()
tolerated=()
total_ladders=0

for row in "${COUNT_ROWS[@]}"; do
    IFS=$'\t' read -r path debt <<< "$row"
    total_ladders=$(( total_ladders + debt ))
    allowed="${BASELINED[$path]:-}"
    if [ -n "$allowed" ]; then
        HIT["$path"]=1
        if [ "$debt" -le "$allowed" ]; then
            tolerated+=("$path ($debt/$allowed)")
            continue
        fi
        violations+=("$path — $debt inline ladder(s) found, baseline allows $allowed")
    else
        violations+=("$path — $debt inline ladder(s) found, not in the baseline (a new file may carry ZERO)")
    fi
done

# A baseline row whose file is now clean (or gone) must be deleted, or the
# ratchet rusts shut at a stale number.
stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path (baseline says ${BASELINED[$path]}, actual 0)")
done

# The baseline FILE's own recorded SUM may never exceed the ceiling this gate
# was introduced with. The only way to raise the ceiling is a change to the
# constant in this script — a visible source diff, not a quiet data-file edit.
if [ "$baseline_sum" -gt "$CEILING" ]; then
    echo ""
    echo "[$GATE] baseline sum ($baseline_sum) exceeds the ratchet ceiling ($CEILING)"
    echo "        in $BASELINE — the baseline was edited upward. Lower it back, or"
    echo "        lower RATCHET_CEILING in this script if the tolerated set has"
    echo "        genuinely grown (a change that belongs in code review, not a"
    echo "        quiet data-file edit)."
    violations+=("$BASELINE — baseline sum $baseline_sum exceeds ceiling $CEILING")
fi

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — files still carrying an inline operator-verdict"
        echo "# ladder instead of selecting an enum node_status_reason and reading"
        echo "# the verdict back from controllers/operator_needed_policy.def."
        echo "#"
        echo "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK."
        echo "#"
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for row in "${COUNT_ROWS[@]}"; do
            IFS=$'\t' read -r path debt <<< "$row"
            echo "$path $debt"
        done | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} violation(s) — a new or grown inline"
    echo "        operator-verdict ladder:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  One table decides this. Select an enum node_status_reason over your"
    echo "  own snapshot, then read status/summary/operator_needed back:"
    echo "    #include \"controllers/operator_needed_policy.h\""
    echo "    node_status_reason_status() / _summary() / _operator_needed()"
    echo "  Add a row to controllers/operator_needed_policy.def for a new reason."
    echo "  Never pass a literal that switches a rung off — a shared function"
    echo "  called with a conjunct-disabling literal is still two ledgers."
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer carries"
    echo "        an inline ladder. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} *.c files scanned, ${#COUNT_ROWS[@]} carrying a ladder, $total_ladders total, $baseline_count baselined file(s) summing to $baseline_sum/$CEILING, ${#tolerated[@]} tolerated, no allow-comment mechanism exists)"
