#!/usr/bin/env bash
# Gate — supervisor PROGRESS-POLICY declaration (ratchet, shrink-only counts).
#
# What it enforces
# ----------------
# A supervised child publishes two different things:
#
#   supervisor_tick()     — "I ran."           (activity)
#   supervisor_progress() — "I got work done." (results)
#
# Only NO_PROGRESS detection reads the second one, and it is gated on
# `progress_max_quiet_us > 0`. That field zero-initializes, so "nobody
# decided" and "deliberately off" were the same value. Measured across the
# tree when this gate was written: ~40 call sites stored a literal 0 and
# three armed anything.
#
# The measurable consequence, on the canonical node 2026-07-28:
#
#   chain.op_return_backfill  ticks_run 13083  holes 13083  blocks_folded 0
#                             stall_reason "none"  stall_fires 0
#
# Thirteen thousand runs, zero results, self-reported healthy, feeding an
# index that held 0 rows. Nothing in the tree could have noticed, because
# nothing was looking at the only signal that would have said so.
#
# So every registered child must make the choice EXPLICIT — one of:
#
#   (a) ARMED  — supervisor_set_progress_max_quiet(id, <non-zero>), or a
#                direct non-zero store to <contract>.progress_max_quiet_us.
#                A frozen marker raises SUPERVISOR_STALL_NO_PROGRESS.
#   (b) EXEMPT — supervisor_set_progress_exempt(id, "why"). Detection off on
#                purpose, with a reason an operator reads in dumpstate. The
#                primitive refuses a blank reason, so this cannot be
#                satisfied with an empty string.
#
# Neither = UNDECLARED: tolerated only where this baseline already records
# it, and the recorded COUNT may only shrink.
#
# What this gate deliberately does NOT do
# ---------------------------------------
# It does not require ARMED. A pure sampler that publishes a gauge and
# produces no work units has no meaningful progress signal, and forcing a
# fake one on it would be worse than an honest exemption — the same reasoning
# as blocker_operator_decisions.def, where "a person must choose" is a
# CORRECT outcome rather than a gap to paper over. What is banned is having
# no answer at all.
#
# It also does not mass-arm the existing population. Arming ~40 children at
# once, on a node whose alarms an operator relies on, is a different and
# far riskier change than making the choice visible. This gate makes the debt
# countable and one-directional; the arming is per-service work, each with
# its own idle-vs-blocked distinction to get right (see
# engine/services/src/op_return_backfill_service.c for the worked example).
#
# Unit of measurement
# -------------------
# Per FILE: `liveness_contract_init(&VAR, "name")` counts a child; an ARMED
# or EXEMPT declaration counts a policy. A file's debt is
# max(0, children - policies). File granularity rather than per-child
# because a file with two contracts cannot be attributed in a shell scan
# without guessing which declaration belongs to which contract — and a gate
# that guesses is a gate that lies. Over-attribution is impossible in the
# safe direction: a file that declares a policy per child has debt 0.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# --selftest plants a fresh undeclared child in a sandbox copy and asserts
# the gate fails on it, so a gate that has quietly stopped detecting anything
# cannot report PASS.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_supervisor_progress_declared
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_SUPERVISOR_PROGRESS_BASELINE:-tools/lint/supervisor_progress_baseline.txt}"

SCAN_ROOTS_DEFAULT="core engine contexts cognition platform"
read -r -a SCAN_ROOTS <<< "${ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

# ── --selftest ───────────────────────────────────────────────────────────
# A ratchet that has silently stopped matching anything reports PASS forever
# and is worse than no gate, because it looks like coverage. Plant a fresh
# undeclared child in a sandbox and require a FAIL; then declare it and
# require a PASS, so the gate is shown to distinguish the two rather than
# merely to reject everything.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/engine/services/src"

    plant() { # $1 = extra declaration line (may be empty)
        cat > "$tmp/engine/services/src/selftest_service.c" <<EOF
#include "util/supervisor.h"
static struct liveness_contract g_c;
void selftest_register(void)
{
    liveness_contract_init(&g_c, "selftest.child");
    supervisor_child_id id = supervisor_register(&g_c);
    $1
}
EOF
    }

    # The gate cd's to the repo root, so the sandbox is reached by ABSOLUTE
    # scan root rather than by changing directory — otherwise the sandbox is
    # silently ignored and every case "passes" for the wrong reason.
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    run_sandbox() {
        ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS="$tmp/app" \
        ZCL_SUPERVISOR_PROGRESS_FILE_FLOOR=1 \
        ZCL_SUPERVISOR_PROGRESS_CHILD_FLOOR=1 \
        ZCL_SUPERVISOR_PROGRESS_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = expected rc class (fail|pass), $2 = message, $3 = decl
        local want="$1" msg="$2" decl="${3:-}" rc=0
        plant "$decl"
        run_sandbox || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    expect fail "an undeclared child did not fail the gate" ""
    expect pass "an ARMED child was still reported undeclared" \
        "supervisor_set_progress_max_quiet(id, 900000000);"
    expect pass "an EXEMPT child was still reported undeclared" \
        'supervisor_set_progress_exempt(id, "pure sampler, no work units");'
    # A literal-zero window is the non-decision this gate exists to count; it
    # must NOT satisfy the requirement, or the gate passes the original bug.
    expect fail "a literal-zero window counted as a policy" \
        "supervisor_set_progress_max_quiet(id, 0);"
    expect fail "a raw zero store counted as a policy" \
        "atomic_store(&g_c.progress_max_quiet_us, (int64_t)0);"
    expect pass "a raw NON-zero store was not recognised as armed" \
        "atomic_store(&g_c.progress_max_quiet_us, (int64_t)900000000);"

    echo "[$GATE] SELFTEST PASS (undeclared/zero-window/zero-store fail; armed, raw-armed and exempt pass)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
# Production source only. lib/test is excluded (fixtures register synthetic
# children on purpose, including deliberately-undeclared ones — the policy
# test in tests/harness/src/test_supervisor_progress_policy.c registers an
# UNDECLARED child by design to prove it stays silent). The supervisor
# primitive itself is excluded: it DEFINES these functions, it does not call
# them.
collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -type f -name '*.c' \
            ! -path 'tests/harness/include/test/*' \
            ! -path 'platform/modules/util/src/supervisor.c' \
            2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files)
gate_require_scanned "${#scan_files[@]}" "${ZCL_SUPERVISOR_PROGRESS_FILE_FLOOR:-200}" "$GATE" \
    "no production .c under: ${SCAN_ROOTS[*]}"

# ── Per-file children vs declarations ────────────────────────────────────
# Emits: path<TAB>children<TAB>policies
#
# A "policy" is counted for:
#   supervisor_set_progress_exempt(...)                  — EXEMPT
#   supervisor_set_progress_max_quiet(<id>, <non-zero>)  — ARMED
#   <x>.progress_max_quiet_us[,)] <non-zero>             — ARMED (raw store)
#
# A literal-zero argument in either arming form is NOT a policy: writing 0 is
# precisely the non-decision this gate exists to count. `(int64_t)0` and
# plain `0` both count as zero.
scan_counts() {
    awk '
        # Normalise the argument tail of a call into just its value.
        # Truncating at the FIRST ")" is wrong: it cuts a cast in half, so
        # "(int64_t)0)" became "(int64_t" and read as non-zero — which would
        # have let every raw zero store count as a decision, i.e. passed the
        # exact bug this gate exists to catch. Strip from the RIGHT instead.
        function value_of(s) {
            gsub(/[ \t]/, "", s)
            sub(/;+$/, "", s)
            sub(/\)+$/, "", s)
            gsub(/\(int64_t\)|\(int\)|\(long\)|\(longlong\)|\(uint64_t\)/, "", s)
            return s
        }
        function is_zero(s,   v) {
            v = value_of(s)
            return (v == "0" || v == "0L" || v == "0LL" || v == "0U" || v == "")
        }
        FNR == 1 { if (NR > 1) emit(); path = FILENAME; kids = 0; pol = 0 }
        {
            line = $0
            sub(/\/\*.*/, "", line)     # strip a trailing block-comment open
            sub(/\/\/.*/, "", line)     # and a line comment

            if (line ~ /liveness_contract_init[ \t]*\(/) kids++

            if (line ~ /supervisor_set_progress_exempt[ \t]*\(/) pol++

            if (match(line, /supervisor_set_progress_max_quiet[ \t]*\([^,]*,/)) {
                rest = substr(line, RSTART + RLENGTH)

                if (!is_zero(rest)) pol++
            }

            # Raw store:  atomic_store(&X.progress_max_quiet_us, VALUE);
            if (match(line, /progress_max_quiet_us[ \t]*,/)) {
                rest = substr(line, RSTART + RLENGTH)

                # A continuation line carries the value; treat an empty tail
                # as non-zero-unknown ONLY if the next line is not a bare 0.
                if (rest ~ /^[ \t]*$/) { pending = 1 }
                else if (!is_zero(rest)) pol++
                next
            }
            if (pending) {
                pending = 0
                v = line
                if (!is_zero(v)) pol++
            }
        }
        END { emit() }
        function emit() {
            if (path != "" && kids > 0)
                printf "%s\t%d\t%d\n", path, kids, pol
        }
    ' "${scan_files[@]}"
}

mapfile -t COUNT_ROWS < <(scan_counts)
gate_require_scanned "${#COUNT_ROWS[@]}" "${ZCL_SUPERVISOR_PROGRESS_CHILD_FLOOR:-30}" "$GATE" \
    "no liveness_contract_init() sites found — the scan or the registration API moved"

declare -A BASELINED=()
gate_load_kv_file "$BASELINE" BASELINED
baseline_count="${#BASELINED[@]}"

declare -A HIT=()
violations=()
tolerated=()
declared_files=0
total_children=0
total_debt=0

for row in "${COUNT_ROWS[@]}"; do
    IFS=$'\t' read -r path kids pol <<< "$row"
    total_children=$((total_children + kids))
    debt=$(( kids - pol ))
    [ "$debt" -lt 0 ] && debt=0
    if [ "$debt" -eq 0 ]; then
        declared_files=$((declared_files + 1))
        continue
    fi
    total_debt=$(( total_debt + debt ))
    allowed="${BASELINED[$path]:-}"
    if [ -n "$allowed" ]; then
        HIT["$path"]=1
        if [ "$debt" -le "$allowed" ]; then
            tolerated+=("$path")
            continue
        fi
        violations+=("$path — $debt undeclared child(ren), baseline allows $allowed")
    else
        violations+=("$path — $debt undeclared child(ren), not in the baseline")
    fi
done

# A baseline row whose file now declares everything (or no longer registers a
# child) must be deleted; otherwise the ratchet rusts shut at a stale number.
stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path")
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — files registering supervisor children with NO"
        echo "# progress-policy declaration (neither armed nor explicitly exempt)."
        echo "# Format: <path> <undeclared-count>.  COUNTS MAY ONLY SHRINK."
        echo "#"
        echo "# Fix a row by giving each child a policy at its register site:"
        echo "#   supervisor_set_progress_max_quiet(id, <window_us>)  — armed, or"
        echo "#   supervisor_set_progress_exempt(id, \"why it has no work units\")"
        echo "# then lower (or delete) the number here. Adding a row is not a fix."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for row in "${COUNT_ROWS[@]}"; do
            IFS=$'\t' read -r path kids pol <<< "$row"
            d=$(( kids - pol )); [ "$d" -lt 0 ] && d=0
            [ "$d" -gt 0 ] && echo "$path $d"
        done | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} file(s) register a supervised child with no"
    echo "        progress policy — nothing would notice it running forever"
    echo "        without achieving anything:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  At the register site, declare ONE of:"
    echo "   1. supervisor_set_progress_max_quiet(id, <window_us>) — ARMED."
    echo "      The child must then report supervisor_progress() when it does"
    echo "      work and supervisor_progress_idle() when it legitimately has"
    echo "      none. Do NOT report idle on an error or not-wired path: those"
    echo "      are exactly what the detector exists to catch."
    echo "   2. supervisor_set_progress_exempt(id, \"why\") — EXEMPT, for a"
    echo "      child with no meaningful unit of work (a pure sampler, a"
    echo "      gauge publisher). The reason is shown to operators verbatim;"
    echo "      a blank one is refused by the primitive."
    echo "  Worked example: engine/services/src/op_return_backfill_service.c"
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer has"
    echo "        undeclared children. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files, ${#COUNT_ROWS[@]} registering file(s), $total_children child(ren), $declared_files fully declared, $total_debt undeclared tolerated across ${#tolerated[@]} of $baseline_count baselined)"
