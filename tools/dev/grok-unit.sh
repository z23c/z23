#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# grok-unit.sh — dispatch ONE scoped unit of C23 work to grok, then judge the
# result here rather than believing the report.
#
# The bottleneck on landing generated code is not writing it, it is trusting
# it. So this script does what the model cannot do for itself:
#
#   1. Injects tools/dev/grok_c23_rules.md, the rules that actually cause
#      rejected work here. A model that has not read them writes -std=c23 on
#      a gcc 13 box, treats LOG_NULL as a print, and registers a test group
#      with nothing in it.
#   2. Runs the unit's test group and reads `groups_ran` -- a selector that
#      matches nothing prints groups_ran=0 and still EXITS 0.
#   3. Prints a verdict from what the gates said, never from what the model
#      said about itself.
#
# ── THREE MEASURED WAYS A GROK UNIT REPORTS SUCCESS HAVING DONE NOTHING ────
#
# All three end with exit 0 and an empty diff. Any harness that trusts the
# exit code accepts all three.
#
#   (a) --json-schema. A forced schema lets grok satisfy it on turn ONE with
#       a {"status":"starting..."} object, which ENDS THE TURN. The lane
#       exits 0 having written zero files, for about a cent. Measured 3 times
#       in 17 lanes by the qedc swarm on this same host; a prose warning not
#       to do it did NOT stop it. So this script NEVER passes --json-schema.
#       The JSON contract is asked for IN BAND, at the end of the prompt,
#       which has never shown the failure.
#   (b) --permission-mode acceptEdits. grok plans, narrates the plan, and
#       exits 0 without executing a single edit. Measured here 2026-08-29.
#       --always-approve is the mode that actually acts headlessly.
#   (c) A timeout with no handling. The unit is killed mid-thought, the log
#       ends on a planning sentence, and the caller sees a partial file set.
#       timeout returns 124 and this script says so out loud.
#
# ── Usage ─────────────────────────────────────────────────────────────────
#
#   tools/dev/grok-unit.sh --task FILE --group NAME [options]
#   tools/dev/grok-unit.sh --task FILE --no-group [options]
#
#   --task FILE     the unit of work, in prose. One job, named files, a bar.
#   --group NAME    the test group that must run and pass afterwards.
#   --no-group      for a unit that genuinely cannot have one (say so aloud).
#   --worktree NAME run in an isolated git worktree. STRONGLY PREFERRED when
#                   anything else is running: a lane editing the Makefile in
#                   the shared tree breaks other lanes' builds through the
#                   checkout lock, which serializes builds but not edits.
#   --model ID      grok model id.
#   --turns N       max agent turns (default 200; the swarm runs uncapped).
#   --timeout N     seconds before the unit is cut off (default 10800). A unit
#                   killed by the clock reports that, rather than looking green.
#   --dry-run       print the composed prompt and exit without calling grok.
#
# Exit: 0 unit landed and its group passed. 1 the unit failed honestly.
#       2 usage or setup error. Nothing here is ever "green by default".

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULES="$REPO_ROOT/tools/dev/grok_c23_rules.md"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23/grok"

TASK_FILE=""
GROUP=""
NO_GROUP=0
WORKTREE=""
MODEL=""
TURNS=200
TIMEOUT_S=10800
DRY_RUN=0

die() { printf '%s\n' "grok-unit: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --task)     TASK_FILE="${2:-}"; shift 2 ;;
        --group)    GROUP="${2:-}"; shift 2 ;;
        --no-group) NO_GROUP=1; shift ;;
        --worktree) WORKTREE="${2:-}"; shift 2 ;;
        --model)    MODEL="${2:-}"; shift 2 ;;
        --turns)    TURNS="${2:-}"; shift 2 ;;
        --timeout)  TIMEOUT_S="${2:-}"; shift 2 ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  sed -n '38,60p' "$0"; exit 0 ;;
        *)          die "unknown argument '$1'" ;;
    esac
done

[ -n "$TASK_FILE" ] || die "need --task FILE"
[ -f "$TASK_FILE" ] || die "task file not found: $TASK_FILE"
[ -f "$RULES" ]     || die "rules file missing: $RULES"
if [ -z "$GROUP" ] && [ "$NO_GROUP" -eq 0 ]; then
    die "need --group NAME, or --no-group if this unit truly cannot have one"
fi
command -v grok >/dev/null 2>&1 || die "grok is not on PATH"

mkdir -p "$STATE_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
unit="$(basename "$TASK_FILE" | sed 's/\.[^.]*$//')"
log="$STATE_DIR/${stamp}-${unit}.log"
prompt="$STATE_DIR/${stamp}-${unit}.prompt"
report="$STATE_DIR/${stamp}-${unit}.report"

# ── Where the work happens ────────────────────────────────────────────────
WORK_DIR="$REPO_ROOT"
if [ -n "$WORKTREE" ]; then
    WORK_DIR="$REPO_ROOT/../z23-lane-$WORKTREE"
    if [ ! -d "$WORK_DIR" ]; then
        git -C "$REPO_ROOT" worktree add -b "lane/$WORKTREE" "$WORK_DIR" HEAD \
            || die "could not create worktree $WORK_DIR"
        # Vendored archives are not tracked, so a fresh worktree cannot build
        # until they are primed. Skipping this produces a link failure that
        # looks like the unit's fault and is not.
        ( cd "$WORK_DIR" && make worktree-prime ) >>"$log" 2>&1 \
            || die "worktree-prime failed; see $log"
    fi
fi

# ── Compose the prompt ────────────────────────────────────────────────────
# Rules first: the top of a long prompt is read most reliably, and the rules
# are what keep the output landable. The JSON contract goes LAST and IN BAND
# -- see failure (a) above for why it is never a --json-schema flag.
{
    cat "$RULES"
    printf '\n\n# Your unit of work\n\n'
    cat "$TASK_FILE"
    printf '\n\n# How this unit will be judged\n\n'
    if [ "$NO_GROUP" -eq 0 ]; then
        printf 'After you finish, this exact command is run and must pass:\n'
        printf '    make t-fast ONLY=%s\n' "$GROUP"
        printf 'It must report a NON-ZERO groups_ran and the line ALL TESTS PASSED.\n'
        printf 'A groups_ran of 0 means your group is registered with nothing, and\n'
        printf 'counts as a failure no matter what the exit code says.\n\n'
    else
        printf 'This unit was dispatched without a test group. Say plainly in your\n'
        printf 'report what is therefore unverified.\n\n'
    fi
    printf 'Do NOT git commit and do NOT git push. Leave the work in the tree.\n\n'
    printf 'FINALLY, ONLY AFTER ALL WORK IS COMPLETE, print one JSON object\n'
    printf 'matching this shape and nothing after it:\n'
    printf '{"files_touched":["path"],"group":"name","groups_ran":0,'
    printf '"passed":false,"blocked":false,"premise_wrong":false,'
    printf '"not_done":"what you deliberately left alone","caveats":"..."}\n\n'
    printf 'Set premise_wrong true if the problem described did not exist. That\n'
    printf 'is a SUCCESSFUL outcome and is worth more than a change made to look\n'
    printf 'busy. Set blocked true if you stopped rather than weaken a check.\n'
} > "$prompt"

if [ "$DRY_RUN" -eq 1 ]; then
    cat "$prompt"
    exit 0
fi

# ── Dispatch ──────────────────────────────────────────────────────────────
printf 'grok-unit: %s\n' "$unit"
printf '  work dir: %s\n' "$WORK_DIR"
printf '  log:      %s\n' "$log"

# Be a good neighbour: this box is shared, and another swarm already drives
# load past 15. A unit that saturates it slows every lane including its own.
export ZCL_BUILD_JOBS="${ZCL_BUILD_JOBS:-6}"

set +e
grok_args=(--prompt-file "$prompt" --cwd "$WORK_DIR"
           --output-format json --max-turns "$TURNS"
           --always-approve)
[ -n "$MODEL" ] && grok_args+=(--model "$MODEL")
timeout --signal=INT "$TIMEOUT_S" grok "${grok_args[@]}" >>"$log" 2>&1
grok_rc=$?
set -e

if [ "$grok_rc" -eq 124 ]; then
    printf '  grok exit: TIMED OUT after %ss -- no report was written.\n' "$TIMEOUT_S"
else
    printf '  grok exit: %d\n' "$grok_rc"
fi

# The in-band JSON object, if it arrived. grok_report is a C tool over the
# in-tree JSON parser -- not jq, which this project does not depend on. It
# finds the report whether the engine emitted it as a real node or quoted it
# as text inside a message, and exits 1 when there is none. A unit that
# printed no report has usually done no work, so the absence is worth saying.
if [ -x "$REPO_ROOT/build/bin/grok_report" ] \
   || make -C "$REPO_ROOT" tools/dev/grok_report >/dev/null 2>&1; then
    if "$REPO_ROOT/build/bin/grok_report" "$log" > "$report" 2>/dev/null; then
        printf '  unit report (the model describing ITSELF -- a claim, not a result):\n'
        while IFS= read -r line; do printf '    %s\n' "$line"; done < "$report"
    else
        printf '  unit report: NONE -- the unit printed no closing report.\n'
    fi
fi

# ── Judge ─────────────────────────────────────────────────────────────────
# Deliberately not trusting grok_rc, and not trusting the report above
# either: both are the model describing itself. The gate is the test group.
if [ "$NO_GROUP" -eq 1 ]; then
    printf 'grok-unit: UNVERIFIED -- dispatched with --no-group. Read %s\n' "$log"
    exit 0
fi

verdict_log="$STATE_DIR/${stamp}-${unit}.verdict"
( cd "$WORK_DIR" \
  && ./tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
       make t-fast "ONLY=$GROUP" ) > "$verdict_log" 2>&1 || true

# Read the numbers, never the exit code.
ran="$(grep -a -oE 'groups_ran=[0-9]+' "$verdict_log" | tail -1 | cut -d= -f2)"
[ -n "${ran:-}" ] || ran=0
passed="$(grep -a -c 'ALL TESTS PASSED' "$verdict_log" || true)"
failed="$(grep -a -c 'SOME TESTS FAILED' "$verdict_log" || true)"

printf '  groups_ran=%s passed_token=%s failed_token=%s\n' "$ran" "$passed" "$failed"

if [ "$ran" -eq 0 ]; then
    printf 'grok-unit: FAIL -- group %s ran NOTHING. It is registered with no\n' "$GROUP"
    printf '  test, or the name is wrong. This is the hollow green this gate exists\n'
    printf '  to catch. See %s\n' "$verdict_log"
    exit 1
fi
if [ "$failed" -ne 0 ] || [ "$passed" -eq 0 ]; then
    printf 'grok-unit: FAIL -- group %s ran %s group(s) and did not pass.\n' "$GROUP" "$ran"
    printf '  See %s\n' "$verdict_log"
    exit 1
fi

printf 'grok-unit: PASS -- group %s ran %s group(s), all passed.\n' "$GROUP" "$ran"
printf '  Review the diff before committing: git -C %s diff\n' "$WORK_DIR"
exit 0
