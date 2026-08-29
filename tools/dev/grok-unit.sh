#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# grok-unit.sh — dispatch ONE scoped unit of C23 work to grok, then judge the
# result here rather than believing the report.
#
# The bottleneck on landing generated code is not writing it, it is trusting
# it. So this script does three things the model cannot do for itself:
#
#   1. Injects tools/dev/grok_c23_rules.md, which is the list of rules that
#      actually cause rejected work here. A model that has not read them
#      writes -std=c23, treats LOG_NULL as a print, and leaves a test file
#      registered with nothing.
#   2. Runs the unit against a REQUIRED test group, and reads `groups_ran=`
#      rather than the exit code -- a selector matching nothing exits 0.
#   3. Prints a verdict from what the gates said, not from what the model
#      said about itself.
#
# Usage:
#   tools/dev/grok-unit.sh --task FILE --group NAME [options]
#   tools/dev/grok-unit.sh --task FILE --no-group [options]
#
#   --task FILE     the unit of work, in prose. One job, named files, a bar.
#   --group NAME    the test group that must run and pass afterwards.
#   --no-group      for a unit that genuinely cannot have one (say so aloud).
#   --worktree NAME run in an isolated git worktree, so lanes do not collide.
#   --model ID      grok model id.
#   --turns N       max agent turns (default 60).
#   --timeout N     seconds before the unit is cut off (default 3600). A unit
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
TURNS=60
# A unit that never returns is worse than one that fails: it holds a lane and
# says nothing. Bound it, and treat the timeout as its own honest verdict.
TIMEOUT_S=3600
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
        -h|--help)  sed -n '5,30p' "$0"; exit 0 ;;
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

# ── Where the work happens ────────────────────────────────────────────────
# A worktree keeps concurrent lanes from editing the same files. It costs a
# prime step for vendored libraries; without it the build fails in a way that
# looks like the unit's fault and is not.
WORK_DIR="$REPO_ROOT"
if [ -n "$WORKTREE" ]; then
    WORK_DIR="$REPO_ROOT/../z23-lane-$WORKTREE"
    if [ ! -d "$WORK_DIR" ]; then
        git -C "$REPO_ROOT" worktree add -b "lane/$WORKTREE" "$WORK_DIR" HEAD \
            || die "could not create worktree $WORK_DIR"
        ( cd "$WORK_DIR" && make worktree-prime ) >>"$log" 2>&1 \
            || die "worktree-prime failed; see $log"
    fi
fi

# ── Compose the prompt ────────────────────────────────────────────────────
# Rules first: a model reads the top of a long prompt most reliably, and the
# rules are what keep the output landable.
{
    cat "$RULES"
    printf '\n\n# Your unit of work\n\n'
    cat "$TASK_FILE"
    printf '\n\n# How this unit will be judged\n\n'
    if [ "$NO_GROUP" -eq 0 ]; then
        printf 'After you finish, this exact command is run and must pass:\n'
        printf '    build/bin/test_parallel --only=%s\n' "$GROUP"
        printf 'It must report a NON-ZERO groups_ran and the line ALL TESTS PASSED.\n'
        printf 'A groups_ran of 0 means your group is registered with nothing, and\n'
        printf 'counts as a failure no matter what the exit code says.\n\n'
    else
        printf 'This unit was dispatched without a test group. Say plainly in your\n'
        printf 'report what is therefore unverified.\n\n'
    fi
    printf 'Do NOT git commit and do NOT git push. Leave the work in the tree.\n'
    printf 'Report, briefly: files touched, the exact groups_ran and pass line,\n'
    printf 'and anything you found wrong that you deliberately did not change.\n'
} > "$prompt"

if [ "$DRY_RUN" -eq 1 ]; then
    cat "$prompt"
    exit 0
fi

# Headless units need --always-approve: with --permission-mode acceptEdits
# grok plans, then exits 0 having written nothing -- a hollow success that
# only the verdict below catches. The rules file, not the permission mode, is
# what keeps a unit away from the live node.
# ── Dispatch ──────────────────────────────────────────────────────────────
printf 'grok-unit: %s\n' "$unit"
printf '  work dir: %s\n' "$WORK_DIR"
printf '  log:      %s\n' "$log"

set +e
grok_args=(--prompt-file "$prompt" --cwd "$WORK_DIR"
           --output-format plain --max-turns "$TURNS"
           --always-approve)
[ -n "$MODEL" ] && grok_args+=(--model "$MODEL")
timeout --signal=INT "$TIMEOUT_S" grok "${grok_args[@]}" >>"$log" 2>&1
grok_rc=$?
set -e

if [ "$grok_rc" -eq 124 ]; then
    printf "  grok exit: TIMED OUT after %ss -- no report was written.\n" "$TIMEOUT_S"
else
    printf "  grok exit: %d\n" "$grok_rc"
fi

# ── Judge ─────────────────────────────────────────────────────────────────
# Deliberately not trusting grok_rc: a model can exit 0 having done nothing,
# or having decided the task was impossible. The gate is the test group.
if [ "$NO_GROUP" -eq 1 ]; then
    printf 'grok-unit: UNVERIFIED -- dispatched with --no-group. Read %s\n' "$log"
    exit 0
fi

verdict_log="$STATE_DIR/${stamp}-${unit}.verdict"
( cd "$WORK_DIR" \
  && ./tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
       make test_parallel ) > "$verdict_log" 2>&1
build_rc=$?
if [ "$build_rc" -ne 0 ]; then
    printf 'grok-unit: FAIL -- the tree does not build. See %s\n' "$verdict_log"
    exit 1
fi

( cd "$WORK_DIR" && build/bin/test_parallel --only="$GROUP" ) \
    >> "$verdict_log" 2>&1 || true

# Read the numbers, never the exit code. `--only` on an unknown group prints
# groups_ran=0 and exits 0, which is the exact shape of a hollow green.
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
