#!/usr/bin/env bash
# Lint gate E5 — Job stages advance OR block; they never silently spin (HARD).
#
# A Job (engine/jobs/src/*_stage.c) is the single-purpose, idempotent step
# function the supervisor ticks. The Job contract (FRAMEWORK.md §3) is that
# every step is honest about non-progress: when it cannot move the chain it
# must surface the blocked/idle outcome AND it must reason about a cursor (the
# stage's position in the log). A step that can ONLY return JOB_ADVANCED, or
# that never references a cursor, is the silent-halt anti-pattern — it spins
# forward with no way to say "I am stuck and here is the position I am stuck
# at."
#
# Scope: every engine/jobs/src/*.c that is a Job step — i.e. it either calls
# stage_create(...) (registers a stage with the kernel) or defines a
# `job_result_t <name>_step*(...)` entry point. Each such file MUST contain:
#
#   1. at least one JOB_BLOCKED or JOB_IDLE return — the honest non-progress
#      outcome; and
#   2. at least one cursor reference — one of `cursor_out`, `c->cursor_in`,
#      or `stage_cursor` — proving the step reasons about its log position.
#
# The current 8 stages all satisfy both, so this gate runs HARD: any Job step
# file missing either property fails immediately.
#
# Override: a Job step that legitimately cannot block (none exist today) may
# carry a file-level `// stage-advance-ok:<tag>` marker (no space after the
# colon, non-empty tag) on any line.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Jobs dir is overridable via ZCL_JOBS_DIR so the lint-gate self-test can point
# the gate at an EMPTY dir and prove the non-empty-floor preflight fires.
JOBS_DIR="${ZCL_JOBS_DIR:-engine/jobs/src}"
# The production tree has at least 8 Job step files; a registration/convention
# rename that drops them all (build green via Makefile glob) would empty the
# checked set and pass hollow. Pin a floor of 8 for the real dir; a test
# override has no such population requirement (floor 0 — the empty-dir check
# below catches the JOBS_DIR-missing case separately).
JOB_STEP_FLOOR=8
[ -n "${ZCL_JOBS_DIR:-}" ] && JOB_STEP_FLOOR=0

fail=0
violations=()

file_overridden() {
    grep -qE '//[[:space:]]*stage-advance-ok:[A-Za-z][A-Za-z0-9_-]*' "$1"
}

is_job_step_file() {
    grep -qE 'stage_create[[:space:]]*\(|job_result_t[[:space:]]+[a-z0-9_]+_step' "$1"
}

if [ ! -d "$JOBS_DIR" ]; then
    echo "check_stage_advances_or_blocks: FATAL — $JOBS_DIR not found." >&2
    echo "  The Job step dir was renamed/moved. Refusing to pass hollow." >&2
    exit 2
fi

# Fail-loud preflight: the *.c file set under JOBS_DIR must be non-empty. An
# empty find result (a moved dir, despite -d above passing on a now-empty dir)
# would skip the loop and pass hollow.
mapfile -t scan_files < <(find "$JOBS_DIR" -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
gate_require_scanned "${#scan_files[@]}" 1 check_stage_advances_or_blocks \
    "no *.c under '$JOBS_DIR'"

checked=0
for f in "${scan_files[@]}"; do
    is_job_step_file "$f" || continue
    file_overridden "$f" && continue
    checked=$((checked + 1))

    if ! grep -qE 'JOB_BLOCKED|JOB_IDLE' "$f"; then
        violations+=("$f: Job step never returns JOB_BLOCKED/JOB_IDLE — it can only advance, so it has no way to surface a stall")
        fail=1
    fi
    if ! grep -qE 'cursor_out|c->cursor_in|stage_cursor' "$f"; then
        violations+=("$f: Job step references no cursor (cursor_out / c->cursor_in / stage_cursor) — it does not reason about its log position")
        fail=1
    fi
done

# Fail-loud: at least JOB_STEP_FLOOR step files must have MATCHED is_job_step_file.
# If a registration/convention rename (stage_create( / _step) drops every file,
# `checked` falls to 0 and the gate would print "clean — all 0 ... files" exit 0
# — a hollow pass that defeats the gate's entire purpose. Pin the known floor.
gate_require_scanned "$checked" "$JOB_STEP_FLOOR" check_stage_advances_or_blocks \
    "matched 0/$checked Job step files under '$JOBS_DIR' — was stage_create(/_step renamed?"

if [ "$fail" = "0" ]; then
    echo "check_stage_advances_or_blocks: clean — all $checked Job step file(s) advance-or-block with a cursor reference"
    exit 0
fi

echo ""
echo "check_stage_advances_or_blocks: ${#violations[@]} Job-contract violation(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "A Job step (engine/jobs/src/*_stage.c) must be honest about non-progress:"
echo "  1. Return JOB_BLOCKED or JOB_IDLE on any non-advancing path (never"
echo "     spin forward silently)."
echo "  2. Reference a cursor (cursor_out / c->cursor_in / stage_cursor) so"
echo "     the stall is anchored to a log position."
echo "  3. For a Job that genuinely cannot block, add a file-level"
echo "     '// stage-advance-ok:<tag>' marker (no exemptions exist today)."
exit 1
