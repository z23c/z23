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
exec "$(dirname "$0")/../../build/bin/z23-lint" check-stage-advances-or-blocks "$@"
