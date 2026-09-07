#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no NEW repair rung without a write-time-invariant test.
#
# The ratchet for TENACITY invariant I3 ("don't grow the repair ladder;
# fix the writer"). The recurring anchor-collapse wedge is a coin tear
# written by an import path that skips verification; the correct fix is a
# WRITE-TIME correctness gate, never another downstream heal/reconcile/
# backfill rung that re-derives the wrong state. The measured repair ladder
# is already ~9,153 LOC across ~24 files — the accumulation IS the smell.
#
# This gate makes the ladder shrink-only: a NEW file in app/ whose name
# marks it as a repair rung (repair / reconcile / backfill, or `heal` but
# not `health`) must either
#   - be listed in tools/scripts/repair_rung_baseline.txt (the grandfathered
#     existing ladder — entries are REMOVED as rungs are deleted, never
#     added), OR
#   - carry a per-file marker `// repair-rung-ok:<cite>` whose <cite> names
#     the write-time-invariant test that makes the rung unnecessary-to-trust
#     (e.g. `// repair-rung-ok:test_utxo_recovery_refuses_torn_import`).
#
# Anything else is a NEW unjustified rung and fails the gate. To clean up
# debt: delete a rung, remove its baseline line, re-run `make lint`.
#
# "health" is explicitly NOT a repair rung (it is observability), so
# *health*.c files are not matched.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-new-repair-rung "$@"
