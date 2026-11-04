#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Correct gate wrapper: lint then full suite, success keyed on ALL-TESTS-PASSED
# (never on grep matching a summary line — SOME-TESTS-FAILED matches too).
# Usage: gate-and-report.sh <lintlog> <testlog>
#
# Manual release-boundary tool — intentionally no in-repo caller. The
# Native cold-suite validation and a clean runner exit are the acceptance
# bar this wraps. Normal worker handoff uses focused acceptance;
# see docs/dev/DEVELOPING.md.
set -u
LINTLOG="${1:?lintlog}"; TESTLOG="${2:?testlog}"
cd "$(git rev-parse --show-toplevel)" || exit 3
if ! make lint >"$LINTLOG" 2>&1; then
  echo "GATE: LINT FAILED"; grep -iE "FAIL —|grew to|Error 1|violation" "$LINTLOG" | tail -8; exit 1
fi
echo "GATE: LINT OK"
# Full binary link — build-only compiles library objects but NOT engine/entry/main.c or
# the final binaries, so it cannot catch a broken entry point or a link gap.
if ! make -j"$(nproc)" >>"$LINTLOG" 2>&1; then
  echo "GATE: FULL BUILD FAILED"; grep -iE "error:|undefined reference|Error 1" "$LINTLOG" | tail -8; exit 1
fi
echo "GATE: FULL BUILD OK"
suite_rc=0
make test-parallel >"$TESTLOG" 2>&1 || suite_rc=$?
if [ "$suite_rc" -ne 0 ]; then
  echo "GATE: SUITE FAILED — runner exited $suite_rc"
  tail -20 "$TESTLOG"; exit 2
fi
# The existing C23 gate checks complete, unique and coherent suite fields,
# nonzero execution and the cold pass headline. It also rejects
# ALL TESTS PASSED (CACHED), failed groups and environment-unobserved runs.
if ! build/bin/z23-lint check-hosted-suite-verdict "$TESTLOG"; then
  echo "GATE: SUITE REJECTED — invalid cold-suite evidence (see native diagnostics)"
  exit 2
fi
echo "GATE: SUITE OK — native cold-suite evidence accepted"
exit 0
