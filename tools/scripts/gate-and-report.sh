#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Correct gate wrapper: lint then full suite, success keyed on ALL-TESTS-PASSED
# (never on grep matching a summary line — SOME-TESTS-FAILED matches too).
# Usage: gate-and-report.sh <lintlog> <testlog>
#
# Manual release-boundary tool — intentionally no in-repo caller. The
# PASS-TOKEN and complete suite accounting, never a substring match, are the
# acceptance bar this wraps. Normal worker handoff uses focused acceptance;
# see docs/DEVELOPING.md.
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
make test-parallel >"$TESTLOG" 2>&1
# A green token is NOT enough. The runner prints the same "ALL TESTS PASSED"
# whether it executed every group or returned almost all of them from the
# content-addressed cache, so this gate reads the machine-greppable
# `SUITE VERDICT` line and refuses anything that did not actually run cold.
VERDICT="$(grep -E '^SUITE VERDICT ' "$TESTLOG" | tail -1)"
if [ -z "$VERDICT" ]; then
  echo "GATE: SUITE FAILED — no SUITE VERDICT line (runner too old, or the run died before reporting)"
  tail -20 "$TESTLOG"; exit 2
fi
echo "GATE: $VERDICT"
if grep -q "ALL TESTS PASSED (CACHED)" "$TESTLOG"; then
  echo "GATE: SUITE REJECTED — this run was CACHED, not cold. A cached run proves"
  echo "      only that nothing downstream of the cached groups changed; it is not"
  echo "      a gate. Re-run with: make test-parallel TEST_PARALLEL_ARGS=--no-cache"
  exit 2
fi
case "$VERDICT" in
  *" mode=cold "*) : ;;
  *) echo "GATE: SUITE REJECTED — mode is not cold: $VERDICT"; exit 2 ;;
esac
if grep -q "ALL TESTS PASSED" "$TESTLOG" && ! grep -q "SOME TESTS FAILED" "$TESTLOG"; then
  echo "GATE: SUITE OK — $(grep -E 'ALL TESTS PASSED' "$TESTLOG" | tail -1)"; exit 0
fi
echo "GATE: SUITE FAILED — $(grep -E 'SOME TESTS FAILED' "$TESTLOG" | tail -1)"
grep -B1 "FAIL," "$TESTLOG" | grep "====" | head -12
exit 2
