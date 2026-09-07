#!/usr/bin/env bash
# Lint gate — no UNCITED victory claim in the one live-state page (HARD).
#
# WHY THIS EXISTS: this repo shipped 9+ "cured / at tip / fully synced" claims
# in six weeks, every one later false, and the owner counted ~103 "wedge FIXED"
# -> re-wedge cycles. A victory sentence with no machine-checkable evidence next
# to it is how a stale narrative outlives the node it describes. This gate makes
# an uncited victory claim in docs/HANDOFF.md (the SINGLE live-state page) fail
# `make lint`, so a "cured" claim cannot land without an evidence token or an
# explicit historical override.
#
# RULE: split docs/HANDOFF.md into blank-line-delimited paragraphs. A paragraph
# that contains a VICTORY PHRASE (case-insensitive, word-bounded) —
#   "at tip", "at-tip", "reaches tip", "holds tip", "fully synced", "cured",
#   "unwedged", "wedge cleared", "wedge closed", "wedge fixed",
#   "soak window open", "soak window running", "proven live", "live-proven",
#   "stable at tip"
# FAILS unless the SAME paragraph also carries a CITATION TOKEN:
#   "uptime-ledger", "slo-summary:", "VERDICT=PASS", "WALL_CLOCK_SECONDS",
#   "gap_vs_oracle", a `ts=<digits>` / `"ts": <digits>` stamp, or the explicit
#   per-paragraph override  <!-- victory-ok: <reason> -->  (for narrating a
#   HISTORICAL event only; never a current-state claim).
#
# HOLLOW-GATE RULE: docs/HANDOFF.md missing or < 10 lines = FAIL (the scan set
# must be non-empty, or an uncited claim could hide in a stubbed-out page).
#
# Standalone-runnable. Hermetic --selftest below. Fast: file read + grep only.
# Test hook: ZCL_LINT_MODE, when it points at an existing file, overrides the
# scanned doc (the C harness's run_gate_script passes its 2nd arg as
# ZCL_LINT_MODE); production `make lint` never sets it, so the real
# docs/HANDOFF.md is scanned.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-uncited-victory "$@"
