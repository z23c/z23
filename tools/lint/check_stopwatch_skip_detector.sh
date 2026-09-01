#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_stopwatch_skip_detector.sh — runs the hermetic selftests of the two
# SHELL halves of the stopwatch skip-streak detector:
#   tools/scripts/stopwatch_skip_class.sh   (the class table parser + streak
#       arithmetic that the collector and the judge both source)
#   tools/scripts/stopwatch_evidence_judge.sh (the report line + the ALARM,
#       plus the 12 pre-existing verdict cases this feature must not move)
#
# Why a lint gate and not just a make target: the C half of this detector is
# covered by the test_stopwatch_skip_watch group, which `make test-parallel`
# runs on its own. The shell half had no automatic guard at all —
# `make stopwatch-judge-selftest` exists but nothing runs it, and a detector
# whose own regression proof nobody runs is the same shape of defect the
# detector exists to fix (a proof that quietly stops proving).
#
# Both selftests build canned ledgers under a mktemp dir. Neither touches the
# operator's real evidence ledgers, a live node, a systemd unit, or $HOME.
#
# FALSE-GREEN GUARD: rc 0 alone is not enough — each selftest must also print
# its own "selftest: PASS" line, so a script that silently no-ops (a renamed
# flag, an early exit) fails this gate instead of passing it.

set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0

run_selftest() {
    local script="$1" out rc
    if [ ! -r "$script" ]; then
        echo "FAIL: $script is missing — the skip-streak detector has no shell-side regression guard"
        fail=1
        return
    fi
    set +e
    out="$(bash "$script" --selftest 2>&1)"
    rc=$?
    set -e
    # Decide on the extracted PASS line, not on the pipeline's exit status:
    # under pipefail a matching `printf | grep -q` can report printf's SIGPIPE
    # 141 instead of grep's 0, so a self-test that really printed its PASS line
    # reads as if it had not. MEASURED 2026-07-30: the two transcripts are 699
    # and 1249 bytes, so the inversion is NOT reachable at that size — a shape
    # fix, not a live-bug fix, kept because a failing transcript is unbounded.
    # Same regex; without -q grep drains stdin so printf completes.
    local pass_line
    pass_line="$(printf '%s\n' "$out" | grep '^selftest: PASS' || true)"
    if [ "$rc" != "0" ] || [ -z "$pass_line" ]; then
        echo "FAIL: $script --selftest (rc=$rc; no 'selftest: PASS' line)"
        printf '%s\n' "$out"
        fail=1
        return
    fi
    echo "  ok: $script --selftest"
}

run_selftest tools/scripts/stopwatch_skip_class.sh
run_selftest tools/scripts/stopwatch_evidence_judge.sh

# The class table itself must remain parseable by BOTH consumers. The C side
# #includes it and would fail to compile on a malformed row; the shell side
# would silently parse zero rows and classify everything as unclassified, so
# assert a non-empty table here rather than discovering it in production.
DEF=engine/services/include/services/stopwatch_skip_classes.def
rows_in_file="$(grep -cE '^STOPWATCH_SKIP_(CLASS|FALLBACK)\(' "$DEF" 2>/dev/null || echo 0)"
rows_parsed="$(bash -c '. tools/scripts/stopwatch_skip_class.sh; stopwatch_skip_class_table' | grep -c '|')"
if [ "$rows_in_file" -lt 5 ] || [ "$rows_in_file" != "$rows_parsed" ]; then
    echo "FAIL: $DEF has $rows_in_file rows but the shell parser sees $rows_parsed"
    echo "      Every row must be ENTIRELY on one line — the parser is line-oriented."
    fail=1
else
    echo "  ok: $DEF — $rows_in_file class rows, parsed identically by the shell side"
fi

if [ "$fail" != 0 ]; then
    exit 1
fi
echo "check_stopwatch_skip_detector: clean — shell skip-streak detector selftests pass"
