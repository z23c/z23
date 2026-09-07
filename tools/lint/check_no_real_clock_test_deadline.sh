#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_real_clock_test_deadline.sh — refuse, in tests/harness/src/*.c, an
# assertion or a hand-timed retry loop whose PASS/FAIL depends on a reading of
# a real clock, unless the line carries a reviewed `/* real-clock: <reason>
# */` marker.
#
# ── WHY A SEPARATE GATE FROM check_no_wallclock_assertion.sh ──────────────
# check_no_wallclock_assertion.sh already refuses an ASSERT/CHECK graded on a
# measured clock INTERVAL, tree-wide, with a shrink-only baseline file and
# (deliberately) no per-line escape hatch. It also documents its own biggest
# blind spot in its header: "IT DOES NOT SEE A FIXED-ITERATION RETRY LOOP...
# test_onion_bootstrap.c polled `for (i = 0; i < 90; i++) { if (ready) break;
# sleep(1); }` ... FAILED inside a full gate run and PASSED standalone". That
# is exactly the shape that cost this project two thrown-away proofs on
# 2026-09-04: a group whose own poll-for-done loop used a fixed iteration
# count as a real-clock deadline surrogate, and failed only under a
# contended, 8-worker pool.
#
# So this gate closes that specific blind spot — a sleep/usleep/nanosleep
# call inside a loop bounded by a fixed iteration count, i.e. "poll N times,
# sleeping between each" used as a real-clock deadline — over the harness's
# own registered-group sources (tests/harness/src/*.c), and it uses a
# PER-LINE marker rather than a baseline file: unlike the tree-wide
# assertion-interval case, the fix here is usually "raise the poll budget
# with a documented reason" (see 3469d44f6), which is a one-line, reviewed,
# self-documenting change — a baseline row a reviewer never re-reads is the
# worse fit for it.
#
# It also independently (and more narrowly) polices the direct clock-in-
# assertion shape named in the same spirit — an ASSERT/CHECK/EXPECT/REQUIRE
# macro whose argument reads a real clock (clock_gettime, gettimeofday,
# time(NULL)/time(0), or this tree's platform_time_* / clock_now_* readers) —
# over the same tests/harness/src/*.c scope, so the harness's own sources
# have ONE marker-driven gate for "this line's verdict rides on a real clock"
# rather than two different remediation stories depending on shape.
#
# ── WHAT COUNTS ────────────────────────────────────────────────────────────
#   (A) ASSERT*/EXPECT*/REQUIRE*/*CHECK(...) whose balanced-paren argument
#       text calls a real-clock reader: clock_gettime, gettimeofday, time(
#       NULL|0), platform_time_monotonic_timespec, platform_time_wall_time_t,
#       platform_time_monotonic_ms, platform_now_* (any name with that
#       prefix), clock_now_monotonic_ns, clock_now_wall_ms, difftime.
#   (B) sleep(/usleep(/nanosleep(/platform_sleep_ms( appearing inside a
#       for/while loop whose own header compares its counter against a fixed
#       numeric bound on the same line as the loop's opening brace (this
#       tree's house style) — the "poll N times" idiom.
#
# Both are refused UNLESS the exact source line carries the marker
# `/* real-clock: <reason> */` (a non-empty reason is required — a bare
# marker documents nothing and is refused just like a missing one).
#
# ── WHAT THIS GATE CANNOT DO (stated plainly) ─────────────────────────────
#   * (A) is a single balanced-paren join per assertion, not the full
#     cross-function taint fixpoint check_no_wallclock_assertion.sh runs —
#     an interval built from a LOCAL VARIABLE that was itself assigned from a
#     reader on an earlier line is invisible here (that shape is exactly what
#     the tree-wide gate exists for; this gate is the narrower, marker-driven
#     complement for tests/harness/src/*.c, not a replacement).
#   * (B) requires the loop header and its opening `{` on ONE physical line
#     (this tree's house style everywhere it was checked) and the sleep call
#     literally inside that same brace-delimited body; a multi-line header or
#     a sleep call reached only through a helper function is invisible.
#   * Comments and string literals are stripped before matching, so a marker
#     can only ever appear as what it actually is: a real, visible comment.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-real-clock-test-deadline "$@"
