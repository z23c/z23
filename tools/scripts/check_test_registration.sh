#!/usr/bin/env bash
# Lint gate — test-registration drift guard (HARD).
#
# THE BUG THIS PREVENTS (lane-3, 2026-06-22): three test entry points
# (test_refold_from_anchor_fatal, test_refold_auto_arm, test_anchor_selfmint)
# lived in dedicated tests/harness/src/test_<name>.c files, COMPILED and linked
# into the test binaries, yet were ABSENT from the canonical test group catalog
# (and not dispatched by the legacy serial runner
# tests/harness/src/test.c either). They therefore proved NOTHING — green forever,
# never executed. This gate makes that drift FAIL CI.
#
# ── CONVENTION (verified against the source) ──────────────────────────────
# A test "entry point" is the function that bears the SAME name as its
# dedicated file: tests/harness/src/test_<name>.c defining
#     int test_<name>(void)
# (with the body opener on its own line — the project style). Multi-test files
# (e.g. test_coins_amount_codec.c, test_models.c) and group files define helper
# / sub-test functions whose names do NOT match the host filename; those are
# deliberately NOT treated as entry points (no false positives on helpers).
#
# An entry point is "dispatched" (i.e. actually runs) iff its <name> is either
#   1. registered in tools/dev/test_group_catalog.def
#      (the `make test` parallel runner — the doctrine runner of record), OR
#   2. invoked as `test_<name>()` from the legacy serial runner test.c.
# Both runners link the same TEST_SRCS_NO_MAIN (Makefile:149), so a function
# dispatched by EITHER does run somewhere. A filename-matching entry point
# dispatched by NEITHER is an orphan: compiled but never executed.
#
# The catalog row ZCL_TEST_GROUP(foo) expands to the test_foo declaration and
# dispatch row in test_parallel.c and to the same full ID in native tooling.
#
# Fail-loud: grep exit >=2 (real error) aborts; an empty entry-point scan
# (convention drift) aborts — we never report "clean" off a broken scan.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-test-registration "$@"
