#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# selftest_scanner_immunity.sh — wf/dx-scanner-immunity regression proof.
#
# This is the gate-selftest-of-the-fix: it plants a transient lint-gate
# fixture file mid-"scan" (present while a PRODUCTION scan runs, exactly
# the race described in the bug report) into an isolated scan root, and
# proves:
#
#   1. A PRODUCTION scan (ZCL_LINT_PRODUCTION_SCAN=1, i.e. what `make lint`
#      / `make check-<gate>` / the dev-watch loop actually run) completely
#      IGNORES it — no false violation, no matter which gate's fixture it
#      is or which gate is scanning.
#   2. A SELFTEST-style direct invocation (no ZCL_LINT_PRODUCTION_SCAN, i.e.
#      what tests/harness/src/test_make_lint_gates.c does) still DETECTS it —
#      proving the exclusion mechanism does not weaken any gate's real
#      detection power.
#   3. A REAL violation in a file that does NOT match the shared
#      fixture-name convention still fails EVERY scan, production or not —
#      proving the exclusion is narrowly scoped to the fixture-name glob,
#      not a blanket "skip new files" hole.
#   4. `make lint`'s own stray-file gate (check_no_stray_untracked_source.sh)
#      ALSO leaves a fixture-named untracked file alone — this is the
#      literal "make lint while a selftest fixture is planted" scenario:
#      an untracked fixture is indistinguishable, from one filesystem
#      snapshot, from a currently-running selftest's live fixture, so this
#      gate must not flake on it either.
#   5. An untracked stray file with an ARBITRARY (non-fixture) name — the
#      other half of the bug: crashed-agent debris wedging `make lint` — is
#      named by check_no_stray_untracked_source.sh as "untracked stray file
#      (not a code violation)" with its exact path, distinguishable from a
#      real violation, rather than being silently treated as ordinary
#      source (or, worse, scanned by every OTHER gate as if it were real
#      committed code).
#
# Run standalone: ./tools/lint/selftest_scanner_immunity.sh
# Exits 0 iff every assertion above holds; prints which assertion failed
# otherwise. Cleans up all planted files unconditionally (trap on EXIT).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

GATE="tools/lint/check_silent_bool_errors.sh"
mkdir -p "$ROOT/.cache"
SCAN_ROOT="$(mktemp -d "$ROOT/.cache/scanner-immunity-selftest.XXXXXX")" || {
    echo "selftest_scanner_immunity: could not create isolated scan root" >&2
    exit 1
}
RACE_FIXTURE="$SCAN_ROOT/_x_fixture_tmp_.c"
REAL_VIOLATION="$SCAN_ROOT/_test_regression_real_violation_scanner_immunity.c"
STRAY_FILE="$SCAN_ROOT/_test_regression_stray_untracked_scanner_immunity.c"

cleanup() {
    rm -f "$RACE_FIXTURE" "$REAL_VIOLATION" "$STRAY_FILE"
    rmdir "$SCAN_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

# This script is ITSELF invoked as a `check-%` Make target (check-scanner-
# immunity), so the Makefile's `check-%: export ZCL_LINT_PRODUCTION_SCAN := 1`
# pattern rule means this script's OWN environment already has the var set
# when run via `make check-scanner-immunity`. Every "selftest-style" call
# below must explicitly CLEAR it (env -u) to faithfully simulate
# test_make_lint_gates.c's direct-exec invocation (no Make involved,
# therefore no ZCL_LINT_PRODUCTION_SCAN) regardless of how THIS script was
# itself launched.
run_selftest_style() {
    env -u ZCL_LINT_PRODUCTION_SCAN \
        ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST="$SCAN_ROOT" bash "$@"
}
run_production_style() {
    env ZCL_LINT_PRODUCTION_SCAN=1 \
        ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST="$SCAN_ROOT" bash "$@"
}

fail=0
note() { echo "  [selftest_scanner_immunity] $*"; }
assert_pass() {
    local desc="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        note "PASS: $desc"
    else
        note "FAIL: $desc (rc=$rc)"
        fail=1
    fi
}
assert_fail() {
    local desc="$1" rc="$2"
    if [ "$rc" -ne 0 ]; then
        note "PASS: $desc"
    else
        note "FAIL: $desc (rc=$rc, expected nonzero)"
        fail=1
    fi
}

echo "== 1/5: race-fixture content (violates check-silent-errors-bool) =="
cat > "$RACE_FIXTURE" <<'EOF'
/* Transient lint-gate selftest fixture — regression proof only, never
 * committed. Named _x_fixture_tmp_.c per the shared convention in
 * tools/lint/scan_exclusions.sh (basename contains "fixture"). */
#include <stdbool.h>
static bool fixture_fallible_call(void) { return true; }
bool _x_fixture_tmp_case(void)
{
    if (!fixture_fallible_call())
        return false;
    return true;
}
EOF

# Assertion 1: production scan (what make lint runs) is CLEAN despite the
# fixture sitting in a real scanned directory right now.
run_production_style "$GATE" >/tmp/scanner_immunity_prod.out 2>&1
prod_rc=$?
assert_pass "PRODUCTION scan (ZCL_LINT_PRODUCTION_SCAN=1) ignores the mid-scan fixture" "$prod_rc"
if [ "$prod_rc" -ne 0 ]; then
    note "  --- production scan output ---"
    sed 's/^/  /' /tmp/scanner_immunity_prod.out
fi

# Assertion 2: selftest-style direct invocation (no env var — exactly what
# test_make_lint_gates.c does) still DETECTS the SAME fixture. Detection is
# NOT weakened. Explicitly cleared (not just "unset in this script") because
# this script may itself be running under `make check-scanner-immunity`,
# which — being a check-% target — already has ZCL_LINT_PRODUCTION_SCAN=1 in
# ITS OWN environment.
run_selftest_style "$GATE" >/tmp/scanner_immunity_selftest.out 2>&1
selftest_rc=$?
assert_fail "SELFTEST-style invocation still detects the fixture (unweakened)" "$selftest_rc"
if [ "$selftest_rc" -eq 0 ]; then
    note "  --- selftest-style output (unexpected clean) ---"
    sed 's/^/  /' /tmp/scanner_immunity_selftest.out
fi

rm -f "$RACE_FIXTURE"

echo "== 2/5: a REAL violation (non-fixture name) still fails every mode =="
cat > "$REAL_VIOLATION" <<'EOF'
/* Deliberately NOT fixture-named (no "fixture" in the basename) — proves
 * the exclusion is scoped to the naming convention, not a blanket skip. */
#include <stdbool.h>
static bool real_fallible_call(void) { return true; }
bool _test_regression_real_violation_scanner_immunity_case(void)
{
    if (!real_fallible_call())
        return false;
    return true;
}
EOF

run_production_style "$GATE" >/tmp/scanner_immunity_real_prod.out 2>&1
real_prod_rc=$?
assert_fail "PRODUCTION scan still catches a REAL (non-fixture-named) violation" "$real_prod_rc"

run_selftest_style "$GATE" >/tmp/scanner_immunity_real_selftest.out 2>&1
real_selftest_rc=$?
assert_fail "SELFTEST-style scan still catches a REAL (non-fixture-named) violation" "$real_selftest_rc"

rm -f "$REAL_VIOLATION"

echo "== 3/5: gate recovers to clean once the real violation is removed =="
run_production_style "$GATE" >/tmp/scanner_immunity_recover.out 2>&1
recover_rc=$?
assert_pass "PRODUCTION scan is clean again after cleanup" "$recover_rc"

echo "== 4/5: 'make lint while a fixture is planted' stays clean (the stray gate itself) =="
# The exact scenario the task's gate #4 requires: an untracked fixture-named
# file sitting in a scanned dir (indistinguishable, from a filesystem
# snapshot, from a currently-running selftest's live fixture) must NOT
# itself wedge check_no_stray_untracked_source.sh — otherwise `make lint`
# would flake every time it raced a concurrently-running gate selftest.
cat > "$RACE_FIXTURE" <<'EOF'
/* Same race fixture as section 1, replanted to prove the STRAY gate
 * (not just check-silent-errors-bool) also leaves it alone. */
static void race_fixture_probe(void) {}
EOF
stray_with_fixture_out=$(
    ZCL_STRAY_SCAN_DIRS_FOR_TEST="$SCAN_ROOT" \
        bash tools/lint/check_no_stray_untracked_source.sh 2>&1
)
stray_with_fixture_rc=$?
assert_pass "check_no_stray_untracked_source.sh ignores an untracked fixture-named file" "$stray_with_fixture_rc"
if [ "$stray_with_fixture_rc" -ne 0 ]; then
    note "  --- unexpected stray-gate output ---"
    printf '%s\n' "$stray_with_fixture_out" | sed 's/^/  /'
fi
rm -f "$RACE_FIXTURE"

echo "== 5/5: untracked stray file is named distinctly, not as a code violation =="
cat > "$STRAY_FILE" <<'EOF'
/* Untracked stray file — simulates crashed-agent debris left in a scanned
 * dir. Content is deliberately clean (no violations) so ANY failure this
 * causes on check_no_stray_untracked_source.sh must come from being
 * untracked, not from its content. */
static void scanner_immunity_stray_probe(void) {}
EOF

stray_out=$(
    ZCL_STRAY_SCAN_DIRS_FOR_TEST="$SCAN_ROOT" \
        bash tools/lint/check_no_stray_untracked_source.sh 2>&1
)
stray_rc=$?
assert_fail "check_no_stray_untracked_source.sh fails on the untracked file" "$stray_rc"
if printf '%s\n' "$stray_out" | grep -q "$STRAY_FILE.*untracked stray file"; then
    note "PASS: output names '$STRAY_FILE' as an untracked stray file (not a code violation)"
else
    note "FAIL: output does not distinctly name the stray file:"
    printf '%s\n' "$stray_out" | sed 's/^/  /'
    fail=1
fi

rm -f "$STRAY_FILE"
stray_clean_rc=0
ZCL_STRAY_SCAN_DIRS_FOR_TEST="$SCAN_ROOT" \
    bash tools/lint/check_no_stray_untracked_source.sh \
    >/tmp/scanner_immunity_stray_clean.out 2>&1 || stray_clean_rc=$?
assert_pass "check_no_stray_untracked_source.sh is clean again after cleanup" "$stray_clean_rc"

echo ""
if [ "$fail" -eq 0 ]; then
    echo "selftest_scanner_immunity: ALL ASSERTIONS PASSED"
    exit 0
else
    echo "selftest_scanner_immunity: FAILED — see [FAIL] lines above"
    exit 1
fi
