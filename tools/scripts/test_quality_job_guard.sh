#!/usr/bin/env bash
# Hermetic regression test for quality_job_guard.sh + log retention.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-quality-guard.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/scripts" "$TMP/bin" "$TMP/state/logs" "$TMP/state/status"
cp "$SCRIPT_DIR/quality_job_guard.sh" "$TMP/scripts/"
cp "$SCRIPT_DIR/quality_log_retention.sh" "$TMP/scripts/"
chmod +x "$TMP/scripts/quality_job_guard.sh" "$TMP/scripts/quality_log_retention.sh"

printf '%s\n' \
    '#!/bin/sh' \
    'printf "background:%s\n" "$1" >> "$QUALITY_GUARD_CALLS"' \
    > "$TMP/scripts/background_quality_lane.sh"
printf '%s\n' \
    '#!/bin/sh' \
    'printf "simnet\n" >> "$QUALITY_GUARD_CALLS"' \
    > "$TMP/scripts/simnet_nightly.sh"
printf '%s\n' \
    '#!/bin/sh' \
    'case "${FAKE_SYSTEMCTL_MODE:-inactive}" in' \
    '  active) printf "%s\n" "zclassic23-mint-receipt.service loaded active running mint" ;;' \
    '  inactive) exit 0 ;;' \
    '  fail) exit 1 ;;' \
    'esac' \
    > "$TMP/bin/systemctl"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$TMP/bin/logger"
chmod +x "$TMP/scripts/background_quality_lane.sh" \
    "$TMP/scripts/simnet_nightly.sh" "$TMP/bin/systemctl" "$TMP/bin/logger"

GUARD="$TMP/scripts/quality_job_guard.sh"
CALLS="$TMP/calls"
export QUALITY_GUARD_CALLS="$CALLS"
export ZCL_QUALITY_STATE_DIR="$TMP/state"
export ZCL_QUALITY_LOG_KEEP=4
export ZCL_QUALITY_LOG_MAX_BYTES=1048576
export PATH="$TMP/bin:/usr/bin:/bin"

for i in $(seq -w 1 12); do
    log="$TMP/state/logs/fuzz-2026-07-14T${i}0000Z.log"
    printf 'fixture %s\n' "$i" > "$log"
    TZ=UTC touch -t "2026071400${i}.00" "$log"
done
printf 'test fixture\n' > "$TMP/state/logs/tests-2026-07-14T000000Z.log"
printf '{"status":"fixture"}\n' > "$TMP/state/status/fuzz.json"
ln -s /etc/passwd "$TMP/state/logs/fuzz-symlink.log"

FAKE_SYSTEMCTL_MODE=active "$GUARD" fuzz > "$TMP/active.out" 2>&1
grep -q 'SKIP lane=fuzz reason=mint_unit_active:zclassic23-mint-receipt.service' "$TMP/active.out"
[ ! -e "$CALLS" ]
[ "$(find "$TMP/state/logs" -maxdepth 1 -type f -name 'fuzz-*.log' | wc -l)" -eq 12 ]

FAKE_SYSTEMCTL_MODE=fail "$GUARD" coverage > "$TMP/fail.out" 2>&1
grep -q 'SKIP lane=coverage reason=mint_query_failed' "$TMP/fail.out"
[ ! -e "$CALLS" ]

"$TMP/scripts/quality_log_retention.sh" fuzz
[ "$(find "$TMP/state/logs" -maxdepth 1 -type f -name 'fuzz-*.log' | wc -l)" -eq 4 ]
[ -f "$TMP/state/logs/fuzz-2026-07-14T120000Z.log" ]
[ -f "$TMP/state/logs/tests-2026-07-14T000000Z.log" ]
[ -L "$TMP/state/logs/fuzz-symlink.log" ]
grep -q '"status":"fixture"' "$TMP/state/status/fuzz.json"

# Count is below KEEP, but aggregate bytes exceed the lane cap. Sparse files
# make the size policy hermetic without writing megabytes. The newest verdict
# must survive even when it alone is larger than the cap.
for i in 1 2 3; do
    log="$TMP/state/logs/coverage-2026-07-14T0${i}0000Z.log"
    truncate -s 600000 "$log"
    TZ=UTC touch -t "20260714010${i}.00" "$log"
done
"$TMP/scripts/quality_log_retention.sh" coverage
[ "$(find "$TMP/state/logs" -maxdepth 1 -type f -name 'coverage-*.log' | wc -l)" -eq 1 ]
[ -f "$TMP/state/logs/coverage-2026-07-14T030000Z.log" ]

FAKE_SYSTEMCTL_MODE=inactive "$GUARD" tests
grep -qx 'background:tests' "$CALLS"

FAKE_SYSTEMCTL_MODE=inactive "$GUARD" simnet-nightly
tail -n 1 "$CALLS" | grep -qx 'simnet'

set +e
FAKE_SYSTEMCTL_MODE=inactive "$GUARD" unknown > "$TMP/invalid.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 64 ]

grep -Fq 'quality_job_guard.sh fuzz' "$ROOT/deploy/zclassic23-fuzz.service"
grep -Fq 'quality_job_guard.sh tests' "$ROOT/deploy/zclassic23-test-suite.service"
grep -Fq 'quality_job_guard.sh coverage' "$ROOT/deploy/zclassic23-coverage.service"
grep -Fq 'quality_job_guard.sh simnet-nightly' "$ROOT/deploy/zclassic23-simnet-nightly.service"

set +e
ZCL_QUALITY_LOG_MAX_BYTES=0 "$TMP/scripts/quality_log_retention.sh" fuzz \
    > "$TMP/invalid-bytes.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 64 ]

echo 'quality-job-guard selftest: PASS'
