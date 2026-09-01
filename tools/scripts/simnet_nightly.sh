#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Wave-2 lane B2: nightly simulator sweep driver, invoked by
# platform/deploy/zclassic23-simnet-nightly.service (systemd --user timer). Mirrors
# tools/scripts/background_quality_lane.sh's structure (dated log under a
# state dir, PASS/FAIL summary, exit code == rc of the sweep) but stays
# POSIX sh — no bash-isms, no python (project ban), so it runs under any
# systemd ExecStart shell.
#
# Composes ONLY existing make machinery (`make simnet-nightly`, and
# optionally the longer `make simnet-fuzz-sweep`) — no new harness, no new
# binary. Both targets are fixed/seeded and terminate; see the Makefile
# comment above `simnet-nightly:` for what each step does and why
# `make chaos` is deliberately NOT part of `make ci` (build-cost, not
# run-cost — the corpus itself replays in ~1.6s once the binary exists).
#
# The byzantine `honest=` cluster-sweep step, the ZCL_UTXO_LADDER_HEAVY
# dense-MMB recompute, and the golden-table tip-coverage-lag check all live
# inside `make simnet-nightly` itself (see the Makefile comment above
# `simnet-nightly:`) — nothing extra needed here, this driver just calls
# that one target.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$ROOT"

STATE_ROOT="${ZCL_QUALITY_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-quality}"
LOG_DIR="$STATE_ROOT/logs"
STATUS_DIR="$STATE_ROOT/status"

mkdir -p "$LOG_DIR" "$STATUS_DIR"

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
epoch_now() { date -u '+%s'; }

git_commit() {
    git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown'
}

# Run the LONGER wire_sweep seed sweep too when explicitly requested. Off
# by default so a plain invocation stays bounded to `make simnet-nightly`'s
# own budget (chaos corpus + 2000-seed wire-sweep + sim-fast, all measured
# well under a few minutes); the timer sets ZCL_SIMNET_NIGHTLY_FUZZ_SWEEP=1
# once the operator wants the longer nightly tail too.
RUN_FUZZ_SWEEP="${ZCL_SIMNET_NIGHTLY_FUZZ_SWEEP:-0}"

STARTED=$(utc_now)
STARTED_EPOCH=$(epoch_now)
STAMP=$(printf '%s' "$STARTED" | tr -d ':')
LOG="$LOG_DIR/simnet-nightly-${STAMP}.log"

{
    printf 'simnet_nightly: started=%s commit=%s fuzz_sweep=%s\n' \
        "$STARTED" "$(git_commit)" "$RUN_FUZZ_SWEEP"
} | tee -a "$LOG"

rc=0

echo "==> make simnet-nightly (chaos corpus + bounded wire-sweep + sim-fast)" | tee -a "$LOG"
if make -C "$ROOT" simnet-nightly 2>&1 | tee -a "$LOG"; then
    :
else
    rc=1
fi

if [ "$rc" -eq 0 ] && [ "$RUN_FUZZ_SWEEP" = "1" ]; then
    echo "==> make simnet-fuzz-sweep (longer wire_sweep seed tail)" | tee -a "$LOG"
    if make -C "$ROOT" simnet-fuzz-sweep 2>&1 | tee -a "$LOG"; then
        :
    else
        rc=1
    fi
fi

FINISHED=$(utc_now)
FINISHED_EPOCH=$(epoch_now)
ELAPSED=$((FINISHED_EPOCH - STARTED_EPOCH))

if [ "$rc" -eq 0 ]; then
    STATUS=passed
    echo "==> simnet_nightly PASSED (elapsed=${ELAPSED}s)" | tee -a "$LOG"
else
    STATUS=failed
    echo "==> simnet_nightly FAILED (elapsed=${ELAPSED}s) — see $LOG" | tee -a "$LOG"
fi

STATUS_TMP="$STATUS_DIR/simnet_nightly.json.tmp"
STATUS_OUT="$STATUS_DIR/simnet_nightly.json"
{
    printf '{'
    printf '"schema":"zcl.simnet_nightly.v1"'
    printf ',"status":"%s"' "$STATUS"
    printf ',"started_at":"%s"' "$STARTED"
    printf ',"finished_at":"%s"' "$FINISHED"
    printf ',"elapsed_seconds":%s' "$ELAPSED"
    printf ',"exit_code":%s' "$rc"
    printf ',"commit":"%s"' "$(git_commit)"
    printf ',"fuzz_sweep":%s' "$RUN_FUZZ_SWEEP"
    printf ',"log":"%s"' "$LOG"
    printf '}\n'
} > "$STATUS_TMP"
mv "$STATUS_TMP" "$STATUS_OUT"

exit "$rc"
