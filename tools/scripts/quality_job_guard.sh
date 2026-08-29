#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# systemd ExecStart guard for CPU/IO-heavy unattended quality jobs.  It uses
# the replay-canary convention: an active *mint* service yields a loud SKIP and
# exit 0 without changing the lane's last verdict.  Mint detection fails
# closed.  Per-lane log retention is enforced before and after every run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LANE="${1:-}"
RETENTION="$SCRIPT_DIR/quality_log_retention.sh"

declare -a TARGET_ARGS=()
case "$LANE" in
    fuzz|tests|coverage)
        TARGET="$SCRIPT_DIR/background_quality_lane.sh"
        TARGET_ARGS=("$LANE")
        ;;
    simnet-nightly)
        TARGET="$SCRIPT_DIR/simnet_nightly.sh"
        ;;
    *)
        echo "usage: quality_job_guard.sh <fuzz|tests|coverage|simnet-nightly>" >&2
        exit 64
        ;;
esac

skip() {
    local reason="$1"
    echo "quality-job-guard: SKIP lane=$LANE reason=$reason" >&2
    logger -t zclassic23-quality \
        "SKIP lane=$LANE reason=$reason — unattended quality job yields" \
        2>/dev/null || true
    exit 0
}

if ! command -v systemctl >/dev/null 2>&1; then
    skip "no_systemctl"
fi

active_mint=""
if ! active_mint="$(systemctl --user list-units --type=service \
        --state=active --no-legend '*mint*' 2>/dev/null)"; then
    skip "mint_query_failed"
fi
if [ -n "$active_mint" ]; then
    mint_units="$(printf '%s\n' "$active_mint" | awk 'NF {print $1}' | paste -sd, -)"
    skip "mint_unit_active:${mint_units:-unknown}"
fi

# A mint skip performs no log-tree mutation.  Retention runs only when this
# lane is actually admitted, so even the first large prune cannot contend with
# the protected fold.
if [ ! -x "$RETENTION" ]; then
    skip "retention_helper_unavailable"
fi
if ! "$RETENTION" "$LANE"; then
    skip "retention_preflight_failed"
fi

set +e
if [ ${#TARGET_ARGS[@]} -gt 0 ]; then
    "$TARGET" "${TARGET_ARGS[@]}"
else
    "$TARGET"
fi
rc=$?
set -e

if ! "$RETENTION" "$LANE"; then
    echo "quality-job-guard: retention postflight failed lane=$LANE" >&2
    if [ "$rc" -eq 0 ]; then
        rc=74
    fi
fi

exit "$rc"
