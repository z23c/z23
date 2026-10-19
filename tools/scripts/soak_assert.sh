#!/usr/bin/env bash
# Soak assertion gate for the three redundancy guarantees.
#
# Polls /api/health + getpeerinfo + getnetworkinfo + getsyncdetail
# every 60 s and asserts:
#   - peer_count >= MIN_PEERS (default 3)
#   - mirror_lag is known and <= LAG_BREACH_BLOCKS (default 10)
#   - mirror_lag_breach_severity == "none"
#   - systemd restart count does not increment
#   - magicbean_peer_count > 0 (validates Goal 3 reporting)
#
# Goal 1 (P2P), Goal 2 (mirror), Goal 3 (magic-bean reporting) all
# tested by a single continuous probe. Output: PASS / FAIL plus the
# first-deviation log line.
#
# Usage:
#   tools/scripts/soak_assert.sh [duration_secs] [poll_secs]
#
# Defaults: 86400 s (24 h) duration, 60 s poll cadence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DURATION_S="${1:-86400}"
POLL_S="${2:-60}"
MIN_PEERS="${MIN_PEERS:-3}"
LAG_BREACH_BLOCKS="${LAG_BREACH_BLOCKS:-10}"
UNIT="${SOAK_UNIT:-z23-node}"
ZCL_CLI="${ZCL_CLI:-$REPO_ROOT/build/bin/zcl-rpc}"
HEALTH_URL="${HEALTH_URL:-https://127.0.0.1:8443/api/health}"

start_ts=$(date +%s)
end_ts=$((start_ts + DURATION_S))
deviations=0
restart_baseline=$(systemctl --user show "$UNIT" -p NRestarts --value 2>/dev/null || echo 0)

echo "soak: unit=$UNIT min_peers=$MIN_PEERS lag_breach=$LAG_BREACH_BLOCKS"
echo "soak: starting at $(date -u --iso-8601=seconds), duration ${DURATION_S}s, poll ${POLL_S}s"
echo "soak: restart_count baseline=$restart_baseline"

json_num() {
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+" |
        head -1 | sed -E 's/.*:[ ]*//' || true
}
json_str() {
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" |
        head -1 | sed -E 's/.*:[ ]*"//; s/"$//' || true
}
json_bool() {
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*(true|false)" |
        head -1 | sed -E 's/.*:[ ]*//' || true
}

while [ "$(date +%s)" -lt "$end_ts" ]; do
    elapsed=$(( $(date +%s) - start_ts ))
    health=$(curl -sk "$HEALTH_URL" 2>/dev/null || echo '{}')

    peer_count=$(json_num "$health" peer_count)
    [ -n "$peer_count" ] || peer_count=-1
    mb_count=$(json_num "$health" magicbean_peer_count)
    [ -n "$mb_count" ] || mb_count=-1
    sync_detail=$($ZCL_CLI getsyncdetail 2>/dev/null || echo '{}')
    lag=$(json_num "$sync_detail" mirror_lag)
    [ -n "$lag" ] || lag=-1
    lag_known=$(json_bool "$sync_detail" mirror_lag_known)
    if [ -z "$lag_known" ]; then
        lag_known=$(json_bool "$sync_detail" lag_known)
    fi
    [ "$lag_known" = "true" ] || lag_known=false
    severity=$(json_str "$sync_detail" mirror_lag_breach_severity)
    [ -n "$severity" ] || severity=unknown
    nrestarts=$(systemctl --user show "$UNIT" -p NRestarts --value 2>/dev/null || echo "$restart_baseline")

    fail=""
    if [ "$peer_count" -lt "$MIN_PEERS" ]; then
        fail="peers=$peer_count<$MIN_PEERS"
    elif [ "$lag_known" != "true" ]; then
        fail="mirror_lag_unknown"
    elif [ "$lag" -gt "$LAG_BREACH_BLOCKS" ]; then
        fail="lag=$lag>$LAG_BREACH_BLOCKS"
    elif [ "$severity" != "none" ]; then
        fail="severity=$severity"
    elif [ "$nrestarts" -gt "$restart_baseline" ]; then
        fail="restart_count=$nrestarts (baseline=$restart_baseline)"
    elif [ "$mb_count" -lt 1 ]; then
        fail="magicbean_peer_count=$mb_count (Goal 3 reporting absent)"
    fi

    if [ -n "$fail" ]; then
        deviations=$((deviations + 1))
        echo "soak DEVIATION @ +${elapsed}s: $fail (peers=$peer_count mb=$mb_count lag=$lag lag_known=$lag_known sev=$severity nrestarts=$nrestarts)"
        if [ "$deviations" -eq 1 ]; then
            echo "soak: first-deviation snapshot:"
            echo "$health" | head -40
        fi
    else
        if [ $((elapsed % 600)) -eq 0 ]; then
            echo "soak OK @ +${elapsed}s: peers=$peer_count mb=$mb_count lag=$lag lag_known=$lag_known sev=$severity"
        fi
    fi

    sleep "$POLL_S"
done

if [ "$deviations" -eq 0 ]; then
    echo "soak PASS: ${DURATION_S}s with zero deviations"
    exit 0
else
    echo "soak FAIL: ${DURATION_S}s with ${deviations} deviations"
    exit 1
fi
