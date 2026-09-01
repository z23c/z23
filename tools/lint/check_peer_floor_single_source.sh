#!/usr/bin/env bash
# Gate: peer-floor single source of truth (HARD).
#
# The healthy-outbound peer floor is a first-class liveness threshold read by
# four independent surfaces:
#
#   1. core/modules/net/src/connman.c            — thread_open_connections backfill floor
#                                          + the dns-seed loop's PEER_FLOOR_MIN
#   2. engine/supervisors/src/net_supervisor.c
#                                        — the net.outbound_floor supervisor child
#   3. engine/conditions/src/peer_floor_violated.c
#                                        — the operator_needed escalation condition
#
# For years these each hardcoded their OWN numeric literal (2, 3, 3, 3), so the
# supervisor fired one peer later than the condition and the dialer, and a
# future edit to one site silently diverged the whole stack. They now all read
# ONE constant, ZCL_PEER_FLOOR_HEALTHY, defined exactly once in net/net.h.
#
# This gate pins that: net.h defines the constant exactly once, each of the four
# sites references it, and no site reintroduces a retired local floor macro bound
# to a bare integer literal. Per repo law 10 the gate FAILS LOUD on an empty scan
# set (a drift that makes the reference scan match nothing must never read as
# "clean"). It also carries an isolated self-test used by test_anchor_peers.c
# (ZCL_PEER_FLOOR_SELFTEST=1 scans ONLY $ZCL_PEER_FLOOR_SELFTEST_FILE for banned
# literals) so the banned-literal detector is proven to trip AND to pass.
set -euo pipefail

# Retired local floor macros: reintroducing any of these as `#define NAME <int>`
# re-forks the floor away from the single source of truth.
BANNED_RE='^[[:space:]]*#[[:space:]]*define[[:space:]]+(PEER_FLOOR_MIN|PEER_FLOOR_MIN_HEALTHY|PEER_FLOOR_TARGET|OUTBOUND_HEALTHY_FLOOR)[[:space:]]+[0-9]'

scan_banned() { # $1=file ; prints matches, returns 0 if any banned literal found
    grep -nE "$BANNED_RE" "$1" 2>/dev/null
}

# ── Isolated self-test hook (used by the unit test) ───────────────────────────
if [ "${ZCL_PEER_FLOOR_SELFTEST:-0}" = "1" ]; then
    f="${ZCL_PEER_FLOOR_SELFTEST_FILE:-}"
    [ -n "$f" ] && [ -f "$f" ] || {
        echo "check_peer_floor_single_source: FATAL — selftest file missing: '$f'" >&2
        exit 2
    }
    if scan_banned "$f" >/dev/null; then
        echo "check_peer_floor_single_source: selftest TRIP — banned floor literal in $f"
        exit 1
    fi
    echo "check_peer_floor_single_source: selftest CLEAN — no banned floor literal in $f"
    exit 0
fi

cd "$(dirname "$0")/../.."

DEF_HDR="core/modules/net/include/net/net.h"
SITES=(
    "core/modules/net/src/connman.c"
    "engine/supervisors/src/net_supervisor.c"
    "engine/conditions/src/peer_floor_violated.c"
)

fail=0

for f in "$DEF_HDR" "${SITES[@]}"; do
    [ -f "$f" ] || {
        echo "check_peer_floor_single_source: FATAL — expected file missing: $f" >&2
        exit 2
    }
done

# (A) The constant is defined exactly once, in net.h, as a numeric literal.
def_count=$(grep -cE '^[[:space:]]*#[[:space:]]*define[[:space:]]+ZCL_PEER_FLOOR_HEALTHY[[:space:]]+[0-9]' "$DEF_HDR" || true)
if [ "$def_count" != "1" ]; then
    echo "check_peer_floor_single_source: FAIL — ZCL_PEER_FLOOR_HEALTHY must be #define'd exactly once (as a number) in $DEF_HDR (found $def_count)" >&2
    fail=1
fi

# Uniqueness across the whole tree (no shadow redefinition anywhere).
tree_defs=$(grep -rlE '^[[:space:]]*#[[:space:]]*define[[:space:]]+ZCL_PEER_FLOOR_HEALTHY[[:space:]]+[0-9]' \
    lib app config core domain tools 2>/dev/null | sort -u || true)
tree_def_count=$(printf '%s\n' "$tree_defs" | grep -c . || true)
if [ "$tree_def_count" != "1" ]; then
    echo "check_peer_floor_single_source: FAIL — ZCL_PEER_FLOOR_HEALTHY defined in $tree_def_count files (expected 1):" >&2
    printf '%s\n' "$tree_defs" | sed 's/^/    /' >&2
    fail=1
fi

# (B) Each site references the shared constant, and none reintroduces a retired
#     literal floor macro. Count total references to fail loud on an empty scan.
total_refs=0
for f in "${SITES[@]}"; do
    refs=$(grep -cE '\bZCL_PEER_FLOOR_HEALTHY\b' "$f" || true)
    total_refs=$((total_refs + refs))
    if [ "$refs" -lt 1 ]; then
        echo "check_peer_floor_single_source: FAIL — $f does not reference ZCL_PEER_FLOOR_HEALTHY (re-hardcoded floor?)" >&2
        fail=1
    fi
    banned=$(scan_banned "$f" || true)
    if [ -n "$banned" ]; then
        echo "check_peer_floor_single_source: FAIL — $f reintroduces a retired floor literal macro:" >&2
        printf '%s\n' "$banned" | sed 's/^/    /' >&2
        echo "    Use ZCL_PEER_FLOOR_HEALTHY from $DEF_HDR instead." >&2
        fail=1
    fi
done

# Law 10: an empty positive scan is a broken gate, not a clean tree.
if [ "$total_refs" -lt 1 ]; then
    echo "check_peer_floor_single_source: FATAL — zero ZCL_PEER_FLOOR_HEALTHY references across all floor sites; the wiring drifted (refusing to report clean)" >&2
    exit 2
fi

if [ "$fail" != "0" ]; then
    echo "check_peer_floor_single_source: the healthy-outbound floor has drifted from its single source of truth." >&2
    exit 1
fi

echo "[check_peer_floor_single_source] OK — ZCL_PEER_FLOOR_HEALTHY defined once in $DEF_HDR and read by all $total_refs floor references across ${#SITES[@]} sites"
exit 0
