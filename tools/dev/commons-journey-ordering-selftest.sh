#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Executable regression for tools/dev/commons_journey_acceptance.sh ordering.
#
# A peer-dependent wait must never run before the peers it depends on have
# been started and their connections attempted. A node with no peer cannot
# leave finding_peers and its build worker cannot admit work, so asking
# before then is waiting on work the harness itself has not done yet: the
# wait burns its whole budget and dies, every run, for a reason that has
# nothing to do with the product.
#
# This is a STATIC check of the script's control flow. It starts no nodes and
# proves no runtime behaviour: a fixture may test harness ordering, it cannot
# substitute for real acceptance.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOURNEY="$SELF_DIR/commons_journey_acceptance.sh"
FAIL=0

fail() { printf 'commons-journey-ordering: FAIL: %s\n' "$*" >&2; FAIL=1; }
pass() { printf 'commons-journey-ordering: ok: %s\n' "$*"; }

[ -r "$JOURNEY" ] || { fail "cannot read $JOURNEY"; exit 2; }

# The function body under test, from `cj_overlay() {` to its closing brace.
overlay="$(awk '/^cj_overlay\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
[ -n "$overlay" ] || { fail "cj_overlay() not found"; exit 2; }

# Guard the guard: a body that no longer contains the steps this reasons
# about means the check has stopped checking, not that ordering is fine.
for needle in 'dht_spawn DHT_PGID_B' 'dht_spawn DHT_PGID_A' \
              'cj_connect_authenticated'; do
    grep -qF -- "$needle" <<<"$overlay" ||
        { fail "cj_overlay no longer contains '$needle'; this selftest is blind"; exit 2; }
done

line_of() { printf '%s\n' "$overlay" | grep -nF -- "$1" | head -1 | cut -d: -f1; }

spawn_b="$(line_of 'dht_spawn DHT_PGID_B')"
spawn_a="$(line_of 'dht_spawn DHT_PGID_A')"
connect="$(line_of 'cj_connect_authenticated')"

# Every wait that can only be satisfied by a peer.
peer_dependent_waits='cj_wait_worker_admits dht_wait_sync_live dht_wait_connected'

for w in $peer_dependent_waits; do
    at="$(printf '%s\n' "$overlay" | grep -nF -- "$w" | head -1 | cut -d: -f1 || true)"
    [ -n "$at" ] || continue
    if [ "$at" -lt "$spawn_b" ] || [ "$at" -lt "$spawn_a" ]; then
        fail "$w at body line $at runs before a node is started (B=$spawn_b A=$spawn_a)"
    elif [ "$at" -lt "$connect" ]; then
        fail "$w at body line $at runs before cj_connect_authenticated ($connect)"
    else
        pass "$w waits only after both nodes are up and connected"
    fi
done

# The readiness assertion must still exist and still fail closed. Deleting it
# would "fix" the ordering by removing the check.
grep -qF 'cj_wait_worker_admits' <<<"$overlay" ||
    fail "the build-worker readiness assertion was removed, not reordered"
grep -qF 'cj_die' <<<"$overlay" ||
    fail "cj_overlay no longer fails closed on a readiness timeout"

# The shared catch-up helper must not be retargeted at node B: its other
# callers deliberately accept blocks_download for the dialing node.
if grep -q 'dht_wait_sync_live[^|]*DHT_DD_B' <<<"$overlay"; then
    fail "dht_wait_sync_live was pointed at node B; it accepts catch-up states"
fi
pass "shared catch-up helper not repurposed for the build-worker node"

[ "$FAIL" -eq 0 ] || exit 1
printf 'commons-journey-ordering: OK\n'
