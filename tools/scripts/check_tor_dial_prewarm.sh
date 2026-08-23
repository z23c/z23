#!/usr/bin/env bash
# Structural boot-order gate: outbound onion work must pre-warm while the
# local hidden-service descriptor publishes; inbound/systemd readiness stays
# gated on successful descriptor publication.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BOOT="$ROOT/config/src/boot_services.c"
TOR="$ROOT/lib/net/src/tor_integration.c"
STREAM="$ROOT/lib/net/src/onion_stream.c"
CONNMAN="$ROOT/lib/net/src/connman.c"
WATCHDOG="$ROOT/config/src/boot_sd_watchdog.c"
REFEREE="$ROOT/tools/scripts/fleet_mesh_acceptance.sh"

die() {
    printf 'check_tor_dial_prewarm: FAIL: %s\n' "$*" >&2
    exit 1
}

network_line=$(grep -n 'zcl_service_kernel_start_all(&svc->network_kernel)' \
    "$BOOT" | head -1 | cut -d: -f1)
frontend_line=$(grep -n 'zcl_service_kernel_start_all(&svc->frontend_kernel)' \
    "$BOOT" | head -1 | cut -d: -f1)
case "$network_line:$frontend_line" in
    *[!0-9:]*|:*|*:) die 'could not resolve network/frontend boot order' ;;
esac
[ "$network_line" -lt "$frontend_line" ] ||
    die 'connman must start before the frontend Tor service'

dial_ready_line=$(grep -n 'atomic_store(&g_tor_dial_ready, true)' "$TOR" |
    head -1 | cut -d: -f1)
publication_line=$(grep -n 'tor_log_has_descriptor_publication(log_path' \
    "$TOR" | head -1 | cut -d: -f1)
case "$dial_ready_line:$publication_line" in
    *[!0-9:]*|:*|*:) die 'could not resolve Tor dial/publication order' ;;
esac
[ "$dial_ready_line" -lt "$publication_line" ] ||
    die 'outbound dial readiness must precede descriptor publication'

grep -q 'tor_integration_is_dial_ready' "$STREAM" ||
    die 'raw onion stream still waits for full inbound readiness'
grep -q 'tor_integration_is_dial_ready' "$CONNMAN" ||
    die 'onion seed discovery still waits for full inbound readiness'
if grep -q 'tor_integration_is_ready' "$STREAM" "$CONNMAN"; then
    die 'an outbound onion path is still gated on descriptor publication'
fi
grep -q 'tor_integration_is_ready' "$WATCHDOG" ||
    die 'systemd READY no longer waits for descriptor publication'
grep -q 'data.dial_ready' "$REFEREE" ||
    die 'fresh referee probe does not observe outbound dial readiness'
if grep -q 'bootstrap.*=.*ready.*break' "$REFEREE"; then
    die 'fresh referee probe still waits for full Tor readiness before dial'
fi
grep -q 'descriptor_ready_at_dial=' "$REFEREE" ||
    die 'fresh referee evidence omits descriptor state at dial time'

printf 'check_tor_dial_prewarm: PASS network_start=%s tor_start=%s dial_ready=%s descriptor_publication=%s\n' \
    "$network_line" "$frontend_line" "$dial_ready_line" "$publication_line"
