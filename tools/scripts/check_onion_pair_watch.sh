#!/usr/bin/env bash
# check_onion_pair_watch.sh — drive the shipped onion_pair_watch.sh and
# assert its source-isolation contract plus pair_probe.jsonl schema.
#
# This is a collector, not a reimplementation of the probe: it runs
# tools/scripts/onion_pair_watch.sh --selftest (which sources
# isolated_node_env.sh and writes one real ledger line through append_probe)
# and then validates every JSONL line with jsonq.
#
# No Python. No mocked probe. A named miss in the live ledger is a valid
# observation; a crash, empty append, prose verdict, or executing the
# isolation helper is not.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
WATCH="$ROOT/tools/scripts/onion_pair_watch.sh"
LOOP="$ROOT/tools/scripts/onion_pair_watch_loop.sh"
HELPER="$ROOT/tools/scripts/isolated_node_env.sh"
LEDGER=${PAIR_PROBE_FILE:-"${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-referee/pair_probe.jsonl"}
JSONQ=${ZCL_JSONQ:-"$ROOT/build/bin/jsonq"}

die() {
    printf 'check_onion_pair_watch: FAIL: %s\n' "$*" >&2
    exit 1
}

[ -f "$WATCH" ] || die "missing $WATCH"
[ -f "$LOOP" ] || die "missing $LOOP"
[ -f "$HELPER" ] || die "missing $HELPER"
[ -x "$JSONQ" ] || die "jsonq not built at $JSONQ (run make jsonq)"

# Structural: this shipped probe is bash. The repository-wide no-runtime gate
# owns interpreter-path enforcement; duplicating its regex here self-matches.
head -n 1 "$WATCH" | grep -q '^#!/usr/bin/env bash$' \
    || die "onion_pair_watch.sh must start with #!/usr/bin/env bash"

# Structural: sources isolated_node_env.sh; does not execute it.
if ! grep -E '^[[:space:]]*\. .*isolated_node_env\.sh' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh does not source isolated_node_env.sh"
fi
if grep -E '^[[:space:]]*(bash |sh |exec )?("\$[^"]+"|[[:alnum:]_./-]+)*isolated_node_env\.sh([[:space:]]|$)' "$WATCH" \
    | grep -v -E '^[[:space:]]*\.' >/dev/null 2>&1; then
    die "onion_pair_watch.sh executes isolated_node_env.sh instead of sourcing it"
fi
if grep -E '^[[:space:]]*iso_spawn_node( |$)' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must not call iso_spawn_node (that helper is -regtest)"
fi
if ! grep -F 'disown "$ISO_NODE_PID"' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must suppress intentional primary cleanup job notices"
fi
if ! grep -F 'disown "$ISO_PEER_PID"' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must suppress intentional peer cleanup job notices"
fi
if ! grep -F 'PAIR_WATCH_PORT_BASE:-39250' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must rent probe quads from documented base 39250"
fi
if ! grep -F 'PAIR_WATCH_PORT_QUAD_ATTEMPTS' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must bound its probe-quad search"
fi
if ! grep -F 'select_probe_port_quads' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must select two free dedicated quads"
fi
if ! grep -F 'PORT_QUAD_EXHAUSTED' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must name bounded port exhaustion"
fi
if ! grep -F 'ISO_PEER_PORT_BASE' "$HELPER" >/dev/null 2>&1; then
    die "isolation helper must accept an explicitly rented peer quad"
fi
if grep -F 'pick_port_base()' "$LOOP" >/dev/null 2>&1; then
    die "pair loop must not select a base by checking only one port"
fi
if grep -F -- '-addnode="${ONION_ADDR}:${ISO_PORT}"' "$WATCH" \
    >/dev/null 2>&1; then
    die "client Tor must bootstrap before the descriptor-gated onion dial"
fi
if ! grep -F 'DESCRIPTOR PUBLICATION observed' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must recognize DESCRIPTOR PUBLICATION observed"
fi
if ! grep -F 'Uploaded hidden service descriptor' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must observe the HSDir status-200 upload line"
fi
if ! grep -F 'descriptor_publication_observed' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must use the descriptor publication helper"
fi
if ! grep -F 'iso_peer_rpc addnode' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must trigger the onion dial after readiness"
fi
# Dial order: the explicit readiness marker must precede the one-shot RPC.
ready_line=$(grep -n '^echo "dial_prerequisites_ready_s=' "$WATCH" | head -1 | cut -d: -f1)
dial_line=$(grep -n '^dial_out=$(iso_peer_rpc addnode' "$WATCH" | head -1 | cut -d: -f1)
case $ready_line in ''|*[!0-9]*) die "could not find dial readiness marker" ;; esac
case $dial_line in ''|*[!0-9]*) die "could not find descriptor-gated dial RPC" ;; esac
if [ "$ready_line" -ge "$dial_line" ]; then
    die "onion dial (line $dial_line) must follow readiness gate (line $ready_line)"
fi
if ! grep -F 'INTRODUCE1 sent' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must require exact INTRODUCE1 evidence"
fi
if ! grep -F 'RENDEZVOUS1 sent' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must require exact RENDEZVOUS1 evidence"
fi
if ! grep -F 'Hidden service descriptor upload complete' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must require successful descriptor upload evidence"
fi
if ! grep -F 'onion stage=circuit_ready' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must require circuit-ready evidence"
fi
if ! grep -F 'result.outbound_streams.circuit_ready' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must read the monotonic circuit-ready counter"
fi
if ! grep -F 'result.outbound_streams.bytes_to_peer' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must require observed P2P framing bytes"
fi

# The root source pin must contain the exact Tor milestones the watcher
# requires. This is the born-red guard for the integration omission where
# application readiness landed on main but the vendor-Tor observability and
# descriptor retry commit remained only on a side lane.
for signal in \
    'Hidden service descriptor upload complete' \
    'INTRODUCE1 sent' \
    'RENDEZVOUS1 sent' \
    'RENDEZVOUS2 received'; do
    if ! git -C "$ROOT/vendor/tor" grep -F "$signal" -- src \
        >/dev/null 2>&1; then
        die "vendor/tor pin lacks required loop signal: $signal"
    fi
done
if ! grep -E 'PAIR_WATCH_POLL:-[0-9]+' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh missing PAIR_WATCH_POLL default"
fi
if ! grep -F 'PROBE_QUAD_FLOOR=39250' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must bind only the documented 39250+ probe quad"
fi
if grep -E 'PAIR_WATCH_PORT_BASE:-[0-9]*39350' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh default must not be 39350 (peer quad binds node2 P2P 39360)"
fi
if ! grep -F 'P2P_PORT=' "$HELPER" >/dev/null 2>&1; then
    die "isolation helper must read published P2P_PORT from deploy/devfleet/node*.txt"
fi
if grep -E 'for b in 39350' "$LOOP" >/dev/null 2>&1; then
    die "onion_pair_watch_loop.sh must not prefer 39350 as a bind candidate"
fi
if grep -E 'git (commit|push)|deploy/devfleet/pair_probe\.jsonl' \
    "$WATCH" "$LOOP" >/dev/null 2>&1; then
    die "recurring pair telemetry must not commit, push, or write the tracked tree"
fi
poll_default=$(sed -n 's/^PAIR_POLL=\${PAIR_WATCH_POLL:-\([0-9]*\)}/\1/p' "$WATCH" | head -1)
case $poll_default in
    ''|*[!0-9]*) die "could not parse PAIR_WATCH_POLL default" ;;
esac
if [ "$poll_default" -lt 150 ]; then
    die "PAIR_WATCH_POLL default is ${poll_default}s; paired_at_s~68s needs >=150s"
fi

validate_line() {
    local line=$1 src=$2
    local ts head_sha verdict paired_at dial rend desc client_ready intro rend1 circuit framing
    [ -n "$line" ] || die "$src: empty line"
    ts=$(printf '%s' "$line" | "$JSONQ" get ts 2>/dev/null || true)
    head_sha=$(printf '%s' "$line" | "$JSONQ" get head_sha 2>/dev/null || true)
    verdict=$(printf '%s' "$line" | "$JSONQ" get verdict 2>/dev/null || true)
    paired_at=$(printf '%s' "$line" | "$JSONQ" get paired_at_s 2>/dev/null || true)
    dial=$(printf '%s' "$line" | "$JSONQ" get dial_attempted 2>/dev/null || true)
    rend=$(printf '%s' "$line" | "$JSONQ" get rendezvous_seen 2>/dev/null || true)
    desc=$(printf '%s' "$line" | "$JSONQ" get descriptor_uploaded 2>/dev/null || true)
    client_ready=$(printf '%s' "$line" | "$JSONQ" get client_tor_ready 2>/dev/null || true)
    intro=$(printf '%s' "$line" | "$JSONQ" get introduce1_seen 2>/dev/null || true)
    rend1=$(printf '%s' "$line" | "$JSONQ" get rendezvous1_seen 2>/dev/null || true)
    circuit=$(printf '%s' "$line" | "$JSONQ" get circuit_ready 2>/dev/null || true)
    framing=$(printf '%s' "$line" | "$JSONQ" get p2p_framing_seen 2>/dev/null || true)

    [ -n "$ts" ] || die "$src: missing ts"
    case $head_sha in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
        *) die "$src: head_sha is not hex (got '${head_sha:-empty}')" ;;
    esac
    case $verdict in
        [A-Z][A-Z0-9_]*) ;;
        *) die "$src: verdict is not a named token (got '${verdict:-empty}')" ;;
    esac
    case $verdict in
        *' '*) die "$src: verdict contains whitespace: $verdict" ;;
    esac
    case $paired_at in
        null|''|[0-9]|[0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9][0-9][0-9]) ;;
        *) die "$src: paired_at_s must be numeric or null (got '$paired_at')" ;;
    esac
    if [ "$verdict" = PAIRED ]; then
        case $paired_at in
            ''|null) die "$src: PAIRED line must have numeric paired_at_s" ;;
        esac
    fi
    case $dial in true|false) ;; *) die "$src: dial_attempted must be JSON boolean (got '$dial')" ;; esac
    case $rend in true|false) ;; *) die "$src: rendezvous_seen must be JSON boolean (got '$rend')" ;; esac
    case $desc in true|false) ;; *) die "$src: descriptor_uploaded must be JSON boolean (got '$desc')" ;; esac
    case $client_ready in true|false) ;; *) die "$src: client_tor_ready must be JSON boolean (got '$client_ready')" ;; esac
    case $intro in true|false) ;; *) die "$src: introduce1_seen must be JSON boolean (got '$intro')" ;; esac
    case $rend1 in true|false) ;; *) die "$src: rendezvous1_seen must be JSON boolean (got '$rend1')" ;; esac
    case $circuit in true|false) ;; *) die "$src: circuit_ready must be JSON boolean (got '$circuit')" ;; esac
    case $framing in true|false) ;; *) die "$src: p2p_framing_seen must be JSON boolean (got '$framing')" ;; esac
    if [ "$verdict" = PAIRED ] &&
       { [ "$dial" != true ] || [ "$desc" != true ] ||
         [ "$client_ready" != true ] ||
         [ "$intro" != true ] || [ "$rend1" != true ] ||
         [ "$circuit" != true ] || [ "$framing" != true ]; }; then
        die "$src: PAIRED requires every declared loop stage"
    fi
}

# Drive the shipped script: --selftest sources the isolation helper and
# writes one ledger line through the same append_probe the live path uses.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl23-pairwatch-check-XXXXXX")
trap 'rm -rf "$tmp"' EXIT
self_ledger="$tmp/pair_probe.jsonl"
if ! PAIR_PROBE_FILE="$self_ledger" "$WATCH" --selftest >"$tmp/selftest.out" 2>"$tmp/selftest.err"; then
    cat "$tmp/selftest.out" >&2 || true
    cat "$tmp/selftest.err" >&2 || true
    die "onion_pair_watch.sh --selftest exited non-zero"
fi
if ! grep -a "sourced isolated_node_env.sh" "$tmp/selftest.out" >/dev/null 2>&1; then
    die "--selftest did not report sourcing isolated_node_env.sh"
fi
[ -s "$self_ledger" ] || die "--selftest did not append a JSONL line"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    validate_line "$line" "$self_ledger"
done <"$self_ledger"

# Live ledger, when present, must tell the truth in the same schema.
if [ -f "$LEDGER" ]; then
    live_n=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        live_n=$((live_n + 1))
        validate_line "$line" "$LEDGER:$live_n"
    done <"$LEDGER"
    echo "check_onion_pair_watch: OK (selftest + $live_n live ledger line(s))"
else
    echo "check_onion_pair_watch: OK (selftest; live ledger not yet present)"
fi
exit 0
