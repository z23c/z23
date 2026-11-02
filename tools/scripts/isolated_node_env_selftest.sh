#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Local readiness fixtures; no node or listening socket is created.
set -euo pipefail
SELF_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
source "$SELF_DIR/isolated_node_env.sh"
[ -x "$ISO_JSONQ_BIN" ] || iso_die 'readiness selftest requires make jsonq'
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-readiness.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
ISO_DD="$fixture"
ISO_PEER_PID=""
ISO_NODE_PID=""
ISO_PEER_PORT=39328
touch "$fixture/.cookie"
fixture_reply=''
fixture_rpc_rc=0
iso_rpc() { printf '%s\n' "$fixture_reply"; return "$fixture_rpc_rc"; }
fail() { printf 'isolated-readiness selftest: FAIL: %s\n' "$*" >&2; exit 1; }
for fixture_reply in \
    '{"result":null,"error":{"code":-28,"message":"warming up"},"id":123}' \
    '{"result":0,"error":{"code":-28},"id":1}' \
    '{"result":"0","error":null}' \
    '{"result":0,"error":"null"}' \
    '{"result":0}' \
    '{"result":-1,"error":null}' \
    '{"result":1.5,"error":null}' \
    '{"result":1e2,"error":null}' \
    '{"result":true,"error":null}' \
    '{"result":[],"error":null}' \
    '{"result":0,"error":null} trailing' \
    '0' ''; do
    if iso_rpc_nonnegative_result getblockcount >/dev/null; then
        fail "invalid response accepted: $fixture_reply"
    fi
done
fixture_reply='{"result":0,"error":null,"id":1}'
[ "$(iso_rpc_nonnegative_result getblockcount)" = 0 ] || fail 'height zero refused'
iso_wait_rpc_ready 1 || fail 'successful height zero did not become ready'
if iso_wait_peer_connected 1; then fail 'zero peers became connected'; fi
fixture_rpc_rc=1
if iso_rpc_nonnegative_result getblockcount >/dev/null; then
    fail 'failed RPC transport qualified through successful-looking output'
fi
fixture_rpc_rc=0
fixture_reply='{"result":2,"error":null,"id":1}'
iso_wait_peer_connected 1 || fail 'connected peers refused'
fixture_reply='{"result":null,"error":{"code":-28},"id":123}'
if iso_wait_rpc_ready 1; then fail 'RPC error became ready'; fi
if iso_wait_peer_connected 1; then fail 'RPC error became connected'; fi
z23_tcp_port_listening() { return 0; }
iso_wait_peer_listen 1 || fail 'observed listener refused'
z23_tcp_port_listening() { return 2; }
rc=0
iso_wait_peer_listen 1 || rc=$?
[ "$rc" = 2 ] || fail 'unobserved listener lost its refusal status'
z23_tcp_port_listening() { return 1; }
if iso_wait_peer_listen 1; then fail 'absent listener qualified'; fi
# The first deadline check crosses a whole-second boundary.
date() {
    if [ "$1" != '+%s' ]; then command date "$@"; return; fi
    if [ ! -e "$fixture/date-boundary" ]; then
        : > "$fixture/date-boundary"
        printf '100\n'
    else
        printf '101\n'
    fi
}
fixture_reply='{"result":0,"error":null,"id":1}'
iso_wait_rpc_ready 1 || fail 'successful height zero lost at second boundary'
rm -f "$fixture/date-boundary"
fixture_reply='{"result":2,"error":null,"id":1}'
iso_wait_peer_connected 1 || fail 'connected peer lost at second boundary'
rm -f "$fixture/date-boundary"
z23_tcp_port_listening() { return 0; }
iso_wait_peer_listen 1 || fail 'listener lost at second boundary'
unset -f date
# Dead-sink guard: iso_init must refuse when anything LISTENs on the -connect
# sink, and must still accept when the sink is dead. Subshells keep the
# stubbed probe and the iso_init EXIT trap away from this selftest.
sink_out="$fixture/sink.out"
if ( ISO_NODE_BIN="$ISO_JSONQ_BIN" ISO_RPC_BIN="$ISO_JSONQ_BIN"
     z23_tcp_port_listening() { [ "$1" = "$ISO_CONNECT_SINK" ] && return 0; return 1; }
     iso_init ) >"$sink_out" 2>&1; then
    fail 'iso_init accepted a LISTENING dead sink'
fi
grep -q 'dead -connect sink port 39999 is already LISTENING' "$sink_out" ||
    fail 'listening dead sink refused without the sink message'
( ISO_NODE_BIN="$ISO_JSONQ_BIN" ISO_RPC_BIN="$ISO_JSONQ_BIN"
  z23_tcp_port_listening() { return 1; }
  iso_init ) >/dev/null 2>&1 || fail 'iso_init refused a dead sink'
printf 'isolated-readiness selftest: PASS typed_rpc=true errors_refused=true portable_listener=true unobserved_refused=true dead_sink_refused=true\n'
