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
printf 'isolated-readiness selftest: PASS typed_rpc=true errors_refused=true portable_listener=true unobserved_refused=true\n'
