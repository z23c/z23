#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Exercise actual peer-tip pollers without opening a socket or node datadir.
set -euo pipefail
SELF_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
source "$SELF_DIR/two_node_peer_tip.sh"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-peer-tip-contract.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
fail() { printf 'peer-tip selftest: FAIL: %s\n' "$*" >&2; exit 1; }
RPC_BIN="$fixture/rpc"
cat > "$RPC_BIN" <<'RPC'
#!/bin/sh
printf '%s\n' "$fixture_reply"
exit "$fixture_rpc_rc"
RPC
chmod 700 "$RPC_BIN"
export fixture_reply='' fixture_rpc_rc=0
for fixture_reply in \
    '{"result":15,"error":{"code":-28}}' \
    '{"result":"15","error":null}' \
    '{"result":15,"error":"null"}' \
    '{"result":15}' '{"result":-1,"error":null}' \
    '{"result":1.5,"error":null}' '{"result":true,"error":null}' \
    '{"result":15,"error":null} trailing' ''; do
    if tn_blockcount "$fixture" 39071 >/dev/null; then fail 'invalid height accepted'; fi
done
fixture_reply='{"result":0,"error":null}'
[ "$(tn_blockcount "$fixture" 39071)" = 0 ] || fail 'height zero refused'
fixture_rpc_rc=1
if tn_blockcount "$fixture" 39071 >/dev/null; then fail 'failed transport accepted'; fi
fixture_rpc_rc=0
tip_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
fixture_reply="{\"result\":\"$tip_hash\",\"error\":null}"
[ "$(tn_blockhash "$fixture" 39071 15)" = "$tip_hash" ] || fail 'exact hash refused'
fixture_reply='{"result":"abc","error":null}'
if tn_blockhash "$fixture" 39071 15 >/dev/null; then fail 'short hash accepted'; fi

TN_TMP="$fixture/"
mkdir "$fixture/zcl23-2node-cleanup"
tn_rm_datadir "$fixture/zcl23-2node-cleanup"
[ ! -e "$fixture/zcl23-2node-cleanup" ] || fail 'trailing-slash scratch cleanup refused'
mkdir "$fixture/zcl23-2node-scratch" "$fixture/zcl23-2node-outside"
TN_TMP="$fixture/zcl23-2node-scratch"
tn_rm_datadir "$TN_TMP"
[ -d "$TN_TMP" ] || fail 'scratch root itself removed'
tn_rm_datadir "$fixture/zcl23-2node-outside"
[ -d "$fixture/zcl23-2node-outside" ] || fail 'outside scratch root removed'

# A deterministic clock exposes budget resets and late RPC answers.
printf '100\n' > "$fixture/clock"
touch "$fixture/.cookie"
date() { cat "$fixture/clock"; }
sleep() { local tick; tick=$(date); printf '%s\n' "$((tick + 1))" > "$fixture/clock"; }
tn_blockcount() { printf '15\n'; }
tn_blockhash() { printf '%s\n' "$tip_hash"; }
tn_wait_rpc "$fixture" 39071 '' 102 || fail 'ready RPC refused'
tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null || fail 'exact tip refused'
if tn_wait_height "$fixture" 39071 '' 15 102 wrong >/dev/null; then
    fail 'same height with different hash accepted'
fi
[ "$(date)" = 102 ] || fail 'poll exceeded shared deadline'
if tn_wait_rpc "$fixture" 39071 '' 102; then fail 'expired warmup accepted'; fi
if tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null; then
    fail 'expired catch-up got a fresh budget'
fi
printf '100\n' > "$fixture/clock"
tn_blockcount() { printf '102\n' > "$fixture/clock"; printf '15\n'; }
if tn_wait_rpc "$fixture" 39071 '' 102; then fail 'late RPC readiness accepted'; fi
printf '100\n' > "$fixture/clock"
if tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null; then
    fail 'late tip accepted'
fi
printf 'peer-tip selftest: PASS (typed RPC, exact hash, shared deadline, late replies, cleanup containment)\n'
