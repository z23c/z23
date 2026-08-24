#!/usr/bin/env bash
# Onion pair-probe v3: joiner B first, member A with Tor log onion, poll getconnectioncount.
# Portable: runs from any checkout; does not hard-code a host path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ISO_KIND=joinp3
ISO_PORT_BASE=39300
ISO_PEER_DIAL=39999
. tools/scripts/isolated_node_env.sh
iso_init
# B = joiner (primary slot first per library contract): sandboxed HOME, -tor, NO sink
export HOME="$ISO_DD/home"
mkdir -p "$HOME/.config/zclassic23"
setsid ./build/bin/zclassic23 \
  -datadir="$ISO_DD" -regtest \
  -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
  -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
  -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 -tor \
  >"$ISO_DD/node.log" 2>&1 &
ISO_NODE_PID=$!; ISO_PGID="$ISO_NODE_PID"
echo "[harness] B pid=$ISO_NODE_PID"
# A = target (peer slot): tor + loopback clearnet advertisement
iso_spawn_peer "-tor -externalip=127.0.0.1"
echo "[harness] A pid=$ISO_PEER_PID p2p=$ISO_PEER_PORT"
A_ONION=""; i=0
while [ $i -lt 420 ]; do
  kill -0 "$ISO_PEER_PID" 2>/dev/null || { echo A_DIED; tail -5 "$ISO_PEER_DD/node.log"; exit 41; }
  A_ONION=$(grep -a "^Tor .onion: " "$ISO_PEER_DD/node.log" | tail -1 | sed 's/^Tor .onion: //' | tr -d ' \n' || true)
  if [ -n "$A_ONION" ]; then break; fi
  i=$((i+5)); sleep 5
done
[ -n "$A_ONION" ] || { echo A_ONION_TIMEOUT; grep -a "Tor" "$ISO_PEER_DD/node.log" | head; exit 42; }
echo "[harness] A_ONION=$A_ONION t=${i}s"
printf '%s\n' "$A_ONION" > "$HOME/.config/zclassic23/onion-seeds"
iso_wait_rpc_ready 300 || { echo B_RPC_TIMEOUT; exit 43; }
echo "[harness] B rpc ready; polling join evidence"
i=0; C=""
while [ $i -lt 480 ]; do
  kill -0 "$ISO_NODE_PID" 2>/dev/null || { echo B_DIED; tail -10 "$ISO_DD/node.log"; exit 44; }
  C=$(iso_rpc getconnectioncount | sed -n 's/.*"result"[^0-9-]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1)
  echo "t=${i}s conns=$C"
  [ -n "$C" ] && [ "$C" -ge 1 ] && break
  i=$((i+10)); sleep 10
done
echo "--- B seed/fetch lines:"; grep -a "Onion seed\|kick\|floor" "$ISO_DD/node.log" | head -12 || true
echo "--- B PEERS LIST:"; ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" ./build/bin/z23 core network peers list
echo "--- B SYNC STATUS:"; ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" ./build/bin/z23 core sync status | head -c 500; echo
echo "--- A conns:"; ZCL_DATADIR="$ISO_PEER_DD" ZCL_RPCPORT="$ISO_PEER_RPCPORT" ./build/bin/zcl-rpc getconnectioncount 2>/dev/null
