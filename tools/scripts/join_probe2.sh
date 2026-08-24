#!/usr/bin/env bash
# Onion pair-probe v2: spawn joiner B first, then member A; seed B with A's onion.
# Portable: runs from any checkout; does not hard-code a host path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ISO_KIND=joinprobe
ISO_PORT_BASE=39160
ISO_PEER_DIAL=39999
. tools/scripts/isolated_node_env.sh
iso_init
# B = joiner FIRST (library requires primary before peer): sandboxed HOME, NO dead-sink connect
export HOME="$ISO_DD/home"
mkdir -p "$HOME/.config/zclassic23"
setsid ./build/bin/zclassic23 \
  -datadir="$ISO_DD" -regtest \
  -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
  -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
  -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 -tor \
  >"$ISO_DD/node.log" 2>&1 &
ISO_NODE_PID=$!; ISO_PGID="$ISO_NODE_PID"
echo "[harness] B pid=$ISO_NODE_PID dd=$ISO_DD rpc=$ISO_RPCPORT home=$HOME"
# A = target network member: peer slot, tor, advertises loopback clearnet
iso_spawn_peer "-tor -externalip=127.0.0.1"
echo "[harness] A pid=$ISO_PEER_PID dd=$ISO_PEER_DD p2p=$ISO_PEER_PORT rpc=$ISO_PEER_RPCPORT"
A_ONION=""; i=0
while [ $i -lt 300 ]; do
  kill -0 "$ISO_PEER_PID" 2>/dev/null || { echo A_DIED; tail -5 "$ISO_PEER_DD/node.log"; exit 41; }
  f="$ISO_PEER_DD/tor_data/onion_service/hostname"
  if [ -f "$f" ]; then A_ONION=$(tr -d ' \n' < "$f"); [ -n "$A_ONION" ] && break; fi
  i=$((i+2)); sleep 2
done
[ -n "$A_ONION" ] || { echo A_ONION_TIMEOUT; tail -8 "$ISO_PEER_DD/node.log"; exit 42; }
echo "[harness] A_ONION=$A_ONION  (t=${i}s)"
printf '%s\n' "$A_ONION" > "$HOME/.config/zclassic23/onion-seeds"
echo "[harness] seeds now:"; cat "$HOME/.config/zclassic23/onion-seeds"
ZB() { ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" ./build/bin/z23 "$@" 2>&1; }
iso_wait_rpc_ready 240 || { echo B_RPC_TIMEOUT; tail -15 "$ISO_DD/node.log"; exit 43; }
echo "[harness] B rpc ready; polling for join evidence (reads seeds on each pass)"
i=0; C=""
while [ $i -lt 480 ]; do
  kill -0 "$ISO_NODE_PID" 2>/dev/null || { echo B_DIED; tail -15 "$ISO_DD/node.log"; exit 44; }
  C=$(iso_rpc getconnectioncount | tr -dc '0-9-')
  echo "t=${i}s conns=$C"
  [ -n "$C" ] && [ "$C" -ge 1 ] && break
  i=$((i+10)); sleep 10
done
if [ -n "$C" ] && [ "$C" -ge 1 ]; then
  echo "--- JOIN EVIDENCE ---"
  echo "--- B peers full:"; ZB core network peers list
  echo "--- B sync status:"; ZB core sync status | head -c 700; echo
fi
echo "--- B log onion lines:"; grep -a "Onion seed\|onion discovery\|kick\|peer-floor\|peer_floor" "$ISO_DD/node.log" | head -15 || true
echo "--- A log inbound:"; grep -a "inbound\|connection" "$ISO_PEER_DD/node.log" | head -8 || true
