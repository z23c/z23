#!/usr/bin/env bash
# Onion pair-probe: existing member A advertises, joiner B seeds A's onion.
# Portable: runs from any checkout; does not hard-code a host path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ISO_KIND=joinprobe
ISO_PORT_BASE=39160
ISO_PEER_DIAL=39999
. tools/scripts/isolated_node_env.sh
iso_init
# A = the "existing network member": peer slot, tor on, advertises loopback clearnet
iso_spawn_peer "-tor -externalip=127.0.0.1"
echo "[harness] waiting for A p2p listen"; iso_wait_peer_listen 60 || echo A_LISTEN_TIMEOUT
# A's onion identity
A_ONION=""
i=0
while [ $i -lt 240 ]; do
  f="$ISO_PEER_DD/tor_data/onion_service/hostname"
  [ -f "$f" ] && A_ONION=$(tr -d ' \n' < "$f") && [ -n "$A_ONION" ] && break
  kill -0 "$ISO_PEER_PID" 2>/dev/null || { echo A_DIED; tail -5 "$ISO_PEER_DD/node.log"; exit 41; }
  i=$((i+2)); sleep 2
done
[ -n "$A_ONION" ] || { echo A_ONION_TIMEOUT; tail -8 "$ISO_PEER_DD/node.log"; exit 42; }
echo "[harness] A_ONION=$A_ONION"
grep -a "Tor\|onion" "$ISO_PEER_DD/node.log" | head -6 || true
# B = joiner: sandboxed HOME, one-line operator seeds file, NO dead-sink connect
export HOME="$ISO_DD/home"
mkdir -p "$HOME/.config/zclassic23"
printf '%s\n' "$A_ONION" > "$HOME/.config/zclassic23/onion-seeds"
echo "[harness] seeds file:"; cat "$HOME/.config/zclassic23/onion-seeds"
setsid ./build/bin/zclassic23 \
  -datadir="$ISO_DD" -regtest \
  -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
  -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
  -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 -tor \
  >"$ISO_DD/node.log" 2>&1 &
ISO_NODE_PID=$!; ISO_PGID="$ISO_NODE_PID"
echo "[harness] B spawned pid=$ISO_NODE_PID dd=$ISO_DD rpc=$ISO_RPCPORT"
ZB() { ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" ./build/bin/z23 "$@" 2>&1; }
iso_wait_rpc_ready 300 || { echo B_RPC_TIMEOUT; tail -15 "$ISO_DD/node.log"; exit 43; }
echo "[harness] B rpc ready; polling for join evidence"
i=0
while [ $i -lt 300 ]; do
  kill -0 "$ISO_NODE_PID" 2>/dev/null || { echo B_DIED; tail -15 "$ISO_DD/node.log"; exit 44; }
  N=$(ZB core network peers list | grep -o '"items":\[[^]]*\]' | head -c 400)
  C=$(iso_rpc getconnectioncount | tr -dc '0-9-')
  echo "t=${i}s conns=$C items=$N"
  [ -n "$C" ] && [ "$C" -ge 1 ] && break
  i=$((i+5)); sleep 5
done
echo "--- B log onion/seed lines:"; grep -a "Onion seed\|onion\|Tor" "$ISO_DD/node.log" | head -12 || true
echo "--- B peers full:"; ZB core network peers list
echo "--- B sync status:"; ZB core sync status
echo "--- B addnode/status conns:"; ZB core network status | head -c 900; echo
echo "--- A conns (should be >=1 inbound):"; ZCL_DATADIR="$ISO_PEER_DD" ZCL_RPCPORT="$ISO_PEER_RPCPORT" ./build/bin/z23 core network status 2>&1 | head -c 600; echo
