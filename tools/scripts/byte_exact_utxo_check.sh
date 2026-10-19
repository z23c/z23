#!/usr/bin/env bash
# byte-exact-from-genesis-check.sh — full-history C8 EXACT tier against the
# producer -full-fold datadir, reusing the replay-canary's exact-tier verbs
# and JSON field names (tools/scripts/replay_canary.sh lines 454-512).
#
# PRE: the producer node is booted NORMALLY (post-fold) and has synced to the
#      live zd tip (gettxoutsetinfo heights must agree on both sides).
#
# Compares, at one agreed height:
#   UC  = getutxocommitment on the producer node (c23 coins SHA3, .sha3_hash)
#   LEG = --legacy-utxo-commitment over the LIVE zd chainstate (read-only
#         WAL-inclusive stable copy; zd keeps running) (.legacy_utxo_sha3)
# PASS iff sha3 + txouts + total_amount are equal at the same height.
#
# Usage: ZCL_PRODUCER_DD=$HOME/.zclassic-c23-producer-fold \
#        ZCL_PRODUCER_RPCPORT=<port> bash byte-exact-from-genesis-check.sh
set -uo pipefail

DD="${ZCL_PRODUCER_DD:?set ZCL_PRODUCER_DD}"
RPCP="${ZCL_PRODUCER_RPCPORT:?set ZCL_PRODUCER_RPCPORT}"
ZD="${ZD_DATADIR:-$HOME/.zclassic}"
ZDRPC="${ZD_RPC:-8232}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${NODE_BIN:-$ROOT/build/bin/z23}"
# zd-side RPC MUST go through zcl-rpc (zclassicd auth — rpcuser/rpcpassword
# from zclassic.conf; the c23 node binary expects a .cookie and is REFUSED).
# Mirrors replay_canary.sh's zd verb (ISO_RPC_BIN = build/bin/zcl-rpc).
ZDRPC_BIN="${ZD_RPC_BIN:-$ROOT/build/bin/zcl-rpc}"

json_field() {
    local v
    v=$(printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" |
        head -1 | sed -E 's/.*:[ ]*"//; s/"$//' || true)
    if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+(\.[0-9]+)?" |
        head -1 | sed -E 's/.*:[ ]*//' || true
}
json_str() { json_field "$1" "$2"; }
json_result_str() { json_field "$1" "$2"; }

deadline=$(( $(date +%s) + 300 ))
while :; do
    TX="$(ZCL_DATADIR="$DD" ZCL_RPCPORT="$RPCP" "$BIN" gettxoutsetinfo 2>/dev/null || true)"
    ZDTX="$(ZCL_DATADIR="$ZD" ZCL_RPCPORT="$ZDRPC" "$ZDRPC_BIN" gettxoutsetinfo 2>/dev/null || true)"
    UC="$(ZCL_DATADIR="$DD" ZCL_RPCPORT="$RPCP" "$BIN" getutxocommitment 2>/dev/null || true)"
    tx_h="$(json_str "$TX" height)"; zd_h="$(json_result_str "$ZDTX" height)"; uc_h="$(json_str "$UC" height)"
    [ -n "$tx_h" ] && [ "$tx_h" = "$zd_h" ] && [ "$tx_h" = "$uc_h" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && { echo "SKIP: heights never agreed (tx=$tx_h zd=$zd_h uc=$uc_h)"; exit 4; }
    sleep 10
done

LEG="$("$BIN" --legacy-utxo-commitment "$ZD" 2>/tmp/legacy_utxo_commitment.stderr || true)"

uc_sha="$(json_str "$UC" sha3_hash)"
leg_sha="$(json_str "$LEG" legacy_utxo_sha3)"
tx_n="$(json_str "$TX" txouts)"; zd_n="$(json_result_str "$ZDTX" txouts)"
tx_s="$(json_str "$TX" total_amount)"; zd_s="$(json_result_str "$ZDTX" total_amount)"

echo "height=$tx_h"
echo "producer coins: sha3=$uc_sha txouts=$tx_n supply=$tx_s"
echo "zd chainstate:  sha3=$leg_sha txouts=$zd_n supply=$zd_s"

if [ -z "$leg_sha" ]; then
    echo "VERDICT=SKIP exact_tier=skew (LEG unusable; see /tmp/legacy_utxo_commitment.stderr)"
    exit 4
fi
if [ "$uc_sha" = "$leg_sha" ] && [ "$tx_n" = "$zd_n" ] && [ "$tx_s" = "$zd_s" ]; then
    echo "VERDICT=PASS exact_tier=match from=genesis-producer-full-fold height=$tx_h"
    exit 0
fi
echo "VERDICT=FAIL exact_tier=mismatch height=$tx_h"
exit 1
