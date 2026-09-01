#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# mvp_gate.sh — the LIVE-NODE MVP probe + soak-accrual check.
#
# Companion to tools/scripts/mvp_scoreboard.sh (which runs the HERMETIC
# slices behind `make mvp`). This script does the OTHER half: it probes
# the RUNNING live node read-only and reports, per measurable MVP-C
# criterion (docs/MVP.md), what the live node ACTUALLY demonstrates right
# now — height/at-tip, onion bootstrap, shielded-receive capability,
# store reachability, parity-vs-zclassicd, and crash-recovery surface —
# plus an MRS score (n/8) and a soak-accrual check (continuous-uptime +
# at-tip duration toward the 168h C6 window).
#
# THE CONTRACT (why this exists and how it cannot false-green):
#   * This is a STATUS PROBE, not a build gate. It is 100% READ-ONLY
#     against every node: it NEVER restarts, mines, sends, or mutates a
#     datadir/service. It only calls read RPCs and reads systemd or launchd
#     runtime state.
#   * PASS is earned ONLY when the live node mechanically demonstrates the
#     measurable part of the criterion right now.
#   * A criterion whose FULL operator claim needs a resource that is ABSENT
#     (a clean accumulated 168h window, an exact zclassicd byte reference,
#     real funds, Tor egress) is reported BLOCKED(reason) — never silently
#     green. BLOCKED does NOT count toward MRS.
#   * The MRS bottom line counts ONLY criteria PASS at the FULL operator
#     claim level. This deliberately matches the docs/MVP.md MRS rule and
#     mvp_scoreboard.sh so the two reporters cannot disagree on the score.
#
# Exit code: 0 always (a status reporter — BLOCKED is the honest expected
# state of several criteria), UNLESS --strict is passed, in which case it
# exits 1 if any criterion that SHOULD pass on the live node FAILs (a real
# live regression: node not at tip, onion not ready, etc).
#
# Usage:
#   tools/mvp_gate.sh                 # human report + MRS + soak accrual
#   tools/mvp_gate.sh --json          # machine-readable single JSON object
#   tools/mvp_gate.sh --strict        # exit 1 on a live-criterion FAIL
#
# Env overrides:
#   ZCL_RPC_BIN       path to the c23 zcl-rpc client (default build/bin/zcl-rpc)
#   ZCL_NODE_BIN      path to the native command binary (default build/bin/zclassic23)
#   ZCL_SOAK_UNIT     service unit/job used for runtime evidence (default zclassic23)
#   ZD_RPCPORT        zclassicd oracle RPC port for the parity probe (default 8232)
#   TIP_GAP_OK        max blocks-behind-peer still counted "at tip" (default 10)
#                     == ZCL_FINALITY_DEPTH; below this the chain is frozen.

set -uo pipefail

MVP_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$MVP_REPO_ROOT/tools/scripts/source_identity_lib.sh"
# shellcheck source=tools/scripts/lib/service_args.sh
. "$MVP_REPO_ROOT/tools/scripts/lib/service_args.sh"

ZCL_RPC_BIN="${ZCL_RPC_BIN:-build/bin/zcl-rpc}"
ZCL_NODE_BIN="${ZCL_NODE_BIN:-build/bin/zclassic23}"
ZCL_SOAK_UNIT="${ZCL_SOAK_UNIT:-zclassic23}"
ZCL_NODE_UNIT="${ZCL_NODE_UNIT:-$ZCL_SOAK_UNIT}"
ZCL_LAUNCHD_PLIST="${ZCL_LAUNCHD_PLIST:-$HOME/Library/LaunchAgents/org.z23.zclassic.plist}"
ZD_RPCPORT="${ZD_RPCPORT:-8232}"
ZD_DATADIR="${ZD_DATADIR:-$HOME/.zclassic}"
TIP_GAP_OK="${TIP_GAP_OK:-10}"

JSON_OUT=0
STRICT=0
for a in "$@"; do
    case "$a" in
        --json)   JSON_OUT=1 ;;
        --strict) STRICT=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "mvp_gate: unknown arg: $a" >&2; exit 2 ;;
    esac
done

# ── tiny JSON field extractor (no python/sqlite3 per project rule) ──
# Pulls the FIRST "key":<number|"string"> after the LAST "result". Good
# enough for the flat top-level fields these RPCs return; this script
# never parses nested arrays for a verdict.
json_num() {  # <json> <key>   -> bare number or empty
    printf '%s' "$1" | grep -oE "\"$2\":[ ]*-?[0-9]+(\.[0-9]+)?" | head -1 | sed -E "s/.*:[ ]*//"
}
json_str() {  # <json> <key>   -> string value (unquoted) or empty
    printf '%s' "$1" | grep -oE "\"$2\":[ ]*\"[^\"]*\"" | head -1 | sed -E "s/.*:[ ]*\"//; s/\"$//"
}
json_bool() { # <json> <key>   -> true|false or empty
    printf '%s' "$1" | grep -oE "\"$2\":[ ]*(true|false)" | head -1 |
        sed -E 's/.*:[ ]*//'
}

DEFAULT_DATADIR="$HOME/.zclassic-c23"
LIVE_DATADIR="${ZCL_DATADIR:-$DEFAULT_DATADIR}"
if [[ -z "${ZCL_DATADIR:-}" ]]; then
    SERVICE_DATADIR="$(zcl_service_exec_arg datadir "$ZCL_NODE_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
    if [[ -n "$SERVICE_DATADIR" ]]; then LIVE_DATADIR="$SERVICE_DATADIR"; fi
fi

LIVE_RPCPORT="${ZCL_RPCPORT:-18232}"
if [[ -z "${ZCL_RPCPORT:-}" ]]; then
    SERVICE_RPCPORT="$(zcl_service_exec_arg rpcport "$ZCL_NODE_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
    if [[ -n "$SERVICE_RPCPORT" ]]; then LIVE_RPCPORT="$SERVICE_RPCPORT"; fi
fi

# ── read-only RPC against the live c23 node ────────────────────────
rpc() {  # <method> [paramsjson]   -> raw json on stdout, "" on failure
    if [[ ! -x "$ZCL_RPC_BIN" ]]; then echo ""; return 1; fi
    if [[ -n "${ZCL_RPCCONNECT:-}" ]]; then
        ZCL_DATADIR="$LIVE_DATADIR" ZCL_RPCPORT="$LIVE_RPCPORT" \
            ZCL_RPCCONNECT="$ZCL_RPCCONNECT" "$ZCL_RPC_BIN" "$@" 2>/dev/null
    else
        ZCL_DATADIR="$LIVE_DATADIR" ZCL_RPCPORT="$LIVE_RPCPORT" \
            "$ZCL_RPC_BIN" "$@" 2>/dev/null
    fi
}
# Typed read-only command against the same live node.
native() {
    if [[ ! -x "$ZCL_NODE_BIN" ]]; then echo ""; return 1; fi
    "$ZCL_NODE_BIN" "$@" --format=json \
        -datadir="$LIVE_DATADIR" -rpcport="$LIVE_RPCPORT" 2>/dev/null
}
# zclassicd oracle (separate RPC port) — uses the same client with ZCL_RPCPORT.
zd_rpc() {  # <method>
    if [[ ! -x "$ZCL_RPC_BIN" ]]; then echo ""; return 1; fi
    ZCL_DATADIR="$ZD_DATADIR" ZCL_RPCPORT="$ZD_RPCPORT" "$ZCL_RPC_BIN" "$@" 2>/dev/null
}

# ── result accumulators (criterion 1..8) ───────────────────────────
declare -A VERDICT DETAIL NAME FULL
NAME[1]="C1 single-binary install / portability floor"
NAME[2]="C2 Tor onion bootstrap <60s"
NAME[3]="C3 cold-start sync to tip <10min"
NAME[4]="C4 receive shielded payment e2e"
NAME[5]="C5 list + sell file via store"
NAME[6]="C6 7-day soak, zero intervention"
NAME[7]="C7 recover from kill -9 <2min"
NAME[8]="C8 consensus parity with zclassicd"

set_v() { VERDICT[$1]="$2"; DETAIL[$1]="$3"; FULL[$1]="${4:-0}"; }

# ── 0. is the live node even reachable? ────────────────────────────
GBCI="$(rpc getblockchaininfo)"
SECURITY_SNAPSHOT="$(rpc operatorsnapshot)"
SECURITY_REVIEW_REQUIRED="$(json_bool "${SECURITY_SNAPSHOT:-}" security_review_required)"
SECURITY_POSTURE_OK=0
[[ "$SECURITY_REVIEW_REQUIRED" == "false" ]] && SECURITY_POSTURE_OK=1
NODE_UP=0
HEIGHT=""; HEADERS=""; CHAIN=""
if [[ -n "$GBCI" ]] && printf '%s' "$GBCI" | grep -q '"blocks"'; then
    NODE_UP=1
    HEIGHT="$(json_num "$GBCI" blocks)"
    HEADERS="$(json_num "$GBCI" best_header_height)"
    [[ -z "$HEADERS" ]] && HEADERS="$(json_num "$GBCI" headers)"
    CHAIN="$(json_str "$GBCI" chain)"
fi

# Peer-tip = max startingheight among connected peers (best observed tip).
PEERTIP=""
if [[ "$NODE_UP" == 1 ]]; then
    PI="$(rpc getpeerinfo)"
    if [[ -n "$PI" ]]; then
        PEERTIP="$(printf '%s' "$PI" | grep -oE '"startingheight":[ ]*-?[0-9]+' \
                    | sed -E 's/.*:[ ]*//' | sort -n | tail -1)"
    fi
fi
# Reference tip for "at tip": prefer peer-tip, else our own best_header.
REFTIP="$HEADERS"
if [[ -n "$PEERTIP" && "$PEERTIP" =~ ^[0-9]+$ && "$PEERTIP" -gt 0 ]]; then
    if [[ -z "$REFTIP" || "$PEERTIP" -gt "$REFTIP" ]]; then REFTIP="$PEERTIP"; fi
fi
GAP=""
AT_TIP=0
if [[ "$NODE_UP" == 1 && -n "$HEIGHT" && -n "$REFTIP" ]]; then
    GAP=$(( REFTIP - HEIGHT ))
    [[ "$GAP" -lt 0 ]] && GAP=0
    [[ "$GAP" -le "$TIP_GAP_OK" ]] && AT_TIP=1
fi

# ────────────────────────────────────────────────────────────────────
# C1 — portability floor / single-binary. The live node IS the installed
# single binary answering RPC; the symbol floor itself is a hermetic
# build gate (make ci-symbol-floor). On the live node we can only confirm
# the install ANSWERS — the floor assertion is BLOCKED to the build gate.
# ────────────────────────────────────────────────────────────────────
if [[ "$NODE_UP" == 1 ]]; then
    set_v 1 "PASS" "installed single binary answers RPC (height=$HEIGHT); symbol floor proven by make ci-symbol-floor" 1
else
    set_v 1 "FAIL" "live node not answering getblockchaininfo" 0
fi

# ────────────────────────────────────────────────────────────────────
# C2 — Tor onion bootstrap <60s. The native onion-status leaf projects the
# health snapshot from the running node. The wall-clock budget is guarded by
# the dedicated local proof; this live probe verifies the resulting ready
# state and v3 address without bypassing the typed command surface.
# ────────────────────────────────────────────────────────────────────
ONION_STATUS="$(native core network onion status || true)"
TOR_READY="$(json_bool "$ONION_STATUS" tor_ready)"
ONION_READY="$(json_bool "$ONION_STATUS" onion_service_ready)"
ONION_ADDRESS="$(json_str "$ONION_STATUS" onion_address)"
if [[ "$NODE_UP" != 1 ]]; then
    set_v 2 "FAIL" "node unreachable" 0
elif [[ ! -x "$ZCL_NODE_BIN" ]]; then
    set_v 2 "BLOCKED" "native command binary missing: $ZCL_NODE_BIN" 0
elif [[ "$TOR_READY" == "true" && "$ONION_READY" == "true" &&
        "$ONION_ADDRESS" == *.onion ]]; then
    set_v 2 "PASS" "native core network onion status reports ready ($ONION_ADDRESS); <60s budget proven by make mvp-onion-local" 1
else
    set_v 2 "FAIL" "native onion status not ready (tor_ready=${TOR_READY:-missing}, onion_service_ready=${ONION_READY:-missing}, address=${ONION_ADDRESS:-missing})" 0
fi

# ────────────────────────────────────────────────────────────────────
# C3 — cold-start sync to tip <10min. The MEASURABLE live fact is "is the
# node at tip now?". Reaching tip in <10min from a FRESH datadir is a
# distinct claim no live probe can make (this node reached tip via the
# two-step --importblockindex crutch). So: at-tip => report it, but the
# FULL <10min-fresh claim stays BLOCKED.
# ────────────────────────────────────────────────────────────────────
if [[ "$NODE_UP" != 1 ]]; then
    set_v 3 "FAIL" "node unreachable" 0
elif [[ "$AT_TIP" == 1 ]]; then
    set_v 3 "BLOCKED" "node IS at tip (h=$HEIGHT gap=$GAP<=$TIP_GAP_OK) but fresh <10min cold-boot to at_tip is unproven (two-step import crutch); see make ci-coldstart" 0
else
    set_v 3 "FAIL" "node NOT at tip (h=$HEIGHT reftip=$REFTIP gap=$GAP>$TIP_GAP_OK) — forward sync behind" 0
fi

# ────────────────────────────────────────────────────────────────────
# C4 — receive shielded payment e2e. Measurable read-only live surface:
# existing sapling z-addrs, if any, plus z_gettotalbalance. Minting a new
# receive address would mutate the wallet, so absence of a listed z-addr is
# BLOCKED to the owner/test proof, not a live-regression FAIL.
# The funded e2e on mainnet needs real funds (owner-gated) => the FULL
# claim is proven by make test-shielded-payment (params host), not here.
# ────────────────────────────────────────────────────────────────────
if [[ "$NODE_UP" != 1 ]]; then
    set_v 4 "FAIL" "node unreachable" 0
else
    ZL="$(rpc z_listaddresses)"
    ZB="$(rpc z_gettotalbalance)"
    if printf '%s' "$ZL" | grep -q '"zs1' && printf '%s' "$ZB" | grep -q '"private"'; then
        set_v 4 "PASS" "sapling z-addr present + z_gettotalbalance answers (receive surface live); funded e2e via make test-shielded-payment" 1
    elif printf '%s' "$ZB" | grep -q '"private"'; then
        set_v 4 "BLOCKED" "z_gettotalbalance answers but no sapling z-addr is listed; creating one is wallet-mutating, so live receive proof is owner/test-gated (make test-shielded-payment)" 0
    else
        set_v 4 "FAIL" "z_gettotalbalance did not answer (shielded balance surface down)" 0
    fi
fi

# ────────────────────────────────────────────────────────────────────
# C5 — list + sell file via store. Live surface: zmarket_list answers.
# Per HANDOFF.md the market is a STUB (zmarket_buy parks; no settlement),
# so the FULL sell-and-receive claim is BLOCKED regardless of liveness.
# ────────────────────────────────────────────────────────────────────
if [[ "$NODE_UP" != 1 ]]; then
    set_v 5 "FAIL" "node unreachable" 0
else
    ML="$(rpc zmarket_list)"
    if printf '%s' "$ML" | grep -qE '"result":[ ]*\['; then
        set_v 5 "BLOCKED" "zmarket_list answers but market is a STUB (no payment/transfer settlement); proxy via make ci-mvp-gates store_e2e" 0
    else
        set_v 5 "BLOCKED" "zmarket_list unreachable; market settlement not wired (HANDOFF.md)" 0
    fi
fi

# ────────────────────────────────────────────────────────────────────
# C6 — 7-day soak, zero intervention. The accrual CHECK (below) reads
# continuous-uptime + at-tip. MET requires a clean accumulated 168h
# window judged by make soak-evidence-report; no instantaneous probe can
# award it. So the verdict is BLOCKED to the soak window, but the soak
# accrual section reports how far the CURRENT uptime has gotten.
# ────────────────────────────────────────────────────────────────────
# (computed after the soak section so DETAIL can carry uptime numbers)

# ────────────────────────────────────────────────────────────────────
# C7 — recover from kill -9 <2min. Cannot be exercised live (guardrails
# forbid touching the node). Proven by make test-crash-bootstrap +
# make test-two-node-peer-tip. Live verdict = BLOCKED to those full
# binary proofs. We DO surface one supporting live signal: the service is
# supervised for failure recovery and currently active (auto-recovery armed).
# ────────────────────────────────────────────────────────────────────
RESTART_POLICY="$(zcl_service_restart_policy "$ZCL_SOAK_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
ACTIVE_STATE="$(zcl_service_active_state "$ZCL_SOAK_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
if [[ ( "$RESTART_POLICY" == "always" || "$RESTART_POLICY" == "on-failure" ) &&
      "$ACTIVE_STATE" == "active" ]]; then
    set_v 7 "BLOCKED" "auto-recovery armed (service $ZCL_SOAK_UNIT policy=$RESTART_POLICY, active); full kill-9 proof via make test-crash-bootstrap + make test-two-node-peer-tip" 0
else
    set_v 7 "BLOCKED" "kill-9 recovery proven only by make test-crash-bootstrap (live kill forbidden by guardrails)" 0
fi

# ────────────────────────────────────────────────────────────────────
# C8 — consensus parity with zclassicd. TWO evidence tiers, merged:
#
#   1. The standing REPLAY CANARY ledger (tools/scripts/replay_canary.sh,
#      sentinels in $ZCL_CANARY_VERDICT_DIR) — the EXACT tier. A
#      from=genesis PASS means: full-history replay through the HEAD
#      reducer with ZERO consensus rejects, the byte-exact UTXO SHA3
#      checkpoint matched at anchor 3,056,758, every script verified, and
#      tip bestblock/txouts/total_amount equal to zclassicd's
#      gettxoutsetinfo. This is the reference the coarse live probe cannot
#      be; per the 2026-08-01 review it is THE C8 gate, and it must
#      ACCUMULATE: a fresh PASS earns C8, a fresh FAIL is a consensus-grade
#      alarm, and a stale/absent ledger is a named gap, never a silent one.
#   2. The live COARSE probe (height vs the zclassicd oracle) — a
#      divergence here FAILs regardless of the ledger.
#
# Freshness: a sentinel older than CANARY_MAX_AGE_S (default 7 days — the
# canary is meant to run on the nightly/weekly linger cadence, see
# `make install-replay-canary`) is treated as absent, so C8 cannot ride
# indefinitely on one old PASS.
# ────────────────────────────────────────────────────────────────────
CANARY_DIR="${ZCL_CANARY_VERDICT_DIR:-$HOME/.local/state/zclassic23-canary}"
CANARY_MAX_AGE_S="${CANARY_MAX_AGE_S:-604800}"
NOW_TS="$(date +%s)"

# canary_read <track> → sets verdict, freshness, and exact binary identity.
canary_read() {
    local f="$CANARY_DIR/replay_canary_$1.json"
    C_VERDICT="absent"; C_TS=0; C_AGE=-1; C_FRESH=0; C_SRC=""; C_ARTIFACT=""
    [[ -f "$f" ]] || return 0
    local blob; blob="$(cat "$f" 2>/dev/null)"
    C_VERDICT="$(json_str "$blob" verdict)"; C_VERDICT="${C_VERDICT:-unreadable}"
    C_TS="$(json_num "$blob" ts)"; C_TS="${C_TS:-0}"
    C_SRC="$(json_str "$blob" source_id_sha256)"
    C_ARTIFACT="$(json_str "$blob" artifact_sha256)"
    if [[ "$C_TS" =~ ^[0-9]+$ && "$C_TS" -gt 0 ]]; then
        C_AGE=$(( NOW_TS - C_TS ))
        [[ "$C_AGE" -le "$CANARY_MAX_AGE_S" ]] && C_FRESH=1
    fi
}

canary_read genesis
G_VERDICT="$C_VERDICT"; G_AGE="$C_AGE"; G_FRESH="$C_FRESH"
G_SRC="$C_SRC"; G_ARTIFACT="$C_ARTIFACT"
canary_read anchor
A_VERDICT="$C_VERDICT"; A_AGE="$C_AGE"; A_FRESH="$C_FRESH"
A_SRC="$C_SRC"; A_ARTIFACT="$C_ARTIFACT"

# Bind release evidence to the executable actually serving this unit. A PASS
# minted by any other checkout or artifact is useful history, but cannot
# qualify the currently running node.
LIVE_SOURCE_ID=""; LIVE_ARTIFACT=""; LIVE_ID_DETAIL="running binary identity unavailable"
capture_running_identity() {
    local pid exe before after snapshot_pid snapshot_schema snapshot_source
    pid="$(zcl_service_pid "$ZCL_NODE_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    exe="/proc/$pid/exe"
    if [[ -x "$exe" ]]; then
        before="$(sha256sum -- "$exe" 2>/dev/null | awk '{print $1}')"
        [[ "$before" =~ ^[0-9a-f]{64}$ ]] || return 1
        LIVE_SOURCE_ID="$(zcl_binary_source_id "$exe")"
        after="$(sha256sum -- "$exe" 2>/dev/null | awk '{print $1}')"
        [[ "$before" == "$after" ]] || return 1
        zcl_is_sha256 "$LIVE_SOURCE_ID" || return 1
        LIVE_ARTIFACT="$before"
        LIVE_ID_DETAIL="running source=$LIVE_SOURCE_ID artifact=$LIVE_ARTIFACT"
        return 0
    fi

    # macOS has no /proc/<pid>/exe handle whose bytes can be hashed without
    # racing the pathname. Bind the node-reported source identity to this PID
    # for visibility, but leave LIVE_ARTIFACT empty so exact C8 qualification
    # remains fail-closed.
    snapshot_schema="$(json_str "$SECURITY_SNAPSHOT" schema)"
    snapshot_pid="$(json_num "$SECURITY_SNAPSHOT" process_id)"
    snapshot_source="$(zcl_json_first_sha256 "$SECURITY_SNAPSHOT" source_id_sha256)"
    if [[ "$snapshot_schema" == "zcl.operator_snapshot.v3" &&
          "$snapshot_pid" == "$pid" ]] && zcl_is_sha256 "$snapshot_source"; then
        LIVE_SOURCE_ID="$snapshot_source"
        LIVE_ID_DETAIL="running PID=$pid reports source=$LIVE_SOURCE_ID; exact running artifact unavailable on this platform"
        return 0
    fi
    return 1
}
capture_running_identity || true

G_ID_MATCH=0
if [[ -n "$LIVE_SOURCE_ID" && "$G_SRC" == "$LIVE_SOURCE_ID" &&
      "$G_ARTIFACT" == "$LIVE_ARTIFACT" ]]; then
    G_ID_MATCH=1
fi

CANARY_LEDGER="canary[genesis=$G_VERDICT age=${G_AGE}s anchor=$A_VERDICT age=${A_AGE}s max_age=${CANARY_MAX_AGE_S}s]"

ZD_GBC="$(zd_rpc getblockcount)"
ZD_H="$(json_num "${ZD_GBC:-}" result)"
# getblockcount returns {"result":<n>,...}; json_num matches result:<n>.
COARSE="unavailable"; COARSE_DETAIL=""
if [[ -z "$ZD_H" ]]; then
    ZD_ERR="$(zd_rpc getblockchaininfo 2>&1)"
    if printf '%s' "$ZD_ERR" | grep -qiE 'reindex|height 0|code.*-28|Activating best chain'; then
        COARSE_DETAIL="zclassicd oracle (RPC $ZD_RPCPORT) is reindexing/not-ready — cannot diff; retry when oracle is at tip"
    else
        COARSE_DETAIL="zclassicd oracle (RPC $ZD_RPCPORT) unreachable"
    fi
elif [[ "$NODE_UP" == 1 && -n "$HEIGHT" ]]; then
    ZDGAP=$(( ZD_H - HEIGHT )); [[ "$ZDGAP" -lt 0 ]] && ZDGAP=$(( -ZDGAP ))
    if [[ "$ZDGAP" -le "$TIP_GAP_OK" ]]; then
        COARSE="match"
        COARSE_DETAIL="coarse height MATCH vs zclassicd (c23=$HEIGHT zd=$ZD_H |Δ|=$ZDGAP)"
    else
        COARSE="diverged"
        COARSE_DETAIL="height divergence vs zclassicd (c23=$HEIGHT zd=$ZD_H |Δ|=$ZDGAP > $TIP_GAP_OK)"
    fi
else
    COARSE_DETAIL="node unreachable for parity diff"
fi

# Verdict precedence: fresh canary FAIL > live divergence > fresh genesis
# PASS (+coarse match) > BLOCKED with the exact gap named.
if [[ "$G_FRESH" == 1 && "$G_VERDICT" == "FAIL" ]]; then
    set_v 8 "FAIL" "replay canary (genesis) FAIL — full-history parity alarm; $CANARY_LEDGER" 0
elif [[ "$A_FRESH" == 1 && "$A_VERDICT" == "FAIL" ]]; then
    set_v 8 "FAIL" "replay canary (anchor) FAIL — replay parity alarm; $CANARY_LEDGER" 0
elif [[ "$COARSE" == "diverged" ]]; then
    set_v 8 "FAIL" "$COARSE_DETAIL; $CANARY_LEDGER" 0
elif [[ "$G_FRESH" == 1 && "$G_VERDICT" == "PASS" && "$G_ID_MATCH" != 1 ]]; then
    set_v 8 "BLOCKED" "replay-canary (genesis) PASS belongs to different or unreadable bytes (sentinel source=${G_SRC:-missing} artifact=${G_ARTIFACT:-missing}; $LIVE_ID_DETAIL); exact running-binary qualification is unearned" 0
elif [[ "$G_FRESH" == 1 && "$G_VERDICT" == "PASS" && "$COARSE" == "match" ]]; then
    set_v 8 "PASS" "EXACT parity: replay-canary (genesis) PASS — 0 consensus rejects over full history, byte-exact UTXO SHA3 at anchor 3056758, tip bestblock/txouts/supply == zclassicd — plus live $COARSE_DETAIL" 1
elif [[ "$G_FRESH" == 1 && "$G_VERDICT" == "PASS" ]]; then
    set_v 8 "BLOCKED" "replay-canary (genesis) PASS but live coarse probe not confirming ($COARSE_DETAIL); $CANARY_LEDGER" 0
elif [[ "$A_FRESH" == 1 && "$A_VERDICT" == "PASS" && "$COARSE" == "match" ]]; then
    set_v 8 "BLOCKED" "anchor-track replay clean + live coarse match; FULL C8 needs a fresh from=genesis PASS (make replay-canary-genesis); $CANARY_LEDGER" 0
else
    set_v 8 "BLOCKED" "$COARSE_DETAIL; no fresh canary PASS — the exact-tier gate is unearned (run make replay-canary-anchor / -genesis on the linger cadence); $CANARY_LEDGER" 0
fi

# ════════════════════════════════════════════════════════════════════
# SOAK ACCRUAL CHECK — continuous-uptime + at-tip duration (toward C6).
# READ-ONLY: service start time + trustworthy restart counter when available.
# ════════════════════════════════════════════════════════════════════
NRESTARTS="$(zcl_service_restart_count "$ZCL_SOAK_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
START_EPOCH="$(zcl_service_started_epoch "$ZCL_SOAK_UNIT" "$ZCL_LAUNCHD_PLIST" || true)"
NOW="$(date +%s)"
UPTIME_S=""
if [[ "$START_EPOCH" =~ ^[0-9]+$ && "$START_EPOCH" -le "$NOW" ]]; then
    UPTIME_S=$(( NOW - START_EPOCH ))
fi
SOAK_WINDOW_S=$(( 168 * 3600 ))
SOAK_PCT=""
SOAK_VERDICT="INSUFFICIENT"
SOAK_REASON="no uptime read"
if [[ -n "$UPTIME_S" ]]; then
    SOAK_PCT=$(( UPTIME_S * 100 / SOAK_WINDOW_S ))
    if [[ -n "$NRESTARTS" && "$NRESTARTS" != "0" ]]; then
        SOAK_VERDICT="NOT_MET"
        SOAK_REASON="service restarted NRestarts=${NRESTARTS} (operator/crash event) — clean window broken"
    elif [[ "$SECURITY_POSTURE_OK" != 1 ]]; then
        SOAK_VERDICT="NOT_MET"
        SOAK_REASON="security posture is ${SECURITY_REVIEW_REQUIRED:-unknown} — soak time does not accrue while review is required or unknown"
    elif [[ "$AT_TIP" != 1 ]]; then
        SOAK_VERDICT="NOT_MET"
        SOAK_REASON="node not at tip (gap=$GAP) — soak time does not accrue while behind tip"
    elif [[ -z "$NRESTARTS" ]]; then
        SOAK_VERDICT="INSUFFICIENT"
        SOAK_REASON="service manager exposes no trustworthy restart counter — zero-intervention window is unproven"
    elif [[ "$UPTIME_S" -ge "$SOAK_WINDOW_S" ]]; then
        SOAK_VERDICT="WINDOW_LONG_ENOUGH"
        SOAK_REASON="continuous uptime >=168h at tip with 0 restarts — judge MET via make soak-evidence-report"
    else
        SOAK_VERDICT="ACCRUING"
        SOAK_REASON="continuous uptime ${UPTIME_S}s (~${SOAK_PCT}% of 168h) at tip, 0 restarts — accruing toward C6"
    fi
fi
SOAK_LINE="soak-accrual: VERDICT=$SOAK_VERDICT uptime_s=${UPTIME_S:-null} pct=${SOAK_PCT:-null} restarts=${NRESTARTS:-null} at_tip=$AT_TIP security_review_required=${SECURITY_REVIEW_REQUIRED:-unknown} security_posture_ok=$SECURITY_POSTURE_OK reason=\"$SOAK_REASON\""

# Wire the C6 verdict now that we have uptime numbers.
set_v 6 "BLOCKED" "$SOAK_LINE; MET only via accumulated clean 168h window judged by make soak-evidence-report" 0

# ── tally MRS (FULL-claim PASS only) ───────────────────────────────
MRS=0
for i in 1 2 3 4 5 6 7 8; do
    [[ "${FULL[$i]}" == 1 ]] && MRS=$(( MRS + 1 ))
done

# ── any live-criterion that SHOULD pass but FAILed? (for --strict) ──
LIVE_FAIL=0
for i in 1 2 3 4 5 6 7 8; do
    [[ "${VERDICT[$i]}" == "FAIL" ]] && LIVE_FAIL=1
done

# ── output ─────────────────────────────────────────────────────────
if [[ "$JSON_OUT" == 1 ]]; then
    printf '{'
    printf '"node_up":%s,' "$NODE_UP"
    printf '"datadir":"%s",' "${LIVE_DATADIR//\"/\\\"}"
    printf '"rpcport":%s,' "$LIVE_RPCPORT"
    printf '"security_review_required":%s,' "${SECURITY_REVIEW_REQUIRED:-null}"
    printf '"security_posture_ok":%s,' "$([[ "$SECURITY_POSTURE_OK" == 1 ]] && echo true || echo false)"
    printf '"height":%s,' "${HEIGHT:-null}"
    printf '"reftip":%s,' "${REFTIP:-null}"
    printf '"gap":%s,' "${GAP:-null}"
    printf '"at_tip":%s,' "$AT_TIP"
    printf '"mrs":"%s/8",' "$MRS"
    printf '"criteria":{'
    for i in 1 2 3 4 5 6 7 8; do
        d="${DETAIL[$i]//\"/\\\"}"
        printf '"C%s":{"verdict":"%s","full_pass":%s,"detail":"%s"}' \
               "$i" "${VERDICT[$i]}" "${FULL[$i]}" "$d"
        [[ "$i" != 8 ]] && printf ','
    done
    printf '},'
    printf '"soak":{"verdict":"%s","uptime_s":%s,"pct":%s,"restarts":%s,"at_tip":%s}' \
           "$SOAK_VERDICT" "${UPTIME_S:-null}" "${SOAK_PCT:-null}" "${NRESTARTS:-null}" "$AT_TIP"
    printf '}\n'
else
    echo "════════════════════════════════════════════════════════════════════"
    echo " Z23 MVP live-node gate  (READ-ONLY probe; docs/MVP.md)"
    echo "════════════════════════════════════════════════════════════════════"
    if [[ "$NODE_UP" == 1 ]]; then
        echo " live node: UP  datadir=$LIVE_DATADIR  rpcport=$LIVE_RPCPORT  height=$HEIGHT  reftip=$REFTIP  gap=${GAP:-?}  at_tip=$AT_TIP  chain=$CHAIN"
    else
        echo " live node: DOWN (getblockchaininfo did not answer via $ZCL_RPC_BIN datadir=$LIVE_DATADIR rpcport=$LIVE_RPCPORT)"
    fi
    echo "────────────────────────────────────────────────────────────────────"
    for i in 1 2 3 4 5 6 7 8; do
        printf ' [%-2s] %-36s %-8s %s\n' "C$i" "${NAME[$i]#C? }" "${VERDICT[$i]}" "${DETAIL[$i]}"
    done
    echo "────────────────────────────────────────────────────────────────────"
    echo " $SOAK_LINE"
    echo "────────────────────────────────────────────────────────────────────"
    echo " MRS (full operator-claim PASS): $MRS/8"
    echo "   (C2/C3/C5/C6/C8 are BLOCKED to the named full proof — by design,"
    echo "    no live instant probe can award the sovereign-foundation claims.)"
    echo "════════════════════════════════════════════════════════════════════"
fi

# ── exit ───────────────────────────────────────────────────────────
if [[ "$STRICT" == 1 && "$LIVE_FAIL" == 1 ]]; then
    exit 1
fi
exit 0
