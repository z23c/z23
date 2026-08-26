#!/usr/bin/env bash
# Read-only health summary for the live/soak/dev node lanes.
#
# This is an operational guard, not a failover controller. It makes the
# three-lane topology visible so development restarts do not accidentally
# consume the public node or the long-running soak evidence lane.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The ONE reader per measurement (peers, RSS, disk bytes, systemd, node
# self-report). Sourced so this script and every evidence ledger measure
# the same host the same way — see tools/scripts/lib/evidence_sources.sh.
. "$SCRIPT_DIR/lib/evidence_sources.sh"

JSON=0
STRICT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
        --strict) STRICT=1 ;;
        -h|--help)
            cat <<'USAGE'
usage: tools/scripts/lane_health.sh [--json] [--strict]

Reports live, soak, and dev lane systemd/RPC/socket health, role readiness,
memory pressure, and soak-evidence eligibility without mutating any service.
--strict exits non-zero when any lane has status=fail.
USAGE
            exit 0
            ;;
        *)
            echo "lane-health: unknown arg '$1'" >&2
            exit 2
            ;;
    esac
    shift
done

ZCL_CLI="${ZCL_CLI:-$REPO_ROOT/build/bin/zclassic-cli}"
RPC_TIMEOUT="${ZCL_LANE_RPC_TIMEOUT:-3}"
AGENT_RPC_TIMEOUT="${ZCL_LANE_AGENT_TIMEOUT:-10}"
LAG_WARN="${ZCL_LANE_LAG_WARN:-10}"
SOAK_LAG_WARN="${ZCL_SOAK_LAG_WARN:-$LAG_WARN}"

# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$REPO_ROOT/tools/scripts/stopwatch_json_lib.sh"  # json_escape
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$REPO_ROOT/tools/scripts/source_identity_lib.sh"  # zcl_json_first_string, zcl_is_sha256

json_bool() {
    if [ "$1" = "1" ]; then
        printf 'true'
    else
        printf 'false'
    fi
}

json_tri_bool() {
    case "$1" in
        1) printf 'true' ;;
        0) printf 'false' ;;
        *) printf 'null' ;;
    esac
}

json_number() {
    case "${1:-}" in
        ''|*[!0-9]*) printf 'null' ;;
        *) printf '%s' "$1" ;;
    esac
}

is_number() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

is_safe_arith_number() {
    is_number "$1" && [ "${#1}" -le 18 ]
}

json_string_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
        | head -1
}

json_int_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p" \
        | head -1
}

json_bool_field() {
    local body="$1" key="$2" v
    v="$(printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" \
        | head -1)"
    case "$v" in
        true) printf 1 ;;
        false) printf 0 ;;
        *) printf null ;;
    esac
}

json_first_bool_field() {
    local body="$1" key="$2" token
    token="$(printf '%s\n' "$body" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\\(true\\|false\\)" 2>/dev/null \
        | head -1 || true)"
    case "$token" in
        *true) printf 1 ;;
        *false) printf 0 ;;
        *) printf null ;;
    esac
}

lane_health_selftest() {
    local sample op blocked detail ready source_id
    sample='{"schema":"zcl.public_status.v2","source_id_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","build_commit":"display-only","status":"blocked","operator_needed":true,"primary_blocker":"operator_needed:window.consistency","restart_watchdog":{"operator_needed":false},"readiness":{"chain_serving_ready":true},"reducer":{"validation_pack_ok":false,"validation_pack_detail":"window.consistency"}}'
    op="$(json_first_bool_field "$sample" "operator_needed")"
    blocked="$(zcl_json_first_string "$sample" "status")"
    detail="$(zcl_json_first_string "$sample" "validation_pack_detail")"
    ready="$(json_first_bool_field "$sample" "chain_serving_ready")"
    source_id="$(zcl_json_first_string "$sample" "source_id_sha256")"
    [ "$op" = "1" ] || {
        echo "lane-health selftest: expected first operator_needed=true" >&2
        return 1
    }
    [ "$blocked" = "blocked" ] || {
        echo "lane-health selftest: expected status=blocked" >&2
        return 1
    }
    [ "$detail" = "window.consistency" ] || {
        echo "lane-health selftest: expected validation detail" >&2
        return 1
    }
    [ "$ready" = "1" ] || {
        echo "lane-health selftest: expected nested readiness=true" >&2
        return 1
    }
    zcl_is_sha256 "$source_id" || {
        echo "lane-health selftest: expected valid source_id_sha256" >&2
        return 1
    }
    if zcl_is_sha256 "195a636c6173736963205369676e6564204d657373"; then
        echo "lane-health selftest: Git/SHA-1-sized identity was trusted" >&2
        return 1
    fi
    return 0
}

if [ "${ZCL_LANE_HEALTH_SELFTEST:-0}" = "1" ]; then
    lane_health_selftest
    exit $?
fi

highest_snapshot() {
    local datadir="$1" file base stem best_h best_path
    best_h=""
    best_path=""
    if [ -d "$datadir" ]; then
        for file in "$datadir"/utxo-seed-*.snapshot; do
            [ -e "$file" ] || continue
            base="${file##*/}"
            stem="${base#utxo-seed-}"
            stem="${stem%.snapshot}"
            is_safe_arith_number "$stem" || continue
            if [ -z "$best_h" ] || [ "$stem" -gt "$best_h" ]; then
                best_h="$stem"
                best_path="$file"
            fi
        done
    fi
    printf '%s|%s\n' "$best_h" "$best_path"
}

exec_arg_value() {
    local cmdline="$1" key="$2"
    printf '%s\n' "$cmdline" \
        | tr ' ' '\n' \
        | sed -n "s/^${key}=//p" \
        | head -1
}

memory_pressure_state() {
    local current="$1" high="$2"
    if ! is_safe_arith_number "$current" || ! is_safe_arith_number "$high"; then
        printf unknown
        return
    fi
    if [ "$high" -le 0 ]; then
        printf unknown
        return
    fi

    local pct=$((current * 100 / high))
    if [ "$pct" -ge 95 ]; then
        printf warn
    elif [ "$pct" -ge 85 ]; then
        printf watch
    else
        printf ok
    fi
}

state_from_status() {
    case "$1" in
        ok) printf ready ;;
        warn) printf degraded ;;
        *) printf down ;;
    esac
}

systemd_show() {
    local unit="$1" prop="$2"
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user show "$unit" -p "$prop" --value 2>/dev/null || true
}

listen_state() {
    local port="$1"
    command -v ss >/dev/null 2>&1 || return 1
    ss -ltn 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]"
}

rpc_call() {
    local datadir="$1" rpcport="$2"
    shift 2
    [ -x "$ZCL_CLI" ] || return 1
    timeout "$RPC_TIMEOUT" "$ZCL_CLI" -datadir="$datadir" -rpcport="$rpcport" "$@" 2>/dev/null
}

rpc_call_timeout() {
    local timeout_s="$1" datadir="$2" rpcport="$3"
    shift 3
    [ -x "$ZCL_CLI" ] || return 1
    timeout "$timeout_s" "$ZCL_CLI" -datadir="$datadir" -rpcport="$rpcport" "$@" 2>/dev/null
}

# peer_count_from_json: stdin filter, delegating to the shared reader.
# The counting rule ("addr" keys in a getpeerinfo response) moved to
# lib/evidence_sources.sh when the SLO ledger started recording peers too —
# two implementations of "how many peers" is exactly how a lane report and
# a ledger come to disagree about the same instant.
peer_count_from_json() { evidence_peer_count_from_json; }

json_true_count() {
    local body="$1" key="$2"
    printf '%s\n' "$body" \
        | { grep -o "\"${key}\"[[:space:]]*:[[:space:]]*true" 2>/dev/null || true; } \
        | wc -l | tr -d ' '
}

report_lane() {
    local lane="$1" unit="$2" datadir="$3" rpcport="$4" p2p_port="$5" role="$6"
    local active mainpid restarts start_ts mem_current mem_high mem_max mem_pressure
    local cmdline rpc_up height peers p2p_listening rpc_listening reindex
    local tip_lag status reason role_ready role_reason soak_eligible soak_reason
    local agent_json agent_rpc_state agent_source_id_sha256 agent_build_commit
    local agent_contract_trusted agent_contract_trust_reason
    local agent_status agent_operator_needed agent_primary_blocker
    local agent_next agent_validation_pack_ok agent_validation_pack_detail
    local agent_chain_serving_ready agent_work_ready
    local bootstrap_json snapshot_info snapshot_seed_height snapshot_path
    local snapshot_present loader_path loader_configured recovery_hint
    local chaininfo_json chain_headers initialblockdownload
    local reducer_json condition_json reducer_hstar reducer_pending_stage
    local reducer_pending_detail reducer_primary_stage reducer_primary_detail
    local reducer_blocker_count condition_active_count condition_unresolved_count
    local condition_operator_needed_count
    local chain_advance_json chain_advance_current_json projection_height projection_lag
    local projection_deferred projection_state projection_deferred_reason

    active="$(systemd_show "$unit" ActiveState)"
    [ -n "$active" ] || active="unknown"
    mainpid="$(systemd_show "$unit" MainPID)"
    [ -n "$mainpid" ] || mainpid="0"
    restarts="$(systemd_show "$unit" NRestarts)"
    [ -n "$restarts" ] || restarts="null"
    start_ts="$(systemd_show "$unit" ExecMainStartTimestamp)"
    [ -n "$start_ts" ] || start_ts="unknown"
    mem_current="$(systemd_show "$unit" MemoryCurrent)"
    mem_high="$(systemd_show "$unit" MemoryHigh)"
    mem_max="$(systemd_show "$unit" MemoryMax)"
    mem_pressure="$(memory_pressure_state "$mem_current" "$mem_high")"

    cmdline=""
    if [ "$mainpid" != "0" ] && [ -r "/proc/$mainpid/cmdline" ]; then
        cmdline="$(tr '\0' ' ' <"/proc/$mainpid/cmdline")"
    fi

    reindex=0
    case "$cmdline" in
        *" -reindex-chainstate"*|*"-reindex-chainstate "*) reindex=1 ;;
    esac

    snapshot_seed_height=""
    snapshot_path=""
    snapshot_present=0
    loader_path="$(exec_arg_value "$cmdline" "-load-snapshot-at-own-height")"
    loader_configured=0
    [ -n "$loader_path" ] && loader_configured=1
    recovery_hint=""
    chain_headers=""
    initialblockdownload="null"
    reducer_json=""
    condition_json=""
    reducer_hstar=""
    reducer_pending_stage=""
    reducer_pending_detail=""
    reducer_primary_stage=""
    reducer_primary_detail=""
    reducer_blocker_count=""
    condition_active_count=""
    condition_unresolved_count=""
    condition_operator_needed_count=""
    projection_height=""
    projection_lag=""
    projection_deferred="null"
    projection_state=""
    projection_deferred_reason=""
    agent_source_id_sha256=""
    agent_build_commit=""
    agent_rpc_state="not_called"
    agent_contract_trusted=0
    agent_contract_trust_reason="agent_rpc_not_called"
    agent_status=""
    agent_operator_needed="null"
    agent_primary_blocker=""
    agent_next=""
    agent_validation_pack_ok="null"
    agent_validation_pack_detail=""
    agent_chain_serving_ready="null"
    agent_work_ready="null"

    p2p_listening=0
    rpc_listening=0
    listen_state "$p2p_port" && p2p_listening=1
    listen_state "$rpcport" && rpc_listening=1

    rpc_up=0
    height=""
    if height="$(rpc_call "$datadir" "$rpcport" getblockcount)"; then
        case "$height" in
            ''|*[!0-9]*) height="" ;;
            *) rpc_up=1 ;;
        esac
    else
        height=""
    fi

    peers=""
    if [ "$rpc_up" = "1" ]; then
        peers="$(rpc_call "$datadir" "$rpcport" getpeerinfo | peer_count_from_json)"
        chaininfo_json="$(rpc_call "$datadir" "$rpcport" getblockchaininfo || true)"
        if [ -n "$chaininfo_json" ]; then
            chain_headers="$(json_int_field "$chaininfo_json" "headers")"
            initialblockdownload="$(json_bool_field "$chaininfo_json" "initialblockdownload")"
        fi
        agent_json=""
        if agent_json="$(rpc_call_timeout "$AGENT_RPC_TIMEOUT" "$datadir" "$rpcport" agent)"; then
            if [ -n "$agent_json" ]; then
                agent_rpc_state="ok"
            else
                agent_rpc_state="empty"
            fi
        else
            case "$?" in
                124) agent_rpc_state="timeout" ;;
                *) agent_rpc_state="error" ;;
            esac
        fi
        agent_contract_trust_reason="agent_rpc_${agent_rpc_state}"
        if [ "$agent_rpc_state" = "ok" ]; then
            # Positional (zcl_json_first_string), not the schema-anchored
            # zcl_agentbuild_v2_top_source_id reader: $agent_json comes from
            # the `agent` RPC's zcl.public_status.v2/v3 contract, not
            # agentbuild's zcl.agent_build.v2 — no strict top-anchored reader
            # exists for this schema in source_identity_lib.sh. Left as-is
            # deliberately: this only feeds agent_contract_trusted/
            # agent_contract_trust_reason, an advisory trust flag, never a
            # freshness verdict (see the line-132 selftest for the same
            # schema). Lowest priority of the sites this lane reviewed.
            agent_source_id_sha256="$(zcl_json_first_string "$agent_json" "source_id_sha256")"
            agent_build_commit="$(zcl_json_first_string "$agent_json" "build_commit")"
            if zcl_is_sha256 "$agent_source_id_sha256"; then
                agent_contract_trusted=1
                agent_contract_trust_reason="valid_source_id_sha256"
            elif [ -n "$agent_source_id_sha256" ]; then
                agent_contract_trust_reason="invalid_source_id_sha256"
            else
                agent_contract_trust_reason="missing_source_id_sha256"
            fi
            agent_status="$(zcl_json_first_string "$agent_json" "status")"
            agent_operator_needed="$(json_first_bool_field "$agent_json" "operator_needed")"
            agent_primary_blocker="$(zcl_json_first_string "$agent_json" "primary_blocker")"
            agent_next="$(zcl_json_first_string "$agent_json" "next")"
            agent_validation_pack_ok="$(json_first_bool_field "$agent_json" "validation_pack_ok")"
            agent_validation_pack_detail="$(zcl_json_first_string "$agent_json" "validation_pack_detail")"
            agent_chain_serving_ready="$(json_first_bool_field "$agent_json" "chain_serving_ready")"
            agent_work_ready="$(json_first_bool_field "$agent_json" "agent_work_ready")"
        fi
        if [ "$agent_contract_trusted" != "1" ]; then
            condition_json="$(rpc_call "$datadir" "$rpcport" dumpstate condition_engine || true)"
            if [ -n "$condition_json" ]; then
                condition_active_count="$(json_int_field "$condition_json" "active_count")"
                condition_unresolved_count="$(json_int_field "$condition_json" "unresolved_count")"
                condition_operator_needed_count="$(json_true_count "$condition_json" "operator_needed_emitted")"
            fi
        fi
        bootstrap_json="$(rpc_call "$datadir" "$rpcport" bootstrapstatus || true)"
        if [ -n "$bootstrap_json" ]; then
            snapshot_seed_height="$(json_int_field "$bootstrap_json" "bundle_seed_height")"
            [ "$snapshot_seed_height" = "-1" ] && snapshot_seed_height=""
            snapshot_path="$(json_string_field "$bootstrap_json" "bundle_path")"
            if [ "$(json_bool_field "$bootstrap_json" "bundle_present")" = "1" ]; then
                snapshot_present=1
            fi
            if [ "$(json_bool_field "$bootstrap_json" "active_loader_configured")" = "1" ]; then
                loader_configured=1
            fi
            loader_path="$(json_string_field "$bootstrap_json" "active_loader_path")"
            recovery_hint="$(json_string_field "$bootstrap_json" "recovery_hint")"
        fi
        chain_advance_json="$(rpc_call "$datadir" "$rpcport" dumpstate chain_advance_coordinator || true)"
        if [ -n "$chain_advance_json" ]; then
            chain_advance_current_json="$chain_advance_json"
            case "$chain_advance_current_json" in
                *\"last_decision\"*)
                    chain_advance_current_json="${chain_advance_current_json%%\"last_decision\"*}"
                    ;;
            esac
            projection_height="$(json_int_field "$chain_advance_current_json" "projection_height")"
            projection_lag="$(json_int_field "$chain_advance_current_json" "projection_lag")"
            projection_deferred="$(json_bool_field "$chain_advance_current_json" "projection_deferred")"
            projection_state="$(json_string_field "$chain_advance_current_json" "projection_state")"
            projection_deferred_reason="$(json_string_field "$chain_advance_current_json" "last_projection_deferred_reason")"
        fi
    fi
    [ -n "$peers" ] || peers="null"

    if [ -z "$snapshot_seed_height" ]; then
        snapshot_info="$(highest_snapshot "$datadir")"
        snapshot_seed_height="${snapshot_info%%|*}"
        snapshot_path="${snapshot_info#*|}"
        if [ -n "$snapshot_seed_height" ]; then
            snapshot_present=1
        fi
    fi

    tip_lag="null"
    if [ -n "$height" ] && [ -n "$LIVE_REFERENCE_HEIGHT" ]; then
        if [ "$height" -le "$LIVE_REFERENCE_HEIGHT" ]; then
            tip_lag=$((LIVE_REFERENCE_HEIGHT - height))
        else
            tip_lag=0
        fi
    fi

    status="ok"
    reason="healthy"
    if [ "$active" != "active" ]; then
        status="fail"
        reason="unit_not_active"
    elif [ "$reindex" = "1" ]; then
        status="fail"
        reason="forced_reindex_flag_present"
    elif [ "$rpc_up" != "1" ]; then
        if [ "$lane" = "dev" ]; then
            status="warn"
            reason="dev_booting_rpc_down"
        else
            status="fail"
            reason="rpc_down"
        fi
    elif [ "$agent_contract_trusted" = "1" ] &&
         [ "$agent_operator_needed" = "1" ]; then
        status="fail"
        reason="agent_operator_needed"
    elif [ "$agent_contract_trusted" = "1" ] &&
         [ "$agent_status" = "blocked" ]; then
        status="fail"
        reason="agent_blocked"
    elif [ "$agent_contract_trusted" = "1" ] &&
         [ "$agent_validation_pack_ok" = "0" ]; then
        status="fail"
        reason="validation_pack_failed"
    elif is_number "$condition_operator_needed_count" &&
         [ "$condition_operator_needed_count" -gt 0 ]; then
        status="fail"
        reason="condition_operator_needed"
    elif [ "$agent_rpc_state" = "timeout" ]; then
        status="warn"
        reason="agent_timeout"
    elif is_number "$peers" && [ "$peers" -lt 1 ]; then
        status="warn"
        reason="no_peers"
    elif [ "$tip_lag" != "null" ] && [ "$tip_lag" -gt "$LAG_WARN" ]; then
        status="warn"
        reason="lag_to_live_${tip_lag}"
    elif is_number "$projection_lag" && [ "$projection_lag" -gt "$LAG_WARN" ]; then
        if [ "$lane" = "dev" ] &&
           [ "$agent_chain_serving_ready" = "1" ] &&
           [ "$agent_work_ready" = "1" ]; then
            status="ok"
            reason="serving_projection_deferred"
        else
            status="warn"
            reason="projection_lag_${projection_lag}"
        fi
    elif [ "$p2p_listening" != "1" ] || [ "$rpc_listening" != "1" ]; then
        status="warn"
        reason="listener_missing"
    fi

    if [ "$agent_contract_trusted" = "1" ] &&
       { [ "$agent_operator_needed" = "1" ] ||
         [ "$agent_status" = "blocked" ]; }; then
        recovery_hint="inspect_agent_primary_blocker"
    elif [ "$agent_contract_trusted" = "1" ] &&
         [ "$agent_validation_pack_ok" = "0" ]; then
        recovery_hint="inspect_validation_pack"
    elif is_number "$condition_operator_needed_count" &&
         [ "$condition_operator_needed_count" -gt 0 ]; then
        recovery_hint="inspect_condition_engine"
    elif [ "$agent_rpc_state" = "timeout" ]; then
        recovery_hint="inspect_agent_timeout"
    fi

    if [ -z "$recovery_hint" ]; then
        if [ "$active" != "active" ]; then
            recovery_hint="start_or_inspect_${unit}"
        elif [ "$reindex" = "1" ]; then
            recovery_hint="remove_forced_reindex_override"
        elif [ "$rpc_up" != "1" ]; then
            recovery_hint="wait_or_tail_node_log"
        elif [ "$agent_operator_needed" = "1" ] ||
             [ "$agent_status" = "blocked" ]; then
            recovery_hint="inspect_agent_primary_blocker"
        elif [ "$agent_validation_pack_ok" = "0" ]; then
            recovery_hint="inspect_validation_pack"
        elif [ "$tip_lag" != "null" ] && [ "$tip_lag" -gt "$LAG_WARN" ]; then
            if [ "$snapshot_present" = "1" ] && [ "$loader_configured" != "1" ]; then
                recovery_hint="restart_with_load_snapshot_at_own_height"
            elif [ "$snapshot_present" != "1" ]; then
                recovery_hint="install_tip_seed_snapshot"
            else
                recovery_hint="inspect_reducer_frontier"
            fi
        elif is_number "$projection_lag" && [ "$projection_lag" -gt "$LAG_WARN" ]; then
            if [ "$lane" = "dev" ] &&
               [ "$agent_chain_serving_ready" = "1" ] &&
               [ "$agent_work_ready" = "1" ]; then
                recovery_hint="none"
            else
                recovery_hint="inspect_chain_advance_coordinator"
            fi
        elif [ "$p2p_listening" != "1" ] || [ "$rpc_listening" != "1" ]; then
            recovery_hint="inspect_listeners"
        elif is_number "$peers" && [ "$peers" -lt 1 ]; then
            recovery_hint="inspect_peer_floor"
        else
            recovery_hint="none"
        fi
    fi

    soak_eligible="null"
    soak_reason="not_soak_lane"
    if [ "$lane" = "soak" ]; then
        soak_eligible=0
        if [ "$active" != "active" ]; then
            soak_reason="unit_not_active"
        elif [ "$reindex" = "1" ]; then
            soak_reason="forced_reindex_flag_present"
        elif [ "$rpc_up" != "1" ]; then
            soak_reason="rpc_down"
        elif [ "$agent_contract_trusted" = "1" ] &&
             [ "$agent_operator_needed" = "1" ]; then
            soak_reason="agent_operator_needed"
        elif [ "$agent_contract_trusted" = "1" ] &&
             [ "$agent_status" = "blocked" ]; then
            soak_reason="agent_blocked"
        elif [ "$agent_contract_trusted" = "1" ] &&
             [ "$agent_validation_pack_ok" = "0" ]; then
            soak_reason="validation_pack_failed"
        elif is_number "$condition_operator_needed_count" &&
             [ "$condition_operator_needed_count" -gt 0 ]; then
            soak_reason="condition_operator_needed"
        elif [ "$agent_rpc_state" = "timeout" ]; then
            soak_reason="agent_timeout"
        elif [ "$p2p_listening" != "1" ] || [ "$rpc_listening" != "1" ]; then
            soak_reason="listener_missing"
        elif [ -z "$LIVE_REFERENCE_HEIGHT" ]; then
            soak_reason="live_reference_missing"
        elif [ "$tip_lag" = "null" ]; then
            soak_reason="lag_unknown"
        elif [ "$tip_lag" -gt "$SOAK_LAG_WARN" ]; then
            soak_reason="lag_to_live_${tip_lag}"
        elif is_number "$projection_lag" && [ "$projection_lag" -gt "$SOAK_LAG_WARN" ]; then
            soak_reason="projection_lag_${projection_lag}"
        elif ! is_number "$peers" || [ "$peers" -lt 1 ]; then
            soak_reason="no_peers"
        else
            soak_eligible=1
            soak_reason="eligible"
        fi
    fi

    role_ready=0
    role_reason="$reason"
    case "$lane" in
        live)
            if [ "$status" = "ok" ] &&
               [ "$tip_lag" = "0" ] &&
               is_number "$peers" && [ "$peers" -gt 0 ]; then
                role_ready=1
                role_reason="canonical_ready"
            else
                role_reason="canonical_${reason}"
            fi
            canonical_state="$(state_from_status "$status")"
            ;;
        soak)
            if [ "$soak_eligible" = "1" ]; then
                role_ready=1
                role_reason="soak_evidence_ready"
                soak_state="ready"
            else
                role_reason="soak_${soak_reason}"
                soak_state="$(state_from_status "$status")"
            fi
            ;;
        dev)
            if [ "$status" = "ok" ] &&
               [ "$active" = "active" ] &&
               [ "$reindex" != "1" ] &&
               [ "$rpc_up" = "1" ] &&
               [ "$p2p_listening" = "1" ] &&
               [ "$rpc_listening" = "1" ] &&
               { [ "$tip_lag" = "null" ] || [ "$tip_lag" -le "$LAG_WARN" ]; }; then
                role_ready=1
                role_reason="dev_lane_ready"
            else
                role_reason="dev_${reason}"
            fi
            dev_state="$(state_from_status "$status")"
            ;;
    esac

    if [ "$rpc_up" = "1" ] &&
       { [ "$status" != "ok" ] ||
         { [ "$lane" = "soak" ] && [ "$soak_eligible" != "1" ]; }; }; then
        reducer_json="$(rpc_call "$datadir" "$rpcport" dumpstate reducer_frontier || true)"
        if [ -n "$reducer_json" ]; then
            reducer_hstar="$(json_int_field "$reducer_json" "hstar")"
            reducer_pending_stage="$(json_string_field "$reducer_json" "hstar_next_pending_stage")"
            reducer_pending_detail="$(json_string_field "$reducer_json" "hstar_next_pending_detail")"
            reducer_primary_stage="$(json_string_field "$reducer_json" "hstar_next_primary_stage")"
            reducer_primary_detail="$(json_string_field "$reducer_json" "hstar_next_primary_detail")"
            reducer_blocker_count="$(json_int_field "$reducer_json" "hstar_next_blocker_count")"
        fi
        if [ -z "$condition_json" ]; then
            condition_json="$(rpc_call "$datadir" "$rpcport" dumpstate condition_engine || true)"
        fi
        if [ -n "$condition_json" ]; then
            condition_active_count="$(json_int_field "$condition_json" "active_count")"
            condition_unresolved_count="$(json_int_field "$condition_json" "unresolved_count")"
            condition_operator_needed_count="$(json_true_count "$condition_json" "operator_needed_emitted")"
        fi
    fi

    case "$status" in
        ok) ok_count=$((ok_count + 1)) ;;
        warn) warn_count=$((warn_count + 1)) ;;
        *) fail_count=$((fail_count + 1)) ;;
    esac

    if [ "$JSON" = "1" ]; then
        printf '{"lane":"%s","unit":"%s","datadir":"%s","rpcport":%s,"p2p_port":%s,"role":"%s","active_state":"%s","mainpid":%s,"restarts":%s,"start_timestamp":"%s","memory_current_bytes":%s,"memory_high_bytes":%s,"memory_max_bytes":%s,"memory_pressure":"%s","rpc_up":%s,"agent_rpc_state":"%s","agent_identity_authority":"source_id_sha256","agent_source_id_sha256":"%s","agent_build_commit":"%s","agent_build_commit_semantics":"display_only_github_trace_metadata","agent_contract_trusted":%s,"agent_contract_trust_reason":"%s","agent_status":"%s","agent_operator_needed":%s,"agent_primary_blocker":"%s","agent_next":"%s","agent_validation_pack_ok":%s,"agent_validation_pack_detail":"%s","height":%s,"chain_headers":%s,"initialblockdownload":%s,"tip_lag_to_live":%s,"peer_count":%s,"p2p_listening":%s,"rpc_listening":%s,"reindex_chainstate":%s,"snapshot_present":%s,"snapshot_seed_height":%s,"snapshot_path":"%s","snapshot_loader_configured":%s,"snapshot_loader_path":"%s","projection_height":%s,"projection_lag":%s,"projection_deferred":%s,"projection_state":"%s","projection_deferred_reason":"%s","recovery_hint":"%s","reducer_hstar":%s,"reducer_pending_stage":"%s","reducer_pending_detail":"%s","reducer_primary_stage":"%s","reducer_primary_detail":"%s","reducer_blocker_count":%s,"condition_active_count":%s,"condition_unresolved_count":%s,"condition_operator_needed_count":%s,"role_ready":%s,"role_reason":"%s","soak_eligible":%s,"soak_reason":"%s","status":"%s","reason":"%s"}\n' \
            "$(json_escape "$lane")" \
            "$(json_escape "$unit")" \
            "$(json_escape "$datadir")" \
            "$rpcport" \
            "$p2p_port" \
            "$(json_escape "$role")" \
            "$(json_escape "$active")" \
            "$(json_number "$mainpid")" \
            "$(json_number "$restarts")" \
            "$(json_escape "$start_ts")" \
            "$(json_number "$mem_current")" \
            "$(json_number "$mem_high")" \
            "$(json_number "$mem_max")" \
            "$(json_escape "$mem_pressure")" \
            "$(json_bool "$rpc_up")" \
            "$(json_escape "$agent_rpc_state")" \
            "$(json_escape "$agent_source_id_sha256")" \
            "$(json_escape "$agent_build_commit")" \
            "$(json_bool "$agent_contract_trusted")" \
            "$(json_escape "$agent_contract_trust_reason")" \
            "$(json_escape "$agent_status")" \
            "$(json_tri_bool "$agent_operator_needed")" \
            "$(json_escape "$agent_primary_blocker")" \
            "$(json_escape "$agent_next")" \
            "$(json_tri_bool "$agent_validation_pack_ok")" \
            "$(json_escape "$agent_validation_pack_detail")" \
            "${height:-null}" \
            "$(json_number "$chain_headers")" \
            "$(json_tri_bool "$initialblockdownload")" \
            "$tip_lag" \
            "$peers" \
            "$(json_bool "$p2p_listening")" \
            "$(json_bool "$rpc_listening")" \
            "$(json_bool "$reindex")" \
            "$(json_bool "$snapshot_present")" \
            "$(json_number "$snapshot_seed_height")" \
            "$(json_escape "$snapshot_path")" \
            "$(json_bool "$loader_configured")" \
            "$(json_escape "$loader_path")" \
            "$(json_number "$projection_height")" \
            "$(json_number "$projection_lag")" \
            "$(json_tri_bool "$projection_deferred")" \
            "$(json_escape "$projection_state")" \
            "$(json_escape "$projection_deferred_reason")" \
            "$(json_escape "$recovery_hint")" \
            "$(json_number "$reducer_hstar")" \
            "$(json_escape "$reducer_pending_stage")" \
            "$(json_escape "$reducer_pending_detail")" \
            "$(json_escape "$reducer_primary_stage")" \
            "$(json_escape "$reducer_primary_detail")" \
            "$(json_number "$reducer_blocker_count")" \
            "$(json_number "$condition_active_count")" \
            "$(json_number "$condition_unresolved_count")" \
            "$(json_number "$condition_operator_needed_count")" \
            "$(json_bool "$role_ready")" \
            "$(json_escape "$role_reason")" \
            "$(json_tri_bool "$soak_eligible")" \
            "$(json_escape "$soak_reason")" \
            "$(json_escape "$status")" \
            "$(json_escape "$reason")"
    else
        printf 'lane-health: %-4s status=%-4s reason=%-28s role_ready=%-3s role_reason=%-24s unit=%-20s active=%-8s pid=%-7s restarts=%-4s rpc=%-4s agent=%-8s agent_rpc=%-8s agent_trusted=%s agent_trust_reason=%s agent_op=%s agent_blocker=%s height=%-8s headers=%-8s ibd=%s lag=%-8s peers=%-4s p2p_listen=%s rpc_listen=%s reindex=%s mem_pressure=%s snapshot_h=%-8s loader=%s projection_h=%-8s projection_lag=%-8s projection_deferred=%s recovery_hint=%s hstar=%-8s reducer_pending=%s:%s cond_active=%s cond_operator_needed=%s soak_eligible=%s soak_reason=%s\n' \
            "$lane" "$status" "$reason" \
            "$([ "$role_ready" = "1" ] && printf yes || printf no)" \
            "$role_reason" \
            "$unit" "$active" "$mainpid" "$restarts" \
            "$([ "$rpc_up" = "1" ] && printf up || printf down)" \
            "${agent_status:-unknown}" \
            "$agent_rpc_state" \
            "$([ "$agent_contract_trusted" = "1" ] && printf yes || printf no)" \
            "$agent_contract_trust_reason" \
            "$([ "$agent_operator_needed" = "1" ] && printf yes || { [ "$agent_operator_needed" = "0" ] && printf no || printf n/a; })" \
            "${agent_primary_blocker:-none}" \
            "${height:-null}" \
            "${chain_headers:-null}" \
            "$([ "$initialblockdownload" = "1" ] && printf yes || { [ "$initialblockdownload" = "0" ] && printf no || printf n/a; })" \
            "$tip_lag" "$peers" \
            "$([ "$p2p_listening" = "1" ] && printf yes || printf no)" \
            "$([ "$rpc_listening" = "1" ] && printf yes || printf no)" \
            "$([ "$reindex" = "1" ] && printf yes || printf no)" \
            "$mem_pressure" \
            "${snapshot_seed_height:-none}" \
            "$([ "$loader_configured" = "1" ] && printf yes || printf no)" \
            "${projection_height:-null}" \
            "${projection_lag:-null}" \
            "$([ "$projection_deferred" = "1" ] && printf yes || { [ "$projection_deferred" = "0" ] && printf no || printf n/a; })" \
            "$recovery_hint" \
            "${reducer_hstar:-null}" \
            "${reducer_pending_stage:-none}" \
            "${reducer_pending_detail:-none}" \
            "${condition_active_count:-null}" \
            "${condition_operator_needed_count:-null}" \
            "$([ "$soak_eligible" = "1" ] && printf yes || { [ "$soak_eligible" = "0" ] && printf no || printf n/a; })" \
            "$soak_reason"
    fi
}

ok_count=0
warn_count=0
fail_count=0
canonical_state="unknown"
soak_state="unknown"
dev_state="unknown"

LIVE_REFERENCE_HEIGHT=""
if live_height="$(rpc_call "$HOME/.zclassic-c23" 18232 getblockcount)"; then
    case "$live_height" in
        ''|*[!0-9]*) LIVE_REFERENCE_HEIGHT="" ;;
        *) LIVE_REFERENCE_HEIGHT="$live_height" ;;
    esac
fi

report_lane live zclassic23 "$HOME/.zclassic-c23" 18232 8033 "public daily-driver"
report_lane soak zclassic23-soak "$HOME/.zclassic-c23-soak" 18242 8043 "long-uptime evidence"
report_lane dev zcl23-dev "$HOME/.zclassic-c23-dev" 18252 8053 "fresh-build development"

if [ "$JSON" != "1" ]; then
    echo "lane-health: SUMMARY ok=$ok_count warn=$warn_count fail=$fail_count"
    echo "lane-health: REDUNDANCY canonical=$canonical_state soak=$soak_state dev=$dev_state"
fi

if [ "$STRICT" = "1" ] && [ "$fail_count" -gt 0 ]; then
    exit 1
fi
exit 0
