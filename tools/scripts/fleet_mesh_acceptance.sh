#!/usr/bin/env bash
# fleet_mesh_acceptance.sh — fail-closed onion P2P mesh acceptance.
#
# The hub runs this from cron every five minutes.  One bounded cycle:
#   * reconciles the checkout with origin/main without discarding local work;
#   * validates all four neutral node publications;
#   * self-dials the hub onion from a fresh, isolated mainnet instance;
#   * asks the isolated node to dial every missing peer by its onion endpoint;
#   * requires an ACTIVE peer (VERSION/VERACK complete) at tip-height parity;
#   * flags each publication's SOURCE_SHA freshness against the observed main;
#   * writes and publishes deploy/devfleet/mesh.status.
#
# Two full observations separated by a real watcher interval set HOLD=pass.
# Later timer invocations then leave the recorded acceptance untouched.
# Production is never read, installed, signalled, or restarted here.
#
# Usage: tools/scripts/fleet_mesh_acceptance.sh <box>
#
# Development-only controls:
#   FLEET_MESH_GIT_MODE=local   skip fetch/commit/push, but write status
#   FLEET_MESH_DIAL_TIMEOUT=45  bounded seconds to observe a handshake
#   FLEET_MESH_SELF_DIAL_TIMEOUT=120  total fresh-probe budget
#   FLEET_MESH_SELF_DIAL_PORT_BASE=39250  isolated 39xxx port quad

set -euo pipefail

BOX="${1:?usage: fleet_mesh_acceptance.sh <box>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${FLEET_SYNC_ENV:-$HOME/.config/zclassic23-fleetsync/$BOX.env}"

if [ ! -f "$ENV_FILE" ]; then
    echo "fleet-mesh: missing local env: $ENV_FILE" >&2
    exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

EXPECTED_NODES=4
GIT_MODE="${FLEET_MESH_GIT_MODE:-publish}"
DIAL_TIMEOUT="${FLEET_MESH_DIAL_TIMEOUT:-45}"
SELF_DIAL_TIMEOUT="${FLEET_MESH_SELF_DIAL_TIMEOUT:-120}"
SELF_DIAL_PORT_BASE="${FLEET_MESH_SELF_DIAL_PORT_BASE:-39250}"
MIN_PASS_INTERVAL="${FLEET_MESH_MIN_PASS_INTERVAL:-240}"
STATE_DIR="$HOME/.local/state/zclassic23-fleetsync"
STATUS_REL="deploy/devfleet/mesh.status"
STATUS_FILE="$REPO_DIR/$STATUS_REL"
ZCL_CLI="${FLEET_MESH_CLI:-$REPO_DIR/build/bin/z23}"
JSONQ="${FLEET_MESH_JSONQ:-$REPO_DIR/build/bin/jsonq}"
NODE_BIN="${FLEET_MESH_NODE_BIN:-$REPO_DIR/build/bin/zclassic23}"
RPC_BIN="${FLEET_MESH_RPC_BIN:-$REPO_DIR/build/bin/zcl-rpc}"
ONION_BASE_COMMIT="355808b13b704624927d9c997a1d5677f17486f6"

case "$BOX" in
    node1|node2|node3|node4) ;;
    *) echo "fleet-mesh: invalid box name: $BOX" >&2; exit 2 ;;
esac
case "$GIT_MODE" in
    publish|local) ;;
    *) echo "fleet-mesh: invalid FLEET_MESH_GIT_MODE: $GIT_MODE" >&2; exit 2 ;;
esac
case "$DIAL_TIMEOUT:$SELF_DIAL_TIMEOUT:$SELF_DIAL_PORT_BASE:$MIN_PASS_INTERVAL" in
    *[!0-9:]*|:*|*:) echo "fleet-mesh: timeout/port values must be unsigned integers" >&2; exit 2 ;;
esac
if [ "$DIAL_TIMEOUT" -lt 1 ] || [ "$DIAL_TIMEOUT" -gt 300 ]; then
    echo "fleet-mesh: FLEET_MESH_DIAL_TIMEOUT must be in 1..300" >&2
    exit 2
fi
if [ "$SELF_DIAL_TIMEOUT" -lt 1 ] || [ "$SELF_DIAL_TIMEOUT" -gt 180 ]; then
    echo "fleet-mesh: FLEET_MESH_SELF_DIAL_TIMEOUT must be in 1..180" >&2
    exit 2
fi
if [ "$SELF_DIAL_PORT_BASE" -lt 39000 ] ||
   [ "$SELF_DIAL_PORT_BASE" -gt 39990 ]; then
    echo "fleet-mesh: FLEET_MESH_SELF_DIAL_PORT_BASE must be in 39000..39990" >&2
    exit 2
fi
if [ "$MIN_PASS_INTERVAL" -lt 1 ] || [ "$MIN_PASS_INTERVAL" -gt 3600 ]; then
    echo "fleet-mesh: FLEET_MESH_MIN_PASS_INTERVAL must be in 1..3600" >&2
    exit 2
fi
if [ ! -x "$ZCL_CLI" ] || [ ! -x "$JSONQ" ] ||
   [ ! -x "$NODE_BIN" ] || [ ! -x "$RPC_BIN" ]; then
    echo "fleet-mesh: z23/jsonq/zclassic23/zcl-rpc is not built" >&2
    exit 2
fi
if [ -z "${DEVFLEET_DATADIR:-}" ] || [ -z "${DEVFLEET_RPCPORT:-}" ] ||
   [ -z "${DEVFLEET_PORT:-}" ]; then
    echo "fleet-mesh: DEVFLEET_DATADIR/RPCPORT/PORT missing from local env" >&2
    exit 2
fi

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/$BOX.lock"
if ! flock -n 9; then
    printf '%s fleet_mesh[%s] REFUSED cycle: fleet lock busy\n' \
        "$(date -u +%FT%TZ)" "$BOX" >&2
    exit 75
fi
cd "$REPO_DIR"

log() {
    printf '%s fleet_mesh[%s] %s\n' "$(date -u +%FT%TZ)" "$BOX" "$*"
}

clean_detail() {
    printf '%s' "$1" | tr '\n\t ,' '____' | tr -cd 'A-Za-z0-9_.:=+@/-' |
        cut -c1-180
}

status_value() {
    local key="$1"
    [ -f "$STATUS_FILE" ] || return 0
    sed -n "s/^${key}=//p" "$STATUS_FILE" | head -n 1
}

tracked_dirty_except_status() {
    local path
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        [ "$path" = "$STATUS_REL" ] || return 0
    done < <({ git diff --name-only; git diff --cached --name-only; } | sort -u)
    return 1
}

commits_owned_by_fleet_control() {
    local changed="$1" path seen=0
    [ -n "$changed" ] || return 1
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        seen=1
        case "$path" in
            "$STATUS_REL"|"deploy/devfleet/$BOX.sync") ;;
            *) return 1 ;;
        esac
    done <<< "$changed"
    [ "$seen" = 1 ]
}

sync_main() {
    if tracked_dirty_except_status; then
        log "REFUSED source_sync: tracked checkout work is not mesh.status"
        return 1
    fi
    if [ -n "$(git diff --name-only -- "$STATUS_REL")" ] ||
       [ -n "$(git diff --cached --name-only -- "$STATUS_REL")" ]; then
        log "REFUSED source_sync: prior mesh.status write is uncommitted"
        return 1
    fi

    git fetch origin main --quiet || {
        log "REFUSED source_sync: fetch_origin_main_failed"
        return 1
    }
    local head origin changed
    head="$(git rev-parse HEAD)"
    origin="$(git rev-parse origin/main)"
    [ "$head" = "$origin" ] && return 0

    if git merge-base --is-ancestor "$head" "$origin"; then
        git merge --ff-only origin/main --quiet || {
            log "REFUSED source_sync: ff_only_merge_failed"
            return 1
        }
        return 0
    fi

    if git merge-base --is-ancestor "$origin" "$head"; then
        changed="$(git diff --name-only "$origin..$head")"
        if commits_owned_by_fleet_control "$changed"; then
            return 0
        fi
        log "REFUSED source_sync: local_commits_not_owned_by_fleet_control"
        return 1
    fi

    changed="$(git diff --name-only "$(git merge-base "$head" "$origin")..$head")"
    if ! commits_owned_by_fleet_control "$changed"; then
        log "REFUSED source_sync: diverged_local_commits_not_owned_by_fleet_control"
        return 1
    fi
    git rebase origin/main --quiet || {
        git rebase --abort >/dev/null 2>&1 || true
        log "REFUSED source_sync: mesh_status_rebase_failed"
        return 1
    }
}

cli() {
    timeout 60 "$ZCL_CLI" -datadir="$DEVFLEET_DATADIR" \
        -rpcport="$DEVFLEET_RPCPORT" "$@" 2>/dev/null
}

json_get() {
    local document="$1" path="$2"
    printf '%s' "$document" | "$JSONQ" get "$path" 2>/dev/null || true
}

peer_row_from() {
    local cli_fn="$1" endpoint="$2" peers count i addr row
    peers="$("$cli_fn" getpeerinfo 2>/dev/null || true)"
    case "$peers" in
        \{*) peers="$(printf '%s' "$peers" | "$JSONQ" unwrap 2>/dev/null || true)" ;;
    esac
    count="$(printf '%s' "$peers" | "$JSONQ" count . 2>/dev/null || true)"
    case "$count" in *[!0-9]*|'') return 1 ;; esac
    i=0
    while [ "$i" -lt "$count" ]; do
        addr="$(json_get "$peers" "[$i].addr")"
        if [ "$addr" = "$endpoint" ]; then
            row="$(json_get "$peers" "[$i]")"
            [ -n "$row" ] || return 1
            printf '%s' "$row"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

peer_row() { peer_row_from cli "$1"; }

probe_cli() {
    timeout 60 "$ZCL_CLI" -datadir="$ISO_DD" -rpcport="$ISO_RPCPORT" \
        "$@" 2>/dev/null
}

probe_peer_row() { peer_row_from probe_cli "$1"; }

# Prove the published hub onion from a new process and empty /tmp datadir on
# every observation.  The shared isolation helper owns port refusal, process-
# group teardown, and the structural canonical-datadir exclusion.  Run it in a
# subshell so an isolation refusal becomes a named mesh gap and its EXIT trap
# cannot affect the long-running referee.
fresh_self_dial() (
    set -euo pipefail
    local endpoint="$1" start deadline status bootstrap add_out add_error
    local row state version elapsed

    ISO_KIND=fleet-selfdial
    ISO_PORT_BASE="$SELF_DIAL_PORT_BASE"
    ISO_NODE_BIN="$NODE_BIN"
    ISO_RPC_BIN="$RPC_BIN"
    # shellcheck source=tools/scripts/isolated_node_env.sh
    . "$REPO_DIR/tools/scripts/isolated_node_env.sh"
    iso_init >/dev/null

    start="$(date +%s)"
    deadline=$((start + SELF_DIAL_TIMEOUT))
    setsid "$ISO_NODE_BIN" \
        -datadir="$ISO_DD" \
        -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
        -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
        -connect=127.0.0.1:"$ISO_CONNECT_SINK" \
        -listen -tor -onion-persist -operator-lane=test \
        -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
        >"$ISO_DD/node.log" 2>&1 &
    ISO_NODE_PID=$!
    ISO_PGID="$ISO_NODE_PID"

    probe_finish() {
        local rc="$1" detail="$2"
        set +e
        iso_cleanup
        wait "$ISO_NODE_PID" 2>/dev/null || true
        trap - EXIT INT TERM
        printf '\nSELF_DIAL_RESULT=%s\n' "$detail"
        exit "$rc"
    }

    if ! iso_wait_rpc_ready "$SELF_DIAL_TIMEOUT" >/dev/null 2>&1; then
        probe_finish 1 self_dial_rpc_not_ready
    fi

    bootstrap="absent"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            probe_finish 1 self_dial_probe_exited_during_tor_bootstrap
        fi
        status="$(probe_cli core network onion status 2>/dev/null || true)"
        bootstrap="$(json_get "$status" data.bootstrap_state)"
        [ -z "$bootstrap" ] && bootstrap="$(json_get "$status" bootstrap_state)"
        [ "$bootstrap" = ready ] && break
        sleep 1
    done
    if [ "$bootstrap" != ready ]; then
        probe_finish 1 \
            "self_dial_tor_not_ready:bootstrap=${bootstrap:-absent}"
    fi

    add_out="$(iso_rpc addnode "\"$endpoint\"" '"add"' 2>/dev/null || true)"
    add_error="$(json_get "$add_out" error)"
    case "$add_error" in
        ''|null) ;;
        *)
            probe_finish 1 \
                "self_dial_addnode_refused:error=$(clean_detail "$add_error")"
            ;;
    esac

    state="absent"
    version=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            probe_finish 1 self_dial_probe_exited_during_handshake
        fi
        row="$(probe_peer_row "$endpoint" || true)"
        state="$(json_get "$row" state)"
        version="$(json_get "$row" version)"
        # A fresh mainnet node advances immediately into header sync after
        # verack.  The negotiated nonzero protocol version is the established
        # stranger-join proof that VERSION/VERACK completed; requiring
        # state=active here would misclassify syncing_headers as handshake rot.
        if [[ "$version" =~ ^[1-9][0-9]*$ ]]; then
            elapsed=$(( $(date +%s) - start ))
            probe_finish 0 \
                "self_dial_version_verack:protocol=$version:state=${state:-unknown}:seconds=$elapsed"
        fi
        sleep 1
    done
    probe_finish 1 \
        "self_dial_version_verack_incomplete:state=${state:-absent}"
)

field_from_file() {
    local file="$1" key="$2" count value
    count="$(sed -n "s/^${key}=//p" "$file" | wc -l | tr -d ' ')"
    [ "$count" = 1 ] || return 1
    value="$(sed -n "s/^${key}=//p" "$file")"
    [ -n "$value" ] || return 1
    printf '%s' "$value"
}

NODE_FILE_BOX=""
NODE_ONION=""
NODE_PORT=""
NODE_SOURCE=""
NODE_RECORD_ERROR=""
read_node_record() {
    local expected="$1" file
    file="deploy/devfleet/$expected.txt"
    NODE_FILE_BOX=""
    NODE_ONION=""
    NODE_PORT=""
    NODE_SOURCE=""
    NODE_RECORD_ERROR=""
    if [ ! -f "$file" ]; then
        NODE_RECORD_ERROR="unpublished"
        return 1
    fi
    NODE_FILE_BOX="$(field_from_file "$file" BOX || true)"
    NODE_ONION="$(field_from_file "$file" ONION_ADDRESS || true)"
    NODE_PORT="$(field_from_file "$file" P2P_PORT || true)"
    NODE_SOURCE="$(field_from_file "$file" SOURCE_SHA || true)"
    if [ "$NODE_FILE_BOX" != "$expected" ]; then
        NODE_RECORD_ERROR="box_identity_mismatch"
    elif [[ ! "$NODE_ONION" =~ ^[a-z2-7]{56}\.onion$ ]]; then
        NODE_RECORD_ERROR="invalid_onion_address"
    elif [[ ! "$NODE_PORT" =~ ^[0-9]+$ ]] ||
         [ "$NODE_PORT" -lt 1 ] || [ "$NODE_PORT" -gt 65535 ]; then
        NODE_RECORD_ERROR="invalid_p2p_port"
    elif [[ "$NODE_SOURCE" =~ ^[0-9a-f]{40}$ ]]; then
        if ! git cat-file -e "$NODE_SOURCE^{commit}" 2>/dev/null ||
           ! git merge-base --is-ancestor "$NODE_SOURCE" HEAD; then
            NODE_RECORD_ERROR="source_sha_not_in_main_history"
        elif ! git merge-base --is-ancestor "$ONION_BASE_COMMIT" "$NODE_SOURCE"; then
            NODE_RECORD_ERROR="source_predates_onion_p2p"
        fi
    elif [[ ! "$NODE_SOURCE" =~ ^[0-9a-f]{64}$ ]]; then
        NODE_RECORD_ERROR="invalid_source_sha"
    fi
    [ -z "$NODE_RECORD_ERROR" ]
}

declare -A NODE_RESULTS
declare -A NODE_SOURCE_SHAS
declare -A NODE_SOURCE_KINDS
declare -A NODE_SOURCE_STALE
declare -A NODE_SOURCE_BEHIND
declare -A NODE_SOURCE_DETAILS
declare -a GAPS
PASS_COUNT=0
PUBLISHED_COUNT=0
LOCAL_HEIGHT_BEFORE=""
LOCAL_HEIGHT_AFTER=""
LOCAL_HASH=""

record_source_evidence() {
    local node="$1" behind
    NODE_SOURCE_SHAS[$node]="${NODE_SOURCE:-absent}"
    NODE_SOURCE_KINDS[$node]=unknown
    NODE_SOURCE_STALE[$node]=unknown
    NODE_SOURCE_BEHIND[$node]=unknown
    NODE_SOURCE_DETAILS[$node]="${NODE_RECORD_ERROR:-unavailable}"

    if [[ "${NODE_SOURCE:-}" =~ ^[0-9a-f]{64}$ ]]; then
        NODE_SOURCE_KINDS[$node]=source_id_sha256
        NODE_SOURCE_DETAILS[$node]=runtime_source_id_git_freshness_unmapped
        return
    fi
    if [[ ! "${NODE_SOURCE:-}" =~ ^[0-9a-f]{40}$ ]]; then
        [ "$NODE_RECORD_ERROR" = unpublished ] && NODE_SOURCE_KINDS[$node]=absent
        [ "$NODE_RECORD_ERROR" = invalid_source_sha ] && NODE_SOURCE_KINDS[$node]=invalid
        [ "$NODE_RECORD_ERROR" = unpublished ] || NODE_SOURCE_STALE[$node]=yes
        return
    fi
    NODE_SOURCE_KINDS[$node]=git_commit
    if ! git cat-file -e "$NODE_SOURCE^{commit}" 2>/dev/null ||
       ! git merge-base --is-ancestor "$NODE_SOURCE" HEAD; then
        NODE_SOURCE_STALE[$node]=yes
        NODE_SOURCE_DETAILS[$node]=not_in_main_history
        return
    fi
    behind="$(git rev-list --count "$NODE_SOURCE..HEAD")"
    NODE_SOURCE_BEHIND[$node]="$behind"
    if [ "$behind" -eq 0 ]; then
        NODE_SOURCE_STALE[$node]=no
        NODE_SOURCE_DETAILS[$node]=at_observed_main
    else
        NODE_SOURCE_STALE[$node]=yes
        NODE_SOURCE_DETAILS[$node]="behind_observed_main:$behind"
    fi
    if ! git merge-base --is-ancestor "$ONION_BASE_COMMIT" "$NODE_SOURCE"; then
        NODE_SOURCE_DETAILS[$node]="predates_onion_p2p:behind=$behind"
    fi
}

record_pass() {
    local node="$1" detail="$2"
    NODE_RESULTS[$node]="pass:$(clean_detail "$detail")"
    PASS_COUNT=$((PASS_COUNT + 1))
}

record_gap() {
    local node="$1" reason="$2"
    reason="$(clean_detail "$reason")"
    NODE_RESULTS[$node]="fail:$reason"
    GAPS+=("$node:$reason")
}

check_local_node() {
    local node="$1" chain_info blocks headers progress published_onion
    local self_dial_detail self_dial_raw self_dial_rc source_error
    source_error=""
    if ! read_node_record "$node"; then
        record_source_evidence "$node"
        [ -f "deploy/devfleet/$node.txt" ] && PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
        case "$NODE_RECORD_ERROR" in
            invalid_source_sha|source_sha_not_in_main_history|source_predates_onion_p2p)
                source_error="$NODE_RECORD_ERROR"
                ;;
            *)
                record_gap "$node" "$NODE_RECORD_ERROR"
                return
                ;;
        esac
    else
        record_source_evidence "$node"
        PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
    fi
    if [ "$NODE_PORT" != "$DEVFLEET_PORT" ]; then
        record_gap "$node" "published_port_differs_from_local_env"
        return
    fi
    published_onion=""
    if [ -f "$DEVFLEET_DATADIR/tor_data/onion_service/hostname" ]; then
        published_onion="$(tr -d '[:space:]' < \
            "$DEVFLEET_DATADIR/tor_data/onion_service/hostname")"
    fi
    if [ "$published_onion" != "$NODE_ONION" ]; then
        record_gap "$node" "published_onion_differs_from_live_service"
        return
    fi
    chain_info="$(cli getblockchaininfo 2>/dev/null || true)"
    blocks="$(json_get "$chain_info" blocks)"
    headers="$(json_get "$chain_info" headers)"
    progress="$(json_get "$chain_info" verificationprogress)"
    LOCAL_HASH="$(json_get "$chain_info" bestblockhash)"
    if [[ ! "$blocks" =~ ^[0-9]+$ ]] || [ "$blocks" != "$headers" ] ||
       [ "$progress" != 1 ] || [[ ! "$LOCAL_HASH" =~ ^[0-9a-f]{64}$ ]]; then
        record_gap "$node" \
            "local_not_synced:blocks=${blocks:-absent}:headers=${headers:-absent}:progress=${progress:-absent}"
        return
    fi
    LOCAL_HEIGHT_BEFORE="$blocks"
    if self_dial_raw="$(fresh_self_dial "$NODE_ONION:$NODE_PORT" 2>&1)"; then
        self_dial_rc=0
    else
        self_dial_rc=$?
    fi
    self_dial_detail="$(printf '%s\n' "$self_dial_raw" |
        sed -n 's/^SELF_DIAL_RESULT=//p' | tail -n 1)"
    if [ -z "$self_dial_detail" ]; then
        self_dial_detail="self_dial_isolation_refused:$(clean_detail "$self_dial_raw")"
    fi
    if [ "$self_dial_rc" -ne 0 ]; then
        record_gap "$node" "${self_dial_detail:-self_dial_failed_without_detail}"
        return
    fi
    if [ -n "$source_error" ]; then
        record_gap "$node" "$source_error:$self_dial_detail"
        return
    fi
    record_pass "$node" "self_synced:height=$blocks:$self_dial_detail"
}

check_remote_node() {
    local node="$1" endpoint row state version peer_height local_before
    local local_after add_out add_ok add_status deadline now source_error
    local publication_suffix
    source_error=""
    if ! read_node_record "$node"; then
        record_source_evidence "$node"
        [ -f "deploy/devfleet/$node.txt" ] && PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
        if [ "$NODE_RECORD_ERROR" = unpublished ]; then
            record_gap "$node" "$NODE_RECORD_ERROR"
            return
        fi
        case "$NODE_RECORD_ERROR" in
            invalid_source_sha|source_sha_not_in_main_history|source_predates_onion_p2p)
                source_error="$NODE_RECORD_ERROR"
                ;;
            *)
                record_gap "$node" "$NODE_RECORD_ERROR"
                return
                ;;
        esac
    else
        record_source_evidence "$node"
        PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
    fi
    publication_suffix=""
    [ -n "$source_error" ] && publication_suffix=":publication=$source_error"
    endpoint="$NODE_ONION:$NODE_PORT"
    if [ -z "$NODE_ONION" ] || [ -z "$NODE_PORT" ]; then
        record_gap "$node" "$source_error"
        return
    fi

    local_before="$(cli getblockcount 2>/dev/null || true)"
    if [[ ! "$local_before" =~ ^[0-9]+$ ]]; then
        record_gap "$node" "local_tip_unreadable"
        return
    fi

    row="$(peer_row "$endpoint" || true)"
    state="$(json_get "$row" state)"
    if [ "$state" != active ]; then
        add_out="$(cli core network peers add --address="$endpoint" 2>&1 || true)"
        add_ok="$(json_get "$add_out" ok)"
        add_status="$(json_get "$add_out" data.status)"
        if [ "$add_ok" != true ] ||
           { [ "$add_status" != dial_requested ] &&
             [ "$add_status" != already_connected ]; }; then
            record_gap "$node" \
                "dial_refused:${add_status:-$(clean_detail "$add_out")}$publication_suffix"
            return
        fi

        deadline=$(( $(date +%s) + DIAL_TIMEOUT ))
        while :; do
            row="$(peer_row "$endpoint" || true)"
            state="$(json_get "$row" state)"
            [ "$state" = active ] && break
            now="$(date +%s)"
            [ "$now" -ge "$deadline" ] && break
            # Condition-driven polling only: no redial/restart or sleep-as-fix.
            sleep 1
        done
    fi

    if [ "$state" != active ]; then
        record_gap "$node" \
            "version_verack_incomplete:state=${state:-absent}$publication_suffix"
        return
    fi
    version="$(json_get "$row" version)"
    peer_height="$(json_get "$row" startingheight)"
    local_after="$(cli getblockcount 2>/dev/null || true)"
    LOCAL_HEIGHT_AFTER="$local_after"
    if [[ ! "$version" =~ ^[1-9][0-9]*$ ]]; then
        record_gap "$node" "version_missing_after_active"
        return
    fi
    if [[ ! "$peer_height" =~ ^[0-9]+$ ]] ||
       [[ ! "$local_after" =~ ^[0-9]+$ ]]; then
        record_gap "$node" "tip_height_unreadable"
        return
    fi
    if [ "$peer_height" != "$local_before" ] &&
       [ "$peer_height" != "$local_after" ]; then
        record_gap "$node" \
            "tip_height_mismatch:peer=$peer_height:local_before=$local_before:local_after=$local_after"
        return
    fi
    if [ -n "$source_error" ]; then
        record_gap "$node" "$source_error"
        return
    fi
    record_pass "$node" \
        "version_verack:protocol=$version:tip_height=$peer_height"
}

join_gaps() {
    local joined="" gap
    for gap in "${GAPS[@]-}"; do
        [ -n "$joined" ] && joined+=","
        joined+="$gap"
    done
    [ -n "$joined" ] || joined="none"
    printf '%s' "$joined"
}

write_status() {
    local now_iso="$1" now_epoch="$2" passes="$3" hold="$4"
    local last_full_epoch="$5" source_sha gap_text tmp
    source_sha="$(git rev-parse HEAD)"
    gap_text="$(join_gaps)"
    tmp="$(mktemp "$REPO_DIR/deploy/devfleet/.mesh.status.XXXXXX")"
    {
        printf 'MESH=%s/%s\n' "$PASS_COUNT" "$EXPECTED_NODES"
        printf 'PUBLISHED=%s/%s\n' "$PUBLISHED_COUNT" "$EXPECTED_NODES"
        if [ "$PASS_COUNT" = "$EXPECTED_NODES" ]; then
            printf 'VERDICT=pass\n'
        else
            printf 'VERDICT=fail\n'
        fi
        printf 'CONSECUTIVE_FULL_PASSES=%s\n' "$passes"
        printf 'HOLD=%s\n' "$hold"
        printf 'OBSERVED_AT=%s\n' "$now_iso"
        printf 'OBSERVED_EPOCH=%s\n' "$now_epoch"
        printf 'LAST_FULL_PASS_EPOCH=%s\n' "$last_full_epoch"
        printf 'LOCAL_BOX=%s\n' "$BOX"
        printf 'LOCAL_HEIGHT=%s\n' "${LOCAL_HEIGHT_AFTER:-$LOCAL_HEIGHT_BEFORE}"
        printf 'LOCAL_BEST_BLOCK=%s\n' "$LOCAL_HASH"
        printf 'SOURCE_SHA=%s\n' "$source_sha"
        local node
        for node in node1 node2 node3 node4; do
            printf '%s_SOURCE_SHA=%s\n' "${node^^}" \
                "${NODE_SOURCE_SHAS[$node]:-absent}"
            printf '%s_SOURCE_SHA_KIND=%s\n' "${node^^}" \
                "${NODE_SOURCE_KINDS[$node]:-unknown}"
            printf '%s_SOURCE_SHA_STALE=%s\n' "${node^^}" \
                "${NODE_SOURCE_STALE[$node]:-unknown}"
            printf '%s_SOURCE_SHA_BEHIND=%s\n' "${node^^}" \
                "${NODE_SOURCE_BEHIND[$node]:-unknown}"
            printf '%s_SOURCE_SHA_DETAIL=%s\n' "${node^^}" \
                "${NODE_SOURCE_DETAILS[$node]:-not_checked}"
            printf '%s=%s\n' "${node^^}" "${NODE_RESULTS[$node]:-fail:not_checked}"
        done
        printf 'GAPS=%s\n' "$gap_text"
    } > "$tmp"
    mv "$tmp" "$STATUS_FILE"
}

publish_status() {
    git add "$STATUS_REL"
    if git diff --cached --quiet -- "$STATUS_REL"; then
        log "status unchanged"
        return 0
    fi
    git commit --quiet -m "devfleet: mesh acceptance ${PASS_COUNT}/${EXPECTED_NODES}"

    git fetch origin main --quiet || {
        log "REFUSED publish: post-commit fetch failed; commit preserved"
        return 1
    }
    if [ "$(git rev-parse HEAD^)" != "$(git rev-parse origin/main)" ]; then
        git rebase origin/main --quiet || {
            git rebase --abort >/dev/null 2>&1 || true
            log "REFUSED publish: mesh status rebase failed; commit preserved"
            return 1
        }
    fi
    git push origin main --quiet || {
        log "REFUSED publish: push failed; commit preserved"
        return 1
    }
    log "published $STATUS_REL at $(git rev-parse HEAD)"
}

if [ "$GIT_MODE" = publish ]; then
    sync_main || exit 1
    if [ "$(status_value HOLD)" = pass ] &&
       [ "$(status_value CONSECUTIVE_FULL_PASSES)" -ge 2 ] 2>/dev/null; then
        log "HOLD: two consecutive 4/4 observations already recorded"
        exit 0
    fi
fi

check_local_node "$BOX"
for node in node1 node2 node3 node4; do
    [ "$node" = "$BOX" ] && continue
    check_remote_node "$node"
done

NOW_EPOCH="$(date +%s)"
NOW_ISO="$(date -u +%FT%TZ)"
PREVIOUS_PASSES="$(status_value CONSECUTIVE_FULL_PASSES)"
PREVIOUS_FULL_EPOCH="$(status_value LAST_FULL_PASS_EPOCH)"
case "$PREVIOUS_PASSES" in *[!0-9]*|'') PREVIOUS_PASSES=0 ;; esac
case "$PREVIOUS_FULL_EPOCH" in *[!0-9]*|'') PREVIOUS_FULL_EPOCH=0 ;; esac

CONSECUTIVE=0
LAST_FULL_EPOCH=0
HOLD=pending
if [ "$PASS_COUNT" = "$EXPECTED_NODES" ]; then
    LAST_FULL_EPOCH="$NOW_EPOCH"
    if [ "$PREVIOUS_PASSES" -eq 0 ]; then
        CONSECUTIVE=1
    elif [ $((NOW_EPOCH - PREVIOUS_FULL_EPOCH)) -ge "$MIN_PASS_INTERVAL" ]; then
        CONSECUTIVE=$((PREVIOUS_PASSES + 1))
    else
        CONSECUTIVE="$PREVIOUS_PASSES"
    fi
    if [ "$CONSECUTIVE" -ge 2 ]; then
        HOLD=pass
    fi
fi

write_status "$NOW_ISO" "$NOW_EPOCH" "$CONSECUTIVE" "$HOLD" \
    "$LAST_FULL_EPOCH"

PUBLISH_OK=1
if [ "$GIT_MODE" = publish ]; then
    publish_status || PUBLISH_OK=0
fi

log "MESH=$PASS_COUNT/$EXPECTED_NODES PUBLISHED=$PUBLISHED_COUNT/$EXPECTED_NODES GAPS=$(join_gaps) HOLD=$HOLD"
[ "$PUBLISH_OK" = 1 ] || exit 1
[ "$PASS_COUNT" = "$EXPECTED_NODES" ] || exit 1
exit 0
