#!/usr/bin/env bash
# fleet_mesh_acceptance.sh — fail-closed onion P2P mesh acceptance.
#
# The hub runs this from cron every five minutes.  One bounded cycle:
#   * reconciles the checkout with origin/main without discarding local work;
#   * validates all four neutral node publications;
#   * self-dials the hub onion from a fresh, isolated mainnet instance;
#   * asks the isolated node to dial every missing peer by its onion endpoint;
#   * requires a handshaked peer (VERSION/VERACK complete) whose CURRENT
#     height — the accepted-header vote, not the handshake-static VERSION
#     number — sits inside the node's own synced band around our tip;
#   * checks each publication's mandatory GIT_SHA against observed main;
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
#   FLEET_MESH_STATUS_FILE=/tmp/mesh.status  local-mode test output
#   FLEET_MESH_FIRST_FULL_FILE=/tmp/mesh.first-4of4.status  local-mode evidence

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
GIT_MODE="${FLEET_MESH_GIT_MODE:-local}"
DIAL_TIMEOUT="${FLEET_MESH_DIAL_TIMEOUT:-45}"
SELF_DIAL_TIMEOUT="${FLEET_MESH_SELF_DIAL_TIMEOUT:-120}"
SELF_DIAL_PORT_BASE="${FLEET_MESH_SELF_DIAL_PORT_BASE:-39250}"
MIN_PASS_INTERVAL="${FLEET_MESH_MIN_PASS_INTERVAL:-240}"
# The product's own synced band: ZCL_NODE_HEALTH_LAG_WARN_BLOCKS in
# app/services/include/services/node_health_service.h:14, used verbatim at
# node_health_service.c:613-616 to decide this node is synced and serving.
# Deliberately NOT env-overridable: widening it is the one edit that could
# turn a genuinely-behind peer into a mesh pass. See remote_peer_at_local_tip.
MESH_TIP_LAG_BLOCKS=10
STATE_DIR="$HOME/.local/state/zclassic23-fleetsync"
STATUS_REL="deploy/devfleet/mesh.status"
STATUS_FILE="${FLEET_MESH_STATUS_FILE:-$REPO_DIR/$STATUS_REL}"
FIRST_FULL_REL="deploy/devfleet/mesh.first-4of4.status"
FIRST_FULL_FILE="${FLEET_MESH_FIRST_FULL_FILE:-$REPO_DIR/$FIRST_FULL_REL}"
ZCL_CLI="${FLEET_MESH_CLI:-$REPO_DIR/build/bin/z23}"
JSONQ="${FLEET_MESH_JSONQ:-$REPO_DIR/build/bin/jsonq}"
NODE_BIN="${FLEET_MESH_NODE_BIN:-$REPO_DIR/build/bin/zclassic23}"
RPC_BIN="${FLEET_MESH_RPC_BIN:-$REPO_DIR/build/bin/zcl-rpc}"
ONION_BASE_COMMIT="355808b13b704624927d9c997a1d5677f17486f6"

# shellcheck source=tools/scripts/fleet_source_status.sh
. "$REPO_DIR/tools/scripts/fleet_source_status.sh"
# shellcheck source=tools/scripts/fleet_mesh_evidence.sh
. "$REPO_DIR/tools/scripts/fleet_mesh_evidence.sh"

case "$BOX" in
    node1|node2|node3|node4) ;;
    *) echo "fleet-mesh: invalid box name: $BOX" >&2; exit 2 ;;
esac
case "$GIT_MODE" in
    publish|local) ;;
    *) echo "fleet-mesh: invalid FLEET_MESH_GIT_MODE: $GIT_MODE" >&2; exit 2 ;;
esac
if [ "$GIT_MODE" = publish ] &&
   { [ "$STATUS_FILE" != "$REPO_DIR/$STATUS_REL" ] ||
     [ "$FIRST_FULL_FILE" != "$REPO_DIR/$FIRST_FULL_REL" ]; }; then
    echo "fleet-mesh: output overrides are local-mode only" >&2
    exit 2
fi
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

# Turn a failed local RPC call into one of a small set of honest, named
# causes instead of collapsing every distinct failure into "absent".
# CLI_LAST_STDERR carries the z23 CLI's own diagnosis verbatim: src/cli.c
# prints "Cannot connect to ..." (and "RPC call failed") when the socket
# never connects, or "Error: <message>" from the JSON-RPC error object —
# which is also how a leaf missing from this binary surfaces (e.g. an
# unknown-method message), so that case carries its real cause too rather
# than needing a separate branch.
classify_cli_failure() {
    local stderr="$1"
    case "$stderr" in
        *'Cannot connect to'*|*'RPC call failed'*)
            printf 'rpc_connection_failed'
            ;;
        *'Error: '*)
            printf 'rpc_error:%s' "$(clean_detail "${stderr#*Error: }")"
            ;;
        '')
            printf 'rpc_no_response'
            ;;
        *)
            printf 'rpc_failed:%s' "$(clean_detail "$stderr")"
            ;;
    esac
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
        case "$path" in
            "$STATUS_REL"|"$FIRST_FULL_REL") ;;
            *) return 0 ;;
        esac
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
            "$STATUS_REL"|"$FIRST_FULL_REL"|"deploy/devfleet/$BOX.sync") ;;
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
    if [ -n "$(git diff --name-only -- "$STATUS_REL" "$FIRST_FULL_REL")" ] ||
       [ -n "$(git diff --cached --name-only -- "$STATUS_REL" "$FIRST_FULL_REL")" ]; then
        log "REFUSED source_sync: prior mesh evidence write is uncommitted"
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

# A command substitution runs cli() in a forked subshell, so any variable it
# assigned directly would vanish the moment that subshell exits. Route the
# CLI's stderr through a fixed file instead — a filesystem write survives
# subshell exit — and have callers who need the diagnosis pull it back into
# the parent shell with cli_read_stderr() right after the `x="$(cli ...)"`
# that produced it.
CLI_STDERR_FILE="$STATE_DIR/$BOX.cli_stderr"
CLI_LAST_STDERR=""
cli() {
    timeout 60 "$ZCL_CLI" -datadir="$DEVFLEET_DATADIR" \
        -rpcport="$DEVFLEET_RPCPORT" "$@" 2>"$CLI_STDERR_FILE"
}
cli_read_stderr() {
    CLI_LAST_STDERR="$(cat "$CLI_STDERR_FILE" 2>/dev/null || true)"
}

json_get() {
    local document="$1" path="$2"
    printf '%s' "$document" | "$JSONQ" get "$path" 2>/dev/null || true
}

json_count() {
    local document="$1" path="$2"
    printf '%s' "$document" | "$JSONQ" count "$path" 2>/dev/null || true
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
    local endpoint="$1" start deadline status dial_ready descriptor_ready
    local add_out add_error row state version elapsed dial_ready_elapsed

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

    dial_ready=false
    descriptor_ready=false
    dial_ready_elapsed=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            probe_finish 1 self_dial_probe_exited_during_tor_bootstrap
        fi
        status="$(probe_cli core network onion status 2>/dev/null || true)"
        dial_ready="$(json_get "$status" data.dial_ready)"
        [ -n "$dial_ready" ] || dial_ready="$(json_get "$status" dial_ready)"
        descriptor_ready="$(json_get "$status" data.tor_ready)"
        [ -n "$descriptor_ready" ] || \
            descriptor_ready="$(json_get "$status" tor_ready)"
        if [ "$dial_ready" = true ]; then
            dial_ready_elapsed=$(( $(date +%s) - start ))
            break
        fi
        sleep 1
    done
    if [ "$dial_ready" != true ]; then
        probe_finish 1 "self_dial_tor_dial_not_ready"
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
                "self_dial_version_verack:protocol=$version:state=${state:-unknown}:seconds=$elapsed:dial_ready_seconds=$dial_ready_elapsed:descriptor_ready_at_dial=${descriptor_ready:-unknown}"
        fi
        sleep 1
    done
    probe_finish 1 \
        "self_dial_version_verack_incomplete:state=${state:-absent}"
)

# field_from_content is the ONE parser: every KEY=VALUE record, wherever its
# bytes came from (a live file, a git-show blob), ends up here as a plain
# string. file/ref readers below only differ in how they PRODUCE that string
# — the extraction rule (exactly one match, non-empty) lives in exactly one
# place.
field_from_content() {
    local content="$1" key="$2" count value
    count="$(printf '%s\n' "$content" | sed -n "s/^${key}=//p" | wc -l | tr -d ' ')"
    [ "$count" = 1 ] || return 1
    value="$(printf '%s\n' "$content" | sed -n "s/^${key}=//p")"
    [ -n "$value" ] || return 1
    printf '%s' "$value"
}

field_from_file() {
    local file="$1" key="$2" content
    content="$(cat "$file" 2>/dev/null)" || return 1
    field_from_content "$content" "$key"
}

NODE_FILE_BOX=""
NODE_ONION=""
NODE_PORT=""
NODE_SOURCE=""
NODE_GIT_SHA=""
NODE_RECORD_ERROR=""
# A node's published record is EVIDENCE (what the fleet claims right now),
# never part of the pinned JUDGE. Every box's record — the local box's own
# publication included, since it is data the fleet-sync heartbeat refreshes
# on origin/main just like any peer's — is therefore resolved from
# $OBSERVED_MAIN (freshly fetched origin/main), not this checkout's pinned
# worktree. Reading the local box's record from the frozen worktree instead
# would reproduce the exact same staleness bug for this box alone, so there
# is no special case here: one rule, four boxes.
node_record_published() {
    [ "$NODE_RECORD_ERROR" != unpublished ]
}
read_node_record() {
    local expected="$1" path content
    path="deploy/devfleet/$expected.txt"
    NODE_FILE_BOX=""
    NODE_ONION=""
    NODE_PORT=""
    NODE_SOURCE=""
    NODE_GIT_SHA=""
    NODE_RECORD_ERROR=""
    if ! content="$(git show "$OBSERVED_MAIN:$path" 2>/dev/null)"; then
        # git show fails exactly when the path does not exist at that ref
        # (or the ref itself is unusable) — today's only other failure mode
        # for this function was "no such file", so this maps onto the same
        # existing "unpublished" token rather than inventing a new one.
        NODE_RECORD_ERROR="unpublished"
        return 1
    fi
    NODE_FILE_BOX="$(field_from_content "$content" BOX || true)"
    NODE_ONION="$(field_from_content "$content" ONION_ADDRESS || true)"
    NODE_PORT="$(field_from_content "$content" P2P_PORT || true)"
    NODE_SOURCE="$(field_from_content "$content" SOURCE_SHA || true)"
    NODE_GIT_SHA="$(field_from_content "$content" GIT_SHA || true)"
    if [ "$NODE_FILE_BOX" != "$expected" ]; then
        NODE_RECORD_ERROR="box_identity_mismatch"
    elif [[ ! "$NODE_ONION" =~ ^[a-z2-7]{56}\.onion$ ]]; then
        NODE_RECORD_ERROR="invalid_onion_address"
    elif [[ ! "$NODE_PORT" =~ ^[0-9]+$ ]] ||
         [ "$NODE_PORT" -lt 1 ] || [ "$NODE_PORT" -gt 65535 ]; then
        NODE_RECORD_ERROR="invalid_p2p_port"
    elif [[ ! "$NODE_SOURCE" =~ ^[0-9a-f]{40}$ ]] &&
         [[ ! "$NODE_SOURCE" =~ ^[0-9a-f]{64}$ ]]; then
        NODE_RECORD_ERROR="invalid_source_sha"
    elif [[ ! "$NODE_GIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
        NODE_RECORD_ERROR="invalid_git_sha"
    else
        fleet_source_status_audit "$REPO_DIR" "$OBSERVED_MAIN" \
            "$NODE_SOURCE" "$NODE_GIT_SHA" "$ONION_BASE_COMMIT"
        if [ "$FLEET_SOURCE_STATUS" = STALE ]; then
            NODE_RECORD_ERROR="STALE_PEER_SOURCE"
        fi
    fi
    [ -z "$NODE_RECORD_ERROR" ]
}

declare -A NODE_RESULTS
declare -A NODE_SOURCE_SHAS
declare -A NODE_SOURCE_KINDS
declare -A NODE_SOURCE_STALE
declare -A NODE_STALE_SOURCE
declare -A NODE_SOURCE_BEHIND
declare -A NODE_SOURCE_DETAILS
declare -A NODE_SOURCE_STATUSES
declare -A NODE_SOURCE_COMMITS
declare -A NODE_SOURCE_COMMIT_DATES
declare -A NODE_CURRENT
declare -A NODE_SILENT
declare -a GAPS
NODE2_FRESH_INBOUND=not_attempted
NODE2_FRESH_INBOUND_DETAIL=none
NODE2_FIRST_REAL_PEER_EDGE_AT="$(status_value NODE2_FIRST_REAL_PEER_EDGE_AT)"
NODE2_FIRST_REAL_PEER_EDGE_DETAIL="$(status_value NODE2_FIRST_REAL_PEER_EDGE_DETAIL)"
[ -n "$NODE2_FIRST_REAL_PEER_EDGE_AT" ] || NODE2_FIRST_REAL_PEER_EDGE_AT=NONE
[ -n "$NODE2_FIRST_REAL_PEER_EDGE_DETAIL" ] || \
    NODE2_FIRST_REAL_PEER_EDGE_DETAIL=NONE
PASS_COUNT=0
PUBLISHED_COUNT=0
LOCAL_HEIGHT_BEFORE=""
LOCAL_HEIGHT_AFTER=""
LOCAL_HASH=""
REFEREE_LOCAL_TIP=""
REFEREE_LOCAL_RPC_FAULT=""

record_source_evidence() {
    local node="$1"
    NODE_SOURCE_SHAS[$node]="${NODE_SOURCE:-absent}"
    fleet_source_status_audit "$REPO_DIR" "$OBSERVED_MAIN" \
        "${NODE_SOURCE:-}" "${NODE_GIT_SHA:-}" "$ONION_BASE_COMMIT"
    NODE_SOURCE_KINDS[$node]="$FLEET_SOURCE_KIND"
    NODE_SOURCE_STATUSES[$node]="$FLEET_SOURCE_STATUS"
    NODE_SOURCE_COMMITS[$node]="$FLEET_SOURCE_COMMIT"
    NODE_SOURCE_COMMIT_DATES[$node]="$FLEET_SOURCE_COMMIT_DATE"
    NODE_SOURCE_BEHIND[$node]="$FLEET_SOURCE_BEHIND"
    NODE_SOURCE_DETAILS[$node]="$FLEET_SOURCE_DETAIL"
    if [ "$FLEET_SOURCE_STATUS" = CURRENT ]; then
        NODE_SOURCE_STALE[$node]=no
        NODE_CURRENT[$node]=yes
    else
        NODE_SOURCE_STALE[$node]=yes
        NODE_CURRENT[$node]=no
    fi
    NODE_STALE_SOURCE[$node]="$FLEET_SOURCE_REQUIRED_FLOOR"
    [ "$NODE_RECORD_ERROR" = unpublished ] && \
        NODE_SOURCE_KINDS[$node]=absent
    return 0
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

# A remote node whose check could not run because THIS box's own RPC read
# failed is neither a pass nor a peer-attributable gap: its status this
# cycle is unknown, not failed, and it must never join GAPS naming the node.
record_unknown() {
    local node="$1" reason="$2"
    NODE_RESULTS[$node]="unknown:$(clean_detail "$reason")"
}

# The referee's own tip height. Every remote check needs it, but a failure
# here is this box's local RPC front door being unhealthy, never a remote
# peer's fault. Read it fresh (state may advance across the cycle) but
# record the cause once, in REFEREE_LOCAL_RPC_FAULT, so a saturated RPC
# queue is never misattributed as a per-node gap.
refresh_referee_local_tip() {
    local out rc
    out="$(cli getblockcount)"
    rc=$?
    cli_read_stderr
    if [ "$rc" -eq 0 ] && [[ "$out" =~ ^[0-9]+$ ]]; then
        REFEREE_LOCAL_TIP="$out"
        return 0
    fi
    REFEREE_LOCAL_TIP=""
    [ -n "$REFEREE_LOCAL_RPC_FAULT" ] || \
        REFEREE_LOCAL_RPC_FAULT="$(classify_cli_failure "$CLI_LAST_STDERR")"
    return 1
}

# Every remote node's height check needs this box's per-peer accepted-header
# votes. Read ONCE for the whole cycle and cached: the referee fires every
# five minutes against the same RPC front door that has already bricked at 54
# CLOSE_WAIT sockets, so it must not add one read per node. Bounded
# diagnostic leaf, same discipline as dumpstate status_frontdoor and for the
# same reason getblockchaininfo is banned here. A malformed or unreadable
# reply is a fault of THIS box, recorded once in REFEREE_LOCAL_RPC_FAULT
# exactly like refresh_referee_local_tip, so a saturated RPC queue is never
# misattributed as a per-node gap. live_peer_votes is required to be an
# integer: it is the leaf's proof that the shape we parse is the shape the
# node actually published, so an older daemon without the field fails closed
# to unknown instead of silently reading zero votes for every peer.
PEER_HEIGHT_VOTES=""
PEER_HEIGHT_VOTES_STATE=unread
refresh_peer_height_votes() {
    local out rc live
    case "$PEER_HEIGHT_VOTES_STATE" in
        ok) return 0 ;;
        failed) return 1 ;;
    esac
    if out="$(cli dumpstate quorum_oracle)"; then
        rc=0
    else
        rc=$?
    fi
    cli_read_stderr
    if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
        live="$(json_get "$out" state.live_peer_votes)"
        if [[ "$live" =~ ^[0-9]+$ ]]; then
            PEER_HEIGHT_VOTES="$out"
            PEER_HEIGHT_VOTES_STATE=ok
            return 0
        fi
    fi
    PEER_HEIGHT_VOTES=""
    PEER_HEIGHT_VOTES_STATE=failed
    [ -n "$REFEREE_LOCAL_RPC_FAULT" ] || \
        REFEREE_LOCAL_RPC_FAULT="$(classify_cli_failure "$CLI_LAST_STDERR")"
    return 1
}

check_local_node() {
    local node="$1" frontdoor frontdoor_rc blocks published sync_gap sync_gap_known
    local all_members_fresh published_onion
    local self_dial_detail self_dial_raw self_dial_rc source_error
    source_error=""
    if ! read_node_record "$node"; then
        record_source_evidence "$node"
        node_record_published && PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
        case "$NODE_RECORD_ERROR" in
            invalid_source_sha|invalid_git_sha|source_sha_not_in_main_history|STALE_SOURCE|STALE_PEER_SOURCE)
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
    # Program O2's status_frontdoor is the node's one bounded operator read:
    # height is lock-free, peer state is trylock/cached, and every dark member
    # is named.  Do not use getblockchaininfo here: a stuck chain read outlives
    # the client timeout, consumes one of four RPC workers, and recurring
    # telemetry can eventually fill the entire 64-connection queue.
    frontdoor="$(cli dumpstate status_frontdoor)"
    frontdoor_rc=$?
    cli_read_stderr
    if [ "$frontdoor_rc" -ne 0 ] || [ -z "$frontdoor" ]; then
        record_gap "$node" \
            "local_status_frontdoor_$(classify_cli_failure "$CLI_LAST_STDERR")"
        return
    fi
    blocks="$(json_get "$frontdoor" state.height)"
    published="$(json_get "$frontdoor" state.provable_tip_published)"
    sync_gap="$(json_get "$frontdoor" state.sync_gap)"
    sync_gap_known="$(json_get "$frontdoor" state.sync_gap_known)"
    all_members_fresh="$(json_get "$frontdoor" state.all_members_fresh)"
    LOCAL_HASH=STATUS_FRONTDOOR_NO_HASH
    if [[ ! "$blocks" =~ ^[0-9]+$ ]] || [ "$published" != true ] ||
       [ "$sync_gap_known" != true ] || [[ ! "$sync_gap" =~ ^[0-9]+$ ]] ||
       [ "$sync_gap" -ne 0 ] || [ "$all_members_fresh" != true ]; then
        record_gap "$node" \
            "local_status_frontdoor_not_synced:height=${blocks:-absent}:published=${published:-absent}:sync_gap=${sync_gap:-absent}:sync_gap_known=${sync_gap_known:-absent}:fresh=${all_members_fresh:-absent}"
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

# The product's own definition of ready (app/controllers/src/
# status_native_helpers.c:337-343): handshake_complete precedes active,
# which precedes header/block/snapshot sync in the C peer ladder (lib/
# event/src/event.c:836-837), so a peer that has moved on to any later
# ready state already completed VERSION/VERACK. Defined once and called
# from every acceptance site in check_remote_node so the false negative
# (requiring state==active) cannot be reintroduced at one call site while
# fixed at another. Pairing the state with a nonzero negotiated protocol
# version keeps acceptance honest: it means the handshake demonstrably
# finished, not merely that a row with this address exists.
remote_peer_handshake_complete() {
    local state="$1" version="$2"
    case "$state" in
        handshake_complete|active|syncing_headers|syncing_blocks| \
            snapshot_serving|snapshot_receiving)
            ;;
        *)
            return 1
            ;;
    esac
    [[ "$version" =~ ^[1-9][0-9]*$ ]]
}

# ── peer tip-height acceptance ───────────────────────────────────────────
#
# Same class of defect as the state==active one above, and fixed the same
# way. `startingheight` is the height the peer wrote into its VERSION message
# at handshake time. lib/net/src/msg_version.c:367 is its only writer and
# lib/net/src/msgprocessor.c:2388 calls it "handshake-static" in so many
# words: it never updates for the life of the connection. Comparing it for
# equality against our own advancing tip is therefore a structural false
# negative — it can only hold if the peer happened to be at exactly our
# height at the instant it connected, and it becomes permanently false as we
# advance. Observed live: node2, at the network tip with blocks == headers
# and verification progress 1, scored tip_height_mismatch:peer=3225759
# against a local tip of 3226744 — the height it had a thousand blocks ago.
#
# peer_lifecycle's `advertised_height` is NOT a fresher second number.
# lib/net/src/peer_lifecycle.c:925-926 publishes `startingheight` and
# `advertised_height` from the same field, e->start_height, whose only writer
# is peer_lifecycle_note_version_received (peer_lifecycle.c:619). Reading it
# would rename this defect, not fix it. `advertised_height_trust`
# (peer_lifecycle.c:420-432) says only that the stale number came from a
# currently-open, handshaked, NODE_NETWORK connection — it annotates
# attributability, never currency.
#
# The one per-peer height in this node that moves AFTER the handshake is the
# accepted-header vote. lib/net/src/msg_headers.c records accepted evidence,
# and quorum_oracle_service retains one monotonic latest (peer_id, height,
# hash) row per peer. Lower historical repair pages cannot downgrade or
# refresh it; `dumpstate quorum_oracle` publishes the live rows as
# state.peer_votes[].{source_id,height}, TTL 1800s. That number is evidence,
# not a claim: to move it a peer must deliver a header chain our own
# accept_block_header() validated, so it cannot simply assert a height the way
# VERSION does. Residual, stated plainly rather than hidden: an accepted header
# proves the peer knows the chain to that height, not that it holds the blocks
# — still strictly stronger than the unverified VERSION number it replaces,
# and the only per-peer height in the product that is current.

# A peer's CURRENT chain height, resolved exactly the way the node itself
# resolves one (app/services/src/network_monitor.c:306-320): the handshake
# height, RAISED by that peer's newest live accepted-header vote when one
# exists. max() and not "vote wins" because the vote table is bounded (64
# slots) and TTL'd, so a peer with no live vote is judged on the handshake
# number — which is exactly what the referee had before this function
# existed, never something weaker. Prints "<height>:<source>"; returns 1
# only when the handshake height itself is unreadable.
remote_peer_current_height() {
    local votes="$1" peer_id="$2" starting="$3"
    local count i src height best source
    [[ "$starting" =~ ^[0-9]+$ ]] || return 1
    best="$starting"
    source=handshake
    if [[ "$peer_id" =~ ^[0-9]+$ ]]; then
        count="$(json_count "$votes" state.peer_votes)"
        case "$count" in *[!0-9]*|'') count=0 ;; esac
        i=0
        while [ "$i" -lt "$count" ]; do
            src="$(json_get "$votes" "state.peer_votes[$i].source_id")"
            height="$(json_get "$votes" "state.peer_votes[$i].height")"
            if [ "$src" = "$peer_id" ] && [[ "$height" =~ ^[0-9]+$ ]]; then
                source=header_vote
                [ "$height" -gt "$best" ] && best="$height"
            fi
            i=$((i + 1))
        done
    fi
    printf '%s:%s' "$best" "$source"
}

# Tip parity, judged against a height this box has CONFIRMED. Our own tip
# advances while the check runs, which is why the caller samples it either
# side of the peer read; min() of the two samples is the height we
# demonstrably held for the whole window, so the race can never manufacture a
# gap. Exact equality is the wrong test in both directions:
#
#   * a peer AT or ABOVE the confirmed tip is in sync. If it is ahead, the
#     box that is behind is this one, which is check_local_node's business
#     and not this peer's.
#   * a peer BELOW it is in sync only while its lag sits inside the node's
#     own synced band, ZCL_NODE_HEALTH_LAG_WARN_BLOCKS = 10
#     (app/services/include/services/node_health_service.h:14), which
#     node_health_service.c:613-616 uses verbatim — tip_lag >= 0 &&
#     tip_lag <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS — to decide the node is
#     synced and serving. The referee reuses the product's own number rather
#     than inventing a second, disagreeing definition of parity.
#
# Ten blocks is about 25 minutes of chain at the 150s target: wide enough to
# absorb one bounded cycle (a 120s self-dial, a 45s dial wait, RPC waits) and
# a peer that has not yet re-announced the block we just connected, and six
# orders of magnitude short of a genuinely-behind peer — node4 syncing at
# height 192 against a 3,226,744 tip misses the band by 3.2 million. A
# stalled or forked peer stops voting, its height freezes, our tip walks past
# the band, and it fails: this check decays into a gap, never into a pass.
remote_peer_at_local_tip() {
    local peer_height="$1" local_before="$2" local_after="$3" confirmed
    [[ "$peer_height" =~ ^[0-9]+$ ]] || return 1
    [[ "$local_before" =~ ^[0-9]+$ ]] || return 1
    [[ "$local_after" =~ ^[0-9]+$ ]] || return 1
    confirmed="$local_before"
    if [ "$local_after" -lt "$confirmed" ]; then
        confirmed="$local_after"
    fi
    [ $((peer_height + MESH_TIP_LAG_BLOCKS)) -ge "$confirmed" ]
}

check_remote_node() {
    local node="$1" endpoint row state version peer_height local_before
    local local_after add_out add_ok add_status deadline now source_error
    local publication_suffix fresh_raw fresh_rc fresh_detail
    local peer_id peer_start_height resolved height_source
    source_error=""
    NODE_SILENT[$node]=yes
    if ! read_node_record "$node"; then
        record_source_evidence "$node"
        node_record_published && PUBLISHED_COUNT=$((PUBLISHED_COUNT + 1))
        if [ "$NODE_RECORD_ERROR" = unpublished ]; then
            record_gap "$node" "$NODE_RECORD_ERROR"
            return
        fi
        case "$NODE_RECORD_ERROR" in
            invalid_source_sha|invalid_git_sha|source_sha_not_in_main_history|STALE_SOURCE|STALE_PEER_SOURCE)
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

    # node2 ingress is independently proved from a new process and empty
    # datadir.  This does not depend on the hosted hub's RPC health and starts
    # at dial-ready, while this probe's own descriptor may still be publishing.
    if [ "$node" = node2 ]; then
        if fresh_raw="$(fresh_self_dial "$endpoint" 2>&1)"; then
            fresh_rc=0
        else
            fresh_rc=$?
        fi
        fresh_detail="$(printf '%s\n' "$fresh_raw" |
            sed -n 's/^SELF_DIAL_RESULT=//p' | tail -n 1)"
        [ -n "$fresh_detail" ] || \
            fresh_detail="fresh_inbound_no_result:$(clean_detail "$fresh_raw")"
        NODE2_FRESH_INBOUND_DETAIL="$(clean_detail "$fresh_detail")"
        if [ "$fresh_rc" -eq 0 ]; then
            NODE2_FRESH_INBOUND=pass
            if [ "$NODE2_FIRST_REAL_PEER_EDGE_AT" = NONE ]; then
                NODE2_FIRST_REAL_PEER_EDGE_AT="$(date -u +%FT%TZ)"
                NODE2_FIRST_REAL_PEER_EDGE_DETAIL="$NODE2_FRESH_INBOUND_DETAIL"
            fi
        else
            NODE2_FRESH_INBOUND=fail
        fi
    fi

    # A referee-local RPC failure belongs to this box, never to the remote
    # node under test: record it once (REFEREE_LOCAL_RPC_FAULT) and leave
    # this node's status unknown rather than scoring it a gap.
    if ! refresh_referee_local_tip; then
        record_unknown "$node" "referee_local_read_failed:$REFEREE_LOCAL_RPC_FAULT"
        return
    fi
    local_before="$REFEREE_LOCAL_TIP"

    row="$(peer_row "$endpoint" || true)"
    state="$(json_get "$row" state)"
    version="$(json_get "$row" version)"
    if ! remote_peer_handshake_complete "$state" "$version"; then
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
            version="$(json_get "$row" version)"
            remote_peer_handshake_complete "$state" "$version" && break
            now="$(date +%s)"
            [ "$now" -ge "$deadline" ] && break
            # Condition-driven polling only: no redial/restart or sleep-as-fix.
            sleep 1
        done
    fi

    if ! remote_peer_handshake_complete "$state" "$version"; then
        record_gap "$node" \
            "version_verack_incomplete:state=${state:-absent}$publication_suffix"
        return
    fi
    NODE_SILENT[$node]=no
    peer_id="$(json_get "$row" id)"
    peer_start_height="$(json_get "$row" startingheight)"
    if [[ ! "$peer_start_height" =~ ^[0-9]+$ ]]; then
        record_gap "$node" "peer_tip_height_unreadable"
        return
    fi
    # Resolving a CURRENT height needs this box's vote snapshot. A failure to
    # read it is this box's RPC front door being unhealthy, never the remote
    # node's fault, so it takes the same route as a failed local tip read:
    # unknown, not a gap naming the peer. Falling back to the handshake
    # height here would resurrect exactly the false negative above.
    if ! refresh_peer_height_votes; then
        record_unknown "$node" "referee_local_read_failed:$REFEREE_LOCAL_RPC_FAULT"
        return
    fi
    resolved="$(remote_peer_current_height "$PEER_HEIGHT_VOTES" \
        "$peer_id" "$peer_start_height")"
    peer_height="${resolved%%:*}"
    height_source="${resolved##*:}"
    if ! refresh_referee_local_tip; then
        record_unknown "$node" "referee_local_read_failed:$REFEREE_LOCAL_RPC_FAULT"
        return
    fi
    local_after="$REFEREE_LOCAL_TIP"
    LOCAL_HEIGHT_AFTER="$local_after"
    if ! remote_peer_at_local_tip "$peer_height" "$local_before" "$local_after"; then
        record_gap "$node" \
            "tip_height_mismatch:peer=$peer_height:height_source=$height_source:handshake=$peer_start_height:local_before=$local_before:local_after=$local_after"
        return
    fi
    if [ -n "$source_error" ]; then
        record_gap "$node" "$source_error"
        return
    fi
    record_pass "$node" \
        "version_verack:protocol=$version:tip_height=$peer_height:height_source=$height_source"
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
    local ingress_file ingress_key ingress_value
    source_sha="$(git rev-parse HEAD)"
    gap_text="$(join_gaps)"
    ingress_file="$REPO_DIR/deploy/devfleet/node1.status"
    tmp="$(mktemp "$(dirname -- "$STATUS_FILE")/.mesh.status.XXXXXX")"
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
        printf 'REFEREE_LOCAL_RPC_FAULT=%s\n' "${REFEREE_LOCAL_RPC_FAULT:-none}"
        printf 'REFEREE_SOURCE_SHA=%s\n' "$source_sha"
        printf 'OBSERVED_MAIN_SHA=%s\n' "$(git rev-parse "$OBSERVED_MAIN")"
        local node
        for node in node1 node2 node3 node4; do
            printf '%s_SOURCE_SHA=%s\n' "${node^^}" \
                "${NODE_SOURCE_SHAS[$node]:-absent}"
            printf '%s_SOURCE_SHA_KIND=%s\n' "${node^^}" \
                "${NODE_SOURCE_KINDS[$node]:-unknown}"
            printf '%s_SOURCE_STATUS=%s\n' "${node^^}" \
                "${NODE_SOURCE_STATUSES[$node]:-STALE}"
            printf '%s_GIT_SHA=%s\n' "${node^^}" \
                "${NODE_SOURCE_COMMITS[$node]:-UNKNOWN}"
            printf '%s_GIT_COMMIT_DATE=%s\n' "${node^^}" \
                "${NODE_SOURCE_COMMIT_DATES[$node]:-UNKNOWN}"
            printf '%s_CURRENT=%s\n' "${node^^}" \
                "${NODE_CURRENT[$node]:-no}"
            printf '%s_STALE=%s\n' "${node^^}" \
                "${NODE_SOURCE_STALE[$node]:-yes}"
            printf '%s_SOURCE_STAMP=%s:%s\n' "${node^^}" \
                "${NODE_SOURCE_STATUSES[$node]:-STALE}" \
                "${NODE_SOURCE_COMMIT_DATES[$node]:-UNKNOWN}"
            printf '%s_SOURCE_SHA_STALE=%s\n' "${node^^}" \
                "${NODE_SOURCE_STALE[$node]:-unknown}"
            printf '%s_STALE_SOURCE=%s\n' "${node^^}" \
                "${NODE_STALE_SOURCE[$node]:-unknown}"
            printf '%s_SOURCE_SHA_BEHIND=%s\n' "${node^^}" \
                "${NODE_SOURCE_BEHIND[$node]:-unknown}"
            printf '%s_SOURCE_SHA_DETAIL=%s\n' "${node^^}" \
                "${NODE_SOURCE_DETAILS[$node]:-not_checked}"
            printf '%s=%s\n' "${node^^}" "${NODE_RESULTS[$node]:-fail:not_checked}"
        done
        printf 'NODE2_SILENT=%s\n' "${NODE_SILENT[node2]:-yes}"
        printf 'NODE2_SILENT_CONSECUTIVE_CYCLES=%s\n' \
            "$NODE2_SILENT_CYCLES"
        printf 'NODE2_SILENT_SINCE=%s\n' "$NODE2_SILENT_SINCE"
        printf 'NODE2_REASSIGNMENT_RECORD=%s\n' \
            "$NODE2_REASSIGNMENT_RECORD"
        printf 'NODE2_FRESH_INBOUND=%s\n' "$NODE2_FRESH_INBOUND"
        printf 'NODE2_FRESH_INBOUND_DETAIL=%s\n' \
            "$NODE2_FRESH_INBOUND_DETAIL"
        printf 'NODE2_FIRST_REAL_PEER_EDGE_AT=%s\n' \
            "$NODE2_FIRST_REAL_PEER_EDGE_AT"
        printf 'NODE2_FIRST_REAL_PEER_EDGE_DETAIL=%s\n' \
            "$NODE2_FIRST_REAL_PEER_EDGE_DETAIL"
        printf 'GAPS=%s\n' "$gap_text"
        # Preserve the referee's bounded ingress verdict and only its exact
        # evidence fields.  node1.status is the capture evidence file;
        # mesh.status remains the five-minute summary rather than growing a
        # second free-form incident ledger.
        for ingress_key in \
            INGRESS_TRIAGE_VERDICT \
            INGRESS_CAPTURE_ID \
            INGRESS_CAPTURE_COMPLETED_AT \
            INGRESS_TARGET_BOX \
            INGRESS_TARGET_ENDPOINT \
            INGRESS_NODE4_STATUS_OBSERVED_AT \
            INGRESS_NODE4_ACK_CAPTURE_ID \
            INGRESS_NODE4_ATTEMPTED_AT \
            INGRESS_MAP_BEGIN \
            INGRESS_MAP_END \
            INGRESS_P2P_BEGIN_COUNT \
            INGRESS_TCP_SAMPLE_COUNT \
            INGRESS_INBOUND_PEER_SAMPLE_COUNT \
            INGRESS_LAST_PROTOCOL_STATE \
            INGRESS_BYTES_IN \
            INGRESS_BYTES_OUT \
            INGRESS_EVIDENCE_FILE \
            INGRESS_SCOPE; do
            ingress_value="$(field_from_file "$ingress_file" \
                "$ingress_key" || true)"
            [ -z "$ingress_value" ] ||
                printf '%s=%s\n' "$ingress_key" "$ingress_value"
        done
    } > "$tmp"
    mv "$tmp" "$STATUS_FILE"
}

capture_first_full() {
    local now_iso="$1" source_sha
    source_sha="$(git rev-parse "$OBSERVED_MAIN")"
    fleet_mesh_capture_first_full "$PASS_COUNT" "$EXPECTED_NODES" \
        "$STATUS_FILE" "$FIRST_FULL_FILE" "$now_iso" "$source_sha"
    [ "$FLEET_FIRST_FULL_CAPTURED" != yes ] || \
        log "captured immutable first 4/4 evidence at $FIRST_FULL_REL"
}

publish_status() {
    local attempt
    git add "$STATUS_REL"
    [ ! -f "$FIRST_FULL_FILE" ] || git add "$FIRST_FULL_REL"
    if git diff --cached --quiet -- "$STATUS_REL" "$FIRST_FULL_REL"; then
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
    if git push origin main --quiet; then
        log "published $STATUS_REL at $(git rev-parse HEAD)"
        return 0
    fi

    # The normal push already ran the required hook. Fleet peers can advance
    # main while that gate runs, so retry only the ref race against fresh main.
    for attempt in 1 2 3; do
        git fetch origin main --quiet || continue
        if [ "$(git rev-parse HEAD^)" != "$(git rev-parse origin/main)" ]; then
            git rebase origin/main --quiet || {
                git rebase --abort >/dev/null 2>&1 || true
                log "REFUSED publish: mesh status retry rebase failed; commit preserved"
                return 1
            }
        fi
        if git push --no-verify origin main --quiet; then
            log "published $STATUS_REL after ref-race retry at $(git rev-parse HEAD)"
            return 0
        fi
        [ "$attempt" -eq 3 ] || sleep $((attempt * 2))
    done
    log "REFUSED publish: push failed after ref-race retries; commit preserved"
    return 1
}

if [ "$GIT_MODE" = publish ]; then
    sync_main || exit 1
else
    # Update only the remote-tracking observation.  The detached referee's
    # HEAD, worktree, and source identity remain pinned across every cycle.
    git fetch origin main --quiet || {
        log "REFUSED observation: fetch_origin_main_failed"
        exit 1
    }
fi
OBSERVED_MAIN=origin/main

check_local_node "$BOX"
for node in node1 node2 node3 node4; do
    [ "$node" = "$BOX" ] && continue
    check_remote_node "$node"
done

NOW_EPOCH="$(date +%s)"
NOW_ISO="$(date -u +%FT%TZ)"
PREVIOUS_OBSERVED_EPOCH="$(status_value OBSERVED_EPOCH)"
PREVIOUS_NODE2_SILENT_CYCLES="$(status_value NODE2_SILENT_CONSECUTIVE_CYCLES)"
PREVIOUS_NODE2_SILENT_SINCE="$(status_value NODE2_SILENT_SINCE)"
fleet_mesh_silence_observe "${NODE_SILENT[node2]:-yes}" \
    "$PREVIOUS_NODE2_SILENT_CYCLES" \
    "${PREVIOUS_NODE2_SILENT_SINCE:-NONE}" "$NOW_ISO" \
    "$PREVIOUS_OBSERVED_EPOCH" "$NOW_EPOCH" "$MIN_PASS_INTERVAL"
NODE2_SILENT_CYCLES=$FLEET_SILENT_COUNT
NODE2_SILENT_SINCE=$FLEET_SILENT_SINCE
NODE2_REASSIGNMENT_RECORD=$FLEET_SILENT_RECORD
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
capture_first_full "$NOW_ISO"

PUBLISH_OK=1
if [ "$GIT_MODE" = publish ]; then
    publish_status || PUBLISH_OK=0
fi

log "MESH=$PASS_COUNT/$EXPECTED_NODES PUBLISHED=$PUBLISHED_COUNT/$EXPECTED_NODES GAPS=$(join_gaps) HOLD=$HOLD"
[ "$PUBLISH_OK" = 1 ] || exit 1
[ "$PASS_COUNT" = "$EXPECTED_NODES" ] || exit 1
exit 0
