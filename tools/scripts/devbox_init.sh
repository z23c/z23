#!/bin/sh
# Start one persistent, isolated regtest node for machine-local agent work.

set -u
umask 077
DB_LOCK_DIR=

db_fail() {
    step=$1
    shift
    if [ -n "$DB_LOCK_DIR" ]; then
        rmdir "$DB_LOCK_DIR" 2>/dev/null || :
        DB_LOCK_DIR=
    fi
    printf 'devbox_init: FAIL step=%s detail=%s\n' "$step" "$*" >&2
    exit 1
}

db_pass() {
    printf 'devbox_init: PASS step=%s\n' "$1" >&2
}

db_defer() {
    printf 'devbox_init: DEFER step=%s detail=%s\n' "$1" "$2" >&2
}

db_field() {
    key=$1
    file=$2
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

db_valid_pid() {
    pid=$1
    control=$2
    case $pid in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    command_line=$(tr '\000' ' ' < "/proc/$pid/cmdline") || return 1
    case $command_line in
        *devbox_init.sh*--supervisor*"$control"*) return 0 ;;
        *) return 1 ;;
    esac
}

db_node_pid_matches() {
    pid=$1
    datadir=$2
    case $pid in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    command_line=$(tr '\000' ' ' < "/proc/$pid/cmdline") || return 1
    case $command_line in
        *zclassic23*"-datadir=$datadir"*) return 0 ;;
        *) return 1 ;;
    esac
}

db_validate_target() {
    datadir=$1
    rpcport=$2
    p2pport=$3
    case $datadir in /tmp/zcl23-devbox-*) ;; *) return 1 ;; esac
    resolved=$(realpath "$datadir" 2>/dev/null) || return 1
    case $resolved in /tmp/zcl23-devbox-*) ;; *) return 1 ;; esac
    case $rpcport in ''|*[!0-9]*) return 1 ;; esac
    case $p2pport in ''|*[!0-9]*) return 1 ;; esac
    [ "$rpcport" -ge 39000 ] && [ "$rpcport" -le 39999 ] || return 1
    [ "$p2pport" -ge 39000 ] && [ "$p2pport" -le 39999 ] || return 1
    return 0
}

db_status() {
    datadir=$1
    rpcport=$2
    "$Z23_BIN" -datadir="$datadir" -rpcport="$rpcport" \
        core network onion status 2>/dev/null
}

db_status_field() {
    key=$1
    sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" | head -n 1
}

db_valid_onion_address() {
    onion=$1
    [ "${#onion}" -eq 62 ] || return 1
    case $onion in
        [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]*.onion) ;;
        *) return 1 ;;
    esac
    onion_host=${onion%.onion}
    [ "${#onion_host}" -eq 56 ] || return 1
    case $onion_host in *[!a-z2-7]*) return 1 ;; esac
    return 0
}

db_valid_port() {
    port=$1
    case $port in ''|*[!0-9]*) return 1 ;; esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

db_configure_fleet_peers() {
    control=$1
    repo_root=$2
    datadir=$3
    rpcport=$4
    local_onion=$5
    requested_count=0
    deferred_count=0

    for fleet_file in "$repo_root"/deploy/devfleet/*.txt; do
        [ -e "$fleet_file" ] || continue
        [ -f "$fleet_file" ] && [ ! -L "$fleet_file" ] || {
            db_write_failure "$control" fleet_file unsafe_file
            return 1
        }
        fleet_box=$(db_field BOX "$fleet_file")
        fleet_onion=$(db_field ONION_ADDRESS "$fleet_file")
        fleet_port=$(db_field P2P_PORT "$fleet_file")
        fleet_source=$(db_field SOURCE_SHA "$fleet_file")
        [ -n "$fleet_box" ] || {
            db_write_failure "$control" fleet_file missing_box
            return 1
        }
        case $fleet_box in *[!a-zA-Z0-9_-]*|'')
            db_write_failure "$control" fleet_file invalid_box
            return 1
            ;;
        esac
        db_valid_onion_address "$fleet_onion" || {
            db_write_failure "$control" fleet_onion invalid_onion_address
            return 1
        }
        db_valid_port "$fleet_port" || {
            db_write_failure "$control" fleet_port invalid_p2p_port
            return 1
        }
        if [ "$fleet_onion" = "$local_onion" ]; then
            db_pass "fleet_self_skipped_$fleet_box"
            continue
        fi
        resolved_source=$(git -C "$repo_root" rev-parse --verify \
            "${fleet_source}^{commit}" 2>/dev/null) || {
            db_write_failure "$control" fleet_source source_not_found
            return 1
        }
        [ "$resolved_source" = "$fleet_source" ] || {
            db_write_failure "$control" fleet_source source_not_exact_sha
            return 1
        }
        git -C "$repo_root" merge-base --is-ancestor "$fleet_source" HEAD \
            2>/dev/null || {
            db_write_failure "$control" fleet_source source_not_ancestor
            return 1
        }
        peer_result=$("$Z23_BIN" -datadir="$datadir" -rpcport="$rpcport" \
            core network peers add --address="$fleet_onion" 2>&1)
        peer_exit=$?
        if [ "$peer_exit" -ne 0 ] \
            || ! printf '%s' "$peer_result" | grep -q '"ok":true'; then
            deferred_count=$((deferred_count + 1))
            db_defer "fleet_peer_unavailable_$fleet_box" \
                onion_rendezvous_failed
            continue
        fi
        requested_count=$((requested_count + 1))
        db_pass "fleet_peer_requested_$fleet_box"
    done
    db_pass "fleet_peers_scanned_requested_${requested_count}_deferred_${deferred_count}"
    return 0
}

db_write_failure() {
    control=$1
    step=$2
    detail=$3
    tmp="$control/failure.$$"
    printf '%s:%s\n' "$step" "$detail" > "$tmp" || exit 1
    mv "$tmp" "$control/failure" || exit 1
}

db_supervisor() {
    control=$1
    port_base=$2
    repo_root=$3

    ISO_KIND=devbox
    ISO_PORT_BASE=$port_base
    ISO_NODE_BIN="$repo_root/build/bin/zclassic23"
    ISO_RPC_BIN="$repo_root/build/bin/zcl-rpc"
    Z23_BIN="$repo_root/build/bin/z23"
    export ISO_KIND ISO_PORT_BASE ISO_NODE_BIN ISO_RPC_BIN Z23_BIN

    # isolated_node_env.sh is the repository's audited Bash isolation
    # boundary. The public script remains POSIX shell; only this private
    # supervisor is re-executed by Bash to source that existing helper.
    # shellcheck source=tools/scripts/isolated_node_env.sh
    . "$repo_root/tools/scripts/isolated_node_env.sh"

    iso_init
    db_pass isolation_initialized
    iso_spawn_node \
        '-operator-lane=dev -tor -onion-persist -listen=1 -wallet-no-phrase-backup'
    db_pass node_spawned

    if ! iso_wait_rpc_ready 60; then
        db_write_failure "$control" rpc_ready timeout
        exit 1
    fi
    db_pass rpc_ready

    deadline=$(( $(date +%s) + 90 ))
    onion_address=
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            db_write_failure "$control" onion_bootstrap node_exited
            exit 1
        fi
        status=$(db_status "$ISO_DD" "$ISO_RPCPORT") || {
            db_write_failure "$control" onion_status command_failed
            exit 1
        }
        if ! printf '%s' "$status" | grep -q '"ok":true'; then
            db_write_failure "$control" onion_status typed_command_refused
            exit 1
        fi
        bootstrap_state=$(printf '%s' "$status" | db_status_field bootstrap_state)
        if [ -z "$bootstrap_state" ]; then
            db_write_failure "$control" onion_status_contract \
                missing_bootstrap_state
            exit 1
        fi
        if [ "$bootstrap_state" = ready ]; then
            onion_address=$(printf '%s' "$status" | db_status_field onion_address)
            break
        fi
        # Observation cadence only: readiness comes solely from the typed
        # command above; elapsed time never converts a failure into success.
        sleep 1
    done
    [ -n "$onion_address" ] || {
        db_write_failure "$control" onion_bootstrap timeout
        exit 1
    }
    case $onion_address in
        *.onion) ;;
        *)
            db_write_failure "$control" onion_status_contract \
                invalid_onion_address
            exit 1
            ;;
    esac
    db_pass onion_bootstrap_ready

    external_ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
        | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1)
    case $external_ip in
        ''|127.*|*[!0-9.]*)
            db_write_failure "$control" p2p_endpoint \
                no_non_loopback_route_address
            exit 1
            ;;
    esac
    if ! ss -tlnH "sport = :$ISO_PORT" 2>/dev/null | grep -q .; then
        db_write_failure "$control" p2p_endpoint not_listening
        exit 1
    fi
    p2p_endpoint="$external_ip:$ISO_PORT"
    db_pass p2p_endpoint_listening

    db_configure_fleet_peers "$control" "$repo_root" "$ISO_DD" \
        "$ISO_RPCPORT" "$onion_address" || exit 1

    state_tmp="$control/state.$$"
    {
        printf 'SUPERVISOR_PID=%s\n' "$$"
        printf 'NODE_PID=%s\n' "$ISO_NODE_PID"
        printf 'DATADIR=%s\n' "$ISO_DD"
        printf 'RPCPORT=%s\n' "$ISO_RPCPORT"
        printf 'P2PPORT=%s\n' "$ISO_PORT"
        printf 'ONION_ADDRESS=%s\n' "$onion_address"
        printf 'P2P_ENDPOINT=%s\n' "$p2p_endpoint"
    } > "$state_tmp" || exit 1
    mv "$state_tmp" "$control/state" || exit 1

    ready_tmp="$control/ready.$$"
    {
        printf 'ONION_ADDRESS=%s\n' "$onion_address"
        printf 'P2P_ENDPOINT=%s\n' "$p2p_endpoint"
    } > "$ready_tmp" || exit 1
    mv "$ready_tmp" "$control/ready" || exit 1
    db_pass ready_published

    if wait "$ISO_NODE_PID"; then
        db_write_failure "$control" node_lifecycle unexpected_clean_exit
    else
        db_write_failure "$control" node_lifecycle node_exited
    fi
    exit 1
}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P) \
    || db_fail locate_script cannot_resolve_script_directory
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd -P) \
    || db_fail locate_repo cannot_resolve_repository_root
SCRIPT_PATH="$SCRIPT_DIR/devbox_init.sh"
Z23_BIN="$REPO_ROOT/build/bin/z23"

if [ "${1:-}" = --supervisor ]; then
    [ "$#" -eq 4 ] || db_fail supervisor_args expected_control_base_root
    db_supervisor "$2" "$3" "$4"
fi
[ "$#" -eq 0 ] || db_fail usage 'expected no arguments'

command -v bash >/dev/null 2>&1 || db_fail preflight bash_not_found
command -v git >/dev/null 2>&1 || db_fail preflight git_not_found
command -v ip >/dev/null 2>&1 || db_fail preflight ip_not_found
command -v realpath >/dev/null 2>&1 || db_fail preflight realpath_not_found
command -v setsid >/dev/null 2>&1 || db_fail preflight setsid_not_found
command -v ss >/dev/null 2>&1 || db_fail preflight ss_not_found
[ -x "$Z23_BIN" ] || db_fail preflight 'build/bin/z23 missing; run make -j2'
[ -x "$REPO_ROOT/build/bin/zclassic23" ] \
    || db_fail preflight 'build/bin/zclassic23 missing; run make -j2'
[ -x "$REPO_ROOT/build/bin/zcl-rpc" ] \
    || db_fail preflight 'build/bin/zcl-rpc missing; run make -j2'
db_pass binaries_present

uid=$(id -u) || db_fail control id_failed
CONTROL="/tmp/z23-devbox-$uid"
[ ! -L "$CONTROL" ] || db_fail control symlink_refused
if [ ! -d "$CONTROL" ]; then
    mkdir "$CONTROL" || db_fail control mkdir_failed
    chmod 700 "$CONTROL" || db_fail control chmod_failed
fi
owner=$(ls -nd "$CONTROL" | awk '{print $3}')
[ "$owner" = "$uid" ] || db_fail control wrong_owner
db_pass control_directory_safe

if [ -e "$CONTROL/state" ] || [ -e "$CONTROL/ready" ]; then
    [ ! -L "$CONTROL/state" ] || db_fail existing_instance state_symlink_refused
    [ ! -L "$CONTROL/ready" ] || db_fail existing_instance ready_symlink_refused
    [ -f "$CONTROL/state" ] \
        || db_fail existing_instance ready_without_state
    supervisor_pid=$(db_field SUPERVISOR_PID "$CONTROL/state")
    node_pid=$(db_field NODE_PID "$CONTROL/state")
    datadir=$(db_field DATADIR "$CONTROL/state")
    rpcport=$(db_field RPCPORT "$CONTROL/state")
    p2pport=$(db_field P2PPORT "$CONTROL/state")
    db_validate_target "$datadir" "$rpcport" "$p2pport" \
        || db_fail existing_instance unsafe_target
    if db_valid_pid "$supervisor_pid" "$CONTROL"; then
        [ -f "$CONTROL/ready" ] \
            || db_fail existing_instance supervisor_not_ready
        status=$(db_status "$datadir" "$rpcport") \
            || db_fail existing_instance onion_status_failed
        bootstrap_state=$(printf '%s' "$status" | db_status_field bootstrap_state)
        [ "$bootstrap_state" = ready ] \
            || db_fail existing_instance onion_not_ready
        local_onion=$(printf '%s' "$status" | db_status_field onion_address)
        db_valid_onion_address "$local_onion" \
            || db_fail existing_instance invalid_onion_address
        db_configure_fleet_peers "$CONTROL" "$REPO_ROOT" "$datadir" \
            "$rpcport" "$local_onion" \
            || db_fail existing_instance fleet_peer_configuration_failed
        db_pass existing_instance_ready
        cat "$CONTROL/ready"
        exit 0
    fi
    db_node_pid_matches "$node_pid" "$datadir" \
        && db_fail existing_instance orphan_node_alive
    rm -f "$CONTROL/state" "$CONTROL/ready" "$CONTROL/failure"
    db_pass stale_state_cleared
fi

if ! mkdir "$CONTROL/lock" 2>/dev/null; then
    db_fail control_lock initializer_already_running
fi
DB_LOCK_DIR="$CONTROL/lock"
rm -f "$CONTROL/failure" "$CONTROL/ready" "$CONTROL/state"

# Four-port quads stay below the helper's 39999 dead sink. A collision is a
# named refusal from isolated_node_env.sh; this script never hunts for a port
# whose accidental availability could hide faulty ownership.
port_base=$((39000 + (($$ % 190) * 4)))
nohup setsid bash "$SCRIPT_PATH" --supervisor "$CONTROL" "$port_base" \
    "$REPO_ROOT" \
    > "$CONTROL/supervisor.log" 2>&1 &
supervisor_pid=$!
db_pass supervisor_started

deadline=$(( $(date +%s) + 100 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -f "$CONTROL/ready" ] && [ -f "$CONTROL/state" ]; then
        db_pass initialization_complete
        rmdir "$DB_LOCK_DIR" || db_fail control_lock release_failed
        DB_LOCK_DIR=
        cat "$CONTROL/ready"
        exit 0
    fi
    if [ -f "$CONTROL/failure" ]; then
        failure=$(head -n 1 "$CONTROL/failure")
        wait "$supervisor_pid" 2>/dev/null || :
        db_fail supervisor "$failure"
    fi
    if ! kill -0 "$supervisor_pid" 2>/dev/null; then
        wait "$supervisor_pid" 2>/dev/null || :
        tail -n 20 "$CONTROL/supervisor.log" >&2
        db_fail supervisor exited_without_named_failure
    fi
    # Observation cadence only; the ready/failure files are the authority.
    sleep 1
done
kill -TERM "$supervisor_pid" 2>/dev/null || :
wait "$supervisor_pid" 2>/dev/null || :
db_fail supervisor initialization_timeout
