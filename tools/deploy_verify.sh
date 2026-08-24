#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Post-restart RPC health check for `make deploy`.
#
# The previous `make deploy` printed "Deployed." whenever systemd reported
# the unit active for >2s. That includes binaries that segfault on first
# RPC call. This script replaces that false-positive with a real probe:
# poll RPC every 2s and only succeed when the node answers with an integer
# height and the public-node hardening diagnostics are registered by the
# running daemon.
#
# The default deadline must absorb a full cold boot of a ~22 GB datadir:
# block-file scan + pprev repair + index reconcile routinely exceed two
# minutes, and a slow boot is not a failed deploy (120s false-FAILed a
# healthy deploy on 2026-06-10).
#
# Exit codes:
#   0  — RPC live, block count observed, diagnostic contract present
#   1  — RPC/diagnostic contract did not come up within the deadline
#   2  — identity inputs or canonical service binding are malformed
#
# Deployment acceptance always requires both environment variables:
#   ZCL_DEPLOY_EXPECT_SOURCE_ID=<64 lowercase hex>
#   ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256=<64 lowercase hex>
# Usage: ./tools/deploy_verify.sh [rpc_tool] [timeout_seconds]
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$SCRIPT_DIR/scripts/source_identity_lib.sh"  # zcl_json_first_string, zcl_is_sha256

RPC_TOOL="${1:-./build/bin/zclassic-cli}"
TIMEOUT="${2:-${ZCL_DEPLOY_VERIFY_TIMEOUT:-600}}"
RPC_CALL_TIMEOUT="${ZCL_DEPLOY_RPC_TIMEOUT:-20}"
INTERVAL=2
RPC_CONNECT="127.0.0.1"
DEPLOY_STAGE="${ZCL_DEPLOY_STAGE:-stable}"

case "$DEPLOY_STAGE" in
    stable|challenger|rollback) ;;
    *)
        echo "deploy_verify: FATAL — ZCL_DEPLOY_STAGE must be stable, challenger, or rollback" >&2
        exit 2
        ;;
esac

# Parse only the explicit -key=value argv form accepted by the service. Values
# containing whitespace are deliberately unsupported: guessing across a quoted
# systemd command line would make endpoint binding ambiguous.
exec_arg_values_from_text() {
    parse_key="$1"
    parse_text="$2"
    printf '%s\n' "$parse_text" |
        tr ' ' '\n' |
        sed -n "s/^-${parse_key}=//p"
}

exec_path_values_from_text() {
    printf '%s\n' "$1" |
        tr ' ' '\n' |
        sed -n 's/^path=//p'
}

exec_argv_values_from_text() {
    # `systemctl show -p ExecStart --value` renders one command as:
    #   { path=/launcher ; argv[]=/launcher /node <args> ; ... }
    # Canonical paths contain no whitespace (the same constraint already used
    # by exec_arg_values_from_text), so split only the argv[] segment.
    printf '%s\n' "$1" |
        sed -n 's/^.*argv\[\]=\([^;]*\);.*$/\1/p' |
        tr ' ' '\n' |
        awk 'NF { print }'
}

single_value_or_empty() {
    single_values="$1"
    single_count=$(printf '%s\n' "$single_values" |
        awk 'NF { count++ } END { print count + 0 }')
    [ "$single_count" -le 1 ] || return 1
    printf '%s\n' "$single_values" | awk 'NF { print; exit }'
}

select_bound_value() {
    bound_exec="$1"
    bound_proc="$2"
    bound_default="$3"
    if [ -n "$bound_exec" ] && [ -n "$bound_proc" ] &&
       [ "$bound_exec" != "$bound_proc" ]; then
        return 1
    fi
    if [ -n "$bound_proc" ]; then
        printf '%s\n' "$bound_proc"
    elif [ -n "$bound_exec" ]; then
        printf '%s\n' "$bound_exec"
    else
        printf '%s\n' "$bound_default"
    fi
}

proc_start_ticks() {
    sed 's/^[0-9][0-9]* ([^)]*) //' "/proc/$1/stat" 2>/dev/null |
        awk 'NF >= 20 { print $20; exit }'
}

service_pid_is_stable() {
    stable_pid=$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)
    [ "$stable_pid" = "$SERVICE_MAIN_PID" ] || return 1
    stable_ticks=$(proc_start_ticks "$SERVICE_MAIN_PID" || true)
    [ -n "$stable_ticks" ] && [ "$stable_ticks" = "$SERVICE_START_TICKS" ] || return 1
    stable_exe=$(readlink -f "/proc/$SERVICE_MAIN_PID/exe" 2>/dev/null || true)
    [ -n "$stable_exe" ] && [ "$stable_exe" = "$SERVICE_EXE" ]
}

proc_exec_arg_values() {
    proc_key="$1"
    tr '\000' '\n' < "/proc/$SERVICE_MAIN_PID/cmdline" |
        sed -n "s/^-${proc_key}=//p"
}

deploy_verify_selftest() {
    # Hostile inherited lane selectors must have no role in the result.
    ZCL_DATADIR="/attacker/datadir"
    ZCL_RPCPORT="1"
    ZCL_RPCCONNECT="attacker.invalid"
    fixture_exec='{ path=/canonical/deploy/zclassic23-launch.sh ; argv[]=/canonical/deploy/zclassic23-launch.sh /canonical/bin/zclassic23 -datadir=/canonical/data -rpcport=18232 ; }'
    fixture_datadirs=$(exec_arg_values_from_text datadir "$fixture_exec")
    fixture_ports=$(exec_arg_values_from_text rpcport "$fixture_exec")
    fixture_datadir=$(single_value_or_empty "$fixture_datadirs") || return 1
    fixture_port=$(single_value_or_empty "$fixture_ports") || return 1
    fixture_bound_datadir=$(select_bound_value "$fixture_datadir" "/canonical/data" "/default") || return 1
    fixture_bound_port=$(select_bound_value "$fixture_port" "18232" "9") || return 1
    [ "$fixture_bound_datadir" = "/canonical/data" ] || return 1
    [ "$fixture_bound_port" = "18232" ] || return 1
    [ "$RPC_CONNECT" = "127.0.0.1" ] || return 1
    if select_bound_value "/one" "/two" "/default" >/dev/null; then
        return 1
    fi
    duplicate_values=$(printf '/one\n/two\n')
    if single_value_or_empty "$duplicate_values" >/dev/null; then
        return 1
    fi
    fixture_paths=$(exec_path_values_from_text "$fixture_exec")
    [ "$(single_value_or_empty "$fixture_paths")" = "/canonical/deploy/zclassic23-launch.sh" ] || return 1
    fixture_argv=$(exec_argv_values_from_text "$fixture_exec")
    [ "$(printf '%s\n' "$fixture_argv" | sed -n '1p')" = "/canonical/deploy/zclassic23-launch.sh" ] || return 1
    [ "$(printf '%s\n' "$fixture_argv" | sed -n '2p')" = "/canonical/bin/zclassic23" ] || return 1
    fixture_direct='{ path=/canonical/bin/zclassic23 ; argv[]=/canonical/bin/zclassic23 -datadir=/canonical/data -rpcport=18232 ; }'
    fixture_direct_paths=$(exec_path_values_from_text "$fixture_direct")
    [ "$(single_value_or_empty "$fixture_direct_paths")" = "/canonical/bin/zclassic23" ] || return 1
    fixture_direct_argv=$(exec_argv_values_from_text "$fixture_direct")
    [ "$(printf '%s\n' "$fixture_direct_argv" | sed -n '1p')" = "/canonical/bin/zclassic23" ] || return 1
    [ "$(printf '%s\n' "$fixture_direct_argv" | sed -n '2p')" = "-datadir=/canonical/data" ] || return 1
    echo "deploy_verify selftest: PASS"
}

if [ "${ZCL_DEPLOY_VERIFY_SELFTEST:-0}" = "1" ]; then
    deploy_verify_selftest || {
        echo "deploy_verify selftest: FAIL" >&2
        exit 1
    }
    exit 0
fi

fatal_binding() {
    echo "deploy_verify: FATAL — $*" >&2
    exit 2
}

# Operational freshness is exact and SHA-1-independent. `make deploy` passes
# the baked source-tree SHA-256 plus the SHA-256 of the installed executable.
# build_commit remains optional GitHub trace metadata and is never compared.
EXPECT_SOURCE_ID="${ZCL_DEPLOY_EXPECT_SOURCE_ID:-}"
EXPECT_ARTIFACT_SHA256="${ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256:-}"

if ! zcl_is_sha256 "$EXPECT_SOURCE_ID"; then
    fatal_binding "ZCL_DEPLOY_EXPECT_SOURCE_ID must be 64 lowercase hex"
fi
if ! zcl_is_sha256 "$EXPECT_ARTIFACT_SHA256"; then
    fatal_binding "ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256 must be 64 lowercase hex"
fi

if [ ! -x "$RPC_TOOL" ]; then
    alt="./build/bin/zcl-rpc"
    if [ -x "$alt" ]; then
        RPC_TOOL="$alt"
    fi
fi

case "$(basename "$RPC_TOOL")" in
    zclassic-cli|zcl-rpc) ;;
    *) fatal_binding "RPC tool must be zclassic-cli or zcl-rpc so its endpoint can be forced" ;;
esac

command -v systemctl >/dev/null 2>&1 ||
    fatal_binding "systemctl is required to bind proof to the canonical service"
SERVICE_MAIN_PID=$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)
case "$SERVICE_MAIN_PID" in
    ''|*[!0-9]*|0) fatal_binding "canonical zclassic23 service has no MainPID" ;;
esac
[ -r "/proc/$SERVICE_MAIN_PID/cmdline" ] &&
[ -r "/proc/$SERVICE_MAIN_PID/stat" ] &&
[ -e "/proc/$SERVICE_MAIN_PID/exe" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID is not inspectable"

SERVICE_START_TICKS=$(proc_start_ticks "$SERVICE_MAIN_PID" || true)
[ -n "$SERVICE_START_TICKS" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID has no stable start identity"
SERVICE_EXE=$(readlink -f "/proc/$SERVICE_MAIN_PID/exe" 2>/dev/null || true)
[ -n "$SERVICE_EXE" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID executable cannot be resolved"
SERVICE_EXEC_TEXT=$(systemctl --user show zclassic23 -p ExecStart --value 2>/dev/null || true)
[ -n "$SERVICE_EXEC_TEXT" ] || fatal_binding "canonical service ExecStart is unavailable"
SERVICE_EXEC_PATH_VALUES=$(exec_path_values_from_text "$SERVICE_EXEC_TEXT")
SERVICE_EXEC_PATH=$(single_value_or_empty "$SERVICE_EXEC_PATH_VALUES") ||
    fatal_binding "canonical service ExecStart has an ambiguous executable path"
case "$SERVICE_EXEC_PATH" in
    /*) ;;
    *) fatal_binding "canonical service ExecStart executable path is not absolute" ;;
esac
SERVICE_LAUNCHER_EXE=$(readlink -f "$SERVICE_EXEC_PATH" 2>/dev/null || true)
[ -n "$SERVICE_LAUNCHER_EXE" ] ||
    fatal_binding "canonical service launcher cannot be resolved"
SERVICE_ARGV_VALUES=$(exec_argv_values_from_text "$SERVICE_EXEC_TEXT")
SERVICE_ARGV0=$(printf '%s\n' "$SERVICE_ARGV_VALUES" | sed -n '1p')
SERVICE_NODE_ARG=$(printf '%s\n' "$SERVICE_ARGV_VALUES" | sed -n '2p')
[ -n "$SERVICE_ARGV0" ] ||
    fatal_binding "canonical service ExecStart must name an executable argv"
case "$SERVICE_ARGV0" in
    /*) ;;
    *) fatal_binding "canonical service executable argv is not absolute" ;;
esac
SERVICE_ARGV0_EXE=$(readlink -f "$SERVICE_ARGV0" 2>/dev/null || true)
[ -n "$SERVICE_ARGV0_EXE" ] &&
[ "$SERVICE_ARGV0_EXE" = "$SERVICE_LAUNCHER_EXE" ] ||
    fatal_binding "canonical service path and executable argv disagree"

# Accept both canonical unit forms while preserving an exact executable bind:
#
#   direct:   ExecStart=/absolute/zclassic23 <flags>
#   launcher: ExecStart=/absolute/launcher /absolute/zclassic23 <flags>
#
# In direct mode argv[1] is normally the first flag, not another executable.
# A launcher is only accepted when its explicit node argument resolves to the
# executable owned by the stable MainPID captured above.
if [ "$SERVICE_LAUNCHER_EXE" = "$SERVICE_EXE" ]; then
    SERVICE_NODE_EXE="$SERVICE_LAUNCHER_EXE"
else
    [ -n "$SERVICE_NODE_ARG" ] ||
        fatal_binding "canonical launcher must name the node binary"
    case "$SERVICE_NODE_ARG" in
        /*) ;;
        *) fatal_binding "canonical launcher node binary argv is not absolute" ;;
    esac
    SERVICE_NODE_EXE=$(readlink -f "$SERVICE_NODE_ARG" 2>/dev/null || true)
    [ -n "$SERVICE_NODE_EXE" ] && [ "$SERVICE_NODE_EXE" = "$SERVICE_EXE" ] ||
        fatal_binding "canonical MainPID executable does not match launcher node binary"
fi

EXEC_DATADIR_VALUES=$(exec_arg_values_from_text datadir "$SERVICE_EXEC_TEXT")
EXEC_RPCPORT_VALUES=$(exec_arg_values_from_text rpcport "$SERVICE_EXEC_TEXT")
PROC_DATADIR_VALUES=$(proc_exec_arg_values datadir)
PROC_RPCPORT_VALUES=$(proc_exec_arg_values rpcport)
EXEC_DATADIR=$(single_value_or_empty "$EXEC_DATADIR_VALUES") ||
    fatal_binding "canonical service ExecStart has duplicate -datadir values"
EXEC_RPCPORT=$(single_value_or_empty "$EXEC_RPCPORT_VALUES") ||
    fatal_binding "canonical service ExecStart has duplicate -rpcport values"
PROC_DATADIR=$(single_value_or_empty "$PROC_DATADIR_VALUES") ||
    fatal_binding "canonical MainPID has duplicate -datadir values"
PROC_RPCPORT=$(single_value_or_empty "$PROC_RPCPORT_VALUES") ||
    fatal_binding "canonical MainPID has duplicate -rpcport values"
[ -n "$EXEC_DATADIR" ] && [ -n "$EXEC_RPCPORT" ] ||
    fatal_binding "canonical service ExecStart must set -datadir and -rpcport"
[ -n "$PROC_DATADIR" ] && [ -n "$PROC_RPCPORT" ] ||
    fatal_binding "canonical MainPID argv must set -datadir and -rpcport"
RPC_DATADIR=$(select_bound_value "$EXEC_DATADIR" "$PROC_DATADIR" "") ||
    fatal_binding "canonical ExecStart/MainPID -datadir values disagree"
RPCPORT=$(select_bound_value "$EXEC_RPCPORT" "$PROC_RPCPORT" "") ||
    fatal_binding "canonical ExecStart/MainPID -rpcport values disagree"
case "$RPC_DATADIR" in
    /*) ;;
    *) fatal_binding "canonical RPC datadir is not absolute" ;;
esac
case "$RPCPORT" in
    ''|*[!0-9]*) fatal_binding "canonical RPC port is not numeric" ;;
esac
[ "$RPCPORT" -ge 1 ] && [ "$RPCPORT" -le 65535 ] ||
    fatal_binding "canonical RPC port is outside 1..65535"
service_pid_is_stable || fatal_binding "canonical MainPID changed during endpoint capture"

# Never permit an inherited shell lane to redirect any part of this proof.
unset ZCL_DATADIR ZCL_RPCPORT ZCL_RPCCONNECT

rpc_exec() {
    rc=0
    if command -v timeout >/dev/null 2>&1; then
        timeout "${RPC_CALL_TIMEOUT}s" "$@" || rc=$?
        if [ "$rc" -eq 124 ]; then
            echo "rpc timed out after ${RPC_CALL_TIMEOUT}s: $*" >&2
        fi
    else
        "$@" || rc=$?
    fi
    return "$rc"
}

rpc_call() {
    name=$(basename "$RPC_TOOL")
    case "$name" in
        zclassic-cli)
            rpc_exec "$RPC_TOOL" "-datadir=$RPC_DATADIR" "-rpcport=$RPCPORT" \
                "-rpcconnect=$RPC_CONNECT" "$@"
            ;;
        zcl-rpc)
            rpc_exec env "ZCL_DATADIR=$RPC_DATADIR" "ZCL_RPCPORT=$RPCPORT" \
                "ZCL_RPCCONNECT=$RPC_CONNECT" "$RPC_TOOL" "$@"
            ;;
        *) return 2 ;;
    esac
}

deadline=$(( $(date +%s) + TIMEOUT ))
attempt=0
last_err=""
chain_advance_verified=0
chain_evidence_verified=0
network_verified=0
peer_lifecycle_verified=0
legacy_mirror_verified=0

json_has_key() {
    printf '%s\n' "$1" | grep -q "\"$2\"[[:space:]]*:"
}

json_not_has_key() {
    ! json_has_key "$1" "$2"
}

json_key_is_true() {
    printf '%s\n' "$1" | grep -q "\"$2\"[[:space:]]*:[[:space:]]*true"
}

json_key_is_string() {
    printf '%s\n' "$1" |
        grep -q "\"$2\"[[:space:]]*:[[:space:]]*\"$3\""
}

json_top_key_is_true() {
    json_key_is_true "$1" "$2"
}

json_top_has_key() {
    json_has_key "$1" "$2"
}

json_top_key_is_string() {
    json_key_is_string "$1" "$2" "$3"
}

json_health_gap_at_most_one() {
    printf '%s\n' "$1" |
        grep -q '"gap"[[:space:]]*:[[:space:]]*[01]\([^0-9]\|$\)'
}

json_rpc_result() {
    printf '%s\n' "$1"
}

extract_health_height() {
    printf '%s\n' "$1" |
        tr ',' '\n' |
        grep -E '"(log_head|projection_height|local_height)"[[:space:]]*:' |
        grep -oE ':[[:space:]]*[0-9]+' |
        grep -oE '[0-9]+' |
        awk '$1 > 0 { print; exit }'
}

json_key_is_int() {
    printf '%s\n' "$1" |
        grep -q "\"$2\"[[:space:]]*:[[:space:]]*$3\\([^0-9]\\|$\\)"
}

extract_height() {
    height=$(printf '%s' "$1" |
        grep -oE '"result"[[:space:]]*:[[:space:]]*[0-9]+' |
        grep -oE '[0-9]+' | head -1)
    if [ -z "$height" ]; then
        plain=$(printf '%s' "$1" | tr -d '[:space:]')
        case "$plain" in
            [0-9]*) height="$plain" ;;
        esac
    fi
    printf '%s' "$height"
}

extract_build_commit() {
    printf '%s\n' "$1" |
        grep -oE '"build_commit"[[:space:]]*:[[:space:]]*"[^"]*"' |
        head -1 |
        sed -E 's/.*"build_commit"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
}

extract_source_id_sha256() {
    zcl_json_first_string "$1" source_id_sha256
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed -E 's/^.*= //'
    else
        return 1
    fi
}

mainpid_socket_inodes() {
    for socket_fd in "/proc/$SERVICE_MAIN_PID/fd/"*; do
        socket_target=$(readlink "$socket_fd" 2>/dev/null || true)
        case "$socket_target" in
            socket:\[*\])
                printf '%s\n' "$socket_target" |
                    sed -n 's/^socket:\[\([0-9][0-9]*\)\]$/\1/p'
                ;;
        esac
    done
}

mainpid_rpc_listener_inodes() {
    listener_port_hex=$(printf '%04X' "$RPCPORT")
    for socket_table in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$socket_table" ] || continue
        awk -v port="$listener_port_hex" '
            NR > 1 {
                split($2, local, ":")
                if (toupper(local[2]) == port && $4 == "0A")
                    print $10
            }
        ' "$socket_table"
    done
}

mainpid_owns_rpc_listener() {
    owned_inodes=$(mainpid_socket_inodes || true)
    listener_inodes=$(mainpid_rpc_listener_inodes || true)
    [ -n "$owned_inodes" ] && [ -n "$listener_inodes" ] || return 1
    for listener_inode in $listener_inodes; do
        if printf '%s\n' "$owned_inodes" | grep -Fxq "$listener_inode"; then
            return 0
        fi
    done
    return 1
}

running_service_artifact_sha256() {
    service_pid_is_stable || return 1
    sha256_file "/proc/$SERVICE_MAIN_PID/exe"
}

pre_rpc_boot_status() {
    service_pid_is_stable || return 1
    boot_status_out=$("$SERVICE_EXE" core node bootstatus \
        "-datadir=$RPC_DATADIR" 2>/dev/null || true)
    service_pid_is_stable || return 1
    printf '%s\n' "$boot_status_out"
}
rpc_dumpstate() {
    component="$1"
    key="${2:-}"
    # zcl-rpc wraps remaining argv directly into a JSON params array, so its
    # string argument needs JSON quotes. zclassic-cli performs its own string
    # encoding and MUST receive the bare subsystem name. Never retry one
    # client's syntax through the other: that overwrites an honest timeout or
    # partial response with a deterministic "unknown subsystem '\"name\"'".
    case "$(basename "$RPC_TOOL")" in
        zcl-rpc)
            if [ -n "$key" ]; then
                out=$(rpc_call dumpstate "\"$component\"" "\"$key\"" 2>&1 || true)
            else
                out=$(rpc_call dumpstate "\"$component\"" 2>&1 || true)
            fi
            ;;
        *)
            if [ -n "$key" ]; then
                out=$(rpc_call dumpstate "$component" "$key" 2>&1 || true)
            else
                out=$(rpc_call dumpstate "$component" 2>&1 || true)
            fi
            ;;
    esac
    out=$(json_rpc_result "$out")
    printf '%s\n' "$out"
}

verify_contract() {
    height="$1"

    service_pid_is_stable ||
        { last_err="canonical zclassic23 MainPID changed during RPC proof"; return 1; }
    mainpid_owns_rpc_listener ||
        { last_err="canonical MainPID does not own RPC listener port $RPCPORT"; return 1; }

    # Each expensive readiness class is sticky for this exact MainPID.  A
    # booting node can legitimately make a later projection probe miss its
    # deadline; restarting the whole sequence in that case used to enqueue the
    # already-proven database-heavy probes again and again.  The stable PID +
    # start-ticks checks above and below keep these receipts process-bound.
    if [ "$chain_advance_verified" -eq 0 ]; then
        ca=$(rpc_dumpstate chain_advance_coordinator initialized)
        json_key_is_true "$ca" initialized ||
            { last_err="chain_advance_coordinator not initialized: $ca"; return 1; }
        json_key_is_true "$ca" has_connman ||
            { last_err="chain_advance_coordinator missing connman: $ca"; return 1; }
        json_key_is_true "$ca" has_main_state ||
            { last_err="chain_advance_coordinator missing main_state: $ca"; return 1; }
        json_key_is_true "$ca" has_node_db ||
            { last_err="chain_advance_coordinator missing node_db: $ca"; return 1; }
        json_key_is_string "$ca" authority local_consensus_validation ||
            { last_err="chain_advance authority contract missing: $ca"; return 1; }
        json_has_key "$ca" selected_source ||
            { last_err="chain_advance selected_source missing: $ca"; return 1; }
        json_has_key "$ca" candidate_source ||
            { last_err="chain_advance candidate_source missing: $ca"; return 1; }
        json_has_key "$ca" sources ||
            { last_err="chain_advance sources missing: $ca"; return 1; }
        chain_advance_verified=1
    fi

    if [ "$chain_evidence_verified" -eq 0 ]; then
        evidence=$(rpc_dumpstate chain_evidence health_reason)
        json_has_key "$evidence" health_reason ||
            { last_err="chain_evidence diagnostics missing health_reason: $evidence"; return 1; }
        printf '%s\n' "$evidence" | grep -q '"health_reason"[[:space:]]*:[[:space:]]*"chain_evidence_gap"' &&
            { last_err="chain_evidence reports generic gap: $evidence"; return 1; }
        printf '%s\n' "$evidence" | grep -q '"health_reason"[[:space:]]*:[[:space:]]*"[^"]' &&
            { last_err="chain_evidence is frozen/degraded: $evidence"; return 1; }
        chain_evidence_verified=1
    fi

    if [ "$network_verified" -eq 0 ]; then
        net=$(rpc_call getnetworkinfo 2>&1 || true)
        net=$(json_rpc_result "$net")
        for key in advertised_subver advertised_services inbound_connections outbound_connections handshaked_connections \
                   inbound_handshake_seen remote_handshake_seen legacy_compatible_peers legacy_magicbean_peers magicbean_peers \
                   zclassic23_peers zclassic_c23_peers peer_lifecycle; do
            json_has_key "$net" "$key" ||
                { last_err="getnetworkinfo missing $key: $net"; return 1; }
        done
        printf '%s\n' "$net" | grep -q '"advertised_subver"[[:space:]]*:[[:space:]]*"/ZClassic23:0\.1\.0/"' ||
            { last_err="node is not advertising native ZClassic23 subver: $net"; return 1; }
        network_verified=1
    fi

    if [ "$peer_lifecycle_verified" -eq 0 ]; then
        peer=$(rpc_dumpstate peer_lifecycle summary)
        json_has_key "$peer" summary ||
            { last_err="peer_lifecycle summary missing: $peer"; return 1; }
        json_has_key "$peer" sources ||
            { last_err="peer_lifecycle sources missing: $peer"; return 1; }
        json_has_key "$peer" legacy_magicbean_handshakes ||
            { last_err="peer_lifecycle missing legacy handshake canary: $peer"; return 1; }
        json_has_key "$peer" legacy_compatible_handshakes ||
            { last_err="peer_lifecycle missing legacy handshake alias: $peer"; return 1; }
        json_has_key "$peer" zclassic23_handshakes ||
            { last_err="peer_lifecycle missing zclassic23 handshake canary: $peer"; return 1; }
        json_has_key "$peer" zclassic_c23_handshakes ||
            { last_err="peer_lifecycle missing zclassic_c23 compatibility canary: $peer"; return 1; }
        json_has_key "$peer" pre_handshake_disconnects ||
            { last_err="peer_lifecycle missing pre-handshake disconnect counter: $peer"; return 1; }
        if ! printf '%s\n' "$peer" | grep -q '"legacy_magicbean_handshakes"[[:space:]]*:[[:space:]]*[1-9]'; then
            printf '%s\n' "$peer" | grep -q '"attempted"[[:space:]]*:[[:space:]]*0' ||
                { last_err="no legacy MagicBean handshake observed and peers were reachable: $peer"; return 1; }
        fi
        peer_lifecycle_verified=1
    fi

    if [ "$legacy_mirror_verified" -eq 0 ]; then
        mirror=$(rpc_dumpstate legacy_mirror consensus_authority)
        json_has_key "$mirror" consensus_authority ||
            { last_err="legacy_mirror authority missing: $mirror"; return 1; }
        json_key_is_string "$mirror" consensus_authority local_consensus_validation ||
            { last_err="legacy_mirror must not claim zclassicd authority: $mirror"; return 1; }
        json_not_has_key "$mirror" mirror_authorization_enabled ||
            { last_err="legacy_mirror exposes deleted mirror_authorization_enabled: $mirror"; return 1; }
        json_not_has_key "$mirror" mirror_consensus_authority ||
            { last_err="legacy_mirror exposes deleted mirror_consensus_authority: $mirror"; return 1; }
        json_has_key "$mirror" candidate_source ||
            { last_err="legacy_mirror candidate_source missing: $mirror"; return 1; }
        json_key_is_string "$mirror" candidate_source legacy_advisory ||
            { last_err="legacy_mirror must expose advisory candidate source: $mirror"; return 1; }
        json_has_key "$mirror" legacy_advisory_gated_by_native_retries ||
            { last_err="legacy_mirror advisory/native retry gate missing: $mirror"; return 1; }
        json_has_key "$mirror" blockers_total ||
            { last_err="legacy_mirror blockers_total missing: $mirror"; return 1; }
        json_has_key "$mirror" stalls_total ||
            { last_err="legacy_mirror stalls_total missing: $mirror"; return 1; }
        json_has_key "$mirror" unsafe_overrides_total ||
            { last_err="legacy_mirror unsafe_overrides_total missing: $mirror"; return 1; }
        json_key_is_int "$mirror" unsafe_overrides_total 0 ||
            { last_err="legacy_mirror unsafe overrides are unhealthy: $mirror"; return 1; }
        json_has_key "$mirror" last_override_safe ||
            { last_err="legacy_mirror last_override_safe missing: $mirror"; return 1; }
        json_has_key "$mirror" last_override_scope ||
            { last_err="legacy_mirror last_override_scope missing: $mirror"; return 1; }
        legacy_mirror_verified=1
    fi

    health=$(rpc_call healthcheck 2>&1 || true)
    health=$(json_rpc_result "$health")
    json_top_key_is_string "$health" consensus_authority local_consensus_validation ||
        { last_err="healthcheck authority contract missing: $health"; return 1; }
    json_not_has_key "$health" mirror_authorization_enabled ||
        { last_err="healthcheck exposes deleted mirror_authorization_enabled: $health"; return 1; }
    json_not_has_key "$health" mirror_consensus_authority ||
        { last_err="healthcheck exposes deleted mirror_consensus_authority: $health"; return 1; }
    json_top_has_key "$health" candidate_source ||
        { last_err="healthcheck candidate_source missing: $health"; return 1; }
    json_top_has_key "$health" candidate_trust ||
        { last_err="healthcheck candidate_trust missing: $health"; return 1; }
    if [ "$DEPLOY_STAGE" = "stable" ]; then
        json_top_key_is_true "$health" healthy ||
            { last_err="healthcheck is not healthy: $health"; return 1; }
    else
        # Challenger staging and rollback recovery are deliberately weaker
        # than stable promotion: they prove exact bytes, process identity,
        # RPC/P2P readiness, evidence consistency, and a <=1 tip gap.  Neither
        # claims PROVEN or baseline equivalence merely because the process came
        # back; named health blockers remain visible for owner review.
        json_top_has_key "$health" healthy ||
            { last_err="challenger healthcheck omitted healthy verdict: $health"; return 1; }
        json_health_gap_at_most_one "$health" ||
            { last_err="challenger tip gap is not <=1: $health"; return 1; }
    fi
    printf '%s\n' "$health" | grep -q '"degraded_reason"[[:space:]]*:[[:space:]]*"chain_evidence_gap"' &&
        { last_err="healthcheck reports generic evidence gap: $health"; return 1; }
    health_height=$(extract_health_height "$health" || true)
    if [ -n "$health_height" ]; then
        height="$health_height"
    fi
    case "$height" in
        ''|0)
            last_err="healthcheck is healthy but no positive verified height was available: $health"
            return 1
            ;;
    esac

    # Staleness guard: require both the exact SHA-256 source identity reported
    # by RPC and the exact SHA-256 of /proc/<MainPID>/exe. The second check
    # distinguishes two compiler outputs built from the same source bytes.
    # Git commit metadata is deliberately excluded from both decisions.
    running_source_id=$(extract_source_id_sha256 "$health" || true)
    running_commit=$(extract_build_commit "$health" || true)
    if ! zcl_is_sha256 "$running_source_id"; then
        last_err="STALE DEPLOY: running daemon exposes no valid source_id_sha256"
        return 1
    fi
    if [ "$running_source_id" != "$EXPECT_SOURCE_ID" ]; then
        last_err="STALE DEPLOY: running source_id_sha256 '$running_source_id' != expected '$EXPECT_SOURCE_ID'"
        return 1
    fi

    service_pid_is_stable ||
        { last_err="canonical zclassic23 MainPID changed after RPC identity proof"; return 1; }
    mainpid_owns_rpc_listener ||
        { last_err="canonical MainPID lost ownership of RPC listener port $RPCPORT"; return 1; }
    running_artifact_sha256=$(running_service_artifact_sha256 || true)
    if ! zcl_is_sha256 "$running_artifact_sha256"; then
        last_err="STALE DEPLOY: could not hash the running zclassic23 MainPID executable"
        return 1
    fi
    if [ "$running_artifact_sha256" != "$EXPECT_ARTIFACT_SHA256" ]; then
        last_err="STALE DEPLOY: running artifact SHA-256 '$running_artifact_sha256' != expected '$EXPECT_ARTIFACT_SHA256'"
        return 1
    fi

    if [ "$DEPLOY_STAGE" = "challenger" ]; then
        echo "CHALLENGER_ACTIVE (unqualified): RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready; stable health promotion not claimed."
    elif [ "$DEPLOY_STAGE" = "rollback" ]; then
        echo "ROLLBACK_VERIFIED: prior RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready."
    else
        echo "Deployed + RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready."
    fi
    return 0
}

while [ "$(date +%s)" -lt "$deadline" ]; do
    attempt=$((attempt + 1))
    if out=$(rpc_call getblockcount 2>&1); then
        # Accept either a plain integer (zclassic-cli) or a JSON
        # envelope with "result":<integer> (build/bin/zcl-rpc). Any other
        # output keeps the loop polling.
        height=$(extract_height "$out")
        if [ -n "$height" ] && verify_contract "$height"; then
            exit 0
        fi
        if [ -z "$height" ]; then
            last_err="$out"
        fi
    else
        last_err="$out"
    fi
    sleep "$INTERVAL"
done

echo "DEPLOY FAILED: RPC/diagnostic contract did not become ready within ${TIMEOUT}s (attempts=$attempt)"
if [ -n "$last_err" ]; then
    echo "last error: $last_err"
fi
boot_status=$(pre_rpc_boot_status || true)
if [ -n "$boot_status" ]; then
    echo "typed boot status: $boot_status"
else
    echo "typed boot status: unavailable (captured service process changed)"
fi
exit 1
