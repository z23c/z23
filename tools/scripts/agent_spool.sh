#!/bin/sh
# Poll one isolated devbox node for messages, or send one P2P message.

set -u
umask 077

spool_fail() {
    step=$1
    shift
    printf 'agent_spool: FAIL step=%s detail=%s\n' "$step" "$*" >&2
    exit 1
}

spool_pass() {
    printf 'agent_spool: PASS step=%s\n' "$1" >&2
}

spool_field() {
    key=$1
    file=$2
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

spool_json_quote() {
    awk '
        BEGIN { ORS=""; first=1; printf "\"" }
        {
            if (!first) printf "\\n"
            first=0
            gsub(/\\/, "\\\\")
            gsub(/"/, "\\\"")
            gsub(/\t/, "\\t")
            gsub(/\r/, "\\r")
            printf "%s", $0
        }
        END { print "\"" }
    '
}

spool_target() {
    if [ -n "${Z23_AGENT_DATADIR:-}" ] || [ -n "${Z23_AGENT_RPCPORT:-}" ]; then
        [ -n "${Z23_AGENT_DATADIR:-}" ] \
            || spool_fail target missing_Z23_AGENT_DATADIR
        [ -n "${Z23_AGENT_RPCPORT:-}" ] \
            || spool_fail target missing_Z23_AGENT_RPCPORT
        TARGET_DATADIR=$Z23_AGENT_DATADIR
        TARGET_RPCPORT=$Z23_AGENT_RPCPORT
    else
        uid=$(id -u) || spool_fail target id_failed
        control="/tmp/z23-devbox-$uid"
        [ ! -L "$control" ] || spool_fail target control_symlink_refused
        owner=$(ls -nd "$control" 2>/dev/null | awk '{print $3}')
        [ "$owner" = "$uid" ] || spool_fail target control_wrong_owner
        [ ! -L "$control/state" ] || spool_fail target state_symlink_refused
        [ ! -L "$control/ready" ] || spool_fail target ready_symlink_refused
        [ -f "$control/state" ] && [ -f "$control/ready" ] \
            || spool_fail target devbox_not_ready
        TARGET_DATADIR=$(spool_field DATADIR "$control/state")
        TARGET_RPCPORT=$(spool_field RPCPORT "$control/state")
    fi

    case $TARGET_DATADIR in
        /tmp/zcl23-*) ;;
        *) spool_fail target non_isolated_datadir ;;
    esac
    resolved=$(realpath "$TARGET_DATADIR" 2>/dev/null) \
        || spool_fail target datadir_unresolvable
    case $resolved in
        /tmp/zcl23-*) ;;
        *) spool_fail target resolved_datadir_not_isolated ;;
    esac
    uid=$(id -u) || spool_fail target id_failed
    owner=$(ls -nd "$resolved" 2>/dev/null | awk '{print $3}')
    [ "$owner" = "$uid" ] || spool_fail target datadir_wrong_owner
    case $TARGET_RPCPORT in ''|*[!0-9]*) spool_fail target invalid_rpcport ;; esac
    [ "$TARGET_RPCPORT" -ge 39000 ] && [ "$TARGET_RPCPORT" -le 39999 ] \
        || spool_fail target rpcport_outside_isolation_band
    spool_pass isolated_target
}

spool_native() {
    "$Z23_BIN" -datadir="$TARGET_DATADIR" -rpcport="$TARGET_RPCPORT" "$@"
}

spool_reply_ok() {
    printf '%s' "$1" | "$JSONQ" get ok 2>/dev/null | grep -qx true
}

spool_last_json() {
    tail -n 1
}

spool_watch() {
    stop=0
    trap 'stop=1' TERM INT
    ready_reported=0
    while [ "$stop" -eq 0 ]; do
        raw=$(spool_native app messaging inbox 2>/dev/null)
        rc=$?
        reply=$(printf '%s\n' "$raw" | spool_last_json)
        [ "$rc" -eq 0 ] || spool_fail inbox command_failed
        spool_reply_ok "$reply" || spool_fail inbox typed_command_refused
        count=$(printf '%s' "$reply" \
            | "$JSONQ" count data.messages 2>/dev/null)
        rc=$?
        [ "$rc" -eq 0 ] || spool_fail inbox invalid_message_array
        case $count in ''|*[!0-9]*) spool_fail inbox invalid_message_count ;; esac

        if [ "$ready_reported" -eq 0 ]; then
            spool_pass watch_ready
            ready_reported=1
        fi

        index=0
        while [ "$index" -lt "$count" ] && [ "$stop" -eq 0 ]; do
            read_state=$(printf '%s' "$reply" \
                | "$JSONQ" get "data.messages[$index].read" 2>/dev/null)
            rc=$?
            [ "$rc" -eq 0 ] || spool_fail inbox missing_read_state
            if [ "$read_state" = false ]; then
                msg_id=$(printf '%s' "$reply" \
                    | "$JSONQ" get "data.messages[$index].msg_id" 2>/dev/null)
                rc=$?
                [ "$rc" -eq 0 ] || spool_fail inbox missing_msg_id
                case $msg_id in
                    *[!0-9a-f]*|'') spool_fail inbox invalid_msg_id ;;
                esac
                [ "${#msg_id}" -eq 64 ] || spool_fail inbox invalid_msg_id_length

                tmp="$SPOOL_DIR/.${msg_id}.$$"
                if ! printf '%s' "$reply" \
                    | "$JSONQ" get "data.messages[$index].body" > "$tmp"; then
                    rm -f "$tmp"
                    spool_fail spool_write missing_message_body
                fi
                chmod 600 "$tmp" || {
                    rm -f "$tmp"
                    spool_fail spool_write chmod_failed
                }
                mv "$tmp" "$SPOOL_DIR/$msg_id.txt" \
                    || spool_fail spool_write atomic_publish_failed

                read_input="{\"msg_id\":\"$msg_id\"}"
                read_raw=$(spool_native app messaging read \
                    --input="$read_input" 2>/dev/null)
                read_rc=$?
                read_reply=$(printf '%s\n' "$read_raw" | spool_last_json)
                [ "$read_rc" -eq 0 ] || spool_fail mark_read command_failed
                spool_reply_ok "$read_reply" \
                    || spool_fail mark_read typed_command_refused
                spool_pass "message_${msg_id}_stored_and_read"
            elif [ "$read_state" != true ]; then
                spool_fail inbox invalid_read_state
            fi
            index=$((index + 1))
        done

        [ "$stop" -eq 0 ] || break
        # Poll cadence only. A failed command exits above; elapsed time never
        # turns a refusal into success or retries a failed operation.
        sleep 1
    done
    spool_pass watch_stopped
    return 0
}

spool_send() {
    peer_id=$1
    text=$2
    case $peer_id in ''|*[!0-9]*) spool_fail send invalid_peer_id ;; esac
    [ -n "$text" ] || spool_fail send empty_text
    text_json=$(printf '%s' "$text" | spool_json_quote) \
        || spool_fail send json_encoding_failed
    input="{\"channel\":\"p2p\",\"peer_id\":$peer_id,\"message\":$text_json,\"confirm\":true}"
    raw=$(spool_native app messaging send --input="$input" 2>/dev/null)
    rc=$?
    reply=$(printf '%s\n' "$raw" | spool_last_json)
    printf '%s\n' "$reply"
    [ "$rc" -eq 0 ] || spool_fail send command_failed
    spool_reply_ok "$reply" || spool_fail send typed_command_refused
    spool_pass send_committed
}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P) \
    || spool_fail locate_script cannot_resolve_script_directory
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd -P) \
    || spool_fail locate_repo cannot_resolve_repository_root
Z23_BIN="$REPO_ROOT/build/bin/z23"
JSONQ="$REPO_ROOT/build/bin/jsonq"
SPOOL_DIR=/tmp/z23-spool

command -v realpath >/dev/null 2>&1 || spool_fail preflight realpath_not_found
[ -x "$Z23_BIN" ] || spool_fail preflight 'build/bin/z23 missing; run make -j2'
[ -x "$JSONQ" ] || spool_fail preflight \
    'build/bin/jsonq missing; run make -j2 jsonq'

[ ! -L "$SPOOL_DIR" ] || spool_fail spool_directory symlink_refused
if [ ! -d "$SPOOL_DIR" ]; then
    mkdir "$SPOOL_DIR" || spool_fail spool_directory mkdir_failed
    chmod 700 "$SPOOL_DIR" || spool_fail spool_directory chmod_failed
fi
[ ! -L "$SPOOL_DIR" ] || spool_fail spool_directory symlink_refused
resolved_spool=$(realpath "$SPOOL_DIR" 2>/dev/null) \
    || spool_fail spool_directory unresolvable
[ "$resolved_spool" = "$SPOOL_DIR" ] \
    || spool_fail spool_directory resolved_path_mismatch
uid=$(id -u) || spool_fail spool_directory id_failed
owner=$(ls -nd "$SPOOL_DIR" | awk '{print $3}')
[ "$owner" = "$uid" ] || spool_fail spool_directory wrong_owner
spool_pass spool_directory_safe

spool_target

case ${1:-} in
    watch)
        [ "$#" -eq 1 ] || spool_fail usage 'watch takes no arguments'
        spool_watch
        ;;
    send)
        [ "$#" -eq 3 ] || spool_fail usage 'send requires peer_id and text'
        spool_send "$2" "$3"
        ;;
    *)
        spool_fail usage 'expected watch or send <peer_id> <text>'
        ;;
esac
