#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Guard the long-running canonical node from accidental deploy restarts.
# Prefer the C-native zcl.agent_deploy_guard.v1 contract exposed by the
# running daemon; fall back to the systemd ExecStart lane flag only for older
# binaries that do not expose the native guard yet.

set -euo pipefail

ACTION="${1:-canonical-deploy}"
UNIT="${ZCL_DEPLOY_GUARD_UNIT:-z23-node}"
RPC_TIMEOUT="${ZCL_DEPLOY_GUARD_RPC_TIMEOUT:-5}"
DEFAULT_DATADIR="${ZCL_DATADIR:-$HOME/.zclassic-c23}"
DEFAULT_RPCPORT="${ZCL_RPCPORT:-18232}"

log() {
    printf 'deploy_guard: %s\n' "$*"
}

fail() {
    printf 'deploy_guard: REFUSE: %s\n' "$*" >&2
    printf 'deploy_guard: set ZCL_DEPLOY_ALLOW_CANONICAL=1 only for an intentional canonical restart window\n' >&2
    exit 1
}

allow() {
    log "allow: $*"
    exit 0
}

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

systemd_show() {
    local prop="$1"
    if [ -n "${ZCL_DEPLOY_GUARD_SYSTEMD_ACTIVE:-}" ] &&
       [ "$prop" = "ActiveState" ]; then
        printf '%s\n' "$ZCL_DEPLOY_GUARD_SYSTEMD_ACTIVE"
        return 0
    fi
    if [ -n "${ZCL_DEPLOY_GUARD_SYSTEMD_EXECSTART:-}" ] &&
       [ "$prop" = "ExecStart" ]; then
        printf '%s\n' "$ZCL_DEPLOY_GUARD_SYSTEMD_EXECSTART"
        return 0
    fi
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user show "$UNIT" -p "$prop" --value 2>/dev/null || true
}

exec_arg_value() {
    local cmdline="$1" key="$2"
    printf '%s\n' "$cmdline" |
        tr ' ' '\n' |
        sed -n "s/^${key}=//p" |
        head -1
}

lane_is_canonical() {
    case "${1:-}" in
        canonical|live|main) return 0 ;;
        *) return 1 ;;
    esac
}

select_rpc_tool() {
    if [ -n "${ZCL_DEPLOY_GUARD_RPC_TOOL:-}" ]; then
        printf '%s\n' "$ZCL_DEPLOY_GUARD_RPC_TOOL"
        return 0
    fi
    if [ -x ./build/bin/zclassic23 ]; then
        printf '%s\n' ./build/bin/zclassic23
        return 0
    fi
    if command -v zclassic23 >/dev/null 2>&1; then
        command -v zclassic23
        return 0
    fi
    if [ -x ./build/bin/zclassic-cli ]; then
        printf '%s\n' ./build/bin/zclassic-cli
        return 0
    fi
    return 1
}

service_exec_start() {
    systemd_show ExecStart || true
}

service_active_state() {
    systemd_show ActiveState || true
}

service_exec_datadir() {
    local cmdline="$1" datadir
    datadir="$(exec_arg_value "$cmdline" "-datadir")"
    printf '%s\n' "${datadir:-$DEFAULT_DATADIR}"
}

service_exec_rpcport() {
    local cmdline="$1" rpcport
    rpcport="$(exec_arg_value "$cmdline" "-rpcport")"
    printf '%s\n' "${rpcport:-$DEFAULT_RPCPORT}"
}

json_string_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" |
        sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" |
        head -1
}

json_bool_true() {
    local body="$1" key="$2"
    printf '%s\n' "$body" |
        grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*true"
}

read_native_guard_json() {
    if [ -n "${ZCL_DEPLOY_GUARD_NATIVE_JSON:-}" ]; then
        printf '%s\n' "$ZCL_DEPLOY_GUARD_NATIVE_JSON"
        return 0
    fi

    local tool execstart datadir rpcport raw
    tool="$(select_rpc_tool)" || return 1
    [ -x "$tool" ] || command -v "$tool" >/dev/null 2>&1 || return 1
    execstart="$(service_exec_start)"
    datadir="$(service_exec_datadir "$execstart")"
    rpcport="$(service_exec_rpcport "$execstart")"
    if command -v timeout >/dev/null 2>&1; then
        raw="$(timeout "${RPC_TIMEOUT}s" "$tool" \
            "-datadir=$datadir" "-rpcport=$rpcport" \
            agentdeployguard "$ACTION" 2>/dev/null || true)"
    else
        raw="$("$tool" "-datadir=$datadir" "-rpcport=$rpcport" \
            agentdeployguard "$ACTION" 2>/dev/null || true)"
    fi
    [ -n "$raw" ] || return 1
    printf '%s\n' "$raw"
}

guard_from_native_json() {
    local body="$1"
    printf '%s\n' "$body" | grep -q '"zcl.agent_deploy_guard.v1"' ||
        return 2

    local lane reason safe_action guard_env
    lane="$(json_string_field "$body" "lane")"
    reason="$(json_string_field "$body" "reason")"
    safe_action="$(json_string_field "$body" "safe_default_action")"
    guard_env="$(json_string_field "$body" "guard_env")"

    if json_bool_true "$body" "allowed"; then
        allow "native agentdeployguard permits action=$ACTION lane=${lane:-unknown}"
    fi

    fail "native agentdeployguard blocks action=$ACTION lane=${lane:-unknown} reason=${reason:-unknown} guard_env=${guard_env:-unknown} safe_default_action=${safe_action:-unknown}"
}

guard_from_systemd() {
    local active execstart lane
    active="$(service_active_state)"
    execstart="$(service_exec_start)"
    lane="$(exec_arg_value "$execstart" "-operator-lane")"

    if [ "$active" = "active" ]; then
        if lane_is_canonical "$lane"; then
            fail "active systemd unit $UNIT is operator-lane=${lane}"
        fi
        if [ -z "$lane" ]; then
            fail "active systemd unit $UNIT has no declared operator lane"
        fi
        allow "active systemd unit $UNIT is noncanonical lane=$lane"
    fi

    allow "no active canonical systemd lane detected for $UNIT"
}

selftest_case_pass() {
    local name="$1"
    shift
    if ! env -u ZCL_DEPLOY_GUARD_SELFTEST "$@" "$0" canonical-deploy >/dev/null 2>&1; then
        printf 'deploy_guard selftest FAIL pass-case: %s\n' "$name" >&2
        exit 1
    fi
}

selftest_case_fail() {
    local name="$1"
    shift
    if env -u ZCL_DEPLOY_GUARD_SELFTEST "$@" "$0" canonical-deploy >/dev/null 2>&1; then
        printf 'deploy_guard selftest FAIL fail-case: %s\n' "$name" >&2
        exit 1
    fi
}

selftest() {
    local canonical_json dev_json
    canonical_json='{"schema":"zcl.agent_deploy_guard.v1","action":"canonical-deploy","allowed":false,"decision":"refuse","reason":"operator_confirmation_required","lane":"canonical","guard_env":"ZCL_DEPLOY_ALLOW_CANONICAL","safe_default_action":"observe_only_or_use_dev_lane"}'
    dev_json='{"schema":"zcl.agent_deploy_guard.v1","action":"canonical-deploy","allowed":true,"decision":"allow","reason":"deployment_safety_allows_action","lane":"dev","guard_env":"","safe_default_action":"deploy_dev_lane"}'

    selftest_case_fail "native canonical blocks" \
        ZCL_DEPLOY_GUARD_NATIVE_JSON="$canonical_json"
    selftest_case_pass "native dev allows" \
        ZCL_DEPLOY_GUARD_NATIVE_JSON="$dev_json"
    selftest_case_pass "explicit canonical override allows" \
        ZCL_DEPLOY_GUARD_NATIVE_JSON="$canonical_json" \
        ZCL_DEPLOY_ALLOW_CANONICAL=1
    selftest_case_fail "active canonical systemd fallback blocks" \
        ZCL_DEPLOY_GUARD_NATIVE_JSON= \
        ZCL_DEPLOY_GUARD_RPC_TOOL=/nonexistent-zclassic23 \
        ZCL_DEPLOY_GUARD_SYSTEMD_ACTIVE=active \
        ZCL_DEPLOY_GUARD_SYSTEMD_EXECSTART='path=/x/zclassic23 ; argv[]=/x/zclassic23 -datadir=/tmp/z -operator-lane=canonical -rpcport=18232'
    selftest_case_pass "inactive canonical systemd fallback allows" \
        ZCL_DEPLOY_GUARD_NATIVE_JSON= \
        ZCL_DEPLOY_GUARD_RPC_TOOL=/nonexistent-zclassic23 \
        ZCL_DEPLOY_GUARD_SYSTEMD_ACTIVE=inactive \
        ZCL_DEPLOY_GUARD_SYSTEMD_EXECSTART='path=/x/zclassic23 ; argv[]=/x/zclassic23 -datadir=/tmp/z -operator-lane=canonical -rpcport=18232'

    log "selftest OK"
}

main() {
    case "$ACTION" in
        canonical-deploy|canonical-restart|deploy|restart|deploy-dev|dev-deploy|restart-dev|dev-restart) ;;
        -h|--help)
            cat <<'USAGE'
usage: tools/deploy_guard.sh [canonical-deploy|canonical-restart|deploy|restart|deploy-dev|restart-dev]

Blocks accidental restarts of an active canonical zclassic23 lane unless
ZCL_DEPLOY_ALLOW_CANONICAL=1 is set for an intentional restart window.
Uses native C JSON contract zcl.agent_deploy_guard.v1 when available.
USAGE
            exit 0
            ;;
        *)
            fail "unknown action: $ACTION"
            ;;
    esac

    if is_true "${ZCL_DEPLOY_GUARD_SELFTEST:-0}"; then
        selftest
        exit 0
    fi

    if is_true "${ZCL_DEPLOY_ALLOW_CANONICAL:-0}"; then
        allow "ZCL_DEPLOY_ALLOW_CANONICAL=1 explicitly permits action=$ACTION"
    fi

    local guard_json
    guard_json="$(read_native_guard_json || true)"
    if [ -n "$guard_json" ]; then
        guard_from_native_json "$guard_json" || true
    fi

    guard_from_systemd
}

main "$@"
