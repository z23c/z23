#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Native fixture only: unique LaunchAgent, isolated regtest ports and datadir.
set -euo pipefail
SELF_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/../.." && pwd)"
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || {
    printf 'macos-launchd: native darwin-arm64 execution required\n' >&2
    exit 2
}
ISO_KIND=launchd-acceptance
ISO_PORT_BASE=39340
ISO_NODE_BIN="${1:-$REPO_ROOT/build/bin/z23}"
ISO_RPC_BIN="${ISO_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
ISO_JSONQ_BIN="${ISO_JSONQ_BIN:-$REPO_ROOT/build/bin/jsonq}"
source "$SELF_DIR/isolated_node_env.sh"
source "$SELF_DIR/lib/service_args.sh"
launchd_uid="$(id -u)"
launchd_domain="user/$launchd_uid"
launchd_session=Background
if launchctl print "gui/$launchd_uid" >/dev/null 2>&1; then
    launchd_domain="gui/$launchd_uid"
    launchd_session=Aqua
fi
launchctl print "$launchd_domain" >/dev/null 2>&1 || iso_die 'no accessible launchd user domain'
iso_init
launchd_label="org.z23.acceptance.$launchd_uid.$$"
launchd_job="$launchd_domain/$launchd_label"
launchd_plist="$ISO_DD/launchd.plist"
launchd_pid=''
launchd_cleanup() {
    local rc=$? cleanup_deadline
    trap - EXIT INT TERM
    if launchctl print "$launchd_job" >/dev/null 2>&1; then
        launchctl bootout "$launchd_job" || {
            printf 'macos-launchd: fixture cleanup failed: %s\n' "$launchd_job" >&2
            exit 1
        }
    fi
    cleanup_deadline=$(( $(date +%s) + 40 ))
    while [ -n "$launchd_pid" ] && kill -0 "$launchd_pid" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$cleanup_deadline" ]; then
            printf 'macos-launchd: process still present; preserving datadir %s\n' "$ISO_DD" >&2
            exit 1
        fi
        sleep 0.2
    done
    if [ "$rc" -ne 0 ] && [ -f "$ISO_DD/node.log" ]; then
        local retained
        retained="$(mktemp "${TMPDIR:-/tmp}/z23-launchd-failure.XXXXXX")"
        cp "$ISO_DD/node.log" "$retained"
        printf 'macos-launchd: fixture log retained at %s\n' "$retained" >&2
    fi
    # launchd owns this process, not the process-group launcher. Remove its
    # exact job before invoking the shared datadir cleanup; never kill a stale PID.
    ISO_NODE_PID=''
    ISO_PGID=''
    iso_cleanup
    exit "$rc"
}
trap launchd_cleanup EXIT
trap 'exit 2' INT TERM

# plutil encodes path bytes instead of interpolating paths into XML.
plutil -create xml1 "$launchd_plist"
plutil -insert Label -string "$launchd_label" "$launchd_plist"
plutil -insert ProgramArguments -array "$launchd_plist"
launchd_args=("$ISO_NODE_BIN" "-datadir=$ISO_DD" -regtest
    "-port=$ISO_PORT" "-rpcport=$ISO_RPCPORT" "-fsport=$ISO_FSPORT"
    "-httpsport=$ISO_HTTPSPORT" "-connect=127.0.0.1:$ISO_CONNECT_SINK"
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0
    -operator-lane=test -wallet-no-phrase-backup)
for i in "${!launchd_args[@]}"; do
    plutil -insert "ProgramArguments.$i" -string "${launchd_args[$i]}" "$launchd_plist"
done
plutil -insert EnvironmentVariables -dictionary "$launchd_plist"
plutil -insert EnvironmentVariables.ZCL_WALLET_PASSPHRASE \
    -string isolated-launchd-acceptance-fixture-only "$launchd_plist"
plutil -insert RunAtLoad -bool true "$launchd_plist"
plutil -insert KeepAlive -bool true "$launchd_plist"
plutil -insert LimitLoadToSessionType -string "$launchd_session" "$launchd_plist"
plutil -insert ThrottleInterval -integer 2 "$launchd_plist"
# Match the canonical node service's bounded grace; acceptance below still
# requires this isolated fixture to finish its clean stop within 40 seconds.
plutil -insert ExitTimeOut -integer 300 "$launchd_plist"
plutil -insert Nice -integer 10 "$launchd_plist"
plutil -insert WorkingDirectory -string "$ISO_DD" "$launchd_plist"
plutil -insert StandardOutPath -string "$ISO_DD/node.log" "$launchd_plist"
plutil -insert StandardErrorPath -string "$ISO_DD/node.log" "$launchd_plist"
chmod 600 "$launchd_plist"
plutil -lint "$launchd_plist" >/dev/null

launchd_ready() {
    local previous="$1" phase="$2" began deadline candidate='' mapped=''
    began=$(date +%s)
    deadline=$((began + 90))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        candidate=$(zcl_service_pid ignored "$launchd_plist" || true)
        if [ -n "$candidate" ] && [ "$candidate" != "$previous" ]; then break; fi
        sleep 0.2
    done
    [ -n "$candidate" ] && [ "$candidate" != "$previous" ] ||
        iso_die "$phase did not produce a new supervisor-owned PID"
    launchd_pid="$candidate"
    ISO_NODE_PID="$candidate"
    iso_wait_rpc_ready 90 || iso_die "$phase did not reach successful RPC"
    "$ISO_NODE_BIN" core node bootwait -datadir="$ISO_DD" \
        --timeout_ms=90000 --heartbeat_ms=250 >/dev/null || iso_die "$phase did not finish boot"
    [ "$(zcl_service_active_state ignored "$launchd_plist")" = active ] ||
        iso_die "$phase was not reported active by service discovery"
    [ "$(zcl_service_pid ignored "$launchd_plist")" = "$candidate" ] ||
        iso_die "$phase changed supervisor-owned PID during readiness"
    mapped=$(lsof -a -p "$candidate" -d txt -Fn 2>/dev/null |
        awk '/^n/ && !seen {print substr($0, 2); seen=1}')
    [ -n "$mapped" ] && cmp -s "$mapped" "$ISO_NODE_BIN" ||
        iso_die "$phase mapped executable locator differs from fixture bytes"
    [ ! -e "$ISO_DD/.shutdown_clean" ] || iso_die "$phase retained the prior shutdown marker"
    printf 'macos-launchd: phase=%s ready_seconds=%s domain=%s\n' \
        "$phase" "$(( $(date +%s) - began ))" "$launchd_session"
}
launchd_stop() {
    local stopping="$launchd_pid" began deadline
    began=$(date +%s)
    deadline=$((began + 40))
    launchctl bootout "$launchd_job"
    while kill -0 "$stopping" 2>/dev/null; do
        [ "$(date +%s)" -lt "$deadline" ] || iso_die 'launchd stop exceeded its bound'
        sleep 0.2
    done
    [ "$(date +%s)" -le "$deadline" ] || iso_die 'launchd bootout exceeded the clean-stop bound'
    ISO_NODE_PID=''
    [ -f "$ISO_DD/.shutdown_clean" ] || iso_die 'launchd stop lost the clean shutdown marker'
    printf 'macos-launchd: clean_stop_seconds=%s marker=present\n' "$(( $(date +%s) - began ))"
}
launchctl bootstrap "$launchd_domain" "$launchd_plist"
launchd_ready '' startup
previous_pid="$launchd_pid"
launchctl kill SIGKILL "$launchd_job"
launchd_ready "$previous_pid" crash-recovery
launchd_stop
previous_pid="$launchd_pid"
launchctl bootstrap "$launchd_domain" "$launchd_plist"
launchd_ready "$previous_pid" clean-restart
launchd_stop
printf 'macos-launchd: PASS native_node=true discovery=true crash_recovery=true clean_restart=true\n'
