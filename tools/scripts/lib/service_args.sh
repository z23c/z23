#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Read service facts from the installed canonical node service. Linux uses
# systemd's resolved unit properties; macOS uses the launchd plist plus the
# live launchctl job record. Callers keep explicit environment overrides as
# the highest authority and use these helpers only for read-only discovery.

zcl_service_launchd_label() {
    local plist="${1:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"

    [ -r "$plist" ] || return 1
    command -v plutil >/dev/null 2>&1 || return 1
    plutil -extract Label raw -o - "$plist" 2>/dev/null
}

zcl_service_launchd_print() {
    local plist="${1:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local label=""

    command -v launchctl >/dev/null 2>&1 || return 1
    label="$(zcl_service_launchd_label "$plist" || true)"
    [ -n "$label" ] || return 1
    launchctl print "gui/$(id -u)/$label" 2>/dev/null
}

zcl_service_exec_arg() {
    local key="$1"
    local unit="${2:-zclassic23}"
    local plist="${3:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local value=""
    local argc=""
    local i=0
    local token=""

    case "$key" in
        ''|*[!A-Za-z0-9_-]*) return 1 ;;
    esac

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p ExecStart --value 2>/dev/null |
            tr ' ' '\n' |
            sed -n "s/^-${key}=//p" |
            head -1)"
        if [ -n "$value" ]; then
            printf '%s\n' "$value"
            return 0
        fi
    fi

    [ -r "$plist" ] || return 1
    command -v plutil >/dev/null 2>&1 || return 1
    argc="$(plutil -extract ProgramArguments raw -o - "$plist" 2>/dev/null || true)"
    case "$argc" in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    i=1
    while [ "$i" -lt "$argc" ]; do
        token="$(plutil -extract "ProgramArguments.$i" raw -o - "$plist" 2>/dev/null || true)"
        case "$token" in
            "-${key}="*)
                printf '%s\n' "${token#-${key}=}"
                return 0
                ;;
        esac
        i=$((i + 1))
    done
    return 1
}

zcl_service_pid() {
    local unit="${1:-zclassic23}"
    local plist="${2:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local value=""

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p MainPID --value 2>/dev/null || true)"
        case "$value" in
            ''|0|*[!0-9]*) ;;
            *) printf '%s\n' "$value"; return 0 ;;
        esac
    fi

    value="$(zcl_service_launchd_print "$plist" |
        sed -n 's/^[[:space:]]*pid = \([1-9][0-9]*\)$/\1/p' |
        head -1)"
    [ -n "$value" ] || return 1
    printf '%s\n' "$value"
}

zcl_service_active_state() {
    local unit="${1:-zclassic23}"
    local plist="${2:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local value=""

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p ActiveState --value 2>/dev/null || true)"
        if [ -n "$value" ]; then
            printf '%s\n' "$value"
            return 0
        fi
    fi

    value="$(zcl_service_launchd_print "$plist" |
        sed -n 's/^[[:space:]]*state = \([^[:space:]][^[:space:]]*\)$/\1/p' |
        head -1)"
    [ -n "$value" ] || return 1
    if [ "$value" = "running" ]; then
        printf 'active\n'
    else
        printf '%s\n' "$value"
    fi
}

zcl_service_restart_policy() {
    local unit="${1:-zclassic23}"
    local plist="${2:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local value=""

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p Restart --value 2>/dev/null || true)"
        if [ -n "$value" ]; then
            printf '%s\n' "$value"
            return 0
        fi
    fi

    [ -r "$plist" ] || return 1
    command -v plutil >/dev/null 2>&1 || return 1
    value="$(plutil -extract KeepAlive.Crashed raw -o - "$plist" 2>/dev/null || true)"
    if [ "$value" = "true" ]; then
        printf 'on-failure\n'
        return 0
    fi
    value="$(plutil -extract KeepAlive raw -o - "$plist" 2>/dev/null || true)"
    if [ "$value" = "true" ]; then
        printf 'always\n'
        return 0
    fi
    return 1
}

zcl_service_started_epoch() {
    local unit="${1:-zclassic23}"
    local plist="${2:-${HOME:-}/Library/LaunchAgents/org.z23.zclassic.plist}"
    local value="" pid=""

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null || true)"
        if [ -n "$value" ] && [ "$value" != "n/a" ]; then
            value="$(LC_ALL=C date -d "$value" +%s 2>/dev/null || true)"
            if [ -n "$value" ]; then
                printf '%s\n' "$value"
                return 0
            fi
        fi
    fi

    pid="$(zcl_service_pid "$unit" "$plist" || true)"
    [ -n "$pid" ] || return 1
    value="$(LC_ALL=C ps -p "$pid" -o lstart= 2>/dev/null |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
        head -1)"
    [ -n "$value" ] || return 1
    if LC_ALL=C date -d "$value" +%s >/dev/null 2>&1; then
        LC_ALL=C date -d "$value" +%s
        return 0
    fi
    LC_ALL=C date -j -f '%a %b %e %T %Y' "$value" +%s 2>/dev/null
}

zcl_service_restart_count() {
    local unit="${1:-zclassic23}"
    local value=""

    if command -v systemctl >/dev/null 2>&1; then
        value="$(systemctl --user show "$unit" -p NRestarts --value 2>/dev/null || true)"
        case "$value" in
            ''|*[!0-9]*) ;;
            *) printf '%s\n' "$value"; return 0 ;;
        esac
    fi

    # launchd's `runs` includes initial and manual launches. It is not an
    # NRestarts equivalent, so fail closed instead of inventing soak evidence.
    return 1
}
