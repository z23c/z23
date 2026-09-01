#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Read one -key=value argument from the installed canonical node service.
# Linux uses systemd's resolved ExecStart; macOS uses launchd's structured
# ProgramArguments array.  Callers keep explicit environment overrides as the
# highest authority and use this only to discover the service's actual target.

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
