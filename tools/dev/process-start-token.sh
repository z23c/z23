#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Print the stable birth token for one live process. Epoch leases pair this
# token with the PID so a recycled PID cannot inherit an earlier build's
# authority. Linux and MSYS expose the kernel tick through procfs; Darwin
# exposes the process start record through ps, which is hashed to a path-safe
# token.

zcl_process_start_token()
{
    local pid="${1:-}"
    local record rest first second observed_pid attempt

    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 2

    case "$(uname -s 2>/dev/null)" in
    Linux|MINGW*|MSYS*)
        record=""
        if ! IFS= read -r record 2>/dev/null < "/proc/$pid/stat"; then
            return 1
        fi
        [ -n "$record" ] || return 1
        # The parenthesized command may contain spaces. Strip through its final
        # closing parenthesis; starttime is field 20 of the remaining fields.
        rest="${record##*) }"
        set -- $rest
        [ "$#" -ge 20 ] || return 1
        [[ "${20}" =~ ^[0-9]+$ ]] || return 1
        printf '%s\n' "${20}"
        ;;
    Darwin)
        record=""
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            first="$(LC_ALL=C ps -p "$pid" -o pid=,lstart=,uid= 2>/dev/null)" || first=""
            second="$(LC_ALL=C ps -p "$pid" -o pid=,lstart=,uid= 2>/dev/null)" || second=""
            if [ -n "$first" ] && [ "$first" = "$second" ] &&
               kill -0 "$pid" 2>/dev/null; then
                record="$first"
                break
            fi
        done
        [ -n "$record" ] || return 1
        observed_pid="${record#${record%%[![:space:]]*}}"
        observed_pid="${observed_pid%%[[:space:]]*}"
        [ "$observed_pid" = "$pid" ] || return 1
        (
            set -o pipefail
            printf '%s' "$record" | shasum -a 256 | awk '{print $1}'
        )
        ;;
    *)
        return 2
        ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    zcl_process_start_token "${1:-}"
fi
