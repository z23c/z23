#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Print the stable birth token for one live process. Epoch leases pair this
# token with the PID so a recycled PID cannot inherit an earlier build's
# authority. Linux and MSYS expose the kernel tick through procfs; Darwin
# exposes the process start record through ps, which is hashed to a path-safe
# token.

set -euo pipefail

pid="${1:-}"
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || exit 2

proc_start_token()
{
    record="$(sed -n '1p' "/proc/$pid/stat" 2>/dev/null)"
    [ -n "$record" ] || return 1
    # The parenthesized command may contain spaces. Strip through its final
    # closing parenthesis; starttime is field 20 of the remaining fields.
    rest="${record##*) }"
    set -- $rest
    [ "$#" -ge 20 ] || return 1
    [[ "${20}" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${20}"
}

case "$(uname -s 2>/dev/null)" in
Linux|MINGW*|MSYS*)
    proc_start_token
    ;;
Darwin)
    record=""
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        set +e
        first="$(LC_ALL=C ps -p "$pid" -o pid=,lstart=,uid= 2>/dev/null)"
        second="$(LC_ALL=C ps -p "$pid" -o pid=,lstart=,uid= 2>/dev/null)"
        set -e
        if [ -n "$first" ] && [ "$first" = "$second" ] &&
           kill -0 "$pid" 2>/dev/null; then
            record="$first"
            break
        fi
    done
    [ -n "$record" ] || exit 1
    observed_pid="${record#${record%%[![:space:]]*}}"
    observed_pid="${observed_pid%%[[:space:]]*}"
    [ "$observed_pid" = "$pid" ] || exit 1
    printf '%s' "$record" | shasum -a 256 | awk '{print $1}'
    ;;
*)
    exit 2
    ;;
esac
