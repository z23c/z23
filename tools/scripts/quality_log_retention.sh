#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Bounded retention for unattended background-quality logs.  Only the four
# dated lane-log families are in scope; status JSON, fuzz artifacts, isolated
# checkouts, and node/mint data are never touched.

set -euo pipefail

LANE="${1:-}"
STATE_ROOT="${ZCL_QUALITY_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-quality}"
LOG_DIR="$STATE_ROOT/logs"
KEEP="${ZCL_QUALITY_LOG_KEEP:-8}"
MAX_BYTES="${ZCL_QUALITY_LOG_MAX_BYTES:-1073741824}"

usage() {
    echo "usage: quality_log_retention.sh <fuzz|tests|coverage|simnet-nightly|all>" >&2
}

if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [ "$KEEP" -lt 1 ] || [ "$KEEP" -gt 64 ]; then
    echo "quality-log-retention: invalid ZCL_QUALITY_LOG_KEEP=$KEEP (expected 1..64)" >&2
    exit 64
fi
if ! [[ "$MAX_BYTES" =~ ^[0-9]+$ ]] || [ "$MAX_BYTES" -lt 1 ] || \
        [ "$MAX_BYTES" -gt 68719476736 ]; then
    echo "quality-log-retention: invalid ZCL_QUALITY_LOG_MAX_BYTES=$MAX_BYTES (expected 1..68719476736)" >&2
    exit 64
fi

if [ ! -d "$LOG_DIR" ]; then
    exit 0
fi

prune_lane() {
    local lane="$1"
    local -a matches=() files=()
    local oldest_idx i file deleted=0 total_bytes=0 file_bytes

    shopt -s nullglob
    matches=()
    case "$lane" in
        fuzz) matches=("$LOG_DIR"/fuzz-*.log) ;;
        tests) matches=("$LOG_DIR"/tests-*.log) ;;
        coverage) matches=("$LOG_DIR"/coverage-*.log) ;;
        simnet-nightly) matches=("$LOG_DIR"/simnet-nightly-*.log) ;;
        *)
            echo "quality-log-retention: unsupported lane=$lane" >&2
            return 64
            ;;
    esac
    shopt -u nullglob

    # Bash 3.2 (macOS /bin/bash) treats "${empty_array[@]}" as unbound under
    # set -u; guard every array expansion that may be empty.
    [ ${#matches[@]} -gt 0 ] || return 0
    for file in "${matches[@]}"; do
        [ -f "$file" ] && [ ! -L "$file" ] && files+=("$file")
    done

    # Count limits alone are insufficient for fuzz output: eight completed
    # logs once consumed 5.2 GB. Bound each lane's logical bytes as well,
    # deleting oldest-first while always preserving its newest verdict log.
    # Symlinks and non-regular entries were filtered above and are untouched.
    [ ${#files[@]} -gt 0 ] || return 0
    for file in "${files[@]}"; do
        if ! file_bytes=$(wc -c < "$file"); then
            echo "quality-log-retention: wc failed lane=$lane file=$file" >&2
            return 1
        fi
        total_bytes=$((total_bytes + file_bytes))
    done
    while [ "${#files[@]}" -gt "$KEEP" ] || \
          { [ "${#files[@]}" -gt 1 ] && [ "$total_bytes" -gt "$MAX_BYTES" ]; }; do
        oldest_idx=-1
        for i in "${!files[@]}"; do
            if [ "$oldest_idx" -lt 0 ] \
                || [ "${files[$i]}" -ot "${files[$oldest_idx]}" ] \
                || { [ ! "${files[$oldest_idx]}" -ot "${files[$i]}" ] \
                    && [[ "${files[$i]}" < "${files[$oldest_idx]}" ]]; }; then
                oldest_idx="$i"
            fi
        done
        if [ "$oldest_idx" -lt 0 ]; then
            echo "quality-log-retention: internal oldest-log selection failed lane=$lane" >&2
            return 1
        fi
        if ! file_bytes=$(wc -c < "${files[$oldest_idx]}"); then
            echo "quality-log-retention: wc failed lane=$lane file=${files[$oldest_idx]}" >&2
            return 1
        fi
        rm -f -- "${files[$oldest_idx]}"
        total_bytes=$((total_bytes - file_bytes))
        unset 'files[oldest_idx]'
        if [ ${#files[@]} -gt 0 ]; then
            files=("${files[@]}")
        else
            files=()
        fi
        deleted=$((deleted + 1))
    done

    if [ "$deleted" -gt 0 ]; then
        echo "quality-log-retention: lane=$lane deleted=$deleted keep=$KEEP max_bytes=$MAX_BYTES"
    fi
}

case "$LANE" in
    fuzz|tests|coverage|simnet-nightly)
        prune_lane "$LANE"
        ;;
    all)
        prune_lane fuzz
        prune_lane tests
        prune_lane coverage
        prune_lane simnet-nightly
        ;;
    *)
        usage
        exit 64
        ;;
esac
