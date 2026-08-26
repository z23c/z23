#!/usr/bin/env bash
# Lint gate: systemd hard memory caps must fit inside the host budget.
#
# This guards the host-level OOM class from recurring. It parses committed
# systemd units plus drop-ins, sums finite MemoryMax and MemorySwapMax values,
# and fails when the aggregate budget reaches/exceeds the configured reference
# host budget. The shipped profiles target the measured 96 GiB operator-host
# class; lint must not change verdict merely because a developer builds on a
# smaller machine. Deploy validation can override the reference through
# ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES. Explicit MemoryMax=infinity is a
# hard failure because it disables a cap deliberately; absent MemoryMax remains
# allowed for lightweight units.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script_path="$script_dir/$(basename "${BASH_SOURCE[0]}")"

trim() {
    local s="$1"
    s="${s#"${s%%[!$' \t\r\n']*}"}"
    s="${s%"${s##*[!$' \t\r\n']}"}"
    printf '%s' "$s"
}

lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

parse_size_bytes() {
    local raw
    raw="$(trim "$1")"
    raw="$(lower "$raw")"
    case "$raw" in
        ""|"infinity")
            printf '%s\n' "INF"
            return 0
            ;;
    esac

    if [[ ! "$raw" =~ ^([0-9]+)([kmgtp]?)(i?b?)$ ]]; then
        return 1
    fi

    local n="${BASH_REMATCH[1]}"
    local suffix="${BASH_REMATCH[2]}"
    local mult=1
    case "$suffix" in
        "" ) mult=1 ;;
        k) mult=1024 ;;
        m) mult=$((1024 * 1024)) ;;
        g) mult=$((1024 * 1024 * 1024)) ;;
        t) mult=$((1024 * 1024 * 1024 * 1024)) ;;
        p) mult=$((1024 * 1024 * 1024 * 1024 * 1024)) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$((n * mult))"
}

memtotal_bytes() {
    if [ -n "${ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES:-}" ]; then
        printf '%s\n' "$ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES"
        return 0
    fi
    printf '%s\n' $((96 * 1024 * 1024 * 1024))
}

budget_bytes() {
    local mem="$1"
    if [ -n "${ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_BYTES:-}" ]; then
        printf '%s\n' "$ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_BYTES"
        return 0
    fi
    local pct="${ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT:-70}"
    if [[ ! "$pct" =~ ^[0-9]+$ ]] || [ "$pct" -le 0 ] || [ "$pct" -gt 100 ]; then
        echo "FAIL: invalid ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT=$pct" >&2
        return 1
    fi
    printf '%s\n' "$((mem * pct / 100))"
}

unit_sequence() {
    local unit="$1"
    printf '%s\n' "$unit"
    if [ -d "${unit}.d" ]; then
        find "${unit}.d" -type f -name '*.conf' | sort
    fi
}

read_unit_limits() {
    local unit="$1"
    local file line section key value parsed
    local in_service=0
    unit_memmax_state="ABSENT"
    unit_memmax_bytes=0
    unit_swap_state="ABSENT"
    unit_swap_bytes=0
    unit_high_state="ABSENT"
    unit_high_bytes=0

    while IFS= read -r file; do
        [ -f "$file" ] || continue
        in_service=0
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            line="$(trim "$line")"
            [ -z "$line" ] && continue
            if [[ "$line" =~ ^\[(.*)\]$ ]]; then
                section="${BASH_REMATCH[1]}"
                [ "$section" = "Service" ] && in_service=1 || in_service=0
                continue
            fi
            [ "$in_service" -eq 1 ] || continue
            if [[ ! "$line" =~ ^(MemoryMax|MemorySwapMax|MemoryHigh)[[:space:]]*=(.*)$ ]]; then
                continue
            fi
            key="${BASH_REMATCH[1]}"
            value="$(trim "${BASH_REMATCH[2]}")"
            if ! parsed="$(parse_size_bytes "$value")"; then
                echo "FAIL: $file: invalid $key=$value" >&2
                return 1
            fi
            case "$key" in
                MemoryMax)
                    unit_memmax_state="$parsed"
                    [ "$parsed" = "INF" ] || unit_memmax_bytes="$parsed"
                    ;;
                MemorySwapMax)
                    unit_swap_state="$parsed"
                    [ "$parsed" = "INF" ] || unit_swap_bytes="$parsed"
                    ;;
                MemoryHigh)
                    unit_high_state="$parsed"
                    [ "$parsed" = "INF" ] || unit_high_bytes="$parsed"
                    ;;
            esac
        done < "$file"
    done < <(unit_sequence "$unit")
}

find_units() {
    local root="$1"
    local dirs="${ZCL_SYSTEMD_MEMORY_BUDGET_DIRS:-deploy}"
    local d
    for d in $dirs; do
        [ -d "$root/$d" ] || continue
        find "$root/$d" -type f -name '*.service'
    done | sort -u
}

run_check() {
    local root="${ZCL_SYSTEMD_MEMORY_BUDGET_ROOT:-.}"
    local mem budget total swap_total failures unit rel
    mem="$(memtotal_bytes)"
    budget="$(budget_bytes "$mem")"
    total=0
    swap_total=0
    failures=0

    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        if ! read_unit_limits "$unit"; then
            failures=1
            continue
        fi
        rel="${unit#$root/}"
        if [ "$unit_memmax_state" = "INF" ]; then
            echo "FAIL: $rel explicitly sets MemoryMax=infinity"
            failures=1
            continue
        fi
        if [ "$unit_memmax_state" != "ABSENT" ]; then
            total=$((total + unit_memmax_bytes))
            if [ "$unit_swap_state" != "ABSENT" ] && [ "$unit_swap_state" != "INF" ]; then
                swap_total=$((swap_total + unit_swap_bytes))
                total=$((total + unit_swap_bytes))
            fi
            printf '  counted %-55s MemoryMax=%s MemorySwapMax=%s\n' \
                "$rel" "$unit_memmax_state" "$unit_swap_state"
        fi
    done < <(find_units "$root")

    if [ "$failures" -ne 0 ]; then
        exit 1
    fi

    printf 'check_systemd_memory_budget: total=%s bytes, swap_component=%s bytes, budget=%s bytes, memtotal=%s bytes\n' \
        "$total" "$swap_total" "$budget" "$mem"
    if [ "$total" -ge "$budget" ]; then
        echo "FAIL: systemd finite MemoryMax(+MemorySwapMax) sum reaches/exceeds budget"
        echo "      Lower MemoryMax caps or raise the explicit budget only with an ops note."
        exit 1
    fi
    echo "  OK: systemd finite memory budget is below the host guardrail"
}

expect_pass() {
    local name="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: expected pass: $name"
        return 1
    fi
}

expect_fail() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: expected failure: $name"
        return 1
    fi
}

selftest_case() {
    local name="$1"
    local expect="$2"
    local body="$3"
    local tmp
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/deploy"
    eval "$body"
    local cmd=(env -u ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST
        ZCL_SYSTEMD_MEMORY_BUDGET_ROOT="$tmp"
        ZCL_SYSTEMD_MEMORY_BUDGET_DIRS="deploy"
        ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES=$((64 * 1024 * 1024 * 1024))
        ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT=100
        "$script_path")
    if [ "$expect" = "pass" ]; then
        expect_pass "$name" "${cmd[@]}"
    else
        expect_fail "$name" "${cmd[@]}"
    fi
    local rc=$?
    rm -rf "$tmp"
    return "$rc"
}

selftest() {
    selftest_case "finite caps below budget" pass '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax = 24G # hard cap
MemorySwapMax=512M
EOF
        cat >"$tmp/deploy/b.service" <<EOF
[Service]
MemoryMax=32G
MemorySwapMax=512M
EOF
    '
    selftest_case "finite caps over budget" fail '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax=40G
EOF
        cat >"$tmp/deploy/b.service" <<EOF
[Service]
MemoryMax=32G
EOF
    '
    selftest_case "explicit infinity fails" fail '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax=infinity
EOF
    '
    selftest_case "absent MemoryMax passes" pass '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryHigh=6G
EOF
    '
    selftest_case "invalid swap directive fails" fail '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax=1G
MemorySwapMax=bogus
EOF
    '
    selftest_case "drop-in lower override wins" pass '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax=80G
EOF
        mkdir -p "$tmp/deploy/a.service.d"
        cat >"$tmp/deploy/a.service.d/10-cap.conf" <<EOF
[Service]
MemoryMax=24G
EOF
    '
    selftest_case "drop-in higher override wins" fail '
        cat >"$tmp/deploy/a.service" <<EOF
[Service]
MemoryMax=24G
EOF
        mkdir -p "$tmp/deploy/a.service.d"
        cat >"$tmp/deploy/a.service.d/10-cap.conf" <<EOF
[Service]
MemoryMax=80G
EOF
    '
    echo "check_systemd_memory_budget: selftest OK"
}

if [ "${ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST:-0}" = "1" ]; then
    selftest
else
    cd "$(dirname "$0")/../.."
    run_check
fi
