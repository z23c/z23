#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Cross-host TCP LISTEN preflight.  Binding remains the final authority.

z23_tcp_port_listening()
{
    local port="${1:-}" output="" diagnostic="" rc=0 failures=""
    case "$port" in
        ''|*[!0-9]*)
            printf 'z23-port-probe: UNOBSERVED port=%s reason=invalid_port\n' \
                "${port:-empty}" >&2
            return 2 ;;
    esac
    if [ "${#port}" -gt 5 ]; then
        printf 'z23-port-probe: UNOBSERVED port=%s reason=invalid_port\n' \
            "$port" >&2
        return 2
    fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        printf 'z23-port-probe: UNOBSERVED port=%s reason=invalid_port\n' \
            "$port" >&2
        return 2
    fi

    if command -v ss >/dev/null 2>&1; then
        if output="$(ss -H -ltn "sport = :$port" 2>&1)"; then
            [ -n "$output" ] && return 0
            return 1
        else
            rc=$?
        fi
        failures="ss_exit_$rc"
    fi

    if command -v lsof >/dev/null 2>&1; then
        if output="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
        if [ "$rc" -eq 0 ]; then
            [ -n "$output" ] && return 0
            return 1
        fi
        if [ "$rc" -eq 1 ] && [ -z "$output" ]; then
            return 1
        fi
        failures="${failures:+$failures,}lsof_exit_$rc"
    fi

    if command -v netstat >/dev/null 2>&1; then
        if output="$(netstat -an 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
        if [ "$rc" -eq 0 ]; then
            if [[ "$output" =~ [.:]${port}[[:space:]].*LISTEN ]]; then
                return 0
            fi
            return 1
        fi
        failures="${failures:+$failures,}netstat_exit_$rc"
    fi

    diagnostic="${failures:-no_backend}"
    printf 'z23-port-probe: UNOBSERVED port=%s reason=%s need=ss,lsof,netstat\n' \
        "$port" "$diagnostic" >&2
    return 2
}

z23_port_probe_selftest()
(
    local work old_path rc output failures=0
    work="$(mktemp -d "${TMPDIR:-/tmp}/z23-port-probe.XXXXXX")" || return 2
    old_path="$PATH"
    trap 'PATH="$old_path"; rm -rf -- "$work"' EXIT

    mkdir -p "$work/ss" "$work/lsof" "$work/netstat" "$work/none"
    cat > "$work/ss/ss" <<'EOF_SS'
#!/bin/sh
case "${Z23_FAKE_SS_MODE:-free}" in
    listen) printf 'LISTEN 0 128 127.0.0.1:39070 0.0.0.0:*\n'; exit 0 ;;
    free) exit 0 ;;
    error) printf 'ss fixture failed\n' >&2; exit 7 ;;
esac
exit 9
EOF_SS
    cat > "$work/lsof/lsof" <<'EOF_LSOF'
#!/bin/sh
case "${Z23_FAKE_LSOF_MODE:-free}" in
    listen) printf 'z23 1 user 3u IPv4 TCP *:39070 (LISTEN)\n'; exit 0 ;;
    free) exit 1 ;;
    error) printf 'lsof fixture failed\n' >&2; exit 8 ;;
esac
exit 9
EOF_LSOF
    cat > "$work/netstat/netstat" <<'EOF_NETSTAT'
#!/bin/sh
case "${Z23_FAKE_NETSTAT_MODE:-free}" in
    listen) printf 'tcp4 0 0 127.0.0.1.39070 *.* LISTEN\n'; exit 0 ;;
    winlisten) printf '  TCP    127.0.0.1:39070    0.0.0.0:0    LISTENING\r\n'; exit 0 ;;
    free) printf 'tcp4 0 0 127.0.0.1.39071 *.* LISTEN\n'; exit 0 ;;
    error) printf 'netstat fixture failed\n' >&2; exit 6 ;;
esac
exit 9
EOF_NETSTAT
    chmod +x "$work/ss/ss" "$work/lsof/lsof" "$work/netstat/netstat"

    z23_probe_expect()
    {
        local name="$1" want="$2" path="$3"; shift 3
        set +e
        output="$(PATH="$path" "$@" 2>&1)"
        rc=$?
        set -e
        if [ "$rc" -ne "$want" ]; then
            printf 'port-probe selftest FAIL: %s rc=%s want=%s output=%s\n' \
                "$name" "$rc" "$want" "$output" >&2
            failures=$((failures + 1))
        fi
        if [ "$want" -eq 2 ] && ! grep -Fq 'UNOBSERVED' <<<"$output"; then
            printf 'port-probe selftest FAIL: %s lacked named UNOBSERVED\n' \
                "$name" >&2
            failures=$((failures + 1))
        fi
    }

    z23_probe_require_output()
    {
        local name="$1" needle="$2"
        if ! grep -Fq "$needle" <<<"$output"; then
            printf 'port-probe selftest FAIL: %s lacked %s output=%s\n' \
                "$name" "$needle" "$output" >&2
            failures=$((failures + 1))
        fi
    }

    z23_probe_expect ss-listen 0 "$work/ss" \
        /usr/bin/env Z23_FAKE_SS_MODE=listen /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect ss-free 1 "$work/ss" \
        /usr/bin/env Z23_FAKE_SS_MODE=free /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect ss-error 2 "$work/ss" \
        /usr/bin/env Z23_FAKE_SS_MODE=error /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_require_output ss-error 'reason=ss_exit_7'
    z23_probe_expect lsof-listen 0 "$work/lsof" \
        /usr/bin/env Z23_FAKE_LSOF_MODE=listen /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect lsof-free 1 "$work/lsof" \
        /usr/bin/env Z23_FAKE_LSOF_MODE=free /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect lsof-error 2 "$work/lsof" \
        /usr/bin/env Z23_FAKE_LSOF_MODE=error /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect netstat-listen 0 "$work/netstat" \
        /usr/bin/env Z23_FAKE_NETSTAT_MODE=listen /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect netstat-win-listen 0 "$work/netstat" \
        /usr/bin/env Z23_FAKE_NETSTAT_MODE=winlisten /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect netstat-free 1 "$work/netstat" \
        /usr/bin/env Z23_FAKE_NETSTAT_MODE=free /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect netstat-error 2 "$work/netstat" \
        /usr/bin/env Z23_FAKE_NETSTAT_MODE=error /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_require_output netstat-error 'reason=netstat_exit_6'
    z23_probe_expect no-backend 2 "$work/none" /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 39070' _ "${BASH_SOURCE[0]}"
    z23_probe_expect invalid-text 2 "$work/none" /bin/bash -c \
        'source "$1"; z23_tcp_port_listening nope' _ "${BASH_SOURCE[0]}"
    z23_probe_expect invalid-zero 2 "$work/none" /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 0' _ "${BASH_SOURCE[0]}"
    z23_probe_expect invalid-high 2 "$work/none" /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 65536' _ "${BASH_SOURCE[0]}"
    z23_probe_expect invalid-overflow 2 "$work/none" /bin/bash -c \
        'source "$1"; z23_tcp_port_listening 999999999999999999999999' _ \
        "${BASH_SOURCE[0]}"

    [ "$failures" -eq 0 ] || return 1
    printf 'port-probe selftest: PASS backends=ss,lsof,netstat tri_state=true\n'
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    case "${1:-}" in
        --selftest) z23_port_probe_selftest ;;
        *) printf 'usage: %s --selftest\n' "$0" >&2; exit 2 ;;
    esac
fi
