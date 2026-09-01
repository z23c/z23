#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Systemd helper for z23-build-zram.service. It never replaces an
# existing zram swap and stops only the device it recorded as self-created.
set -euo pipefail

CONFIG=/etc/z23-ram-dev.conf
STATE=/run/z23-build-zram.state

die() { printf 'z23-build-zram: REFUSE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "root is required"
[ -r "$CONFIG" ] || die "missing $CONFIG"
# shellcheck disable=SC1090
. "$CONFIG"
[[ "${Z23_ZRAM_SIZE:-}" =~ ^[1-9][0-9]*[MG]$ ]] || die "invalid Z23_ZRAM_SIZE"

case "${1:-}" in
    start)
        existing="$(awk 'NR > 1 && $1 ~ /^\/dev\/zram[0-9]+$/ { print $1; exit }' /proc/swaps)"
        if [ -n "$existing" ]; then
            printf 'external:%s\n' "$existing" >"$STATE"
            printf 'z23-build-zram: preserving existing swap %s\n' "$existing"
            exit 0
        fi
        command -v zramctl >/dev/null 2>&1 || die "zramctl is required"
        command -v mkswap >/dev/null 2>&1 || die "mkswap is required"
        modprobe zram || die "kernel zram module unavailable"
        dev="$(zramctl --find --algorithm zstd --size "$Z23_ZRAM_SIZE")" \
            || die "could not allocate $Z23_ZRAM_SIZE zram with zstd"
        case "$dev" in /dev/zram[0-9]*) ;; *) die "zramctl returned unsafe device '$dev'" ;; esac
        cleanup=1
        trap '[ "$cleanup" -eq 0 ] || zramctl --reset "$dev" 2>/dev/null || true' EXIT
        mkswap "$dev" >/dev/null
        swapon --priority 100 "$dev"
        printf 'managed:%s\n' "$dev" >"$STATE"
        cleanup=0
        trap - EXIT
        printf 'z23-build-zram: activated %s size=%s priority=100\n' \
            "$dev" "$Z23_ZRAM_SIZE"
        ;;
    stop)
        [ -r "$STATE" ] || exit 0
        IFS=: read -r ownership dev <"$STATE"
        if [ "$ownership" = managed ]; then
            case "$dev" in /dev/zram[0-9]*) ;; *) die "unsafe recorded device '$dev'" ;; esac
            swapoff "$dev" 2>/dev/null || true
            zramctl --reset "$dev" 2>/dev/null || true
        fi
        rm -f -- "$STATE"
        ;;
    status)
        awk 'NR == 1 || $1 ~ /^\/dev\/zram[0-9]+$/' /proc/swaps
        ;;
    *) die "usage: $0 start|stop|status" ;;
esac
