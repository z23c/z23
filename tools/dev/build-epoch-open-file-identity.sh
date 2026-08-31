#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Shared descriptor/path identity proof for compile-epoch authorities.

z23_build_epoch_identity_values_match()
{
    local fd_device="${1:-}" fd_inode="${2:-}"
    local path_device="${3:-}" path_inode="${4:-}"
    [[ "$fd_device" =~ ^0x[0-9a-fA-F]+$ ]] || return 1
    [[ "$fd_inode" =~ ^[0-9]+$ ]] || return 1
    [[ "$path_device" =~ ^[0-9]+$ ]] || return 1
    [[ "$path_inode" =~ ^[0-9]+$ ]] || return 1
    while [ "${#fd_inode}" -gt 1 ] && [[ "$fd_inode" = 0* ]]; do
        fd_inode="${fd_inode#0}"
    done
    while [ "${#path_inode}" -gt 1 ] && [[ "$path_inode" = 0* ]]; do
        path_inode="${path_inode#0}"
    done
    (( 16#${fd_device#0x} == 10#$path_device )) &&
        [ "$fd_inode" = "$path_inode" ]
}

z23_build_epoch_open_fd_matches_path()
{
    local path="${1:-}" fd="${2:-}" host_system="${3:-}"
    local fields line fd_record= fd_device= fd_inode= path_device path_inode extra
    [[ "$fd" =~ ^[0-9]+$ ]] || return 1
    if [ "$host_system" != Darwin ]; then
        [ "$path" -ef "/dev/fd/$fd" ]
        return
    fi
    [ -x /usr/sbin/lsof ] && [ -x /usr/bin/stat ] || return 1
    fields="$(/usr/sbin/lsof -a -p "$$" -d "$fd" -FDi 2>/dev/null)" ||
        return 1
    while IFS= read -r line; do
        case "$line" in
            p*) [[ "$line" =~ ^p[0-9]+$ ]] || return 1 ;;
            f*) [ -z "$fd_record" ] && [ "$line" = "f$fd" ] || return 1
                fd_record="$line" ;;
            D*) [ -z "$fd_device" ] || return 1
                fd_device="${line#D}" ;;
            i*) [ -z "$fd_inode" ] || return 1
                fd_inode="${line#i}" ;;
            *) return 1 ;;
        esac
    done <<< "$fields"
    [ "$fd_record" = "f$fd" ] || return 1
    read -r path_device path_inode extra <<< \
        "$(/usr/bin/stat -f '%d %i' "$path" 2>/dev/null)" || return 1
    [ -z "${extra:-}" ] || return 1
    z23_build_epoch_identity_values_match "$fd_device" "$fd_inode" \
        "$path_device" "$path_inode"
}
