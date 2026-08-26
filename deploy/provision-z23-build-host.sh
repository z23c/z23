#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Provision one bounded, disposable RAM development workspace without changing
# the persistent source checkout or any node service or datadir.
set -euo pipefail

CONFIG=/etc/z23-ram-dev.conf
TOOL=/usr/local/bin/z23-ram-dev
ZRAM_HELPER=/usr/local/libexec/z23-build-zram
ZRAM_UNIT=/etc/systemd/system/z23-build-zram.service
MIN_MEM_KB=$((14 * 1024 * 1024))
die() { printf 'provision-z23-build-host: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'provision-z23-build-host: %s\n' "$*"; }
valid_size() { [[ "$1" =~ ^[1-9][0-9]*[MG]$ ]]; }
safe_path() { [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] && [ "$1" != / ]; }
mount_unit_for() { systemd-escape --path --suffix=mount "$1"; }
size_bytes() { local n="${1%?}" s="${1: -1}" m; case "$s" in M) m=$((1024*1024));; G) m=$((1024*1024*1024));; *) return 1;; esac; printf '%s\n' "$((n*m))"; }

render_mount_unit() {
    local where="$1" size="$2" uid="$3" gid="$4"
    cat <<EOF
[Unit]
Description=Z23 bounded disposable RAM development workspace
After=local-fs.target
Before=z23-build-zram.service
[Mount]
What=tmpfs
Where=$where
Type=tmpfs
Options=rw,nosuid,nodev,noatime,size=$size,mode=0700,uid=$uid,gid=$gid
[Install]
WantedBy=multi-user.target
EOF
}
render_zram_unit() { cat <<EOF
[Unit]
Description=Z23 build-host zram assurance
After=swap.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ZRAM_HELPER start
ExecStop=$ZRAM_HELPER stop
[Install]
WantedBy=multi-user.target
EOF
}
require_root_ubuntu() {
    [ "$(id -u)" -eq 0 ] || die "run with sudo"
    . /etc/os-release
    [ "${ID:-}" = ubuntu ] || die "Ubuntu is required"
    [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] || die "systemd must be PID 1"
}
require_commands() { local c; for c in findmnt git mountpoint pgrep realpath systemd-escape systemctl; do command -v "$c" >/dev/null || die "required command absent: $c"; done; }
assert_idle() { local p; p="$(pgrep -u "$1" -x 'make|gcc|g[+][+]|clang|clang[+][+]|ld|ld.lld|mold|zcc|grok' 2>/dev/null || true)"; [ -z "$p" ] || die "development process active for uid $1: $(printf '%s' "$p" | tr '\n' ',')"; }
config_is_safe() { [ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] && [ "$(stat -c %u "$CONFIG")" -eq 0 ] && [ "$((8#$(stat -c %a "$CONFIG") & 8#022))" -eq 0 ]; }
write_config() {
    cat >"$CONFIG" <<EOF
# Copyright 2026 Rhett Creighton - Apache License 2.0
Z23_DEV_USER=$1
Z23_DEV_UID=$2
Z23_DEV_GID=$3
Z23_PERSISTENT_REPO=$4
Z23_RAM_ROOT=$5
Z23_RAM_SIZE=$6
Z23_ZRAM_SIZE=$7
Z23_ZCC_MAX_MB=1536
Z23_DEV_MEMORY_HIGH=8G
Z23_DEV_MEMORY_MAX=10G
EOF
    chmod 0644 "$CONFIG"
}
install_accelerator() {
    local user="$1" repo="$2" ram_size="$3" zram_size="$4" uid gid mem_kb repo_fs ram_root unit
    [ -n "$user" ] && id "$user" >/dev/null 2>&1 || die "valid --user is required"
    case "$user" in *[!A-Za-z0-9_-]*|'') die "unsafe user name";; esac
    uid="$(id -u "$user")"; gid="$(id -g "$user")"; [ "$uid" -ne 0 ] || die "development user must not be root"
    safe_path "$repo" || die "repo must be an absolute path without spaces"
    repo="$(realpath -e "$repo")"; [ -e "$repo/.git" ] && [ -f "$repo/Makefile" ] && [ -f "$repo/AGENTS.md" ] || die "not a Z23 checkout: $repo"
    [ "$(stat -c %u "$repo")" -eq "$uid" ] || die "checkout is not owned by $user"
    valid_size "$ram_size" && valid_size "$zram_size" || die "sizes must be positive M/G values"
    [ "$(size_bytes "$ram_size")" -le $((6*1024*1024*1024)) ] || die "RAM workspace exceeds 6G coexistence limit"
    [ "$(size_bytes "$zram_size")" -le $((8*1024*1024*1024)) ] || die "zram exceeds 8G coexistence limit"
    mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"; [ "$mem_kb" -ge "$MIN_MEM_KB" ] || die "at least 14 GiB RAM required"
    repo_fs="$(findmnt -n -o FSTYPE --target "$repo")"; [ "$repo_fs" != tmpfs ] || die "persistent source is volatile"
    ram_root="/mnt/z23-dev-$user"; [ ! -L "$ram_root" ] || die "workspace target is a symlink"
    assert_idle "$uid"
    if [ -e "$CONFIG" ]; then config_is_safe || die "existing config is unsafe"; . "$CONFIG"; [ "$Z23_DEV_USER:$Z23_PERSISTENT_REPO:$Z23_RAM_SIZE:$Z23_ZRAM_SIZE" = "$user:$repo:$ram_size:$zram_size" ] || die "configuration differs; uninstall first"; fi
    install -d -m 0700 -o "$uid" -g "$gid" "$ram_root"
    write_config "$user" "$uid" "$gid" "$repo" "$ram_root" "$ram_size" "$zram_size"
    install -d -m 0755 /usr/local/libexec
    install -m 0755 "$(dirname "$0")/z23-build-zram.sh" "$ZRAM_HELPER"
    install -m 0755 "$(dirname "$0")/../tools/scripts/z23-ram-dev.sh" "$TOOL"
    unit="$(mount_unit_for "$ram_root")"; render_mount_unit "$ram_root" "$ram_size" "$uid" "$gid" >"/etc/systemd/system/$unit"; render_zram_unit >"$ZRAM_UNIT"
    systemctl daemon-reload; systemctl enable --now "$unit" z23-build-zram.service
    status_accelerator; say "PASS persistent_source=$repo source_fs=$repo_fs RAM_workspace=$ram_root cap=$ram_size"; say "next: sudo -u $user $TOOL bootstrap"
}
status_accelerator() {
    config_is_safe || die "not installed or unsafe config"; . "$CONFIG"
    local sf rf rb zr; sf="$(findmnt -n -o FSTYPE --target "$Z23_PERSISTENT_REPO")"; rf="$(findmnt -n -o FSTYPE --mountpoint "$Z23_RAM_ROOT" 2>/dev/null || true)"
    [ "$sf" != tmpfs ] && [ "$rf" = tmpfs ] || die "storage boundary failed"
    rb="$(findmnt -b -n -o SIZE --mountpoint "$Z23_RAM_ROOT")"; [ "$rb" -le "$(size_bytes "$Z23_RAM_SIZE")" ] || die "workspace exceeds cap"
    [ "$(stat -c %u "$Z23_RAM_ROOT")" -eq "$Z23_DEV_UID" ] || die "workspace ownership drifted"
    zr="$(awk 'NR>1 && $1~/^\/dev\/zram[0-9]+$/ {print $1 ":" $3 "KiB:priority=" $5; exit}' /proc/swaps)"; [ -n "$zr" ] || die "no active zram swap"
    say "status PASS source_fs=$sf RAM_fs=$rf RAM_cap_bytes=$rb zram=$zr"
}
uninstall_accelerator() {
    local confirm="$1" unit; [ -e "$CONFIG" ] || { say "already uninstalled"; exit 0; }; config_is_safe || die "unsafe config"; . "$CONFIG"; safe_path "$Z23_RAM_ROOT" || die "unsafe mount path"; assert_idle "$Z23_DEV_UID"
    [ "$confirm" = 1 ] || sudo -u "$Z23_DEV_USER" "$TOOL" can-discard || die "RAM work is not on origin/main; checkpoint it or pass --confirm-discard-ram"
    unit="$(mount_unit_for "$Z23_RAM_ROOT")"; systemctl disable --now z23-build-zram.service "$unit"; mountpoint -q "$Z23_RAM_ROOT" && die "workspace still mounted"
    rm -f -- "$ZRAM_UNIT" "/etc/systemd/system/$unit" "$ZRAM_HELPER" "$TOOL" "$CONFIG"; rmdir "$Z23_RAM_ROOT" 2>/dev/null || true; systemctl daemon-reload; say "PASS uninstalled; persistent source unchanged"
}
selftest() { local u helper runner; selftest_tmp="$(mktemp -d "${TMPDIR:-/tmp}/z23-provision.XXXXXX")"; trap '[ -z "${selftest_tmp:-}" ] || rm -rf -- "$selftest_tmp"' EXIT; valid_size 6G && ! valid_size 6T && [ "$(size_bytes 6G)" -eq 6442450944 ] || die "size selftest"; u="$(mount_unit_for /mnt/z23-dev-operator)"; render_mount_unit /mnt/z23-dev-operator 6G 1000 1000 >"$selftest_tmp/$u"; grep -q 'size=6G,mode=0700,uid=1000,gid=1000' "$selftest_tmp/$u" || die "mount selftest"; ! grep -Eq '\.zclassic|systemctl (restart|stop).*zclassic' "$selftest_tmp/$u" || die "authority selftest"; helper="$(dirname "$0")/z23-build-zram.sh"; runner="$(dirname "$0")/../tools/scripts/z23-ram-dev.sh"; grep -Fxq "CONFIG=$CONFIG" "$helper" || die "zram helper config contract drifted"; grep -Fxq 'STATE=/run/z23-build-zram.state' "$helper" || die "zram helper state contract drifted"; grep -Fq 'Z23_RAM_DEV_CONFIG:-/etc/z23-ram-dev.conf' "$runner" || die "runner config contract drifted"; render_zram_unit >"$selftest_tmp/z23-build-zram.service"; grep -Fxq "ExecStart=$ZRAM_HELPER start" "$selftest_tmp/z23-build-zram.service" || die "zram unit start contract drifted"; grep -Fxq "ExecStop=$ZRAM_HELPER stop" "$selftest_tmp/z23-build-zram.service" || die "zram unit stop contract drifted"; say "selftest PASS"; }

action="${1:-}"; shift || true; user= repo= ram_size=6G zram_size=8G confirm=0
while [ $# -gt 0 ]; do case "$1" in --user=*) user="${1#*=}";; --repo=*) repo="${1#*=}";; --ram-size=*) ram_size="${1#*=}";; --zram-size=*) zram_size="${1#*=}";; --confirm-discard-ram) confirm=1;; *) die "unknown argument: $1";; esac; shift; done
case "$action" in --selftest) selftest;; install) require_root_ubuntu; require_commands; install_accelerator "$user" "$repo" "$ram_size" "$zram_size";; status) require_root_ubuntu; require_commands; status_accelerator;; uninstall) require_root_ubuntu; require_commands; uninstall_accelerator "$confirm";; *) die "usage: $0 install --user=USER --repo=PATH | status | uninstall [--confirm-discard-ram] | --selftest";; esac
