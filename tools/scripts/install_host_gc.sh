#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Installs the host garbage collector and its worktree delegate into the
# maintainer's own tool tree, and (re)writes the two user systemd units that
# run it hourly.
#
# WHY A SEPARATE INSTALLER. host_gc.sh reads $SCRIPT_DIR/worktree_gc.sh at
# run time, so the two scripts must live side by side wherever host_gc.sh is
# actually invoked from. The hourly timer must NOT invoke either script
# inside a checkout (a `git worktree remove` or a lane teardown can delete
# the very file the timer is executing mid-run), so both are copied into
# $HOME/.local/lib/z23/tools/ — outside every checkout — and the unit's
# ExecStart points there, never at $REPO_ROOT.
#
# This script only WRITES files under $HOME/.local/lib/z23 and
# $HOME/.config/systemd/user, and reloads the user systemd manager. It never
# touches a datadir, a checkout, or a live node. It is idempotent: rerunning
# it just rewrites the same install.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LIB_DIR="${ZCL_HOST_GC_INSTALL_LIB:-$HOME/.local/lib/z23/tools}"
UNIT_DIR="${ZCL_HOST_GC_INSTALL_UNITS:-$HOME/.config/systemd/user}"
SYSTEMCTL_BIN="${ZCL_HOST_GC_SYSTEMCTL_BIN:-systemctl}"

usage() {
    cat <<'USAGE'
usage: tools/scripts/install_host_gc.sh [--no-reload]

Installs tools/scripts/host_gc.sh and tools/scripts/worktree_gc.sh into
~/.local/lib/z23/tools/, and writes zclassic23-host-gc.timer/.service into
~/.config/systemd/user/ (hourly, ExecStart pointing at the installed copy).

--no-reload   skip `systemctl --user daemon-reload` and enabling the timer
              (useful when scripting the install from something that will
              reload once at the end itself)
USAGE
}

RELOAD=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-reload) RELOAD=0 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'install-host-gc: unknown arg %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

mkdir -p -- "$LIB_DIR" "$UNIT_DIR"

install -m 0755 -- "$SCRIPT_DIR/host_gc.sh" "$LIB_DIR/host_gc.sh"
install -m 0755 -- "$SCRIPT_DIR/worktree_gc.sh" "$LIB_DIR/worktree_gc.sh"

cat > "$UNIT_DIR/zclassic23-host-gc.timer" <<'TIMER'
[Unit]
Description=ZClassic23 Host Garbage Collector Timer

[Timer]
# Hourly at :47 (+300s jitter). See tools/scripts/host_gc.sh and
# docs/HOST_GC.md for why this slot and why hourly.
OnCalendar=*-*-* *:47:00
RandomizedDelaySec=300
Persistent=true
Unit=zclassic23-host-gc.service

[Install]
WantedBy=timers.target
TIMER

cat > "$UNIT_DIR/zclassic23-host-gc.service" <<SERVICE
[Unit]
Description=ZClassic23 Host Garbage Collector

[Service]
Type=oneshot
ExecStart=%h/.local/lib/z23/tools/host_gc.sh --apply
TimeoutStartSec=1800
Nice=19
CPUWeight=10
IOWeight=10
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
SERVICE

if [ "$RELOAD" = 1 ]; then
    if command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
        "$SYSTEMCTL_BIN" --user daemon-reload
        "$SYSTEMCTL_BIN" --user enable --now zclassic23-host-gc.timer
    else
        printf 'install-host-gc: %s not found — units written, not enabled\n' "$SYSTEMCTL_BIN" >&2
    fi
fi

printf 'install-host-gc: installed %s and %s\n' "$LIB_DIR/host_gc.sh" "$LIB_DIR/worktree_gc.sh"
printf 'install-host-gc: wrote %s and %s\n' \
    "$UNIT_DIR/zclassic23-host-gc.timer" "$UNIT_DIR/zclassic23-host-gc.service"
