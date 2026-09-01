#!/bin/bash
# install-host-watchdog.sh — installs the SYSTEM-level host watchdog
# (deploy/system/zclassic23-host-watchdog.{service,timer}); see
# platform/deploy/zclassic23-host-watchdog.sh header for what it does. Requires
# passwordless sudo (`sudo -n true`); refuses politely otherwise, never
# prompts. Idempotent: safe to re-run.
#
# Manual operator tool — one-time root-level installer, intentionally no
# in-repo caller. Invocation: `bash platform/deploy/install-host-watchdog.sh` (see the
# refusal branch below for the manual `install`/`systemctl` equivalent when
# passwordless sudo isn't available). Owning runbook: this file's own header
# plus platform/deploy/zclassic23-host-watchdog.sh's header for what the watchdog does
# once installed.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! sudo -n true 2>/dev/null; then
    cat >&2 <<EOF
Passwordless sudo is not available non-interactively — refusing to prompt.
Install manually as root:
  install -m755 $REPO_DIR/platform/deploy/zclassic23-host-watchdog.sh /usr/local/sbin/zclassic23-host-watchdog.sh
  install -m644 $REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.service /etc/systemd/system/
  install -m644 $REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.timer   /etc/systemd/system/
  install -d -m755 /etc/logrotate.d
  install -m644 $REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.logrotate /etc/logrotate.d/zclassic23-host-watchdog
  systemctl daemon-reload
  systemctl enable --now zclassic23-host-watchdog.timer
EOF
    exit 1
fi

echo "installing zclassic23-host-watchdog (operator user: ${ZCL_HOST_WATCHDOG_USER:-rhett})"
sudo install -m755 "$REPO_DIR/platform/deploy/zclassic23-host-watchdog.sh" /usr/local/sbin/zclassic23-host-watchdog.sh
sudo install -m644 "$REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.service" /etc/systemd/system/zclassic23-host-watchdog.service
sudo install -m644 "$REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.timer" /etc/systemd/system/zclassic23-host-watchdog.timer
sudo install -d -m755 /etc/logrotate.d
sudo install -m644 "$REPO_DIR/platform/deploy/system/zclassic23-host-watchdog.logrotate" /etc/logrotate.d/zclassic23-host-watchdog

sudo systemctl daemon-reload
sudo systemctl enable --now zclassic23-host-watchdog.timer

echo "running one probe cycle (copy-prove)..."
sudo systemctl start zclassic23-host-watchdog.service
sleep 1
sudo journalctl -u zclassic23-host-watchdog.service -n 5 --no-pager || true
if sudo test -f /var/log/zclassic23-host-watchdog.log; then
    echo "log tail:"; sudo tail -n1 /var/log/zclassic23-host-watchdog.log
else
    echo "(no log line yet — healthy/quiet cycle, this is expected)"
fi
