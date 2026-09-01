#!/bin/bash
# One-time deployment setup for Z23.
# Run once with: sudo bash platform/deploy/setup.sh
#
# After this, 'make deploy' works without sudo ever again.
set -e

TARGET_USER="${SUDO_USER:-$(whoami)}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_DIR="$(eval echo ~$TARGET_USER)/.config/systemd/user"

echo "Setting up Z23 for user: $TARGET_USER"

# Enable linger (service survives logout) — may already be enabled
loginctl enable-linger "$TARGET_USER" 2>/dev/null || true

# Install user service file
mkdir -p "$SERVICE_DIR"
install -m 644 "$REPO_DIR/platform/deploy/zclassic23.service" "$SERVICE_DIR/zclassic23.service"
su - "$TARGET_USER" -c "systemctl --user daemon-reload && systemctl --user enable zclassic23" 2>/dev/null || \
    echo "Note: run 'systemctl --user daemon-reload && systemctl --user enable zclassic23' as $TARGET_USER"

# Clean up old setcap sudoers rule if present
rm -f /etc/sudoers.d/zclassic23-setcap
# Retire the old iptables-based port-forward (replaced by the linger forwarder).
if systemctl list-unit-files 2>/dev/null | grep -q '^zcl-portfwd\.service'; then
    systemctl disable --now zcl-portfwd 2>/dev/null || true
    rm -f /etc/systemd/system/zcl-portfwd.service
    systemctl daemon-reload 2>/dev/null || true
fi

echo "Done. 'make deploy' will now work without sudo."
echo
echo "To expose the block explorer on public 443/80 (no nginx, ONE more sudo, once):"
echo "    sudo bash $REPO_DIR/tools/scripts/zcl-portfwd-setup.sh"
echo "See docs/BLOCK_EXPLORER_HOSTING.md."
