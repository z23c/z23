#!/bin/bash
# One-time deployment setup for Z23.
# Run once with: sudo bash platform/deploy/setup.sh
#
# After this, 'make deploy' works without sudo ever again.
set -e

TARGET_USER="${SUDO_USER:-$(whoami)}"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SERVICE_DIR="$(eval echo ~$TARGET_USER)/.config/systemd/user"

echo "Setting up Z23 for user: $TARGET_USER"

# Refuse to enable z23-node while the pre-rename unit is active or enabled:
# both would bind the same datadir and ports. The migration is a separate step.
legacy_state=""
for verb in is-active is-enabled; do
    st="$(su - "$TARGET_USER" -c "systemctl --user $verb zclassic23.service" 2>/dev/null || true)"
    case "$verb:$st" in
        is-active:active|is-active:activating|is-active:reloading|is-enabled:enabled*|is-enabled:linked*)
            legacy_state="$legacy_state $st" ;;
    esac
done
if [ -n "$legacy_state" ]; then
    {
        echo "REFUSE: zclassic23.service is$legacy_state for $TARGET_USER; enabling z23-node would run two nodes on one datadir and ports 8033/18232."
        echo "Nothing was changed. Migrate deliberately, then rerun:"
        echo "  systemctl --user stop zclassic23.service"
        echo "  systemctl --user disable zclassic23.service"
        echo "Procedure: docs/node/GETTING_STARTED.md#migrating-from-the-pre-rename-zclassic23service-unit"
    } >&2
    exit 3
fi

# Enable linger (service survives logout) — may already be enabled
loginctl enable-linger "$TARGET_USER" 2>/dev/null || true

# Install user service file
mkdir -p "$SERVICE_DIR"
install -m 644 "$REPO_DIR/platform/deploy/z23-node.service" "$SERVICE_DIR/z23-node.service"
su - "$TARGET_USER" -c "systemctl --user daemon-reload && systemctl --user enable z23-node" 2>/dev/null || \
    echo "Note: run 'systemctl --user daemon-reload && systemctl --user enable z23-node' as $TARGET_USER"

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
