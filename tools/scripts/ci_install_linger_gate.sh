#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ci_install_linger_gate.sh — the REAL MVP C1 operator proof (no docker, ever).
#
# MVP criterion #1 is "single-binary install on clean Ubuntu/Debian: a fresh
# operator runs `make install && systemctl --user start z23-node` and the node
# comes up." The on-host ci-install gate proves the install MECHANISM but spawns
# the node directly (no systemd). THIS gate proves the exact operator claim the
# criterion names — a real `systemctl --user start` of a linger service brings
# the installed binary up and it answers RPC — using systemd --user (linger),
# never docker.
#
# It is fully ISOLATED from the live node:
#   - a DISTINCT unit name `z23-citest.service` (NEVER touches the live
#     `z23-node.service`),
#   - the binaries installed by the REAL `make install` to a throwaway /tmp
#     prefix (DESTDIR set => the live --user unit install is skipped),
#   - a /tmp regtest datadir + 3906x non-live ports + a dead `-connect` sink +
#     `-nolegacyimport` (so it never reads ~/.zclassic or binds a live port),
#   - torn down on every exit (stop + disable + remove unit + daemon-reload +
#     rm the prefix/datadir).
#
# Exit: 0 PASS · 2 SKIP (no systemd --user session) · 1 FAIL.

set -uo pipefail

GATE_SRC="${BASH_SOURCE[0]}"
GATE_DIR="$(cd "$(dirname "$GATE_SRC")" && pwd)"
REPO_ROOT="$(cd "$GATE_DIR/../.." && pwd)"

gate_skip() { echo "ci-install-linger: SKIP ($*)"; exit 2; }
gate_die()  { echo "ci-install-linger: FAIL: $*" >&2; exit 1; }

UNIT="z23-citest"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_FILE="$USER_UNIT_DIR/$UNIT.service"
PREFIX=""
DATADIR=""

# ── Safety: refuse to run if the test unit name could ever be the live one ──
case "$UNIT" in
    zclassic23) gate_die "refusing: test unit name collides with the live unit" ;;
esac

# ── Preflight: a usable systemd --user session ──────────────────────
command -v systemctl >/dev/null 2>&1 || gate_skip "systemctl absent"
systemctl --user show-environment >/dev/null 2>&1 || gate_skip "no systemd --user session (run under a logged-in/linger-enabled user)"

# ── Teardown (armed before we create anything) ──────────────────────
cleanup() {
    systemctl --user stop "$UNIT" >/dev/null 2>&1 || true
    systemctl --user disable "$UNIT" >/dev/null 2>&1 || true
    case "$UNIT_FILE" in */systemd/user/z23-citest.service) rm -f "$UNIT_FILE" ;; esac
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    case "${PREFIX:-}"  in /tmp/zcl-linger-prefix.*) rm -rf "$PREFIX"  2>/dev/null || true ;; esac
    case "${DATADIR:-}" in /tmp/zcl-linger-dd.*)     rm -rf "$DATADIR" 2>/dev/null || true ;; esac
}
trap cleanup EXIT INT TERM

# ── (1) REAL `make install` to a throwaway prefix (binaries only) ───
PREFIX="$(mktemp -d /tmp/zcl-linger-prefix.XXXXXX)" || gate_die "mktemp prefix failed"
echo "ci-install-linger: make install -> $PREFIX"
make -C "$REPO_ROOT" install DESTDIR="$PREFIX" PREFIX= >/dev/null 2>&1 \
    || gate_die "make install -> prefix failed"
NODE_BIN="$PREFIX/bin/zclassic23"
RPC_BIN="$PREFIX/bin/zcl-rpc"
[ -x "$NODE_BIN" ] || gate_die "installed node missing/!executable: $NODE_BIN"
[ -x "$RPC_BIN" ]  || gate_die "installed zcl-rpc missing/!executable: $RPC_BIN"

# ── (2) Write an ISOLATED --user unit pointing at the installed binary ──
DATADIR="$(mktemp -d /tmp/zcl-linger-dd.XXXXXX)" || gate_die "mktemp datadir failed"
P2P=39060; RPC=39061; FS=39062; HTTPS=39063; SINK=39999
mkdir -p "$USER_UNIT_DIR"
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Z23 CI install proof (isolated regtest; safe to remove)
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$NODE_BIN -datadir=$DATADIR -regtest -port=$P2P -rpcport=$RPC -fsport=$FS -httpsport=$HTTPS -connect=127.0.0.1:$SINK -nobgvalidation -nolegacyimport -showmetrics=0
EOF
systemctl --user daemon-reload >/dev/null 2>&1 || gate_die "daemon-reload failed"

# ── (3) The operator claim: `systemctl --user start` ────────────────
echo "ci-install-linger: systemctl --user start $UNIT (isolated regtest, ports 3906x)"
systemctl --user start "$UNIT" >/dev/null 2>&1 || gate_die "systemctl --user start $UNIT failed"

# ── (4) Poll: unit active AND the INSTALLED binary answers RPC ──────
ok=0
for _ in $(seq 1 60); do
    if [ "$(systemctl --user is-active "$UNIT" 2>/dev/null)" != "active" ]; then
        echo "ci-install-linger: unit left 'active' during warmup:"
        systemctl --user status "$UNIT" --no-pager -n 20 2>/dev/null | sed 's/^/  /'
        break
    fi
    if [ -f "$DATADIR/.cookie" ]; then
        bc="$(ZCL_DATADIR="$DATADIR" ZCL_RPCPORT="$RPC" "$RPC_BIN" getblockcount 2>/dev/null \
              | sed -E 's/.*"result":(-?[0-9]+).*/\1/')"
        if printf '%s' "$bc" | grep -qE '^-?[0-9]+$'; then
            echo "ci-install-linger: installed binary answered getblockcount=$bc (unit active)"
            ok=1
            break
        fi
    fi
    sleep 0.5
done

if [ "$ok" = 1 ]; then
    echo "=== ci-install-linger: PASSED (real make install + systemctl --user start; node serves RPC) ==="
    exit 0
fi
echo "ci-install-linger: node never served RPC under systemd --user — journal tail:"
journalctl --user -u "$UNIT" --no-pager -n 30 2>/dev/null | sed 's/^/  /' || true
gate_die "operator claim not met (unit up but no RPC)"
