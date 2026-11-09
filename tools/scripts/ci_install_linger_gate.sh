#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ci_install_linger_gate.sh — isolated systemd install/start evidence.
#
# MVP criterion #1 is "single-binary install on clean Ubuntu/Debian: a fresh
# operator runs `make install && systemctl --user start z23-node` and the node
# comes up." The on-host ci-install gate spawns the node directly. This gate
# exercises a real systemd --user start of an isolated fixture unit and checks
# that the installed binary answers RPC; it does not run the canonical unit.
#
# It is fully ISOLATED from the live node:
#   - an exclusively created, unique `z23-citest.*.service` unit,
#   - the binaries installed by the REAL `make install` to a throwaway /tmp
#     prefix (DESTDIR set => the live --user unit install is skipped),
#   - a /tmp regtest datadir + 3906x non-live ports + a dead `-connect` sink +
#     `-nolegacyimport` (so it never reads ~/.zclassic or binds a live port),
#   - teardown stops and removes only its own unit; ownership or stop
#     uncertainty retains the unit and fixture directories for inspection.
#
# Exit: 0 PASS · 2 SKIP (no systemd --user session) · 1 FAIL.

set -uo pipefail

GATE_SRC="${BASH_SOURCE[0]}"
GATE_DIR="$(cd "$(dirname "$GATE_SRC")" && pwd)"
REPO_ROOT="$(cd "$GATE_DIR/../.." && pwd)"

gate_skip() { echo "ci-install-linger: SKIP ($*)"; exit 2; }
gate_die()  { echo "ci-install-linger: FAIL: $*" >&2; exit 1; }

USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT=""
UNIT_FILE=""
UNIT_ID=""
UNIT_DIGEST=""
UNIT_DIR=""
START_ATTEMPTED=0
PREFIX=""
DATADIR=""
FIXTURE_TMP="${TMPDIR:-/tmp}"

# ── Preflight: a usable systemd --user session ──────────────────────
command -v systemctl >/dev/null 2>&1 || gate_skip "systemctl absent"
systemctl --user show-environment >/dev/null 2>&1 || gate_skip "no systemd --user session (run under a logged-in/linger-enabled user)"

# ── Teardown (armed before we create anything) ──────────────────────
unit_owned() {
    [ -n "$UNIT_ID" ] && [ -f "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ] &&
        [ "$(stat -Lc '%d:%i' -- "$UNIT_FILE" 2>/dev/null)" = "$UNIT_ID" ] &&
        [ "$(sha256sum -- "$UNIT_FILE" 2>/dev/null | cut -d' ' -f1)" = "$UNIT_DIGEST" ]
}
cleanup() {
    local prior_status=$?
    trap - EXIT INT TERM
    if [ -n "$UNIT_FILE" ]; then
        if ! unit_owned; then
            echo "ci-install-linger: unit ownership changed; retaining fixture: $UNIT_FILE" >&2
            exit 1
        fi
        if [ "$START_ATTEMPTED" = 1 ] &&
           ! timeout -k 2s 10s systemctl --user stop "$UNIT" >/dev/null 2>&1; then
            echo "ci-install-linger: unit stop failed; retaining fixture: $UNIT" >&2
            exit 1
        fi
        if [ "$START_ATTEMPTED" = 1 ]; then
            local state mainpid
            state="$(timeout -k 2s 10s systemctl --user show "$UNIT" -p ActiveState --value 2>/dev/null)" || state=""
            mainpid="$(timeout -k 2s 10s systemctl --user show "$UNIT" -p MainPID --value 2>/dev/null)" || mainpid=""
            if { [ "$state" != inactive ] && [ "$state" != failed ]; } || [ "$mainpid" != 0 ]; then
                echo "ci-install-linger: unit stop unconfirmed; retaining fixture: $UNIT" >&2
                exit 1
            fi
        fi
        if ! unit_owned || ! rm -- "$UNIT_FILE"; then
            echo "ci-install-linger: unit removal refused; retaining fixture: $UNIT_FILE" >&2
            exit 1
        fi
        systemctl --user daemon-reload >/dev/null 2>&1 || true
        UNIT_FILE=""
    fi
    if [ -n "$UNIT_DIR" ]; then
        rmdir -- "$UNIT_DIR" || exit 1
        UNIT_DIR=""
    fi
    case "${PREFIX:-}"  in "$FIXTURE_TMP"/zcl-linger-prefix.*) rm -rf "$PREFIX" || exit 1 ;; esac
    case "${DATADIR:-}" in "$FIXTURE_TMP"/zcl-linger-dd.*)     rm -rf "$DATADIR" || exit 1 ;; esac
    PREFIX=""
    DATADIR=""
    return "$prior_status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ── (1) REAL `make install` to a throwaway prefix (binaries only) ───
PREFIX="$(mktemp -d "$FIXTURE_TMP/zcl-linger-prefix.XXXXXX")" || gate_die "mktemp prefix failed"
echo "ci-install-linger: make install -> $PREFIX"
make -C "$REPO_ROOT" install DESTDIR="$PREFIX" PREFIX= >/dev/null 2>&1 \
    || gate_die "make install -> prefix failed"
NODE_BIN="$PREFIX/bin/zclassic23"
RPC_BIN="$PREFIX/bin/zcl-rpc"
[ -x "$NODE_BIN" ] || gate_die "installed node missing/!executable: $NODE_BIN"
[ -x "$RPC_BIN" ]  || gate_die "installed zcl-rpc missing/!executable: $RPC_BIN"

# ── (2) Write an ISOLATED --user unit pointing at the installed binary ──
DATADIR="$(mktemp -d "$FIXTURE_TMP/zcl-linger-dd.XXXXXX")" || gate_die "mktemp datadir failed"
P2P=39060; RPC=39061; FS=39062; HTTPS=39063; SINK=39999
mkdir -p "$USER_UNIT_DIR"
UNIT_DIR="$(mktemp -d "$USER_UNIT_DIR/.z23-citest.XXXXXXXX")" || gate_die "unit name reservation failed"
UNIT="${UNIT_DIR##*/.}"
UNIT_CANDIDATE="$USER_UNIT_DIR/$UNIT.service"
load_state="$(timeout -k 2s 10s systemctl --user show "$UNIT" -p LoadState --value 2>/dev/null)" || gate_die "unit load state unavailable"
[ "$load_state" = not-found ] || gate_die "unit name already loaded"
( set -o noclobber; : > "$UNIT_CANDIDATE" ) || gate_die "unit creation failed"
UNIT_FILE="$UNIT_CANDIDATE"
UNIT_ID="$(stat -Lc '%d:%i' -- "$UNIT_FILE")" || gate_die "unit identity unavailable"
UNIT_DIGEST="$(sha256sum -- "$UNIT_FILE" | cut -d' ' -f1)" || gate_die "unit digest unavailable"
cat > "$UNIT_FILE" <<EOF || gate_die "unit write failed"
[Unit]
Description=Z23 CI install proof (isolated regtest; safe to remove)
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$NODE_BIN -datadir=$DATADIR -regtest -port=$P2P -rpcport=$RPC -fsport=$FS -httpsport=$HTTPS -connect=127.0.0.1:$SINK -nobgvalidation -nolegacyimport -showmetrics=0
EOF
UNIT_DIGEST="$(sha256sum -- "$UNIT_FILE" | cut -d' ' -f1)" || gate_die "unit digest unavailable"
unit_owned || gate_die "unit ownership changed before reload"
systemctl --user daemon-reload >/dev/null 2>&1 || gate_die "daemon-reload failed"

# ── (3) The operator claim: `systemctl --user start` ────────────────
echo "ci-install-linger: systemctl --user start $UNIT (isolated regtest, ports 3906x)"
unit_owned || gate_die "unit ownership changed before start"
START_ATTEMPTED=1
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
    cleanup
    echo "=== ci-install-linger: PASSED (real make install + systemctl --user start; node serves RPC) ==="
    exit 0
fi
echo "ci-install-linger: node never served RPC under systemd --user — journal tail:"
journalctl --user -u "$UNIT" --no-pager -n 30 2>/dev/null | sed 's/^/  /' || true
gate_die "operator claim not met (unit up but no RPC)"
