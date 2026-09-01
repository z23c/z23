#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zcl-portfwd-setup.sh — one-time setup for the clearnet port forwarder.
#
# THE WHOLE POINT: the operator runs ONE privileged command, ONCE, ever:
#
#       sudo bash tools/scripts/zcl-portfwd-setup.sh
#
# The ONLY thing that needs root is a single `setcap` on a project-owned forwarder
# binary so it may bind ports <1024. Everything else (build, install the user unit,
# enable+start the service) is done as the operator with NO sudo. After this, an AI
# agent / the operator manages the service with `systemctl --user ...` forever:
#
#       systemctl --user enable --now zcl-portfwd      # start + persist across reboot
#       systemctl --user {start,stop,restart,status} zcl-portfwd
#
# It forwards public 443 -> 127.0.0.1:8443 (node HTTPS) and 80 -> 127.0.0.1:8080
# (node HTTP redirect). The node keeps binding the high ports as the unprivileged
# user; only this tiny forwarder gets the one capability. The cap lives on the
# forwarder file, so it SURVIVES node redeploys (`make deploy`). See
# docs/BLOCK_EXPLORER_HOSTING.md and deploy/systemd/zcl-portfwd.service.
#
# Modes:
#   (default)     build + setcap (the one sudo) + install unit + enable+start
#   --status      show forwarder/cap/unit/service state (no changes, no sudo)
#   --uninstall   stop + disable + remove unit + forwarder (no sudo; cap dies with the file)
#
# Idempotent and safe to re-run.

set -uo pipefail

# ── Resolve the operator (the user whose --user session owns the service) ──
# When invoked via `sudo`, $SUDO_USER is the human; otherwise it's us.
OP_USER="${SUDO_USER:-$(id -un)}"
OP_HOME="$(eval echo "~$OP_USER")"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FWD_SRC="$REPO_ROOT/tools/zcl_portfwd.c"
UNIT_SRC="$REPO_ROOT/platform/deploy/systemd/zcl-portfwd.service"
FWD_BIN="$OP_HOME/.local/bin/zcl-portfwd"
UNIT_DIR="$OP_HOME/.config/systemd/user"
UNIT_DST="$UNIT_DIR/zcl-portfwd.service"
CAP="cap_net_bind_service=+ep"

say()  { printf '%s\n' "$*"; }
die()  { printf 'zcl-portfwd-setup: ERROR: %s\n' "$*" >&2; exit 1; }

# Run a command AS the operator (drop root if we were invoked via sudo).
as_op() {
    if [ "$(id -un)" = "$OP_USER" ]; then
        "$@"
    else
        # Preserve the user systemd session env so `systemctl --user` works.
        local uid; uid="$(id -u "$OP_USER")"
        sudo -u "$OP_USER" \
            XDG_RUNTIME_DIR="/run/user/$uid" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            "$@"
    fi
}

build_forwarder() {
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || die "no C compiler (cc/gcc)"
    local CC; CC="$(command -v cc || command -v gcc)"
    as_op mkdir -p "$(dirname "$FWD_BIN")"
    say "  building forwarder -> $FWD_BIN"
    as_op "$CC" -O2 -Wall -Wextra -std=c2x -o "$FWD_BIN" "$FWD_SRC" \
        || die "forwarder failed to compile"
}

install_unit() {
    as_op mkdir -p "$UNIT_DIR"
    say "  installing user unit -> $UNIT_DST"
    # Use install via the operator so ownership/mode are right.
    as_op install -m 644 "$UNIT_SRC" "$UNIT_DST" || die "could not install unit"
    as_op systemctl --user daemon-reload || say "  (daemon-reload deferred — no live --user session here)"
}

enable_start() {
    say "  enabling + starting zcl-portfwd (linger user service)"
    if ! as_op systemctl --user enable --now zcl-portfwd 2>/dev/null; then
        say "  NOTE: could not reach the operator's --user session from here."
        say "        As $OP_USER, run:  systemctl --user enable --now zcl-portfwd"
    fi
}

do_setcap() {
    [ -x "$FWD_BIN" ] || die "forwarder not built yet ($FWD_BIN missing)"
    if [ "$(id -u)" -ne 0 ]; then
        # Not root: we did the unprivileged parts; tell the human the ONE command.
        say ""
        say "  >>> ONE privileged step remains. Run exactly this:"
        say ""
        say "      sudo setcap '$CAP' $FWD_BIN"
        say ""
        say "  Then start the service (no sudo):"
        say "      systemctl --user enable --now zcl-portfwd"
        return 1
    fi
    say "  setcap '$CAP' $FWD_BIN   (the one privileged action)"
    setcap "$CAP" "$FWD_BIN" || die "setcap failed (is libcap setcap installed?)"
    return 0
}

cmd_install() {
    say "zcl-portfwd setup for user '$OP_USER' (home: $OP_HOME)"
    [ -f "$FWD_SRC" ]  || die "missing $FWD_SRC"
    [ -f "$UNIT_SRC" ] || die "missing $UNIT_SRC"
    build_forwarder
    install_unit
    # Linger so the --user service survives logout/reboot (usually already on).
    if command -v loginctl >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        loginctl enable-linger "$OP_USER" 2>/dev/null || true
    fi
    if do_setcap; then
        # We are root AND the cap is set: finish by enabling+starting as the operator.
        enable_start
        say ""
        say "DONE. Forwarding 443->8443 and 80->8080 is live."
        say "Manage it (no sudo): systemctl --user {start,stop,restart,status} zcl-portfwd"
    fi
    # Always remind about the 8080 collision.
    say ""
    say "  8080 NOTE: if the old 'zcl-supply' still listens on 127.0.0.1:8080,"
    say "             retire it first (see docs/BLOCK_EXPLORER_HOSTING.md §B) — else"
    say "             http://...:80 forwards to the wrong backend."
}

cmd_status() {
    say "== zcl-portfwd status =="
    say "operator        : $OP_USER ($OP_HOME)"
    if [ -x "$FWD_BIN" ]; then
        say "forwarder binary: $FWD_BIN  [present]"
        if command -v getcap >/dev/null 2>&1; then
            local c; c="$(getcap "$FWD_BIN" 2>/dev/null)"
            if printf '%s' "$c" | grep -q cap_net_bind_service; then
                say "capability      : GRANTED  ($c)"
            else
                say "capability      : NOT set  -> run: sudo setcap '$CAP' $FWD_BIN"
            fi
        fi
    else
        say "forwarder binary: $FWD_BIN  [MISSING — run setup]"
    fi
    [ -f "$UNIT_DST" ] && say "user unit       : $UNIT_DST  [installed]" \
                       || say "user unit       : [not installed]"
    if command -v systemctl >/dev/null 2>&1; then
        local act ena
        act="$(as_op systemctl --user is-active  zcl-portfwd 2>/dev/null)"; [ -n "$act" ] || act="inactive"
        ena="$(as_op systemctl --user is-enabled zcl-portfwd 2>/dev/null)"; [ -n "$ena" ] || ena="disabled"
        say "service state   : active=$act enabled=$ena"
    fi
    # Surface the 8080 collision if visible.
    if command -v ss >/dev/null 2>&1; then
        if grep -q '127.0.0.1:8080' <<<"$(ss -ltnp 2>/dev/null)"; then
            local who; who="$(ss -ltnp 2>/dev/null | grep '127.0.0.1:8080' | grep -oE 'users:\(\("[^"]+' | head -1 | sed 's/.*"//')"
            say "8080 listener   : $who is on 127.0.0.1:8080 (must be the NODE, not zcl-supply)"
        fi
    fi
}

cmd_uninstall() {
    say "uninstalling zcl-portfwd for $OP_USER"
    as_op systemctl --user disable --now zcl-portfwd 2>/dev/null || true
    [ -f "$UNIT_DST" ] && as_op rm -f "$UNIT_DST" && say "  removed $UNIT_DST"
    as_op systemctl --user daemon-reload 2>/dev/null || true
    # Removing the file removes its capability too.
    [ -e "$FWD_BIN" ] && as_op rm -f "$FWD_BIN" && say "  removed $FWD_BIN (capability gone with it)"
    say "done."
}

case "${1:---install}" in
    --install|"") cmd_install ;;
    --status)     cmd_status ;;
    --uninstall)  cmd_uninstall ;;
    -h|--help)
        say "usage: [sudo] bash tools/scripts/zcl-portfwd-setup.sh [--install|--status|--uninstall]"
        say "  --install    (default) build forwarder, install user unit, the one setcap, start"
        say "  --status     show forwarder/cap/unit/service state (no sudo, no changes)"
        say "  --uninstall  stop + remove the service and forwarder (no sudo)"
        ;;
    *) die "unknown arg '$1' (try --help)" ;;
esac
