#!/usr/bin/env bash
# fleet_sync.sh — per-box devfleet self-sync loop.
#
# One box runs this on a timer (cron). Each cycle it:
#   1. fast-forwards this checkout to origin/main (fail-closed on divergence);
#   2. rebuilds when HEAD moved;
#   3. restarts any configured instance whose deployed binary is stale, and
#      relaunches any instance that is down (watchdog);
#   4. rewrites deploy/devfleet/<box>.sync with the observed state and pushes
#      it to main when anything material changed or the heartbeat is stale.
#
# Per-box configuration lives OUTSIDE the repo at
# ~/.config/zclassic23-fleetsync/<box>.env (uncommitted: local paths, clearnet
# endpoints, and unit names never land on GitHub). Other fleet boxes adopt
# this loop by writing their own local env and a crontab entry after pulling
# main.
#
# Usage: tools/scripts/fleet_sync.sh <box>

set -euo pipefail

BOX="${1:?usage: fleet_sync.sh <box>}"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SELF_DIR/../.." && pwd)"
# Per-box configuration lives OUTSIDE the repo at
# ~/.config/zclassic23-fleetsync/<box>.env (uncommitted: it holds local paths,
# clearnet endpoints, and unit names that must never land on GitHub). A
# committed deploy/devfleet/<box>.env is accepted only as a legacy fallback.
ENV_FILE="${FLEET_SYNC_ENV:-$HOME/.config/zclassic23-fleetsync/$BOX.env}"
if [ ! -f "$ENV_FILE" ] && [ -f "$REPO_DIR/deploy/devfleet/$BOX.env" ]; then
    ENV_FILE="$REPO_DIR/deploy/devfleet/$BOX.env"
fi
if [ ! -f "$ENV_FILE" ]; then
    echo "fleet_sync: missing $ENV_FILE" >&2
    exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

cd "$REPO_DIR"
STATE_DIR="$HOME/.local/state/zclassic23-fleetsync"
mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/$BOX.lock"
flock -n 9 || exit 0

SYNC_FILE="deploy/devfleet/$BOX.sync"
PUSH_STAMP="$STATE_DIR/$BOX.last-push"
PUSH_HEARTBEAT_SECONDS="${PUSH_HEARTBEAT_SECONDS:-1800}"
RESTART_PROD="${RESTART_PROD:-manual}"

log() { printf '%s fleet_sync[%s] %s\n' "$(date -u +%FT%TZ)" "$BOX" "$*"; }

now_epoch() { date +%s; }

devfleet_node_up() {
    build/bin/zclassic23 -datadir="$DEVFLEET_DATADIR" -rpcport="$DEVFLEET_RPCPORT" \
        getconnectioncount >/dev/null 2>&1
}

devfleet_peers() {
    build/bin/zclassic23 -datadir="$DEVFLEET_DATADIR" -rpcport="$DEVFLEET_RPCPORT" \
        getconnectioncount 2>/dev/null || printf '0'
}

devfleet_start() {
    setsid nohup build/bin/zclassic23 -datadir="$DEVFLEET_DATADIR" \
        -port="$DEVFLEET_PORT" -rpcport="$DEVFLEET_RPCPORT" $DEVFLEET_FLAGS \
        > "$DEVFLEET_DATADIR/node.log" 2>&1 < /dev/null &
}

devfleet_stop() {
    pids="$(pgrep -f "build/bin/zclassic23 -datadir=$DEVFLEET_DATADIR" || true)"
    [ -z "$pids" ] && return 0
    kill $pids 2>/dev/null || true
    for _ in $(seq 1 18); do
        pgrep -f "build/bin/zclassic23 -datadir=$DEVFLEET_DATADIR" >/dev/null || return 0
        sleep 5
    done
    return 1
}

devfleet_wait_rpc() {
    for _ in $(seq 1 36); do
        devfleet_node_up && return 0
        sleep 5
    done
    return 1
}

# --- 1. sync source -------------------------------------------------------

git fetch origin --quiet
OLD_HEAD="$(git rev-parse HEAD)"
NEW_MAIN="$(git rev-parse origin/main)"
SYNC_ERROR=""

if [ "$OLD_HEAD" != "$NEW_MAIN" ]; then
    if ! git merge --ff-only origin/main --quiet; then
        SYNC_ERROR="ff_pull_failed"
        log "ERROR ff-only pull to $NEW_MAIN failed; preserving local state"
    elif ! make -j"$(nproc)" > "$STATE_DIR/build.log" 2>&1; then
        SYNC_ERROR="build_failed"
        log "ERROR build failed at $(git rev-parse HEAD); see $STATE_DIR/build.log"
    else
        log "synced $OLD_HEAD -> $(git rev-parse HEAD) and rebuilt"
    fi
fi
HEAD_NOW="$(git rev-parse HEAD)"
HEAD_MOVED=0
[ "$OLD_HEAD" != "$HEAD_NOW" ] && HEAD_MOVED=1

# --- 2. devfleet instance: restart on new binary, relaunch when down ------

DEVFLEET_ACTION="none"
if [ -z "$SYNC_ERROR" ]; then
    if devfleet_node_up; then
        if [ "$HEAD_MOVED" = 1 ]; then
            if devfleet_stop && { devfleet_start; devfleet_wait_rpc; }; then
                DEVFLEET_ACTION="restarted"
                log "devfleet node restarted on $HEAD_NOW"
            else
                SYNC_ERROR="devfleet_restart_failed"
                log "ERROR devfleet node restart failed"
            fi
        fi
    else
        devfleet_stop || true
        if devfleet_start && devfleet_wait_rpc; then
            DEVFLEET_ACTION="relaunched"
            log "devfleet node was down; relaunched"
        else
            SYNC_ERROR="devfleet_relaunch_failed"
            log "ERROR devfleet node down and relaunch failed"
        fi
    fi
fi

DEVFLEET_NODE_UP=0
DEVFLEET_PEERS=0
if devfleet_node_up; then
    DEVFLEET_NODE_UP=1
    DEVFLEET_PEERS="$(devfleet_peers)"
fi

# --- 3. production instance (owner-authorized auto-update) -----------------
# Restarting production resets any running soak clock; the owner accepted
# that tradeoff by setting RESTART_PROD=auto in the box env file.

PROD_ACTION="disabled"
if [ "$RESTART_PROD" = "auto" ] && [ -n "${PROD_UNIT:-}" ] && [ -n "${PROD_BIN:-}" ]; then
    PROD_SYSTEMCTL="${PROD_SYSTEMCTL:-systemctl --user}"
    # cron has no session bus; lingering users still have one.
    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    PROD_PENDING="$STATE_DIR/$BOX.prod-pending-restart"
    if [ -z "$SYNC_ERROR" ]; then
        if ! cmp -s build/bin/zclassic23 "$PROD_BIN"; then
            install -m 0755 build/bin/zclassic23 "$PROD_BIN.fleetsync-new"
            mv "$PROD_BIN.fleetsync-new" "$PROD_BIN"
            touch "$PROD_PENDING"
            log "production binary updated; restart pending"
        fi
        if [ -f "$PROD_PENDING" ]; then
            if $PROD_SYSTEMCTL restart "$PROD_UNIT" 2>"$STATE_DIR/prod-restart.err"; then
                rm -f "$PROD_PENDING"
                PROD_ACTION="updated+restarted"
                log "production $PROD_UNIT restarted"
            else
                PROD_ACTION="restart_error:$(head -1 "$STATE_DIR/prod-restart.err")"
                SYNC_ERROR="prod_restart_failed"
                log "ERROR production restart failed: $PROD_ACTION"
            fi
        elif ! $PROD_SYSTEMCTL is-active --quiet "$PROD_UNIT"; then
            if $PROD_SYSTEMCTL restart "$PROD_UNIT" 2>"$STATE_DIR/prod-restart.err"; then
                PROD_ACTION="relaunched"
                log "production unit was inactive; relaunched"
            else
                PROD_ACTION="relaunch_error:$(head -1 "$STATE_DIR/prod-restart.err")"
                SYNC_ERROR="prod_relaunch_failed"
                log "ERROR production relaunch failed: $PROD_ACTION"
            fi
        else
            PROD_ACTION="current"
        fi
    else
        PROD_ACTION="skipped:$SYNC_ERROR"
    fi
fi

# --- 4. publish heartbeat --------------------------------------------------

LAST_PUSH=0
[ -f "$PUSH_STAMP" ] && LAST_PUSH="$(cat "$PUSH_STAMP")"
HEARTBEAT_DUE=0
[ $(( $(now_epoch) - LAST_PUSH )) -ge "$PUSH_HEARTBEAT_SECONDS" ] && HEARTBEAT_DUE=1

NEW_CONTENT="BOX=$BOX
LAST_SYNC_AT=$(date -u +%FT%TZ)
LAST_SYNC_SHA=$HEAD_NOW
ORIGIN_MAIN=$NEW_MAIN
DEVFLEET_NODE_UP=$DEVFLEET_NODE_UP
DEVFLEET_PEERS=$DEVFLEET_PEERS
DEVFLEET_ACTION=$DEVFLEET_ACTION
PROD_ACTION=$PROD_ACTION
SYNC_ERROR=${SYNC_ERROR:-none}
"

OLD_CONTENT=""
[ -f "$SYNC_FILE" ] && OLD_CONTENT="$(cat "$SYNC_FILE")"
# Material change = anything except the timestamp line.
material_changed=0
if [ "$(printf '%s\n' "$OLD_CONTENT" | grep -v '^LAST_SYNC_AT=')" != \
     "$(printf '%s\n' "$NEW_CONTENT" | grep -v '^LAST_SYNC_AT=')" ]; then
    material_changed=1
fi

if [ "$material_changed" = 0 ] && [ "$HEARTBEAT_DUE" = 0 ]; then
    log "no material change; heartbeat fresh; nothing to push"
    exit 0
fi

printf '%s' "$NEW_CONTENT" > "$SYNC_FILE"

# Push only from a clean ff position; never stomp unrelated dirty work.
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    log "local HEAD diverged from origin/main before commit; skipping push this cycle"
    exit 0
fi

git add "$SYNC_FILE"
git -c user.name="$BOX-fleetsync" -c user.email="$BOX@devfleet.local" \
    commit --quiet -m "devfleet: $BOX sync heartbeat"
pushed=0
for attempt in 1 2 3; do
    git fetch origin --quiet
    if git rebase origin/main --quiet 2>/dev/null && git push origin main --quiet; then
        pushed=1
        break
    fi
    git rebase --abort 2>/dev/null || true
    sleep $((attempt * 5))
done
if [ "$pushed" = 1 ]; then
    now_epoch > "$PUSH_STAMP"
    log "heartbeat pushed: $SYNC_FILE"
else
    log "ERROR push failed after 3 attempts; commit kept locally"
fi
