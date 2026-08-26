#!/usr/bin/env bash
# fleet_sync.sh — keep one operator-owned box current with origin/main.
#
# This repository designates no fleet and grants no box any authority. Anyone
# may run one machine or twenty; this script is the small loop that keeps a
# machine you own following public `main` and running the bytes it just built.
# Everything it learns stays on that machine.
#
# One box runs this on a timer (cron). Each cycle it:
#   1. fast-forwards this checkout to origin/main, refusing loudly — without
#      touching HEAD — when local commits or uncommitted product edits are in
#      the way;
#   2. rebuilds when HEAD moved;
#   3. asks systemd to restart the box's node unit when the RUNNING daemon's
#      baked source identity no longer matches the built binary, or when the
#      unit is failed/inactive. Type=notify "activating" with a live MainPID
#      is a boot, not a down unit — restarting it aborts IBD;
#   4. records what it observed to the box's LOCAL state file under
#      ${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23/fleet/<box>.sync.
#
# ── IT NEVER COMMITS AND NEVER PUSHES ─────────────────────────────────────
# An earlier revision wrote its observations to a tracked file, committed
# them, and pushed the commit to origin/main every cycle. That is why public
# history carried thousands of per-box heartbeat commits naming four specific
# machines, their onion addresses and their ports — which made a project
# anyone can join look like it had a privileged in-crowd. There is no code
# path here that runs `git commit`, `git push`, or `git rebase` any more, and
# `tools/lint/` should keep it that way. What a box observes is that box's
# business; if an operator wants to publish it, that is a deliberate,
# separate act.
#
# ── WHO OWNS THE NODE PROCESS ─────────────────────────────────────────────
# systemd does, through the box's node unit (default
# `zcl23-devfleet@<box>.service`, overridable with MESH_UNIT). This script
# NEVER launches, signals, or kills the node itself. It used to: `setsid nohup
# build/bin/zclassic23 ... &` plus a pgrep/kill stop. Once the unit existed,
# that launcher became a way to put a SECOND zclassic23 process on ONE datadir
# — which corrupts it. There is deliberately NO fallback launcher here: if the
# unit is not installed this cycle fails with a named SYNC_ERROR and starts
# nothing. A silent fallback would reintroduce the double-node hazard at
# exactly the moment nobody is watching.
#
# The unit is Type=notify with NotifyAccess=main, so `systemctl restart`
# already returns only after the node has sent READY=1 (or TimeoutStartSec
# expires). Do not add an RPC/pgrep readiness poll on top of it: that is a
# second, weaker copy of a guarantee systemd already makes, and the old
# 36x5s poll is what used to hide a failed start behind a timeout.
#
# The unit also owns the node's stdout/stderr with an `append:` redirect. This
# script must never redirect that log itself, and in particular must never
# truncate it: the previous launcher opened node.log with `>` and destroyed,
# on every restart, exactly the evidence of the crash it was restarting from.
# Rotation is a separate concern with its own owner; it does not belong here.
#
# ── SELF-HEALING RULES ────────────────────────────────────────────────────
# Do not relax these without re-reading the incident that motivated them — a
# box stuck 178-222 commits behind because a stalled push or a dirty file
# silently wedged the loop forever:
#   - A checkout that is only BEHIND origin/main fast-forwards and rebuilds.
#   - A HEAD carrying any commit not on origin/main is left exactly as-is: no
#     rebase, no merge, no reset. A human resolves it. The one exception is
#     narrow and named below (legacy published-state commits), because those
#     commits are this script's own historical droppings, not anyone's work.
#   - An uncommitted edit to a tracked product file is never touched, rebased
#     over, or discarded — but it also must not go quiet: the file name is
#     recorded in the local state so the operator can see why the box stopped
#     moving.
#
# ── MIGRATION OFF THE OLD COMMITTED STATE ─────────────────────────────────
# Boxes that ran the old loop have, in their checkout, published state files
# under deploy/<mesh dir>/ that are now untracked, and possibly local commits
# that only ever touched them. Both would wedge the fast-forward forever. So
# once, and only for paths whose whole content is published state, this script
# copies them to the local state directory and then clears them out of the
# way. It never does this for a path outside that set, and never for a commit
# that touches anything else.
#
# ── CONFIGURATION ─────────────────────────────────────────────────────────
# Per-box configuration lives OUTSIDE the repo at
# ~/.config/zclassic23-fleetsync/<box>.env (uncommitted: local paths, clearnet
# endpoints, and unit names never land in a public repository). See
# deploy/devfleet/README.md and the .example files beside it.
#
# Usage: tools/scripts/fleet_sync.sh <box>

set -euo pipefail

BOX="${1:?usage: fleet_sync.sh <box>}"
case "$BOX" in
    ''|*/*|.|..) echo "fleet_sync: invalid box label '$BOX'" >&2; exit 2 ;;
esac

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SELF_DIR/../.." && pwd)"

# Per-box configuration lives OUTSIDE the repo. A file inside the checkout is
# accepted only as a legacy fallback so an existing box does not wedge on the
# first cycle after this change; it is gitignored and must never be committed.
ENV_FILE="${FLEET_SYNC_ENV:-$HOME/.config/zclassic23-fleetsync/$BOX.env}"
LEGACY_DIR="$REPO_DIR/deploy/devfleet"
if [ ! -f "$ENV_FILE" ] && [ -f "$LEGACY_DIR/$BOX.env" ]; then
    ENV_FILE="$LEGACY_DIR/$BOX.env"
fi
if [ ! -f "$ENV_FILE" ]; then
    echo "fleet_sync: no local mesh configured for '$BOX'" >&2
    echo "fleet_sync: expected $HOME/.config/zclassic23-fleetsync/$BOX.env" >&2
    echo "fleet_sync: see deploy/devfleet/README.md" >&2
    exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

cd "$REPO_DIR"

# The ONE canonical reader for a build's baked source identity. Nine inline
# copies of this parser had diverged (a greedy sed returns the LAST of
# agentbuild's several source_id_sha256 values, i.e. a runtime value, not the
# baked one) — tools/lint/check_identity_parser_single.sh exists to stop a
# tenth. zcl_binary_source_id() is the only identity reader used below.
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$REPO_DIR/tools/scripts/source_identity_lib.sh"
# fleet_state_dir(): the one definition of where local mesh state lives.
# shellcheck source=tools/scripts/fleet_source_status.sh
. "$REPO_DIR/tools/scripts/fleet_source_status.sh"

# Run state (lock, counters, build log). Deliberately NOT moved: a cycle
# started by the previous revision may still be holding this lock.
STATE_DIR="$HOME/.local/state/zclassic23-fleetsync"
mkdir -p "$STATE_DIR"

# Published-observation state. This is the file the old loop used to commit.
MESH_DIR="$(fleet_state_dir)"
mkdir -p "$MESH_DIR"
SYNC_FILE="$MESH_DIR/$BOX.sync"

log() { printf '%s fleet_sync[%s] %s\n' "$(date -u +%FT%TZ)" "$BOX" "$*"; }

# A contended lock is not an error — the previous cycle is still running, and
# overlapping cycles on one checkout is exactly what this lock prevents. But
# `flock -n 9 || exit 0` said nothing at all, so an operator reading the cron
# log saw a successful run that did nothing, with no way to tell that apart
# from "nothing to do" or "never started". Exit 0, loudly.
exec 9>"$STATE_DIR/$BOX.lock"
if ! flock -n 9; then
    log "REFUSED cycle: fleet lock busy"
    exit 0
fi

STALE_STREAK_FILE="$STATE_DIR/$BOX.stale-streak"
RESTART_PROD="${RESTART_PROD:-manual}"
# MESH_* are the current names. The DEVFLEET_* spellings are what existing
# operator env files use and are still honoured, so upgrading this script
# never requires editing a box's uncommitted config.
NODE_UNIT="${MESH_UNIT:-${DEVFLEET_UNIT:-zcl23-devfleet@$BOX.service}}"
NODE_DATADIR="${MESH_DATADIR:-${DEVFLEET_DATADIR:-}}"
NODE_RPCPORT="${MESH_RPCPORT:-${DEVFLEET_RPCPORT:-}}"

# cron has no session bus; lingering users still have one. Both the node unit
# and the optional production unit are user units, so this must be set before
# the first systemctl call, not just before the production block.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# --- migration off the old committed state ----------------------------------
# Paths whose whole content is published per-box observation. Nothing else
# under the legacy directory is ever copied, reset, or discarded by this
# script; README.md and the .example templates are tracked product files and
# are treated as such. Kept as an array so the shell never glob-expands them
# before git sees them as pathspecs.
LEGACY_STATE_PATHSPEC=(
    'deploy/devfleet/*.txt'
    'deploy/devfleet/*.sync'
    'deploy/devfleet/*.status'
    'deploy/devfleet/*.identity'
    'deploy/devfleet/*.jsonl'
)

is_legacy_state_path() {
    case "$1" in
        deploy/devfleet/*.txt)      return 0 ;;
        deploy/devfleet/*.sync)     return 0 ;;
        deploy/devfleet/*.status)   return 0 ;;
        deploy/devfleet/*.identity) return 0 ;;
        deploy/devfleet/*.jsonl)    return 0 ;;
    esac
    return 1
}

# Preserve any leftover published state before anything can clear it. Copy,
# never move, and never over an existing local file: the local copy is the
# live one and a stale checkout copy must not clobber it.
preserve_legacy_state() {
    local f b
    [ -d "$LEGACY_DIR" ] || return 0
    for f in "$LEGACY_DIR"/*.txt "$LEGACY_DIR"/*.sync "$LEGACY_DIR"/*.status \
             "$LEGACY_DIR"/*.identity "$LEGACY_DIR"/*.jsonl; do
        [ -f "$f" ] || continue
        b="${f##*/}"
        [ -e "$MESH_DIR/$b" ] && continue
        cp -p "$f" "$MESH_DIR/$b" 2>/dev/null \
            && log "preserved legacy published state -> $MESH_DIR/$b"
    done
    return 0
}

# Tracked paths, dirty in the working tree, that are legacy published state.
dirty_legacy_state_paths() {
    git status --porcelain --untracked-files=no -- \
        "${LEGACY_STATE_PATHSPEC[@]}" 2>/dev/null | cut -c4- || true
}

# Tracked files with uncommitted changes that are NOT legacy published state.
# These are product edits: never touched, never rebased over, never discarded.
dirty_product_files() {
    local all legacy
    all="$(git status --porcelain --untracked-files=no | cut -c4- || true)"
    legacy="$(dirty_legacy_state_paths)"
    if [ -z "$legacy" ]; then
        printf '%s' "$all"
        return 0
    fi
    printf '%s\n' "$all" | grep -vxF "$legacy" || true
}

# True only if every commit reachable from $2 but not from $1 touches nothing
# except legacy published state. Those commits are this script's own
# historical droppings; anything else is someone's work and stays put.
local_commits_are_legacy_state_only() {
    local from="$1" to="$2" c f files
    for c in $(git rev-list "$from..$to"); do
        files="$(git show --name-only --pretty=format: "$c" | sed '/^$/d')"
        [ -n "$files" ] || return 1
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            is_legacy_state_path "$f" || return 1
        done <<<"$files"
    done
    return 0
}

# --- the node process: systemd is the supervisor ----------------------------

node_unit_load_state() {
    systemctl --user show "$NODE_UNIT" -p LoadState --value 2>/dev/null || true
}

node_unit_active() {
    systemctl --user is-active --quiet "$NODE_UNIT"
}

node_unit_main_pid() {
    local pid
    pid="$(systemctl --user show "$NODE_UNIT" -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|*[!0-9]*) pid=0 ;; esac
    printf '%s' "$pid"
}

# Type=notify stays "activating" until READY=1 (onion descriptor published).
# `systemctl is-active` is false in that state, which used to look like a
# down unit and trigger restart — killing a still-loading block index.
node_boot_in_progress() {
    local st pid
    st="$(systemctl --user is-active "$NODE_UNIT" 2>/dev/null || true)"
    [ "$st" = "activating" ] || return 1
    pid="$(node_unit_main_pid)"
    [ "$pid" != 0 ] && [ -d "/proc/$pid" ]
}

# Type=notify: this blocks until the node reports READY=1 or TimeoutStartSec
# expires. Nothing else here waits on the node.
node_restart() {
    systemctl --user restart "$NODE_UNIT" 2>"$STATE_DIR/node-restart.err"
}

# Measure, never assume. NODE_SOURCE is only ever set from a comparison of two
# baked identities actually read this cycle: the built binary's, and the
# RUNNING process's, taken from its kernel-pinned /proc/<pid>/exe inode (still
# correct after the path was replaced). One definition, called both before and
# after a restart, because "systemctl restart returned 0" is activity, not the
# result — it does not prove the new process runs the bytes we just built.
# Reads BUILT_SOURCE_ID; writes UNIT_PID, RUNNING_SOURCE_ID, NODE_SOURCE.
measure_node_source() {
    UNIT_PID="$(node_unit_main_pid)"
    RUNNING_SOURCE_ID=""
    if [ "$UNIT_PID" != 0 ] && [ -r "/proc/$UNIT_PID/exe" ]; then
        RUNNING_SOURCE_ID="$(zcl_binary_source_id "/proc/$UNIT_PID/exe")"
    fi
    if [ -z "$BUILT_SOURCE_ID" ] || [ -z "$RUNNING_SOURCE_ID" ]; then
        NODE_SOURCE="unreadable"
    elif [ "$BUILT_SOURCE_ID" = "$RUNNING_SOURCE_ID" ]; then
        NODE_SOURCE="current"
    else
        NODE_SOURCE="drifted"
    fi
}

node_rpc_up() {
    [ -n "$NODE_DATADIR" ] && [ -n "$NODE_RPCPORT" ] || return 1
    build/bin/zclassic23 -datadir="$NODE_DATADIR" -rpcport="$NODE_RPCPORT" \
        getconnectioncount >/dev/null 2>&1
}

node_peers() {
    build/bin/zclassic23 -datadir="$NODE_DATADIR" -rpcport="$NODE_RPCPORT" \
        getconnectioncount 2>/dev/null || printf '0'
}

# --- staleness bookkeeping (crosses cycles) ---------------------------------
# STALE_CYCLES recorded in the state file reflects cycles completed BEFORE
# this one. It is updated for the next cycle to read no matter which exit path
# we take.
PREV_STREAK=0
[ -f "$STALE_STREAK_FILE" ] && PREV_STREAK="$(cat "$STALE_STREAK_FILE" 2>/dev/null || echo 0)"
case "$PREV_STREAK" in ''|*[!0-9]*) PREV_STREAK=0 ;; esac
CYCLE_OK=0
update_stale_streak() {
    if [ "$CYCLE_OK" = 1 ]; then
        printf '0\n' > "$STALE_STREAK_FILE" 2>/dev/null || true
    else
        printf '%s\n' "$((PREV_STREAK + 1))" > "$STALE_STREAK_FILE" 2>/dev/null || true
    fi
}
trap update_stale_streak EXIT

# --- 1. sync source -------------------------------------------------------

preserve_legacy_state

git fetch origin --quiet
OLD_HEAD="$(git rev-parse HEAD)"
# The head this cycle STARTED at, never reassigned. HEAD_MOVED is measured
# against this, so a move made by the legacy-commit drop below still counts as
# a move and still earns the rebuild — otherwise a box could land on new main
# while still holding, and still running, the previous build.
CYCLE_START_HEAD="$OLD_HEAD"
NEW_MAIN="$(git rev-parse origin/main)"
SYNC_ERROR=""

LOCAL_ONLY="$(git rev-list --count "$NEW_MAIN..$OLD_HEAD" 2>/dev/null || echo 0)"

# Clear leftover working-tree copies of published state so they cannot block a
# fast-forward. Their content was preserved above; regenerating them is what
# the local state file is for. This runs BEFORE the commit drop below, because
# `git reset --keep` correctly refuses while such a file is still modified.
LEGACY_DIRTY="$(dirty_legacy_state_paths)"
if [ -n "$LEGACY_DIRTY" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        git checkout -- "$p" 2>/dev/null || true
    done <<<"$LEGACY_DIRTY"
    log "cleared leftover published-state edits from the checkout"
fi

# One-time migration, narrowly scoped: drop local commits that only ever
# touched published state. `git reset --keep` refuses rather than destroying
# an uncommitted local modification, so this cannot eat someone's work.
if [ "$LOCAL_ONLY" -gt 0 ] && local_commits_are_legacy_state_only "$NEW_MAIN" "$OLD_HEAD"; then
    if git reset --keep "$NEW_MAIN" --quiet 2>/dev/null; then
        log "dropped $LOCAL_ONLY legacy published-state commit(s); state now lives in $MESH_DIR"
        OLD_HEAD="$(git rev-parse HEAD)"
        LOCAL_ONLY=0
    else
        log "could not drop legacy published-state commit(s); leaving HEAD alone"
    fi
fi

BEHIND="$(git rev-list --count "$OLD_HEAD..$NEW_MAIN" 2>/dev/null || echo 0)"
DIRTY="$(dirty_product_files)"
DIRTY_ONELINE=""
[ -n "$DIRTY" ] && DIRTY_ONELINE="$(printf '%s' "$DIRTY" | paste -sd, -)"

if [ "$LOCAL_ONLY" -gt 0 ]; then
    SYNC_ERROR="local_commits:${LOCAL_ONLY}_ahead"
    [ -n "$DIRTY_ONELINE" ] && SYNC_ERROR="$SYNC_ERROR+dirty:$DIRTY_ONELINE"
    log "ERROR HEAD carries $LOCAL_ONLY commit(s) not on origin/main; this needs a human. Leaving HEAD at $OLD_HEAD untouched."
    log "  local commit(s): $(git log --oneline "$NEW_MAIN..$OLD_HEAD" | tr '\n' ';')"
    [ -n "$DIRTY_ONELINE" ] && log "  also dirty: $DIRTY_ONELINE"
elif [ -n "$DIRTY" ]; then
    SYNC_ERROR="dirty_tracked_file:$DIRTY_ONELINE"
    log "ERROR uncommitted change(s) to tracked product file(s) [$DIRTY_ONELINE]; preserving local state, recording this in $SYNC_FILE"
elif [ "$BEHIND" -gt 0 ]; then
    if ! git merge --ff-only origin/main --quiet; then
        SYNC_ERROR="ff_pull_failed"
        log "ERROR ff-only pull to $NEW_MAIN failed; preserving local state"
    fi
fi

HEAD_NOW="$(git rev-parse HEAD)"
HEAD_MOVED=0
[ "$CYCLE_START_HEAD" != "$HEAD_NOW" ] && HEAD_MOVED=1

# ONE build, gated on the head actually having moved this cycle — by the
# fast-forward or by the legacy-commit drop, it makes no difference. Keeping
# the build inside the fast-forward branch is what let a box land on new main
# holding the previous binary, with nothing left to notice.
if [ "$HEAD_MOVED" = 1 ] && [ -z "$SYNC_ERROR" ]; then
    if ! make -j"$(nproc)" > "$STATE_DIR/build.log" 2>&1; then
        SYNC_ERROR="build_failed"
        log "ERROR build failed at $HEAD_NOW; see $STATE_DIR/build.log"
    else
        log "synced $CYCLE_START_HEAD -> $HEAD_NOW and rebuilt"
    fi
fi

# --- 2. the node: restart on source drift, relaunch when down -------------

NODE_ACTION="none"
NODE_SOURCE="unknown"
UNIT_STATE="$(node_unit_load_state)"

if [ "$UNIT_STATE" != "loaded" ]; then
    # Fail loudly. Starting the node any other way would put a second process
    # on the same datadir the unit is already using.
    NODE_ACTION="unit_not_installed"
    [ -z "$SYNC_ERROR" ] && SYNC_ERROR="node_unit_not_installed"
    log "ERROR node unit $NODE_UNIT is not installed (LoadState=${UNIT_STATE:-unknown}); refusing to launch a node outside systemd. Install the unit and enable it for this box."
elif [ -n "$SYNC_ERROR" ]; then
    NODE_ACTION="skipped:$SYNC_ERROR"
else
    # Source drift, not "did HEAD move", is the real question. A cycle that
    # rebuilt and then died before restarting, a hand-run build, or a restart
    # that silently failed all leave the RUNNING daemon on bytes that no
    # longer match build/bin/zclassic23 — and HEAD_MOVED=0 forever after, so
    # nothing ever noticed. Compare the two baked identities directly.
    BUILT_SOURCE_ID="$(zcl_binary_source_id build/bin/zclassic23)"
    measure_node_source

    RESTART_REASON=""
    if [ "$NODE_SOURCE" = "drifted" ]; then
        RESTART_REASON="source_drift"
    elif [ "$NODE_SOURCE" = "unreadable" ] && [ "$HEAD_MOVED" = 1 ]; then
        # Drift is undecidable this cycle, so fall back to the old, weaker
        # trigger rather than silently skipping a restart the box owes.
        RESTART_REASON="head_moved"
    fi
    if node_boot_in_progress; then
        if [ -n "$RESTART_REASON" ]; then
            log "deferring $RESTART_REASON: Type=notify boot in progress (pid=$(node_unit_main_pid))"
            NODE_ACTION="deferred_boot:$RESTART_REASON"
            RESTART_REASON=""
        else
            NODE_ACTION="boot_in_progress"
        fi
    elif ! node_unit_active; then
        RESTART_REASON="unit_inactive"
    fi

    if [ -n "$RESTART_REASON" ]; then
        if node_restart; then
            NODE_ACTION="restarted:$RESTART_REASON"
            log "node restarted via $NODE_UNIT ($RESTART_REASON) at $HEAD_NOW"
            measure_node_source
            if [ "$NODE_SOURCE" = "drifted" ]; then
                SYNC_ERROR="node_source_drift_persists"
                log "ERROR restart returned success but the running daemon still does not match build/bin/zclassic23 (built=$BUILT_SOURCE_ID running=$RUNNING_SOURCE_ID); the unit's ExecStart is probably bound to a different binary"
            fi
        else
            NODE_ACTION="restart_failed:$RESTART_REASON"
            SYNC_ERROR="node_restart_failed"
            log "ERROR systemctl --user restart $NODE_UNIT failed: $(head -1 "$STATE_DIR/node-restart.err" 2>/dev/null || true)"
        fi
    fi
fi

NODE_UP=0
NODE_PEERS=0
if node_rpc_up; then
    NODE_UP=1
    NODE_PEERS="$(node_peers)"
fi

# --- 3. optional second instance (operator-authorized auto-update) --------
# Restarting a production instance resets any running soak clock; an operator
# opts into that by setting RESTART_PROD=auto in their own env file.

PROD_ACTION="disabled"
if [ "$RESTART_PROD" = "auto" ] && [ -n "${PROD_UNIT:-}" ] && [ -n "${PROD_BIN:-}" ]; then
    PROD_SYSTEMCTL="${PROD_SYSTEMCTL:-systemctl --user}"
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

# --- 4. record what we observed, locally ----------------------------------
# A plain KEY=value file on this machine. No commit, no push, no network.
# Writing every cycle is free here; the old material-change/heartbeat-window
# logic existed only to rate-limit pushes and has no reason to survive.

[ -z "$SYNC_ERROR" ] && CYCLE_OK=1

COMMITS_BEHIND="$(git rev-list --count "$HEAD_NOW..$NEW_MAIN" 2>/dev/null || echo 0)"

TMP_SYNC="$SYNC_FILE.tmp.$$"
{
    printf 'BOX=%s\n' "$BOX"
    printf 'LAST_SYNC_AT=%s\n' "$(date -u +%FT%TZ)"
    printf 'LAST_SYNC_SHA=%s\n' "$HEAD_NOW"
    printf 'ORIGIN_MAIN=%s\n' "$NEW_MAIN"
    printf 'NODE_UP=%s\n' "$NODE_UP"
    printf 'NODE_PEERS=%s\n' "$NODE_PEERS"
    printf 'NODE_ACTION=%s\n' "$NODE_ACTION"
    printf 'NODE_SOURCE=%s\n' "$NODE_SOURCE"
    printf 'PROD_ACTION=%s\n' "$PROD_ACTION"
    printf 'SYNC_ERROR=%s\n' "${SYNC_ERROR:-none}"
    printf 'COMMITS_BEHIND=%s\n' "$COMMITS_BEHIND"
    printf 'STALE_CYCLES=%s\n' "$PREV_STREAK"
} > "$TMP_SYNC"
mv -f "$TMP_SYNC" "$SYNC_FILE"
log "recorded local state: $SYNC_FILE (error=${SYNC_ERROR:-none})"
