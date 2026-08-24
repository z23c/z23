#!/usr/bin/env bash
# fleet_sync.sh — per-box devfleet self-sync loop.
#
# One box runs this on a timer (cron). Each cycle it:
#   1. fast-forwards this checkout to origin/main, reconciling a
#      heartbeat-only divergence automatically and refusing loudly (without
#      touching HEAD) when real product commits are involved;
#   2. rebuilds when HEAD moved;
#   3. asks systemd to restart the box's devfleet unit when the RUNNING
#      daemon's baked source identity no longer matches the built binary, or
#      when the unit is failed/inactive. Type=notify "activating" with a live
#      MainPID is a boot, not a down unit — restarting it aborts IBD.
#   4. rewrites deploy/devfleet/<box>.sync with the observed state — including
#      how far behind origin/main this box is and how many consecutive
#      cycles it has failed to fully sync — and publishes it to main,
#      retrying through push races instead of giving up after a fixed count.
#
# ── WHO OWNS THE NODE PROCESS ─────────────────────────────────────────────
# systemd does, through zcl23-devfleet@<box>.service (deploy/
# zcl23-devfleet@.service). This script NEVER launches, signals, or kills the
# node itself. It used to: `setsid nohup build/bin/zclassic23 ... &` plus a
# pgrep/kill stop. Once the unit existed, that launcher became a way to put a
# SECOND zclassic23 process on ONE datadir — which corrupts it. There is
# deliberately NO fallback launcher here: if the unit is not installed this
# cycle fails with a named SYNC_ERROR and starts nothing. A silent fallback
# would reintroduce the double-node hazard at exactly the moment nobody is
# watching.
#
# The unit is Type=notify with NotifyAccess=main, so `systemctl restart`
# already returns only after the node has sent READY=1 (or TimeoutStartSec
# expires). Do not add an RPC/pgrep readiness poll on top of it: that is a
# second, weaker copy of a guarantee systemd already makes, and the old
# 36x5s poll is what used to hide a failed start behind a timeout.
#
# The unit also owns the node's stdout/stderr with
# `append:%h/.zclassic-c23-devfleet/node.log`. This script must never redirect
# that log itself, and in particular must never truncate it: the previous
# launcher opened node.log with `>` and destroyed, on every restart, exactly
# the evidence of the crash it was restarting from. Rotation is a separate
# concern and already has an owner (zclassic23-logrotate.timer); it does not
# belong here either.
#
# ── SELF-HEALING RULES ────────────────────────────────────────────────────
# Do not relax these without re-reading the incident that motivated them — a
# box stuck 178-222 commits behind because a stalled push or a dirty file
# silently wedged the loop forever:
#   - A push race (another box's heartbeat landed first) is expected and
#     harmless: re-fetch, rebase this box's own commit(s) onto the new tip,
#     and retry. Every cycle re-attempts a still-unpushed commit, not just
#     the cycle that created it.
#   - A HEAD that is ahead of origin/main ONLY by this box's own heartbeat
#     commit(s) reconciles and pushes automatically.
#   - A HEAD carrying any commit that is NOT this box's own heartbeat commit
#     is left exactly as-is: no rebase, no merge, no reset, and no push. That
#     holds whether origin/main moved or not — see the guard note below.
#   - An uncommitted edit to a tracked product file is never touched, rebased
#     over, or discarded — but it also must not go quiet: the file name is
#     published in the heartbeat so the fleet can see which box is stuck.
#
# ── THE ONE PUSHABILITY DECISION ──────────────────────────────────────────
# `local_commits_are_heartbeat_only` is evaluated EXACTLY ONCE per cycle, into
# LOCAL_COMMITS_PUSHABLE, before any branch reads it. An earlier revision
# called it only from the two-sided-divergence branch and let a separate
# "local HEAD already contains origin/main" fast path fall straight through to
# the push step. That path is taken whenever HEAD is strictly ahead — which is
# precisely the shape a human's unreviewed product commit has on a box whose
# origin/main has not moved — so the next cron tick would have pushed it to
# main. One predicate, one evaluation, every branch reads the same answer.
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

# The ONE canonical reader for a build's baked source identity. Nine inline
# copies of this parser had diverged (a greedy sed returns the LAST of
# agentbuild's several source_id_sha256 values, i.e. a runtime value, not the
# baked one) — tools/lint/check_identity_parser_single.sh exists to stop a
# tenth. zcl_binary_source_id() is the only identity reader used below.
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$REPO_DIR/tools/scripts/source_identity_lib.sh"

STATE_DIR="$HOME/.local/state/zclassic23-fleetsync"
mkdir -p "$STATE_DIR"

log() { printf '%s fleet_sync[%s] %s\n' "$(date -u +%FT%TZ)" "$BOX" "$*"; }

now_epoch() { date +%s; }

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

SYNC_FILE="deploy/devfleet/$BOX.sync"
PUSH_STAMP="$STATE_DIR/$BOX.last-push"
STALE_STREAK_FILE="$STATE_DIR/$BOX.stale-streak"
PUSH_HEARTBEAT_SECONDS="${PUSH_HEARTBEAT_SECONDS:-1800}"
RESTART_PROD="${RESTART_PROD:-manual}"
PUSH_MAX_ATTEMPTS="${PUSH_MAX_ATTEMPTS:-6}"
DEVFLEET_UNIT="${DEVFLEET_UNIT:-zcl23-devfleet@$BOX.service}"

# cron has no session bus; lingering users still have one. Both the devfleet
# unit and the optional production unit are user units, so this must be set
# before the first systemctl call, not just before the production block.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# --- self-healing sync helpers ----------------------------------------------

# Tracked files with uncommitted changes, excluding this box's own sync file
# (which this script owns outright and freely rewrites/commits each cycle).
dirty_product_files() {
    git status --porcelain --untracked-files=no | cut -c4- | grep -vF "$SYNC_FILE" || true
}

# True only if every commit reachable from $2 ("to", e.g. our HEAD) but not
# from $1 ("from", e.g. origin/main) is a heartbeat commit for THIS box:
# the expected subject line, touching nothing but this box's own sync file.
# Anything else means real product work rode along, and this must stay a
# human-resolved refusal rather than an auto-rebase or an auto-push.
local_commits_are_heartbeat_only() {
    local from="$1" to="$2" c files subject
    for c in $(git rev-list "$from..$to"); do
        subject="$(git log -1 --format=%s "$c")"
        [ "$subject" = "devfleet: $BOX sync heartbeat" ] || return 1
        files="$(git show --name-only --pretty=format: "$c" | sed '/^$/d')"
        [ "$files" = "$SYNC_FILE" ] || return 1
    done
    return 0
}

# --- devfleet instance: systemd is the supervisor ---------------------------

devfleet_unit_load_state() {
    systemctl --user show "$DEVFLEET_UNIT" -p LoadState --value 2>/dev/null || true
}

devfleet_unit_active() {
    systemctl --user is-active --quiet "$DEVFLEET_UNIT"
}

# Type=notify stays "activating" until READY=1 (onion descriptor published).
# `systemctl is-active` is false in that state, which used to look like a
# down unit and trigger restart — killing a still-loading block index.
devfleet_boot_in_progress() {
    local st pid
    st="$(systemctl --user is-active "$DEVFLEET_UNIT" 2>/dev/null || true)"
    [ "$st" = "activating" ] || return 1
    pid="$(devfleet_unit_main_pid)"
    [ "$pid" != 0 ] && [ -d "/proc/$pid" ]
}

devfleet_unit_main_pid() {
    local pid
    pid="$(systemctl --user show "$DEVFLEET_UNIT" -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|*[!0-9]*) pid=0 ;; esac
    printf '%s' "$pid"
}

# Type=notify: this blocks until the node reports READY=1 or TimeoutStartSec
# expires. Nothing else here waits on the node.
devfleet_restart() {
    systemctl --user restart "$DEVFLEET_UNIT" 2>"$STATE_DIR/devfleet-restart.err"
}

# Measure, never assume. DEVFLEET_SOURCE is only ever set from a comparison of
# two baked identities actually read this cycle: the built binary's, and the
# RUNNING process's, taken from its kernel-pinned /proc/<pid>/exe inode (still
# correct after the path was replaced). One definition, called both before and
# after a restart, because "systemctl restart returned 0" is activity, not the
# result — it does not prove the new process runs the bytes we just built.
# Reads BUILT_SOURCE_ID; writes UNIT_PID, RUNNING_SOURCE_ID, DEVFLEET_SOURCE.
measure_devfleet_source() {
    UNIT_PID="$(devfleet_unit_main_pid)"
    RUNNING_SOURCE_ID=""
    if [ "$UNIT_PID" != 0 ] && [ -r "/proc/$UNIT_PID/exe" ]; then
        RUNNING_SOURCE_ID="$(zcl_binary_source_id "/proc/$UNIT_PID/exe")"
    fi
    if [ -z "$BUILT_SOURCE_ID" ] || [ -z "$RUNNING_SOURCE_ID" ]; then
        DEVFLEET_SOURCE="unreadable"
    elif [ "$BUILT_SOURCE_ID" = "$RUNNING_SOURCE_ID" ]; then
        DEVFLEET_SOURCE="current"
    else
        DEVFLEET_SOURCE="drifted"
    fi
}

devfleet_node_up() {
    build/bin/zclassic23 -datadir="$DEVFLEET_DATADIR" -rpcport="$DEVFLEET_RPCPORT" \
        getconnectioncount >/dev/null 2>&1
}

devfleet_peers() {
    build/bin/zclassic23 -datadir="$DEVFLEET_DATADIR" -rpcport="$DEVFLEET_RPCPORT" \
        getconnectioncount 2>/dev/null || printf '0'
}

# --- staleness bookkeeping (crosses cycles) ---------------------------------
# STALE_CYCLES published in the heartbeat reflects cycles completed BEFORE
# this one (avoids a chicken/egg with the commit we are about to make). It is
# updated for the next cycle to read no matter which exit path we take.
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

# A leftover write of our OWN sync file from a killed prior run is not
# product work; discard it before it can trip the dirty-file refusal or the
# ff-only merge below. We regenerate this file's content every cycle anyway.
git diff --quiet -- "$SYNC_FILE" 2>/dev/null || git checkout -- "$SYNC_FILE" 2>/dev/null || true

# --- 1. sync source -------------------------------------------------------

git fetch origin --quiet
OLD_HEAD="$(git rev-parse HEAD)"
NEW_MAIN="$(git rev-parse origin/main)"
SYNC_ERROR=""
REFUSAL=0   # 1 = a human must resolve this; never touch HEAD, never push it.

LOCAL_ONLY="$(git rev-list --count "$NEW_MAIN..$OLD_HEAD" 2>/dev/null || echo 0)"
BEHIND="$(git rev-list --count "$OLD_HEAD..$NEW_MAIN" 2>/dev/null || echo 0)"

# THE single pushability decision for this cycle (see the header note). Every
# branch below reads this variable; none of them re-derives it.
LOCAL_COMMITS_PUSHABLE=1
if [ "$LOCAL_ONLY" -gt 0 ] && ! local_commits_are_heartbeat_only "$NEW_MAIN" "$OLD_HEAD"; then
    LOCAL_COMMITS_PUSHABLE=0
fi

DIRTY="$(dirty_product_files)"
DIRTY_ONELINE=""
[ -n "$DIRTY" ] && DIRTY_ONELINE="$(printf '%s' "$DIRTY" | paste -sd, -)"

if [ "$LOCAL_COMMITS_PUSHABLE" = 0 ]; then
    # Checked FIRST, ahead of the dirty-file case: a dirty tree still
    # publishes by pushing HEAD, and HEAD is exactly what must not move here.
    REFUSAL=1
    SYNC_ERROR="local_product_commits:${LOCAL_ONLY}_local"
    [ -n "$DIRTY_ONELINE" ] && SYNC_ERROR="$SYNC_ERROR+dirty:$DIRTY_ONELINE"
    log "ERROR HEAD carries $LOCAL_ONLY commit(s) that are not this box's heartbeat; this needs a human, not an auto-push. Leaving HEAD at $OLD_HEAD untouched and pushing nothing from it."
    log "  offending commit(s): $(git log --oneline "$NEW_MAIN..$OLD_HEAD" | tr '\n' ';')"
    [ -n "$DIRTY_ONELINE" ] && log "  also dirty: $DIRTY_ONELINE"
elif [ -n "$DIRTY" ]; then
    SYNC_ERROR="dirty_tracked_file:$DIRTY_ONELINE"
    log "ERROR uncommitted change(s) to tracked product file(s) [$DIRTY_ONELINE]; preserving local state, publishing this as the heartbeat"
elif [ "$BEHIND" -gt 0 ] && [ "$LOCAL_ONLY" = 0 ]; then
    if git merge --ff-only origin/main --quiet; then
        if ! make -j"$(nproc)" > "$STATE_DIR/build.log" 2>&1; then
            SYNC_ERROR="build_failed"
            log "ERROR build failed at $(git rev-parse HEAD); see $STATE_DIR/build.log"
        else
            log "synced $OLD_HEAD -> $(git rev-parse HEAD) and rebuilt"
        fi
    else
        SYNC_ERROR="ff_pull_failed"
        log "ERROR ff-only pull to $NEW_MAIN failed; preserving local state"
    fi
elif [ "$BEHIND" -gt 0 ] && [ "$LOCAL_ONLY" -gt 0 ]; then
    # Two-sided divergence, and LOCAL_COMMITS_PUSHABLE already established
    # that the local side is nothing but this box's own heartbeat commits.
    if git rebase origin/main --quiet 2>/dev/null; then
        if ! make -j"$(nproc)" > "$STATE_DIR/build.log" 2>&1; then
            SYNC_ERROR="build_failed"
            log "ERROR build failed after reconciling heartbeat-only divergence at $(git rev-parse HEAD)"
        else
            log "reconciled heartbeat-only divergence: replayed local heartbeat commit(s) onto $NEW_MAIN"
        fi
    else
        git rebase --abort 2>/dev/null || true
        SYNC_ERROR="ff_pull_failed"
        log "ERROR could not replay heartbeat-only commit(s) onto $NEW_MAIN; preserving local state"
    fi
elif [ "$LOCAL_ONLY" -gt 0 ]; then
    # Ahead only, by this box's own heartbeat commit(s): nothing to pull. The
    # push step below retries them.
    log "local HEAD already contains origin/main ($NEW_MAIN); $LOCAL_ONLY unpushed heartbeat commit(s) pending"
fi

HEAD_NOW="$(git rev-parse HEAD)"
HEAD_MOVED=0
[ "$OLD_HEAD" != "$HEAD_NOW" ] && HEAD_MOVED=1

# --- 2. devfleet instance: restart on source drift, relaunch when down -----

DEVFLEET_ACTION="none"
DEVFLEET_SOURCE="unknown"
UNIT_STATE="$(devfleet_unit_load_state)"

if [ "$UNIT_STATE" != "loaded" ]; then
    # Fail loudly. Starting the node any other way would put a second process
    # on the same datadir the unit is already using.
    DEVFLEET_ACTION="unit_not_installed"
    [ -z "$SYNC_ERROR" ] && SYNC_ERROR="devfleet_unit_not_installed"
    log "ERROR devfleet unit is not installed (LoadState=${UNIT_STATE:-unknown}); refusing to launch a node outside systemd. Install deploy/zcl23-devfleet@.service and enable it for this box."
elif [ -n "$SYNC_ERROR" ]; then
    DEVFLEET_ACTION="skipped:$SYNC_ERROR"
else
    # Source drift, not "did HEAD move", is the real question. A cycle that
    # rebuilt and then died before restarting, a hand-run build, or a restart
    # that silently failed all leave the RUNNING daemon on bytes that no
    # longer match build/bin/zclassic23 — and HEAD_MOVED=0 forever after, so
    # nothing ever noticed. Compare the two baked identities directly.
    BUILT_SOURCE_ID="$(zcl_binary_source_id build/bin/zclassic23)"
    measure_devfleet_source

    RESTART_REASON=""
    if [ "$DEVFLEET_SOURCE" = "drifted" ]; then
        RESTART_REASON="source_drift"
    elif [ "$DEVFLEET_SOURCE" = "unreadable" ] && [ "$HEAD_MOVED" = 1 ]; then
        # Drift is undecidable this cycle, so fall back to the old, weaker
        # trigger rather than silently skipping a restart the box owes.
        RESTART_REASON="head_moved"
    fi
    if devfleet_boot_in_progress; then
        if [ -n "$RESTART_REASON" ]; then
            log "deferring $RESTART_REASON: Type=notify boot in progress (pid=$(devfleet_unit_main_pid))"
            DEVFLEET_ACTION="deferred_boot:$RESTART_REASON"
            RESTART_REASON=""
        else
            DEVFLEET_ACTION="boot_in_progress"
        fi
    elif ! devfleet_unit_active; then
        RESTART_REASON="unit_inactive"
    fi

    if [ -n "$RESTART_REASON" ]; then
        if devfleet_restart; then
            DEVFLEET_ACTION="restarted:$RESTART_REASON"
            log "devfleet node restarted via $DEVFLEET_UNIT ($RESTART_REASON) at $HEAD_NOW"
            measure_devfleet_source
            if [ "$DEVFLEET_SOURCE" = "drifted" ]; then
                SYNC_ERROR="devfleet_source_drift_persists"
                log "ERROR restart returned success but the running daemon still does not match build/bin/zclassic23 (built=$BUILT_SOURCE_ID running=$RUNNING_SOURCE_ID); the unit's ExecStart is probably bound to a different binary"
            fi
        else
            DEVFLEET_ACTION="restart_failed:$RESTART_REASON"
            SYNC_ERROR="devfleet_restart_failed"
            log "ERROR systemctl --user restart $DEVFLEET_UNIT failed: $(head -1 "$STATE_DIR/devfleet-restart.err" 2>/dev/null || true)"
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

[ -z "$SYNC_ERROR" ] && CYCLE_OK=1

LAST_PUSH=0
[ -f "$PUSH_STAMP" ] && LAST_PUSH="$(cat "$PUSH_STAMP" 2>/dev/null || echo 0)"
case "$LAST_PUSH" in ''|*[!0-9]*) LAST_PUSH=0 ;; esac
HEARTBEAT_DUE=0
[ $(( $(now_epoch) - LAST_PUSH )) -ge "$PUSH_HEARTBEAT_SECONDS" ] && HEARTBEAT_DUE=1

COMMITS_BEHIND="$(git rev-list --count "$HEAD_NOW..$NEW_MAIN" 2>/dev/null || echo 0)"

NEW_CONTENT="BOX=$BOX
LAST_SYNC_AT=$(date -u +%FT%TZ)
LAST_SYNC_SHA=$HEAD_NOW
ORIGIN_MAIN=$NEW_MAIN
DEVFLEET_NODE_UP=$DEVFLEET_NODE_UP
DEVFLEET_PEERS=$DEVFLEET_PEERS
DEVFLEET_ACTION=$DEVFLEET_ACTION
DEVFLEET_SOURCE=$DEVFLEET_SOURCE
PROD_ACTION=$PROD_ACTION
SYNC_ERROR=${SYNC_ERROR:-none}
COMMITS_BEHIND=$COMMITS_BEHIND
STALE_CYCLES=$PREV_STREAK
"

# The baseline a "material change" is measured against is whatever this
# heartbeat will sit on top of: the working tree in the normal path, and
# origin/main's own copy on the refusal path, whose heartbeat is built
# directly on origin/main and never on this box's HEAD.
OLD_CONTENT=""
if [ "$REFUSAL" = 1 ]; then
    OLD_CONTENT="$(git show "$NEW_MAIN:$SYNC_FILE" 2>/dev/null || true)"
elif [ -f "$SYNC_FILE" ]; then
    OLD_CONTENT="$(cat "$SYNC_FILE")"
fi

# Material change = anything except the fields that necessarily drift every
# single cycle even when nothing real happened: the timestamp; the commit
# distance and stale-streak counters; and LAST_SYNC_SHA/ORIGIN_MAIN, which
# name the commit this heartbeat is built on top of and so can never equal
# what THIS heartbeat's own commit will become — comparing them raw would
# make every cycle "material" forever and push on every single tick, which
# is itself a needless source of push-race contention across the fleet.
# A real sync still surfaces here via DEVFLEET_ACTION/DEVFLEET_SOURCE/
# SYNC_ERROR changing, so nothing observable is lost by excluding them.
VOLATILE_FIELDS='^(LAST_SYNC_AT|LAST_SYNC_SHA|ORIGIN_MAIN|COMMITS_BEHIND|STALE_CYCLES)='
material_changed=0
if [ "$(printf '%s\n' "$OLD_CONTENT" | grep -vE "$VOLATILE_FIELDS")" != \
     "$(printf '%s\n' "$NEW_CONTENT" | grep -vE "$VOLATILE_FIELDS")" ]; then
    material_changed=1
fi

# Publish the heartbeat WITHOUT pushing HEAD.
#
# `git push origin main` moves a BRANCH, so pushing from a HEAD that carries a
# human's product commit publishes that commit — the exact thing the refusal
# exists to prevent. But a box that goes silent is the other half of the
# incident: nobody noticed node1/node4 falling 178-222 commits behind. Both
# are avoidable. Build the heartbeat commit with plumbing, directly on top of
# origin/main, in a scratch index, and push that object. HEAD, the real index
# and the working tree are never touched, so the human's commit stays exactly
# where they left it and is never published.
publish_off_origin_main() {
    local content="$1" base blob tree commit idx
    base="$(git rev-parse origin/main)"
    idx="$STATE_DIR/$BOX.detached-index"
    rm -f "$idx"
    GIT_INDEX_FILE="$idx" git read-tree "$base" || return 1
    blob="$(printf '%s' "$content" | git hash-object -w --stdin)" || return 1
    [ -n "$blob" ] || return 1
    GIT_INDEX_FILE="$idx" git update-index --add --cacheinfo 100644 "$blob" "$SYNC_FILE" || return 1
    tree="$(GIT_INDEX_FILE="$idx" git write-tree)" || return 1
    rm -f "$idx"
    commit="$(git commit-tree "$tree" -p "$base" -m "devfleet: $BOX sync heartbeat")" || return 1
    git push origin "$commit:main" --quiet
}

if [ "$REFUSAL" = 1 ]; then
    log "REFUSED push: $LOCAL_ONLY local commit(s) on HEAD are not this box's heartbeat; publishing status off origin/main instead, HEAD untouched"
    if [ "$material_changed" = 0 ] && [ "$HEARTBEAT_DUE" = 0 ]; then
        log "no material change; heartbeat fresh; nothing to publish"
        exit 0
    fi
    published=0
    for attempt in $(seq 1 "$PUSH_MAX_ATTEMPTS"); do
        git fetch origin --quiet
        if publish_off_origin_main "$NEW_CONTENT"; then
            published=1
            break
        fi
        sleep "$(( attempt * 2 + (RANDOM % 3) ))"
    done
    if [ "$published" = 1 ]; then
        now_epoch > "$PUSH_STAMP"
        log "heartbeat published off origin/main: $SYNC_FILE"
    else
        log "ERROR could not publish refusal heartbeat after $PUSH_MAX_ATTEMPTS attempts"
    fi
    exit 0
fi

HAVE_UNPUSHED=0
[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ] && HAVE_UNPUSHED=1

if [ "$material_changed" = 1 ] || [ "$HEARTBEAT_DUE" = 1 ]; then
    printf '%s' "$NEW_CONTENT" > "$SYNC_FILE"
    git add "$SYNC_FILE"
    git commit --quiet -m "devfleet: $BOX sync heartbeat"
    HAVE_UNPUSHED=1
fi

if [ "$HAVE_UNPUSHED" = 0 ]; then
    log "no material change; heartbeat fresh; nothing to push"
    exit 0
fi

# Push with retry: a race with another box's heartbeat is expected and
# harmless (each box only ever touches its own file), so re-fetch and replay
# our commit(s) on top of the new tip rather than giving up. This also
# retries any commit left unpushed by an earlier cycle's failed attempt.
#
# Rebase only when origin actually moved past us: it requires a clean
# working tree, and a dirty-tracked-product-file cycle (SYNC_ERROR set, HEAD
# otherwise untouched) must still be able to publish its heartbeat by a plain
# fast-forward push, which needs no clean tree at all.
pushed=0
for attempt in $(seq 1 "$PUSH_MAX_ATTEMPTS"); do
    git fetch origin --quiet
    if git merge-base --is-ancestor origin/main HEAD; then
        git push origin main --quiet 2>/dev/null && { pushed=1; break; }
    elif git rebase origin/main --quiet 2>/dev/null; then
        if git push origin main --quiet 2>/dev/null; then
            pushed=1
            break
        fi
        git rebase --abort 2>/dev/null || true
    elif [ "$(git diff --name-only --diff-filter=U)" = "$SYNC_FILE" ] \
         && git checkout --ours -- "$SYNC_FILE" \
         && git add "$SYNC_FILE" \
         && GIT_EDITOR=true git rebase --continue --quiet 2>/dev/null \
         && git push origin main --quiet 2>/dev/null; then
        pushed=1
        break
    else
        git rebase --abort 2>/dev/null || true
    fi
    sleep "$(( attempt * 2 + (RANDOM % 3) ))"
done
if [ "$pushed" = 1 ]; then
    now_epoch > "$PUSH_STAMP"
    log "heartbeat pushed: $SYNC_FILE"
else
    CYCLE_OK=0
    log "ERROR push failed after $PUSH_MAX_ATTEMPTS attempts; commit kept locally, will retry every cycle until it lands"
fi
