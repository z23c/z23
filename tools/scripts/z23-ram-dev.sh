#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Manage commands in a disposable RAM checkout. A checkpoint copies clean
# commits to persistent storage, then verifies that origin/main contains them.
set -euo pipefail
CONFIG="${Z23_RAM_DEV_CONFIG:-/etc/z23-ram-dev.conf}"
die() { printf 'z23-ram-dev: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'z23-ram-dev: %s\n' "$*"; }
[ -r "$CONFIG" ] || die "missing $CONFIG; run the root provisioner first"
. "$CONFIG"
[ "$(id -u)" -eq "$Z23_DEV_UID" ] || die "configured for uid $Z23_DEV_UID, running as $(id -u)"
[ -e "$Z23_PERSISTENT_REPO/.git" ] || die "persistent source unavailable"
[ "$(findmnt -n -o FSTYPE --target "$Z23_PERSISTENT_REPO" 2>/dev/null)" != tmpfs ] || die "persistent source must not be tmpfs"
[ "$(findmnt -n -o FSTYPE --mountpoint "$Z23_RAM_ROOT" 2>/dev/null)" = tmpfs ] || die "RAM workspace is not mounted"
workspace="$Z23_RAM_ROOT/workspace"; cache="$Z23_RAM_ROOT/cache"
checkpoint_ref="refs/z23-ram-checkpoints/$Z23_DEV_USER"; safe_marker="$Z23_RAM_ROOT/.safe-to-discard"
require_clean() { git -C "$workspace" diff --quiet --ignore-submodules -- && git -C "$workspace" diff --cached --quiet --ignore-submodules -- && [ -z "$(git -C "$workspace" ls-files --others --exclude-standard)" ]; }
bootstrap() {
    local url saved head upstream
    [ ! -e "$workspace" ] || die "workspace exists; use status or run"
    [ "$(git -C "$Z23_PERSISTENT_REPO" symbolic-ref --short HEAD)" = main ] || die "persistent checkout must be on main"
    [ -z "$(git -C "$Z23_PERSISTENT_REPO" status --porcelain)" ] || die "persistent checkout is dirty; commit or clean it first"
    url="$(git -C "$Z23_PERSISTENT_REPO" remote get-url origin)" || die "persistent checkout has no origin"
    git -C "$Z23_PERSISTENT_REPO" fetch --no-tags origin main
    git -C "$Z23_PERSISTENT_REPO" merge --ff-only origin/main || die "persistent main cannot fast-forward to origin/main"
    saved="$(git -C "$Z23_PERSISTENT_REPO" rev-parse --verify -q "$checkpoint_ref" || true)"
    if [ -n "$saved" ] && ! git -C "$Z23_PERSISTENT_REPO" merge-base --is-ancestor "$saved" origin/main; then die "unpublished persistent checkpoint $saved must be recovered and pushed before bootstrap"; fi
    mkdir -p "$cache"; git clone --no-hardlinks --branch main -- "$Z23_PERSISTENT_REPO" "$workspace"; git -C "$workspace" remote set-url origin "$url"
    git -C "$workspace" fetch --no-tags origin main
    head="$(git -C "$workspace" rev-parse HEAD)"; upstream="$(git -C "$workspace" rev-parse origin/main)"; [ "$head" = "$upstream" ] || die "RAM checkout does not exactly match origin/main"
    rm -f -- "$safe_marker"; say "PASS workspace=$workspace source=$(git -C "$workspace" rev-parse HEAD)"; say "WARNING: RAM-only checkout; run 'z23-ram-dev checkpoint' before shutdown"
}
status_workspace() { local s h; [ -e "$workspace/.git" ] || { say "workspace absent; run bootstrap"; return; }; h="$(git -C "$workspace" rev-parse HEAD)"; if require_clean; then s=clean; else s=dirty; fi; say "status workspace=$workspace head=$h tree=$s"; findmnt -n -o TARGET,SIZE,USED,AVAIL,FSTYPE --mountpoint "$Z23_RAM_ROOT"; }
workspace_path() { [ -e "$workspace/.git" ] || die "workspace absent; run bootstrap"; printf '%s\n' "$workspace"; }
checkpoint() {
    local h; [ -e "$workspace/.git" ] || die "workspace absent"; require_clean || die "commit all tracked and untracked files before checkpoint"; h="$(git -C "$workspace" rev-parse HEAD)"
    git -C "$Z23_PERSISTENT_REPO" fetch --no-tags "$workspace" "HEAD:$checkpoint_ref"; say "local durable checkpoint=$h ref=$checkpoint_ref"
    git -C "$workspace" fetch --no-tags origin main || die "local checkpoint is safe, but origin/main verification failed"
    if ! git -C "$workspace" merge-base --is-ancestor "$h" origin/main; then rm -f -- "$safe_marker"; die "commit $h is not on origin/main; push HEAD:main, then checkpoint again"; fi
    printf '%s\n' "$h" >"$safe_marker"; say "PASS origin/main contains $h; RAM workspace is safe to discard"
}
can_discard() { local h m; [ -e "$workspace/.git" ] || return 0; require_clean || die "workspace is dirty"; h="$(git -C "$workspace" rev-parse HEAD)"; m="$(sed -n '1p' "$safe_marker" 2>/dev/null || true)"; [ "$m" = "$h" ] || die "HEAD $h lacks a verified origin/main checkpoint"; say "PASS discard-safe head=$h"; }
run_command() {
    [ -e "$workspace/.git" ] || die "workspace absent; run bootstrap"; [ "$#" -gt 0 ] || die "run requires a command"
    rm -f -- "$safe_marker"; mkdir -p "$workspace/build/tmp" "$cache/zcc" "$cache/xdg"
    export TMPDIR="$workspace/build/tmp" ZCC_DIR="$cache/zcc" ZCC_MAX_MB="$Z23_ZCC_MAX_MB" XDG_CACHE_HOME="$cache/xdg"
    exec systemd-run --user --scope --wait --collect --pipe --quiet --property=CPUWeight=25 --property=IOWeight=25 --property="MemoryHigh=$Z23_DEV_MEMORY_HIGH" --property="MemoryMax=$Z23_DEV_MEMORY_MAX" --working-directory="$workspace" -- "$@"
}
action="${1:-}"; shift || true
case "$action" in bootstrap) [ $# -eq 0 ] || die "bootstrap takes no arguments"; bootstrap;; status) status_workspace;; path) workspace_path;; checkpoint) checkpoint;; can-discard) can_discard;; run) [ "${1:-}" = -- ] && shift; run_command "$@";; *) die "usage: $0 bootstrap|status|path|checkpoint|run -- COMMAND [ARG...]";; esac
