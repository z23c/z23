#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_git_hooks_selftest.sh — the three properties tools/scripts/
# install_git_hooks.sh has to hold, proved against real Git in a throwaway
# repository, never against this checkout's own configuration.
#
# WHY THIS EXISTS. The installer used to run an UNSCOPED
# `git config --unset-all core.hooksPath`, which git resolves to the SHARED
# .git/config, and then wrote an ABSOLUTE replacement into the invoking
# worktree's own config.worktree. Running the documented `make setup` in a
# second worktree therefore disarmed every worktree that had been relying on
# the shared value, silently — a push that should have been refused went
# through instead. The repository carried a standing rule telling developers
# not to run its own documented command. This is the executable half of
# retiring that rule:
#
#   A. installing in one worktree changes NO other worktree's effective
#      core.hooksPath, and leaves a pre-existing SHARED value untouched;
#   B. the installed value is the relative `build/githooks`, and Git really
#      does resolve a relative core.hooksPath against the worktree that runs
#      the hook — so one spelling is correct in every worktree at once;
#   C. a second run is a no-op: byte-identical config, exit 0.
#
# Read-only with respect to this checkout: every write lands under a
# mktemp -d scratch directory that is removed on exit.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALLER="$SCRIPT_DIR/install_git_hooks.sh"
NATIVE_BIN="${ZCL_GIT_HOOK_NATIVE_BIN:-$SOURCE_ROOT/build/bin/z23-git-hook}"

bad=0
fail() {
    printf 'install_git_hooks selftest: FAIL — %s\n' "$*" >&2
    bad=1
}
unobserved() {
    printf 'install_git_hooks selftest: UNOBSERVED — %s\n' "$*"
    exit 0
}

command -v git >/dev/null 2>&1 || unobserved "no git on PATH"
[[ -x "$INSTALLER" ]] || unobserved "installer is not executable: $INSTALLER"
[[ -x "$SOURCE_ROOT/tools/githooks/pre-commit" ]] ||
    unobserved "tracked pre-commit hook absent"
[[ -x "$NATIVE_BIN" ]] ||
    unobserved "native hook binary absent: $NATIVE_BIN (make git-hook)"

scratch_base="${ZCL_SCRATCH_DIR:-$HOME/.local/state/zclassic23/scratch}"
mkdir -p "$scratch_base" 2>/dev/null || scratch_base="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "$scratch_base/zcl-hooks-selftest.XXXXXX")" ||
    unobserved "cannot create a scratch directory under $scratch_base"
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

# A fixture repository never inherits the operator's signing or identity
# settings: those would make a fixture commit prompt, sign, or refuse.
g() { git -c commit.gpgsign=false -c user.name=z23 -c user.email=z23@invalid "$@"; }

install_into() {
    ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
    ZCL_GIT_HOOK_ROOT="$1" \
    ZCL_GIT_HOOK_NATIVE_BIN="$NATIVE_BIN" \
    ZCL_GIT_HOOK_HOST=posix \
        "$INSTALLER"
}

effective() { git -C "$1" config --get core.hooksPath 2>/dev/null || true; }
shared_value() { git -C "$1" config --local --get core.hooksPath 2>/dev/null || true; }

# ── fixture: one repository, three worktrees ────────────────────────────────
REPO="$WORK/repo"
g init -q -b main "$REPO" || unobserved "git init failed"
: >"$REPO/seed"
g -C "$REPO" add seed
g -C "$REPO" commit -q -m seed || unobserved "fixture commit failed"

# The value the old unscoped unset destroyed. Nothing below may touch it.
SENTINEL="$WORK/sentinel-shared-hooks"
g -C "$REPO" config --local core.hooksPath "$SENTINEL"

WT_A="$WORK/wt-a"
WT_B="$WORK/wt-b"
g -C "$REPO" worktree add -q -b wt-a "$WT_A" >/dev/null 2>&1 ||
    unobserved "git worktree add failed"
g -C "$REPO" worktree add -q -b wt-b "$WT_B" >/dev/null 2>&1 ||
    unobserved "git worktree add failed"

ALL=("$REPO" "$WT_A" "$WT_B")

# ── A. install in each, in turn; nobody else moves ──────────────────────────
installed=()
for target in "${ALL[@]}"; do
    out="$(install_into "$target" 2>&1)" || {
        fail "installer exited nonzero in $target: $out"
        break
    }
    case "$out" in
        *"core.hooksPath  build/githooks"*) ;;
        *) fail "installer did not report the path it wrote: $out" ;;
    esac
    case "$out" in
        *config.worktree*) ;;
        *) fail "installer did not report the scope it wrote: $out" ;;
    esac
    installed+=("$target")
    for done_wt in "${installed[@]}"; do
        got="$(effective "$done_wt")"
        [[ "$got" == "build/githooks" ]] ||
            fail "after installing in $target, $done_wt resolves to '$got'"
        [[ -x "$done_wt/build/githooks/pre-push" ]] ||
            fail "$done_wt has no executable pre-push after install"
    done
    got_shared="$(shared_value "$REPO")"
    [[ "$got_shared" == "$SENTINEL" ]] ||
        fail "installing in $target changed the SHARED core.hooksPath to '$got_shared'"
done

# A worktree that never ran the installer must not be silently armed with
# somebody else's hooks: it falls back to the shared value, unchanged.
WT_C="$WORK/wt-c"
g -C "$REPO" worktree add -q -b wt-c "$WT_C" >/dev/null 2>&1 || true
if [[ -d "$WT_C" ]]; then
    got="$(effective "$WT_C")"
    case "$got" in
        build/githooks|"$SENTINEL") ;;
        *) fail "a fresh worktree inherited '$got'" ;;
    esac
fi

# ── C. idempotence: a second run rewrites nothing ───────────────────────────
cfg="$(git -C "$WT_A" rev-parse --git-path config.worktree)"
cfg="$WT_A/$cfg"
[[ -f "$cfg" ]] || cfg="$(git -C "$WT_A" rev-parse --absolute-git-dir)/config.worktree"
before="$(cat "$cfg" 2>/dev/null)"
install_into "$WT_A" >/dev/null 2>&1 || fail "second install in $WT_A exited nonzero"
after="$(cat "$cfg" 2>/dev/null)"
[[ "$before" == "$after" ]] ||
    fail "second install rewrote $cfg: '$before' -> '$after'"

# ── B. Git really resolves a relative core.hooksPath per worktree ───────────
# The whole fix rests on githooks(5): a hook runs with its working directory
# at the top of the invoking worktree, so `build/githooks` names a different
# directory in each one. Proved with a marker hook, not with a manual page.
RIG="$WORK/rig"
g init -q -b main "$RIG" >/dev/null 2>&1
: >"$RIG/seed"
g -C "$RIG" add seed
g -C "$RIG" commit -q -m seed >/dev/null 2>&1
g -C "$RIG" config --local core.hooksPath build/githooks
RIG_B="$WORK/rig-b"
g -C "$RIG" worktree add -q -b rig-b "$RIG_B" >/dev/null 2>&1
for wt in "$RIG" "$RIG_B"; do
    mkdir -p "$wt/build/githooks"
    {
        printf '%s\n' '#!/bin/sh'
        printf 'printf %%s "$PWD" > "%s/mark.$(basename "$PWD")"\n' "$WORK"
    } >"$wt/build/githooks/pre-commit"
    chmod 0755 "$wt/build/githooks/pre-commit"
    : >"$wt/probe"
    g -C "$wt" add probe
    g -C "$wt" commit -q -m probe >/dev/null 2>&1 ||
        fail "fixture commit in $wt failed"
done
for wt in "$RIG" "$RIG_B"; do
    mark="$WORK/mark.$(basename "$wt")"
    [[ -f "$mark" ]] || { fail "no hook fired in $wt (relative hooksPath)"; continue; }
    got="$(cat "$mark")"
    [[ "$got" == "$wt" ]] ||
        fail "relative hooksPath in $wt resolved to '$got'"
done

if [[ "$bad" -ne 0 ]]; then
    exit 1
fi
printf '%s\n' \
    "install_git_hooks: self-test PASS (per-worktree scope: a shared value and" \
    "  every other worktree survive an install; relative core.hooksPath resolves" \
    "  to the worktree that runs the hook; a second run rewrites nothing)"
