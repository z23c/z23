#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Install the checkout-local hook set selected for this host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="${ZCL_GIT_HOOK_SOURCE_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${ZCL_GIT_HOOK_ROOT:-$SOURCE_ROOT}"
HOOK_DIR="${ZCL_GIT_HOOK_DIR:-$ROOT/build/githooks}"

fail() {
    printf '%s\n' "install_git_hooks: REFUSE: $*" >&2
    exit 1
}

host_kind="${ZCL_GIT_HOOK_HOST:-}"
if [[ -z "$host_kind" ]]; then
    case "$(uname -s 2>/dev/null || true)" in
        MINGW*|MSYS*|CYGWIN*) host_kind=windows ;;
        *)                    host_kind=posix ;;
    esac
fi
case "$host_kind" in
    posix|windows) ;;
    *) fail "unknown host selection '$host_kind'" ;;
esac
native_suffix=""
[[ "$host_kind" == windows ]] && native_suffix=".exe"
NATIVE_BIN="${ZCL_GIT_HOOK_NATIVE_BIN:-$ROOT/build/bin/z23-git-hook$native_suffix}"

[[ -d "$ROOT" ]] || fail "checkout root is not a directory: $ROOT"
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 ||
    fail "checkout root is not a Git worktree: $ROOT"
case "$HOOK_DIR" in
    "$ROOT"/*) ;;
    *) fail "hook directory must be contained by the checkout: $HOOK_DIR" ;;
esac
[[ "$HOOK_DIR" != "$ROOT" ]] || fail "hook directory cannot be the checkout root"
[[ -x "$SOURCE_ROOT/tools/githooks/pre-commit" ]] ||
    fail "tracked pre-commit hook is missing or not executable"

[[ -x "$NATIVE_BIN" ]] || fail "native receipt hook is missing: $NATIVE_BIN"

unlink_if_present() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        unlink -- "$path" || fail "cannot replace stale hook: $path"
    fi
}

if [[ "$host_kind" == windows ]]; then
    mkdir -p "$HOOK_DIR"
    digest="$(sha256sum "$NATIVE_BIN" | awk '{print $1}')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "cannot hash native hook"
    generation="${HOOK_DIR%/}/native-v2-$digest"
    if [[ ! -d "$generation" ]]; then
        staging="${HOOK_DIR%/}/.native-v2-$digest-$$"
        mkdir -p "$staging"
        install -m 0755 "$SOURCE_ROOT/tools/githooks/pre-commit" \
            "$staging/pre-commit"
        for hook in pre-push post-commit post-merge post-checkout; do
            install -m 0755 "$NATIVE_BIN" "$staging/$hook.exe"
        done
        if ! mv "$staging" "$generation" 2>/dev/null; then
            rm -rf -- "$staging"
            [[ -d "$generation" ]] || fail "cannot publish hook generation"
        fi
    fi
    HOOK_DIR="$generation"
else
    mkdir -p "$HOOK_DIR"
    install -m 0755 "$SOURCE_ROOT/tools/githooks/pre-commit" \
        "$HOOK_DIR/pre-commit"
    install -m 0755 "$NATIVE_BIN" "$HOOK_DIR/z23-git-hook"
    for hook in pre-push post-commit post-merge post-checkout; do
        unlink_if_present "$HOOK_DIR/$hook"
        ln -s z23-git-hook "$HOOK_DIR/$hook"
    done
fi

# ---------------------------------------------------------------------------
# Config scope: this worktree, and only this worktree.
#
# core.hooksPath is per-WORKTREE state. Every worktree builds its own
# build/githooks out of its own source, so one value shared by the whole
# repository arms every worktree with SOME OTHER checkout's hook binaries.
# Two rules follow, and this script used to break both:
#
#   1. Only this worktree's scope is written. The previous version ran an
#      UNSCOPED `git config --unset-all core.hooksPath`, which git resolves
#      to the SHARED .git/config: running the documented `make setup` in a
#      second worktree silently cleared the value every worktree without its
#      own config.worktree was relying on. Every write and unset below
#      carries --worktree.
#   2. The value is RELATIVE. Git runs a hook with its working directory at
#      the top of the invoking worktree and resolves a relative
#      core.hooksPath against that directory (githooks(5)), so the single
#      spelling `build/githooks` is correct in every worktree at once —
#      including a worktree `git worktree add` cloned this config into, which
#      otherwise inherits the spawning checkout's absolute path verbatim.
#      Windows keeps an absolute, content-addressed generation path: the
#      whole point there is that the directory changes identity whenever the
#      binary does, so it cannot be a fixed relative name.
#
# --worktree writes require the repository extension to be on. Enabling it is
# a shared-config write, so it is announced rather than done silently.
if [[ "$(git -C "$ROOT" config --get extensions.worktreeConfig 2>/dev/null \
    || true)" != "true" ]]; then
    printf '%s\n' "install_git_hooks: enabling repository extension" \
        "  extensions.worktreeConfig = true   (shared config, one time)" \
        "  without it Git has no per-worktree scope and every worktree would" \
        "  have to share one core.hooksPath" >&2
    git -C "$ROOT" config extensions.worktreeConfig true ||
        fail "cannot enable extensions.worktreeConfig on $ROOT"
fi

configured_hook_dir="$HOOK_DIR"
if [[ "$host_kind" == windows ]]; then
    if command -v cygpath >/dev/null 2>&1; then
        configured_hook_dir="$(cygpath -m "$HOOK_DIR")"
    fi
else
    configured_hook_dir="${HOOK_DIR#"$ROOT"/}"
    case "$configured_hook_dir" in
        /*|"$HOOK_DIR") fail "hook directory is not inside $ROOT: $HOOK_DIR" ;;
    esac
fi

git -C "$ROOT" config --worktree --unset-all core.hooksPath 2>/dev/null || true
git -C "$ROOT" config --worktree core.hooksPath "$configured_hook_dir" ||
    fail "cannot write --worktree core.hooksPath (git >= 2.20 required)"

# Report what is actually in effect, read back from Git rather than assumed:
# the old message named a path and a scope this script had not written.
effective="$(git -C "$ROOT" config --get core.hooksPath 2>/dev/null || true)"
origin_pair="$(git -C "$ROOT" config --show-origin --get core.hooksPath \
    2>/dev/null || true)"
origin_file="${origin_pair%%$'\t'*}"
origin_file="${origin_file#file:}"
[[ -n "$origin_file" ]] || origin_file="(unknown)"
shared_value="$(git -C "$ROOT" config --local --get core.hooksPath \
    2>/dev/null || true)"

if [[ "$host_kind" == windows ]]; then
    git -C "$ROOT" config --worktree --unset-all z23.windowsMsys2Root \
        2>/dev/null || true
    printf '%s\n' "Installed native Windows git hooks"
    printf '%s\n' "  locked executables -> immutable content-addressed generation"
else
    printf '%s\n' "Installed native git hooks"
    printf '%s\n' "  pre-push -> admits one immutable exact commit/base receipt"
    printf '%s\n' "  post-commit/post-merge/post-checkout -> schedule proof and return"
fi
printf '%s\n' "  pre-commit -> refuses non-main-branch commits in the MAIN checkout"
printf '%s\n' "                (lane work goes in a worktree; ZCL_LANE_COMMIT_OK=1 overrides)"
printf '%s\n' "  full-suite/fuzz/coverage -> make install-quality-linger"
printf '%s\n' "  core.hooksPath  $effective"
printf '%s\n' "  scope           $origin_file"
printf '%s\n' "                  (this worktree only; no other worktree changed)"
printf '%s\n' "  resolves to     $HOOK_DIR"
if [[ -n "$shared_value" ]]; then
    printf '%s\n' \
        "  note            the SHARED config still carries core.hooksPath =" \
        "                  $shared_value, which this script leaves alone. It is" \
        "                  the fallback for any worktree that never ran" \
        "                  \`make install-hooks\`; clear it deliberately with" \
        "                  git -C $ROOT config --local --unset-all core.hooksPath"
fi
