#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Install the checkout-local hook set selected for this host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="${ZCL_GIT_HOOK_SOURCE_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${ZCL_GIT_HOOK_ROOT:-$SOURCE_ROOT}"
HOOK_DIR="${ZCL_GIT_HOOK_DIR:-$ROOT/build/githooks}"
NATIVE_BIN="${ZCL_GIT_HOOK_NATIVE_BIN:-$ROOT/build/bin/z23-git-hook}"

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

windows_msys2_root=""
if [[ "$host_kind" == windows ]]; then
    [[ -x "$SOURCE_ROOT/tools/githooks/pre-push" ]] ||
        fail "tracked pre-push hook is missing or not executable"
    windows_msys2_root="${Z23_WINDOWS_MSYS2_ROOT:-${Z23_MSYS2_ROOT_MSYS:-}}"
    if [[ -z "$windows_msys2_root" ]]; then
        windows_msys2_root="$(git -C "$ROOT" config --worktree --get \
            z23.windowsMsys2Root 2>/dev/null || true)"
    fi
    windows_msys2_root="${windows_msys2_root:-/c/msys64}"
    case "$windows_msys2_root" in
        /*) ;;
        *) fail "MSYS2 root must be an absolute MSYS path: $windows_msys2_root" ;;
    esac
    [[ "$windows_msys2_root" != *$'\n'* &&
       "$windows_msys2_root" != *$'\r'* ]] ||
        fail "MSYS2 root contains a line break"
else
    [[ -x "$NATIVE_BIN" ]] || fail "native receipt hook is missing: $NATIVE_BIN"
fi

unlink_if_present() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        unlink -- "$path" || fail "cannot replace stale hook: $path"
    fi
}

mkdir -p "$HOOK_DIR"
install -m 0755 "$SOURCE_ROOT/tools/githooks/pre-commit" \
    "$HOOK_DIR/pre-commit"

if [[ "$host_kind" == windows ]]; then
    install -m 0755 "$SOURCE_ROOT/tools/githooks/pre-push" \
        "$HOOK_DIR/pre-push"
    for stale in z23-git-hook post-commit post-merge post-checkout; do
        unlink_if_present "$HOOK_DIR/$stale"
    done
else
    install -m 0755 "$NATIVE_BIN" "$HOOK_DIR/z23-git-hook"
    for hook in pre-push post-commit post-merge post-checkout; do
        unlink_if_present "$HOOK_DIR/$hook"
        ln -s z23-git-hook "$HOOK_DIR/$hook"
    done
fi

git -C "$ROOT" config extensions.worktreeConfig true
git -C "$ROOT" config --unset-all core.hooksPath 2>/dev/null || true
git -C "$ROOT" config --worktree core.hooksPath "$HOOK_DIR"

if [[ "$host_kind" == windows ]]; then
    git -C "$ROOT" config --worktree z23.windowsMsys2Root \
        "$windows_msys2_root"
    printf '%s\n' "Installed Windows shell hooks: core.hooksPath=$HOOK_DIR"
    printf '%s\n' "  pre-push -> synchronous native Windows acceptance"
    printf '%s\n' "  MSYS2 root -> $windows_msys2_root"
    printf '%s\n' "  asynchronous exact-receipt hooks -> UNAVAILABLE on Windows"
else
    printf '%s\n' "Installed native git hooks: core.hooksPath=$HOOK_DIR"
    printf '%s\n' "  pre-push -> admits one immutable exact commit/base receipt"
    printf '%s\n' "  post-commit/post-merge/post-checkout -> schedule proof and return"
fi
printf '%s\n' "  pre-commit -> refuses non-main-branch commits in the MAIN checkout"
printf '%s\n' "                (lane work goes in a worktree; ZCL_LANE_COMMIT_OK=1 overrides)"
printf '%s\n' "  full-suite/fuzz/coverage -> make install-quality-linger"
