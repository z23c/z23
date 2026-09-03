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

git -C "$ROOT" config extensions.worktreeConfig true
git -C "$ROOT" config --unset-all core.hooksPath 2>/dev/null || true
configured_hook_dir="$HOOK_DIR"
if [[ "$host_kind" == windows ]] && command -v cygpath >/dev/null 2>&1; then
    configured_hook_dir="$(cygpath -m "$HOOK_DIR")"
fi
git -C "$ROOT" config --worktree core.hooksPath "$configured_hook_dir"

if [[ "$host_kind" == windows ]]; then
    git -C "$ROOT" config --worktree --unset-all z23.windowsMsys2Root \
        2>/dev/null || true
    printf '%s\n' "Installed native Windows git hooks: core.hooksPath=$configured_hook_dir"
    printf '%s\n' "  locked executables -> immutable content-addressed generation"
else
    printf '%s\n' "Installed native git hooks: core.hooksPath=$HOOK_DIR"
    printf '%s\n' "  pre-push -> admits one immutable exact commit/base receipt"
    printf '%s\n' "  post-commit/post-merge/post-checkout -> schedule proof and return"
fi
printf '%s\n' "  pre-commit -> refuses non-main-branch commits in the MAIN checkout"
printf '%s\n' "                (lane work goes in a worktree; ZCL_LANE_COMMIT_OK=1 overrides)"
printf '%s\n' "  full-suite/fuzz/coverage -> make install-quality-linger"
