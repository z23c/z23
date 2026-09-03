#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hooks_status.sh — `make hooks-status`. Whether this checkout's Git hooks
# are armed, and what the armed pre-push hook actually runs.
#
# WHY THIS EXISTS. `core.hooksPath` is unset by default in a freshly cloned
# or freshly `git worktree add`-ed checkout, which means NO hook fires and a
# red commit reaches origin/main unnoticed — nothing about a plain `git push`
# says so. `make install-hooks` is a repo-shared write (it touches this
# checkout's Git config, which every worktree on the same checkout reads via
# `extensions.worktreeConfig`), so it belongs to the operator/orchestrator,
# never to a lane script. This is the read-only half: report the fact,
# install nothing.
#
# core.hooksPath can be set at either config scope install_git_hooks.sh uses
# (checkout-local `--worktree`, once `extensions.worktreeConfig=true`, or the
# plain repo config on an older checkout); `git config --get core.hooksPath`
# resolves whichever is effective for THIS worktree without this script
# needing to know which scope won.
#
# Read-only: writes nothing, installs nothing, never fails a build.
set -uo pipefail

# ZCL_HOOKS_STATUS_ROOT overrides which checkout to inspect — test isolation
# only (a manual fixture repo); unset in production, where this always
# reports the checkout the script itself lives in.
ROOT="${ZCL_HOOKS_STATUS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

hooks_path="$(git config --get core.hooksPath 2>/dev/null || true)"

if [ -z "$hooks_path" ]; then
    echo "core.hooksPath: UNSET — no hook fires. \`git push\` runs no local CI at all."
    echo "arm it:         make install-hooks   (writes this checkout's Git config)"
    exit 0
fi

echo "core.hooksPath: $hooks_path"

pre_push="$hooks_path/pre-push"
if [ ! -e "$pre_push" ] && [ -e "$pre_push.exe" ]; then
    pre_push="$pre_push.exe"
fi
if [ ! -e "$pre_push" ] && [ ! -L "$pre_push" ]; then
    echo "pre-push:       MISSING at $pre_push despite hooksPath being set"
    echo "                re-arm: make install-hooks"
    exit 0
fi

if [ -L "$pre_push" ]; then
    target="$(readlink "$pre_push" 2>/dev/null || echo '?')"
    echo "pre-push:       $pre_push -> $target"
    case "$target" in
        z23-git-hook)
            echo "runs:           the native receipt hook — admits one immutable"
            echo "                exact commit/base receipt (see tools/dev/z23_git_hook.c);"
            echo "                post-commit/post-merge/post-checkout schedule proof and return"
            ;;
        *)
            echo "runs:           unrecognized symlink target — inspect $pre_push directly"
            ;;
    esac
else
    case "$pre_push" in
        *.exe)
            echo "pre-push:       $pre_push (native Windows receipt hook)"
            echo "runs:           immutable exact commit/base receipt admission;"
            echo "                no shell, Make, compile, test, wait, or fetch"
            ;;
        *)
            echo "pre-push:       $pre_push (unrecognized regular hook)"
            echo "runs:           inspect this file; re-arm with make install-hooks"
            ;;
    esac
fi

echo "last measured wall: see the header of tools/githooks/pre-push (never"
echo "                     re-typed here — timings drift, the file does not)"
echo "bypass one push:     git push --no-verify   OR   ZCL_SKIP_PREPUSH=1 git push"
echo "full-suite/fuzz/coverage (not on this path): make install-quality-linger"
