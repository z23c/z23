#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hooks_status.sh — `make hooks-status`. Whether this checkout's Git hooks
# are armed, and what the armed pre-push hook actually runs.
#
# WHY THIS EXISTS. `core.hooksPath` is unset by default in a freshly cloned
# or freshly `git worktree add`-ed checkout, which means NO hook fires and a
# red commit reaches origin/main unnoticed — nothing about a plain `git push`
# says so. `make install-hooks` writes THIS worktree's own Git config scope
# and nothing else's, so it is safe to run in every worktree; this is the
# read-only half — report the fact, install nothing.
#
# core.hooksPath is written per worktree (`git config --worktree`, which needs
# extensions.worktreeConfig), and an older checkout may still carry a value in
# the shared repo config. `git config --get` resolves whichever wins for THIS
# worktree; `--show-origin` names the file it came from, which is the half an
# operator actually needs when two worktrees disagree about which hooks fire.
#
# Read-only: writes nothing, installs nothing, never fails a build.
set -uo pipefail

# ZCL_HOOKS_STATUS_ROOT overrides which checkout to inspect — test isolation
# only (a manual fixture repo); unset in production, where this always
# reports the checkout the script itself lives in.
ROOT="${ZCL_HOOKS_STATUS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

hooks_path="$(git config --get core.hooksPath 2>/dev/null || true)"
origin_pair="$(git config --show-origin --get core.hooksPath 2>/dev/null || true)"
origin_file="${origin_pair%%$'\t'*}"
origin_file="${origin_file#file:}"

if [ -z "$hooks_path" ]; then
    echo "core.hooksPath: UNSET — no hook fires. \`git push\` runs no local CI at all."
    echo "arm it:         make install-hooks   (writes THIS worktree's Git config)"
    exit 0
fi

echo "core.hooksPath: $hooks_path"
case "$hooks_path" in
    /*) resolved="$hooks_path" ;;
    *)  resolved="$ROOT/$hooks_path"
        echo "                relative — Git resolves it against the top of the"
        echo "                worktree running the hook, so each worktree gets"
        echo "                its own: here, $resolved" ;;
esac
case "$origin_file" in
    "")                 echo "set in:         (origin unknown to this git)" ;;
    *config.worktree)   echo "set in:         $origin_file"
                        echo "                (this worktree's own scope — other worktrees unaffected)" ;;
    *)                  echo "set in:         $origin_file"
                        echo "                (shared repo scope — every worktree without its own"
                        echo "                config.worktree inherits this; run make install-hooks"
                        echo "                here to give this worktree its own)" ;;
esac
echo "checkout:       $ROOT"

pre_push="$resolved/pre-push"
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
