#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify that this worktree uses its native receipt-admission hooks.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

expected="$ROOT/build/githooks"
actual="${ZCL_GIT_HOOKS_PATH_FOR_TEST:-$(git config --worktree --get core.hooksPath 2>/dev/null || true)}"
case "$actual" in
    build/githooks) actual="$expected" ;;
esac

if [[ "$actual" != "$expected" ]]; then
    echo "check_git_hooks_installed: FAIL — checkout-local core.hooksPath is '${actual:-<unset>}'" >&2
    echo "  Run: make install-hooks" >&2
    exit 1
fi

binary="$ROOT/build/bin/z23-git-hook"
if [[ ! -x "$binary" ]]; then
    echo "check_git_hooks_installed: FAIL — native hook binary is missing" >&2
    echo "  Run: make install-hooks" >&2
    exit 1
fi

for hook in pre-push post-commit post-merge post-checkout; do
    installed="$actual/$hook"
    if [[ ! -x "$installed" ]] || ! cmp -s "$binary" "$installed"; then
        echo "check_git_hooks_installed: FAIL — $installed is not the installed native hook" >&2
        echo "  Run: make install-hooks" >&2
        exit 1
    fi
done

precommit="${ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST:-$actual/pre-commit}"
if [[ ! -x "$precommit" ]] || ! cmp -s tools/githooks/pre-commit "$precommit"; then
    echo "check_git_hooks_installed: FAIL — pre-commit lane guard differs from the tracked hook" >&2
    exit 1
fi

source_file="${ZCL_GIT_HOOK_FILE_FOR_TEST:-tools/dev/z23_git_hook.c}"
if [[ ! -f "$source_file" ]] ||
   ! grep -Fq 'zcl_dev_proof_receipt_validate' "$source_file" ||
   ! grep -Fq 'refs/heads/main' "$source_file" ||
   ! grep -Fq 'merge-base' "$source_file" ||
   ! grep -Fq 'dev proof wait' "$source_file" ||
   ! grep -Fq 'post-commit' "$source_file"; then
    echo "check_git_hooks_installed: FAIL — native hook source lacks exact receipt admission" >&2
    exit 1
fi

tools/lint/check_dev_proof_native_fast_path.sh >/dev/null
"$binary" --selftest >/dev/null

echo "check_git_hooks_installed: clean — checkout-local native hooks armed"
