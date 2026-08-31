#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify the checkout-local hook set selected for this host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="${ZCL_GIT_HOOK_SOURCE_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${ZCL_GIT_HOOK_ROOT:-$SOURCE_ROOT}"
CHECKER="$SCRIPT_DIR/check_git_hooks_installed.sh"
INSTALLER="$SCRIPT_DIR/install_git_hooks.sh"

run_selftest() {
    local fixture hooks native output rc failures=0 tests=0
    fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-git-hooks.XXXXXX")"
    HOOK_SELFTEST_FIXTURE="$fixture"
    trap 'rm -rf -- "$HOOK_SELFTEST_FIXTURE"' EXIT
    hooks="$fixture/build/githooks"
    native="$fixture/build/bin/z23-git-hook"
    git init -q "$fixture"

    install_windows() {
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_DIR="$hooks" ZCL_GIT_HOOK_HOST=windows \
            ZCL_GIT_HOOK_NATIVE_BIN="$fixture/does-not-exist" \
            Z23_MSYS2_ROOT_MSYS=/d/msys64 "$INSTALLER" >/dev/null
    }
    check_windows() {
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_HOST_FOR_TEST=windows \
            ZCL_GIT_HOOK_EXPECTED_MSYS2_ROOT_FOR_TEST=/d/msys64 \
            "$CHECKER"
    }
    expect_green() {
        local label="$1"; shift
        tests=$((tests + 1))
        set +e
        output="$("$@" 2>&1)"; rc=$?
        set -e
        if [[ "$rc" -ne 0 ]]; then
            printf '%s\n' "SELF-TEST FAIL: $label expected green (rc=$rc)" >&2
            printf '%s\n' "$output" >&2
            failures=$((failures + 1))
        else
            printf '%s\n' "  self-test ok (GREEN): $label"
        fi
    }
    expect_red() {
        local label="$1" needle="$2"; shift 2
        tests=$((tests + 1))
        set +e
        output="$("$@" 2>&1)"; rc=$?
        set -e
        if [[ "$rc" -eq 0 || "$output" != *"$needle"* ]]; then
            printf '%s\n' "SELF-TEST FAIL: $label expected red naming '$needle' (rc=$rc)" >&2
            printf '%s\n' "$output" >&2
            failures=$((failures + 1))
        else
            printf '%s\n' "  self-test ok (RED): $label"
        fi
    }

    expect_green "Windows install does not require the POSIX receipt binary" \
        install_windows
    expect_green "Windows exact shell-hook set and custom root reconcile" \
        check_windows

    unlink "$hooks/pre-push"
    expect_red "missing Windows pre-push is rejected" \
        "tracked shell hook" check_windows

    install_windows
    printf '%s\n' '# stale receipt hook' > "$hooks/post-commit"
    expect_red "stale Windows receipt hook is rejected" \
        "unsupported receipt hook post-commit" check_windows

    install_windows
    git -C "$fixture" config --worktree z23.windowsMsys2Root /c/wrong
    expect_red "wrong persisted custom root is rejected" \
        "expected '/d/msys64'" check_windows

    install_windows
    mkdir -p "$(dirname "$native")"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$native"
    chmod 0755 "$native"
    expect_green "POSIX native receipt hook set installs" \
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_DIR="$hooks" ZCL_GIT_HOOK_HOST=posix \
            ZCL_GIT_HOOK_NATIVE_BIN="$native" "$INSTALLER"
    expect_green "POSIX native receipt hook set reconciles" \
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_HOST_FOR_TEST=posix \
            ZCL_GIT_HOOK_NATIVE_BIN_FOR_TEST="$native" "$CHECKER"

    unlink "$hooks/pre-push"
    install -m 0755 "$SOURCE_ROOT/tools/githooks/pre-push" "$hooks/pre-push"
    expect_red "POSIX shell pre-push cannot impersonate receipt admission" \
        "is not the installed native hook" \
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_HOST_FOR_TEST=posix \
            ZCL_GIT_HOOK_NATIVE_BIN_FOR_TEST="$native" "$CHECKER"

    expect_red "unknown host selection fails closed" "unknown host selection" \
        env ZCL_GIT_HOOK_ROOT="$fixture" \
            ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" \
            ZCL_GIT_HOOK_DIR="$hooks" ZCL_GIT_HOOK_HOST=plan9 \
            "$INSTALLER"

    if [[ "$failures" -ne 0 ]]; then
        printf '%s\n' "check_git_hooks_installed: self-test FAIL ($failures/$tests)" >&2
        return 1
    fi
    printf '%s\n' "check_git_hooks_installed: self-test PASS ($tests/$tests)"
}

case "${1:-}" in
    --self-test) run_selftest; exit $? ;;
    "") ;;
    *) printf '%s\n' "usage: $0 [--self-test]" >&2; exit 2 ;;
esac

fail() {
    printf '%s\n' "check_git_hooks_installed: FAIL — $*" >&2
    printf '%s\n' "  Run: make install-hooks" >&2
    return 1
}

host_kind="${ZCL_GIT_HOOK_HOST_FOR_TEST:-}"
if [[ -z "$host_kind" ]]; then
    case "$(uname -s 2>/dev/null || true)" in
        MINGW*|MSYS*|CYGWIN*) host_kind=windows ;;
        *)                    host_kind=posix ;;
    esac
fi
case "$host_kind" in
    posix|windows) ;;
    *) fail "unknown host selection '$host_kind'"; exit 1 ;;
esac

expected="${ZCL_GIT_HOOK_EXPECTED_DIR_FOR_TEST:-$ROOT/build/githooks}"
actual="${ZCL_GIT_HOOKS_PATH_FOR_TEST:-$(git -C "$ROOT" config --worktree --get core.hooksPath 2>/dev/null || true)}"
case "$actual" in
    build/githooks) actual="$expected" ;;
esac
if [[ "$actual" != "$expected" ]]; then
    fail "checkout-local core.hooksPath is '${actual:-<unset>}'"; exit 1
fi

precommit="${ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST:-$actual/pre-commit}"
if [[ ! -x "$precommit" ]] ||
   ! cmp -s "$SOURCE_ROOT/tools/githooks/pre-commit" "$precommit"; then
    fail "pre-commit lane guard differs from the tracked hook"; exit 1
fi

if [[ "$host_kind" == windows ]]; then
    prepush="$actual/pre-push"
    if [[ ! -x "$prepush" ]] ||
       ! cmp -s "$SOURCE_ROOT/tools/githooks/pre-push" "$prepush"; then
        fail "Windows pre-push gate differs from the tracked shell hook"; exit 1
    fi
    for stale in z23-git-hook post-commit post-merge post-checkout; do
        if [[ -e "$actual/$stale" || -L "$actual/$stale" ]]; then
            fail "Windows hook set retains unsupported receipt hook $stale"; exit 1
        fi
    done
    msys2_root="$(git -C "$ROOT" config --worktree --get \
        z23.windowsMsys2Root 2>/dev/null || true)"
    case "$msys2_root" in
        /*) ;;
        *) fail "Windows MSYS2 root is missing or not an absolute MSYS path"; exit 1 ;;
    esac
    expected_msys2="${ZCL_GIT_HOOK_EXPECTED_MSYS2_ROOT_FOR_TEST:-}"
    if [[ -n "$expected_msys2" && "$msys2_root" != "$expected_msys2" ]]; then
        fail "Windows MSYS2 root is '$msys2_root', expected '$expected_msys2'"; exit 1
    fi
    grep -Fq 'z23.windowsMsys2Root' \
        "$SOURCE_ROOT/tools/githooks/pre-push" || {
        fail "tracked Windows pre-push hook does not read the persisted MSYS2 root"
        exit 1
    }
    printf '%s\n' \
        "check_git_hooks_installed: clean — Windows synchronous shell hooks armed; asynchronous receipt hooks UNAVAILABLE"
    exit 0
fi

binary="${ZCL_GIT_HOOK_NATIVE_BIN_FOR_TEST:-$ROOT/build/bin/z23-git-hook}"
if [[ ! -x "$binary" ]]; then
    fail "native hook binary is missing"; exit 1
fi
for hook in pre-push post-commit post-merge post-checkout; do
    installed="$actual/$hook"
    if [[ ! -x "$installed" ]] || ! cmp -s "$binary" "$installed"; then
        fail "$installed is not the installed native hook"; exit 1
    fi
done

source_file="${ZCL_GIT_HOOK_FILE_FOR_TEST:-$SOURCE_ROOT/tools/dev/z23_git_hook.c}"
if [[ ! -f "$source_file" ]] ||
   ! grep -Fq 'zcl_dev_proof_receipt_validate' "$source_file" ||
   ! grep -Fq 'refs/heads/main' "$source_file" ||
   ! grep -Fq 'merge-base' "$source_file" ||
   ! grep -Fq 'dev proof wait' "$source_file" ||
   ! grep -Fq 'post-commit' "$source_file"; then
    fail "native hook source lacks exact receipt admission"; exit 1
fi

"$SOURCE_ROOT/tools/lint/check_dev_proof_native_fast_path.sh" >/dev/null
"$binary" --selftest >/dev/null
printf '%s\n' \
    "check_git_hooks_installed: clean — checkout-local native receipt hooks armed"
exit 0
