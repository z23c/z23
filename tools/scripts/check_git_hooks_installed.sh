#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_git_hooks_installed.sh — guarantee that this clone's local CI hooks are
# ARMED, and that the armed hooks are the TRACKED ones. The project runs CI
# locally, so a clone on the default .git/hooks path can push without the
# tracked tools/githooks/pre-push gate ever running.
#
# Four situations that used to be conflated into one failure, now separated:
#
#   1. core.hooksPath is UNSET — a fresh clone. Nobody chose anything, so this
#      gate ARMS it (core.hooksPath=tools/githooks), prints what it wrote, and
#      then verifies the hook contents exactly as it always has. Previously
#      this exited 1 telling the reader to run `make install-hooks`, a command
#      documented in no contributor-facing file, and left the clone UNARMED —
#      so the first thing `.github/CONTRIBUTING.md` asks a contributor to do
#      (`make lint`, and `make ci` which depends on it) could not succeed.
#
#   2. core.hooksPath is set to some OTHER directory — a deliberate choice.
#      Hard FAIL, byte-identical to the message this gate has always printed.
#      Never silently overwritten.
#
#   3. core.hooksPath is set to an ABSOLUTE spelling of this checkout's own
#      tools/githooks — same substance, different spelling (worktree agents
#      flap this). Normalized back to the canonical relative form.
#
#   4. we are in a LINKED worktree and core.hooksPath — which lives in the
#      SHARED config — carries the PRIMARY checkout's absolute spelling. That
#      is this same repository's tracked hooks directory, so it is accepted;
#      those files are additionally required to exist and be executable.
#      Previously this was indistinguishable from case 2, so `make lint` could
#      not pass in any linked worktree at all. On a plain clone git-common-dir
#      is $ROOT/.git, so this branch collapses into case 3 and nothing changes.
#      Their BODIES are deliberately not asserted — the primary checkout may
#      sit on any branch, and a lint gate must not make this tree's result
#      depend on what some other tree has checked out. The body assertions
#      always run against THIS checkout's tracked hooks, which is what this
#      tree is responsible for.
#
# The armed set is strictly LARGER after this change than before: case 1 now
# ends armed instead of unarmed, case 4 adds an existence/executable check
# where the gate previously refused to run at all, case 2 is unchanged, and
# the hook executable/content checks below run in every case. No new state
# exists in which this gate exits 0 while the wrong hooks are armed.
#
# ZCL_HOOKS_NO_AUTOARM=1 skips only the config WRITE — for a read-only
# checkout or an unpacked tarball, where the write would fail and pushing is
# not the point. It never rescues case 2 and never skips a content check; it
# prints a loud unarmed warning.
#
# --self-test builds throwaway git repositories and proves each outcome. It
# also runs automatically at the end of a normal invocation (skipped when a
# ZCL_GIT_HOOK*_FOR_TEST override is present, i.e. under the C harness, and in
# the child invocations the self-test itself spawns).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

want="tools/githooks"

hook_is_executable() {
    [[ "${ZCL_HOOK_EXECUTABLE_FOR_TEST:-1}" != "0" && -x "$1" ]]
}

##############################################################################
# Self-test — a throwaway repository per decision branch of the logic above.
##############################################################################
selftest_repo() {
    # $1 = directory to build a minimal fixture repo in.
    mkdir -p "$1/tools/scripts" "$1/tools/githooks" || return 1
    cp "$ROOT/tools/scripts/check_git_hooks_installed.sh" \
       "$1/tools/scripts/" || return 1
    cp "$ROOT/$want/pre-push" "$ROOT/$want/pre-commit" \
       "$1/$want/" || return 1
    chmod +x "$1/tools/scripts/check_git_hooks_installed.sh" \
             "$1/$want/pre-push" "$1/$want/pre-commit" || return 1
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$1" init -q >/dev/null 2>&1 || return 1
    return 0
}

selftest_git() {
    # git, with the ambient user/global/system config kept out of the fixture.
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@invalid \
        GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@invalid \
        git "$@"
}

selftest_repo_with_worktree() {
    # $1 = primary checkout dir, $2 = linked worktree dir. Echoes nothing;
    # returns non-zero if the fixture could not be built.
    selftest_repo "$1" || return 1
    selftest_git -C "$1" add -A >/dev/null 2>&1 || return 1
    selftest_git -C "$1" commit -qm fixture >/dev/null 2>&1 || return 1
    selftest_git -C "$1" worktree add -q -b lane "$2" >/dev/null 2>&1 || return 1
    return 0
}

selftest_run() {
    # $1 = fixture repo dir; remaining args = extra environment assignments.
    # Echoes the exit status; never aborts the caller.
    local repo="$1"; shift
    local rc=0
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        ZCL_HOOKS_SELFTEST_CHILD=1 ZCL_HOOKS_NO_AUTOARM= \
        ZCL_HOOK_EXECUTABLE_FOR_TEST= \
        ZCL_GIT_HOOKS_PATH_FOR_TEST= ZCL_GIT_HOOK_FILE_FOR_TEST= "$@" \
        "$repo/tools/scripts/check_git_hooks_installed.sh" \
        >/dev/null 2>&1 || rc=$?
    echo "$rc"
}

selftest_armed_value() {
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$1" config --get core.hooksPath 2>/dev/null || true
}

selftest_fail() {
    echo "check_git_hooks_installed: SELF-TEST FAIL — $1" >&2
    selftest_failures=$((selftest_failures + 1))
}

run_self_test() {
    local tmp rc armed hook_out local_sha remote_sha
    selftest_failures=0

    tmp="$(mktemp -d 2>/dev/null || true)"
    if [[ -z "$tmp" || ! -d "$tmp" ]]; then
        echo "check_git_hooks_installed: SELF-TEST SKIPPED — no writable temp dir" >&2
        return 0
    fi
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    if ! selftest_repo "$tmp/unset"; then
        echo "check_git_hooks_installed: SELF-TEST SKIPPED — cannot build a fixture git repo here" >&2
        return 0
    fi

    # (1) fresh clone, core.hooksPath unset -> auto-armed, exit 0.
    rc="$(selftest_run "$tmp/unset")"
    armed="$(selftest_armed_value "$tmp/unset")"
    [[ "$rc" == "0" ]] || selftest_fail "unset core.hooksPath should pass after arming (got exit $rc)"
    [[ "$armed" == "$want" ]] || selftest_fail "unset core.hooksPath should end armed at '$want' (got '$armed')"

    # (2) hooksPath deliberately pointed elsewhere -> hard FAIL.
    selftest_repo "$tmp/elsewhere" || selftest_fail "could not build the 'elsewhere' fixture"
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$tmp/elsewhere" config core.hooksPath .git/hooks
    rc="$(selftest_run "$tmp/elsewhere")"
    [[ "$rc" != "0" ]] || selftest_fail "core.hooksPath pointed elsewhere must FAIL (got exit 0)"

    # (3) armed, but the hook is not executable -> hard FAIL.
    selftest_repo "$tmp/notexec" || selftest_fail "could not build the 'notexec' fixture"
    rc="$(selftest_run "$tmp/notexec" ZCL_HOOK_EXECUTABLE_FOR_TEST=0)"
    [[ "$rc" != "0" ]] || selftest_fail "a non-executable pre-push hook must FAIL (got exit 0)"

    # (4) opt-out + unset -> passes the content checks, writes NOTHING.
    selftest_repo "$tmp/optout" || selftest_fail "could not build the 'optout' fixture"
    rc="$(selftest_run "$tmp/optout" ZCL_HOOKS_NO_AUTOARM=1)"
    armed="$(selftest_armed_value "$tmp/optout")"
    [[ "$rc" == "0" ]] || selftest_fail "opt-out with unset hooksPath should still verify content and pass (got exit $rc)"
    [[ -z "$armed" ]] || selftest_fail "opt-out must not write core.hooksPath (got '$armed')"

    # (5) opt-out must NOT rescue a hooksPath pointed elsewhere.
    selftest_repo "$tmp/optout_wrong" || selftest_fail "could not build the 'optout_wrong' fixture"
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$tmp/optout_wrong" config core.hooksPath .git/hooks
    rc="$(selftest_run "$tmp/optout_wrong" ZCL_HOOKS_NO_AUTOARM=1)"
    [[ "$rc" != "0" ]] || selftest_fail "opt-out must not rescue a wrong core.hooksPath (got exit 0)"

    # (6) opt-out must NOT skip a content check.
    selftest_repo "$tmp/optout_notexec" || selftest_fail "could not build the 'optout_notexec' fixture"
    rc="$(selftest_run "$tmp/optout_notexec" ZCL_HOOKS_NO_AUTOARM=1 \
        ZCL_HOOK_EXECUTABLE_FOR_TEST=0)"
    [[ "$rc" != "0" ]] || selftest_fail "opt-out must not skip the hook content checks (got exit 0)"

    # (7) linked worktree whose SHARED config carries the primary checkout's
    #     absolute hooks path -> accepted (this repository's own tracked hooks
    #     directory), instead of the blanket FAIL this used to be.
    if selftest_repo_with_worktree "$tmp/primary" "$tmp/primary_wt"; then
        selftest_git -C "$tmp/primary" config core.hooksPath "$tmp/primary/$want"
        rc="$(selftest_run "$tmp/primary_wt")"
        [[ "$rc" == "0" ]] || selftest_fail "a linked worktree sharing the primary checkout's hooks path should pass (got exit $rc)"

        # (8) ...but only for THIS repository's primary checkout. An absolute
        #     path into some unrelated directory is still a hard FAIL, even
        #     when that directory holds byte-identical hooks.
        mkdir -p "$tmp/stranger/$want"
        cp "$tmp/primary/$want/pre-push" "$tmp/primary/$want/pre-commit" \
           "$tmp/stranger/$want/"
        chmod +x "$tmp/stranger/$want/pre-push" "$tmp/stranger/$want/pre-commit"
        selftest_git -C "$tmp/primary" config core.hooksPath "$tmp/stranger/$want"
        rc="$(selftest_run "$tmp/primary_wt")"
        [[ "$rc" != "0" ]] || selftest_fail "an absolute hooks path outside this repository must FAIL (got exit 0)"

        # (9) the accepted primary hooks must still be present and executable.
        selftest_git -C "$tmp/primary" config core.hooksPath "$tmp/primary/$want"
        rc="$(selftest_run "$tmp/primary_wt" \
            ZCL_HOOK_EXECUTABLE_FOR_TEST=0)"
        [[ "$rc" != "0" ]] || selftest_fail "a non-executable hook in the primary checkout must FAIL from a worktree (got exit 0)"
    else
        echo "check_git_hooks_installed: SELF-TEST NOTE — skipped the linked-worktree cases (fixture build failed)" >&2
    fi

    # (10) A push advertisement may name a remote main commit absent from the
    # local object database. The hook must fetch that exact branch, name the
    # integration invariant, and stop before CI; a descendant proposal then
    # reaches the injected green gate. This is the physical regression for
    # the old opaque `fatal: bad object <remote-sha>` failure.
    if selftest_repo "$tmp/push_seed" &&
       selftest_git init -q --bare "$tmp/push_remote.git" &&
       printf 'base\n' >"$tmp/push_seed/base" &&
       selftest_git -C "$tmp/push_seed" add -A &&
       selftest_git -C "$tmp/push_seed" commit -qm base &&
       selftest_git -C "$tmp/push_seed" branch -M main &&
       selftest_git -C "$tmp/push_seed" remote add origin \
           "$tmp/push_remote.git" &&
       selftest_git -C "$tmp/push_seed" push -q -u origin main &&
       selftest_git --git-dir="$tmp/push_remote.git" symbolic-ref HEAD \
           refs/heads/main &&
       selftest_git clone -q "$tmp/push_remote.git" "$tmp/push_local" &&
       selftest_git clone -q "$tmp/push_remote.git" "$tmp/push_other"; then
        printf 'remote\n' >"$tmp/push_other/remote"
        selftest_git -C "$tmp/push_other" add remote
        selftest_git -C "$tmp/push_other" commit -qm remote
        selftest_git -C "$tmp/push_other" push -q origin main
        printf 'local\n' >"$tmp/push_local/local"
        selftest_git -C "$tmp/push_local" add local
        selftest_git -C "$tmp/push_local" commit -qm local
        local_sha="$(selftest_git -C "$tmp/push_local" rev-parse HEAD)"
        remote_sha="$(selftest_git --git-dir="$tmp/push_remote.git" \
            rev-parse refs/heads/main)"
        if selftest_git -C "$tmp/push_local" cat-file -e \
                "${remote_sha}^{commit}" 2>/dev/null; then
            selftest_fail 'remote-advance fixture unexpectedly already has the remote tip'
        fi
        set +e
        hook_out="$(cd "$tmp/push_local" &&
            printf 'refs/heads/main %s refs/heads/main %s\n' \
                "$local_sha" "$remote_sha" |
            ZCL_PREPUSH_CMD=true tools/githooks/pre-push origin \
                "$tmp/push_remote.git" 2>&1)"
        rc=$?
        set -e
        [[ "$rc" != "0" ]] ||
            selftest_fail 'non-descendant remote advancement must block before CI'
        case "$hook_out" in
            *remote-main-not-integrated*) ;;
            *) selftest_fail "remote advancement was not named: $hook_out" ;;
        esac
        selftest_git -C "$tmp/push_local" cat-file -e \
            "${remote_sha}^{commit}" 2>/dev/null ||
            selftest_fail 'hook did not fetch the advertised remote tip'

        selftest_git -C "$tmp/push_local" checkout -q -b integrated \
            "$remote_sha"
        printf 'integrated\n' >"$tmp/push_local/integrated"
        selftest_git -C "$tmp/push_local" add integrated
        selftest_git -C "$tmp/push_local" commit -qm integrated
        local_sha="$(selftest_git -C "$tmp/push_local" rev-parse HEAD)"
        set +e
        hook_out="$(cd "$tmp/push_local" &&
            printf 'refs/heads/main %s refs/heads/main %s\n' \
                "$local_sha" "$remote_sha" |
            ZCL_PREPUSH_CMD=true tools/githooks/pre-push origin \
                "$tmp/push_remote.git" 2>&1)"
        rc=$?
        set -e
        [[ "$rc" == "0" ]] ||
            selftest_fail "integrated advertised tip should reach green CI: $hook_out"
    else
        selftest_fail 'could not build the remote-advance pre-push fixture'
    fi

    if [[ "$selftest_failures" -ne 0 ]]; then
        echo "check_git_hooks_installed: SELF-TEST FAIL — $selftest_failures assertion(s)" >&2
        return 1
    fi
    echo "check_git_hooks_installed: self-test clean — unset arms, wrong path fails, unexecutable hook fails, opt-out writes nothing and rescues nothing, linked worktree accepts only this repository's primary hooks, remote advancement is fetched and named"
    return 0
}

if [[ "${1-}" == "--self-test" ]]; then
    run_self_test
    exit $?
fi

cd "$ROOT"

##############################################################################
# 1/2/3 — where is core.hooksPath pointing?
##############################################################################
actual="${ZCL_GIT_HOOKS_PATH_FOR_TEST-}"
if [[ -z "$actual" ]]; then
    actual="$(git config --get core.hooksPath || true)"
fi

if [[ -z "$actual" ]]; then
    # Case 1 — a fresh clone. Nobody chose anything; arm it and say so.
    if [[ -n "${ZCL_HOOKS_NO_AUTOARM:-}" ]]; then
        echo "check_git_hooks_installed: WARNING — core.hooksPath is unset and ZCL_HOOKS_NO_AUTOARM is set." >&2
        echo "  The tracked hooks are still verified below, but they are NOT active for this clone." >&2
        echo "  Arm them with: make install-hooks" >&2
    else
        git config core.hooksPath "$want"
        armed_now="$(git config --get core.hooksPath || true)"
        if [[ "$armed_now" != "$want" ]]; then
            echo "check_git_hooks_installed: FAIL — could not arm core.hooksPath (still '$armed_now', want '$want')" >&2
            echo "  Run: make install-hooks" >&2
            echo "  Or, if this checkout is intentionally read-only: ZCL_HOOKS_NO_AUTOARM=1 make lint" >&2
            exit 1
        fi
        echo "check_git_hooks_installed: armed core.hooksPath=$want (it was unset — fresh clone)"
    fi
elif [[ "$actual" != "$want" ]]; then
    # Worktree agents flap the shared config to an ABSOLUTE spelling of the
    # same directory. The gate enforces substance (the tracked hooks are the
    # armed hooks), not spelling — accept any path resolving to $ROOT/$want,
    # and normalize the stored value back to the canonical relative form.
    resolved="$(realpath -m -- "$actual" 2>/dev/null || true)"

    # core.hooksPath lives in the SHARED config, so inside a linked worktree
    # it usually carries the PRIMARY checkout's absolute spelling. The hooks
    # git will actually execute are then the primary checkout's, not this
    # worktree's same-named copies — so accept that path and point the content
    # checks below at it. On a plain clone git-common-dir is $ROOT/.git, so
    # primary_root == $ROOT and this branch is identical to the one above:
    # the only situation it changes is a linked worktree, where the gate
    # previously failed outright and no `make lint` could pass at all.
    primary_common="$(git rev-parse --git-common-dir 2>/dev/null || true)"
    primary_root=""
    if [[ -n "$primary_common" && -d "$primary_common" ]]; then
        primary_root="$(cd "$primary_common/.." && pwd)"
    fi

    if [[ "$resolved" == "$ROOT/$want" ]]; then
        if [[ -z "${ZCL_HOOKS_NO_AUTOARM:-}" ]]; then
            git config core.hooksPath "$want" 2>/dev/null || true
            echo "check_git_hooks_installed: normalized absolute core.hooksPath back to '$want'"
        fi
    elif [[ -n "$primary_root" && "$resolved" == "$primary_root/$want" &&
            -d "$resolved" ]]; then
        # The hooks git will actually execute here live in the primary
        # checkout, which may sit on a different branch — so their BODIES are
        # not asserted (that would make every worktree's `make lint` depend on
        # what the primary happens to have checked out). What is asserted is
        # that they exist and are executable, which is branch-stable. The body
        # assertions below still run, against THIS checkout's tracked hooks —
        # exactly the files this branch is responsible for.
        for h in pre-push pre-commit; do
            if ! hook_is_executable "$resolved/$h"; then
                echo "check_git_hooks_installed: FAIL — $resolved/$h is missing or not executable" >&2
                echo "  These are the hooks git runs for this worktree (core.hooksPath is shared config)." >&2
                echo "  Run, in the primary checkout: chmod +x $want/$h && make install-hooks" >&2
                exit 1
            fi
        done
        echo "check_git_hooks_installed: linked worktree — armed hooks are the primary checkout's, $resolved"
    else
        # Case 2 — a deliberate, different choice. Never overwritten, and the
        # opt-out above does not reach here.
        echo "check_git_hooks_installed: FAIL — core.hooksPath='$actual' (want '$want')" >&2
        echo "  Run: make install-hooks" >&2
        echo "  This arms tools/githooks/pre-push so local make pre-push-ci runs before push." >&2
        exit 1
    fi
fi

##############################################################################
# The armed hooks must be the tracked hooks — always checked, in every case.
##############################################################################
# Self-tests inspect an isolated copy so they never rewrite the tracked hook
# and wake the live development watcher. Production calls leave the override
# unset and therefore continue to verify the armed, tracked hook exactly.
hook="${ZCL_GIT_HOOK_FILE_FOR_TEST:-$want/pre-push}"
if ! hook_is_executable "$hook"; then
    echo "check_git_hooks_installed: FAIL — $hook is missing or not executable" >&2
    echo "  Run: chmod +x $hook && make install-hooks" >&2
    exit 1
fi

if ! awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*CMD="\$\{ZCL_PREPUSH_CMD:-make pre-push-ci\}"[[:space:]]*$/ { default_cmd=1 }
    /refs\/heads\/main/ { main_only=1 }
    /git cat-file -e "\$\{rsha\}\^\{commit\}"/ { remote_tip_loaded=1 }
    /git fetch --no-tags --quiet "\$remote_name" "\$rref"/ { fetches_advertised_ref=1 }
    /git merge-base --is-ancestor "\$rsha" "\$lsha"/ { proves_remote_ancestor=1 }
    /remote-main-not-integrated/ { names_remote_divergence=1 }
    /git diff --name-only "\$rsha" "\$lsha"/ { range_diff=1 }
    /ZCL_FAST_CHANGED_FILES_FILE="\$changed_files"/ { changed_env=1 }
    /ZCL_FAST_CHANGED_FILES_ONLY=1/ { changed_only_env=1 }
    # The gate invocation must run $CMD with both changed-files env vars set
    # and its exit status captured (directly, or piped/redirected first —
    # e.g. into a log file for SIGPIPE-safety) so a nonzero exit still
    # blocks the push.
    /^[[:space:]]*ZCL_FAST_CHANGED_FILES_FILE="\$changed_files"[[:space:]]+ZCL_FAST_CHANGED_FILES_ONLY=1[[:space:]]+\$CMD([[:space:]]*>[^|]*)?[[:space:]]*\|\|[[:space:]]*rc=\$\?[[:space:]]*$/ { invokes_cmd=1 }
    /^[[:space:]]*if[[:space:]]+![[:space:]]+ZCL_FAST_CHANGED_FILES_FILE="\$changed_files"[[:space:]]+ZCL_FAST_CHANGED_FILES_ONLY=1[[:space:]]+\$CMD;[[:space:]]*then[[:space:]]*$/ { invokes_cmd=1 }
    /rc"?[[:space:]]*-ne[[:space:]]*0/ { checks_rc=1 }
    END { exit !(default_cmd && main_only && remote_tip_loaded &&
                 fetches_advertised_ref && proves_remote_ancestor &&
                 names_remote_divergence && range_diff && changed_env &&
                 changed_only_env && invokes_cmd && checks_rc) }
' "$hook"; then
    echo "check_git_hooks_installed: FAIL — $hook does not run the local range-aware make pre-push-ci gate" >&2
    echo "  Restore the tracked pre-push hook or run: git checkout -- $hook" >&2
    exit 1
fi

# The gate's own verbose stdout must never stream straight through this
# hook's stdout/stderr — a downstream reader that doesn't fully drain it
# (agent harness, `| head`, ...) makes a `make` recipe's write() fail with
# EPIPE, which is reported as a fatal error even though the checks passed,
# spuriously blocking the push. Require the CI invocation to redirect into
# a regular file instead.
if ! grep -qE '\$CMD[[:space:]]*>[[:space:]]*"\$LOG_FILE"[[:space:]]+2>&1' "$hook"; then
    echo "check_git_hooks_installed: FAIL — $hook does not redirect the CI gate's verbose output to a log file (SIGPIPE-unsafe)" >&2
    echo "  Restore the tracked pre-push hook or run: git checkout -- $hook" >&2
    exit 1
fi

# The pre-commit main-checkout guard is armed by the same hooksPath and must
# still carry its guard: refuse a non-main-branch commit in the MAIN checkout
# (git-dir == git-common-dir) — but ONLY when the repository actually has
# extra checkouts (`git worktree list`), because with no linked worktree there
# is no parallel agent and therefore no accident to prevent. Worktrees, main
# itself, and the ZCL_LANE_COMMIT_OK deliberate-override valve stay allowed.
# Self-tests point the override at an isolated fixture, same convention as the
# pre-push check above.
precommit="${ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST:-$want/pre-commit}"
if ! hook_is_executable "$precommit"; then
    echo "check_git_hooks_installed: FAIL — $precommit is missing or not executable" >&2
    echo "  Run: chmod +x $precommit && make install-hooks" >&2
    exit 1
fi

if ! awk '
    /^[[:space:]]*#/ { next }
    /ZCL_LANE_COMMIT_OK/ { override=1 }
    /--absolute-git-dir/ { gitdir=1 }
    /--git-common-dir/ { common=1 }
    /git symbolic-ref --short/ { branch=1 }
    /git worktree list/ { wtlist=1 }
    /git worktree add \.claude\/worktrees/ { howto=1 }
    /exit 1/ { refuses=1 }
    END { exit !(override && gitdir && common && branch && wtlist && howto && refuses) }
' "$precommit"; then
    echo "check_git_hooks_installed: FAIL — $precommit does not carry the main-checkout lane guard scoped to repositories with extra checkouts" >&2
    echo "  Restore the tracked pre-commit hook or run: git checkout -- $precommit" >&2
    exit 1
fi

echo "check_git_hooks_installed: clean — core.hooksPath=$want"

# Prove the three-case decision above still decides the way it claims to.
# Skipped under the C harness (which drives this script with explicit
# ZCL_GIT_HOOK*_FOR_TEST overrides) and inside the self-test's own children.
if [[ -z "${ZCL_HOOKS_SELFTEST_CHILD:-}${ZCL_GIT_HOOKS_PATH_FOR_TEST-}${ZCL_GIT_HOOK_FILE_FOR_TEST:-}${ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST:-}" ]]; then
    run_self_test
fi
