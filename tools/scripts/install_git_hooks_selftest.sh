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

scratch_base="${ZCL_SCRATCH_DIR:-$HOME/.local/state/zclassic23/scratch}"
mkdir -p "$scratch_base" 2>/dev/null || scratch_base="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "$scratch_base/zcl-hooks-selftest.XXXXXX")" ||
    unobserved "cannot create a scratch directory under $scratch_base"
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

# Exercise the real parse-time bootstrap decision with missing archives. The
# fixture replaces build actions only: a marker proves whether Make remade
# the included vendor prerequisite before reaching the requested hook goal.
bootstrap_fixture="$WORK/bootstrap"
mkdir -p "$bootstrap_fixture"
awk '/^ZCL_WINDOWS_LAUNCHER_GOALS :=/ { copying=1 }
     /^# Generated view headers/ { exit }
     copying { print }' "$SOURCE_ROOT/Makefile" > "$bootstrap_fixture/Makefile"
grep -q '^ZCL_BOOTSTRAP_HELPER_ONLY :=' "$bootstrap_fixture/Makefile" ||
    fail "vendor bootstrap fixture did not capture the real Makefile block"
awk '/^ZCL_TOR_SKIP_GOALS :=/ { copying=1 }
     /^# The stub is reachable/ { exit }
     copying { print }' "$SOURCE_ROOT/Makefile" >> "$bootstrap_fixture/Makefile"
grep -q '^ZCL_TOR_LINK_REQUESTED :=' "$bootstrap_fixture/Makefile" ||
    fail "Tor bootstrap fixture did not capture the real Makefile block"
cat >> "$bootstrap_fixture/Makefile" <<'MAKE'
.DEFAULT_GOAL := z23
.PHONY: git-hook git-hook-selftest install-hooks z23 unknown-goal
git-hook git-hook-selftest install-hooks:
	@touch hook-ran
z23 unknown-goal:
	@touch node-ran
vendor-ready.mk:
	@touch vendor-ran
	@printf '# established\n' > $@
tor-ready.mk:
	@touch tor-ran
	@printf '# established\n' > $@
MAKE
for goals in git-hook git-hook-selftest install-hooks \
        'git-hook install-hooks' 'install-hooks z23' unknown-goal default; do
    rm -f "$bootstrap_fixture/"{hook-ran,node-ran,vendor-ran,vendor-ready.mk,tor-ran,tor-ready.mk}
    goal_args=()
    [[ "$goals" == default ]] || read -r -a goal_args <<< "$goals"
    if ! make -s -C "$bootstrap_fixture" VENDOR_MISSING_INPUTS=missing.a \
            VENDOR_BOOTSTRAP_MK=vendor-ready.mk ZCL_TOR=full \
            TOR_MISSING_ARCHIVES=missing-tor.a TOR_BOOTSTRAP_MK=tor-ready.mk \
            "${goal_args[@]}" \
            > "$bootstrap_fixture/output" 2>&1; then
        fail "bootstrap probe failed for $goals: $(cat "$bootstrap_fixture/output")"
        continue
    fi
    case "$goals" in
        'install-hooks z23'|unknown-goal|default)
            [[ -f "$bootstrap_fixture/vendor-ran" && -f "$bootstrap_fixture/tor-ran" && -f "$bootstrap_fixture/node-ran" ]] ||
                fail "node or unknown goal bypassed vendor/Tor bootstrap: $goals" ;;
        *)
            [[ -f "$bootstrap_fixture/hook-ran" && ! -e "$bootstrap_fixture/vendor-ran" && ! -e "$bootstrap_fixture/tor-ran" ]] ||
                fail "standalone hook goal performed unrelated vendor/Tor bootstrap: $goals" ;;
    esac
done
[[ "$bad" == 0 ]] || exit 1
[[ -x "$NATIVE_BIN" ]] ||
    unobserved "native hook binary absent: $NATIVE_BIN (make git-hook)"

# A fixture repository never inherits the operator's signing or identity
# settings: those would make a fixture commit prompt, sign, or refuse.
fixture_git() {
    git -c commit.gpgsign=false -c user.name=z23 -c user.email=z23@invalid "$@"
}
# Landing deliberately suppresses its own post-hooks. Its foreground proof
# inherits that setting, but these isolated repositories must exercise their
# hooks. A subshell preserves the invoking landing process's environment.
g() ( unset ZCL_LAND_HOOK_QUIET; fixture_git "$@"; )

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

# ── D. a rebuilt hook binary reaches an armed checkout, and only that one ───
# WT_A/WT_B were armed above; WT_C never was. A changed binary stands in for a
# rebuild of z23-git-hook; the refresh step is what the Makefile rule runs.
REFRESH="$SCRIPT_DIR/refresh_git_hooks_if_armed.sh"
NEW_BIN="$WORK/z23-git-hook.rebuilt"
cp -- "$NATIVE_BIN" "$NEW_BIN" && printf 'rebuilt\n' >>"$NEW_BIN"
refresh_into() {
    ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" ZCL_GIT_HOOK_ROOT="$1" \
    ZCL_GIT_HOOK_NATIVE_BIN="$NEW_BIN" "$REFRESH" >/dev/null 2>&1
}
[[ -x "$REFRESH" ]] || fail "refresh_git_hooks_if_armed.sh is missing or not executable"
if [[ -x "$REFRESH" ]]; then
    cmp -s "$NEW_BIN" "$WT_A/build/githooks/z23-git-hook" &&
        fail "fixture rebuild did not change the installed hook comparison"
    refresh_into "$WT_A" || fail "refresh in armed $WT_A exited nonzero"
    cmp -s "$NEW_BIN" "$WT_A/build/githooks/z23-git-hook" ||
        fail "armed $WT_A kept a stale hook after a rebuild"
    for hook in pre-push post-commit post-merge post-checkout; do
        [[ "$(readlink "$WT_A/build/githooks/$hook")" == z23-git-hook ]] ||
            fail "armed $WT_A lost its $hook link after refresh"
    done
    [[ "$(effective "$WT_A")" == "build/githooks" ]] ||
        fail "refresh moved $WT_A's core.hooksPath"
    cmp -s "$NEW_BIN" "$WT_B/build/githooks/z23-git-hook" &&
        fail "refreshing $WT_A rewrote the hooks of $WT_B"
    # An unarmed checkout stays unarmed and gains no hook files. WT_D has no
    # worktree-scope value; WT_C inherited one but never installed hooks.
    WT_D="$WORK/wt-d"
    g -C "$REPO" worktree add -q -b wt-d "$WT_D" >/dev/null 2>&1 ||
        fail "git worktree add failed for wt-d"
    git -C "$WT_D" config --worktree --unset-all core.hooksPath >/dev/null 2>&1
    for idle in "$WT_C" "$WT_D"; do
        [[ -d "$idle" ]] || continue
        before_i="$(git -C "$idle" config --worktree --get core.hooksPath 2>&1)"
        refresh_into "$idle" || fail "refresh in idle $idle exited nonzero"
        after_i="$(git -C "$idle" config --worktree --get core.hooksPath 2>&1)"
        [[ "$before_i" == "$after_i" ]] ||
            fail "refresh changed idle $idle: '$before_i' -> '$after_i'"
        [[ ! -e "$idle/build/githooks/z23-git-hook" ]] ||
            fail "refresh installed hooks into idle $idle"
    done
    [[ -z "$(git -C "$WT_D" config --worktree --get core.hooksPath 2>/dev/null)" ]] ||
        fail "refresh armed unarmed $WT_D"
    [[ "$(shared_value "$REPO")" == "$SENTINEL" ]] ||
        fail "refresh changed the SHARED core.hooksPath"
fi

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

# An ordinary commit with foreground-proof residue must not launch any dev
# process. The fixture dev executable only records attempted invocation;
# neither a watcher nor a service is activated by this regression.
QUIET="$WORK/quiet"
g init -q -b main "$QUIET" || fail "quiet fixture init failed"
mkdir -p "$QUIET/build/githooks" "$QUIET/build/bin" "$QUIET/.cache"
printf '#!/usr/bin/env bash\nexec %q --hook=post-commit\n' "$NATIVE_BIN" \
    > "$QUIET/build/githooks/post-commit"
cat > "$QUIET/build/bin/z23-dev" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$*" >> proof-notify-marker
EOF
chmod 700 "$QUIET/build/githooks/post-commit" "$QUIET/build/bin/z23-dev"
g -C "$QUIET" config --local core.hooksPath build/githooks
for residue in empty dead malformed unreadable; do
    case "$residue" in
        empty) : > "$QUIET/.cache/zcl-dev-watch.lock" ;;
        dead) printf '999999 verify ready proofq1\n' > "$QUIET/.cache/zcl-dev-watch.lock" ;;
        malformed) printf 'not a watcher receipt\n' > "$QUIET/.cache/zcl-dev-watch.lock" ;;
        unreadable) chmod 000 "$QUIET/.cache/zcl-dev-watch.lock" ;;
    esac
    printf '%s\n' "$residue" >> "$QUIET/seed"
    g -C "$QUIET" add seed
    g -C "$QUIET" commit -q -m "$residue" || fail "$residue quiet fixture commit failed"
done
chmod 600 "$QUIET/.cache/zcl-dev-watch.lock"
# Detached post-hook children, if incorrectly launched, have a bounded window
# to expose their invocation. All fixture executables terminate immediately.
sleep 1
[[ ! -e "$QUIET/proof-notify-marker" ]] || \
    fail "an ordinary commit launched a dev process from stale watcher residue"

# Explicit landing suppression must still prevent notification even when the
# fixture has a complete, kernel-held ready record. Presence, including an
# empty value, is the production hook's suppression contract.
(
    exec 9> "$QUIET/.cache/zcl-dev-watch.lock"
    flock -x 9 || exit 1
    printf '2 verify ready proofq1 1 %s\n' \
        1111111111111111111111111111111111111111111111111111111111111111 >&9
    for quiet_value in 1 ''; do
        printf 'explicit-quiet\n' >> "$QUIET/seed"
        g -C "$QUIET" add seed
        ZCL_LAND_HOOK_QUIET="$quiet_value" \
            fixture_git -C "$QUIET" commit -q -m explicit-quiet || exit 1
    done
    sleep 1
) || fail "explicit quiet fixture failed"
[[ ! -e "$QUIET/proof-notify-marker" ]] || \
    fail "explicit landing suppression notified a fixture receiver"

# A kernel-held complete candidate must transport the attach-only key. This
# is a notification wiring fixture, not a claim of native session authority:
# the fixture executable records argv and cannot activate a watcher.
(
    exec 9> "$QUIET/.cache/zcl-dev-watch.lock"
    flock -x 9 || exit 1
    printf '2 verify ready proofq1 1 %s\n' \
        1111111111111111111111111111111111111111111111111111111111111111 >&9
    printf 'held-ready\n' >> "$QUIET/seed"
    g -C "$QUIET" add seed
    g -C "$QUIET" commit -q -m held-ready || exit 1
    # Git has returned, but the detached receiver need not have run yet.
    # Keep the ready lock held until its complete argv is observed. Retain
    # append semantics: duplicate notifications must still fail exact equality.
    notify_deadline=$((SECONDS + 10))
    while [[ ! -f "$QUIET/proof-notify-marker" ]] ||
          [[ "$(cat "$QUIET/proof-notify-marker")" != \
             'dev proof ensure --input={"require_existing_watcher":true}' ]]; do
        (( SECONDS < notify_deadline )) || exit 1
        sleep 0.1
    done
) || fail "held candidate fixture failed"
[[ -f "$QUIET/proof-notify-marker" ]] || fail "held candidate did not notify fixture receiver"
if [[ -f "$QUIET/proof-notify-marker" ]]; then
    [[ "$(cat "$QUIET/proof-notify-marker")" == \
        'dev proof ensure --input={"require_existing_watcher":true}' ]] || \
        fail "held candidate notification omitted attach-only authority guard"
fi

if [[ "$bad" -ne 0 ]]; then
    exit 1
fi
printf '%s\n' \
    "install_git_hooks: self-test PASS (per-worktree scope: a shared value and" \
    "  every other worktree survive an install; relative core.hooksPath resolves" \
    "  to the worktree that runs the hook; a second run rewrites nothing; a rebuilt" \
    "  hook binary reaches an armed checkout and never arms an unarmed one)"
