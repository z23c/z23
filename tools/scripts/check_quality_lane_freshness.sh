#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_quality_lane_freshness.sh — is the background quality lane's OWN
# checkout ($ROOT — the systemd unit's WorkingDirectory, %h/github/zclassic23)
# actually at the tip of `main`, or pinned to whatever commit it happened to
# be checked out at?
#
# background_quality_lane.sh's prepare_lane_tree() already does the right
# thing ONE level down: every lane run re-points its isolated worktree at
# $ROOT's CURRENT HEAD (`git reset --hard "$head"`), so that half of the
# pipeline can never go stale relative to $ROOT. What it cannot fix is $ROOT
# itself: if $ROOT sits in detached HEAD at a fixed commit instead of
# following the `main` branch ref, or simply never gets fast-forwarded,
# every lane run faithfully refreshes against a HEAD that never moves — the
# fuzz lane re-fuzzes and re-reports an already-fixed bug forever, and a
# reader has no signal that the lane's evidence is about old code. This is
# the same shape of incident recorded for the (separate, since-removed)
# mesh referee, which judged for hours from a checkout six commits behind
# main with nothing surfacing it.
#
# WHAT THIS CHECKS. `main`'s tip is resolved locally first — worktrees of
# this repository share one object store and one set of refs, so if $ROOT is
# a worktree of the same repository as `main` lives in, no network fetch is
# needed and none is attempted. Only when no local `main` ref exists (a
# standalone clone of $ROOT) does this fall back to `origin/main`, which
# requires `git fetch` and therefore a network path — that fallback FAILS
# closed (exit 2) rather than silently reporting "0 behind" when the fetch
# does not run or does not succeed.
#
# Usage:
#   check_quality_lane_freshness.sh --check   [--root=DIR] [--ref=REF]
#   check_quality_lane_freshness.sh --refresh [--root=DIR] [--ref=REF]
#   check_quality_lane_freshness.sh --selftest
#
#   --check (default if neither given): report commits-behind and exit
#       0  = at the ref's tip (or ahead of it — a local integration checkout
#            legitimately can be)
#       1  = behind — VISIBLE staleness, not a hard build failure by itself
#       2  = could not determine (not a git checkout, ref not resolvable,
#            network fetch required and failed) — fail closed, never "0"
#
#   --refresh: does --check's resolution, and if $ROOT is behind AND it is
#       safe (working tree clean via `git status --porcelain`, HEAD is
#       either already on a branch named $REF or detached-with-no-commits-
#       of-its-own-ahead-of-$REF), fast-forwards $ROOT to the ref tip
#       (`git merge --ff-only`, checking out $REF first if detached). Never
#       forces, never discards a dirty tree, never touches history that has
#       diverged — any of those abort with a named reason and exit 2, the
#       same "cannot safely act" signal --check gives when it cannot tell.
#
# Mode: WARN | FAIL (ZCL_LINT_MODE; default FAIL) — only affects the process
# exit code on staleness, never the printed report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="check_quality_lane_freshness"

ACTION="check"
ROOT_ARG=""
REF="main"
for arg in "$@"; do
    case "$arg" in
        --check)      ACTION="check" ;;
        --refresh)    ACTION="refresh" ;;
        --selftest)   ACTION="selftest" ;;
        --root=*)     ROOT_ARG="${arg#--root=}" ;;
        --ref=*)      REF="${arg#--ref=}" ;;
        -h|--help)
            echo "usage: $GATE.sh [--check|--refresh|--selftest] [--root=DIR] [--ref=REF]"
            exit 0 ;;
        *) echo "$GATE: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

# report_freshness ROOT REF -> prints "commits_behind=N root_head=<sha> ref_head=<sha> ref_source=<local|origin>"
# on stdout and returns 0 (at/ahead of tip), 1 (behind), or 2 (could not tell).
report_freshness() {
    local root="$1" ref="$2" root_head ref_head ref_source behind
    if ! git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "$GATE: FATAL — '$root' is not a git checkout" >&2
        return 2
    fi
    root_head="$(git -C "$root" rev-parse HEAD 2>/dev/null)" || {
        echo "$GATE: FATAL — cannot resolve HEAD in '$root'" >&2
        return 2
    }

    if git -C "$root" rev-parse --verify -q "refs/heads/$ref" >/dev/null 2>&1; then
        ref_head="$(git -C "$root" rev-parse "refs/heads/$ref")"
        ref_source="local"
    else
        # No local branch named $ref: this checkout is either not a worktree
        # of the repo that carries it, or $ref really has no local branch.
        # Only path left is a network fetch — and if that does not
        # unambiguously succeed, this reports FATAL rather than "0 behind".
        if ! git -C "$root" fetch --quiet origin "$ref" 2>/dev/null; then
            echo "$GATE: FATAL — no local 'refs/heads/$ref' in '$root' and 'git fetch origin $ref' failed" >&2
            echo "  Refusing to report a commits-behind count without a resolved tip: that is" >&2
            echo "  exactly the silent-stale shape this gate exists to close." >&2
            return 2
        fi
        ref_head="$(git -C "$root" rev-parse FETCH_HEAD 2>/dev/null)" || {
            echo "$GATE: FATAL — fetched origin/$ref but cannot resolve FETCH_HEAD" >&2
            return 2
        }
        ref_source="origin"
    fi

    if [[ "$root_head" == "$ref_head" ]]; then
        printf 'commits_behind=0 root_head=%s ref_head=%s ref_source=%s\n' \
            "$root_head" "$ref_head" "$ref_source"
        return 0
    fi

    if git -C "$root" merge-base --is-ancestor "$root_head" "$ref_head" 2>/dev/null; then
        behind="$(git -C "$root" rev-list --count "$root_head..$ref_head" 2>/dev/null || echo '?')"
        printf 'commits_behind=%s root_head=%s ref_head=%s ref_source=%s\n' \
            "$behind" "$root_head" "$ref_head" "$ref_source"
        return 1
    fi

    if git -C "$root" merge-base --is-ancestor "$ref_head" "$root_head" 2>/dev/null; then
        # root is AHEAD of ref (a local integration checkout that has not
        # pushed yet). Not staleness — report it plainly and pass.
        printf 'commits_behind=0 root_head=%s ref_head=%s ref_source=%s note=root_is_ahead\n' \
            "$root_head" "$ref_head" "$ref_source"
        return 0
    fi

    echo "$GATE: FATAL — '$root' HEAD ($root_head) and $ref ($ref_head) have DIVERGED" >&2
    echo "  Neither is an ancestor of the other. A commits-behind count is not" >&2
    echo "  meaningful here; this needs a human, not an automatic refresh." >&2
    return 2
}

do_check() {
    local root="$1" ref="$2" out rc
    rc=0
    out="$(report_freshness "$root" "$ref")" || rc=$?
    printf '%s\n' "$out"
    if (( rc == 1 )); then
        echo "$GATE: '$root' is BEHIND $ref — the quality lanes it drives are" >&2
        echo "  fuzzing/testing OLD code. Refresh with:" >&2
        echo "  $0 --refresh --root=$root --ref=$ref" >&2
    fi
    return "$rc"
}

do_refresh() {
    local root="$1" ref="$2" out rc dirty cur_branch
    rc=0
    out="$(report_freshness "$root" "$ref")" || rc=$?
    printf '%s\n' "$out"
    if (( rc == 0 )); then
        echo "$GATE: '$root' is already at (or ahead of) $ref — nothing to refresh"
        return 0
    fi
    if (( rc == 2 )); then
        echo "$GATE: FATAL — cannot refresh: freshness could not be determined (see above)" >&2
        return 2
    fi

    dirty="$(git -C "$root" status --porcelain 2>/dev/null)" || {
        echo "$GATE: FATAL — 'git status' failed in '$root'" >&2
        return 2
    }
    if [[ -n "$dirty" ]]; then
        echo "$GATE: REFUSING to refresh — '$root' has uncommitted changes." >&2
        echo "  A stale pin is a visible problem; discarding someone's work to fix it" >&2
        echo "  would be a worse one. Commit or stash by hand, then re-run." >&2
        return 2
    fi

    cur_branch="$(git -C "$root" symbolic-ref --short -q HEAD || true)"
    if [[ -n "$cur_branch" && "$cur_branch" != "$ref" ]]; then
        echo "$GATE: REFUSING to refresh — '$root' is on branch '$cur_branch', not '$ref'." >&2
        echo "  Switching branches out from under a running lane is not this gate's job." >&2
        return 2
    fi

    if [[ -z "$cur_branch" ]]; then
        # Detached HEAD, verified above to be a strict ancestor of $ref (not
        # diverged): attach to $ref, which is always a fast-forward from here.
        if ! git -C "$root" checkout -q "$ref" 2>/dev/null; then
            echo "$GATE: FATAL — 'git checkout $ref' failed in '$root'" >&2
            return 2
        fi
    fi

    if ! git -C "$root" merge --ff-only -q "$ref" 2>/dev/null; then
        echo "$GATE: FATAL — 'git merge --ff-only $ref' failed in '$root'" >&2
        echo "  Not forcing it. Resolve by hand." >&2
        return 2
    fi

    local new_head
    new_head="$(git -C "$root" rev-parse HEAD)"
    echo "$GATE: refreshed '$root' to $ref ($new_head)"
    return 0
}

# ── --selftest: prove the detector actually detects, and refresh actually
# fast-forwards, and refuses on a dirty tree — using two disposable git
# repos, never the real $ROOT. ──
run_selftest() {
    local work upstream clone rc out
    work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-quality-freshness-selftest.XXXXXX")"
    trap 'rm -rf "$work"' RETURN
    upstream="$work/upstream"
    clone="$work/clone"
    mkdir -p "$upstream"
    git -C "$upstream" init -q -b main
    git -C "$upstream" -c user.email=t@t -c user.name=t commit -q --allow-empty -m c1
    git clone -q "$upstream" "$clone" >/dev/null 2>&1
    # Detach immediately: git refuses to fetch a ref onto the branch that is
    # currently checked out, and the real-world case this models — $ROOT
    # pinned at a fixed commit instead of following `main` — IS detached.
    # Staying detached for the rest of the test (re-detaching after the one
    # point that legitimately attaches, --refresh) is what lets each
    # `fetch main:main` below succeed.
    git -C "$clone" checkout -q --detach HEAD

    # 1. Freshly cloned, detached at main's own tip: 0 behind.
    rc=0; out="$(report_freshness "$clone" main)" || rc=$?
    if [[ "$rc" -ne 0 ]] || ! str_contains "$out" "commits_behind=0"; then
        echo "$GATE --selftest: FAIL — a fresh clone at main's tip reported behind" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi

    # 2. Advance upstream two commits and pull the ref (not the tree) into
    #    the clone's local 'main' — this is what a linked worktree gets for
    #    free by sharing refs; a plain clone needs the explicit update. The
    #    clone's HEAD stays detached at c1, so this must report behind=2.
    git -C "$upstream" -c user.email=t@t -c user.name=t commit -q --allow-empty -m c2
    git -C "$upstream" -c user.email=t@t -c user.name=t commit -q --allow-empty -m c3
    git -C "$clone" fetch -q "$upstream" main:main
    rc=0; out="$(report_freshness "$clone" main)" || rc=$?
    if [[ "$rc" -ne 1 ]] || ! str_contains "$out" "commits_behind=2"; then
        echo "$GATE --selftest: FAIL — did not detect 2-commits-behind" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi

    # 3. --refresh on a clean, non-diverged detached tree fast-forwards
    #    (this is the one point where the clone legitimately attaches to
    #    the branch — checking that out and merging --ff-only is the point).
    rc=0; out="$(do_refresh "$clone" main)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "$GATE --selftest: FAIL — refresh did not succeed on a safe case" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi
    rc=0; out="$(report_freshness "$clone" main)" || rc=$?
    if [[ "$rc" -ne 0 ]] || ! str_contains "$out" "commits_behind=0"; then
        echo "$GATE --selftest: FAIL — refresh ran but tree is still behind" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi

    # 4. Detach again (undoing step 3's attach, back to the pinned shape),
    #    fall behind once more, dirty the tree, and prove --refresh REFUSES
    #    rather than discarding the uncommitted change.
    git -C "$clone" checkout -q --detach HEAD
    git -C "$upstream" -c user.email=t@t -c user.name=t commit -q --allow-empty -m c4
    git -C "$clone" fetch -q "$upstream" main:main
    echo dirty > "$clone/untracked-dirt.txt"
    rc=0; out="$(do_refresh "$clone" main 2>&1)" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        echo "$GATE --selftest: FAIL — refresh proceeded on a DIRTY tree" >&2
        return 1
    fi
    if ! str_contains "$out" "REFUSING"; then
        echo "$GATE --selftest: FAIL — refresh refused but did not say so plainly" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi
    rm -f "$clone/untracked-dirt.txt"

    echo "[$GATE] selftest: 0-behind clean, N-behind detected, safe refresh fast-forwards, dirty refresh refuses"
    return 0
}

# shellcheck source=tools/scripts/sh_str.sh
. "$SCRIPT_DIR/sh_str.sh"

case "$ACTION" in
    selftest)
        run_selftest
        exit $? ;;
    check)
        ROOT="${ROOT_ARG:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
        do_check "$ROOT" "$REF"
        rc=$?
        if (( rc == 1 )) && [[ "${ZCL_LINT_MODE:-FAIL}" == "WARN" ]]; then
            exit 0
        fi
        exit "$rc" ;;
    refresh)
        ROOT="${ROOT_ARG:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
        do_refresh "$ROOT" "$REF"
        exit $? ;;
esac
