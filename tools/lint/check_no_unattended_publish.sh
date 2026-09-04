#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_unattended_publish — HARD gate, closed allowlist.
#
# THE RULE: no script in this repository may write to the shared remote.
# Publishing is a deliberate act a person performs, never a side effect of a
# background loop.
#
# WHAT MOTIVATED IT, measured 2026-08-26: tools/scripts/fleet_sync.sh ran on
# cron every ten minutes on four machines and pushed a "<box> sync heartbeat"
# commit to origin/main every cycle. Each commit carried that box's onion
# address, its P2P port, the source hash of the binary it was running, its
# peer count, whether it was up, and its last error. Three consequences, all
# bad: the public history filled with machine chatter, live operator state
# shipped to every reader of the repository, and a project anyone is supposed
# to be able to join looked like it had four designated boxes. It also meant
# an unattended timer could move `main` — the branch every other checkout
# fast-forwards from — with nobody reviewing what it pushed.
#
# The script no longer has such a path. This gate is what keeps it that way,
# and it exists because that script's own header asks for it by name.
#
# WHAT IS ALLOWED. The allowlist below is CLOSED and every entry carries a
# mandatory reason. A file not named there may not publish, and an unknown
# file is refused rather than assumed benign (fail closed). Three shapes are
# legitimate:
#   * the deliberate operator-run deploy path,
#   * a hook that only PRINTS advice mentioning the command,
#   * a lint fixture whose whole purpose is to contain the forbidden string.
# A sandbox that commits inside its own throwaway repo is not a publish and
# is not matched: only pushes and the low-level commit-tree plumbing are.
#
# WHY THESE TWO COMMANDS. `git push` is the obvious one. `git commit-tree` is
# the subtle one: it builds a commit object without touching the index or the
# working tree, so `git commit-tree ... | git push origin <sha>:main` moves a
# branch from a detached HEAD while leaving the checkout looking untouched.
# That is exactly the shape the heartbeat used, and a reviewer scanning for
# "git commit" would never have seen it.
#
# NATIVE LEAVES. A shell script spells `git push` as literal text; a native
# command under tools/command/*.c or tools/dev/*.c never does — it reaches
# git only through an argv array handed to util/spawn.h's zcl_spawn*(), so
# the shell-oriented regex above cannot see it. Those two directories are
# scanned separately for the shape that DOES show up in the source: a
# "push" subcommand literal and an "origin" remote literal in the same file
# that also calls a spawn function. tools/command/native_dev_land.c (the
# landing service, dev.land) is the one file that legitimately matches —
# see its ALLOW_PATHS row — and it is scanned like everything else, not
# exempted from the search.
#
# PIPEFAIL. Status-carrying substring tests go through str_contains from
# tools/scripts/sh_str.sh. `printf | grep -q` under `set -o pipefail` reports
# a MATCH as 141, which in a lint gate reads a FOUND VIOLATION as CLEAN — the
# precise failure that would make this gate hollow while looking green.
#
# Usage:
#   ./tools/lint/check_no_unattended_publish.sh            # FAIL mode
#   ./tools/lint/check_no_unattended_publish.sh --selftest # planted proof
#
# Exit: 0 clean, 1 violation, 2 the gate could not scan (loud, never quiet).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
# shellcheck source=tools/scripts/sh_str.sh
source "$ROOT/tools/scripts/sh_str.sh"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

GATE="check-no-unattended-publish"

# Closed allowlist: path<TAB>reason. Adding a row is a deliberate decision to
# let a file publish, and the reason is what a reviewer reads.
ALLOW_PATHS=(
  "tools/ship.sh|the operator-run deploy path; a person invokes it and it verifies the running daemon's source id"
  "tools/githooks/pre-push|prints advice text naming the override command; performs no push of its own"
  "tools/githooks/pre-commit|prints advice text naming the override command; performs no commit of its own"
  "tools/scripts/hooks_status.sh|read-only \`make hooks-status\` reporter; prints the same override advice text as tools/githooks/pre-push, performs no push of its own"
  "tools/lint/check_stable_publish_containment.sh|lint fixture: the forbidden string is the input it tests"
  "tools/scripts/check_stable_publish_containment.sh|lint fixture: the forbidden string is the input it tests"
  "tools/lint/check_no_unattended_publish.sh|this gate; a gate exempt from itself is a place to hide, so it is listed rather than skipped"
  "tools/command/native_dev_land.c|the landing service pushes only a tip whose exact proof receipt was admitted; see docs/agent/TRAIN_PROTOCOL.md"
)

# ── --selftest: a gate nobody has seen FAIL is not a gate ──────────────────
# Plants a violation in a mktemp sandbox, scans ONLY that sandbox (via
# ZCL_UNATTENDED_PUBLISH_SCAN_FILES, so the real index is never touched) and
# requires exit 1; then a clean file and requires exit 0. Assertion 2 is the
# one that catches the pipefail inversion this repository has been bitten by:
# a gate reporting a FOUND violation as CLEAN would still pass assertion 1.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0

    st_run() {  # st_run <expect-rc> <label> <file>
        local want="$1" label="$2" f="$3" rc
        ZCL_UNATTENDED_PUBLISH_SCAN_FILES="$f" \
            "$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")" >/dev/null 2>&1
        rc=$?
        if [ "$rc" != "$want" ]; then
            echo "[$GATE] SELFTEST FAIL: $label expected rc=$want, got rc=$rc"
            fails=1
        else
            echo "[$GATE]   selftest ok: $label (rc=$rc)"
        fi
    }

    # 1. A clean script passes. Without this, a gate that failed on
    #    everything would satisfy the rest and prove nothing.
    printf '#!/bin/sh\nprintf "%%s\\n" up > "$STATE_DIR/box.sync"\n' > "$tmp/clean.sh"
    st_run 0 "a script that records its state locally" "$tmp/clean.sh"

    # 2. The heartbeat shape that motivated this gate.
    printf '#!/bin/sh\ngit push origin main --quiet\n' > "$tmp/push.sh"
    st_run 1 "a script that pushes to the shared remote" "$tmp/push.sh"

    # 3. Git accepts global options before the subcommand. -C and -c are
    # common in scripts and must not turn a publish into an invisible one.
    printf '#!/bin/sh\ngit -C "$repo" push origin main\n' > "$tmp/push_cwd.sh"
    st_run 1 "git -C cannot hide a push" "$tmp/push_cwd.sh"
    printf '#!/bin/sh\ngit -c core.hooksPath=/dev/null push origin main\n' \
        > "$tmp/push_config.sh"
    st_run 1 "git -c cannot hide a push" "$tmp/push_config.sh"
    printf '#!/bin/sh\ngit --git-dir="$repo/.git" commit-tree "$t"\n' \
        > "$tmp/tree_gitdir.sh"
    st_run 1 "a long global option cannot hide commit-tree" \
        "$tmp/tree_gitdir.sh"

    # 4. The plumbing shape a reviewer scanning for "git commit" misses:
    #    commit-tree builds a commit object without touching the index, so
    #    the checkout still looks untouched afterwards.
    printf '#!/bin/sh\nc=$(git commit-tree "$t" -p "$b" -m heartbeat)\n' > "$tmp/tree.sh"
    st_run 1 "a script that builds a commit object out of band" "$tmp/tree.sh"

    # 5. A real grep error is fatal, not silently translated into no-match.
    printf '#!/bin/sh\necho clean\n' > "$tmp/grep_error.sh"
    ZCL_UNATTENDED_PUBLISH_TEST_REGEX='[' \
        st_run 2 "a scan error fails loud" "$tmp/grep_error.sh"

    # 6. A comment naming the command is documentation, not a publish. If
    #    this failed, authors would delete the explanations that keep the
    #    rule legible in order to get past the gate.
    printf '#!/bin/sh\n# there is no git push path here any more\necho ok\n' > "$tmp/comment.sh"
    st_run 0 "a comment that names the forbidden command" "$tmp/comment.sh"

    # 7. A native leaf under tools/command/ or tools/dev/ spells no shell
    #    text at all — it hands an argv array straight to zcl_spawn*(). The
    #    shell PUBLISH_RE above cannot see this shape; the native scan must.
    mkdir -p "$tmp/tools/command" "$tmp/tools/dev"
    cat > "$tmp/tools/command/native_push.c" <<'EOF'
static void go(void) {
    const char *argv[] = { "git", "push", "origin", "HEAD:main", NULL };
    zcl_spawn_capture(argv, buf, sizeof(buf), 1000);
}
EOF
    st_run 1 "a native leaf under tools/command/ that pushes via spawn" \
        "$tmp/tools/command/native_push.c"
    cat > "$tmp/tools/dev/native_push.c" <<'EOF'
static void go(void) {
    const char *argv[] = { "git", "push", "origin", "HEAD:main", NULL };
    zcl_spawn(argv);
}
EOF
    st_run 1 "a native leaf under tools/dev/ that pushes via spawn" \
        "$tmp/tools/dev/native_push.c"

    # 8. "push" and "origin" appearing together is not enough on its own —
    #    without a spawn call reaching git, the file cannot actually
    #    publish anything, and flagging it would train authors to strip the
    #    words rather than fix a real defect.
    cat > "$tmp/tools/command/native_prose.c" <<'EOF'
/* purpose: explains that "push" to "origin" is the landing service's job,
 * not this leaf's. This file never calls a spawn function. */
static void go(void) { return; }
EOF
    st_run 0 "push/origin prose with no spawn call is not a violation" \
        "$tmp/tools/command/native_prose.c"

    if [ "$fails" -ne 0 ]; then echo "[$GATE] selftest: FAIL"; exit 1; fi
    echo "[$GATE] selftest: PASS"
    exit 0
fi

allow_reason() {  # allow_reason <path> -> prints reason, rc 0 if allowed
    local p="$1" row
    for row in "${ALLOW_PATHS[@]}"; do
        if [ "${row%%|*}" = "$p" ]; then printf '%s' "${row#*|}"; return 0; fi
    done
    return 1
}

# The scan set: every tracked shell script and systemd unit. Derived from the
# index, never hand-listed, so a script added tomorrow is covered the day it
# lands.
if [ -n "${ZCL_UNATTENDED_PUBLISH_SCAN_FILES:-}" ]; then
    mapfile -t FILES <<< "$ZCL_UNATTENDED_PUBLISH_SCAN_FILES"
else
    mapfile -t FILES < <(git ls-files -- 'tools/*' 'deploy/*' '*.sh' 2>/dev/null)
fi

scanned=0
violations=0
PUBLISH_RE='(^|[^[:alnum:]_-])git([[:space:]]+(-C|-c|--git-dir|--work-tree|--namespace|--config-env)[[:space:]]+[^[:space:]]+|[[:space:]]+--(git-dir|work-tree|namespace|config-env|exec-path)=[^[:space:]]+|[[:space:]]+(-p|-P|--paginate|--no-pager|--no-replace-objects|--bare))*[[:space:]]+(push|commit-tree)([^[:alnum:]_-]|$)'
if [ -n "${ZCL_UNATTENDED_PUBLISH_SCAN_FILES:-}" ] && \
   [ -n "${ZCL_UNATTENDED_PUBLISH_TEST_REGEX:-}" ]; then
    PUBLISH_RE=$ZCL_UNATTENDED_PUBLISH_TEST_REGEX
fi
# A native command file reaches git only through an argv array handed to
# zcl_spawn*() — never through shell text — so PUBLISH_RE cannot see it.
# What IS visible in the source is the argv itself: a "push" subcommand
# literal and an "origin" remote literal, in a file that also calls a spawn
# function. Path-globbed with a leading `*/` alternative too, so a
# --selftest fixture placed under a tmp sandbox's own tools/command/ or
# tools/dev/ subtree is scanned exactly like the real tree.
NATIVE_SPAWN_RE='zcl_spawn(_capture)?\('

for f in "${FILES[@]}"; do
    [ -n "$f" ] || continue
    [ -f "$f" ] || continue
    kind=""
    case "$f" in
        *.sh|*/pre-push|*/pre-commit|*.service|*.timer) kind=shell ;;
        tools/command/*.c|*/tools/command/*.c|tools/dev/*.c|*/tools/dev/*.c)
            kind=native ;;
        *) continue ;;
    esac
    scanned=$((scanned + 1))

    if [ "$kind" = native ]; then
        # gate_grep toggles the shell's -e option internally; calling it as
        # a bare statement (rather than through a command substitution,
        # which shields the parent shell from that toggle) would make a
        # clean legitimate no-match abort this whole script instead of
        # continuing the scan. Every call below goes through "$(...)" for
        # exactly that reason, matching the idiom the shell branch already
        # uses.
        out="$(gate_grep -qE '"push"' "$f")"; has_push=$?
        [ "$has_push" -ge 2 ] && exit 2
        [ "$has_push" -ne 0 ] && continue
        out="$(gate_grep -qE '"origin"' "$f")"; has_origin=$?
        [ "$has_origin" -ge 2 ] && exit 2
        [ "$has_origin" -ne 0 ] && continue
        out="$(gate_grep -qE "$NATIVE_SPAWN_RE" "$f")"; has_spawn=$?
        [ "$has_spawn" -ge 2 ] && exit 2
        [ "$has_spawn" -ne 0 ] && continue
        hits="$(gate_grep -nE '"push"|"origin"' "$f")"
        scan_rc=$?
        [ "$scan_rc" -ge 2 ] && exit 2
    else
        # A line whose first non-blank character is `#` cannot execute, in a
        # shell script or in a systemd unit. A comment saying "there is no
        # git push here" is documentation, not a publish, and matching it
        # would push authors to delete the very explanation that keeps the
        # rule legible.
        raw_hits="$(gate_grep -nE "$PUBLISH_RE" "$f")"
        scan_rc=$?
        [ "$scan_rc" -ge 2 ] && exit 2
        [ "$scan_rc" -ne 0 ] && continue
        hits="$(printf '%s\n' "$raw_hits" | grep -vE '^[0-9]+:[[:space:]]*#')"
        filter_rc=$?
        [ "$filter_rc" -ge 2 ] && exit 2
        [ "$filter_rc" -ne 0 ] && continue
    fi

    if reason="$(allow_reason "$f")"; then
        continue
    fi
    if [ "$violations" -eq 0 ]; then
        echo "[$GATE] a script may not write to the shared remote:" >&2
    fi
    violations=$((violations + 1))
    printf '  %s\n' "$f" >&2
    printf '%s\n' "$hits" | sed 's/^/      /' >&2
done

# A gate whose scan set silently emptied reports clean while a violation
# stands. The floor is deliberately well below the real population so an
# ordinary deletion does not trip it, but a scan that found almost nothing
# does.
if [ -z "${ZCL_UNATTENDED_PUBLISH_SCAN_FILES:-}" ]; then
    gate_require_scanned "$scanned" 50 "$GATE" \
        "expected the tracked tools/ and deploy/ script set" || exit 2
fi

if [ "$violations" -gt 0 ]; then
    cat >&2 <<'MSG'

Publishing is a deliberate act a person performs, not a side effect of a
background loop. A timer that can move `main` moves it for every checkout
that fast-forwards from it, with nobody reviewing what went out.

If this file genuinely must publish, add it to ALLOW_PATHS in this gate with
a reason a reviewer can weigh. If it is recording what a machine observed,
write that to the operator's own state directory instead — see the header of
tools/scripts/fleet_sync.sh for the shape.
MSG
    exit 1
fi

echo "[$GATE] PASS ($scanned tracked script(s)/unit(s) scanned; ${#ALLOW_PATHS[@]} allowlisted, each with a reason)"
exit 0
