#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# build_drift_probe.sh — scheduled answer to one question:
#
#     Is the binary actually running still the binary we think is running?
#
# The expectation is stored (a systemd drop-in, and a checked-in candidate
# pin), the ground truth is queryable (`<bin> agentbuild` -> source_id_sha256),
# and until now nothing compared them except a human typing `make agent-doctor`.
# On 2026-07-28 the live binary was replaced at 11:10 and the unit restarted at
# 11:12 with no record anywhere; that deploy was reconstructed afterwards from
# file mtimes. This probe makes that reconstruction unnecessary.
#
# WHY /proc/<pid>/exe AND NOT THE PATH
# ------------------------------------
# tools/dev/agent-doctor.sh fingerprints ~/.local/bin/zclassic23-live — the
# file at the path. That is the right question for "is my tree deployed", and
# the WRONG question for "what is running": a deploy that overwrites the file
# under a live process leaves the path showing the NEW build while the node
# keeps executing the OLD one, and the two only converge at the next restart.
# That window is exactly when an operator is most likely to misdiagnose. This
# probe resolves /proc/<MainPID>/exe, which the kernel pins to the inode the
# process is actually executing even after the path is replaced or unlinked,
# and it reports path-vs-running disagreement as its own field
# (`artifact_path_matches_running`) rather than silently preferring one.
#
# THREE INDEPENDENT COMPARISONS, NEVER COLLAPSED INTO ONE BOOLEAN
# ---------------------------------------------------------------
#   expectation_match  drop-in ZCL_AGENT_EXPECT_SOURCE_ID vs running
#                      -> "does the box still run what the box was told to run"
#   pin_match          platform/deploy/release-candidates.jsonl vs running
#                      -> "does the box run the CANDIDATE under proof"
#   tree_distance      commits between the pinned commit and repo HEAD
#                      -> "how far has development moved past what is running"
#
# These fail independently and a single `match` field would hide two of them.
# On the day this was written the box read expectation_match=true,
# pin_match=true, tree_distance=82 — i.e. the running node is exactly what it
# was declared to be, and is 82 commits behind main. A one-boolean check would
# have printed "match" and said nothing useful.
#
# Read-only by construction: it never signals, restarts, or writes to any node
# datadir. `agentbuild` is an identity command that runs as a separate
# short-lived process; the same call is already made by agent-doctor.sh.
# It exits non-zero only if it could not LOCK or APPEND to its own ledger —
# a drift FINDING is a successful probe, not a probe failure, so a scheduler
# does not flap on it. Use `assert` (below) when you want drift to exit non-zero.
#
# Bounded ledger: rotates at 50 MiB keeping 2 generations, same rule as
# node_slo_probe.sh. bash + sed + flock + coreutils only.
#
# Usage:
#   build_drift_probe.sh [collect]   # probe and append one ledger line
#   build_drift_probe.sh report      # human-readable, no append
#   build_drift_probe.sh assert      # exit 1 if drift, for a gate/pager
#
# Env:
#   ZCL_DRIFT_LEDGER_DIR    ledger dir (default ~/.local/state/zclassic23-drift)
#   ZCL_DRIFT_UNIT          unit to inspect (default zclassic23)
#   ZCL_DRIFT_PIN_FILE      candidate pin record (default platform/deploy/release-candidates.jsonl)
#   ZCL_DRIFT_PIN_TAG       pin a specific rc- tag (default: last line of pin file)
#   ZCL_DRIFT_ROTATE_BYTES  rotation threshold (default 52428800)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tools/dev/dev_lib.sh
. "$REPO/tools/dev/dev_lib.sh"   # json_escape, baked_source_id

MODE="${1:-collect}"
SCHEMA="zcl.build_drift.v1"

UNIT="${ZCL_DRIFT_UNIT:-zclassic23}"
LEDGER_DIR="${ZCL_DRIFT_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-drift}"
LEDGER_FILE="$LEDGER_DIR/build-drift-ledger.jsonl"
ROTATE_BYTES="${ZCL_DRIFT_ROTATE_BYTES:-52428800}"
PIN_FILE="${ZCL_DRIFT_PIN_FILE:-$REPO/platform/deploy/release-candidates.jsonl}"
PIN_TAG="${ZCL_DRIFT_PIN_TAG:-}"

fail() { echo "build-drift-probe: FAIL $*" >&2; exit 1; }

# ---------------------------------------------------------------- primitives

# jfield <json> <key> — first string value for key. Deliberately NOT greedy:
# same trap baked_source_id documents.
#
# The trailing `|| true` is load-bearing under `set -euo pipefail`: a missing
# key makes grep exit 1, pipefail propagates that as the pipeline's status, and
# a bare `x="$(jfield ...)"` would then abort the whole probe. "Key absent" is a
# normal answer here (no pin file yet, a node that is not running), not an
# error, and a monitoring probe that dies on its own empty case is worse than
# no probe.
jfield() {
    { printf '%s\n' "$1" |
        grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" |
        head -1 |
        sed 's/.*:[[:space:]]*"//; s/"$//'; } || true
}

# rotate_ledger_if_needed: run BEFORE appending so a rotation never splits a
# run's output across two files.
rotate_ledger_if_needed() {
    [ -f "$LEDGER_FILE" ] || return 0
    local size
    size="$(stat -c %s "$LEDGER_FILE" 2>/dev/null || echo 0)"
    if [ "$size" -ge "$ROTATE_BYTES" ]; then
        [ -f "$LEDGER_FILE.2" ] && rm -f "$LEDGER_FILE.2"
        [ -f "$LEDGER_FILE.1" ] && mv "$LEDGER_FILE.1" "$LEDGER_FILE.2"
        mv "$LEDGER_FILE" "$LEDGER_FILE.1"
        echo "build-drift-probe: rotated ledger (size=$size >= $ROTATE_BYTES)" >&2
    fi
}

append_line() {
    local line="$1" rc=0
    (
        flock -x -w 30 9 || exit 9
        printf '%s\n' "$line" >&9
    ) 9>>"$LEDGER_FILE" || rc=$?
    if [ "$rc" -ne 0 ]; then
        [ "$rc" -eq 9 ] &&
            fail "could not acquire append lock on $LEDGER_FILE within 30s"
        fail "could not append to $LEDGER_FILE (rc=$rc)"
    fi
}

# ------------------------------------------------------------------ gathering

# The expectation the RUNNING process was actually started with, read from its
# own environ — not from the drop-in on disk. Editing a drop-in without a
# daemon-reload+restart leaves the file and the process disagreeing, and the
# process is the one that matters. Falls back to the unit's configured
# environment when /proc is unreadable.
running_expect_source_id() {
    local pid="$1" v=""
    if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/environ" ]; then
        v="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
             sed -n 's/^ZCL_AGENT_EXPECT_SOURCE_ID=//p' | head -1)"
    fi
    if [ -z "$v" ]; then
        v="$(systemctl --user show "$UNIT" -p Environment --value 2>/dev/null |
             tr ' ' '\n' |
             sed -n 's/^ZCL_AGENT_EXPECT_SOURCE_ID=//p' | head -1)"
    fi
    printf '%s' "$v"
}

running_expect_commit() {
    local pid="$1" v=""
    if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/environ" ]; then
        v="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
             sed -n 's/^ZCL_AGENT_EXPECT_BUILD_COMMIT=//p' | head -1)"
    fi
    printf '%s' "$v"
}

# The pinned candidate: a named rc- tag, else the last line of the pin file.
pin_line() {
    [ -f "$PIN_FILE" ] || return 0
    if [ -n "$PIN_TAG" ]; then
        grep -F "\"tag\":\"$PIN_TAG\"" "$PIN_FILE" 2>/dev/null | tail -1 || true
    else
        grep -E '^\{' "$PIN_FILE" 2>/dev/null | tail -1 || true
    fi
}

# pending_restart_tokens <pid> — configured ExecStart flags that the running
# process does NOT have.
#
# Editing a drop-in + `systemctl daemon-reload` changes what the unit WILL run
# without changing what it IS running, and systemd reports the new value with
# no hint that the live process predates it. That gap is invisible to every
# identity check in this file, because the binary can be byte-identical on both
# sides — 2026-07-29 06:27 produced exactly that state on this host: the unit
# gained -operator-lane=canonical and lost -load-snapshot-at-own-height while
# the running process kept the old argv, and `systemctl show` displayed only
# the new one.
#
# Tokens beginning with `$` are skipped: systemd shows them unexpanded in
# ExecStart but the kernel shows them expanded in /proc/<pid>/cmdline, so they
# would mismatch forever and train the reader to ignore this field.
pending_restart_tokens() {
    local pid="$1" cfg running tok out=""
    [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/cmdline" ] || return 0
    cfg="$(systemctl --user show "$UNIT" -p ExecStart --value 2>/dev/null |
           sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | head -1)"
    [ -n "$cfg" ] || return 0
    running=" $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    for tok in $cfg; do
        case "$tok" in
            \$*) continue ;;
        esac
        case "$running" in
            *" $tok "*) ;;
            *) out="$out${out:+,}$tok" ;;
        esac
    done
    printf '%s' "$out"
}

# stale_running_flags <pid> — flags the running process HAS that the configured
# ExecStart no longer does. The mirror of pending_restart_tokens, and the more
# dangerous direction: a flag REMOVED from the unit is still in effect until a
# restart, so an operator who deletes a flag and reloads can believe it is gone
# while the node is still acting on it. On 2026-07-29 that flag was
# -load-snapshot-at-own-height, the v1 seed loader — removed from the unit,
# still live in the running node. Only `-flag` tokens are compared; addnode /
# externalip values arrive through $ZCL_* expansion and are not comparable.
stale_running_flags() {
    local pid="$1" cfg running tok out=""
    [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/cmdline" ] || return 0
    cfg=" $(systemctl --user show "$UNIT" -p ExecStart --value 2>/dev/null |
            sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | head -1) "
    [ -n "${cfg// /}" ] || return 0
    running="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    for tok in $running; do
        case "$tok" in
            -*) ;;
            *) continue ;;
        esac
        # Flags whose value comes from $ZCL_* expansion are not comparable.
        case "$tok" in
            -externalip=*|-addnode=*) continue ;;
        esac
        case "$cfg" in
            *" $tok "*) ;;
            *) out="$out${out:+,}$tok" ;;
        esac
    done
    printf '%s' "$out"
}

probe() {
    local pid exe_target running_id running_sha path_bin path_sha
    local expect_id expect_commit pin pin_tag pin_id pin_commit pin_sha
    local expectation_match="false" pin_match="false" pin_artifact_match="false"
    local path_matches="false" tree_distance="-1" state="ok" detail=""

    # ZCL_DRIFT_PID is a test seam: it lets the hot-swap detection be proven
    # against a throwaway process instead of against the canonical node, which
    # must never be restarted to exercise a probe.
    pid="${ZCL_DRIFT_PID:-$(systemctl --user show "$UNIT" -p MainPID --value 2>/dev/null || echo 0)}"
    [[ "$pid" =~ ^[0-9]+$ ]] || pid=0

    expect_id="$(running_expect_source_id "$pid")"
    expect_commit="$(running_expect_commit "$pid")"

    pin="$(pin_line)"
    pin_tag="$(jfield "$pin" tag)"
    pin_id="$(jfield "$pin" source_id_sha256)"
    pin_commit="$(jfield "$pin" commit)"
    pin_sha="$(jfield "$pin" artifact_sha256)"

    running_id=""; running_sha=""; path_bin=""; path_sha=""
    if [ "$pid" != "0" ] && [ -r "/proc/$pid/exe" ]; then
        # Kernel-pinned inode: correct even if the path was replaced.
        running_id="$(baked_source_id "/proc/$pid/exe")"
        running_sha="$(sha256sum "/proc/$pid/exe" 2>/dev/null | cut -d' ' -f1 || true)"
        exe_target="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        path_bin="${exe_target% (deleted)}"
        if [ -n "$path_bin" ] && [ -r "$path_bin" ]; then
            path_sha="$(sha256sum "$path_bin" 2>/dev/null | cut -d' ' -f1 || true)"
        fi
    else
        state="node_not_running"
        detail="unit $UNIT has no MainPID or /proc entry is unreadable"
    fi

    [ -n "$running_id" ] && [ "$running_id" = "$expect_id" ] && expectation_match="true"
    [ -n "$running_id" ] && [ "$running_id" = "$pin_id" ] && pin_match="true"
    [ -n "$running_sha" ] && [ "$running_sha" = "$pin_sha" ] && pin_artifact_match="true"
    [ -n "$running_sha" ] && [ "$running_sha" = "$path_sha" ] && path_matches="true"

    if [ -n "$pin_commit" ]; then
        tree_distance="$(git -C "$REPO" rev-list --count "$pin_commit"..HEAD 2>/dev/null || echo -1)"
    fi

    if [ "$state" = "ok" ] && [ -z "$running_id" ]; then
        state="identity_unreadable"
        detail="agentbuild produced no 64-hex source_id_sha256 for /proc/$pid/exe"
    fi

    printf '{"schema":"%s","ts":"%s","unit":"%s","pid":%s,"state":"%s"' \
        "$SCHEMA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$UNIT")" \
        "${pid:-0}" "$state"
    printf ',"expected":"%s","running":"%s","match":%s' \
        "$(json_escape "$expect_id")" "$(json_escape "$running_id")" "$expectation_match"
    printf ',"artifact_sha256":"%s"' "$(json_escape "$running_sha")"
    printf ',"expected_commit":"%s"' "$(json_escape "$expect_commit")"
    printf ',"pin_tag":"%s","pin_source_id":"%s","pin_commit":"%s","pin_artifact_sha256":"%s"' \
        "$(json_escape "$pin_tag")" "$(json_escape "$pin_id")" \
        "$(json_escape "$pin_commit")" "$(json_escape "$pin_sha")"
    printf ',"pin_match":%s,"pin_artifact_match":%s' "$pin_match" "$pin_artifact_match"
    printf ',"artifact_path":"%s","artifact_path_sha256":"%s","artifact_path_matches_running":%s' \
        "$(json_escape "$path_bin")" "$(json_escape "$path_sha")" "$path_matches"
    printf ',"tree_distance_commits":%s,"repo_head":"%s"' \
        "$tree_distance" "$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    local pending stale
    pending="$(pending_restart_tokens "$pid")"
    stale="$(stale_running_flags "$pid")"
    printf ',"pending_restart":%s,"pending_restart_flags":"%s","stale_running_flags":"%s"' \
        "$([ -n "$pending$stale" ] && echo true || echo false)" \
        "$(json_escape "$pending")" "$(json_escape "$stale")"
    printf ',"error_detail":"%s"}' "$(json_escape "$detail")"
    printf '\n'
}

# --------------------------------------------------------------------- modes

case "$MODE" in
    collect)
        mkdir -p "$LEDGER_DIR"
        rotate_ledger_if_needed
        line="$(probe)"
        append_line "$line"
        printf '%s\n' "$line"
        ;;
    report)
        line="$(probe)"
        printf '%s\n' "$line"
        echo "---"
        printf 'expectation_match : %s\n' \
            "$(printf '%s' "$line" | grep -oE '"match":(true|false)' | sed 's/.*://')"
        printf 'pin_match         : %s\n' \
            "$(printf '%s' "$line" | grep -oE '"pin_match":(true|false)' | sed 's/.*://')"
        printf 'path_vs_running   : %s\n' \
            "$(printf '%s' "$line" | grep -oE '"artifact_path_matches_running":(true|false)' | sed 's/.*://')"
        printf 'running           : %s\n' "$(jfield "$line" running)"
        printf 'expected          : %s\n' "$(jfield "$line" expected)"
        printf 'pin_tag           : %s\n' "$(jfield "$line" pin_tag)"
        printf 'artifact_sha256   : %s\n' "$(jfield "$line" artifact_sha256)"
        printf 'tree_distance     : %s commit(s) behind %s\n' \
            "$(printf '%s' "$line" | grep -oE '"tree_distance_commits":-?[0-9]+' | sed 's/.*://')" \
            "$(jfield "$line" repo_head)"
        ;;
    assert)
        line="$(probe)"
        printf '%s\n' "$line"
        m="$(printf '%s' "$line" | grep -oE '"match":(true|false)' | sed 's/.*://')"
        p="$(printf '%s' "$line" | grep -oE '"pin_match":(true|false)' | sed 's/.*://')"
        if [ "$m" = "true" ] && [ "$p" = "true" ]; then
            echo "build-drift-probe: OK running binary matches both expectation and pin" >&2
            exit 0
        fi
        echo "build-drift-probe: DRIFT expectation_match=$m pin_match=$p" >&2
        exit 1
        ;;
    *)
        echo "usage: build_drift_probe.sh [collect|report|assert]" >&2
        exit 2
        ;;
esac
