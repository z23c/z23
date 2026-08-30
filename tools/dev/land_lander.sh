#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# land_lander.sh — one batching lander for the whole box.
#
# THE ARITHMETIC THIS EXISTS FOR
# ------------------------------
# `ZCL_STRESS_TESTS=1 make pre-push-ci` costs 15-25 minutes on this tree and
# has no cache, so a second run costs exactly what the first did. Four agents
# landing four commits used to pay four full gate runs — one each, serially,
# each blocking its agent — and then raced each other to publish, which sent
# at least one of them back to re-merge and re-gate from the top.
#
# This runs the gate ONCE for the whole batch. Four submissions, one gate run:
# gate runs per landed commit falls from 1.0 to 0.25, and no agent waits for
# any of it.
#
# WHEN THE BATCH IS RED
# ---------------------
# A batch failure must never refuse innocent work and must never land guilty
# work, so a red batch is bisected: gate the halves, recurse, and a member
# that gates red ALONE is the culprit and is refused with the gate's own
# output. Everything that gates green in a smaller batch lands. Worst case is
# one bad submission out of N costing about 2*log2(N)+1 gate runs instead of
# N — still cheaper than the serial world, and the innocent submissions land
# without their authors doing anything.
#
# WHAT IT WILL NOT DO
# -------------------
# It does not publish. tools/lint/check_no_unattended_publish.sh forbids a
# script from writing to the shared remote and it is right to: a background
# loop that can move the branch every checkout fast-forwards from moves it for
# everyone, with nobody reviewing what went out. This lander stops one step
# short — it leaves a gated, ready-to-publish integration branch (default
# `land/ready`) and names it in every receipt. A person publishes it in
# seconds. The 15-25 minutes an agent used to lose was the gating and the
# racing; both are gone regardless.
#
# WHAT IT RECORDS IS WHAT IT DID
# ------------------------------
# Every gate run and every verdict is a frame in a chainlog. A LANDED verdict
# is refused by the queue itself unless it names a gate run that really
# happened, really passed, really covered that submission, and really ran with
# ZCL_STRESS_TESTS=1. There is no path from "the gate did not run" to "the
# gate passed" — an aborted, crashed or timed-out batch produces REFUSED or
# TIMEOUT, never a landing.
#
# It works in its OWN git worktree and takes that worktree's checkout lock, so
# it never blocks a developer's build and a developer's build never corrupts
# a batch.
#
# Usage:
#   land_lander.sh                # loop forever (the systemd shape)
#   land_lander.sh --once         # drain what is queued now, then exit
#   land_lander.sh --status       # what the lander thinks is going on
#
# Environment:
#   ZCL_LAND_STATE_DIR   state root (default ~/.local/state/zclassic23-land)
#   ZCL_LAND_WORKTREE    the lander's own worktree (default <state>/worktree)
#   ZCL_LAND_BASE        base ref to integrate onto (default main)
#   ZCL_LAND_READY_REF   branch left ready to publish (default land/ready)
#   ZCL_LAND_BATCH_MAX   most submissions in one batch (default 16)
#   ZCL_LAND_GATE_TIMEOUT_S  per gate run (default 2700 = 45 min)
#   ZCL_LAND_MAX_ATTEMPTS    gate-timeout retries per batch (default 2)
#   ZCL_LAND_INTERVAL_S  idle poll interval (default 30)
#   ZCL_LAND_GATE_CMD    override the gate. A run under an override is
#                        recorded with stress=0, and the queue then REFUSES to
#                        land anything from it. An override can only ever
#                        produce refusals — it is for testing the lander, and
#                        it cannot be used to launder work past the gate.
#
# Exit: 0 done, 1 the lander itself failed, 2 usage/environment.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=tools/scripts/sh_str.sh
source "$ROOT/tools/scripts/sh_str.sh"

LAND_STATE_DIR="${ZCL_LAND_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-land}"
LAND_QUEUE="${ZCL_LAND_QUEUE:-$LAND_STATE_DIR/queue.chainlog}"
LAND_TIMING="${ZCL_LAND_TIMING:-$LAND_STATE_DIR/timing.journal}"
LAND_BIN="${ZCL_LAND_BIN:-$ROOT/build/bin/z23-land}"
LAND_WORKTREE="${ZCL_LAND_WORKTREE:-$LAND_STATE_DIR/worktree}"
LAND_BASE="${ZCL_LAND_BASE:-main}"
LAND_READY_REF="${ZCL_LAND_READY_REF:-land/ready}"
LAND_BATCH_MAX="${ZCL_LAND_BATCH_MAX:-16}"
LAND_GATE_TIMEOUT_S="${ZCL_LAND_GATE_TIMEOUT_S:-2700}"
LAND_MAX_ATTEMPTS="${ZCL_LAND_MAX_ATTEMPTS:-2}"
LAND_INTERVAL_S="${ZCL_LAND_INTERVAL_S:-30}"
LAND_LOG_DIR="$LAND_STATE_DIR/logs"
LAND_LOCK="$LAND_STATE_DIR/lander.lock"

# The one token `make pre-push-ci` prints when the focused gate completed with
# a skip-free receipt. Exit 0 alone is not enough evidence: gating on the
# named PASS line is this repository's standing rule, because a gate that
# returned 0 without running is the failure mode that matters.
GATE_PASS_TOKEN="PASS: pre-push focused gate complete"

# The real gate. ZCL_STRESS_TESTS=1 is not decoration: without it four groups
# self-skip and `make pre-push-ci` itself refuses the receipt with
# reason=self_skips. A run that skipped its groups is not a pass.
DEFAULT_GATE_CMD="env ZCL_STRESS_TESTS=1 make pre-push-ci"
LAND_GATE_CMD="${ZCL_LAND_GATE_CMD:-$DEFAULT_GATE_CMD}"
if [ "$LAND_GATE_CMD" = "$DEFAULT_GATE_CMD" ]; then
    GATE_STRESS=1
else
    GATE_STRESS=0
fi

say() { printf 'lander: %s\n' "$*"; }
die() { printf 'lander: %s\n' "$*" >&2; exit 2; }
now() { date -u '+%s'; }

# ── preflight ─────────────────────────────────────────────────────────────

preflight() {
    [ -x "$LAND_BIN" ] || die "z23-land is not built. Run: make z23-land"
    mkdir -p "$LAND_STATE_DIR" "$LAND_LOG_DIR" || die "cannot create $LAND_STATE_DIR"
    command -v flock >/dev/null 2>&1 || die "flock is required"
    command -v timeout >/dev/null 2>&1 || die "timeout(1) is required"

    if [ ! -d "$LAND_WORKTREE/.git" ] && [ ! -f "$LAND_WORKTREE/.git" ]; then
        say "creating the lander worktree at $LAND_WORKTREE"
        git -C "$ROOT" worktree add --detach "$LAND_WORKTREE" "$LAND_BASE" \
            >/dev/null 2>&1 ||
            die "could not create a worktree at $LAND_WORKTREE from $LAND_BASE"
    fi
    # The lander's worktree shares the repository object store, so every
    # submitted commit is already reachable here without a fetch.
    git -C "$LAND_WORKTREE" rev-parse --git-dir >/dev/null 2>&1 ||
        die "$LAND_WORKTREE is not a git worktree"
}

base_sha() {
    git -C "$LAND_WORKTREE" rev-parse --verify "$LAND_BASE^{commit}" 2>/dev/null
}

# ── receipts ──────────────────────────────────────────────────────────────

record_gate_run() {  # record_gate_run <outcome> <integration-sha> <csv-members>
    "$LAND_BIN" gate-run --queue "$LAND_QUEUE" --outcome "$1" \
        --integration "$2" --stress "$GATE_STRESS" --members "$3"
}

record_verdict() {  # record_verdict <seq> <state> <gate-run-seq> <integ> <reason>
    local seq="$1" state="$2" grseq="$3" integ="$4" reason="$5"
    local -a args=(verdict --queue "$LAND_QUEUE" --seq "$seq" --state "$state"
                   --reason "$reason")
    [ "$grseq" != "0" ] && args+=(--gate-run "$grseq")
    [ -n "$integ" ] && args+=(--integration "$integ")
    if ! "$LAND_BIN" "${args[@]}"; then
        # A verdict the queue refused is the fail-closed seam doing its job.
        # Say so loudly rather than pretending the submission settled.
        say "REFUSED TO RECORD: seq=$seq state=$state — the queue rejected it"
        return 1
    fi
    "$LAND_BIN" timing --timing "$LAND_TIMING" --mark settled --seq "$seq" \
        --at "$(now)" || true
    return 0
}

# ── merging ───────────────────────────────────────────────────────────────
# Build the integration tree for a member list. Any member that will not
# merge is refused HERE, with the truth about what happened, and dropped —
# a conflict is not something a gate run can decide.
#
# Sets: MERGED_SEQS (array), INTEGRATION_SHA.

MERGED_SEQS=()
INTEGRATION_SHA=""

build_integration() {  # build_integration <seq:head:branch>...
    local base entry seq head branch
    base="$(base_sha)" || return 1
    [ -n "$base" ] || { say "base ref $LAND_BASE does not resolve"; return 1; }

    MERGED_SEQS=()
    INTEGRATION_SHA=""

    git -C "$LAND_WORKTREE" merge --abort >/dev/null 2>&1 || true
    git -C "$LAND_WORKTREE" checkout --detach "$base" >/dev/null 2>&1 ||
        { say "cannot detach onto $base"; return 1; }
    # A stale file from a previous aborted batch would silently become part of
    # the tree the gate proves. Start from exactly the base commit.
    git -C "$LAND_WORKTREE" reset --hard "$base" >/dev/null 2>&1 ||
        { say "cannot reset the lander worktree onto $base"; return 1; }

    for entry in "$@"; do
        # seq:head:branch. head is fixed-width hex and the branch is
        # everything after the SECOND colon, so a branch name containing a
        # colon still parses.
        seq="${entry%%:*}"
        head="${entry#*:}"; head="${head%%:*}"
        branch="${entry#*:}"; branch="${branch#*:}"
        if git -C "$LAND_WORKTREE" merge --no-ff --no-edit \
               -m "land $branch ($head)" "$head" >/dev/null 2>&1; then
            MERGED_SEQS+=("$seq")
        else
            git -C "$LAND_WORKTREE" merge --abort >/dev/null 2>&1 || true
            say "seq=$seq branch=$branch does not merge onto the integration tree"
            record_verdict "$seq" refused 0 "" \
                "merge conflict against the integration tree at ${base:0:12}" || true
        fi
    done

    if [ "${#MERGED_SEQS[@]}" -eq 0 ]; then
        return 1
    fi
    INTEGRATION_SHA="$(git -C "$LAND_WORKTREE" rev-parse HEAD)" || return 1
    return 0
}

# ── the gate ──────────────────────────────────────────────────────────────
# Runs ONCE per batch, inside the lander's own worktree, under that
# worktree's checkout lock so it never fights a developer's build.
#
# Sets: GATE_OUTCOME (green|red|timeout), GATE_LOG.

GATE_OUTCOME=""
GATE_LOG=""

run_gate() {  # run_gate <label>
    local label="$1" rc out changed
    GATE_LOG="$LAND_LOG_DIR/gate_${label}_$(now).log"

    # Hand the gate the batch's own changed set explicitly. Without it the
    # gate falls back to the working tree — which is clean after a merge —
    # and a clean tree maps to zero groups. That is the exact shape that once
    # printed PASS having executed nothing.
    changed="$LAND_LOG_DIR/changed_${label}_$(now).txt"
    git -C "$LAND_WORKTREE" diff --name-only "$(base_sha)" HEAD > "$changed" ||
        { say "cannot compute the batch changed set"; GATE_OUTCOME=red; return; }
    if [ ! -s "$changed" ]; then
        # Nothing changed relative to base. Gating an empty diff would return
        # a green that proves nothing, so refuse to call it a pass.
        say "the batch changes nothing relative to $LAND_BASE"
        GATE_OUTCOME=red
        printf 'the batch changes nothing relative to %s\n' "$LAND_BASE" \
            > "$GATE_LOG"
        return
    fi

    say "gate run label=$label timeout=${LAND_GATE_TIMEOUT_S}s log=$GATE_LOG"
    # The gate command is a string so the environment can override it, so the
    # split into words is deliberate and happens exactly once, here.
    local -a gate_words=()
    read -r -a gate_words <<< "$LAND_GATE_CMD"
    # Output goes to a FILE, never through a pipe to tail: a pipe would hide
    # the exit code behind the reader's.
    (
        cd "$LAND_WORKTREE" || exit 125
        export ZCL_FAST_CHANGED_FILES_FILE="$changed"
        # The lander's OWN checkout lock, in the lander's OWN worktree. It
        # never contends with a developer's build, and a developer's build can
        # never land inside a batch the gate is proving.
        exec timeout --signal=TERM --kill-after=60 "$LAND_GATE_TIMEOUT_S" \
            tools/dev/checkout-lock.sh foreground \
            "$LAND_WORKTREE/build/.checkout.lock" -- \
            "${gate_words[@]}"
    ) > "$GATE_LOG" 2>&1
    rc=$?

    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        GATE_OUTCOME=timeout
        say "gate TIMED OUT after ${LAND_GATE_TIMEOUT_S}s"
        return
    fi
    if [ "$rc" -ne 0 ]; then
        GATE_OUTCOME=red
        say "gate RED (exit $rc)"
        return
    fi
    # Exit 0 is necessary and not sufficient. A gate that returned 0 without
    # running its groups is the failure this token exists to catch.
    if [ "$LAND_GATE_CMD" = "$DEFAULT_GATE_CMD" ]; then
        out="$(cat "$GATE_LOG")"
        if str_lacks "$out" "$GATE_PASS_TOKEN"; then
            GATE_OUTCOME=red
            say "gate exited 0 but never printed its PASS token — treating as RED"
            return
        fi
    fi
    GATE_OUTCOME=green
    say "gate GREEN"
}

# ── the failing detail a refusal has to carry ─────────────────────────────

gate_failure_reason() {
    local first
    first="$(grep -a -m1 -E 'FIRST-ERROR|^FAIL:|FAILED|focused receipt invalid|unmapped code changes' \
        "$GATE_LOG" 2>/dev/null)"
    if [ -z "$first" ]; then
        first="$(tail -n 3 "$GATE_LOG" 2>/dev/null | tr '\n' ' ')"
    fi
    # One line, bounded, no control characters: it goes into a canonical
    # record whose encoder refuses anything else.
    printf '%s' "$first" | tr -d '\000-\037\177' | cut -c1-400
}

# ── the ready branch ──────────────────────────────────────────────────────

publish_ready() {  # publish_ready <integration-sha>
    # Moves a LOCAL branch only. Nothing here writes to a shared remote —
    # see the header, and tools/lint/check_no_unattended_publish.sh.
    git -C "$LAND_WORKTREE" branch --force "$LAND_READY_REF" "$1" \
        >/dev/null 2>&1 ||
        say "could not move $LAND_READY_REF to $1"
}

# ── the recursion: gate a group, bisect it if red ─────────────────────────

process_group() {  # process_group <seq:head:branch>...
    local -a members=("$@")
    local n="${#members[@]}"
    local label csv seq grseq attempt=0
    local -a half_a=() half_b=()

    [ "$n" -gt 0 ] || return 0
    label="n${n}"

    if ! build_integration "${members[@]}"; then
        say "nothing merged for a group of $n; every member was answered"
        return 0
    fi

    # Only the members that actually merged are in the batch from here on.
    local -a merged_entries=()
    local entry mseq
    for entry in "${members[@]}"; do
        mseq="${entry%%:*}"
        for seq in "${MERGED_SEQS[@]}"; do
            if [ "$seq" = "$mseq" ]; then
                merged_entries+=("$entry")
                break
            fi
        done
    done
    n="${#merged_entries[@]}"
    [ "$n" -gt 0 ] || return 0

    csv="$(printf '%s,' "${MERGED_SEQS[@]}")"
    csv="${csv%,}"

    while : ; do
        attempt=$((attempt + 1))
        run_gate "$label"

        grseq="$(record_gate_run "$GATE_OUTCOME" "$INTEGRATION_SHA" "$csv")"
        if [ -z "$grseq" ]; then
            say "could not record the gate run; refusing to settle anything"
            return 1
        fi

        case "$GATE_OUTCOME" in
        green)
            publish_ready "$INTEGRATION_SHA"
            for entry in "${merged_entries[@]}"; do
                seq="${entry%%:*}"
                record_verdict "$seq" landed "$grseq" "$INTEGRATION_SHA" \
                    "green in a batch of $n; ready on $LAND_READY_REF" || true
            done
            say "LANDED $n submission(s) on one gate run"
            return 0
            ;;
        red)
            if [ "$n" -eq 1 ]; then
                seq="${merged_entries[0]%%:*}"
                record_verdict "$seq" refused "$grseq" "" \
                    "gate red alone: $(gate_failure_reason)" || true
                say "REFUSED seq=$seq — red when gated by itself"
                return 0
            fi
            # Bisect. Neither half inherits the other's verdict: the whole
            # point is that a batch failure refuses only the culprit.
            say "batch of $n is RED — bisecting"
            local mid=$(( n / 2 )) i
            half_a=(); half_b=()
            for (( i = 0; i < mid; i++ )); do half_a+=("${merged_entries[$i]}"); done
            for (( i = mid; i < n; i++ )); do half_b+=("${merged_entries[$i]}"); done
            process_group "${half_a[@]}"
            process_group "${half_b[@]}"
            return 0
            ;;
        timeout)
            if [ "$attempt" -lt "$LAND_MAX_ATTEMPTS" ]; then
                say "gate timed out; retrying (attempt $((attempt + 1)) of $LAND_MAX_ATTEMPTS)"
                # Rebuild the tree: a killed gate may have left artefacts.
                build_integration "${merged_entries[@]}" || return 0
                continue
            fi
            # Capped, and said out loud. A batch that timed out is REFUSED
            # with TIMEOUT — never retried forever, and never landed.
            for entry in "${merged_entries[@]}"; do
                seq="${entry%%:*}"
                record_verdict "$seq" timeout "$grseq" "" \
                    "gate exceeded ${LAND_GATE_TIMEOUT_S}s on $LAND_MAX_ATTEMPTS attempt(s)" || true
            done
            say "TIMEOUT on $n submission(s) after $LAND_MAX_ATTEMPTS attempt(s)"
            return 0
            ;;
        esac
    done
}

# ── one drain cycle ───────────────────────────────────────────────────────

drain_once() {
    local pending count
    pending="$("$LAND_BIN" pending --queue "$LAND_QUEUE")" || {
        say "cannot read the queue"
        return 1
    }
    if [ -z "$pending" ]; then
        return 0
    fi

    local -a batch=()
    local seq branch head rest
    while IFS=$'\t' read -r seq branch head rest; do
        [ -n "$seq" ] || continue
        [ "${#batch[@]}" -lt "$LAND_BATCH_MAX" ] || break
        # seq:head:branch — head is fixed-width hex and branch is last, so a
        # branch name containing a colon still parses.
        batch+=("$seq:$head:$branch")
    done <<< "$pending"

    count="${#batch[@]}"
    [ "$count" -gt 0 ] || return 0
    say "batching $count submission(s) into ONE gate run"
    process_group "${batch[@]}"
    return 0
}

# ── entry ─────────────────────────────────────────────────────────────────

MODE=loop
case "${1:-}" in
    --once)   MODE=once ;;
    --status) MODE=status ;;
    "")       MODE=loop ;;
    *) die "unknown argument: $1" ;;
esac

preflight

if [ "$MODE" = status ]; then
    say "queue=$LAND_QUEUE"
    say "worktree=$LAND_WORKTREE base=$LAND_BASE ready=$LAND_READY_REF"
    say "gate=$LAND_GATE_CMD stress=$GATE_STRESS"
    "$LAND_BIN" metrics --queue "$LAND_QUEUE" --timing "$LAND_TIMING"
    exit $?
fi

# One lander per box. Non-blocking: a second invocation says so and leaves,
# rather than queueing up behind a 25-minute gate run.
exec {lock_fd}>"$LAND_LOCK" || die "cannot open $LAND_LOCK"
if ! flock -n "$lock_fd"; then
    say "another lander already holds $LAND_LOCK — leaving it to run"
    exit 0
fi

if [ "$MODE" = once ]; then
    drain_once
    exit $?
fi

say "lander up. queue=$LAND_QUEUE worktree=$LAND_WORKTREE base=$LAND_BASE"
while : ; do
    drain_once || say "drain cycle failed; continuing"
    sleep "$LAND_INTERVAL_S"
done
