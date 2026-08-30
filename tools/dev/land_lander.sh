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
# that gates red ALONE is the candidate culprit. Everything that gates green
# in a smaller batch lands. Worst case is one bad submission out of N costing
# about 2*log2(N)+1 gate runs instead of N, and the innocent submissions land
# without their authors doing anything.
#
# AND THEN A CONTROL, WHICH THE FIRST REAL RUN PROVED IS NOT OPTIONAL.
# Measured here: a batch of three bisected correctly, gated one member alone,
# and that run went red on test_make_lint_gates_realroot — a group with
# nothing to do with that member's one-line comment, failing under the load
# of three concurrent gate runs on this box. The member was refused for a
# stranger's flake.
#
# Bisection is attribution, and attribution over a gate that is not perfectly
# deterministic turns "find the culprit" into "blame whoever was in the room".
# So before any refusal, the base is gated BY ITSELF over the same file list,
# which selects the same groups and leaves the merged change as the only
# variable:
#   base green -> the red is attributable; refuse the submission.
#   base red   -> the tree was already broken; nothing queued is at fault,
#                 and the receipt says so instead of blaming an author.
# This never weakens the landing rule — a landing still needs a green,
# stress-enabled, identified run over the exact tree.
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

# The commit a batch is built on.
#
# NOT simply $LAND_BASE. Once something has landed, THAT is the base: a
# bisect that landed one submission and then gated the next group against the
# original base would prove a tree nobody is going to publish, and worse, the
# ready branch would be force-moved to the second group's integration and the
# first landing would silently vanish from it. Measured: after demo-a landed,
# `land/ready` held demo-a; a subsequent green group built from $LAND_BASE
# would have replaced it.
#
# So the ready branch advances the base, and every gate run proves exactly
# the tree it produces. The ancestry check is what keeps that honest: if the
# operator has published and $LAND_BASE has moved past the ready branch, the
# ready branch is stale and the base wins.
base_sha() {
    local base ready
    base="$(git -C "$LAND_WORKTREE" rev-parse --verify "$LAND_BASE^{commit}" \
        2>/dev/null)" || return 1
    [ -n "$base" ] || return 1
    ready="$(git -C "$LAND_WORKTREE" rev-parse --verify \
        "$LAND_READY_REF^{commit}" 2>/dev/null)" || ready=""
    if [ -n "$ready" ] && [ "$ready" != "$base" ] &&
       git -C "$LAND_WORKTREE" merge-base --is-ancestor "$base" "$ready" \
           2>/dev/null; then
        printf '%s\n' "$ready"
        return 0
    fi
    printf '%s\n' "$base"
}

# WHICH TREE THE GATE PROVED, as a value rather than as this machine's word
# for it. tools/dev/source-identity.sh is this repository's own answer to
# "what exactly is this checkout", and it is what makes a verdict portable: a
# second machine that gates the same commits computes the same identity and
# therefore the same verdict digest, so the two receipts are comparable
# without either machine trusting the other.
#
# Prints nothing and fails when it cannot capture a clean identity. The queue
# then REFUSES to land behind it — see land_queue.h — because a pass nobody
# else can check is the receipt this whole design exists to remove.
capture_gate_id() {
    local record id clean mutation extra
    record="$(cd "$LAND_WORKTREE" && \
        ./tools/dev/source-identity.sh capture-record 2>/dev/null)" || return 1
    read -r id clean mutation extra <<< "$record"
    [ -z "${extra:-}" ] || return 1
    [ "${clean:-0}" = 1 ] || return 1
    [ -n "${mutation:-}" ] || return 1
    [ "${#id}" -eq 64 ] || return 1
    case "$id" in
        *[!0-9a-f]*) return 1 ;;
    esac
    printf '%s\n' "$id"
}

# ── receipts ──────────────────────────────────────────────────────────────

record_gate_run() {  # record_gate_run <outcome> <integration> <csv> <gate-id>
    local -a args=(gate-run --queue "$LAND_QUEUE" --outcome "$1"
                   --integration "$2" --stress "$GATE_STRESS" --members "$3")
    [ -n "${4:-}" ] && args+=(--gate-id "$4")
    "$LAND_BIN" "${args[@]}"
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
GATE_ID=""

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
    # Captured HERE, over the merged tree, before the gate runs and before
    # the build writes anything: this is the identity of exactly what is
    # about to be proved.
    GATE_ID="$(capture_gate_id)" || {
        GATE_ID=""
        say "WARNING: could not identify the gated tree; the queue will "\
"refuse to land behind this run"
    }
    return 0
}

# ── the gate ──────────────────────────────────────────────────────────────
# Runs ONCE per batch, inside the lander's own worktree, under that
# worktree's checkout lock so it never fights a developer's build.
#
# Sets: GATE_OUTCOME (green|red|timeout), GATE_LOG.

GATE_OUTCOME=""
GATE_LOG=""
GATE_CHANGED=""

run_gate() {  # run_gate <label> [changed-file-list]
    local label="$1" reuse="${2:-}" rc out changed stamp
    stamp="$(now)"
    GATE_LOG="$LAND_LOG_DIR/gate_${label}_${stamp}.log"

    # Hand the gate the batch's own changed set explicitly. Without it the
    # gate falls back to the working tree — which is clean after a merge —
    # and a clean tree maps to zero groups. That is the exact shape that once
    # printed PASS having executed nothing.
    #
    # A caller may pass a list to REUSE. That is how the control run works:
    # gating the base against the same file list selects the same groups, so
    # the only variable between the two runs is the merged change itself.
    if [ -n "$reuse" ] && [ -s "$reuse" ]; then
        changed="$reuse"
    else
        changed="$LAND_LOG_DIR/changed_${label}_${stamp}.txt"
        git -C "$LAND_WORKTREE" diff --name-only "$(base_sha)" HEAD \
            > "$changed" || {
            say "cannot compute the batch changed set"
            GATE_OUTCOME=red
            return
        }
    fi
    GATE_CHANGED="$changed"
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

# A refusal has to tell its author what to fix, so the NAMED failure is
# preferred over the summary. Measured on the first real run: the summary
# line "SOME TESTS FAILED — 1/15 groups failed" was recorded as the reason,
# which tells the author nothing at all. The named group and the failing
# assertion are what is actually actionable, so they are tried first and the
# summary is only the fallback.
gate_failure_reason() {
    local named group
    group="$(grep -a -m1 -E '^=+ [a-z0-9_]+ \(FAIL' "$GATE_LOG" 2>/dev/null |
        sed -E 's/^=+ //; s/ \(FAIL.*//')"
    named="$(grep -a -m1 -E 'FAIL at [^ ]+:[0-9]+|focused receipt invalid|unmapped code changes|^FAIL:' \
        "$GATE_LOG" 2>/dev/null)"
    if [ -z "$named" ]; then
        named="$(grep -a -m1 -E 'FIRST-ERROR|FAILED' "$GATE_LOG" 2>/dev/null)"
    fi
    if [ -z "$named" ]; then
        named="$(tail -n 3 "$GATE_LOG" 2>/dev/null | tr '\n' ' ')"
    fi
    [ -n "$group" ] && named="group=$group $named"
    # One line, bounded, no control characters: it goes into a canonical
    # record whose encoder refuses anything else.
    printf '%s' "$named" | tr -d '\000-\037\177' | cut -c1-400
}

# ── the control ───────────────────────────────────────────────────────────
#
# WHY THIS EXISTS, measured on the first real run of this lander. A batch of
# three went red and bisected correctly. It then gated land/demo-b alone,
# that run went red on test_make_lint_gates_realroot — a group with nothing
# to do with demo-b's one-line comment, failing under the load of three
# concurrent gate runs — and demo-b was refused for a stranger's flake.
#
# That is the failure mode a bisecting lander is uniquely exposed to. It
# attributes a red run to whatever happened to be inside it, and a gate that
# is not perfectly deterministic turns "find the culprit" into "blame the
# nearest submission". Refusing an agent's work for a flake is exactly the
# outcome the batching was supposed to prevent.
#
# So a refusal now needs a CONTROL: the base gated by ITSELF, with nothing
# merged into it. Once per drain cycle, cached, because the base does not
# change underneath a cycle.
#
#   base GREEN -> the red is attributable to what was merged. Proceed.
#   base RED   -> the tree was already broken. NOTHING in this batch is at
#                 fault, and refusing any of it would be a lie. The cycle
#                 stops and says so.
#
# This never weakens the landing rule: a landing still requires a green,
# stress-enabled, identified run over the exact tree. It only stops the
# lander from converting "everything is broken" into "your change is bad".
CONTROL_VERDICT=""   # "", "green" or "red" — cached for the drain cycle
CONTROL_REASON=""

control_base_is_green() {  # control_base_is_green <changed-file-list>
    local base changed="${1:-}"
    if [ -n "$CONTROL_VERDICT" ]; then
        [ "$CONTROL_VERDICT" = green ]
        return $?
    fi
    if [ -z "$changed" ] || [ ! -s "$changed" ]; then
        # With no file list there is no matched control: the two runs would
        # select different groups and the comparison would mean nothing.
        # Say so rather than inventing a verdict.
        CONTROL_VERDICT=red
        CONTROL_REASON="no changed-file list to run a matched control against"
        return 1
    fi
    base="$(base_sha)" || { CONTROL_VERDICT=red; return 1; }
    say "control: gating the base ${base:0:12} over the SAME file list, so "\
"the only difference between the two runs is the merged change"

    git -C "$LAND_WORKTREE" merge --abort >/dev/null 2>&1 || true
    git -C "$LAND_WORKTREE" checkout --detach "$base" >/dev/null 2>&1 || {
        CONTROL_VERDICT=red
        CONTROL_REASON="could not check out the base to run the control"
        return 1
    }
    git -C "$LAND_WORKTREE" reset --hard "$base" >/dev/null 2>&1 || true

    run_gate control "$changed"
    if [ "$GATE_OUTCOME" = green ]; then
        CONTROL_VERDICT=green
        say "control: the base is GREEN — a red batch is attributable"
        return 0
    fi
    CONTROL_VERDICT=red
    CONTROL_REASON="$(gate_failure_reason)"
    say "control: the base itself is RED — nothing queued is at fault"
    return 1
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

        grseq="$(record_gate_run "$GATE_OUTCOME" "$INTEGRATION_SHA" "$csv" \
            "$GATE_ID")"
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
                local why member_changed
                why="$(gate_failure_reason)"
                member_changed="$GATE_CHANGED"
                # THE ATTRIBUTION CHECK. Red alone is necessary and not
                # sufficient: if the base is red too, this submission is not
                # what broke anything, and saying it was would be a lie the
                # author cannot argue with.
                if ! control_base_is_green "$member_changed"; then
                    record_verdict "$seq" refused "$grseq" "" \
                        "not this change: the base is itself red — $CONTROL_REASON" ||
                        true
                    say "NOT ATTRIBUTABLE seq=$seq — the base is red; the "\
"queue is blocked until someone fixes it"
                    return 0
                fi
                record_verdict "$seq" refused "$grseq" "" \
                    "gate red alone (base green): $why" || true
                say "REFUSED seq=$seq — red when gated by itself, base green"
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
    # The control is cached for a cycle, not for the process: a base that was
    # red an hour ago may have been fixed, and a lander that remembered the
    # old answer would keep refusing work on a tree that is now sound.
    CONTROL_VERDICT=""
    CONTROL_REASON=""
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
