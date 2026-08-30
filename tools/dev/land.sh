#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# land.sh — submit a branch for landing, and read the receipt. This is the
# whole developer-facing surface of the landing queue.
#
# WHAT IT REPLACES, MEASURED ON THIS TREE
# ---------------------------------------
#   ZCL_STRESS_TESTS=1 make pre-push-ci   15-25 minutes, no cache
#   make lint (bare)                       7-10 minutes, 177 gates
#   ...then a race with four other machines that frequently sends the agent
#   back to re-merge and re-gate from the top.
#
# Every agent paid that serially, per push. The owner's description — "always
# stuck for 20 minutes trying to push" — is the arithmetic, not an
# exaggeration. The cost is the gating and the racing, not the publish.
#
#   ./tools/dev/land.sh submit --branch lane/foo --note "why"
#
# returns in milliseconds. It appends one frame to a chainlog and stops. The
# lander (tools/dev/land_lander.sh) batches everything queued and runs the
# gate ONCE for the batch, so N submissions cost one gate run instead of N.
#
# WHAT IT DOES NOT DO
# -------------------
# It does not publish, and neither does the lander.
# tools/lint/check_no_unattended_publish.sh forbids that, and it is right: a
# background loop that can move the branch every checkout fast-forwards from
# moves it for everyone, with nobody reviewing what went out. The lander
# produces a gated, ready integration branch; a person publishes it with one
# command, in seconds. The 20 minutes an agent loses is gone either way.
#
# Usage:
#   land.sh submit --branch NAME [--note TEXT] [--head SHA]
#   land.sh status [--branch NAME]
#   land.sh metrics
#   land.sh verify
#   land.sh queue-path
#
# Exit: 0 done, 1 refused with a reason, 2 usage or environment.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=tools/scripts/sh_str.sh
source "$ROOT/tools/scripts/sh_str.sh"

# The queue lives in the operator's state directory, never in the checkout: a
# queue committed to the repository would be shared history that every agent
# rewrites, which is exactly the shape the unattended-publish incident took.
LAND_STATE_DIR="${ZCL_LAND_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-land}"
LAND_QUEUE="${ZCL_LAND_QUEUE:-$LAND_STATE_DIR/queue.chainlog}"
LAND_TIMING="${ZCL_LAND_TIMING:-$LAND_STATE_DIR/timing.journal}"
LAND_BIN="${ZCL_LAND_BIN:-$ROOT/build/bin/z23-land}"

die() {
    printf 'land: %s\n' "$*" >&2
    exit 2
}

require_bin() {
    if [ ! -x "$LAND_BIN" ]; then
        die "z23-land is not built. Run: make z23-land"
    fi
}

usage() {
    sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

CMD="${1:-}"
[ -n "$CMD" ] || usage
shift || true

BRANCH=""
NOTE=""
HEAD_SHA=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --branch) BRANCH="${2:-}"; shift 2 || die "--branch needs a value" ;;
        --note)   NOTE="${2:-}";   shift 2 || die "--note needs a value" ;;
        --head)   HEAD_SHA="${2:-}"; shift 2 || die "--head needs a value" ;;
        *) die "unknown option: $1" ;;
    esac
done

mkdir -p "$LAND_STATE_DIR" || die "cannot create $LAND_STATE_DIR"

case "$CMD" in
queue-path)
    printf '%s\n' "$LAND_QUEUE"
    exit 0
    ;;

submit)
    require_bin
    [ -n "$BRANCH" ] || die "submit needs --branch"

    # Resolve the branch to a commit HERE, in the submitter's own checkout,
    # and record the sha. The lander later fetches exactly that object. If
    # the submitter moves the branch afterwards, the receipt still names what
    # was actually submitted — a queue that recorded only a branch NAME would
    # gate one tree and report about another.
    if [ -z "$HEAD_SHA" ]; then
        HEAD_SHA="$(git -C "$ROOT" rev-parse --verify "$BRANCH^{commit}" 2>/dev/null)" ||
            die "no such branch in this checkout: $BRANCH"
    fi
    case "$HEAD_SHA" in
        [0-9a-f]*) ;;
        *) die "head is not a lowercase hex sha: $HEAD_SHA" ;;
    esac
    [ "${#HEAD_SHA}" -eq 40 ] || die "head must be a full 40-hex sha: $HEAD_SHA"

    submitter="${ZCL_LAND_SUBMITTER:-${USER:-unknown}@$(uname -n)}"

    seq="$("$LAND_BIN" submit --queue "$LAND_QUEUE" --branch "$BRANCH" \
        --head "$HEAD_SHA" --submitter "$submitter" --note "$NOTE")"
    rc=$?
    if [ "$rc" -ne 0 ] || [ -z "$seq" ]; then
        exit "${rc:-1}"
    fi
    # Wall-clock telemetry, deliberately outside the chained receipts. If this
    # line is lost the receipts are untouched; nothing decides anything from it.
    "$LAND_BIN" timing --timing "$LAND_TIMING" --mark queued --seq "$seq" \
        --at "$(date -u '+%s')" || true
    printf 'queued seq=%s branch=%s head=%s\n' "$seq" "$BRANCH" "$HEAD_SHA"
    printf 'the lander will gate it in a batch; nothing here waits.\n'
    printf 'receipt: ./tools/dev/land.sh status --branch %s\n' "$BRANCH"
    exit 0
    ;;

status)
    require_bin
    if [ -n "$BRANCH" ]; then
        "$LAND_BIN" status --queue "$LAND_QUEUE" --branch "$BRANCH"
    else
        "$LAND_BIN" status --queue "$LAND_QUEUE"
    fi
    exit $?
    ;;

metrics)
    require_bin
    "$LAND_BIN" metrics --queue "$LAND_QUEUE" --timing "$LAND_TIMING"
    exit $?
    ;;

verify)
    require_bin
    "$LAND_BIN" verify --queue "$LAND_QUEUE"
    exit $?
    ;;

*)
    usage
    ;;
esac
