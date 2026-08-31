#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Executable regression for tools/dev/checkout-lock.sh: a foreground holder
# and a watcher never run concurrently, the watcher defers instead of
# racing (never blocks), a foreground holder always blocks and eventually
# runs, and a nested call inside an already-held lock does not self-deadlock.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$SELF_DIR/checkout-lock.sh"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
MAKEFILE="$ROOT/Makefile"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-checkout-lock-selftest.XXXXXX")"
LOCK="$WORK/checkout.lock"
CHILD_PIDS=()

cleanup()
{
    local pid
    for pid in "${CHILD_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${CHILD_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail()
{
    printf 'checkout-lock-selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

[ -x "$TOOL" ] || fail 'checkout-lock.sh is not executable'

# 1. A watcher invocation with no contention runs normally and releases.
OUT="$("$TOOL" watcher "$LOCK" -- echo uncontended)"
[ "$OUT" = uncontended ] || fail 'uncontended watcher call did not run the command'

# 2. Foreground holds the lock; watcher must defer (exit 99), print the
#    documented one-line status, and never run the wrapped command.
HOLD_MARKER="$WORK/fg-holding"
HOLD_RELEASE="$WORK/fg-release"
RAN_MARKER="$WORK/watcher-ran"
"$TOOL" foreground "$LOCK" -- bash -c \
    ": > '$HOLD_MARKER'; while [ ! -e '$HOLD_RELEASE' ]; do sleep 0.01; done" &
FG_PID=$!
CHILD_PIDS+=("$FG_PID")
# Wait for the foreground holder to actually take the lock, guarded by the
# holder being alive rather than by a 5s iteration budget. A just-forked
# `flock` holder needs to be scheduled and to create a file; on a loaded box
# that can take longer than 5s while nothing at all is wrong, and the
# assertion below would then blame the lock implementation. Exhaustion is no
# longer reachable: this ends on the marker (success) or on the holder dying
# without it (a real defect). A holder that neither takes the lock nor exits
# is a hang, and is reported as one by the runner-level progress watchdog.
while [ ! -e "$HOLD_MARKER" ]; do
    kill -0 "$FG_PID" 2>/dev/null || break
    sleep 0.01
done
[ -e "$HOLD_MARKER" ] || fail 'foreground holder did not start'

set +e
WATCHER_ERR="$("$TOOL" watcher "$LOCK" -- bash -c ": > '$RAN_MARKER'" 2>&1 >/dev/null)"
WATCHER_RC=$?
set -e
[ "$WATCHER_RC" -eq 99 ] || fail "watcher must defer with exit 99 under contention, got $WATCHER_RC"
[ ! -e "$RAN_MARKER" ] || fail 'watcher ran the wrapped command instead of deferring'
case "$WATCHER_ERR" in
    *"deferred: foreground build holds the lock"*) ;;
    *) fail "watcher did not print the documented deferred status: $WATCHER_ERR" ;;
esac

# 3. A foreground caller arriving after the watcher deferred must still
#    block (not refuse) and run as soon as the holder releases — the
#    watcher yields, a human/agent-invoked make never does.
FG2_START="$WORK/fg2-start"
FG2_DONE="$WORK/fg2-done"
"$TOOL" foreground "$LOCK" -- bash -c \
    ": > '$FG2_START'; : > '$FG2_DONE'" &
FG2_PID=$!
CHILD_PIDS+=("$FG2_PID")
sleep 0.2
[ ! -e "$FG2_START" ] || fail 'second foreground caller ran while the first still held the lock'
: > "$HOLD_RELEASE"
wait "$FG_PID"
wait "$FG2_PID"
[ -e "$FG2_DONE" ] || fail 'second foreground caller never ran after the holder released'

# 4. Nested acquisition inside an already-held section must not deadlock —
#    a lock-wrapped recipe invoking another lock-wrapped script in the same
#    process family runs directly instead of re-blocking on itself.
NESTED_OUT="$("$TOOL" foreground "$LOCK" -- bash -c \
    "'$TOOL' foreground '$LOCK' -- echo nested-ok")"
[ "$NESTED_OUT" = nested-ok ] || fail 'nested acquisition inside a held lock deadlocked or misbehaved'

# 5. A failing wrapped command still releases the lock (a later caller is
#    not left waiting on a dead holder).
"$TOOL" foreground "$LOCK" -- false 2>/dev/null || true
OUT2="$("$TOOL" foreground "$LOCK" -- echo released-after-failure)"
[ "$OUT2" = released-after-failure ] || fail 'lock was not released after the wrapped command failed'

# 6. The source-wide fast gate must enter this same checkout critical section.
# `pre-push-ci` delegates to `make fast-ci`; without this wiring a concurrent
# focused runner can overlap the supposedly-exclusive host-latency pre-pass.
FAST_CI_RECIPE="$(sed -n '/^fast-ci agent-fast-ci dev-ci:/,/^agent-plan:/p' "$MAKEFILE")"
case "$FAST_CI_RECIPE" in
    *'$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)"'*) ;;
    *) fail 'fast-ci source-wide proof is outside the checkout lock' ;;
esac

# 7. Public test entry points must acquire the lock before asking a recursive
# make to construct prerequisites. A prerequisite on the public target itself
# runs before its recipe and therefore outside the critical section — exactly
# the depfile race this contract exists to prevent.
assert_build_and_run_locked()
{
    local public="$1" inner="$2" required="${3:-dev-package-verifier-ensure}"
    local header block inner_header
    header="$(awk -v target="$public" '$0 == target ":" { print; exit }' \
        "$MAKEFILE")"
    [ "$header" = "$public:" ] ||
        fail "$public has prerequisites outside the checkout lock"
    block="$(awk -v target="$public" \
        '$0 == target ":" { found=1; left=8 } \
         found && left-- > 0 { print }' "$MAKEFILE")"
    case "$block" in
        *'$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)"'*"$inner"*) ;;
        *) fail "$public does not delegate construction under the checkout lock" ;;
    esac
    inner_header="$(awk -v target="$inner" \
        'index($0, target ":") == 1 { print; exit }' "$MAKEFILE")"
    case "$inner_header" in
        "$inner:"*"$required"*) ;;
        *) fail "$inner does not own required prerequisite $required" ;;
    esac
}

assert_build_and_run_locked test-parallel test-parallel-locked
assert_build_and_run_locked test-parallel-active test-parallel-active-locked
assert_build_and_run_locked test-parallel-fast-active test-parallel-fast-active-locked
assert_build_and_run_locked t t-locked
assert_build_and_run_locked t-fast t-fast-locked
assert_build_and_run_locked t-fast-exact t-fast-exact-locked
assert_build_and_run_locked test test-locked
assert_build_and_run_locked test-full test-full-locked test_zcl
assert_build_and_run_locked secure-release-regressions \
    secure-release-regressions-locked

# A copied inner target must fail during Make parsing, before it can launch
# any prerequisite writer outside the critical section.
set +e
INNER_ERR="$(ZCL_CHECKOUT_LOCK_HELD=0 make -s -C "$ROOT" -n \
    t-fast-locked ONLY=build_fabric 2>&1 >/dev/null)"
INNER_RC=$?
set -e
[ "$INNER_RC" -ne 0 ] || fail 'direct inner target unexpectedly ran unlocked'
case "$INNER_ERR" in
    *'internal locked test goal requires the checkout lock'*) ;;
    *) fail "direct inner target did not report the lock invariant: $INNER_ERR" ;;
esac

printf 'checkout-lock-selftest: PASS uncontended=true watcher_defers=true foreground_blocks=true nested_no_deadlock=true releases_on_failure=true fast_ci_serialized=true build_and_run_serialized=true inner_bypass_refused=true\n'
