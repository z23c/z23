#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Per-checkout mutual exclusion between the dev-watch loop and a foreground
# `make`. The per-profile epoch-GC lock in build-epoch-session.sh only
# serializes writers of ONE profile's object root (dev vs test-fast vs
# test-rel ...); it does not stop the watcher's `make ff` (dev profile,
# test_parallel --only=...) from running at the same wall-clock instant as a
# human's `make test-parallel` (test-rel profile, full suite) in the SAME
# checkout. Both drive tests/harness/src/test_make_lint_gates.c and
# test_consensus_state_snapshot_install through fixed, non-PID-namespaced
# fixture paths, so two concurrent test_parallel processes racing those
# paths is a real false-failure source, not just a build-object collision.
# This adds one checkout-wide flock so the two invocations never overlap.
#
# Foreground (a human/agent-invoked make) blocks until it can acquire the
# lock — normal, bounded contention, never a refusal. The watcher acquires
# non-blocking and defers its whole cycle the instant a foreground build
# already holds it; it never makes a foreground `make` wait on it.

set -uo pipefail

fail()
{
    printf 'checkout-lock: %s\n' "$*" >&2
    exit 2
}

[ "$#" -ge 3 ] || fail 'usage: checkout-lock.sh {foreground|watcher} LOCK_FILE -- CMD...'
MODE="$1"; shift
LOCK_FILE="$1"; shift
case "${1:-}" in --) shift ;; esac
[ "$#" -ge 1 ] || fail 'usage: checkout-lock.sh {foreground|watcher} LOCK_FILE -- CMD...'
case "$MODE" in foreground|watcher) ;; *) fail "unknown mode: $MODE" ;; esac
command -v flock >/dev/null 2>&1 || fail 'flock is required for the checkout lock'

# Already inside the critical section (a lock-wrapped recipe invoked another
# lock-wrapped recipe as a sub-make/sub-script in the same process family) —
# run directly instead of re-acquiring, which would self-deadlock a blocking
# foreground wait against its own holder.
if [ "${ZCL_CHECKOUT_LOCK_HELD:-0}" = 1 ]; then
    exec "$@"
fi

mkdir -p "$(dirname -- "$LOCK_FILE")" || fail "cannot create lock directory for $LOCK_FILE"
exec {lock_fd}>"$LOCK_FILE" || fail "cannot open $LOCK_FILE"

if [ "$MODE" = watcher ]; then
    if ! flock -n "$lock_fd"; then
        echo "deferred: foreground build holds the lock" >&2
        exit 99
    fi
else
    flock -x "$lock_fd" || fail "could not acquire $LOCK_FILE"
fi

ZCL_CHECKOUT_LOCK_HELD=1 "$@"
rc=$?
flock -u "$lock_fd" 2>/dev/null || true
exit "$rc"
