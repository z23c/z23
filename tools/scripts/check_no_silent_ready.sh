#!/usr/bin/env bash
# Lint gate E8 — no-silent-ready: the block-connection authority must
# advance-the-tip OR name-a-typed-blocker; it may NEVER go silently "ready"
# while the active tip is below the most-work valid-header chain (HARD).
#
# Why this exists
# ----------------
# 2026-05-26 live witness: chain_activation_controller went to
# ACTIVATION_READY with reason "behind_peers" whenever tip_h + 100 < best_h
# and the tick could not advance. That is the silent-ready hole — the reducer
# reports "ready" while +950 behind, naming no actionable reason and reaching
# no operator sink, deadlocked against a 3-peer P2P quorum a personal stack
# can't form. The Prime Directive (FRAMEWORK.md) requires the reducer to
# advance-the-tip OR name-a-typed-blocker (blocker_set / a Condition) every
# tick. Going READY is only honest when local_tip == most-work header tip.
#
# The check
# ---------
# The single block-connection authority is
#   engine/services/src/chain_activation_service.c
# It owns the transition to ACTIVATION_READY. Any file that performs an
#   activation_set_state(..., ACTIVATION_READY, ...)
# on a non-progress path MUST also route a typed blocker through the blocker
# primitive (`blocker_set(` directly, or a helper such as
# `activation_set_behind_blocker(`) so the stall is always visible in
# `z23 dumpstate blocker` and reaches the supervisor escape / operator
# sink. A file that transitions to READY but never names a typed blocker is
# the silent-ready anti-pattern.
#
# This guards the *structure* — a future edit that removes the blocker
# registration but keeps the READY transition turns the build red.
#
# Override: a deliberate READY transition that provably cannot be a
# non-progress stall (e.g. a clean caught-up path) may carry a line-level
#   // no-silent-ready-ok:<tag>
# marker (no space after the colon, non-empty tag) on the offending
# activation_set_state(... ACTIVATION_READY ...) line.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-silent-ready "$@"
