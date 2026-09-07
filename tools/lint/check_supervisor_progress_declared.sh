#!/usr/bin/env bash
# Gate — supervisor PROGRESS-POLICY declaration (ratchet, shrink-only counts).
#
# What it enforces
# ----------------
# A supervised child publishes two different things:
#
#   supervisor_tick()     — "I ran."           (activity)
#   supervisor_progress() — "I got work done." (results)
#
# Only NO_PROGRESS detection reads the second one, and it is gated on
# `progress_max_quiet_us > 0`. That field zero-initializes, so "nobody
# decided" and "deliberately off" were the same value. Measured across the
# tree when this gate was written: ~40 call sites stored a literal 0 and
# three armed anything.
#
# The measurable consequence, on the canonical node 2026-07-28:
#
#   chain.op_return_backfill  ticks_run 13083  holes 13083  blocks_folded 0
#                             stall_reason "none"  stall_fires 0
#
# Thirteen thousand runs, zero results, self-reported healthy, feeding an
# index that held 0 rows. Nothing in the tree could have noticed, because
# nothing was looking at the only signal that would have said so.
#
# So every registered child must make the choice EXPLICIT — one of:
#
#   (a) ARMED  — supervisor_set_progress_max_quiet(id, <non-zero>), or a
#                direct non-zero store to <contract>.progress_max_quiet_us.
#                A frozen marker raises SUPERVISOR_STALL_NO_PROGRESS.
#   (b) EXEMPT — supervisor_set_progress_exempt(id, "why"). Detection off on
#                purpose, with a reason an operator reads in dumpstate. The
#                primitive refuses a blank reason, so this cannot be
#                satisfied with an empty string.
#
# Neither = UNDECLARED: tolerated only where this baseline already records
# it, and the recorded COUNT may only shrink.
#
# What this gate deliberately does NOT do
# ---------------------------------------
# It does not require ARMED. A pure sampler that publishes a gauge and
# produces no work units has no meaningful progress signal, and forcing a
# fake one on it would be worse than an honest exemption — the same reasoning
# as blocker_operator_decisions.def, where "a person must choose" is a
# CORRECT outcome rather than a gap to paper over. What is banned is having
# no answer at all.
#
# It also does not mass-arm the existing population. Arming ~40 children at
# once, on a node whose alarms an operator relies on, is a different and
# far riskier change than making the choice visible. This gate makes the debt
# countable and one-directional; the arming is per-service work, each with
# its own idle-vs-blocked distinction to get right (see
# engine/services/src/op_return_backfill_service.c for the worked example).
#
# Unit of measurement
# -------------------
# Per FILE: `liveness_contract_init(&VAR, "name")` counts a child; an ARMED
# or EXEMPT declaration counts a policy. A file's debt is
# max(0, children - policies). File granularity rather than per-child
# because a file with two contracts cannot be attributed in a shell scan
# without guessing which declaration belongs to which contract — and a gate
# that guesses is a gate that lies. Over-attribution is impossible in the
# safe direction: a file that declares a policy per child has debt 0.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# --selftest plants a fresh undeclared child in a sandbox copy and asserts
# the gate fails on it, so a gate that has quietly stopped detecting anything
# cannot report PASS.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-supervisor-progress-declared "$@"
