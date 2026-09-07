#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_denied_leaves.sh — no command leaf named in
# engine/composition/hotswap_denied_leaves.def may appear in ANY hot-swap manifest.
#
# ── WHY THIS GATE IS NOT check-hotswap-eligible-scope ──────────────────────
# That gate is PATH-based: it refuses a manifest row whose translation unit
# sits under core/, lib/consensus/, core/modules/validation/, engine/modules/storage/, core/modules/net/,
# core/modules/coins/ or engine/jobs/. It structurally cannot express the owner rule this
# gate enforces, because the TU that owns core.chain.block.get and
# core.chain.transaction.get is engine/controllers/src/chain_native_handlers.c —
# an app-layer controller that is legitimately eligible and ALREADY admitted
# (probe core.consensus.utxo.audit). What must be denied is two LEAF NAMES
# inside an otherwise-eligible file.
#
# Nor is "READY + read-only" the right test: both leaves are
# ZCL_COMMAND_READY_READ and pass every existing eligibility check cleanly.
# They RENDER BLOCK AND TRANSACTION BYTES, so a swapped generation misreports
# the chain to every RPC reader while validation and the node's own consensus
# state stay untouched and self-consistent. The reason for each denial lives
# in the .def next to the name, never in this script.
#
# ── FAIL-CLOSED CONTRACT ───────────────────────────────────────────────────
# Every "I could not look" path is exit 2, never exit 0:
#   * denylist missing / unreadable            → exit 2
#   * denylist parses to zero entries          → exit 2 (gate_require_scanned)
#   * a denied leaf is not declared in the engine/composition/commands catalog → exit 1
#     (a typo'd row denies NOTHING; that is a hollow denial, so it is a
#     violation, not a pass)
#   * an entry carries no reason               → exit 1
#   * zero manifests found to scan             → exit 2
#   * zero translation units parsed from them  → exit 2
# A denied leaf found in a manifest is exit 1.
#
# The scan set is DERIVED, not enumerated: every config/hotswap*.def plus
# engine/composition/hotfork_capsules.def, so a hot-swap manifest added after this gate
# was written is covered on the day it lands rather than on the day somebody
# remembers to widen a list here.
#
# ── THE MANIFEST THAT IS WRITTEN IN C ──────────────────────────────────────
# Scanning config/ alone would have been a rail around an open door. The
# Tier-1 generation path stages whatever a TU's ZCL_HOTSWAP_EXPORT_LEAVES
# table exports, and hotswap_leaf_stage_thunk() in
# engine/modules/hotswap/src/hotswap_loader.c applies NO per-leaf allowlist — it accepts
# every row. When this gate was written, engine/controllers/src/
# chain_native_handlers.c staged core.chain.block.get and
# core.chain.transaction.get in exactly that table, so a recompiled
# generation re-pointed both of them although neither leaf was named in any
# .def file. (The Tier-2 module path was never exposed: hotswap_module_admit()
# checks each leaf against config/hotswap_swappable.def.) So the
# `#ifdef ZCL_HOTSWAP_GEN` / `#ifdef ZCL_HOTSWAP_MODULE_GEN` blocks of every
# TU either manifest can recompile are scanned as manifests too. Resident code
# outside those blocks is NOT scanned — a controller may name its own leaf.
#
# Overrides (test isolation only; unset in production):
#   ZCL_HOTSWAP_DENYLIST        path to the denylist .def
#   ZCL_HOTSWAP_DENY_SCAN_DIR   directory whose hot-swap manifests are scanned
#   ZCL_HOTSWAP_DENY_CATALOG    engine/composition/commands catalog directory
#   ZCL_HOTSWAP_DENY_TU_ROOT    base dir manifest TU paths resolve against
#
# --selftest is 9 cases: an unmodified sandbox copy passes (so a later "it
# tripped" means something), a denied leaf trips as an eligibility PROBE, as
# one entry of a space-separated swappable LEAF LIST, as a resident PROBE
# CASE, and inside a C ZCL_HOTSWAP_GEN leaf table; the same leaf named only in
# a COMMENT or only in RESIDENT code does not trip; a missing denylist and an
# empty denylist are both exit 2; and the real tree is exit 0. A gate that has
# never been shown to fire is not evidence of anything.


# Ported to the C23 lint runtime (z23-lint); this shim keeps the gate's own
# name in the lint driver's gate list.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hotswap-denied-leaves "$@"
