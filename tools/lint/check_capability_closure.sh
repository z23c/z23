#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — every external entry point this tree's compiled
#          objects reach is classified, and every file that reaches a
#          classified capability has said so, and only what it uses.
#
# WHY THIS EXISTS. engine/composition/capability_classes.def names nine kinds of reach a
# translation unit can have (network, process spawn, dynamic load, filesystem
# read/write, wallet-key reach, randomness, clock, privilege). Two files make
# that design real:
#
#   engine/composition/capability_symbols.def   — every external symbol this tree calls,
#                                      and which class it belongs to (or
#                                      CAP_HARMLESS, meaning none).
#   engine/composition/module_capabilities.def  — cross-target source declarations.
#   engine/composition/module_capabilities_linux.def / _windows.def — exact overrides for
#                                      paths whose selected host arm differs.
#
# Neither file enforces anything by existing. This gate is the enforcement:
# it reads what the compiler already proved (every undefined symbol in every
# compiled object, via `nm`) and checks it against both tables. A file with
# no row in module_capabilities.def declares nothing, and nothing is enforced
# positively — reaching a classified symbol without a row is a build failure.
#
# WHAT THIS CHECKS, all six, all run every time (no short-circuit — one pass
# reports every violation — except item 6, which by its nature must abort the
# rest of the pass; see below):
#
#   1. CLOSURE.      Every undefined symbol the object tree carries appears
#                     in config/capability_symbols.def. An unclassified
#                     symbol is a build failure, not an assumed-harmless one.
#   2. DECLARATION.   Every object referencing a symbol classified to a real
#                     capability (anything but CAP_HARMLESS) maps to a source
#                     file whose module_capabilities.def row grants that
#                     class. Undeclared reach fails.
#   3. SYMMETRY.      A row granting a class the file's object does not
#                     actually use fails (declarations cannot rot upward as
#                     code shrinks). A row naming a source file that no
#                     longer exists fails.
#   4. HOLLOWNESS.    Fewer than CAP_CLOSURE_MIN_OBJECTS_SCANNED objects
#                     scanned prints UNPROVEN and exits 2 — never 0. Modeled
#                     on CJ_MIN_OBJECTS_SCANNED in
#                     tests/harness/src/test_cold_join_sovereign.c.
#   5. RAW SYSCALL BAN. A hand-rolled syscall reaches the kernel with no
#                     symbol for `nm` to see, which defeats checks 1-3
#                     entirely. Every tracked .c file with no CAP_PRIVILEGE
#                     row is grepped for a direct `syscall(` call and for
#                     inline-asm trap instructions (`int $0x80`, `svc #`, a
#                     bare `syscall` mnemonic inside an asm block). Files
#                     that declare CAP_PRIVILEGE are exempt — they have
#                     already told a reviewer to look.
#   6. COVERAGE FLOOR. Every row in engine/composition/module_capabilities.def names a
#                     source file that was compiled into an epoch when the
#                     table was written — the table is a coverage
#                     expectation. Runs immediately after the epoch's object
#                     list is gathered, BEFORE items 1-3 and 5 are graded off
#                     it. More than CAP_CLOSURE_COVERAGE_BASELINE declared
#                     rows with no compiled object anywhere in this scan
#                     prints UNPROVEN and exits 2 — a partial epoch (e.g. a
#                     `make z23-dev`-only rebuild) can hold thousands of
#                     objects, well past the HOLLOWNESS floor, while still
#                     silently missing files the hollowness floor cannot see
#                     it missing. See CAP_CLOSURE_COVERAGE_BASELINE below for
#                     the measured baseline and how it was produced. FEWER
#                     unobserved rows than the baseline fails too (as a
#                     VIOLATION, not UNPROVEN) — the baseline is a shrink-only
#                     ratchet and coverage improving without lowering it is
#                     exactly how a ratchet rusts shut at a stale number.
#
# WEAK-UNDEFINED SYMBOLS. `nm -u` reports both STRONG undefined (type `U`)
# and WEAK undefined (type `w`, occasionally `v` for a weak object) symbols.
# A strip that keeps only `U` silently drops every weak-undefined reference —
# measured on this tree: 18 occurrences, including
# ed25519_secret_key_from_seed (CAP_WALLET) and five dynhost_*/tor_*/hs_*
# CAP_NETWORK entry points reached through Tor's weak-symbol linkage. A gate
# that stops seeing a whole symbol class while still reporting clean is worse
# than no gate. This gate treats `U`, `w` and `v` alike as undefined
# everywhere it reads `nm` output, and --selftest carries a case that
# regresses on it (case C of the selftest).
#
# THE OBJECT TREE THIS SCRIPT MEASURES: build/dev-obj/epochs/<hash>, the
# newest-mtime subdirectory when more than one epoch is present (a stale
# epoch can sit alongside a fresh one; this is the same "several epochs can
# coexist" accommodation test_cold_join_sovereign.c makes). Populate a
# COMPLETE one (the COVERAGE FLOOR above will refuse a `make z23-dev`-only
# rebuild) with:
#
#     tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
#       make -j16 build/bin/z23-dev build/bin/z23-package-verify-dev
#
# A cold build/dev-obj/ prints UNPROVEN and exits 2 rather than reporting a
# false clean — see HOLLOWNESS above. A newer-but-partial epoch (present but
# missing declared files) also prints UNPROVEN and exits 2 — see COVERAGE
# FLOOR above.
#
# Exit: 0 clean, 1 violations (including a stale, too-high coverage
# baseline), 2 hollow/partial scan, broken selftest, or cannot read
# engine/composition/capability_symbols.def (that file is owned by a different lane; its
# absence is a broken precondition, not zero violations).
#
# Usage:
#   tools/lint/check_capability_closure.sh              # the gate
#   tools/lint/check_capability_closure.sh --selftest    # prove it fires

# IMPLEMENTATION. This file is a shim: the gate and its --selftest are the z23-lint
# entry check-capability-closure (tools/lint/lintc/gate_capability_closure*.c).
# CAP_CLOSURE_MIN_OBJECTS_SCANNED is CCG_MIN_OBJECTS there and the baseline
# measured below, CAP_CLOSURE_HOST_BASELINE, is CCG_HOST_BASELINE; the
# stale-baseline message still names CAP_CLOSURE_COVERAGE_BASELINE, which
# ZCL_CAP_CLOSURE_COVERAGE_BASELINE overrides. ZCL_CAP_CLOSURE_ENFORCE_SYMMETRY,
# ZCL_CAP_CLOSURE_SOURCE_RECORD and CAP_CLOSURE_CFLAGS_OVERRIDE keep their meaning.

# Anti-hollow floor. Named after CJ_MIN_OBJECTS_SCANNED in
# tests/harness/src/test_cold_join_sovereign.c, same discipline: a tree below the
# floor is refused, never reported clean (500 objects).

# Coverage floor, shrink-only ratchet (same discipline as
# WCA_RATCHET_CEILING in gate_no_wallclock_assertion.c — read that file's header for the
# convention this mirrors). Every row in engine/composition/module_capabilities.def names
# a source file that WAS compiled into an epoch when the table was written;
# the table is itself a coverage expectation. A partial rebuild (e.g.
# `make z23-dev` alone) produces a newer-but-incomplete epoch that silently
# drops objects like tools/package_verify.o while still holding thousands of
# objects — comfortably above CAP_CLOSURE_MIN_OBJECTS_SCANNED, so the
# hollowness floor above cannot see it. Measured live: exactly that rebuild
# made this gate report "OK — closed" while three genuinely unclassified
# symbols reachable only from tools/package_verify.c stayed invisible to it.
# The count of module_capabilities.def rows with NO compiled object anywhere
# in the scanned epoch ("declared but unobserved") is the signal a targeted,
# partial scan leaves that a blanket object-count floor cannot.
#
# Overridable (ZCL_CAP_CLOSURE_COVERAGE_BASELINE) so --selftest can aim it at
# synthetic fixtures far too small to ever carry the production count.
#
# Baseline measured 2026-08-30 against a freshly built COMPLETE Linux epoch:
#   tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
#     make -j16 build/bin/z23-dev build/bin/z23-package-verify-dev
# (2060 objects, epoch 2617150eb95064fbce18c5cd445173e9dc2e80d3787aa96ad604d8c14f9b26f7).
# Of the host-selected module declaration set, exactly 2 have no compiled
# object anywhere in that epoch, both genuine standalone binaries neither
# target links:
#   tests/harness/src/test_thread_qos.c   — built only by the test harness
#   tools/rebuild_recent.c           — its own BUILD_NODE_TOOL binary
# Neither belongs in z23-dev or the package verifier; this is the honest
# floor for THIS pair of targets, not padding. Host alternatives that Makefile
# does not select are excluded by exact source identity below: Linux drops the
# sandbox stub; Darwin drops the Linux sandbox and native self-backtrace arms;
# Windows drops the Linux sandbox and VCS arms plus the explicitly refused
# Linux-confinement package verifier. They are not baseline headroom. If a
# dependency shape changes, the baseline may only move DOWN without review —
# a rise means either a legitimate new standalone exemption (document it
# above) or the partial-scan regression this floor exists to catch.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-capability-closure "$@"
