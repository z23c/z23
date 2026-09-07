#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_macos_acceptance.sh — run the STATIC half of the macOS acceptance
# script under `make lint`, and say UNOBSERVED, in that word, about the half
# that needs an Apple host.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/scripts/macos_acceptance.sh has existed since the macOS port landed and
# nothing ran it. Its only reference in the whole tree was the recipe of the
# `macos-acceptance` Make target, which is a target a Linux box never invokes
# because its --run mode refuses on a non-Darwin host. It was in none of the
# four places a lint gate has to be wired (the gate_command() case table in
# tools/lint/run_lint.sh, LINT_GATES + a recipe + .PHONY in Makefile, the
# LINT-GATES block in docs/DEFENSIVE_CODING.md, and tools/lint/lint_cache.sh),
# so `make lint` never touched it. A script nobody runs is a script that is
# already wrong and has not been told.
#
# ── WHAT IS ACTUALLY CHECKED HERE, AND WHAT IS NOT ──────────────────────────
# The script has two modes and only one of them needs an Apple machine:
#
#   --check   Pure text. It reads engine/composition/platform/macos_capabilities.def and
#             asserts: the capability SET has not drifted from the validator's
#             closed list; every row carries one of the three legal states
#             (available / degraded / unavailable); every row carries a typed
#             reason code; and every evidence group a row names is a group
#             REGISTERED in tools/dev/test_group_catalog.def. Nothing here
#             touches Darwin, an SDK, or a compiler. It goes red on this box
#             the moment somebody adds a capability without evidence, points a
#             row at a test group that was renamed or deleted, or quietly
#             promotes an `unavailable` row to `available` while renaming it.
#             THAT is the gate, and it is a real one.
#
#   --run     Builds and executes the exact test groups the matrix derives,
#             then cuts, audits, checksums, and executes the node-free guide
#             from the real temporary darwin-arm64 runtime package. It refuses
#             unless `uname -s` is Darwin and `uname -m` is arm64. It cannot
#             run here and this gate does not pretend to.
#
# So this gate runs --check for real and reports --run as UNOBSERVED. It never
# prints a pass for the native leg. A gate that always passes is worse than no
# gate: it manufactures confidence. The honest deliverable on a Linux box is
# "the matrix is well-formed and every claim in it is backed by a registered
# test group; nobody here has watched those tests run on a Mac", and that is
# what it prints.
#
# ── WHY NOT RUN --run WHEN THE HOST *IS* DARWIN ─────────────────────────────
# Deliberate. --run builds and executes the derived test groups; `make lint` is the
# static pass and must stay seconds, not minutes. On an Apple host the native
# leg is `make macos-acceptance`, and this gate names that command in its
# UNOBSERVED line rather than silently doing something a lint run should not.
#
# Usage:
#   tools/lint/check_macos_acceptance.sh             # the gate
#   tools/lint/check_macos_acceptance.sh --self-test # prove it can go red
#
# Exit: 0 clean (the --check leg really ran); 1 on a malformed/unbacked
# capability matrix; 2 when the script, the matrix or the catalog is missing.


case "${1:-}" in
    --self-test) exec "$(dirname "$0")/../../build/bin/z23-lint" check-macos-acceptance --selftest ;;
    "")          exec "$(dirname "$0")/../../build/bin/z23-lint" check-macos-acceptance ;;
    *)           echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
