#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no dev-history phrasing in production contract files.
#
# A header under any **/include/** dir, or a command .def table, IS the
# contract an operator or an LLM agent reads to learn what a module
# currently does. A stale "STEP-0 STATUS: contract + stub bodies; lane 2A
# lands the real thing" comment left behind after the real body landed is
# INCORRECT MODEL CONTEXT, not a style nit — an agent (or a human) reading
# the header trusts it over the .c body and reasonably concludes the
# feature is still unimplemented, re-proposing already-shipped work or
# distrusting a real, working call site. This gate rejects a narrow,
# high-signal set of dev-history phrases from those two production-contract
# surfaces so the pattern cannot creep back in once cleaned up.
#
# Scope: every tracked-shape *.h file under any **/include/** directory,
# and every *.def table, anywhere in the tree. Allowlisted OUT: docs/
# (narrative is its whole point), vendor/ (third-party), and anything under
# a "test"/"tests" path component or named *_test.* (fixtures/tests narrate
# lane history and stub scaffolding on purpose).
#
# Phrase set is deliberately NARROW (high-signal only): generic phrases
# like "in flight" / "not done" false-positive on legitimate present-tense
# state descriptions elsewhere in the tree and are intentionally NOT
# included.
#
# Hollow-gate guard: gate_require_scanned aborts (exit 2) if the scan set
# is empty (a renamed/moved include/ dir or emptied .def population would
# otherwise silently report "clean" while blind).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-dev-history-in-contracts "$@"
