#!/usr/bin/env bash
# Lint gate #49 — blocker escape-action totality.
#
# escape_action is dual-purpose, and a literal is valid in any of three
# forms:
#
#   1. A DISPATCH KEY: blocker_supervisor_sweep() (platform/modules/util/src/blocker.c
#      ~:492) looks the string up in the blocker_register_escape() registry
#      via exact strcmp and calls the matching function. Valid iff a
#      blocker_register_escape("<same string>") call exists anywhere in the
#      tree.
#   2. A human-readable REMEDY DESCRIPTION for the operator (e.g. "re-run
#      script_validate for selected block hash") — never dispatched, purely
#      informational. A dispatch key or a condition name is always a single
#      identifier, never a phrase, so any literal containing whitespace is
#      recognized as this form and is exempt unconditionally.
#   3. The name of a CONDITION-ENGINE healer that drives the fix out of
#      band (e.g. "reducer_frontier_reconcile_light") — not a registered
#      escape function, but still not dead: the condition runs on its own
#      cadence and the literal is documentation of which one owns the fix.
#      Valid iff the identifier matches a registered condition name, i.e. a
#      ZCL_CONDITION(<name>) entry in
#      engine/conditions/include/conditions/condition_registry.def and/or a
#      `#define <X>_COND_NAME "<name>"` literal anywhere in the tree.
#
# A literal that is none of the three — an identifier matching no
# registered escape function AND no registered condition name — silently
# dead-ends blocker_supervisor_sweep's lookup AND is invisible to
# engine/conditions/src/blocker_stall_meta_detector.c's empty-escape backstop
# (which only catches truly empty strings), so nothing catches it. That is
# what this gate exists to catch.
#
# Empty escape_action strings are exempt (the meta-detector backstop already
# covers the "no escape configured" case; this gate is about strings that
# LOOK configured but silently dead-end).
#
# Scope: app/ config/ lib/ src/, excluding lib/test (production code only —
# test fixtures intentionally exercise unregistered names).

exec "$(dirname "$0")/../../build/bin/z23-lint" check-blocker-escape-registered "$@"
