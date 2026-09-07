#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fleet_facts.sh — every fleet fact still says something checkable, and
# the executor routing table in the docs is this table's output (HARD).
#
# engine/composition/fleet_facts.def is the one place the fleet's doctrine is
# written down: which executor handles which unit kind, what a train and a
# proof require, which failure signature names which trap. `z23 dev know`
# answers from it. A row whose object is a typo, or whose path names no
# tracked file, is a false statement an agent will act on.
#
# Asserted:
#   A. Every FLEET_TERM is unique, non-empty, bounded, and lowercase-rooted.
#   B. Every term containing '/' is a tracked file.
#   C. Every fact subject and object is a declared term or a canonical root
#      (64 lowercase hex). There is no free text on either side of a relation.
#   D. Every relation and context is declared in this same file.
#   E. Every confidence is DOCTRINE or OBSERVED. UNKNOWN is what the query
#      synthesizes when it has no row; writing it here would be a lie.
#   F. Every row has a `why`, bounded by the module's field.
#   G. No two rows repeat one subject/relation/object/context.
#   H. Every declared term is used. Dead vocabulary rots into a second
#      spelling of a live term.
#   I. A lives_at object is a path, not a token.
#   J. docs/agent/EXECUTOR_HEURISTICS.md's routing block is this file's own
#      output, so the .md can never become a second source.
#   K. Row and vocabulary counts are at or above their floors (a hollow scan
#      is exit 2).
#
# Usage:
#   tools/lint/check_fleet_facts.sh
#   tools/lint/check_fleet_facts.sh --selftest
#   tools/lint/check_fleet_facts.sh --write-doc   # `make docs-executor-routing`
#
# Env:
#   ZCL_FLEET_FACTS_ROOT   repo root (default: this script's repo)
#   ZCL_FLEET_FACTS_DEF    table path relative to root
#   ZCL_FLEET_FACTS_FLOOR  minimum fact-row count (default: 20)
#
# Exit: 0 clean, 1 on a false row, 2 on a hollow/missing table.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-fleet-facts "$@"
