#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_specialists.sh — every specialist row still points at real territory,
# real lint gates, and real registered test groups (HARD).
#
# engine/composition/specialists.def is the one place a specialist lane is
# written down. `code focus` ranks from that table. A row whose globs match
# nothing, or that names a deleted gate or test group, is a false statement
# about where a lane should work.
#
# Asserted:
#   A. Every SPECIALIST name is unique and non-empty.
#   B. Every territory token matches at least one tracked file.
#   C. Every named gate exists in Makefile LINT_GATES / LINT_FAST_GATES or as
#      a `check-*:` target.
#   D. Every named test group is a ZCL_TEST_GROUP / ZCL_SPEC_GROUP row in
#      tools/dev/test_group_catalog.def.
#   E. Row count is at least the floor (a hollow scan is exit 2).
#
# Usage:
#   tools/lint/check_specialists.sh
#   tools/lint/check_specialists.sh --selftest
#
# Env:
#   ZCL_SPECIALISTS_ROOT   repo root (default: this script's repo)
#   ZCL_SPECIALISTS_DEF    catalog path relative to root
#   ZCL_SPECIALISTS_FLOOR  minimum row count (default: 10)
#
# Exit: 0 clean, 1 on a false row, 2 on a hollow/missing catalog.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-specialists "$@"
