#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_acceptance_guard.sh — a Windows acceptance translation unit
# that defines main() must be an empty TU off Windows, or it collides with
# every test binary that links the harness sources. See
# tools/lint/lintc/gate_windows_acceptance_guard.c for the check itself.
#
# Usage:
#   tools/lint/check_windows_acceptance_guard.sh              # the gate
#   tools/lint/check_windows_acceptance_guard.sh --self-test  # prove red+green
#
# Env:
#   ZCL_WINDOWS_ACCEPTANCE_GUARD_ROOT  tree to scan (default: this repo).
#   ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH  selftest fixture root (default:
#                                       $HOME/.local/state/zclassic23/scratch).
#
# Exit: 0 clean, 1 on any guard-shape violation, 2 on a hollow/unreadable
#       scan (missing catalog, missing declared file, floor).
bin="$(dirname "$0")/../../build/bin/z23-lint"
if [ "${1:-}" = "--self-test" ]; then
    shift
    exec "$bin" check-windows-acceptance-guard --selftest "$@"
fi
exec "$bin" check-windows-acceptance-guard "$@"
