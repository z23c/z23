#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
# Gate wrapper - see tools/lint/lintc/gate_object_reproducible.c for the
# full purpose comment. With arguments (--selftest, or the full flag set) it
# runs the gate directly. With none it asks the Makefile recipe, the single
# source of the flags, to run it.
if [ "$#" -eq 0 ]; then
    exec make --no-print-directory check-object-reproducible
fi
exec "$(dirname "$0")/../../build/bin/z23-lint" check-object-reproducible "$@"
