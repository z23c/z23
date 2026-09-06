#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_static_state.sh — every TU that can be recompiled into a
# hot-swap .so must define NO mutable file-scope statics.
#
# Ported to the C23 lint runtime (z23-lint); this shim keeps the gate's own
# name in the lint driver's gate list.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hotswap-static-state "$@"
