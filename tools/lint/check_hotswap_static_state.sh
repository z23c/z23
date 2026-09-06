#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_static_state.sh — ported to the C23 lint runtime (z23-lint).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hotswap-static-state "$@"
