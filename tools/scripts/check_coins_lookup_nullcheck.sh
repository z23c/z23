#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_coins_lookup_nullcheck.sh — ensure controller-level coins lookups
# are gated by the P24.14 chainstate safety guard.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-coins-lookup-nullcheck "$@"
