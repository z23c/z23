#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_eligible_scope.sh — every TU in the Tier-1 hot-swap
# eligibility manifest (engine/composition/hotswap_eligible.def) must be an app-layer
# surface.
#
# Ported to the C23 lint runtime (z23-lint); this shim keeps the gate's own
# name in the lint driver's gate list.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hotswap-eligible-scope "$@"
