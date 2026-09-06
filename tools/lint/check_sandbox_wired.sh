#!/usr/bin/env bash
# Gate: sandbox wired (HARD).
#
# Ported to the C23 lint runtime (z23-lint); this shim keeps the gate's own
# name in the lint driver's gate list.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-sandbox-wired "$@"
