#!/usr/bin/env bash
# check_silent_bool_errors — RATCHET gate (shrink-only).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-silent-errors-bool "$@"
