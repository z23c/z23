#!/usr/bin/env bash
# Every register_*_rpc_commands() callsite must use
# rpc_table_must_append (abort on failure) instead of rpc_table_append
# (returns false silently). Failure to register an RPC at boot is a
# programmer error — duplicate name, MAX_RPC_COMMANDS cap hit, or
# table already running. Silent drops left the control-group RPCs
# unreachable for a full release cycle; this gate prevents regressions.
#
# Allowed callers of rpc_table_append:
#   - engine/modules/rpc/src/server.c          — defines both helpers, internal use
#   - tests/harness/include/test/*                    — test fixtures may need the bool form
#
# Anything else is a failure.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-rpc-registrar "$@"
