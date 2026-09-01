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

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

HITS=$(grep -rn 'rpc_table_append\b' lib/ app/ tools/ config/ \
    --include='*.c' --include='*.h' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
    | grep -v '^engine/modules/rpc/src/server.c:' \
    | grep -v '^engine/modules/rpc/include/rpc/server.h:' \
    | grep -v '^tests/harness/include/test/' \
    || true)

if [ -n "$HITS" ]; then
    echo "$HITS"
    echo ""
    echo "FAIL: rpc_table_append() used outside engine/modules/rpc/src/server.c and tests/harness/include/test/."
    echo "      Use rpc_table_must_append() in every register_*_rpc_commands()"
    echo "      callsite. See engine/modules/rpc/include/rpc/server.h for the contract."
    exit 1
fi

echo "  OK: all RPC registrar callsites use rpc_table_must_append"
