#!/usr/bin/env bash
# Lint gate E7 — no-authoritative-RAM-state (RATCHET).
#
# Consensus authority must live in the log, projections, and durable cursors.
# In-memory chain indexes can exist only as derived caches. This gate blocks
# new direct access to active_chain internals and new global/static active_chain
# instances, both of which make RAM look authoritative again.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-authoritative-ram-state "$@"
