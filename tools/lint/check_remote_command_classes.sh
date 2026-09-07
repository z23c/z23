#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_remote_command_classes.sh — every command leaf has exactly one remote
# class, and the class table names nothing that does not exist.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# engine/composition/remote_command_classes.def answers, for each command leaf, "may a peer
# on our own mesh ask this node to run it?" (design:
# docs/work/REMOTE_COMMAND_CHANNEL.md). The table is only worth anything if it
# is COMPLETE. Two ways it rots, both silent:
#
#   A. A NEW leaf lands with no row. The table's own rule is that an
#      unclassified leaf is never_remote, so an omission is safe TODAY — and
#      that is exactly what makes it dangerous. Nothing breaks, nobody notices,
#      and the table stops being the place the decision is made. This gate makes
#      adding a command leaf a two-file operation: register it, and say whether
#      it may be reached remotely.
#
#   B. A row names a leaf that no longer exists. A renamed leaf leaves its old
#      name behind holding a permission. When the transport is written it will
#      look up by name; a stale row is a grant with no owner, and the next
#      person to add a leaf with a recycled name inherits it.
#
# Neither failure can be caught by reading one file. Both are set arithmetic
# between two sources of truth, which is what this gate does.
#
# ── SOURCES OF TRUTH (never re-parsed by hand) ──────────────────────────────
#   typed registry : engine/composition/commands/**/*.def, read by
#                    tools/lint/lintc/gate_remote_command_classes_parse.c
#                    (the eight ZCL_COMMAND_*_{READ,COMMAND} leaf macros;
#                    ZCL_COMMAND_BRANCH is not a leaf and dispatches nothing).
#   agent registry : cognition/controllers/include/controllers/agent_contracts.def,
#                    the flat AGENT_CONTRACT() method table that backs
#                    `z23 agentops`, `z23 agentdeployguard` and friends. It is a
#                    SECOND dispatchable command surface; leaving it out would
#                    leave `dbquery` and `dumpstate` unclassified.
#   class table    : engine/composition/remote_command_classes.def, read by
#                    the same gate_remote_command_classes_parse.c.
#
# ── WHAT IS ASSERTED (all fail-closed) ──────────────────────────────────────
#   1. Every registry leaf has a row.                    (defect A)
#   2. Every row names a live registry leaf.             (defect B)
#   3. No leaf is classified twice. Two rows for one leaf is two decisions,
#      and which one wins is decided by include order rather than by anyone.
#   4. Every row's class is one of the three known tokens. A typo'd class is a
#      row the future dispatcher cannot act on; failing closed on an unknown
#      token beats guessing.
#   5. Every REMOTE_CLASS_READ_ONLY / REMOTE_CLASS_OWNER_CAPABILITY row carries
#      a non-empty reason. Refusing needs no defence; PERMITTING does, and an
#      unexplained permission is the one a later reader cannot audit or remove.
#      REMOTE_CLASS_NEVER rows carry an empty reason by design — their argument
#      is the section comment above their group.
#   6. Every row is two well-formed C string literals. The table is X-macro data
#      that nothing #includes yet, so no compiler is watching it; a bare quote
#      typed in the reason prose passes checks 1-5 (the reason parses, silently
#      truncated) and detonates on whoever writes the first consumer. This check
#      was added because exactly that had happened twice in the first draft.
#
# There is NO baseline and no allowlist. The tree is clean, so a shrink-only
# baseline would only be a place to hide the next omission. Do not type the
# current leaf count into this comment — the gate prints the live counts on
# every run, and a frozen number here would go stale the next time somebody
# registers a command.
#
# Usage:
#   tools/lint/check_remote_command_classes.sh            # the gate
#   tools/lint/check_remote_command_classes.sh --selftest # prove it fires
# Env (self-test only; production never sets these):
#   ZCL_REMOTE_CLASS_DEF_DIR    typed command registry root
#   ZCL_REMOTE_CLASS_AGENT_DEF  agent-contract table
#   ZCL_REMOTE_CLASS_TABLE      remote class table
#
# Exit: 0 clean, 1 on any violation, 2 on a hollow/broken scan.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-remote-command-classes "$@"
