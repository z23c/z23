#!/usr/bin/env bash
# Gate P3 (docs/work/palace-design.md §3) — check-no-orphan-placement: every
# tracked .c/.h resolves to a known navigator group (lib/<mod>, app/<shape>,
# core, config, tools, domain, adapters, ports). A file that falls through to
# the catch-all "root" group has no obvious home — the complement of the app/
# shape gate (#18), operationalizing "exactly one obvious place for each
# concept" across the WHOLE tree.
#
# The placement decision is the shell mirror of ci_group_for_path()
# (cognition/modules/codeindex/src/codeindex_group.c:79-94): a path is placed iff its first
# segment is one of the known tops followed by "/"; anything else → "root" →
# violation.
#
# Mode: WARN | RATCHET | FAIL (controlled by ZCL_LINT_MODE; default WARN),
# modeled on tools/lint/check_group_purpose.sh + framework_shape_check.sh.
# Ships RATCHET (palace-design §5, P4.4) against the shrink-only
# orphan_placement_baseline.txt seeded from the pre-ratchet tree; graduates to
# FAIL once the baseline empties.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-orphan-placement "$@"
