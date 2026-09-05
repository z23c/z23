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
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"

MODE="${ZCL_LINT_MODE:-WARN}"
BASELINE="$SCRIPT_DIR/orphan_placement_baseline.txt"

# The scan set is `git ls-files '*.c' '*.h'`. ZCL_ORPHAN_PLACEMENT_FILES
# overrides it (space/newline-separated repo-relative paths) — test isolation
# only, since git ls-files never sees an untracked planted fixture. Unset in
# production. Mirrors ZCL_SUPERVISOR_WORKER_FILES in check_supervisor_domain.sh.
if [[ -n "${ZCL_ORPHAN_PLACEMENT_FILES:-}" ]]; then
    read -r -a all_files <<< "$ZCL_ORPHAN_PLACEMENT_FILES"
    FLOOR=1
else
    mapfile -t all_files < <(git ls-files '*.c' '*.h')
    FLOOR=1500
fi

# Excludes: vendor (third-party), build artifacts, the test fixtures dir, and
# the repo's `_`-prefixed ephemeral-source convention (planted lint fixtures).
# contexts/commons/packages/ holds C23 Commons package payloads: inert published artifacts that
# are never compiled into the node build. Their placement discipline is the
# fixed Commons package layout (LICENSE/include/src/tests/zcode-package.json)
# enforced by the package factory gate, and the corpus census counts them
# through package-store intake — they have no node navigator group by design.
# apps/ is application code, not node code. The navigator groups this gate
# checks are the node's own (ci_group_for_path), and codeindex does not scan
# apps/ at all — it is not in source_roots.def — so a file there resolves to the
# catch-all "root" no matter where it sits. Its placement discipline is the
# application's own layout, and its C23 and portability gates are separate; see
# the two-tier rule in docs/DEFENSIVE_CODING.md §7.
is_excluded() {
    local f="$1" base="${1##*/}"
    case "$f" in
        apps/*|vendor/*|build/*|tests/harness/fixtures/*|contexts/commons/packages/*) return 0 ;;
    esac
    case "$base" in
        _*) return 0 ;;
    esac
    return 1
}

# Does the path resolve to a known group, or the catch-all "root"?
# Returns 0 (placed) or 1 (orphan → "root").
#
# The list is DERIVED from the Makefile's -I flag lists by repo_shape.sh, not
# hand-kept here. The hand-kept version omitted `application` — which the build
# has always carried an APPLICATION_INCLUDES for — so the first file written
# under engine/application/ would have been reported as misplaced by this very gate.
KNOWN_TOPS=("${ZCL_REPO_TOPS[@]}")
is_placed() {
    local f="$1" top
    for top in "${KNOWN_TOPS[@]}"; do
        [[ "$f" == "$top/"* ]] && return 0
    done
    return 1
}

declare -A ALLOWED=()
gate_load_list_file "$BASELINE" ALLOWED

scanned=0
considered=0
violations=0
allowlisted=0
for f in "${all_files[@]}"; do
    scanned=$((scanned + 1))
    is_excluded "$f" && continue
    considered=$((considered + 1))
    if is_placed "$f"; then
        continue
    fi
    if [[ "$MODE" != "FAIL" && -n "${ALLOWED[$f]:-}" ]]; then
        allowlisted=$((allowlisted + 1))
        continue
    fi
    violations=$((violations + 1))
    echo "$f: orphan placement — resolves to the catch-all 'root' group; move it under a known top (lib/<mod>, app/<shape>, core, config, tools, domain, adapters, ports)" >&2
done

gate_require_scanned "$scanned" "$FLOOR" check-no-orphan-placement \
    "git ls-files returned too few .c/.h — run from repo root inside the worktree?"

echo "[check_no_orphan_placement] scanned $scanned tracked source(s), considered $considered after excludes"
echo "[check_no_orphan_placement] $violations violation(s) found (mode: $MODE)"
if (( allowlisted > 0 )); then
    echo "[check_no_orphan_placement] $allowlisted allowlisted violation(s) ignored"
fi
if (( violations > 0 )); then
    echo "[check_no_orphan_placement] give the file an obvious home, or (shrink-only) write to tools/lint/orphan_placement_baseline.txt"
fi

fail=0
if (( violations > 0 )) && [[ "$MODE" == "FAIL" || "$MODE" == "RATCHET" ]]; then
    fail=1
fi
exit "$fail"
