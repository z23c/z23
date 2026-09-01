#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_stray_untracked_source.sh — wf/dx-scanner-immunity mechanism 2b.
#
# Crashed agents and abandoned worktrees sometimes leave untracked .c/.h
# files sitting in a real scanned directory (app/**, domain/**, lib/**,
# config/**, core, adapters, tools). Every OTHER content-scanning gate then
# reports whatever that file happens to contain as if it were a real code
# violation — indistinguishable from an actual defect until a human
# recognizes `git status` shows it untracked and deletes it by hand. That
# recognition step is the actual papercut: `make lint` gives no hint the
# file is debris, not a defect.
#
# This gate runs FIRST in the `lint:` chain (see Makefile) and names the
# problem precisely: any untracked .c/.h file under a scanned root — OTHER
# than one matching the shared lint-fixture naming convention — is reported
# as "untracked stray file (not a code violation)" with its exact path,
# distinguishing it at a glance from every other gate's real violations
# (which are about tracked source content).
#
# Why the shared fixture-name glob (`_*fixture*.c`, see
# tools/lint/scan_exclusions.sh) IS excluded here, unlike the description in
# the header above might suggest: a file matching that convention is, BY
# DESIGN, untracked and transient — it is either a currently-running gate
# selftest's live fixture (tests/harness/src/test_make_lint_gates.c plants,
# scans, and unlinks one in well under a second) or leftover debris from a
# crashed run. There is no way to tell those two cases apart from a single
# filesystem snapshot, and `make lint` must not flake because a selftest
# happened to be running concurrently (see tools/lint/scan_exclusions.sh —
# every OTHER production scan already excludes this same glob for the same
# reason). A truly orphaned fixture is still visible to a plain `git status`
# and is harmless (excluded from every gate), so leaving it unflagged here
# is the correct tradeoff. This gate's job is the OTHER class of stray file:
# arbitrary-named debris (a half-written source file, a crashed agent's
# scratch output) that does NOT match the known-transient convention and
# WOULD otherwise be scanned as if it were real committed source.
#
# Mode is always FAIL (no baseline): a genuine stray file is never something
# to grandfather, only something to delete or `git add`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$SCRIPT_DIR/scan_exclusions.sh"

if [[ -n "${ZCL_STRAY_SCAN_DIRS_FOR_TEST:-}" ]]; then
    read -r -a SCAN_DIRS <<< "$ZCL_STRAY_SCAN_DIRS_FOR_TEST"
else
    SCAN_DIRS=(core engine contexts cognition platform core adapters tools)
fi

existing_dirs=()
for d in "${SCAN_DIRS[@]}"; do
    [[ -d "$d" ]] && existing_dirs+=("$d")
done
gate_require_scanned "${#existing_dirs[@]}" 1 check-no-stray-untracked-source \
    "none of the scanned root dirs exist — layout changed?"

mapfile -t candidates < <(
    find "${existing_dirs[@]}" -type f \( -name '*.c' -o -name '*.h' \) \
        -not -path "*/${LINT_PLANTED_DIR}/*" \
        -not -path '*/build/*' \
        -not -path '*/vendor/*' \
        -not -path '*/test-tmp/*' \
        -not -regex '.*/_[^/]*fixture[^/]*\.[ch]' \
        2>/dev/null | sort -u
)

strays=()
for f in "${candidates[@]}"; do
    if git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
        continue
    fi
    strays+=("$f")
done

if (( ${#strays[@]} > 0 )); then
    echo "FAIL: ${#strays[@]} untracked stray file(s) under scanned source dirs" >&2
    echo "  These are NOT code violations — they are files git does not track," >&2
    echo "  most often leftovers from a crashed agent or an abandoned worktree" >&2
    echo "  (files matching the lint-gate selftest fixture naming convention," >&2
    echo "  _*fixture*.c, are excluded from this check — see the header comment)." >&2
    echo "  Delete them (or 'git add' if intentional new source):" >&2
    for f in "${strays[@]}"; do
        echo "    $f [untracked stray file -- not a code violation]" >&2
    done
    exit 1
fi

echo "[check_no_stray_untracked_source] scanned ${#candidates[@]} file(s) under ${existing_dirs[*]}; 0 untracked strays"
exit 0
