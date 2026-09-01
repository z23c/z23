#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# agent-baseline.sh — emit the pin a lane is judged against, as key=value.
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# Before dispatching a lane, the orchestrator was hand-deriving and hand-typing
# a baseline into a scratchpad note: HEAD sha, the registered test-group count,
# sha256 of the files that must not change, the lint gate count. Every one of
# those is mechanically derivable, and a hand-typed pin has two failure modes a
# derived one does not — it can be wrong when written, and it goes stale
# silently. A pin nobody can recompute is not a pin.
#
# ── CONTRACT ───────────────────────────────────────────────────────────────
#   * key=value on stdout, one per line, stable order. Diffable.
#   * DETERMINISTIC: same tree in, same bytes out. Deliberately NO timestamp —
#     a generated_at field would make every baseline differ from every other
#     baseline and destroy the only property that makes this useful.
#   * No network. No build. Nothing written anywhere.
#   * Fails (exit 1) if a file named in BASELINE_FILES is missing. Silently
#     dropping a file you were told to pin is the exact defect this replaces.
#
# ── USAGE ──────────────────────────────────────────────────────────────────
#   make agent-baseline
#   make agent-baseline BASELINE_FILES="core/MANIFEST.sha3 tests/harness/src/test_parallel.c"
#   tools/dev/agent-baseline.sh core/MANIFEST.sha3        # same, standalone
#
# Files may also arrive in the BASELINE_FILES environment variable
# (whitespace-separated), which is how the Makefile target passes them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO"

status=0

echo "baseline_schema=zcl.agent_baseline.v1"
echo "repo_root=$REPO"

# ── git identity ───────────────────────────────────────────────────────────
head_sha="$(git rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
echo "head_sha=$head_sha"
echo "head_short=${head_sha:0:9}"
echo "branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo UNKNOWN)"

# Dirty state belongs in the pin: a baseline taken over a modified tree does
# not describe head_sha, and a lane graded against it would be graded against
# something no commit contains.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "tree_dirty=1"
    echo "tree_dirty_files=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
else
    echo "tree_dirty=0"
    echo "tree_dirty_files=0"
fi

echo "merge_base_main=$(git merge-base HEAD main 2>/dev/null || echo UNKNOWN)"
echo "commits_ahead_of_main=$(git rev-list --count main..HEAD 2>/dev/null || echo UNKNOWN)"

# ── registered test groups ─────────────────────────────────────────────────
# From the X-macro registry, not from a run: a baseline must be derivable
# without building anything.
if reg="$("$SCRIPT_DIR/test-group-list.sh" --count 2>/dev/null)"; then
    echo "registered_test_groups=$reg"
else
    echo "registered_test_groups=UNKNOWN"
    status=1
fi

# ── lint gates ─────────────────────────────────────────────────────────────
# The authority is $(words $(LINT_GATES)) inside the Makefile, which the
# `make agent-baseline` target passes in ZCL_BASELINE_LINT_GATES. Standalone
# runs have no make, so parse LINT_GATES here too — and when BOTH are
# available, report a disagreement rather than picking one. A silent pick is
# how a derived number stops being derived from what it claims.
parse_lint_gates() {
    awk '
        /^LINT_GATES[[:space:]]*:?=/ { inside = 1 }
        inside {
            n = split($0, a, /[[:space:]]+/)
            for (i = 1; i <= n; i++)
                if (a[i] ~ /^check-/) c++
            if ($0 !~ /\\[[:space:]]*$/) exit
        }
        END { print c + 0 }
    ' Makefile
}
parsed_gates="$(parse_lint_gates)"
make_gates="${ZCL_BASELINE_LINT_GATES:-}"
if [ -n "$make_gates" ]; then
    echo "lint_gates=$make_gates"
    if [ "$make_gates" != "$parsed_gates" ]; then
        echo "lint_gates_parse_mismatch=$parsed_gates"
        status=1
    fi
else
    echo "lint_gates=$parsed_gates"
fi

# ── pinned file digests ────────────────────────────────────────────────────
files=()
if [ "$#" -gt 0 ]; then
    files=("$@")
elif [ -n "${BASELINE_FILES:-}" ]; then
    # Intentional word splitting: BASELINE_FILES is a whitespace-separated list.
    # shellcheck disable=SC2206
    files=(${BASELINE_FILES})
fi

echo "baseline_file_count=${#files[@]}"
for f in "${files[@]}"; do
    if [ -f "$f" ]; then
        digest="$(sha256sum -- "$f" | cut -d' ' -f1)"
        echo "sha256.$f=$digest"
    else
        echo "sha256.$f=MISSING"
        status=1
    fi
done

exit "$status"
