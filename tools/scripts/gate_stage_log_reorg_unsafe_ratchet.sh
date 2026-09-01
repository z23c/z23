#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — ratchet on the reorg-UNSAFE "INSERT OR REPLACE keyed by
# height alone" pattern across the stage-log stores.
#
# WHAT IT GUARDS
# --------------
# Each stage-log store records per-height witness rows in a table whose
# PRIMARY KEY is `height` and writes them with `INSERT OR REPLACE` (verified
# this run, e.g. engine/jobs/src/utxo_apply_log_store.c:18 `height INTEGER
# PRIMARY KEY` + :68 `INSERT OR REPLACE INTO utxo_apply_log`). That UPSERT
# is keyed by height alone, so a reorg that re-applies a DIFFERENT block at
# the same height silently overwrites the prior witness instead of being a
# distinct, replayable record. The 8 existing stores share this shape; it is
# the current baseline. The danger is the pattern SPREADING to a new stage
# log without anyone re-examining reorg-correctness.
#
# THE RATCHET
# -----------
# This gate counts the `INSERT OR REPLACE` occurrences in the eight known
# stage-log store files and bakes 8 as the baseline. It PASSES today by
# construction. It FAILS if the count INCREASES — i.e. a 9th such store
# (or a second UPSERT in an existing store) is added. A new stage log MUST
# be made reorg-correct (key by block hash / be append-only) rather than
# copy the height-keyed-UPSERT shape, OR the author must consciously raise
# the baseline below after proving the new site is reorg-safe.
#
# The count may FREELY DECREASE (a store made reorg-correct removes its
# UPSERT) — that lowers the realized count under the ceiling and still
# passes; clean up the debt and lower BASELINE to re-tighten the ratchet.
set -euo pipefail

# Run from the repo root regardless of caller cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# When wired into the repo this script lives under tools/; fall back to the
# git toplevel so it also works when invoked from /tmp during development.
if [ -d "$SCRIPT_DIR/../.." ] && [ -f "$SCRIPT_DIR/../../Makefile" ]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
cd "$REPO_ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

# Baked baseline: the 8 known reorg-unsafe stage-log stores, one
# height-keyed INSERT OR REPLACE each (verified this run).
BASELINE=8

FILES=(
    engine/models/src/header_admit_log.c
    engine/jobs/src/body_fetch_log_store.c
    engine/jobs/src/script_validate_log_store.c
    engine/jobs/src/utxo_apply_log_store.c
    engine/jobs/src/validate_headers_log_store.c
    engine/jobs/src/tip_finalize_log_store.c
    engine/jobs/src/proof_validate_log_store.c
    engine/jobs/src/body_persist_log_store.c
)

# Optional override of the tracked FILES set (space-separated) so the lint-gate
# self-test can point the gate at a planted/empty set and prove the
# drifted-surface preflight fires (exit 2).
if [ -n "${ZCL_REORG_RATCHET_FILES:-}" ]; then
    read -r -a FILES <<< "$ZCL_REORG_RATCHET_FILES"
fi

# Fail-loud preflight: the tracked FILES list must itself be non-empty AND every
# entry must exist. A moved/renamed/emptied stage-log store would otherwise let
# the count loop run over a smaller (or empty) set and pass hollow under the
# ceiling. Treat a drifted scan surface as FATAL (exit 2), matching the
# consensus-parity gate's "refuse to pass off a partial scan" stance.
gate_require_scanned "${#FILES[@]}" 1 gate_stage_log_reorg_unsafe_ratchet \
    "the tracked stage-log store list is empty"
missing=0
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "gate_stage_log_reorg_unsafe_ratchet: MISSING tracked file: $f" >&2
        missing=1
    fi
done
if [ "$missing" != "0" ]; then
    echo "gate_stage_log_reorg_unsafe_ratchet: a stage-log store was moved/renamed." >&2
    echo "Update the FILES list (and re-verify the baseline) deliberately." >&2
    echo "Refusing to report a clean count off a drifted (partial) scan surface." >&2
    exit 2
fi

count=0
sites=()
for f in "${FILES[@]}"; do
    # Case-insensitive: catch 'insert or replace' regardless of casing.
    # grep exit 0=match/1=no-match pass through gate_grep; >=2 (unreadable file)
    # is FATAL instead of being masked as "no UPSERT here" by `|| true`.
    while IFS=: read -r lineno _; do
        [ -n "$lineno" ] || continue
        sites+=("$f:$lineno")
        count=$((count + 1))
    done < <(gate_grep -ni 'INSERT OR REPLACE' "$f")
done

if [ "$count" -le "$BASELINE" ]; then
    echo "gate_stage_log_reorg_unsafe_ratchet: OK — ${count} height-keyed INSERT OR REPLACE site(s) (baseline ${BASELINE})"
    for s in "${sites[@]}"; do echo "    $s"; done
    if [ "$count" -lt "$BASELINE" ]; then
        echo ""
        echo "NOTE: count (${count}) is BELOW the baseline (${BASELINE}) — debt was"
        echo "removed. Lower BASELINE in this script to ${count} to re-tighten the ratchet."
    fi
    exit 0
fi

echo ""
echo "gate_stage_log_reorg_unsafe_ratchet: FAIL — ${count} height-keyed INSERT OR REPLACE site(s), baseline is ${BASELINE}"
echo ""
echo "A NEW reorg-unsafe stage-log UPSERT appeared. Current sites:"
for s in "${sites[@]}"; do echo "    $s"; done
echo ""
echo "These stage-log stores key their witness rows by height alone and write"
echo "with INSERT OR REPLACE, so a reorg replacing the block at a height"
echo "silently overwrites the prior witness instead of recording a distinct,"
echo "replayable row. Do NOT spread the shape:"
echo "  - Make the new stage log reorg-correct (key by block hash, or be"
echo "    append-only) so re-application at a height does not clobber history; OR"
echo "  - If the new site is genuinely reorg-safe and reviewed, raise BASELINE"
echo "    in tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh deliberately,"
echo "    citing why."
exit 1
