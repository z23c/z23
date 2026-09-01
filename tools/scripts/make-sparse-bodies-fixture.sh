#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# make-sparse-bodies-fixture.sh — build a synthetic "sparse bodies" mini-
# datadir on disk, for local manual repro of the body-coverage-aware
# auto-reindex-chainstate DECISION (lane 2B, "Track B" — see
# tests/harness/src/test_reindex_sparse_bodies.c, which builds the IDENTICAL
# layout in-process for the automated regression gate).
#
# Scenario modeled: coins are seeded at a tip height H, but the on-disk
# block bodies are SPARSE — present only for a tail window [H-K, H], not
# contiguously from genesis. A body-coverage-aware reindex decision must
# REFUSE the destructive -reindex-chainstate remedy here (a full replay
# from genesis through H cannot be supplied by this datadir), never
# consume the armed auto_reindex_request sentinel and wipe the seeded
# coins for a rebuild that cannot even complete.
#
# Output layout (NOT a real node datadir — no node.db/progress.kv/block
# index; this is a minimal fixture for exercising the decision in
# isolation, e.g. under a debugger or a future manual CLI probe):
#
#   <dir>/blocks/h<N>.body     — empty marker file per height N whose body
#                                is present, written only for N in [H-K, H]
#   <dir>/coins_best           — "<height> <hash_verified 0|1>"
#   <dir>/auto_reindex_request — "<anchor> <count>" (the REAL on-disk
#                                sentinel format — see
#                                engine/modules/storage/include/storage/boot_auto_reindex.h)
#
# Usage:
#   tools/scripts/make-sparse-bodies-fixture.sh [dir] [H] [K]
#
#   dir   destination directory (default: a fresh mktemp -d under /tmp).
#         Refused if it already exists and is non-empty — this script
#         never overwrites or merges into an existing directory.
#   H     the seeded coins-best / wedge-tip height (default: 5000)
#   K     bodies are present only in [H-K, H] (default: 100)
#
# Never touches a live datadir: `dir` defaults under /tmp and is refused
# outright if it resolves under $HOME/.zclassic-c23* or $HOME/.zclassic.

set -euo pipefail

DIR="${1:-}"
H="${2:-5000}"
K="${3:-100}"

case "$H" in
    ''|*[!0-9]*) echo "make-sparse-bodies-fixture: H must be a non-negative integer, got '$H'" >&2; exit 1 ;;
esac
case "$K" in
    ''|*[!0-9]*) echo "make-sparse-bodies-fixture: K must be a non-negative integer, got '$K'" >&2; exit 1 ;;
esac
if [ "$K" -gt "$H" ]; then
    echo "make-sparse-bodies-fixture: K ($K) must be <= H ($H) so the tail window stays >= 0" >&2
    exit 1
fi

if [ -z "$DIR" ]; then
    DIR="$(mktemp -d "/tmp/zcl23-sparse-bodies-XXXXXX")"
else
    if [ -n "${HOME:-}" ]; then
        case "$DIR" in
            "$HOME"/.zclassic-c23*|"$HOME"/.zclassic|"$HOME"/.zclassic/*)
                echo "make-sparse-bodies-fixture: refusing a live-datadir path: $DIR" >&2
                exit 1
                ;;
        esac
    fi
    if [ -e "$DIR" ]; then
        if [ ! -d "$DIR" ]; then
            echo "make-sparse-bodies-fixture: $DIR exists and is not a directory" >&2
            exit 1
        fi
        if [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
            echo "make-sparse-bodies-fixture: $DIR already exists and is non-empty — refusing to merge into it" >&2
            exit 1
        fi
    fi
fi

mkdir -p "$DIR/blocks"

FIRST=$((H - K))
n=0
h="$FIRST"
while [ "$h" -le "$H" ]; do
    : > "$DIR/blocks/h${h}.body"
    n=$((n + 1))
    h=$((h + 1))
done

printf '%s %s\n' "$H" 1 > "$DIR/coins_best"

# The armed sentinel, in the REAL on-disk format boot_auto_reindex_request
# writes (engine/modules/storage/src/boot_auto_reindex.c): "<anchor> <count>".
printf '%s %s\n' "$H" 1 > "$DIR/auto_reindex_request"

echo "make-sparse-bodies-fixture: wrote $DIR"
echo "  bodies present:  [$FIRST, $H] ($n marker files under blocks/)"
if [ "$FIRST" -gt 0 ]; then
    echo "  bodies MISSING:  [0, $((FIRST - 1))]  (sparse — no contiguous-from-genesis coverage)"
else
    echo "  bodies MISSING:  none (K >= H — genesis itself is covered; not a sparse fixture)"
fi
echo "  coins_best:       height=$H hash_verified=1"
echo "  auto_reindex_request: anchor=$H count=1 (armed)"
