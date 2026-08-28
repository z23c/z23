#!/usr/bin/env bash
# Gate: sysinit boot-boundary ordering (HARD).
#
# The declarative boot-stage boundary records live in config/src/boot.c
# (k_boot_sysinit_records[]). sysinit_run_stage() runs each stage's records in
# the deterministic (stage, order, name) sort order — the SAME order this gate
# reconstructs. This gate pins that sorted order in a golden file so that
# adding, removing, or reordering a boundary record is a conscious, reviewed
# change (update the golden) rather than a silent shift in what runs when.
#
# Mirrors the sysinit_cmp() total order (lib/util/src/sysinit.c): stage number
# ascending, then `order` ascending, then `name` strcmp. The stage-name→number
# map below mirrors enum boot_stage (util/boot_phase.h) — keep them in lockstep.
#
# Regenerate the golden after an intentional change:
#   tools/lint/check_sysinit_ordering.sh --update
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

SRC="config/src/boot.c"
GOLDEN="$SCRIPT_DIR/sysinit_ordering_golden.txt"

[[ -f "$SRC" ]] || { echo "check_sysinit_ordering: FATAL — missing $SRC" >&2; exit 2; }

# enum boot_stage → rank (mirror of util/boot_phase.h). If boot.c references a
# stage not listed here, the gate aborts rather than silently ranking it 0.
declare -A STAGE_RANK=(
    [INIT]=0 [DATADIR_LOCKED]=1 [CRYPTO_READY]=2 [DB_OPEN]=3
    [WALLET_LOADED]=4 [BLOCK_INDEX_LOADED]=5 [CHAIN_TIP_RESOLVED]=6
    [NETWORK_READY]=7 [SERVICES_RUNNING]=8 [READY]=9
    [SHUTDOWN_REQUESTED]=10 [SHUTDOWN_COMPLETE]=11
)

# Extract one "rank|order|name" line per record literal. A record literal is a
# single source line carrying .stage=BOOT_STAGE_X, .order=N, and .name="...".
derive() {
    local line stage order name rank
    while IFS= read -r line; do
        stage=$(sed -n 's/.*\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_\([A-Z_]*\).*/\1/p' <<<"$line")
        [[ -n "$stage" ]] || continue
        # \{0,1\}, not GNU \?: the optional-sign quantifier must stay POSIX BRE
        # so Apple's sed parses the same pattern as GNU sed.
        order=$(sed -n 's/.*\.order[[:space:]]*=[[:space:]]*\(-\{0,1\}[0-9]*\).*/\1/p' <<<"$line")
        name=$(sed -n 's/.*\.name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$line")
        if [[ -z "$order" || -z "$name" ]]; then
            echo "check_sysinit_ordering: FATAL — record line missing .order/.name: $line" >&2
            exit 2
        fi
        rank="${STAGE_RANK[$stage]:-}"
        if [[ -z "$rank" ]]; then
            echo "check_sysinit_ordering: FATAL — unknown BOOT_STAGE_$stage (update STAGE_RANK)" >&2
            exit 2
        fi
        printf '%02d %06d %s\n' "$rank" "$order" "$name"
    done < <(grep -E '\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_' "$SRC")
}

DERIVED="$(derive | LC_ALL=C sort -k1,1n -k2,2n -k3,3)"

if [[ -z "${DERIVED//[[:space:]]/}" ]]; then
    echo "check_sysinit_ordering: FATAL — no boundary records found in $SRC" >&2
    exit 2
fi

if [[ "${1:-}" == "--update" ]]; then
    printf '%s\n' "$DERIVED" > "$GOLDEN"
    echo "[check_sysinit_ordering] golden updated ($(wc -l <"$GOLDEN") records)"
    exit 0
fi

[[ -f "$GOLDEN" ]] || { echo "check_sysinit_ordering: FATAL — missing golden $GOLDEN (run --update)" >&2; exit 2; }

if ! diff -u "$GOLDEN" <(printf '%s\n' "$DERIVED") >&2; then
    echo "[check_sysinit_ordering] FAIL — sysinit boundary order drifted from the golden." >&2
    echo "[check_sysinit_ordering] If intentional: tools/lint/check_sysinit_ordering.sh --update" >&2
    exit 1
fi

echo "[check_sysinit_ordering] OK — $(wc -l <"$GOLDEN") boundary records match the golden"
exit 0
