#!/usr/bin/env bash
# check-no-writer-below-sealed-frontier — the North Star's single-writer rule
# (docs/ARCHITECTURE_NORTH_STAR.md invariant 1) made mechanical for the sealed
# ROM segment store (engine/modules/storage/chain_segment): written-once-then-immutable
# (chmod 0444, never rewritten/appended — see chain_segment.h's on-disk format
# doc), so exactly ONE designated surface may mutate it.
#
# WHY
# --------------------------------------------------------------------------
# Two functions are the entire WRITE API of the sealed store:
#   chain_segment_seal_range()       — seals a [first,first+count) range
#   chain_segment_manifest_rebuild() — rebuilds manifest.dat from disk
# Anything calling either of these is addressing a block position BELOW the
# sealed frontier with WRITE intent. If a random production caller starts
# doing that (a copy-paste seal call from a new feature, an ad-hoc "let me
# just reseal this" repair), it can race the one background sealer (one
# segment per tick, finality-margin gated) or the segment_corruption healer's
# unlink-then-rebuild repair, corrupting the store's write-once invariant.
#
# The designated writer surface (the only files allowed to call either
# function):
#   engine/modules/storage/src/chain_segment.c                  the writer implementation
#   engine/modules/storage/include/storage/chain_segment.h      the API declaration
#   engine/services/src/segment_sealer_service.c        the background sealer
#   engine/controllers/src/chain_segment_controller.c   the manual `sealsegments` RPC
#   engine/conditions/src/segment_corruption.c          the corruption healer's
#                                                     manifest rebuild-after-unlink
#
# Every other production `.c`/`.h` file is FORBIDDEN from calling either
# function. tests/harness/include/test/** (fixtures exercise the writer directly) is out of
# scope, same as check_no_shellouts; a fixture builder that lives outside
# lib/test carries an in-code `// writer-below-frontier-ok` marker naming why,
# so the exception is visible at the call site rather than hidden in this
# script's allowlist.
#
# NOT HOLLOW: the raw scan set is asserted against a floor via
# gate_require_scanned (docs/work/lint-gate-hollowness-audit.md) so a renamed
# symbol or an emptied scan root aborts LOUD instead of reporting clean.
#
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/lint/gate_lib.sh
. "$SCRIPT_DIR/gate_lib.sh"

cd "$ROOT"

GATE=check_no_writer_below_sealed_frontier

ALLOWLIST=(
    "engine/modules/storage/src/chain_segment.c"
    "engine/modules/storage/include/storage/chain_segment.h"
    "engine/services/src/segment_sealer_service.c"
    "engine/controllers/src/chain_segment_controller.c"
    "engine/conditions/src/segment_corruption.c"
)

# The designated writer surface must actually exist — a renamed/moved file
# would otherwise silently shrink the scan set and the gate would pass off a
# hollow scan.
for a in "${ALLOWLIST[@]}"; do
    if [[ ! -f "$a" ]]; then
        echo "$GATE: FATAL — designated writer file '$a' is missing." >&2
        echo "  The sealed-store write surface moved; update this gate's" >&2
        echo "  ALLOWLIST deliberately instead of letting the scan go hollow." >&2
        exit 2
    fi
done

is_allowed() {
    local f="$1"
    for a in "${ALLOWLIST[@]}"; do
        [[ "$f" == "$a" ]] && return 0
    done
    return 1
}

roots=()
for root in core engine contexts cognition platform; do
    [[ -d "$root" ]] && roots+=("$root")
done
gate_require_scanned "${#roots[@]}" 5 "$GATE" \
    "expected all five production authorities to exist"

# Raw scan: every mention of either write entry point across the production
# source roots, before any filtering. This is what the floor is asserted on.
raw=$(gate_grep -rn --include='*.c' --include='*.h' \
        -E '\b(chain_segment_seal_range|chain_segment_manifest_rebuild)\s*\(' \
        "${roots[@]}" || true)
raw_count=$(printf '%s' "$raw" | grep -c '' || true)
# Floor: the declaration pair in chain_segment.h, the definition pair in
# chain_segment.c, plus the sealer/RPC/healer call sites — a real tree can
# never have fewer than this and still have a sealed-segment substrate.
gate_require_scanned "$raw_count" 5 "$GATE" \
    "chain_segment_seal_range/chain_segment_manifest_rebuild appear to have been renamed"

matches=$(
    printf '%s\n' "$raw" \
    | grep -v '^tests/' \
    | grep -v '// writer-below-frontier-ok' \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    || true
)

violations=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    f="${line%%:*}"
    is_allowed "$f" && continue
    violations=$((violations + 1))
    echo "$line" >&2
done <<< "$matches"

echo "[$GATE] scanned $raw_count call/declaration site(s); $violations violation(s) (mode: $MODE)"
echo "[$GATE] only the sealer/RPC/healer/writer may call"
echo "[$GATE] chain_segment_seal_range() or chain_segment_manifest_rebuild();"
echo "[$GATE] add // writer-below-frontier-ok for a documented, reviewed exception"

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
