#!/usr/bin/env bash
# Lint gate E4 — projections are pure folds over the event log (HARD).
#
# A projection (engine/modules/storage/src/*_projection.c) rebuilds a read-optimized
# view by folding the event/storage log into its OWN table(s). It must NOT
# reach upward into the app layer or mutate state through the model write
# path. Concretely, a projection must NOT:
#
#   1. #include anything from engine/services/ or engine/controllers/ — that
#      inverts the dependency arrow (storage is the foundation; services
#      and controllers are upstream consumers) and turns a pure fold into
#      a side-effecting coordinator.
#   2. write through the ActiveRecord model save path (AR_ADHOC_SAVE /
#      AR_CACHED_SAVE / AR_BEGIN_SAVE) — a projection owns raw projection
#      SQL over its own tables; routing a write through a Model save fires
#      that model's before/after hooks and creates a cross-shape write.
#
# The current projection set fully complies, so this gate runs HARD: any
# new include of a service/controller header, or any AR model save inside a
# projection, fails immediately.
#
# Override: a legitimate cache write (e.g. memoizing a derived value back
# into the projection's own table outside the strict fold) may carry
# `// projection-cache-ok:<tag>` (no space after the colon, non-empty tag)
# on the offending line.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Scan dir is overridable via ZCL_PROJ_SCAN_DIR so the lint-gate self-test can
# point the gate at an EMPTY dir and prove the non-empty-floor preflight fires
# (exit 2). Production scans engine/modules/storage/src.
PROJ_SCAN_DIR="${ZCL_PROJ_SCAN_DIR:-engine/modules/storage/src}"

fail=0
violations=()

line_overridden() {
    echo "$1" | grep -qE '//[[:space:]]*projection-cache-ok:[A-Za-z][A-Za-z0-9_-]*'
}

# Fail-loud preflight: discover the projection set and assert it is non-empty.
# A renamed *_projection.c suffix (build stays green via glob) would empty this
# set, run the loops zero times, and pass hollow. The floor catches that LOUD.
# find's nonzero exit (a missing dir) is not swallowed into a silent pass: it
# empties scan_files, which the floor below trips.
mapfile -t scan_files < <(find "$PROJ_SCAN_DIR" -type f -name '*_projection.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
gate_require_scanned "${#scan_files[@]}" 1 check_projections_pure \
    "no *_projection.c found under '$PROJ_SCAN_DIR' — a projection file was renamed/moved?"

for f in "${scan_files[@]}"; do
    # 1. upward includes into the app layer.
    while IFS= read -r match; do
        content="${match#*:}"
        line_overridden "$content" && continue
        violations+=("$f: projection includes an app-layer header (services/ or controllers/): ${content#"${content%%[![:space:]]*}"}")
        fail=1
    done < <(gate_grep -nE '^[[:space:]]*#include[[:space:]]+"(services|controllers)/' "$f")

    # 2. ActiveRecord model save path inside a projection.
    while IFS= read -r match; do
        content="${match#*:}"
        line_overridden "$content" && continue
        violations+=("$f: projection uses the AR model save path: ${content#"${content%%[![:space:]]*}"}")
        fail=1
    done < <(gate_grep -nE 'AR_(ADHOC|CACHED|BEGIN)_SAVE[[:space:]]*\(' "$f")
done

if [ "$fail" = "0" ]; then
    echo "check_projections_pure: clean — every *_projection.c is a pure fold (no app includes, no AR model saves)"
    exit 0
fi

echo ""
echo "check_projections_pure: ${#violations[@]} projection-purity violation(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "A projection is a pure fold over the event/storage log into its own"
echo "table(s). Fix options:"
echo "  1. Drop the app-layer include (forward-declare, or move the symbol"
echo "     down into lib/)."
echo "  2. Replace the AR model save with raw projection SQL over the"
echo "     projection's own table (projections do not fire model hooks)."
echo "  3. For a legitimate cache write, add '// projection-cache-ok:<tag>'"
echo "     on that line."
exit 1
