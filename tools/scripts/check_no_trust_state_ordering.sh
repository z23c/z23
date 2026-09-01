#!/usr/bin/env bash
# Lint gate — no ordinal comparison of enum sync_trust_state (HARD).
#
# The sync-trust states (services/sync_trust_policy.h) are ORTHOGONAL
# provenance facts, NOT a trust ordinal: EXPORT_ROOT_REDERIVED (¬S ∧ X) grants
# EXPORT only; ARTIFACT_VERIFIED (S ∧ ¬X) grants serve/spend/mine/seed but NOT
# export. Neither state is a superset of the other, so any `<`/`<=`/`>`/`>=`
# comparison against a SYNC_TRUST_* enumerator (or `enum sync_trust_state`) is a
# latent authorization bug — e.g. `if (state >= SYNC_TRUST_ARTIFACT_VERIFIED)
# allow(...)` would silently mis-grant. Authorization must route through the
# capability MASK (sync_trust_cap_allowed / sync_capabilities_from_evidence),
# never an ordinal.
#
# This gate FAILS (exit 1) if any tracked/untracked .c/.h under the scanned
# source trees contains such a comparison. The enum's own loop-bound over the
# COUNT sentinel (`s < SYNC_TRUST_STATE_COUNT`) is a legitimate iteration bound,
# not an ordinal trust comparison, so hits whose compared token is
# SYNC_TRUST_STATE_COUNT are excluded. Test sources (tests/harness/include/test/) are excluded.
#
# House style mirrors the other repo-scanning gates: exit 0 clean,
# exit 1 on a violation, exit 2 (via gate_require_scanned) on a hollow/empty
# scan.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

scan_pathspecs=()
for source_root in "${ZCL_SOURCE_AUTHORITIES[@]}" tools; do
    scan_pathspecs+=("$source_root/**/*.c" "$source_root/**/*.h")
done

# Comparators immediately adjacent to a SYNC_TRUST_* enumerator or the
# `enum sync_trust_state` type, in either operand position.
ORDER_RE='(<=|>=|<|>)[[:space:]]*SYNC_TRUST_|SYNC_TRUST_[A-Z_]+[[:space:]]*(<=|>=|<|>)|(<=|>=|<|>)[[:space:]]*enum[[:space:]]+sync_trust_state|enum[[:space:]]+sync_trust_state[[:space:]]*(<=|>=|<|>)'

# Scan tracked + untracked (non-ignored) .c/.h under the real source trees,
# excluding test sources. --untracked lets a selftest's planted fixture be
# seen; the shared scan_exclusions filter drops fixture/build/vendor noise when
# run through `make lint` (ZCL_LINT_PRODUCTION_SCAN=1), and passes everything
# through when a selftest execs this script directly.
mapfile -t hits < <(
    git grep --untracked -nE "$ORDER_RE" -- \
        "${scan_pathspecs[@]}" 2>/dev/null \
    | grep -vE 'SYNC_TRUST_STATE_COUNT' \
    | lint_filter_excluded || true
)

# Fail-loud: the enum definition + its callers guarantee the source trees carry
# SYNC_TRUST_ tokens. If NOTHING mentioning the enum is scannable, the scan
# producer emptied (renamed/moved tree) — never report clean off a hollow scan.
mapfile -t universe < <(
    git grep --untracked -lE 'SYNC_TRUST_|enum[[:space:]]+sync_trust_state' -- \
        "${scan_pathspecs[@]}" 2>/dev/null || true
)
gate_require_scanned "${#universe[@]}" 1 check_no_trust_state_ordering \
    "no source under the architecture authorities mentions SYNC_TRUST_ — was services/sync_trust_policy.* renamed/moved?"

if [ "${#hits[@]}" -gt 0 ]; then
    echo ""
    echo "check_no_trust_state_ordering: FAIL — ordinal comparison of enum sync_trust_state"
    echo ""
    for v in "${hits[@]}"; do
        echo "  $v"
    done
    echo ""
    echo "The sync_trust_state enumerators are ORTHOGONAL provenance facts, not a"
    echo "trust ordinal (EXPORT_ROOT_REDERIVED grants export-only; ARTIFACT_VERIFIED"
    echo "grants serve/spend/mine/seed but not export — neither is a superset)."
    echo "Fix: gate on the capability MASK, e.g."
    echo "  sync_trust_cap_allowed(st, SYNC_CAP_...) / sync_capabilities_from_evidence(...)"
    echo "never a </<=/>/>= comparison against a SYNC_TRUST_* value."
    exit 1
fi

echo "check_no_trust_state_ordering: clean — no ordinal sync_trust_state comparison (${#universe[@]} files scanned)"
exit 0
