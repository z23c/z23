#!/usr/bin/env bash
# Gate — command-contract ratchet (lane OS-B1). Every native command leaf
# registered in engine/composition/commands/*.def must supply a NON-EMPTY `semantics`
# argument (the OUTPUT-interpretation contract inserted right after `summary`).
# The compiler already guarantees the argument is PRESENT (a missing macro arg
# fails the build); this gate guarantees it is not the empty/blank placeholder
# `""` that would compile but be dishonest, and fails loud on a hollow scan.

set -e

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

# Scan roots overridable so the lint-gate self-test can point at a planted
# fixture; production scans the seven command catalog fragments.
DEF_DIR="${ZCL_COMMAND_CONTRACT_DIR:-engine/composition/commands}"

mapfile -t def_files < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null)
gate_require_scanned "${#def_files[@]}" 1 check_command_contract \
    "no *.def under: $DEF_DIR"

# Leaf-registration macros (every one carries a semantics argument). Branches
# (ZCL_COMMAND_BRANCH) carry none and are excluded.
LEAF_RE='ZCL_COMMAND_(READY_READ|COMPAT_READ|PLANNED_READ|PLANNED_COMMAND|COMPAT_COMMAND|READY_COMMAND|DEV_READ|DEV_COMMAND)\('

# Fail-loud floor: the leaf population is large and known. A renamed/emptied
# catalog fragment would silently shrink the scan; refuse to pass off a hollow
# set. The floor sits below the live count (132) with headroom.
set +e
LEAF_COUNT=$(grep -hoE "$LEAF_RE" "${def_files[@]}" | wc -l)
lrc=${PIPESTATUS[0]}
set -e
if [ "$lrc" -ge 2 ]; then
    echo "check_command_contract: FATAL — leaf-count grep failed (exit $lrc)." >&2
    exit 2
fi
gate_require_scanned "$LEAF_COUNT" 125 check_command_contract \
    "leaf-macro population collapsed under floor"

MODE="${ZCL_LINT_MODE:-FAIL}"

# Empty/blank semantics: the `semantics` string sits immediately before the
# `budget` argument, so an empty (or whitespace-only) string literal followed
# by a budget token (`0`, a bare integer, or a ZCL_COMMAND_*_BUDGET name) is a
# placeholder semantics. No other empty string literal in a leaf macro
# (aliases/input_keys/positional_keys) is ever followed by a budget token, so
# this pattern is specific to a hollow semantics argument.
EMPTY_RE='"[[:space:]]*"[[:space:]]*,[[:space:]]*(0|[1-9][0-9]*|ZCL_COMMAND_[A-Z_]+)'
set +e
HITS=$(grep -rnE "$EMPTY_RE" "${def_files[@]}")
grc=$?
set -e
if [ "$grc" -ge 2 ]; then
    echo "check_command_contract: FATAL — scan grep failed (exit $grc);" >&2
    echo "  refusing to report PASS off a broken scan." >&2
    exit 2
fi

COUNT=$(printf "%s\n" "$HITS" | sed '/^$/d' | wc -l)
if [ "$COUNT" -gt 0 ]; then
    printf "%s\n" "$HITS"
    echo "[check_command_contract] $COUNT leaf(s) with an empty/blank" \
         "semantics argument (mode: $MODE)"
    echo "  Every leaf must supply a specific one-line OUTPUT-interpretation"
    echo "  semantics (source/freshness/units/completeness) — not \"\" and not"
    echo "  a restatement of summary. See engine/modules/kernel/include/kernel/"
    echo "  command_registry.h (struct zcl_command_spec.semantics)."
    if [ "$MODE" = "FAIL" ]; then exit 1; fi
fi

echo "[check_command_contract] PASS ($LEAF_COUNT leaves, all with semantics)"
