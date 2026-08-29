#!/usr/bin/env bash
# check-lib-module-order — lib/ module link order (RATCHET).
#
# config/lib_module_order.def declares every lib/ module in LINK ORDER: rank
# is line position, and a module may reference only STRICTLY LOWER ranks. This
# gate proves that against the MEASURED graph, not against #include lines —
# tools/dev/module-linkgraph.sh joins `nm` defined-symbols (owner module)
# against undefined-symbols (referencing module) over the compiled objects, so
# it also sees references made through a bare `extern` with no include at all.
#
# Three things fail the gate:
#   (a) the module SET in config/lib_module_order.def disagreeing with the
#       lib/ tree itself. That file is the DECLARATION — the Makefile derives
#       LIB_MODULES from it and repo_shape.sh reads it — so it is checked
#       against the filesystem, the one witness that is still independent of
#       it. Checking it against anything derived from it would compare it to
#       itself,
#   (b) a lib/ module in the link graph that config/lib_module_order.def does
#       not declare (someone added lib/<mod>/ without ranking it), and
#   (c) an edge lib/A -> lib/B where rank(B) >= rank(A) and the edge is not
#       grandfathered in tools/scripts/lib_module_order_baseline.txt.
#
# Baseline file: tools/scripts/lib_module_order_baseline.txt
#   Format: one "lib/<from> -> lib/<to>" entry per line.
#   Blank lines and # comments are ignored.
#
# Ratchet, not HARD-empty: the tree has two strongly-connected components
# (2026-08-29, after the zcashconsensus shim purge) — {metrics sync validation
# net rpc storage} and {util health} — so no ordering can be back-edge-free.
# The baseline holds 4 back edges, which is the PROVEN MINIMUM (exhaustive
# over both components: 6! and 2! orderings give 3 + 1), not a heuristic's
# leftovers. That has a
# consequence worth stating plainly:
# re-ranking config/lib_module_order.def can NEVER remove a baseline line. Each
# one is paid down only by breaking the cycle — move the symbol down, or invert
# the dependency behind a seam the lower module owns. See the .def's header for
# how to re-derive all of this. A new back edge fails immediately. The gate
# also reports baseline entries that are no longer violations so the file can
# be tightened.
#
# ARMING. This gate needs compiled objects, and it measures ONE tree:
# build/obj, the production compile tree. Exactly one command populates it:
#
#     make build-only -j"$(nproc)"          <- the canonical arming path
#
# and `make lint-armed` runs that and then lint with the gate made mandatory.
# Nothing else arms it. In particular a full `make` does NOT: every binary in
# `all` is one whole-program `cc` straight from $(ALL_SRCS) with no -c step,
# so it leaves zero .o files behind. `make test*` populates build/test-rel-obj
# and friends, which this gate deliberately ignores — see the WHICH TREE note
# in tools/dev/module-linkgraph.sh for why cross-tree comparison is a category
# error, not drift.
#
# With build/obj cold the gate reports NOT MEASURED and exits 0 rather than
# failing on unmodified code. Set ZCL_LINT_REQUIRE_LINKGRAPH=1 to turn that
# into a failure (CI that always builds first should set it; `make lint-armed`
# does).
set -euo pipefail

cd "$(dirname "$0")/../.."

# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

DEF=config/lib_module_order.def
BASELINE=tools/scripts/lib_module_order_baseline.txt
GRAPH_TOOL=tools/dev/module-linkgraph.sh
# The one object tree this gate measures. Must match the baseline's
# "measured-from-tree" header, asserted below.
OBJ_ROOT=build/obj

[ -f "$DEF" ] || { echo "check_lib_module_order: FAIL — missing $DEF"; exit 1; }
[ -x "$GRAPH_TOOL" ] || { echo "check_lib_module_order: FAIL — missing $GRAPH_TOOL"; exit 1; }
[ -f "$BASELINE" ] || touch "$BASELINE"

# Keying the baseline to its tree. A baseline seeded from build/obj compared
# against edges measured from a test tree reports violations that do not exist
# in the shipped binary — the failure mode this header exists to make loud.
declared_tree=$(sed -n 's/^#[[:space:]]*measured-from-tree:[[:space:]]*//p' "$BASELINE" | head -1)
if [ -n "$declared_tree" ] && [ "$declared_tree" != "$OBJ_ROOT" ]; then
    echo "check_lib_module_order: FAIL — baseline/tree mismatch."
    echo "  $BASELINE says it was measured from '$declared_tree'."
    echo "  This gate measures '$OBJ_ROOT'. Those are not comparable."
    echo "  Re-seed the baseline from $OBJ_ROOT (make build-only, then"
    echo "  tools/dev/module-linkgraph.sh --summary --obj-root $OBJ_ROOT)."
    exit 1
fi

# ── the .def is the DECLARATION, so check it against the tree ────────────
# The Makefile derives LIB_MODULES from this file and repo_shape.sh reads it
# directly, so comparing the .def to either of them now compares it to itself
# and would pass no matter how wrong it was. Deleting a copy removes the
# cross-check that copy provided, so the check has to be re-pointed at
# something that is still an independent witness. That is the filesystem: a
# lib/<mod>/ directory with tracked sources exists whether or not anyone
# remembered to declare it.
#
# lib/test is excluded deliberately — the test runner is built from its own
# Makefile variable and is outside the production link order (see the .def
# header).
def_set=$(sed -n 's/^[[:space:]]*LIB_MODULE("\([A-Za-z0-9_]*\)").*/\1/p' "$DEF" | LC_ALL=C sort -u)
disk_set=$(git ls-files lib | cut -d/ -f2 | LC_ALL=C sort -u | grep -vx test || true)

gate_require_scanned "$(printf '%s\n' "$disk_set" | grep -c . || true)" 1 \
    check_lib_module_order \
    "no lib/<mod>/ directories found — is this a checkout, and did git ls-files run?"

if [ "$def_set" != "$disk_set" ]; then
    echo "check_lib_module_order: FAIL — $DEF does not match the lib/ tree."
    echo "  declared but no such module directory:"
    comm -23 <(printf '%s\n' "$def_set") <(printf '%s\n' "$disk_set") | sed 's/^/    /'
    echo "  present in lib/ but never declared:"
    comm -13 <(printf '%s\n' "$def_set") <(printf '%s\n' "$disk_set") | sed 's/^/    /'
    echo
    echo "  An undeclared module compiles nothing: the Makefile derives every"
    echo "  lib/ source glob and -I flag from this file, so a module missing"
    echo "  here is a module missing from the build. Add it at the lowest rank"
    echo "  that keeps this gate green."
    exit 1
fi

# ── ranks: line position in the .def ─────────────────────────────────────
declare -A rank
n=0
while IFS= read -r mod; do
    n=$((n + 1))
    rank["lib/$mod"]=$n
done < <(sed -n 's/^[[:space:]]*LIB_MODULE("\([A-Za-z0-9_]*\)").*/\1/p' "$DEF")

if [ "$n" -eq 0 ]; then
    echo "check_lib_module_order: FAIL — no LIB_MODULE() entries parsed from $DEF"
    exit 1
fi

# ── baseline ─────────────────────────────────────────────────────────────
declare -A baseline
declare -A baseline_hit
baseline_count=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# ── measured graph ───────────────────────────────────────────────────────
# ZCL_LINKGRAPH_OBJ_DIR is the test/diagnostic seam: point the gate at a
# synthetic object tree instead of build/obj. test_make_lint_gates uses it to
# plant a violation and prove this gate fires (the private sandbox those
# checks run in has no build/ at all). Setting it is always EXPLICIT — the
# hazard this gate was fixed for was an implicit fall-through to whatever tree
# happened to be warm, not a deliberate override.
if [ -n "${ZCL_LINKGRAPH_OBJ_DIR:-}" ]; then
    GRAPH_SELECT="--obj-dir $ZCL_LINKGRAPH_OBJ_DIR"
    MEASURED="$ZCL_LINKGRAPH_OBJ_DIR (ZCL_LINKGRAPH_OBJ_DIR)"
else
    GRAPH_SELECT="--obj-root $OBJ_ROOT"
    MEASURED="$OBJ_ROOT"
fi
# shellcheck disable=SC2086  # GRAPH_SELECT is two controlled words.
GRAPH=$("$GRAPH_TOOL" --summary $GRAPH_SELECT 2>/dev/null) && graph_rc=0 || graph_rc=$?
if [ "$graph_rc" = "3" ]; then
    # Objects exist but their symbol tables could not be read. Never a green:
    # an unreadable graph is indistinguishable from a clean one, which is
    # exactly the false-green this gate exists to prevent.
    echo "check_lib_module_order: FAIL — the link graph could not be measured."
    "$GRAPH_TOOL" --summary $GRAPH_SELECT >/dev/null || true
    exit 1
fi
if [ "$graph_rc" != "0" ]; then
    if [ "${ZCL_LINT_REQUIRE_LINKGRAPH:-0}" = "1" ]; then
        echo "check_lib_module_order: FAIL — no compiled objects under $MEASURED; cannot measure the link graph."
        echo "  Run 'make build-only -j\$(nproc)' first (ZCL_LINT_REQUIRE_LINKGRAPH=1 is set)."
        exit 1
    fi
    echo "check_lib_module_order: NOT MEASURED — no compiled objects under $MEASURED."
    echo "  Ranks in $DEF were not checked. Run 'make build-only -j\$(nproc)'"
    echo "  (the canonical arming path) or 'make lint-armed', then re-run."
    exit 0
fi

fail=0
undeclared=()
violations=()

while IFS=$'\t' read -r edge count _syms; do
    from="${edge%% -> *}"
    to="${edge##* -> }"
    case "$from" in lib/*) ;; *) continue ;; esac
    case "$to"   in lib/*) ;; *) continue ;; esac
    # lib/test is the test runner, deliberately outside the production link
    # order and absent from the .def.
    [ "$from" = "lib/test" ] && continue
    [ "$to" = "lib/test" ] && continue

    if [ -z "${rank[$from]+x}" ]; then undeclared+=("$from"); fail=1; continue; fi
    if [ -z "${rank[$to]+x}" ];   then undeclared+=("$to");   fail=1; continue; fi

    if [ "${rank[$to]}" -lt "${rank[$from]}" ]; then
        continue   # forward edge: references a strictly lower rank. Good.
    fi
    key="$from -> $to"
    if [ -n "${baseline[$key]+x}" ]; then
        baseline_hit["$key"]=1
        continue
    fi
    violations+=("$key  (rank ${rank[$from]} -> ${rank[$to]}, ${count} symbol(s))")
    fail=1
done <<< "$GRAPH"

# Baseline entries that no longer correspond to a violation — the ratchet has
# room to tighten. Reported, never fatal (a different object profile can be
# missing a module's objects entirely).
stale=()
for key in "${!baseline[@]}"; do
    [ -z "${baseline_hit[$key]+x}" ] && stale+=("$key")
done

if [ "$fail" = "0" ]; then
    echo "check_lib_module_order: clean — ${n} ranked modules, ${baseline_count} baselined back edge(s), no NEW rank violations"
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "  ratchet can tighten — ${#stale[@]} baseline entry/entries no longer violate:"
        printf '    %s\n' "${stale[@]}" | sort
        echo "  Delete them from $BASELINE."
    fi
    exit 0
fi

echo ""
if [ "${#undeclared[@]}" -gt 0 ]; then
    echo "check_lib_module_order: lib module(s) in the link graph but NOT ranked in $DEF:"
    printf '%s\n' "${undeclared[@]}" | sort -u | sed 's/^/    /'
    echo ""
    echo "  Add a LIB_MODULE(\"<name>\") line at the lowest rank that keeps this"
    echo "  gate green. The Makefile's LIB_MODULES and codeindex's k_lib_modules[]"
    echo "  are both derived from that file, so this is the ONE place to declare it."
    echo ""
fi
if [ "${#violations[@]}" -gt 0 ]; then
    echo "check_lib_module_order: ${#violations[@]} NEW rank violation(s) not in $BASELINE"
    echo ""
    printf '    %s\n' "${violations[@]}" | sort
    echo ""
    echo "Fix options (RATCHET gate — new debt is never accepted):"
    echo "  1. Move the referenced symbol DOWN into a lower-ranked module."
    echo "  2. Invert the dependency: register a callback/port seam so the lower"
    echo "     module never names the higher one (see"
    echo "     node_db_set_quick_check_skip_probe in app/models/include/models/database.h)."
    echo "  3. Re-rank in $DEF — legitimate ONLY when the new position is"
    echo "     genuinely correct for the whole graph. Re-run"
    echo "     'tools/dev/module-linkgraph.sh --summary' and confirm the total"
    echo "     back-edge count did not grow before doing this."
    echo ""
    echo "  Inspect the exact reference sites:"
    echo "    tools/dev/module-linkgraph.sh --edges | grep -P '^lib/<from>\\tlib/<to>\\t'"
fi
exit 1
