#!/usr/bin/env bash
# Lint gate #14 — lib/ layer purity (HARD).
#
# Files under lib/ should not #include from engine/controllers/, engine/models/,
# engine/services/, contexts/explorer/views/, or config/. lib/ is the foundation; app/ is the
# upstream consumer and config/ is the composition root that wires the whole
# process together — both sit ABOVE lib/. A backward include typically means
# the lib/ file is doing something that belongs upstairs, or relying on a
# struct/function that should live in lib/.
#
# config/ is the sharpest case because the dependency is mutual: config/
# constructs the message processor, the reducer, and the databases, so a
# lib/ file that names a config/ symbol makes the two layers cyclic. When
# lib/ genuinely needs something the composition root owns (a live handle, a
# policy answer), declare a port in lib/ and let config/ register the
# implementation — see core/modules/net/include/net/net_runtime_port.h and
# engine/modules/storage/include/storage/node_db_runtime.h for the two shapes in tree.
#
# Not matched, deliberately: engine/modules/hotswap's `../../../config/*.def` includes.
# Those are X-macro DATA tables pasted into the translation unit; `nm` over
# hotswap_activate.o / hotswap_loader.o shows zero undefined config symbols,
# so they carry no link edge. Their paths are also named in docs/DEVELOPING.md,
# docs/AGENT_TRAPS.md and three other lint gates.
#
# tests/harness/include/test/ is out of scope (the find below prunes it): the test harness
# links and drives the composition root by design.
#
# Promotion (architecture audit): the baseline has reached zero — there are
# no grandfathered lib/ → app/ or lib/ → config/ includes left. HARD: ANY
# violation (new OR a re-added baseline entry) fails the build. The baseline
# is asserted to stay empty; adding an entry to "grandfather" a new violation
# is itself a failure. (The related domain/ source-purity gate now exists as
# tools/scripts/check_domain_purity.sh — gate #45, also HARD — so domain/ purity
# is enforced explicitly there, not just by build include-path scoping.)
#
# Baseline file: tools/scripts/lib_layering_baseline.txt
#   Format: one "<file>:<include-line>" entry per line.
#   Blank lines and # comments are ignored. MUST stay empty (HARD gate).
#
# Override on a specific line (preferred when you understand the trade-off
# and want to keep the include): add `// lib-layer-ok:<tag>` after the
# include directive. Use sparingly — every override is a debt marker.
#
# To clean up debt: remove the include from lib/ code (via forward decl
# or moving the symbol down to lib/), then delete the matching baseline
# entry. CI will then enforce that the file stays clean.
set -euo pipefail

# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

BASELINE=tools/scripts/lib_layering_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

# Read accepted violations into a hash set. Lines that start with # or
# that are blank are ignored.
declare -A baseline
baseline_count=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# HARD gate: the baseline has reached zero and must stay empty. A non-empty
# baseline would silently re-grandfather a lib/ → app/ include, so any entry
# is itself a failure.
if [ "$baseline_count" -ne 0 ]; then
    echo ""
    echo "check_lib_layering: $BASELINE must stay EMPTY (HARD gate) — found"
    echo "  ${baseline_count} grandfathered entr(y/ies). Fix the lib/ include and"
    echo "  delete the line instead of baselining it."
    exit 1
fi

fail=0
new_violations=()
while IFS= read -r f; do
    while IFS= read -r match; do
        line_content="${match#*:}"
        # Per-line override marker: skip immediately.
        if echo "$line_content" | grep -qE '//[[:space:]]*lib-layer-ok:[A-Za-z][A-Za-z0-9_-]*'; then
            continue
        fi
        # Extract just the bare `#include "..."` token (drop any trailing
        # comments) so the baseline key stays stable across cosmetic edits.
        include_token=$(echo "$line_content" \
            | sed -E 's@//.*$@@' \
            | sed -E 's@/\*.*\*/@@g' \
            | sed -E 's@^[[:space:]]+@@; s@[[:space:]]+$@@')
        key="${f}:${include_token}"
        if [ -n "${baseline[$key]+x}" ]; then
            # Pre-existing violation, accepted by the baseline. Continue.
            continue
        fi
        new_violations+=("$key")
        fail=1
    done < <(grep -nE '^[[:space:]]*#include[[:space:]]+"(controllers|models|services|views|config)/' "$f" || true)
done < <(find lib -type f \( -name '*.c' -o -name '*.h' \) ! -path '*/test/*' "${LINT_FIND_PRUNE_ARGS[@]}")

if [ "$fail" = "0" ]; then
    echo "check_lib_layering: clean — empty baseline (HARD), no lib/ → app/ or lib/ → config/ includes"
    exit 0
fi

echo ""
echo "check_lib_layering: ${#new_violations[@]} NEW violation(s) not in $BASELINE"
echo ""
for v in "${new_violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Fix options (this is a HARD gate — baselining is NOT an option):"
echo "  1. Delete the include if it's unused (the symbol may already come from elsewhere)."
echo "  2. Replace with a forward declaration (struct fwd + extern fn decl)."
echo "  3. Move the symbol down into lib/ where it can be referenced cleanly."
echo "  4. For a config/ include: declare a port in lib/ and register the"
echo "     implementation from config/ (net/net_runtime_port.h,"
echo "     storage/node_db_runtime.h are the two worked examples)."
echo "  5. As a deliberate, reviewed exception only, add an override marker"
echo "     '// lib-layer-ok:<tag>' to the include line."
exit 1
