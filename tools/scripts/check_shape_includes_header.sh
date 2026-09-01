#!/usr/bin/env bash
# Lint gate E3 — shape source files include their shape header (HARD).
#
# The framework places each app/.c file in a shape folder (Gate #18). That
# is a PATH-only claim: a file under engine/conditions/src/ is "a Condition"
# by virtue of where it sits, even if it never touches the Condition shape
# contract. This gate closes that mislabel hole — a shape file must include
# the header that defines its shape's contract:
#
#   engine/conditions/src/*.c   -> "framework/condition.h"  (the Condition
#                               shape contract) OR a "conditions/" header.
#   engine/models/src/*.c       -> a "models/" header (each model header pulls
#                               in models/activerecord.h, the AR lifecycle).
#   engine/supervisors/src/*.c  -> a "supervisors/" header OR "util/supervisor.h"
#                               (the supervisor liveness contract).
#
# engine/jobs/ is intentionally skipped: its job.h shape header does not exist
# yet. The tree fully satisfies this gate today, so it runs HARD — any new
# off-shape file (e.g. a Service mislabeled as a Condition because it lacks
# the contract include) fails immediately.
#
# Override: a shape file that legitimately cannot include the shape header
# (a pure registry/aggregator) may carry `// shape-include-ok:<tag>`
# (no space after the colon, non-empty tag) anywhere in the file.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

fail=0
violations=()

has_include() {
    # $1 = file, $2 = extended-regex matched against #include lines
    grep -qE "^[[:space:]]*#include[[:space:]]+\"$2\"" "$1"
}

has_override() {
    grep -qE '//[[:space:]]*shape-include-ok:[A-Za-z][A-Za-z0-9_-]*' "$1"
}

# Conditions: framework/condition.h OR a conditions/ header.
while IFS= read -r f; do
    has_override "$f" && continue
    if has_include "$f" 'framework/condition\.h' || has_include "$f" 'conditions/[^"]+'; then
        continue
    fi
    violations+=("$f: condition file includes neither \"framework/condition.h\" nor a \"conditions/\" header")
    fail=1
done < <(find engine/conditions/src -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)

# Models: a models/ header (transitively pulls activerecord.h).
while IFS= read -r f; do
    has_override "$f" && continue
    if has_include "$f" 'models/[^"]+'; then
        continue
    fi
    violations+=("$f: model file includes no \"models/\" header (activerecord lifecycle)")
    fail=1
done < <(find engine/models/src -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)

# Supervisors: a supervisors/ header OR util/supervisor.h.
while IFS= read -r f; do
    has_override "$f" && continue
    if has_include "$f" 'supervisors/[^"]+' || has_include "$f" 'util/supervisor\.h'; then
        continue
    fi
    violations+=("$f: supervisor file includes neither a \"supervisors/\" header nor \"util/supervisor.h\"")
    fail=1
done < <(find engine/supervisors/src -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)

if [ "$fail" = "0" ]; then
    echo "check_shape_includes_header: clean — every condition/model/supervisor file includes its shape header"
    exit 0
fi

echo ""
echo "check_shape_includes_header: ${#violations[@]} shape file(s) missing their shape header"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "A shape file must include the header that defines its shape contract."
echo "If it does not, it is a mislabeled file (likely a Service in disguise)."
echo "Fix: add the shape header, move the file to the correct shape folder,"
echo "or — for a genuine registry/aggregator — add '// shape-include-ok:<tag>'."
exit 1
