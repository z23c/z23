#!/usr/bin/env bash
# Gate #19: no direct clock_gettime/gettimeofday/time(NULL)/getrandom outside platform/modules/platform.
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL for Phase 1)
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

roots=(tools engine/composition engine/application platform/adapters platform/ports)
mapfile -t app_roots < <(repo_shape_dirs app)
mapfile -t module_roots < <(repo_shape_dirs lib)
roots+=("${app_roots[@]}" "${module_roots[@]}" "${ZCL_DOMAIN_DIRS[@]}"
        core/consensus core/params core/math core/chainparams)

matches=$(
    grep -rn --include='*.c' --include='*.h' \
        -E '\bclock_gettime\s*\(|\bgettimeofday\s*\(|\btime\s*\(\s*NULL\s*\)|\bgetrandom\s*\(' \
        "${roots[@]}" "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
    | grep -v '^platform/modules/platform/' \
    | grep -v '^tools/lint/check_no_raw_clock_outside_platform.sh:' \
    | grep -v '// platform-ok' \
    || true
)

violations=0
gate_count_and_report "$matches" violations

echo "[check_no_raw_clock_outside_platform] $violations violation(s) found (mode: $MODE)"
echo "[check_no_raw_clock_outside_platform] ratchet now FAIL -- no new raw clock calls allowed"
echo "[check_no_raw_clock_outside_platform] use platform.clock/platform.rng or add // platform-ok for a documented exception"

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
