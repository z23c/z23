#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Execute the real umbrella recipe with harmless gates and count dispatches.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z23-lint-explicit.XXXXXX")
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/tools/lint"
cat > "$fixture/Makefile" <<'EOF'
LINT_GATES := check-windows-acceptance check-other
ZCL_LINT_JOBS := 2
.PHONY: tor-provenance-ready check-windows-acceptance check-other
tor-provenance-ready:
	@:
check-windows-acceptance check-other:
	@echo $@ >> calls
	@test "$(FAIL_GATE)" != "$@"
EOF
awk '/^lint lint-cached lint-cold-audit:/{copy=1} /^# Everything the lint dimension/{copy=0} copy' \
    "$root/Makefile" >> "$fixture/Makefile"
cat > "$fixture/tools/lint/run_lint.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
    case "$1" in
        --jobs|--bin-dir) shift 2 ;;
        --cache|--cold-audit) shift ;;
        *) make --no-print-directory "$1"; shift ;;
    esac
done
EOF
chmod +x "$fixture/tools/lint/run_lint.sh"
for mode in alone combined all_explicit; do
    rm -f "$fixture/calls"
    goals=(lint)
    case "$mode" in
        combined) goals+=(check-windows-acceptance) ;;
        all_explicit) goals+=(check-windows-acceptance check-other) ;;
    esac
    make -s -C "$fixture" -j2 "${goals[@]}"
    for gate in check-windows-acceptance check-other; do
        count=$(awk -v gate="$gate" '$0==gate {n++} END {print n+0}' "$fixture/calls")
        if [ "$count" -ne 1 ]; then
            echo "FAIL: $mode executed $gate $count times (expected 1)" >&2
            exit 1
        fi
    done
done
rm -f "$fixture/calls"
if make -s -C "$fixture" -j2 lint check-windows-acceptance FAIL_GATE=check-windows-acceptance > "$fixture/failure.log" 2>&1; then
    echo 'FAIL: explicit gate failure did not fail the umbrella' >&2
    exit 1
fi
if grep -F 'all checks passed' "$fixture/failure.log" ||
   grep -Fx check-other "$fixture/calls"; then
    echo 'FAIL: lint ran after its explicit prerequisite failed' >&2
    exit 1
fi
echo 'PASS: lint dispatches each gate once and preserves explicit failures'
