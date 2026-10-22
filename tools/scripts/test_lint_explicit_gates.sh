#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Execute the real umbrella recipe with harmless gates and count dispatches.
set -euo pipefail
# Refuse inherited repository/configuration selectors before invoking Git.
for git_selector in "${!GIT_@}"; do
    case "$git_selector" in
        GIT_PAGER|GIT_TERMINAL_PROMPT) continue ;;
    esac
    printf 'FAIL: inherited Git variable %s is not permitted\n' \
        "$git_selector" >&2
    exit 2
done
unset git_selector
root=$(git rev-parse --show-toplevel)
# The registered caller creates and cleans this directory with test_core.h.
fixture=${1:?expected caller-owned fixture directory}
[ -d "$fixture" ] || { echo 'FAIL: fixture directory missing' >&2; exit 2; }
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
awk '/^lint:/{copy=1} /^# Everything the lint dimension/{copy=0} copy' \
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
[ -f "$fixture/calls" ] || { echo 'FAIL: explicit failing gate not reached' >&2; exit 1; }
if grep -F 'all checks passed' "$fixture/failure.log" ||
   grep -Fx check-other "$fixture/calls"; then
    echo 'FAIL: lint ran after its explicit prerequisite failed' >&2
    exit 1
fi
echo 'PASS: lint dispatches each gate once and preserves explicit failures'

# Copy the real fast assignment and both production target recipes.
# Dependencies unrelated to dispatch are empty fixture variables; the
# existing tor-provenance-ready target is a harmless prerequisite.
awk '
    /^LINT_FAST_GATES :=/ { copy=1 }
    copy { print }
    copy && /^endif$/ { exit }
' "$root/Makefile" >> "$fixture/Makefile"
cat >> "$fixture/Makefile" <<'EOF_FAST'
.PHONY: $(LINT_FAST_GATES)
$(LINT_FAST_GATES):
	@echo $@ >> calls
	@test "$(FAIL_GATE)" != "$@"
EOF_FAST
fast_gate_once() {
    local gate=$1 count=0
    if [ -f "$fixture/calls" ]; then
        count=$(awk -v gate="$gate" '$0==gate {n++} END {print n+0}' "$fixture/calls")
    fi
    if [ "$count" -ne 1 ]; then
        echo "FAIL: lint-fast serial=$serial executed $gate $count times (expected 1)" >&2
        exit 1
    fi
}
for serial in 0 1; do
    rm -f "$fixture/calls"
    make -s -C "$fixture" -j2 lint-fast ZCL_LINT_SERIAL="$serial"
    for gate in check-capability-inventory-generated check-zcode-package-registry; do
        fast_gate_once "$gate"
        rm -f "$fixture/calls"
        if make -s -C "$fixture" -j2 lint-fast ZCL_LINT_SERIAL="$serial" \
            FAIL_GATE="$gate" > "$fixture/fast-failure.log" 2>&1; then
            echo "FAIL: lint-fast serial=$serial ignored $gate failure" >&2
            exit 1
        fi
        if [ ! -f "$fixture/calls" ] || ! grep -Fx "$gate" "$fixture/calls" >/dev/null; then
            echo "FAIL: lint-fast serial=$serial did not reach failing $gate" >&2
            exit 1
        fi
        rm -f "$fixture/calls"
        make -s -C "$fixture" -j2 lint-fast ZCL_LINT_SERIAL="$serial"
        fast_gate_once "$gate"
    done
done
echo 'PASS: both lint-fast recipes dispatch freshness gates and preserve their failures'
