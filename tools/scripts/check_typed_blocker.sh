#!/usr/bin/env bash
# Lint gate #16 — typed blocker primitive adoption.
#
# Goal: every "this is blocked" signal in the codebase is a typed
# blocker_record routed through `blocker_set()` (platform/modules/util/blocker.h),
# not a raw `char *_blocker[N]` string field or a bare `state == "blocked"`
# bool. The typed primitive is the only path with rate-limiting,
# escape dispatch, retry budget, and class-aware policy.
#
# Why: 2026-05-21 — the live node ran 4.3 days with
# `activation_blocker = "activation-no-progress"` re-firing ~5/sec
# because there was no de-duplication at the recorder. Round 6 C1
# shipped the typed primitive; C2/C3/C4/C5 wired it into the mirror
# consensus, source scoring, BLOCK_FAILED model, and native diagnostics. This gate
# is the ratchet that drives the rest of the codebase to opt in.
#
# A file is a "raw blocker site" if it contains one of:
#   - char[[:space:]]+[a-z_]*_blocker(_code)?\[   (raw blocker char[N] field)
#   - lms_set_blocker\(                            (legacy mirror string setter)
#   - g_[a-z_]*\.last_blocker_code\b             (legacy blocker_code mutation)
#
# Such a file must EITHER:
#   - call `blocker_set(` (uses the typed primitive somewhere); OR
#   - carry a per-file override marker `// blocker-ok:<tag>` on a line
#     in the file (explain WHY this site intentionally uses the string
#     surface — usually because it predates the typed primitive and is
#     scheduled for migration); OR
#   - appear in `tools/scripts/typed_blocker_baseline.txt`.
#
# To clean up debt: pick a baseline entry, migrate it to blocker_set()
# (see engine/services/src/block_source_policy_runtime.c
# classify_mirror_blocker_class() + score_source for the typed pattern),
# delete the baseline line, re-run `make lint`.
set -euo pipefail

BASELINE=tools/scripts/typed_blocker_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# Scan only production code (not tests, not vendor).
roots=(app/services app/controllers core/modules/validation platform/modules/util core/modules/net)

fail=0
new_violations=()
for root in "${roots[@]}"; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        # Skip the typed primitive itself and its tests.
        case "$f" in
            platform/modules/util/src/blocker.c|platform/modules/util/include/util/blocker.h) continue ;;
        esac
        # Match a raw blocker site.
        if ! grep -qE 'char[[:space:]]+[a-z_]*_blocker(_code)?\[|lms_set_blocker\(|g_[a-z_]*\.last_blocker_code\b' "$f"; then
            continue
        fi
        # Already calls the typed primitive somewhere? Pass.
        if grep -qE '\bblocker_set\(' "$f"; then
            continue
        fi
        # Per-file override marker? Pass.
        if grep -qE '//[[:space:]]*blocker-ok:[A-Za-z][A-Za-z0-9_-]*' "$f"; then
            continue
        fi
        # In baseline? Pass.
        if [ -n "${baseline[$f]+x}" ]; then
            continue
        fi
        new_violations+=("$f")
        fail=1
    done < <(find "$root" -name '*.c' -o -name '*.h')
done

if [ "$fail" = "0" ]; then
    echo "check_typed_blocker: clean — ${baseline_count} grandfathered, no new ones"
    exit 0
fi

echo ""
echo "check_typed_blocker: ${#new_violations[@]} NEW file(s) with raw blocker string surface but no typed blocker_set call"
echo ""
for v in "${new_violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Fix options (preferred → fallback):"
echo "  1. Call blocker_set() to register the blocker through the typed"
echo "     primitive. See engine/services/src/block_source_policy_runtime.c"
echo "     classify_mirror_blocker_class() for the classification pattern."
echo "  2. Add a per-file marker '// blocker-ok:<tag>' explaining why"
echo "     this site uses raw strings (typically: scheduled for migration"
echo "     in Round 7-8 or pre-dates the primitive)."
echo "  3. Last resort: add the file to $BASELINE."
exit 1
