#!/usr/bin/env bash
# check_model_validation.sh — gate #11
#
# Every engine/models/src/*.c must either invoke at least one validates_*
# macro from engine/models/include/models/activerecord.h, or carry a
# deliberate `ar-validate-skip:<reason>` marker explaining why the AR
# validation lifecycle does not apply (e.g. infrastructure wrappers,
# registries, helper-only modules).
#
# Marker syntax (matches the obs-ok / raw-*-ok family):
#   ar-validate-skip:<short-tag>
# No space after the colon. The tag must be non-empty.
#
# Exit 0 on clean, 1 on any model file that satisfies neither rule.

set -euo pipefail

fail=0
missing=()
unTagged=()

shopt -s nullglob
for f in engine/models/src/*.c; do
    if grep -qE "ar-validate-skip:[A-Za-z][A-Za-z0-9_-]+" "$f"; then
        continue
    fi
    if grep -qE "validates_[a-z_]+\s*\(" "$f"; then
        continue
    fi
    # Catch the case where someone wrote the marker but left the tag empty
    if grep -qE "ar-validate-skip:?[[:space:]]*$" "$f" 2>/dev/null; then
        unTagged+=("$f")
    else
        missing+=("$f")
    fi
    fail=1
done

if (( ${#missing[@]} )); then
    echo "FAIL: the following model sources have no validates_* call and no ar-validate-skip:<tag> marker:"
    printf '  %s\n' "${missing[@]}"
fi

if (( ${#unTagged[@]} )); then
    echo "FAIL: the following files have an ar-validate-skip marker without a :<tag>:"
    printf '  %s\n' "${unTagged[@]}"
fi

if (( fail == 0 )); then
    echo "check_model_validation: clean — every model has validates_* or a tagged skip marker"
fi

exit $fail
