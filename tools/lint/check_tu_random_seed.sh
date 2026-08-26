#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — every per-TU object recipe pins GCC's random seed (HARD).
#
# THE BUG THIS PREVENTS. GCC derives its default random seed from the OUTPUT
# file name. tools/dev/compile-epoch-object.sh compiles every object into a
# fresh mktemp staging directory and publishes it atomically, so that name —
# and therefore the seed — was different on every single compile. Under
# -flto the seed becomes the `.gnu.lto_*.<suffix>` section-name suffix, and
# the shipped profile's objects stopped repeating even twice in ONE
# directory: measured 31/31 representative node TUs differing, with the object
# SIZE moving too because GCC trims leading zeros from that suffix.
#
# Nothing downstream notices. The binary still links, the tests still pass,
# and the only visible symptom is that the compile cache can never confirm it
# is serving the bytes a fresh compile would produce — which is the one thing
# a cache in a reproducibility-bearing project must be able to confirm.
#
# The fix is one flag, $(ZCL_TU_RANDOM_SEED), appended to each per-TU compile.
# It is easy to add a tenth object tree and forget it, and the omission is
# invisible, so this gate requires every `dep`-mode object recipe to carry it.
#
# The `coverage`-mode recipe is deliberately EXEMPT and is asserted to be the
# only exemption: gcov pairs a .gcno note with the object that will emit the
# .gcda, that recipe keeps its staging directory alive precisely because the
# object embeds the staging basename, and re-seeding it is a change to
# coverage plumbing rather than to reproducibility.
#
# `make repro-build` is the end-to-end proof; this is the cheap guard that
# keeps the flag from silently going missing between those slow runs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

MAKEFILE=Makefile
SEED_VAR='ZCL_TU_RANDOM_SEED'
fail=0

# The variable must exist and must be per-TU. A seed shared by every
# translation unit is not what GCC asks for and would defeat the purpose.
seed_def="$(grep -E "^$SEED_VAR[[:space:]]*=" "$MAKEFILE" || true)"
if [ -z "$seed_def" ]; then
    echo "FAIL: $MAKEFILE does not define $SEED_VAR"
    exit 1
fi
case "$seed_def" in
    *'-frandom-seed='*'$<'*) ;;
    *)
        echo "FAIL: $SEED_VAR must expand to -frandom-seed=<per-TU value>."
        echo "      A seed that is the same for every TU is not a per-TU seed."
        echo "      Found: $seed_def"
        exit 1
        ;;
esac

# Every object recipe routed through compile-epoch-object.sh, with its mode
# and the compiler line that follows it.
recipes="$(awk -v var="$SEED_VAR" '
    /BUILD_EPOCH_OBJECT_TOOL\)[[:space:]]+(dep|coverage)[[:space:]]/ {
        mode = ($0 ~ /[[:space:]]coverage[[:space:]]/) ? "coverage" : "dep"
        start = NR
        line = ""
        # The recipe is backslash-continued; the compiler argv is its last line.
        while ($0 ~ /\\[[:space:]]*$/) { if ((getline) <= 0) break }
        line = $0
        printf "%s\t%d\t%s\n", mode, start, line
    }
' "$MAKEFILE")"

if [ -z "$recipes" ]; then
    echo "FAIL: found no compile-epoch-object.sh object recipes in $MAKEFILE"
    exit 1
fi

dep_total=0
dep_seeded=0
cov_total=0
while IFS=$'\t' read -r mode line_no argv; do
    case "$mode" in
        dep)
            dep_total=$((dep_total + 1))
            case "$argv" in
                *"\$($SEED_VAR)"*) dep_seeded=$((dep_seeded + 1)) ;;
                *)
                    echo "FAIL: $MAKEFILE:$line_no — per-TU object recipe does not carry \$($SEED_VAR)"
                    echo "      $argv"
                    fail=1
                    ;;
            esac
            ;;
        coverage)
            cov_total=$((cov_total + 1))
            case "$argv" in
                *"\$($SEED_VAR)"*)
                    echo "FAIL: $MAKEFILE:$line_no — the coverage recipe carries \$($SEED_VAR)."
                    echo "      Coverage is the documented exemption (gcno/gcda pairing)."
                    echo "      If that changed, update this gate and the reason with it."
                    fail=1
                    ;;
            esac
            ;;
    esac
done <<< "$recipes"

if [ "$cov_total" -gt 1 ]; then
    echo "FAIL: expected exactly one coverage-mode object recipe, found $cov_total."
    echo "      The exemption is documented for one recipe; a second one has to"
    echo "      justify itself rather than inherit the first one's reason."
    fail=1
fi

if [ "$fail" != 0 ]; then
    echo ""
    echo "Fix: append \$($SEED_VAR) to the compiler argv of the object recipe."
    echo "     Proof of the property it buys: make repro-build"
    exit 1
fi

echo "check-tu-random-seed: PASS — $dep_seeded/$dep_total per-TU object recipes pin GCC's random seed ($cov_total coverage recipe exempt)"
