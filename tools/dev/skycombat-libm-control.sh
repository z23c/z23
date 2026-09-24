#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Test an allowlisted libm control recipe and a compile-valid wrong app edit.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s FACTORY_EVIDENCE_DIR NEW_OUTPUT_DIR\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
factory=$(realpath "$1")
output=$(realpath -m "$2")
[[ -f $factory/report.json && -f $factory/publisher.pub ]] || exit 2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
cmp "$root/apps/skycombat/src/models/aircraft.c" \
    "$factory/pkg/src/aircraft.c" > "$output/app-source-verified"
date --iso-8601=seconds > "$output/local-time"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -1 > "$output/compiler"
if [[ -r /proc/cpuinfo ]]; then
    awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
        /proc/cpuinfo > "$output/cpu-model"
elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string > "$output/cpu-model"
else
    printf 'unavailable\n' > "$output/cpu-model"
fi

cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
    -D_POSIX_C_SOURCE=200809L -ffunction-sections -fdata-sections \
    -I"$root/contexts/commons/modules/vcs/include" \
    -I"$root/platform/modules/codec/include" \
    -I"$root/platform/modules/base/include" \
    -I"$root/platform/modules/sha3/include" \
    "$root/tools/dev/fixtures/skycombat/recipe_libm.c" \
    "$root/contexts/commons/modules/vcs/src/package_recipe.c" \
    "$root/contexts/commons/modules/vcs/src/package_manifest.c" \
    "$root/platform/modules/codec/src/cursor.c" \
    "$root/platform/modules/base/src/safe_alloc.c" \
    "$root/platform/modules/base/src/log_level.c" \
    "$root/platform/modules/sha3/src/sha3.c" \
    -Wl,--gc-sections -o "$output/recipe-libm"

package_root=$("$root/build/bin/jsonq" get package.package_root \
    < "$factory/report.json")
recipe_root=$("$root/build/bin/jsonq" get package.recipe_root \
    < "$factory/report.json")
original_recipe="$factory/store-a/zcode/recipes/$recipe_root"
"$output/recipe-libm" "$original_recipe" "$output/recipe.libm" \
    > "$output/recipe-root"
"$root/build/bin/zclassic23" zcode package add plan \
    --input="{\"name_or_root\":\"$package_root\",\"datadir\":\"$factory/store-a\"}" \
    > "$output/add-plan.json"
lock_root=$("$root/build/bin/jsonq" get data.lock_root \
    < "$output/add-plan.json")

run_verifier()
{
    local label=$1 source=$2 source_root=$3 extra=$4 rc=0
    local emit="$output/$label-emit"
    local -a extra_args=()
    if [[ -n $extra ]]; then extra_args+=("$extra"); fi
    mkdir -p "$emit"
    { TIMEFORMAT='%R %U %S'; time \
        "$root/build/bin/zclassic23-package-verify" "$source_root" \
        --zbuild-package-source="$source" \
        --zbuild-package-recipe="$output/recipe.libm" \
        --zbuild-package-name=qualification/skycombat-aircraft \
        --zbuild-package-profile=standard \
        --zbuild-package-max-cpu-seconds=60 \
        --emit="$emit" --lock-root="$lock_root" \
        "${extra_args[@]}" --require-full-isolation \
        > "$output/$label.stdout" 2> "$output/$label.stderr"; } \
        2> "$output/$label.time" || rc=$?
    printf '%s\n' "$rc" > "$output/$label.exit"
}

run_verifier good "$factory/pkg" "$package_root" \
    "--plan=$output/good-plan.json"
[[ $(cat "$output/good.exit") == 0 ]] || exit 1
grep -q 'result=test-pass outputs=4 isolation=full' "$output/good.stdout"
grep -q 'zbuild-package-ok=1' "$output/good.stdout"

cp -a "$factory/pkg" "$output/wrong-pkg"
awk '
    index($0, "aircraft->speed + 50.0f * dt") {
        sub(/50[.]0f [*] dt/, "0.0f * dt")
        changed++
    }
    { print }
    END { if (changed != 1) exit 1 }
' "$output/wrong-pkg/src/aircraft.c" > "$output/wrong-aircraft.c"
mv "$output/wrong-aircraft.c" "$output/wrong-pkg/src/aircraft.c"
cc -std=c23 -Wall -Wextra -Werror -pedantic \
    -I"$output/wrong-pkg/include" \
    "$output/wrong-pkg/src/aircraft.c" \
    "$output/wrong-pkg/src/raymath_impl.c" \
    "$output/wrong-pkg/tests/test_aircraft.c" -lm \
    -o "$output/wrong-local-test"
wrong_local_exit=0
"$output/wrong-local-test" > "$output/wrong-local.stdout" \
    2> "$output/wrong-local.stderr" || wrong_local_exit=$?
[[ $wrong_local_exit == 1 ]] || exit 1
pubkey=$(cat "$factory/publisher.pub")
"$root/build/bin/z23" zcode package dev prepare \
    --input="{\"dir\":\"$output/wrong-pkg\",\"publisher_pubkey\":\"$pubkey\",\"publisher_sequence\":1}" \
    > "$output/wrong-prepare.json"
wrong_root=$("$root/build/bin/jsonq" get data.package_root \
    < "$output/wrong-prepare.json")
run_verifier wrong "$output/wrong-pkg" "$wrong_root" ""
[[ $(cat "$output/wrong.exit") == 6 ]] || exit 1
grep -q 'zbuild-package-standard-refused=1' "$output/wrong.stdout"
sha256sum "$output/recipe.libm" "$output/good-emit/build-report" \
    "$output/wrong-pkg/src/aircraft.c" > "$output/roots.sha256"
printf 'good_root=%s recipe_root=%s wrong_root=%s good=pass wrong=refused\n' \
    "$package_root" "$(cat "$output/recipe-root")" "$wrong_root"
