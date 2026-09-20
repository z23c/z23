#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Measure the real factory, including both stores and reproduction. Run under
# devbuild. All signing keys, stores, caches, and reports belong to this fixture.
set -euo pipefail

fail() { printf 'c23-ingest-bench: %s\n' "$*" >&2; exit 1; }
if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "usage: $0 PACKAGE_DIR FACTORY BIN_DIR NEW_OUTPUT_DIR [ROUNDS=5]" >&2
    exit 2
fi
[[ $(uname -s) == Linux ]] || fail 'timing collection currently requires Linux'
root=$(cd "$(dirname "$0")/../.." && pwd -P)
cd "$root"
package=$(realpath "$1")
factory=$(realpath "$2")
binaries=$(realpath "$3")
output=$(realpath -m "$4")
rounds=${5:-5}
[[ $rounds =~ ^[1-9][0-9]*$ && $rounds -le 100 ]] || fail 'rounds must be 1..100'
[[ -d $package && -x $factory && -x build/bin/jsonq ]] || fail 'required input unavailable'
[[ ! -e $output ]] || fail 'output already exists; preserve earlier evidence'
mkdir -m 700 -p "$output/bin"
trap 'echo "c23-ingest-bench: interrupted; evidence retained at $output" >&2; exit 2' HUP INT TERM

# Freeze executable bytes so a rebuild cannot change the experiment midway.
cp "$factory" "$output/factory"
for binary in zclassic23 zclassic23-package-sign zclassic23-package-verify; do
    cp "$binaries/$binary" "$output/bin/$binary"
done
sha256sum "$output/factory" "$output/bin/"* > "$output/executables.sha256"
git rev-parse HEAD > "$output/checkout-commit"
git status --short > "$output/checkout-status"
uname -srm > "$output/host"
awk '/Cpus_allowed_list/ {print}' /proc/self/status >> "$output/host"
"$output/bin/zclassic23-package-sign" --generate "$output/publisher.key" > "$output/publisher.pub"
pubkey=$(cat "$output/publisher.pub")

prepare()
{
    "$output/bin/zclassic23" zcode package dev prepare --dir="$package" \
        --publisher_pubkey="$pubkey" --publisher_sequence=1
}
prepare > "$output/prepare.json"
field() { build/bin/jsonq get "$2" < "$1"; }
[[ $(field "$output/prepare.json" data.dependency_count) == 0 ]] ||
    fail 'workload requires dependency stores; select a dependency-free real package'
package_root=$(field "$output/prepare.json" data.package_root)
printf 'round\tstate\twall_s\tuser_s\tsystem_s\thits\tmisses\treused_bytes\n' > "$output/results.tsv"

for ((round=1; round<=rounds; round++)); do
    for state in cold warm; do
        prefix="$output/$round-$state"
        # Fresh stores in both runs, a fresh cache per round. Only the warm
        # run shares the round's cache. Neither host caches nor state is erased.
        /usr/bin/time -f '%e %U %S' -o "$prefix.time" \
            "$output/factory" run --package "$package" \
            --publisher-key-file "$output/publisher.key" --publisher-pubkey "$pubkey" \
            --store-a "$prefix-a" --store-b "$prefix-b" \
            --report "$prefix.report.json" --signer-seed-file "$output/admission.seed" \
            --bin-dir "$output/bin" --fast-cache "$output/$round.cache" \
            > "$prefix.log" 2>&1 || fail "factory failed; inspect $prefix.log"
        report="$prefix.report.json"
        [[ $(field "$report" ok) == true ]] || fail 'factory report failed'
        [[ $(field "$report" package.package_root) == "$package_root" ]] || fail 'source changed'
        for store in a b; do
            [[ $(field "$report" "stores.$store.reproduced") == true ]] || fail 'reproduction missing'
            for profile in quick standard; do
                id=$(field "$report" "stores.$store.receipt_$profile")
                oracle=$(field "$output/1-cold.report.json" "stores.a.receipt_$profile")
                [[ $id == "$oracle" ]] || fail "receipt changed: $store/$profile"
                cmp "$output/1-cold-a/zcode/receipts/$oracle" \
                    "$prefix-$store/zcode/receipts/$id" || fail 'receipt bytes changed'
            done
        done
        read -r wall cpu_user cpu_system < "$prefix.time"
        hits=$(field "$report" fast_cache.hits)
        misses=$(field "$report" fast_cache.misses)
        reused=$(field "$report" fast_cache.objects_reused_bytes)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$round" "$state" "$wall" "$cpu_user" "$cpu_system" \
            "$hits" "$misses" "$reused" >> "$output/results.tsv"
    done
done
prepare > "$output/prepare-after.json"
for key in package_root recipe_root dependency_lock_root; do
    [[ $(field "$output/prepare.json" "data.$key") == \
       "$(field "$output/prepare-after.json" "data.$key")" ]] || fail "workload changed: $key"
done
sha256sum -c "$output/executables.sha256" > "$output/executables-verified"
cat "$output/results.tsv"
printf 'evidence=%s\n' "$output"
