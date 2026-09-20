#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Black-box cache acceptance on isolated copies of the real zsha256 package.
# Run through devbuild. Never changes the host compiler or existing caches.
set -euo pipefail
fail() { printf 'c23-cache-adversarial: %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: c23-cache-adversarial.sh BIN_DIR NEW_OUTPUT_DIR'
root=$(cd "$(dirname "$0")/../.." && pwd -P)
cd "$root"
binaries=$(realpath "$1")
output=$(realpath -m "$2")
[[ $output != *[!a-zA-Z0-9/._-]* ]] || fail 'output path must use plain path characters'
[[ ! -e $output ]] || fail 'output exists; preserve prior evidence'
mkdir -m 700 -p "$output/bin"
for binary in zclassic23 zclassic23-package-verify; do
    cp "$binaries/$binary" "$output/bin/$binary"
done
sha256sum "$output/bin/"* > "$output/executables.sha256"
node="$output/bin/zclassic23"
verifier="$output/bin/zclassic23-package-verify"
field() { "$root/build/bin/jsonq" get "$2" < "$1"; }
# Public generator point, used for unsigned prepare only.
pubkey=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
package="$output/package"
cp -R contexts/commons/packages/zsha256 "$package"

prepare() {
    "$node" zcode package dev prepare --dir="$package" \
        --publisher_pubkey="$pubkey" --publisher_sequence=1 > "$output/prepare.json"
    [[ $(field "$output/prepare.json" ok) == true ]] || fail 'prepare refused'
    package_root=$(field "$output/prepare.json" data.package_root)
    lock_root=$(field "$output/prepare.json" data.dependency_lock_root)
    field "$output/prepare.json" data.recipe_hex | xxd -r -p > "$output/recipe"
}
run() {
    local name=$1 cache=$2 profile=${3:-standard}
    "$verifier" "$package_root" --zbuild-package-source="$package" \
        --zbuild-package-recipe="$output/recipe" --zbuild-package-name=zsha256/zsha256 \
        --zbuild-package-profile="$profile" --zbuild-package-max-cpu-seconds=120 \
        --emit="$output/$name.emit" --lock-root="$lock_root" \
        --fast-cache="$cache" --require-full-isolation > "$output/$name.log" 2>&1
}
passed() {
    grep -q 'result=test-pass .*isolation=full' "$output/$1.log" || fail "$1 not isolated test-pass"
}
counters() {
    grep -q "zbuild-package-fast-cache=v1 hits=$2 misses=$3 " "$output/$1.log" ||
        fail "$1 unexpected cache counters"
}
control() {
    local name=$1
    run "$name-fresh" "$output/$name-fresh-cache"
    passed "$name-fresh"
    cmp "$output/$name.emit/build-report" "$output/$name-fresh.emit/build-report" ||
        fail "$name differs from fresh-cache oracle"
}

# A real public header value affects the library object, but not the tests.
# Preserve timestamps during mutation: the cache must follow bytes.
header="$package/include/zsha256/zsha256.h"
printf '\n#define INGEST_CACHE_VALUE 1\n' >> "$header"
printf '\nconst unsigned ingest_cache_value = INGEST_CACHE_VALUE;\n' >> "$package/src/zsha256.c"
prepare
run header-cold "$output/header-cache"
passed header-cold
counters header-cold 0 2
run header-warm "$output/header-cache"
passed header-warm
counters header-warm 2 0
cp -p "$header" "$output/header.original"
sed 's/INGEST_CACHE_VALUE 1/INGEST_CACHE_VALUE 2/' "$header" > "$output/header.next"
cat "$output/header.next" > "$header"
touch -r "$output/header.original" "$header"
prepare
run header-change "$output/header-cache"
passed header-change
counters header-change 1 1
control header-change
if cmp -s "$output/header-cold.emit/build-report" "$output/header-change.emit/build-report"; then
    fail 'header mutation did not change the actual output report'
fi

# Profile selection changes actual compiler warning flags and the cache key.
run flags-change "$output/header-cache" quick
passed flags-change
counters flags-change 0 2
run flags-warm "$output/header-cache" quick
passed flags-warm
counters flags-warm 2 0

# Generated C is an ordinary declared input, regenerated at the same path.
sed 's|"src/zsha256.c",|"src/generated.c", "src/zsha256.c",|' \
    "$package/zcode-package.json" > "$output/manifest.next"
cat "$output/manifest.next" > "$package/zcode-package.json"
printf 'const unsigned ingest_generated_value = 7;\n' > "$package/src/generated.c"
prepare
run generated-cold "$output/generated-cache"
passed generated-cold
counters generated-cold 0 3
cp -p "$package/src/generated.c" "$output/generated.original"
printf 'const unsigned ingest_generated_value = 8;\n' > "$package/src/generated.c"
touch -r "$output/generated.original" "$package/src/generated.c"
prepare
run generated-change "$output/generated-cache"
passed generated-change
counters generated-change 2 1
control generated-change
if cmp -s "$output/generated-cold.emit/build-report" "$output/generated-change.emit/build-report"; then
    fail 'generated mutation did not change the actual output report'
fi

# Corrupt bytes and each possible half of an interrupted pair must refuse,
# even though the complete correct cache is already warm for this input.
for kind in corrupt missing-object missing-sidecar; do
    cache="$output/$kind-cache"
    cp -R "$output/generated-cache" "$cache"
    # Every entry is damaged, including the current generated-input key.
    while IFS= read -r object; do
        chmod u+w "$object"
        case $kind in
            corrupt) printf 'invalid object bytes\n' > "$object" ;;
            missing-object) rm "$object" ;;
            missing-sidecar) rm "${object%.o}.json" ;;
        esac
    done < <(find "$cache/objects" -type f -name '*.o')
    if run "$kind" "$cache"; then fail "$kind was accepted"; fi
    grep -Eq 'fast cache (CORRUPTION|torn entry)' "$output/$kind.log" ||
        fail "$kind failed for an unrelated reason"
done

# Compiler identity binding at the carrier boundary: changing the capsule
# under an existing key must prevent export. This is not a live compiler
# replacement test; the host toolchain remains untouched.
"$node" zcode package fastobj export \
    --input="$(printf '{"cache_dir":"%s","datadir":"%s"}' "$output/generated-cache" "$output/export-control-store")" \
    > "$output/compiler-binding-control.log" 2>&1 || fail 'unaltered cache export refused'
cache="$output/compiler-binding-cache"
cp -R "$output/generated-cache" "$cache"
while IFS= read -r sidecar; do
    sed -E 's/("capsule_root":")[0-9a-f]{64}/\10000000000000000000000000000000000000000000000000000000000000000/' \
        "$sidecar" > "$output/sidecar.next"
    chmod u+w "$sidecar"
    cat "$output/sidecar.next" > "$sidecar"
done < <(find "$cache/objects" -type f -name '*.json')
if "$node" zcode package fastobj export \
    --input="$(printf '{"cache_dir":"%s","datadir":"%s"}' "$cache" "$output/export-store")" > "$output/compiler-binding.log" 2>&1; then
    fail 'changed compiler capsule exported under original key'
fi
grep -q 'sidecar key_components hash to' "$output/compiler-binding.log" ||
    fail 'compiler binding failed for unrelated reason'
sha256sum -c "$output/executables.sha256"
printf 'PASS: header, profile flags, generated C, corrupt object, interrupted pair; compiler capsule carrier binding\n'
printf 'NOT COVERED: replacement of an actual compiler executable\n'
