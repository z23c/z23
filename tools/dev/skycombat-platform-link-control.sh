#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# purpose: Exercise a declared C23 program with and without an X11 link need.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR BIN_DIR\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
output=$(realpath -m "$1")
bin_dir=$(realpath "$2")
[[ ! -e $output ]] || {
    printf 'output exists: %s\n' "$output" >&2
    exit 2
}
for binary in package-factory zclassic23 zclassic23-package-sign \
    zclassic23-package-verify jsonq; do
    [[ -x $bin_dir/$binary ]] || {
        printf 'missing executable: %s\n' "$binary" >&2
        exit 2
    }
done

fixture="$root/tools/dev/fixtures/skycombat"
for kind in x11 plain; do
    case_root="$output/$kind"
    package="$case_root/pkg"
    mkdir -m 700 -p "$package/app" "$package/src" "$package/include" \
        "$package/tests" "$case_root/keys"
    cp "$fixture/platform_${kind}_main.c" "$package/app/main.c"
    cp "$fixture/platform_marker.c" "$package/src/marker.c"
    cp "$fixture/platform_marker.h" "$package/include/marker.h"
    cp "$fixture/platform_test_marker.c" "$package/tests/test_marker.c"
    cp "$root/LICENSE" "$package/LICENSE"
    cat > "$package/zcode-package.json" <<'EOF'
{
  "schema": 1,
  "name": "qualification/skycombat-platform-link",
  "semver": "0.1.0",
  "language": "c23",
  "license": "Apache-2.0",
  "include_dir": "include",
  "source_dir": "src",
  "dependencies": [],
  "programs": ["app/main.c"]
}
EOF
    cat > "$package/README.md" <<'EOF'
<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Platform link qualification

This package declares one C23 executable and one independent library test.
EOF
    if [[ $kind == x11 ]]; then
        cc -std=c23 -Wall -Wextra -Werror -pedantic \
            "$package/app/main.c" -lX11 -o "$case_root/local-x11"
    fi
    "$bin_dir/zclassic23-package-sign" --generate \
        "$case_root/keys/publisher.key" > "$case_root/publisher.pub"
    publisher_pubkey=$(cat "$case_root/publisher.pub")
    factory_rc=0
    "$bin_dir/package-factory" run --package "$package" \
        --publisher-key-file "$case_root/keys/publisher.key" \
        --publisher-pubkey "$publisher_pubkey" \
        --store-a "$case_root/store-a" --store-b "$case_root/store-b" \
        --report "$case_root/report.json" \
        --signer-seed-file "$case_root/keys/admission.seed" \
        --bin-dir "$bin_dir" --fast-cache "$case_root/cache" \
        > "$case_root/factory.log" 2>&1 || factory_rc=$?
    [[ -f $case_root/report.json ]] || {
        printf '%s: missing factory report\n' "$kind" >&2
        exit 1
    }
    if [[ $kind == x11 ]]; then
        [[ $factory_rc != 0 ]] || exit 1
        [[ $("$bin_dir/jsonq" get ok < "$case_root/report.json") == false ]] || exit 1
        grep -q 'BUILD_NOT_INSTALLABLE: verdict build-fail' \
            "$case_root/factory.log" || exit 1
    else
        [[ $factory_rc == 0 ]] || exit 1
        [[ $("$bin_dir/jsonq" get ok < "$case_root/report.json") == true ]] || exit 1
        [[ $("$bin_dir/jsonq" get stores.a.reproduced \
            < "$case_root/report.json") == true ]] || exit 1
        [[ $("$bin_dir/jsonq" get stores.b.reproduced \
            < "$case_root/report.json") == true ]] || exit 1
    fi
    printf '%s factory_rc=%s package_root=%s recipe_root=%s report_sha256=%s\n' \
        "$kind" "$factory_rc" \
        "$("$bin_dir/jsonq" get package.package_root < "$case_root/report.json")" \
        "$("$bin_dir/jsonq" get package.recipe_root < "$case_root/report.json")" \
        "$(sha256sum "$case_root/report.json" | cut -d' ' -f1)"
done

plain_recipe=$("$bin_dir/jsonq" get package.recipe_root \
    < "$output/plain/report.json")
x11_recipe=$("$bin_dir/jsonq" get package.recipe_root \
    < "$output/x11/report.json")
[[ $plain_recipe == "$x11_recipe" ]] || {
    printf 'recipe roots differ across controls\n' >&2
    exit 1
}
