#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Run evolving C23 source through the real two-store package factory.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 || ! $2 =~ ^([1-9]|[1-9][0-9]|100)$ ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR REVISIONS(1..100) [BIN_DIR]\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
bin_dir=$(realpath "${3:-$root/build/bin}")
output=$(realpath -m "$1")
revisions=$2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output/bin"
cp "$bin_dir/package-factory" "$output/bin/package-factory"
for binary in zclassic23 zclassic23-package-sign zclassic23-package-verify jsonq; do
    cp "$bin_dir/$binary" "$output/bin/$binary"
done
sha256sum "$output/bin/"* > "$output/executables.sha256"
sha256sum "$root/tools/dev/factory-evolving-fixture.sh" \
    "$root/tools/dev/factory-evolving-qualification.sh" > "$output/harness.sha256"
git -C "$root" rev-parse HEAD > "$output/checkout-commit"
git -C "$root" status --short > "$output/checkout-status"
date --iso-8601=seconds > "$output/local-time"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"
"$output/bin/zclassic23-package-sign" --generate "$output/publisher.key" > "$output/publisher.pub"
pubkey=$(cat "$output/publisher.pub")
printf 'case\trevision\tmode\tsource_sha256\tpackage_root\trecipe_root\treport_sha256\treceipt_a_quick\treceipt_a_standard\tfactory_ok\tbuildable\tpreviewed\ttested\tverified\taccepted\twall_s\tuser_s\tsystem_s\ttest_exit\n' > "$output/ledger.tsv"

run_case()
{
    local label=$1 revision=$2 mode=$3
    local case_dir="$output/$label" package="$output/$label/pkg"
    mkdir -p "$case_dir"
    cp -a "$root/tests/harness/fixtures/zcode/tiny-lines" "$package"
    bash "$root/tools/dev/factory-evolving-fixture.sh" "$package" "$revision" "$mode" \
        > "$case_dir/generator.log"
    local source_sha
    source_sha=$(sha256sum "$package/src/history.c" | cut -d' ' -f1)
    local report="$case_dir/report.json"
    local factory_exit=0
    { TIMEFORMAT='%R %U %S'; time \
        "$output/bin/package-factory" run --package "$package" \
        --publisher-key-file "$output/publisher.key" --publisher-pubkey "$pubkey" \
        --store-a "$case_dir/store-a" --store-b "$case_dir/store-b" \
        --report "$report" --signer-seed-file "$output/admission.seed" \
        --bin-dir "$output/bin" --fast-cache "$output/cache" \
        > "$case_dir/factory.log" 2>&1; } 2> "$case_dir/factory.time" || factory_exit=$?
    local factory_ok=0 package_root=unavailable recipe_root=unavailable
    local receipt_a_quick=unavailable receipt_a_standard=unavailable
    if [[ -f $report ]]; then
        package_root=$("$output/bin/jsonq" get package.package_root < "$report")
        recipe_root=$("$output/bin/jsonq" get package.recipe_root < "$report")
        receipt_a_quick=$("$output/bin/jsonq" get stores.a.receipt_quick < "$report")
        receipt_a_standard=$("$output/bin/jsonq" get stores.a.receipt_standard < "$report")
        if [[ $factory_exit == 0 && $("$output/bin/jsonq" get ok < "$report") == true ]]; then
            factory_ok=1
        fi
    fi
    local buildable=0 previewed=0 tested=0 verified=0 test_exit=0
    if cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
        "$package/src/history.c" "$package/src/tiny_lines.c" \
        "$package/tests/test_history.c" "$package/tests/test_tiny_lines.c" \
        -o "$case_dir/test-package" > "$case_dir/test-build.log" 2>&1; then
        buildable=1
        previewed=1
        "$case_dir/test-package" > "$case_dir/test.log" 2>&1 || test_exit=$?
        tested=1
        if [[ $test_exit == 0 && $factory_ok == 1 ]]; then verified=1; fi
    fi
    local report_sha=unavailable
    if [[ -f $report ]]; then report_sha=$(sha256sum "$report" | cut -d' ' -f1); fi
    read -r wall user system < "$case_dir/factory.time"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t0\t%s\t%s\t%s\t%s\n' \
        "$label" "$revision" "$mode" "$source_sha" "$package_root" \
        "$recipe_root" "$report_sha" "$receipt_a_quick" \
        "$receipt_a_standard" "$factory_ok" "$buildable" "$previewed" \
        "$tested" "$verified" "$wall" "$user" "$system" "$test_exit" \
        >> "$output/ledger.tsv"
}

for ((revision=1; revision<=revisions; revision++)); do
    run_case "revision-$revision" "$revision" normal
done
if ((revisions >= 2)); then run_case wrong-prefix-2 2 wrong; fi
sha256sum -c "$output/executables.sha256" > "$output/executables-verified"
cat "$output/ledger.tsv"
printf 'evidence=%s\n' "$output"
