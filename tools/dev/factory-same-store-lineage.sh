#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Qualify cumulative source admission under one publisher and two fixed stores.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s QUALIFICATION_EVIDENCE NEW_OUTPUT_DIR\n' "$0" >&2
    exit 2
fi
qualification=$(realpath "$1")
output=$(realpath -m "$2")
[[ -f $qualification/revision-1/report.json &&
   -f $qualification/revision-2/report.json ]] || exit 2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -n 1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"
pubkey=$(cat "$qualification/publisher.pub")

package_files()
{
    (
        builtin cd "$1"
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    )
}
package_files "$qualification/revision-1/pkg" > "$output/revision-1.files.sha256"
package_files "$qualification/revision-2/pkg" > "$output/revision-2.files.sha256"
sha256sum "$qualification/bin/package-factory" \
    "$qualification/publisher.pub" \
    "$qualification/revision-1/report.json" \
    "$qualification/revision-2/report.json" "$0" \
    > "$output/inputs.sha256"

run_case()
{
    local label=$1 revision=$2 sequence=$3 rc=0
    { TIMEFORMAT='%R %U %S'; time \
        "$qualification/bin/package-factory" run \
        --package "$qualification/revision-$revision/pkg" \
        --publisher-key-file "$qualification/publisher.key" \
        --publisher-pubkey "$pubkey" --publisher-sequence "$sequence" \
        --store-a "$output/store-a" --store-b "$output/store-b" \
        --report "$output/$label.json" \
        --signer-seed-file "$output/admission.seed" \
        --bin-dir "$qualification/bin" --fast-cache "$output/cache" \
        > "$output/$label.log" 2>&1; } \
        2> "$output/$label.time" || rc=$?
    printf '%s\n' "$rc" > "$output/$label.exit"
}

run_case first 1 1
[[ $(cat "$output/first.exit") == 0 ]]
[[ $("$qualification/bin/jsonq" get ok < "$output/first.json") == true ]]
first_root=$("$qualification/bin/jsonq" get package.package_root < "$output/first.json")
expected=$("$qualification/bin/jsonq" get package.package_root \
    < "$qualification/revision-1/report.json")
[[ $first_root == "$expected" ]]
for store in a b; do
    installed="$output/store-$store/zcode/installed/$first_root"
    [[ -d $installed ]]
    package_files "$installed" > "$output/store-$store.before"
done

run_case same-sequence 2 1
[[ $(cat "$output/same-sequence.exit") != 0 ]]
grep -q 'publisher-equivocation' "$output/same-sequence.log"
for store in a b; do
    package_files "$output/store-$store/zcode/installed/$first_root" \
        > "$output/store-$store.after-same-sequence"
    cmp "$output/store-$store.before" \
        "$output/store-$store.after-same-sequence"
done

run_case next-sequence 2 2
[[ $(cat "$output/next-sequence.exit") != 0 ]]
grep -q 'PUBLISH_FREQUENCY_LIMIT' "$output/next-sequence.log"
for store in a b; do
    package_files "$output/store-$store/zcode/installed/$first_root" \
        > "$output/store-$store.after-next-sequence"
    cmp "$output/store-$store.before" \
        "$output/store-$store.after-next-sequence"
done

printf 'case\trevision\tpublisher_sequence\tfactory_exit\twall_s\treport_sha256\tlog_sha256\n' \
    > "$output/ledger.tsv"
for label in first same-sequence next-sequence; do
    case $label in
        first) revision=1; sequence=1 ;;
        same-sequence) revision=2; sequence=1 ;;
        next-sequence) revision=2; sequence=2 ;;
    esac
    read -r wall _ < "$output/$label.time"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$revision" "$sequence" "$(cat "$output/$label.exit")" \
        "$wall" "$(sha256sum "$output/$label.json" | cut -d' ' -f1)" \
        "$(sha256sum "$output/$label.log" | cut -d' ' -f1)" \
        >> "$output/ledger.tsv"
done
sha256sum "$output/ledger.tsv" "$output/store-a.before" \
    "$output/store-b.before" "$output/store-a.after-next-sequence" \
    "$output/store-b.after-next-sequence" > "$output/outputs.sha256"
cat "$output/ledger.tsv"
