#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Run all bounded factory faults and audit their actual evaluated inputs.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s QUALIFICATION_EVIDENCE NEW_OUTPUT_DIR\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
qualification=$(realpath "$1")
output=$(realpath -m "$2")
[[ -f $qualification/ledger.tsv && -d $qualification/bin ]] || exit 2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -n 1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"
sha256sum "$qualification/ledger.tsv" \
    "$root/tools/dev/factory-counterexamples.sh" "$0" \
    > "$output/inputs.sha256"
printf 'mode\tcommand_exit\twall_s\tlog_sha256\tevaluated_report_sha256\trecovery_report_sha256\n' \
    > "$output/ledger.tsv"

file_sha_or_unavailable()
{
    if [[ -f $1 ]]; then
        sha256sum "$1" | cut -d' ' -f1
    else
        printf 'unavailable\n'
    fi
}

for mode in wrong interface stale contradictory partial dependency worker \
            publisher duplicate revoked resource; do
    case_dir="$output/$mode"
    rc=0
    { TIMEFORMAT='%R %U %S'; time \
        "$root/tools/dev/factory-counterexamples.sh" "$qualification" "$mode" \
        "$case_dir" > "$output/$mode.log" 2>&1; } \
        2> "$output/$mode.time" || rc=$?
    [[ $rc == 0 ]] || {
        printf 'fault script failed: %s exit=%s\n' "$mode" "$rc" >&2
        exit 1
    }
    report="$case_dir/report.json"
    [[ $mode == contradictory ]] && report="$case_dir/altered.json"
    if [[ $mode == worker || $mode == publisher ]]; then
        pubkey=$(cat "$qualification/publisher.pub")
        "$qualification/bin/package-factory" run \
            --package "$qualification/revision-2/pkg" \
            --publisher-key-file "$qualification/publisher.key" \
            --publisher-pubkey "$pubkey" \
            --store-a "$case_dir/store-a" --store-b "$case_dir/store-b" \
            --report "$case_dir/recovery.json" \
            --signer-seed-file "$case_dir/admission.seed" \
            --bin-dir "$qualification/bin" --fast-cache "$case_dir/cache" \
            > "$case_dir/recovery.log" 2>&1
        [[ $("$qualification/bin/jsonq" get ok < "$case_dir/recovery.json") == true ]]
        expected=$("$qualification/bin/jsonq" get package.package_root \
            < "$qualification/revision-2/report.json")
        actual=$("$qualification/bin/jsonq" get package.package_root \
            < "$case_dir/recovery.json")
        [[ $expected == "$actual" ]]
    fi
    read -r wall _ < "$output/$mode.time"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mode" "$rc" "$wall" \
        "$(file_sha_or_unavailable "$output/$mode.log")" \
        "$(file_sha_or_unavailable "$report")" \
        "$(file_sha_or_unavailable "$case_dir/recovery.json")" \
        >> "$output/ledger.tsv"
done
"$root/tools/dev/factory-fault-evidence-audit.sh" "$qualification" \
    "$output" "$output/audit" > "$output/audit.stdout"
sha256sum "$output/ledger.tsv" "$output/audit/matrix.tsv" \
    > "$output/outputs.sha256"
cat "$output/ledger.tsv"
