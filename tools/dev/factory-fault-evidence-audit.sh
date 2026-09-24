#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Bind each frozen fault verdict to the package and report bytes it evaluated.
set -euo pipefail

if [[ $# != 3 ]]; then
    printf 'usage: %s QUALIFICATION_EVIDENCE FAULT_EVIDENCE NEW_OUTPUT_DIR\n' "$0" >&2
    exit 2
fi
qualification=$(realpath "$1")
faults=$(realpath "$2")
output=$(realpath -m "$3")
[[ -f $qualification/ledger.tsv && -f $faults/ledger.tsv ]] || exit 2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
root=$(cd "$(dirname "$0")/../.." && pwd -P)
sha256sum "$qualification/ledger.tsv" "$faults/ledger.tsv" \
    "$root/tools/dev/factory-counterexamples.sh" "$0" > "$output/inputs.sha256"

package_manifest_sha()
{
    local package=$1
    [[ -d $package ]] || return 1
    [[ -z $(find "$package" -type l -print -quit) ]] || return 1
    (
        cd "$package"
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    ) | sha256sum | cut -d' ' -f1
}

file_sha_or_unavailable()
{
    if [[ -f $1 ]]; then
        sha256sum "$1" | cut -d' ' -f1
    else
        printf 'unavailable\n'
    fi
}

printf 'mode\tsource_manifest_sha256\tevaluated_report_sha256\tsecondary_report_sha256\tverdict_log_sha256\tverdict\n' \
    > "$output/matrix.tsv"
for mode in wrong interface stale contradictory partial dependency worker \
            publisher duplicate revoked resource; do
    case_dir="$faults/$mode"
    log="$faults/$mode.log"
    report="$case_dir/report.json"
    secondary="$case_dir/absent"
    package="$qualification/revision-2/pkg"
    verdict=refused
    case $mode in
        wrong) package="$qualification/wrong-prefix-2/pkg" ;;
        interface) package="$case_dir/pkg"; verdict=interface_break ;;
        stale) package="$qualification/revision-3/pkg" ;;
        contradictory) report="$case_dir/altered.json" ;;
        dependency) package="$case_dir/pkg" ;;
        worker|publisher) secondary="$case_dir/recovery.json" ;;
        duplicate) secondary="$case_dir/duplicate.json"; verdict=duplicate_work ;;
    esac
    [[ -f $log ]] || { printf 'missing verdict log: %s\n' "$mode" >&2; exit 1; }
    grep -q "counterexample=$mode " "$log" || {
        printf 'missing verdict: %s\n' "$mode" >&2
        exit 1
    }
    source_sha=$(package_manifest_sha "$package")
    report_sha=$(file_sha_or_unavailable "$report")
    secondary_sha=$(file_sha_or_unavailable "$secondary")
    log_sha=$(file_sha_or_unavailable "$log")
    declared=$(awk -F '\t' -v name="$mode" '$1 == name {print; found = 1}
        END {if (!found) exit 1}' "$faults/ledger.tsv")
    IFS=$'\t' read -r declared_mode declared_exit declared_wall \
        declared_log declared_report declared_recovery <<< "$declared"
    if [[ $declared_mode != "$mode" || ! $declared_wall =~ ^[0-9]+([.][0-9]+)?$ ||
          $declared_exit != 0 || $declared_log != "$log_sha" ||
          $declared_report != "$report_sha" ]]; then
        printf 'ledger binding mismatch: %s\n' "$mode" >&2
        exit 1
    fi
    if [[ -n ${declared_recovery:-} && $declared_recovery != "$(file_sha_or_unavailable "$case_dir/recovery.json")" ]]; then
        printf 'recovery binding mismatch: %s\n' "$mode" >&2
        exit 1
    fi
    stated_sha=$(sed -n 's/.*report_sha256=\([0-9a-f]\{64\}\).*/\1/p' "$log" | tail -n 1)
    if [[ -n $stated_sha && $report_sha != "$stated_sha" ]]; then
        printf 'report binding mismatch: %s\n' "$mode" >&2
        exit 1
    fi
    if [[ $mode == publisher && $report_sha != unavailable ]]; then
        printf 'publisher death unexpectedly produced a report\n' >&2
        exit 1
    fi
    if [[ $mode == duplicate ]]; then
        [[ $report_sha != unavailable && $secondary_sha != unavailable ]] || exit 1
        first=$("$qualification/bin/jsonq" get package.package_root < "$report")
        second=$("$qualification/bin/jsonq" get package.package_root < "$secondary")
        [[ $first == "$second" ]] || exit 1
    fi
    if [[ $mode == worker || $mode == publisher ]]; then
        [[ $secondary_sha != unavailable ]] || exit 1
        [[ $("$qualification/bin/jsonq" get ok < "$secondary") == true ]] || exit 1
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mode" "$source_sha" "$report_sha" "$secondary_sha" "$log_sha" "$verdict" \
        >> "$output/matrix.tsv"
done
sha256sum "$output/matrix.tsv" "$output/inputs.sha256" > "$output/outputs.sha256"
cat "$output/matrix.tsv"
