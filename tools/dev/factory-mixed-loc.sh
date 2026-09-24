#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Count source changes separately from generated tests in a completed corpus.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s CORPUS_DIR NEW_LOC_LEDGER\n' "$0" >&2
    exit 2
fi
corpus=$(realpath "$1")
output=$(realpath -m "$2")
[[ -f $corpus/ledger.tsv && ! -e $output ]] || exit 2
root=$(cd "$(dirname "$0")/../.." && pwd -P)

line_delta()
{
    local old=$1 new=$2
    if [[ ! -f $old ]]; then
        if [[ -f $new ]]; then
            printf '%s 0\n' "$(wc -l < "$new")"
        else
            printf '0 0\n'
        fi
    elif [[ ! -f $new ]]; then
        printf '0 %s\n' "$(wc -l < "$old")"
    else
        { git diff --no-index --numstat -- "$old" "$new" || true; } |
            awk 'BEGIN {a=0; d=0} {a+=$1; d+=$2} END {print a, d}'
    fi
}

printf 'revision\tclass\tsource_sha256\tpackage_root\tadded\tremoved\tgenerated_loc\tbuildable_loc\tpreviewed_loc\ttested_loc\tverified_loc\tdev_accepted_loc\tfully_accepted_loc\n' \
    > "$output"
for ((revision=1; revision<=100; revision++)); do
    package="$corpus/revision-$revision/pkg"
    if ((revision == 1)); then
        previous="$root/tests/harness/fixtures/zcode/tiny-lines"
    else
        previous="$corpus/revision-$((revision - 1))/pkg"
    fi
    [[ -f $package/src/history.c && -f $corpus/revision-$revision/report.json ]] || exit 1
    read -r recorded_sha package_root buildable previewed tested verified full dev < <(
        awk -F '\t' -v label="revision-$revision" \
            '$1==label {print $4, $5, $11, $12, $13, $14, $15, $20}' \
            "$corpus/ledger.tsv")
    [[ -n $recorded_sha && $recorded_sha == \
       "$(sha256sum "$package/src/history.c" | cut -d' ' -f1)" ]] || exit 1
    local_added=0
    local_removed=0
    for path in include/history.h src/history.c examples/history_cli.c; do
        read -r added removed < <(line_delta "$previous/$path" "$package/$path")
        local_added=$((local_added + added))
        local_removed=$((local_removed + removed))
    done
    category=data
    case $revision in
        1) category=scaffold_data ;;
        25) category=range_feature_data ;;
        50) category=range_refactor_data ;;
        75) category=terminal_ui_data ;;
        90) category=input_fix_data ;;
    esac
    printf '%u\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n' \
        "$revision" "$category" "$recorded_sha" "$package_root" \
        "$local_added" "$local_removed" "$local_added" \
        "$((local_added * buildable))" "$((local_added * previewed))" \
        "$((local_added * tested))" "$((local_added * verified))" \
        "$((local_added * dev))" "$((local_added * full))" >> "$output"
done
cat "$output"
