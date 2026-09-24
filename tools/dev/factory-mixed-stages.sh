#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Attribute real factory wall time to the two-store commit and proof steps.
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'usage: %s CORPUS_DIR NEW_STAGE_LEDGER\n' "$0" >&2
    exit 2
fi
corpus=$(realpath "$1")
output=$(realpath -m "$2")
[[ -f $corpus/ledger.tsv && -x $corpus/bin/jsonq && ! -e $output ]] || exit 2
jsonq="$corpus/bin/jsonq"

step_ms()
{
    local report=$1 index=$2 expected=$3
    local name
    name=$("$jsonq" get "steps[$index].name" < "$report")
    [[ $name == "$expected" ]] || {
        printf 'step mismatch: expected %s, found %s\n' "$expected" "$name" >&2
        return 1
    }
    "$jsonq" get "steps[$index].ms" < "$report"
}

printf 'revision\treport_sha256\tfactory_wall_ms\tadd_commit_a_ms\treproduce_a_ms\tadd_commit_b_ms\treproduce_b_ms\tfour_steps_ms\n' \
    > "$output"
for ((revision=1; revision<=100; revision++)); do
    report="$corpus/revision-$revision/report.json"
    [[ -f $report ]] || exit 1
    wall_ms=$(awk -F '\t' -v label="revision-$revision" \
        '$1==label {printf "%.0f", $16 * 1000}' "$corpus/ledger.tsv")
    [[ -n $wall_ms ]] || exit 1
    add_a=$(step_ms "$report" 7 add_commit_a)
    reproduce_a=$(step_ms "$report" 8 reproduce_build_a)
    add_b=$(step_ms "$report" 14 add_commit_b)
    reproduce_b=$(step_ms "$report" 15 reproduce_build_b)
    printf '%u\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$revision" "$(sha256sum "$report" | cut -d' ' -f1)" \
        "$wall_ms" "$add_a" "$reproduce_a" "$add_b" "$reproduce_b" \
        "$((add_a + reproduce_a + add_b + reproduce_b))" >> "$output"
done
awk -F '\t' 'NR>1 {wall+=$3; four+=$8} END {
    printf "factory_wall_ms=%.0f four_steps_ms=%.0f share=%.1f%%\n",
           wall, four, four*100/wall
}' "$output"
