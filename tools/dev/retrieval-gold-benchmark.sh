#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Benchmark every reviewed retrieval task at its exact clean parent epoch.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
corpus="$repo_root/docs/work/RETRIEVAL_GOLD_CORPUS.jsonl"
jsonq="$repo_root/build/bin/jsonq"
z23_dev="$repo_root/build/bin/z23-dev"
evaluator="$repo_root/build/bin/retrieval-eval"

fail() { printf 'retrieval-gold-benchmark: FAIL — %s\n' "$*" >&2; return 1; }

[[ $# -eq 1 ]] || {
    printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
}
output=$1
[[ ! -e $output ]] || fail "output already exists: $output" || exit 1
mkdir -p -- "$output"
output=$(cd "$output" && pwd -P)
for tool in "$jsonq" "$z23_dev" "$evaluator"; do
    [[ -x $tool ]] || fail "required executable is unavailable: $tool" || exit 1
done

fixtures=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-gold.XXXXXX")
trap 'rm -r -- "$fixtures"' EXIT HUP INT TERM
results="$output/results.jsonl"
batch="$output/evaluation.batch"
timings="$output/timings.tsv"
task_count=$(sed -n '1p' "$corpus" | "$jsonq" get task_count)
printf 'zcl.retrieval_eval_batch.v2 tasks=%s\n' "$task_count" >"$batch"
printf 'task_id\telapsed_us\tliteral_files\tbm25_files\tliteral_context_bytes_at_5\tbm25_context_bytes_at_5\n' >"$timings"

field() { printf '%s\n' "$1" | "$jsonq" get "$2"; }
raw() { printf '%s\n' "$1" | "$jsonq" raw "$2"; }
emit_arm() {
    local result=$1 arm=$2 count complete i path bytes displayed
    count=$(field "$result" "data.$arm.ranked_files")
    displayed=$(field "$result" "data.$arm.displayed_files")
    [[ $(field "$result" "data.$arm.display_offset") = 0 &&
       $displayed = $(printf '%s\n' "$result" | "$jsonq" count "data.$arm.ranking") ]] ||
        fail "$arm first page is incomplete" || return 1
    if [[ $(field "$result" "data.$arm.ranking_complete") = true &&
          $displayed = "$count" ]]; then complete=1; else complete=0; fi
    printf '%s observed %s %s\n' "$arm" "$complete" "$displayed" >>"$batch"
    for ((i = 0; i < displayed; i++)); do
        path=$(field "$result" "data.$arm.ranking[$i].path")
        bytes=$(field "$result" "data.$arm.ranking[$i].context_bytes")
        printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$batch"
    done
}

task_index=0
while IFS= read -r row || [[ -n $row ]]; do
    [[ $(field "$row" record) = task ]] || continue
    task_index=$((task_index + 1))
    id=$(field "$row" id)
    parent=$(field "$row" parent_commit)
    root=$(field "$row" expected_vcs_root)
    query=$(field "$row" query)
    relevant_count=$(printf '%s\n' "$row" | "$jsonq" count relevant_paths)
    fixture="$fixtures/$id"
    mkdir -- "$fixture"
    git -C "$repo_root" archive "$parent" | tar -x -C "$fixture"
    input=$(printf '{"workspace":"%s","expected_vcs_root":"%s","task_id":%s,"query":%s}' \
        "$fixture" "$root" "$(raw "$row" id)" "$(raw "$row" query)")
    result=$("$z23_dev" dev retrieval benchmark --input="$input") ||
        fail "native benchmark failed for $id" || exit 1
    [[ $(field "$result" ok) = true &&
       $(field "$result" data.task_id) = "$id" &&
       $(field "$result" data.query) = "$query" &&
       $(field "$result" data.observed_vcs_root_pre) = "$root" &&
       $(field "$result" data.observed_vcs_root_post) = "$root" &&
       $(field "$result" data.rank_offset) = 0 ]] ||
        fail "native receipt binding failed for $id" || exit 1
    printf '{"corpus":%s,"result":%s}\n' "$row" "$result" >>"$results"
    printf 'task %s %s\nquery %s\n' "$id" "$relevant_count" "$query" >>"$batch"
    for ((i = 0; i < relevant_count; i++)); do
        printf 'relevant %s\n' "$(field "$row" "relevant_paths[$i]")" >>"$batch"
    done
    emit_arm "$result" literal
    emit_arm "$result" bm25
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$(field "$result" elapsed_us)" \
        "$(field "$result" data.literal.ranked_files)" \
        "$(field "$result" data.bm25.ranked_files)" \
        "$(field "$result" data.literal.context_bytes_at_5)" \
        "$(field "$result" data.bm25.context_bytes_at_5)" >>"$timings"
    printf 'retrieval-gold-benchmark: task=%d/%s id=%s elapsed_us=%s\n' \
        "$task_index" "$task_count" "$id" "$(field "$result" elapsed_us)" >&2
done <"$corpus"
[[ $task_index = "$task_count" ]] ||
    fail "corpus task count changed during run" || exit 1
printf 'end\n' >>"$batch"
"$evaluator" <"$batch" >"$output/aggregate.json"
printf 'retrieval-gold-benchmark: PASS tasks=%s output=%s\n' \
    "$task_count" "$output" >&2
cat "$output/aggregate.json"
