#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Run the reviewed retrieval corpus against each task's exact parent epoch.

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
corpus=${ZCL_RETRIEVAL_GOLD_CORPUS:-$repo_root/docs/work/RETRIEVAL_GOLD_CORPUS.jsonl}
corpus_check=${ZCL_RETRIEVAL_GOLD_CHECK:-$repo_root/tools/dev/retrieval-gold-corpus-check.sh}
jsonq=${ZCL_JSONQ:-$repo_root/build/bin/jsonq}
rank_bin=${ZCL_RETRIEVAL_BENCH_Z23:-$repo_root/build/bin/z23-dev}
capture_bin=${ZCL_RETRIEVAL_CAPTURE_Z23:-$repo_root/build/bin/z23}
evaluator=${ZCL_RETRIEVAL_EVAL:-$repo_root/build/bin/retrieval-eval}
sha3=${ZCL_AGENT_SHA3:-$repo_root/build/bin/agent_sha3}
command_timeout=${ZCL_RETRIEVAL_BENCH_TIMEOUT_SECONDS:-300}
keep=${ZCL_RETRIEVAL_BENCH_KEEP:-0}
mode=${1:---run-local}
publishable=false
readonly eval_arm_keys='recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly eval_result_keys="schema,tasks_evaluated,binding_kind,context_cost_kind,token_basis,literal,$eval_arm_keys,bm25,$eval_arm_keys"

. "$repo_root/tools/dev/dev_lib.sh" # json_escape

fail() {
    printf 'retrieval-gold-benchmark: FAIL — %s\n' "$*" >&2
    exit 1
}

[[ $# -le 1 ]] || {
    printf 'usage: %s [--run-local|--run]\n' "$0" >&2
    exit 64
}
case "$mode" in
    --run) publishable=true ;;
    --run-local) ;;
    *) printf 'usage: %s [--run-local|--run]\n' "$0" >&2; exit 64 ;;
esac
for executable in "$jsonq" "$rank_bin" "$capture_bin" "$evaluator" "$sha3" \
    "$corpus_check"; do
    [[ -x $executable ]] || fail "required executable is unavailable: $executable"
done
[[ $command_timeout =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"
case "$keep" in 0|1) ;; *) fail "ZCL_RETRIEVAL_BENCH_KEEP must be 0 or 1" ;; esac

field() {
    local document=$1 path=$2 value
    value=$(printf '%s\n' "$document" | "$jsonq" get "$path") ||
        fail "missing or malformed JSON field: $path"
    printf '%s' "$value"
}

raw_field() {
    local document=$1 path=$2 value
    value=$(printf '%s\n' "$document" | "$jsonq" raw "$path") ||
        fail "missing or malformed JSON value: $path"
    printf '%s' "$value"
}

array_count() {
    local document=$1 path=$2 value
    value=$(printf '%s\n' "$document" | "$jsonq" count "$path") ||
        fail "missing or malformed JSON array: $path"
    [[ $value =~ ^[0-9]+$ ]] || fail "non-integer array count: $path"
    printf '%s' "$value"
}

field_type() {
    local document=$1 path=$2 value
    value=$(printf '%s\n' "$document" | "$jsonq" type "$path") ||
        fail "missing or malformed JSON type: $path"
    printf '%s' "$value"
}

uint_field() {
    local document=$1 path=$2 maximum=$3 value
    [[ $(field_type "$document" "$path") = number ]] ||
        fail "field is not a JSON number: $path"
    value=$(field "$document" "$path")
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || fail "non-canonical integer: $path"
    if ((${#value} > ${#maximum})) ||
       { ((${#value} == ${#maximum})) && [[ $value > $maximum ]]; }; then
        fail "integer exceeds bound $maximum: $path"
    fi
    printf '%s' "$value"
}

bool_field() {
    local document=$1 path=$2 value
    [[ $(field_type "$document" "$path") = bool ]] ||
        fail "field is not a JSON boolean: $path"
    value=$(field "$document" "$path")
    [[ $value = true || $value = false ]] || fail "invalid boolean: $path"
    printf '%s' "$value"
}

root_field() {
    local document=$1 path=$2 value
    [[ $(field_type "$document" "$path") = string ]] ||
        fail "field is not a JSON string: $path"
    value=$(field "$document" "$path")
    [[ $value =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA3 root: $path"
    printf '%s' "$value"
}

hash_file() {
    local path=$1 output root
    output=$("$sha3" "$path") || fail "could not hash file: $path"
    root=${output%% *}
    [[ $root =~ ^[0-9a-f]{64}$ ]] || fail "malformed file SHA3: $path"
    printf '%s' "$root"
}

hash_text() {
    local value=$1 root
    root=$(printf '%s' "$value" | "$sha3") || fail "could not hash text"
    [[ $root =~ ^[0-9a-f]{64}$ ]] || fail "malformed text SHA3"
    printf '%s' "$root"
}

validate_envelope() {
    local document=$1 command=$2 data_schema=$3 expected_budget=$4
    local elapsed_us elapsed_ms budget_ms exceeded should_exceed
    [[ $(field "$document" schema) = zcl.result.v1 &&
       $(field "$document" command) = "$command" &&
       $(bool_field "$document" ok) = true &&
       $(field "$document" status) = passed &&
       $(field "$document" data_schema) = "$data_schema" &&
       $(field_type "$document" data) = object &&
       $(field_type "$document" next) = array ]] ||
        fail "invalid command envelope for $command"
    elapsed_us=$(uint_field "$document" elapsed_us 9223372036854775807)
    elapsed_ms=$(uint_field "$document" elapsed_ms 9223372036854775807)
    budget_ms=$(uint_field "$document" budget_ms 9223372036854775807)
    exceeded=$(bool_field "$document" budget_exceeded)
    [[ $budget_ms -eq $expected_budget && $elapsed_ms -eq $((elapsed_us / 1000)) ]] ||
        fail "invalid timing envelope for $command"
    should_exceed=false
    ((elapsed_us > budget_ms * 1000)) && should_exceed=true
    [[ $exceeded = "$should_exceed" ]] ||
        fail "budget_exceeded disagrees with elapsed time for $command"
}

keys_exact() {
    local document=$1 path=$2 expected=$3 observed
    observed=$(printf '%s\n' "$document" | "$jsonq" keys "$path" | paste -sd, -) ||
        fail "cannot enumerate object keys: $path"
    [[ $observed = "$expected" ]] || fail "unexpected object shape: $path"
}

validate_metric() {
    local document=$1 path=$2 available
    keys_exact "$document" "$path" available,basis_points
    available=$(bool_field "$document" "$path.available")
    if [[ $available = true ]]; then
        uint_field "$document" "$path.basis_points" 10000 >/dev/null
    else
        [[ $(field_type "$document" "$path.basis_points") = null ]] ||
            fail "unavailable metric has a value: $path"
    fi
}

validate_eval_arm() {
    local document=$1 arm=$2 expected_files=$3 expected_context=$4
    local actual_files actual_context actual_tokens r5_available r20_available r5 r20
    keys_exact "$document" "$arm" "$eval_arm_keys"
    validate_metric "$document" "$arm.recall_at_5"
    validate_metric "$document" "$arm.recall_at_20"
    validate_metric "$document" "$arm.mrr"
    validate_metric "$document" "$arm.wrong_scope_at_5"
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = false ]] ||
        fail "$arm wrong-scope must remain unavailable"
    actual_files=$(uint_field "$document" "$arm.task_unique_file_selections_at_5" 9223372036854775807)
    actual_context=$(uint_field "$document" "$arm.projected_context_bytes_at_5" 9223372036854775807)
    actual_tokens=$(uint_field "$document" "$arm.approximate_tokens_at_5" 9223372036854775807)
    [[ $actual_files -eq $expected_files && $actual_context -eq $expected_context &&
       $actual_tokens -eq $(((expected_context + 3) / 4)) ]] ||
        fail "$arm evaluator cost totals do not rederive"
    r5_available=$(bool_field "$document" "$arm.recall_at_5.available")
    r20_available=$(bool_field "$document" "$arm.recall_at_20.available")
    if [[ $r5_available = true && $r20_available = true ]]; then
        r5=$(uint_field "$document" "$arm.recall_at_5.basis_points" 10000)
        r20=$(uint_field "$document" "$arm.recall_at_20.basis_points" 10000)
        ((r20 >= r5)) || fail "$arm Recall@20 is below Recall@5"
    fi
}

canonical_path() {
    [[ -n $1 && $1 != /* && $1 != ./* && $1 != */ && $1 != *//* &&
       $1 != *\\* && $1 =~ ^[A-Za-z0-9][A-Za-z0-9._/+@-]*$ &&
       ! $1 =~ (^|/)(\.|\.\.)($|/) ]]
}

tmp_base=$(cd "${TMPDIR:-/tmp}" && pwd -P) || fail "TMPDIR is unavailable"
run_root=$(mktemp -d "$tmp_base/z23-retrieval-gold.XXXXXX")
run_root=$(cd "$run_root" && pwd -P) || fail "cannot canonicalize scratch root"
workspace=''
workspace_registered=false

cleanup_workspace() {
    if [[ -n $workspace && $workspace_registered = true ]]; then
        case "$workspace" in
            "$run_root"/epoch)
                [[ -z $(git -C "$workspace" status --porcelain --untracked-files=all) ]] ||
                    return 1
                git -C "$repo_root" worktree remove -- "$workspace" \
                    >/dev/null 2>&1 || return 1 ;;
            *) return 1 ;;
        esac
    fi
    workspace=''
    workspace_registered=false
}

cleanup() {
    if ! cleanup_workspace; then
        printf 'retrieval-gold-benchmark: cleanup failed; artifacts preserved: %s\n' \
            "$run_root" >&2
        return 1
    fi
    if [[ $keep = 1 ]]; then
        printf 'retrieval-gold-benchmark: artifacts=%s\n' "$run_root" >&2
        return
    fi
    case "$run_root" in
        "$tmp_base"/z23-retrieval-gold.*) rm -r -- "$run_root" ;;
        *) return 1 ;;
    esac
}

on_exit() {
    local status=$?
    trap - EXIT HUP INT TERM
    cleanup || status=1
    exit "$status"
}
on_signal() { exit "$1"; }
trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

verify_checkout() {
    local expected=$1 observed
    observed=$(git -C "$workspace" rev-parse --verify HEAD) ||
        fail "cannot resolve epoch HEAD"
    [[ $observed = "$expected" ]] ||
        fail "epoch mismatch: expected=$expected observed=$observed"
    [[ -z $(git -C "$workspace" status --porcelain --untracked-files=all) ]] ||
        fail "epoch worktree is not clean"
}

prepare_checkout() {
    local parent=$1
    cleanup_workspace
    workspace="$run_root/epoch"
    git -C "$repo_root" worktree add --detach "$workspace" "$parent" \
        >/dev/null || fail "could not create exact epoch worktree"
    workspace_registered=true
    workspace=$(cd "$workspace" && pwd -P)
    [[ $workspace = "$run_root/epoch" ]] || fail "epoch path is not canonical"
    verify_checkout "$parent"
}

capture_root() {
    local input output root
    input=$(printf '{"workspace":"%s"}' "$(json_escape "$workspace")")
    output=$(printf '%s' "$input" | timeout "$command_timeout" \
        "$capture_bin" zcode workspace source capture --input=-) ||
        fail "ZVCS scratch capture failed"
    validate_envelope "$output" zcode.workspace.source.capture \
        zcl.zcode_source_capture.v1 750
    [[ $(bool_field "$output" data.accepted) = false &&
       $(bool_field "$output" data.git_required) = false &&
       $(bool_field "$output" data.source_executed) = false ]] ||
        fail "ZVCS capture crossed its unaccepted/non-executing boundary"
    root=$(root_field "$output" data.source_root)
    printf '%s' "$root"
}

set_invariant() {
    local name=$1 value=$2 variable="invariant_$1"
    if [[ ! -v $variable ]]; then
        printf -v "$variable" '%s' "$value"
    else
        [[ $value = "${!variable}" ]] || fail "page invariant changed: $name"
    fi
}

record_invariant() {
    local output=$1 name=$2 path=$3 kind=$4 value
    case "$kind" in
        uint) value=$(uint_field "$output" "$path" 9223372036854775807) || return 1 ;;
        bool) value=$(bool_field "$output" "$path") || return 1 ;;
        root) value=$(root_field "$output" "$path") || return 1 ;;
        string) value=$(field "$output" "$path") || return 1 ;;
        *) fail "unknown invariant kind: $kind" ;;
    esac
    set_invariant "$name" "$value"
}

append_arm_page() {
    local output=$1 arm=$2 offset=$3 page_limit=$4 target=$5
    local count declared expected i rank path bytes retained
    count=$(array_count "$output" "data.$arm.ranking")
    declared=$(uint_field "$output" "data.$arm.displayed_files" 20)
    [[ $declared -eq $count && $declared -le $page_limit ]] ||
        fail "$arm displayed-file count mismatch"
    [[ $(uint_field "$output" "data.$arm.display_offset" 127) -eq $offset ]] ||
        fail "$arm display offset mismatch"
    retained=$(uint_field "$output" "data.$arm.ranked_files" 128)
    expected=0
    ((retained > offset)) && expected=$((retained - offset))
    ((expected > page_limit)) && expected=$page_limit
    [[ $declared -eq $expected ]] || fail "$arm page does not match retained count"
    for ((i = 0; i < count; i++)); do
        rank=$(uint_field "$output" "data.$arm.ranking[$i].rank" 128)
        [[ $rank -eq $((offset + i + 1)) ]] ||
            fail "$arm rank discontinuity"
        path=$(field "$output" "data.$arm.ranking[$i].path")
        canonical_path "$path" || fail "$arm emitted non-canonical path: $path"
        bytes=$(uint_field "$output" "data.$arm.ranking[$i].context_bytes" 9223372036854775807)
        printf '%s\t%s\t%s\n' "$rank" "$bytes" "$path" >>"$target"
    done
}

check_rank_file() {
    local arm=$1 file=$2 expected_count=$3 expected_bytes=$4 complete=$5 expected_root=$6
    local observed_count observed_bytes observed_root complete_bit
    observed_count=$(wc -l <"$file"); observed_count=${observed_count//[[:space:]]/}
    [[ $observed_count -eq $expected_count ]] ||
        fail "$arm reconstructed $observed_count/$expected_count retained rows"
    awk -F '\t' 'BEGIN { ok=1 } $1 != NR || seen[$3]++ { ok=0 } END { exit !ok }' \
        "$file" || fail "$arm ranks are non-contiguous or duplicate a path"
    observed_bytes=$(awk -F '\t' '$1 <= 5 { sum += $2 } END { print sum + 0 }' "$file")
    [[ $observed_bytes -eq $expected_bytes ]] ||
        fail "$arm top-five context bytes do not rederive"
    [[ $complete = true ]] && complete_bit=1 || complete_bit=0
    observed_root=$("$evaluator" --rank-root "$complete_bit" <"$file") ||
        fail "$arm ranking-root verifier refused reconstructed ranks"
    [[ $observed_root = "$expected_root" ]] ||
        fail "$arm ranking root does not independently rederive"
}

membership_check() {
    local row=$1 eligibility=$2 count i path input room merkle room_found merkle_found kind tree_root
    count=$(array_count "$row" relevant_paths)
    for ((i = 0; i < count; i++)); do
        path=$(field "$row" "relevant_paths[$i]")
        input=$(printf '{"path":"%s"}' "$(json_escape "$path")")
        room=$(printf '%s' "$input" | env ZCL_DEV_SOURCE_ROOT="$workspace" \
            timeout "$command_timeout" "$rank_bin" code room --input=-) ||
            fail "code.room failed for $path"
        merkle=$(printf '%s' "$input" | env ZCL_DEV_SOURCE_ROOT="$workspace" \
            timeout "$command_timeout" "$rank_bin" code provenance merkle \
            --input=-) || fail "code.provenance.merkle failed for $path"
        validate_envelope "$room" code.room zcl.code_room.v1 250
        validate_envelope "$merkle" code.provenance.merkle zcl.code_merkle.v1 250
        [[ $(field "$room" data.path) = "$path" &&
           $(field "$merkle" data.path) = "$path" ]] ||
            fail "membership command returned a different path"
        room_found=$(bool_field "$room" data.found)
        merkle_found=$(bool_field "$merkle" data.found)
        tree_root=$(root_field "$merkle" data.tree_root) || return 1
        set_invariant membership_tree_root "$tree_root"
        if [[ $eligibility = c23_codeindex ]]; then
            [[ $room_found = true && $merkle_found = true ]] ||
                fail "eligible relevant path is absent from exact codeindex: $path"
            kind=$(field "$merkle" data.kind)
            [[ $kind = file ]] || fail "relevant merkle leaf is not a file: $path"
        else
            [[ $room_found = false && $merkle_found = false ]] ||
                fail "outside-index relevant path unexpectedly indexed: $path"
            [[ $(field "$merkle" data.kind) = absent ]] ||
                fail "outside-index path did not return an absent Merkle leaf: $path"
        fi
    done
}

emit_batch_task() {
    local row=$1 id=$2 literal_file=$3 literal_count=$4 literal_complete=$5
    local bm25_file=$6 bm25_count=$7 bm25_complete=$8 n i path rank bytes query
    n=$(array_count "$row" relevant_paths)
    printf 'task %s %s\n' "$id" "$n" >>"$batch"
    query=$(field "$row" query)
    [[ -n $query && ${#query} -le 768 && $query =~ ^[[:print:]]+$ ]] ||
        fail "task query is not one canonical line: $id"
    printf 'query %s\n' "$query" >>"$batch"
    for ((i = 0; i < n; i++)); do
        path=$(field "$row" "relevant_paths[$i]")
        printf 'relevant %s\n' "$path" >>"$batch"
    done
    [[ $literal_complete = true ]] && literal_complete=1 || literal_complete=0
    [[ $bm25_complete = true ]] && bm25_complete=1 || bm25_complete=0
    printf 'literal observed %s %s\n' "$literal_complete" "$literal_count" >>"$batch"
    while IFS=$'\t' read -r rank bytes path; do
        printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$batch"
    done <"$literal_file"
    printf 'bm25 observed %s %s\n' "$bm25_complete" "$bm25_count" >>"$batch"
    while IFS=$'\t' read -r rank bytes path; do
        printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$batch"
    done <"$bm25_file"
}

run_eligible_task() {
    local row=$1 id=$2 query=$3 expected_root=$4 task_dir=$5
    local literal_file="$task_dir/literal.tsv" bm25_file="$task_dir/bm25.tsv"
    local offset=0 pages=0 output input started ended wall_us span next has_more
    local literal_display bm25_display max_display elapsed_us budget_ms exceeded
    local page_limit max_count remaining expected_span expected_more page_file literal_take bm25_take
    local total_elapsed=0 total_wall=0 any_budget_exceeded=false
    local page0_elapsed_us page0_wall_us page0_budget_ms page0_budget_exceeded arm
    : >"$literal_file"; : >"$bm25_file"
    unset invariant_task_id invariant_query invariant_expected_root \
        invariant_pre_root invariant_post_root invariant_codeindex_root \
        invariant_corpus_files invariant_document_profile \
        invariant_literal_count invariant_literal_complete invariant_literal_root \
        invariant_literal_context invariant_literal_tokens invariant_bm25_count \
        invariant_bm25_complete invariant_bm25_root invariant_bm25_context \
        invariant_bm25_tokens invariant_membership_tree_root
    while :; do
        pages=$((pages + 1)); ((pages <= 128)) || fail "pagination cycle for $id"
        input=$(printf '{"workspace":"%s","expected_vcs_root":"%s","task_id":"%s","query":"%s","cursor":%s}' \
            "$(json_escape "$workspace")" "$expected_root" \
            "$(json_escape "$id")" "$(json_escape "$query")" "$offset")
        started=$(date +%s%N)
        output=$(printf '%s' "$input" | timeout "$command_timeout" \
            "$rank_bin" dev retrieval benchmark --input=-) ||
            fail "ranking command failed for $id at offset $offset"
        ended=$(date +%s%N); wall_us=$(((ended - started) / 1000))
        page_file=$(printf '%s/page-%03d.json' "$task_dir" "$pages")
        printf '%s\n' "$output" >"$page_file"
        validate_envelope "$output" dev.retrieval.benchmark \
            zcl.dev_retrieval_benchmark.v1 900
        [[ $(field "$output" data.schema) = zcl.dev_retrieval_benchmark.v1 &&
           $(bool_field "$output" data.observational) = true &&
           $(bool_field "$output" data.production_ordering_changed) = false &&
           $(bool_field "$output" data.promotion_authorized) = false &&
           $(bool_field "$output" data.native_execution) = true &&
           $(bool_field "$output" data.ready_to_benchmark) = true &&
           $(field "$output" data.gold_basis) = not_supplied_rank_only &&
           $(field "$output" data.scope_basis) = unavailable &&
           $(field "$output" data.context_basis) = full_file_bytes &&
           $(field "$output" data.context_cost_kind) = projected_not_read &&
           $(field "$output" data.token_basis) = 'ceil(context_bytes/4)' &&
           $(field "$output" data.literal_selector_basis) = production_algorithm_caller_owned_index ]] ||
            fail "ranking authority/evidence boundary failed for $id"
        [[ $(uint_field "$output" data.rank_offset 127) -eq $offset ]] ||
            fail "top-level rank offset mismatch for $id"
        page_limit=$(uint_field "$output" data.page_limit 20)
        ((page_limit >= 1)) || fail "page limit is zero for $id"
        record_invariant "$output" task_id data.task_id string
        record_invariant "$output" query data.query string
        record_invariant "$output" expected_root data.expected_vcs_root root
        record_invariant "$output" pre_root data.observed_vcs_root_pre root
        record_invariant "$output" post_root data.observed_vcs_root_post root
        record_invariant "$output" codeindex_root data.shared_codeindex_source_root_sha3 root
        record_invariant "$output" corpus_files data.corpus_files uint
        record_invariant "$output" document_profile data.document_profile string
        for arm in literal bm25; do
            record_invariant "$output" "${arm}_count" "data.$arm.ranked_files" uint
            record_invariant "$output" "${arm}_complete" "data.$arm.ranking_complete" bool
            record_invariant "$output" "${arm}_root" "data.$arm.ranking_root_sha3" root
            record_invariant "$output" "${arm}_context" "data.$arm.context_bytes_at_5" uint
            record_invariant "$output" "${arm}_tokens" "data.$arm.approximate_tokens_at_5" uint
        done
        ((invariant_literal_count <= 128 && invariant_bm25_count <= 128 &&
          invariant_corpus_files > 0)) || fail "ranking count is outside its bound"
        [[ $invariant_task_id = "$id" && $invariant_query = "$query" &&
           $invariant_expected_root = "$expected_root" &&
           $invariant_pre_root = "$expected_root" &&
           $invariant_post_root = "$expected_root" &&
           $invariant_document_profile = path+group+purpose+symbol_name+signature+doc+guard ]] ||
            fail "ranking is not bound to the reviewed task/source root"
        append_arm_page "$output" literal "$offset" "$page_limit" "$literal_file"
        append_arm_page "$output" bm25 "$offset" "$page_limit" "$bm25_file"
        literal_display=$(uint_field "$output" data.literal.displayed_files 20)
        bm25_display=$(uint_field "$output" data.bm25.displayed_files 20)
        ((literal_display > bm25_display)) && max_display=$literal_display || max_display=$bm25_display
        span=$(uint_field "$output" data.page_span 20)
        ((invariant_literal_count > invariant_bm25_count)) &&
            max_count=$invariant_literal_count || max_count=$invariant_bm25_count
        remaining=0; ((max_count > offset)) && remaining=$((max_count - offset))
        expected_span=$remaining; ((expected_span > page_limit)) && expected_span=$page_limit
        [[ $span -eq $max_display && $span -eq $expected_span ]] ||
            fail "page span mismatch for $id"
        elapsed_us=$(uint_field "$output" elapsed_us 9223372036854775807)
        budget_ms=$(uint_field "$output" budget_ms 9223372036854775807)
        exceeded=$(bool_field "$output" budget_exceeded)
        total_elapsed=$((total_elapsed + elapsed_us)); total_wall=$((total_wall + wall_us))
        [[ $exceeded = true ]] && any_budget_exceeded=true
        if ((pages == 1)); then
            page0_elapsed_us=$elapsed_us; page0_wall_us=$wall_us
            page0_budget_ms=$budget_ms; page0_budget_exceeded=$exceeded
        fi
        has_more=$(bool_field "$output" data.has_more)
        next=$(uint_field "$output" data.next_offset 127)
        expected_more=false
        ((offset + span < max_count)) && expected_more=true
        [[ $has_more = "$expected_more" ]] || fail "has_more formula mismatch for $id"
        if [[ $has_more = false ]]; then
            [[ $next -eq 0 && $((offset + span)) -eq $max_count ]] ||
                fail "terminal page does not close the retained ranking"
            break
        fi
        [[ $has_more = true && $span -gt 0 && $next -eq $((offset + span)) &&
           $next -gt $offset && $next -le 127 ]] ||
            fail "invalid pagination continuation for $id"
        offset=$next
    done
    check_rank_file literal "$literal_file" "$invariant_literal_count" \
        "$invariant_literal_context" "$invariant_literal_complete" \
        "$invariant_literal_root"
    check_rank_file bm25 "$bm25_file" "$invariant_bm25_count" \
        "$invariant_bm25_context" "$invariant_bm25_complete" \
        "$invariant_bm25_root"
    [[ $invariant_literal_tokens -eq $(((invariant_literal_context + 3) / 4)) &&
       $invariant_bm25_tokens -eq $(((invariant_bm25_context + 3) / 4)) ]] ||
        fail "token approximation does not rederive for $id"
    literal_take=$invariant_literal_count; ((literal_take > 5)) && literal_take=5
    bm25_take=$invariant_bm25_count; ((bm25_take > 5)) && bm25_take=5
    literal_eval_files=$((literal_eval_files + literal_take))
    bm25_eval_files=$((bm25_eval_files + bm25_take))
    literal_eval_context=$((literal_eval_context + invariant_literal_context))
    bm25_eval_context=$((bm25_eval_context + invariant_bm25_context))
    membership_check "$row" c23_codeindex
    verify_checkout "$(field "$row" parent_commit)"
    [[ $(capture_root) = "$expected_root" ]] || fail "post-task source root changed for $id"
    emit_batch_task "$row" "$id" "$literal_file" "$invariant_literal_count" \
        "$invariant_literal_complete" "$bm25_file" "$invariant_bm25_count" \
        "$invariant_bm25_complete"
    printf '{"record":"task","schema":"zcl.retrieval_gold_benchmark_task.v1","id":"%s","status":"observed","expected_vcs_root":"%s","shared_codeindex_source_root_sha3":"%s","membership_tree_root_sha3":"%s","membership_join_basis":"source_stability_backed_separate_indexes","pages":%d,"page0":{"elapsed_us":%s,"wall_us":%s,"budget_ms":%s,"budget_exceeded":%s},"all_pages":{"elapsed_us":%s,"wall_us":%s,"any_budget_exceeded":%s},"literal":{"retained_files":%s,"ranking_complete":%s,"ranking_root_sha3":"%s","projected_context_bytes_at_5":%s,"approximate_tokens_at_5":%s},"bm25":{"retained_files":%s,"ranking_complete":%s,"ranking_root_sha3":"%s","projected_context_bytes_at_5":%s,"approximate_tokens_at_5":%s},"scope_available":false,"files_read_observed":false,"reuse_success_available":false,"unique_loc_avoided_available":false}\n' \
        "$(json_escape "$id")" "$expected_root" "$invariant_codeindex_root" \
        "$invariant_membership_tree_root" "$pages" "$page0_elapsed_us" \
        "$page0_wall_us" "$page0_budget_ms" "$page0_budget_exceeded" \
        "$total_elapsed" "$total_wall" "$any_budget_exceeded" \
        "$invariant_literal_count" "$invariant_literal_complete" \
        "$invariant_literal_root" "$invariant_literal_context" \
        "$invariant_literal_tokens" "$invariant_bm25_count" \
        "$invariant_bm25_complete" "$invariant_bm25_root" \
        "$invariant_bm25_context" "$invariant_bm25_tokens" >>"$task_rows"
}

"$corpus_check" --selftest >/dev/null
"$corpus_check" --check >/dev/null
driver_commit=$(git -C "$repo_root" rev-parse HEAD)
remote_commit=$(git -C "$repo_root" rev-parse origin/main 2>/dev/null) ||
    fail "origin/main is unavailable; fetch before benchmarking"
driver_status=$(git -C "$repo_root" status --porcelain --untracked-files=all)
driver_clean=true; [[ -n $driver_status ]] && driver_clean=false
if [[ $publishable = true ]]; then
    [[ $driver_clean = true ]] ||
        fail "publishable benchmark implementation checkout must be clean"
    [[ $driver_commit = "$remote_commit" ]] ||
        fail "publishable benchmark must be the exact observed origin/main commit"
    publication_admission=exact_observed_origin_main
else
    publication_admission=local_observation_only
fi
runner_path="$repo_root/tools/dev/retrieval-gold-benchmark.sh"
rank_sha3=$(hash_file "$rank_bin")
capture_sha3=$(hash_file "$capture_bin")
evaluator_sha3=$(hash_file "$evaluator")
jsonq_sha3=$(hash_file "$jsonq")
sha3_sha3=$(hash_file "$sha3")
checker_sha3=$(hash_file "$corpus_check")
corpus_sha3=$(hash_file "$corpus")
runner_sha3=$(hash_file "$runner_path")
driver_status_sha3=$(hash_text "$driver_status")
task_rows="$run_root/tasks.jsonl"; : >"$task_rows"
batch="$run_root/eval.body"; : >"$batch"
tasks=0; eligible=0; unsupported=0
literal_eval_files=0; bm25_eval_files=0
literal_eval_context=0; bm25_eval_context=0

while IFS= read -r row || [[ -n $row ]]; do
    [[ $(field "$row" record) = task ]] || continue
    tasks=$((tasks + 1))
    id=$(field "$row" id); parent=$(field "$row" parent_commit)
    expected_root=$(field "$row" expected_vcs_root)
    eligibility=$(field "$row" index_eligibility)
    printf 'retrieval-gold-benchmark: task=%s parent=%s\n' "$id" "$parent" >&2
    prepare_checkout "$parent"
    [[ $(capture_root) = "$expected_root" ]] ||
        fail "historical source-root KAT mismatch for $id"
    verify_checkout "$parent"
    task_dir="$run_root/$id"; mkdir -p -- "$task_dir"
    if [[ $eligibility = outside_c23_codeindex ]]; then
        unset invariant_membership_tree_root
        membership_check "$row" "$eligibility"
        verify_checkout "$parent"
        [[ $(capture_root) = "$expected_root" ]] ||
            fail "post-membership source root changed for $id"
        unsupported=$((unsupported + 1))
        printf '{"record":"task","schema":"zcl.retrieval_gold_benchmark_task.v1","id":"%s","status":"unsupported","reason":"outside_c23_codeindex","expected_vcs_root":"%s","membership_tree_root_sha3":"%s","membership_absence_observed":true,"literal":null,"bm25":null}\n' \
            "$(json_escape "$id")" "$expected_root" \
            "$invariant_membership_tree_root" >>"$task_rows"
    else
        [[ $eligibility = c23_codeindex ]] || fail "unknown eligibility for $id"
        query=$(field "$row" query)
        run_eligible_task "$row" "$id" "$query" "$expected_root" "$task_dir"
        eligible=$((eligible + 1))
    fi
    cleanup_workspace
done <"$corpus"

[[ $tasks -eq 7 && $eligible -eq 6 && $unsupported -eq 1 ]] ||
    fail "task classification changed"
batch_body=$batch
batch="$run_root/eval.batch"
printf 'zcl.retrieval_eval_batch.v2 tasks=%s\n' "$eligible" >"$batch"
cat "$batch_body" >>"$batch"
printf 'end\n' >>"$batch"
batch_sha3=$(hash_file "$batch")
metrics=$("$evaluator" <"$batch") || fail "maintained evaluator adapter failed"
keys_exact "$metrics" . "$eval_result_keys"
[[ $(uint_field "$metrics" tasks_evaluated 32) -eq 6 &&
   $(field "$metrics" schema) = zcl.retrieval_eval_batch_result.v2 &&
   $(field "$metrics" binding_kind) = metrics_only_runner_seals_provenance &&
   $(field "$metrics" context_cost_kind) = projected_not_read &&
   $(field "$metrics" token_basis) = 'ceil(context_bytes/4)' ]] ||
    fail "evaluator task set differs from runner task set"
validate_eval_arm "$metrics" literal "$literal_eval_files" "$literal_eval_context"
validate_eval_arm "$metrics" bm25 "$bm25_eval_files" "$bm25_eval_context"
[[ $(hash_file "$rank_bin") = "$rank_sha3" &&
   $(hash_file "$capture_bin") = "$capture_sha3" &&
   $(hash_file "$evaluator") = "$evaluator_sha3" &&
   $(hash_file "$jsonq") = "$jsonq_sha3" &&
   $(hash_file "$sha3") = "$sha3_sha3" &&
   $(hash_file "$corpus_check") = "$checker_sha3" &&
   $(hash_file "$corpus") = "$corpus_sha3" &&
   $(hash_file "$runner_path") = "$runner_sha3" &&
   $(hash_file "$batch") = "$batch_sha3" ]] ||
    fail "benchmark input, executable, or batch changed during the run"
[[ $(git -C "$repo_root" rev-parse HEAD) = "$driver_commit" &&
   $(git -C "$repo_root" rev-parse origin/main) = "$remote_commit" &&
   $(hash_text "$(git -C "$repo_root" status --porcelain --untracked-files=all)") = "$driver_status_sha3" ]] ||
    fail "benchmark implementation identity changed during the run"

printf '{"record":"benchmark","schema":"zcl.retrieval_gold_benchmark.v1","corpus_id":"z23-historical-agent-tasks-v1","mode":"%s","publishable":%s,"publication_admission":"%s","promotion_authorized":false,"driver_commit":"%s","driver_commit_semantics":"display_only_github_trace_metadata","observed_origin_main":"%s","driver_clean":%s,"driver_status_sha3":"%s","tasks_declared":7,"tasks_evaluated":6,"tasks_unsupported":1,"source_epoch_kind":"git_parent_commit","source_root_basis":"vcs_manifest_v1_nonignored_filesystem","relevance_judgment":"landed_changed_path_present_in_parent","query_strata":{"commit_subject_only":1,"same_commit_unordered":6},"original_prompts_available":false,"canonical_task_roots_available":false,"ranking_may_read_relevance":false,"rank_binary_sha3":"%s","capture_binary_sha3":"%s","evaluator_binary_sha3":"%s","corpus_sha3":"%s","runner_sha3":"%s","evaluator_batch_root_sha3":"%s"}\n' \
    "${mode#--}" "$publishable" "$publication_admission" "$driver_commit" \
    "$remote_commit" "$driver_clean" "$driver_status_sha3" "$rank_sha3" \
    "$capture_sha3" "$evaluator_sha3" "$corpus_sha3" "$runner_sha3" "$batch_sha3"
cat "$task_rows"
printf '{"record":"aggregate","schema":"zcl.retrieval_gold_benchmark_aggregate.v1","metrics":%s,"files_read_observed":false,"observed_token_count_available":false,"wrong_scope_basis":"unavailable","reuse_success_available":false,"duplicate_avoidance_available":false,"new_unique_loc_avoided_available":false}\n' \
    "$(raw_field "$metrics" .)"
