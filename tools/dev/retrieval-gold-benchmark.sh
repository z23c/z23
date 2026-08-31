#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Run the reviewed retrieval corpus against each task's exact parent epoch.

set -euo pipefail
export LC_ALL=C

# vcs_manifest_v1 binds raw st_mode permission bits.  Git applies the caller's
# umask when it materializes a linked worktree, so an ambient 0002 checkout
# (0664/0775) has a different exact root from the reviewed 0022 checkout
# (0644/0755).  Fix the materialization environment before creating any
# historical epoch; the pinned task roots then prove this rail stayed active.
readonly historical_checkout_umask=0022
umask "$historical_checkout_umask"
[[ $(umask) = "$historical_checkout_umask" ]] || {
    printf 'retrieval-gold-benchmark: FAIL — cannot establish historical checkout umask %s\n' \
        "$historical_checkout_umask" >&2
    exit 1
}

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
scope_selftest=false
readonly eval_arm_keys='recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly eval_base_result_keys="schema,tasks_evaluated,aggregation_kind,tasks_denominator,eligible_relevance_judgments,binding_kind,context_cost_kind,token_basis,literal,$eval_arm_keys,bm25,$eval_arm_keys"
readonly eval_result_keys="$eval_base_result_keys,identifier_graph,$eval_arm_keys"

. "$repo_root/tools/dev/dev_lib.sh" # json_escape

fail() {
    printf 'retrieval-gold-benchmark: FAIL — %s\n' "$*" >&2
    exit 1
}

[[ $# -le 1 ]] || {
    printf 'usage: %s [--run-local|--run|--scope-selftest]\n' "$0" >&2
    exit 64
}
case "$mode" in
    --run) publishable=true ;;
    --run-local) ;;
    --scope-selftest) scope_selftest=true ;;
    *) printf 'usage: %s [--run-local|--run|--scope-selftest]\n' "$0" >&2; exit 64 ;;
esac
if [[ $scope_selftest = true ]]; then
    required_executables=("$jsonq" "$rank_bin" "$evaluator")
else
    required_executables=("$jsonq" "$rank_bin" "$capture_bin" "$evaluator" \
        "$sha3" "$corpus_check")
fi
for executable in "${required_executables[@]}"; do
    [[ -x $executable ]] || fail "required executable is unavailable: $executable"
done
command -v base64 >/dev/null 2>&1 || fail "required executable is unavailable: base64"
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

encode_base64_file() {
    base64 <"$1" | tr -d '\n'
}

query_stratum() {
    case "$1" in
        commit_subject_only) printf '%s' commit_subject_only ;;
        same_commit_unordered_question|same_commit_unordered_intent|same_commit_unordered_intention)
            printf '%s' same_commit_unordered ;;
        *) fail "unknown query provenance: $1" ;;
    esac
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

validate_stream_page() {
    local document=$1 expected_budget=$2
    local elapsed_us elapsed_ms budget_ms exceeded should_exceed
    [[ $(field "$document" schema) = zcl.dev_retrieval_benchmark_stream_page.v3 &&
       $(field "$document" command) = dev.retrieval.benchmark &&
       $(bool_field "$document" shared_computation) = true &&
       $(uint_field "$document" ranking_computations 1) -eq 1 &&
       $(field "$document" data_schema) = zcl.dev_retrieval_benchmark.v2 &&
       $(field_type "$document" data) = object ]] ||
        fail "invalid retrieval benchmark stream page"
    elapsed_us=$(uint_field "$document" ranking_elapsed_us 9223372036854775807)
    elapsed_ms=$(uint_field "$document" ranking_elapsed_ms 9223372036854775807)
    budget_ms=$(uint_field "$document" ranking_budget_ms 9223372036854775807)
    exceeded=$(bool_field "$document" ranking_budget_exceeded)
    [[ $budget_ms -eq $expected_budget && $elapsed_ms -eq $((elapsed_us / 1000)) ]] ||
        fail "invalid retrieval benchmark stream timing"
    should_exceed=false
    ((elapsed_us > budget_ms * 1000)) && should_exceed=true
    [[ $exceeded = "$should_exceed" ]] ||
        fail "stream budget_exceeded disagrees with elapsed time"
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
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = true ]] ||
        fail "$arm wrong-scope group-membership proxy is unavailable"
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

validate_eval_result_envelope() {
    local document=$1 expected_tasks=$2 expected_judgments=$3 label=$4
    [[ $(field "$document" schema) = zcl.retrieval_eval_batch_result.v3 &&
       $(field "$document" aggregation_kind) = macro_equal_task_weight &&
       $(uint_field "$document" tasks_evaluated 32) -eq $expected_tasks &&
       $(uint_field "$document" tasks_denominator 32) -eq $expected_tasks &&
       $(uint_field "$document" eligible_relevance_judgments 4096) -eq \
           $expected_judgments &&
       $(field "$document" binding_kind) = metrics_only_runner_seals_provenance &&
       $(field "$document" context_cost_kind) = projected_not_read &&
       $(field "$document" token_basis) = 'ceil(context_bytes/4)' ]] ||
        fail "$label evaluator task/envelope contract differs from runner"
}

canonical_path() {
    [[ -n $1 && $1 != /* && $1 != ./* && $1 != */ && $1 != *//* &&
       $1 != *\\* && $1 =~ ^[A-Za-z0-9][A-Za-z0-9._/+@-]*$ ]] || return 1
    if [[ $1 =~ (^|/)(\.|\.\.)($|/) ]]; then
        return 1
    fi
    return 0
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

validate_identifier_graph_contract() {
    local bm25_file=$1 graph_file=$2 bm25_count=$3 graph_count=$4
    local bm25_complete=$5 graph_complete=$6 bm25_context=$7 graph_context=$8
    local seed_count=$9 reverse_ref_files=${10} saturated=${11} reason=${12}
    local evidence_available=${13}
    [[ $graph_count -eq $bm25_count &&
       $graph_complete = "$bm25_complete" &&
       $graph_context -le $bm25_context &&
       $seed_count -le 512 && $reverse_ref_files -le $bm25_count ]] ||
        fail "identifier-graph bounds differ from the declared basis"
    cmp -s \
        <(awk -F '\t' '{ print $3 "\t" $2 }' "$bm25_file" | sort) \
        <(awk -F '\t' '{ print $3 "\t" $2 }' "$graph_file" | sort) ||
        fail "identifier-graph changed a BM25 path/context binding"
    cmp -s \
        <(awk -F '\t' '$1 <= 20 { print $3 }' "$bm25_file" | sort) \
        <(awk -F '\t' '$1 <= 20 { print $3 }' "$graph_file" | sort) ||
        fail "identifier-graph changed the BM25 top-20 candidate set"
    case "$reason:$saturated" in
        none:false)
            [[ $evidence_available = true ]] && ((seed_count > 0)) ||
                fail "applied identifier-graph ranking has no seed symbol" ;;
        query_atom_cap:true|symbol_cap:true|identifier_seed_cap:true|caller_cap:true)
            [[ $evidence_available = false ]] &&
                ((seed_count == 0 && reverse_ref_files == 0)) ||
                fail "saturated identifier-graph fallback retained partial evidence"
            cmp -s "$bm25_file" "$graph_file" ||
                fail "saturated identifier-graph fallback changed BM25 order" ;;
        no_window_evidence:false|context_guard_fallback:false)
            [[ $evidence_available = false ]] ||
                fail "identifier-graph fallback claimed row evidence"
            cmp -s "$bm25_file" "$graph_file" ||
                fail "identifier-graph fallback changed BM25 order" ;;
        *) fail "invalid identifier-graph fallback/saturation state: $reason/$saturated" ;;
    esac
}

membership_check() {
    local row=$1 eligibility=$2 groups_file=${3:-}
    local count i path input room merkle room_found merkle_found kind tree_root group
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
            group=$(field "$room" data.group)
            canonical_path "$group" ||
                fail "eligible relevant path has no canonical code.room group: $path"
            [[ -n $groups_file ]] || fail "eligible membership check has no group sink"
            printf '%s\n' "$group" >>"$groups_file"
        else
            [[ $room_found = false && $merkle_found = false ]] ||
                fail "outside-index relevant path unexpectedly indexed: $path"
            [[ $(field "$merkle" data.kind) = absent ]] ||
                fail "outside-index path did not return an absent Merkle leaf: $path"
        fi
    done
}

code_room_document() {
    local path=$1 input output
    input=$(printf '{"path":"%s"}' "$(json_escape "$path")")
    output=$(printf '%s' "$input" | env ZCL_DEV_SOURCE_ROOT="$workspace" \
        timeout "$command_timeout" "$rank_bin" code room --input=-) ||
        fail "code.room failed for path: $path"
    printf '%s' "$output"
}

validated_room_group() {
    local document=$1 expected_path=$2 group
    validate_envelope "$document" code.room zcl.code_room.v1 250
    [[ $(field "$document" data.path) = "$expected_path" ]] ||
        fail "code.room returned a different path during group classification"
    [[ $(bool_field "$document" data.found) = true ]] ||
        fail "path is absent from exact codeindex during group classification: $expected_path"
    group=$(field "$document" data.group)
    canonical_path "$group" ||
        fail "path has no canonical code.room group: $expected_path"
    printf '%s' "$group"
}

ranked_file_in_scope() {
    local path=$1 groups_file=$2 room group
    room=$(code_room_document "$path")
    group=$(validated_room_group "$room" "$path")
    if grep -Fqx -- "$group" "$groups_file"; then
        printf '1'
    else
        printf '0'
    fi
}

run_scope_selftest() {
    local net_path=lib/net/src/acme_alpn_challenge.c
    local test_path=lib/test/differential/groth16_comb_bench.c
    local outside_path=config/src/app_context.c
    local groups_file="$run_root/scope-selftest.groups"
    local literal_file="$run_root/scope-selftest.literal.tsv"
    local bm25_file="$run_root/scope-selftest.bm25.tsv"
    local body="$run_root/scope-selftest.body"
    local graph_body="$run_root/scope-selftest.graph-body"
    local fixture="$run_root/scope-selftest.batch"
    local graph_fixture="$run_root/scope-selftest.graph-batch"
    local row room group output graph_output bad arm
    workspace=$repo_root
    row=$(printf '{"query":"exact directory group union","relevant_paths":["%s","%s"]}' \
        "$net_path" "$test_path")
    : >"$groups_file"
    unset invariant_membership_tree_root
    membership_check "$row" c23_codeindex "$groups_file"
    sort -u -o "$groups_file" "$groups_file"
    [[ $(paste -sd, "$groups_file") = lib/net,lib/test ]] ||
        fail "scope selftest relevant directory-group union changed"
    room=$(code_room_document "$outside_path")
    group=$(validated_room_group "$room" "$outside_path")
    [[ $group = config ]] || fail "scope selftest outside directory group changed"
    printf '1\t1\t%s\n2\t1\t%s\n' "$test_path" "$outside_path" >"$literal_file"
    cp -- "$literal_file" "$bm25_file"
    batch=$body; graph_batch=$graph_body; : >"$batch"; : >"$graph_batch"
    emit_batch_task "$row" scope_union "$literal_file" 2 true \
        "$bm25_file" 2 true "$bm25_file" 2 true "$groups_file"
    {
        printf '%s\n' 'zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=2'
        cat "$body"
        printf '%s\n' end
    } >"$fixture"
    {
        printf '%s\n' 'zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=2'
        cat "$graph_body"
        printf '%s\n' end
    } >"$graph_fixture"
    output=$("$evaluator" <"$fixture") || fail "scope selftest evaluator refused fixture"
    graph_output=$("$evaluator" <"$graph_fixture") ||
        fail "scope selftest evaluator refused identifier-graph fixture"
    validate_eval_result_envelope "$output" 1 2 scope-baseline
    validate_eval_result_envelope "$graph_output" 1 2 scope-identifier-graph
    for arm in literal bm25; do
        [[ $(bool_field "$output" "$arm.wrong_scope_at_5.available") = true &&
           $(uint_field "$output" "$arm.wrong_scope_at_5.basis_points" 10000) -eq 5000 ]] ||
            fail "$arm scope selftest metric did not rederive"
    done
    [[ $(bool_field "$graph_output" bm25.wrong_scope_at_5.available) = true &&
       $(uint_field "$graph_output" bm25.wrong_scope_at_5.basis_points 10000) -eq 5000 ]] ||
        fail "identifier-graph scope selftest metric did not rederive"
    room=$(code_room_document "$test_path")
    bad=${room/\"path\":\"$test_path\"/\"path\":\"wrong.c\"}
    if (validated_room_group "$bad" "$test_path" >/dev/null 2>&1); then
        fail "scope selftest accepted a mismatched echoed path"
    fi
    bad=${room/\"found\":true/\"found\":false}
    if (validated_room_group "$bad" "$test_path" >/dev/null 2>&1); then
        fail "scope selftest accepted missing membership"
    fi
    bad=${room/\"group\":\"lib\/test\"/\"group\":\"\"}
    [[ $bad != "$room" ]] || fail "scope selftest empty-group mutation was hollow"
    if (validated_room_group "$bad" "$test_path" >/dev/null 2>&1); then
        fail "scope selftest accepted an empty group"
    fi
    printf 'retrieval-gold-benchmark: SCOPE SELFTEST PASS mutations=3\n'
}

emit_batch_task() {
    local row=$1 id=$2 literal_file=$3 literal_count=$4 literal_complete=$5
    local bm25_file=$6 bm25_count=$7 bm25_complete=$8
    local graph_file=$9 graph_count=${10} graph_complete=${11} groups_file=${12}
    local n i path rank bytes query in_scope destination
    n=$(array_count "$row" relevant_paths)
    query=$(field "$row" query)
    [[ -n $query && ${#query} -le 768 && $query =~ ^[[:print:]]+$ ]] ||
        fail "task query is not one canonical line: $id"
    for destination in "$batch" "$graph_batch"; do
        printf 'task %s %s\n' "$id" "$n" >>"$destination"
        printf 'query %s\n' "$query" >>"$destination"
        for ((i = 0; i < n; i++)); do
            path=$(field "$row" "relevant_paths[$i]")
            printf 'relevant %s\n' "$path" >>"$destination"
        done
    done
    [[ $literal_complete = true ]] && literal_complete=1 || literal_complete=0
    [[ $bm25_complete = true ]] && bm25_complete=1 || bm25_complete=0
    [[ $graph_complete = true ]] && graph_complete=1 || graph_complete=0
    printf 'literal observed %s %s\n' "$literal_complete" "$literal_count" >>"$batch"
    while IFS=$'\t' read -r rank bytes path; do
        if ((rank <= 5)); then
            in_scope=$(ranked_file_in_scope "$path" "$groups_file")
            printf 'rank %s 1 %s %s\n' "$bytes" "$in_scope" "$path" >>"$batch"
        else
            printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$batch"
        fi
    done <"$literal_file"
    printf 'bm25 observed %s %s\n' "$bm25_complete" "$bm25_count" >>"$batch"
    while IFS=$'\t' read -r rank bytes path; do
        if ((rank <= 5)); then
            in_scope=$(ranked_file_in_scope "$path" "$groups_file")
            printf 'rank %s 1 %s %s\n' "$bytes" "$in_scope" "$path" >>"$batch"
        else
            printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$batch"
        fi
    done <"$bm25_file"

    printf 'literal observed %s %s\n' "$literal_complete" "$literal_count" >>"$graph_batch"
    while IFS=$'\t' read -r rank bytes path; do
        if ((rank <= 5)); then
            in_scope=$(ranked_file_in_scope "$path" "$groups_file")
            printf 'rank %s 1 %s %s\n' "$bytes" "$in_scope" "$path" >>"$graph_batch"
        else
            printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$graph_batch"
        fi
    done <"$literal_file"
    printf 'bm25 observed %s %s\n' "$graph_complete" "$graph_count" >>"$graph_batch"
    while IFS=$'\t' read -r rank bytes path; do
        if ((rank <= 5)); then
            in_scope=$(ranked_file_in_scope "$path" "$groups_file")
            printf 'rank %s 1 %s %s\n' "$bytes" "$in_scope" "$path" >>"$graph_batch"
        else
            printf 'rank %s 0 0 %s\n' "$bytes" "$path" >>"$graph_batch"
        fi
    done <"$graph_file"
}

if [[ $scope_selftest = true ]]; then
    run_scope_selftest
    exit 0
fi

run_eligible_task() {
    local row=$1 id=$2 query=$3 expected_root=$4 task_dir=$5
    local literal_file="$task_dir/literal.tsv" bm25_file="$task_dir/bm25.tsv"
    local graph_file="$task_dir/identifier-graph.tsv"
    local scope_groups="$task_dir/relevant.groups"
    local offset=0 pages=0 output input started ended process_wall_us span next has_more
    local literal_display bm25_display graph_display max_display elapsed_us budget_ms exceeded
    local page_limit max_count remaining expected_span expected_more page_file literal_take bm25_take graph_take stream_file
    local total_elapsed=0 total_wall=0 any_budget_exceeded=false terminal=false
    local arm
    : >"$literal_file"; : >"$bm25_file"; : >"$graph_file"; : >"$scope_groups"
    unset invariant_task_id invariant_query invariant_expected_root \
        invariant_pre_root invariant_post_root invariant_codeindex_root \
        invariant_corpus_files invariant_document_profile \
        invariant_literal_count invariant_literal_complete invariant_literal_root \
        invariant_literal_context invariant_literal_tokens invariant_bm25_count \
        invariant_bm25_complete invariant_bm25_root invariant_bm25_context \
        invariant_bm25_tokens invariant_identifier_graph_count \
        invariant_identifier_graph_complete invariant_identifier_graph_root \
        invariant_identifier_graph_context invariant_identifier_graph_tokens \
        invariant_identifier_seed_symbols invariant_reverse_ref_files \
        invariant_query_lookup_saturated invariant_graph_fallback_reason \
        invariant_graph_evidence_available \
        invariant_membership_tree_root \
        invariant_stream_elapsed_us invariant_stream_budget_ms \
        invariant_stream_budget_exceeded
    input=$(printf '{"workspace":"%s","expected_vcs_root":"%s","task_id":"%s","query":"%s"}' \
        "$(json_escape "$workspace")" "$expected_root" \
        "$(json_escape "$id")" "$(json_escape "$query")")
    stream_file="$task_dir/pages.jsonl"
    started=$(date +%s%N)
    if ! printf '%s' "$input" | timeout "$command_timeout" \
        "$rank_bin" dev retrieval benchmark --format=jsonl --input=- \
        >"$stream_file"; then
        fail "ranking stream failed for $id"
    fi
    ended=$(date +%s%N); process_wall_us=$(((ended - started) / 1000))
    [[ -s $stream_file ]] || fail "ranking stream emitted no pages for $id"
    while IFS= read -r output || [[ -n $output ]]; do
        [[ $terminal = false ]] ||
            fail "ranking stream emitted a record after its terminal page for $id"
        pages=$((pages + 1)); ((pages <= 128)) || fail "pagination cycle for $id"
        page_file=$(printf '%s/page-%03d.json' "$task_dir" "$pages")
        printf '%s\n' "$output" >"$page_file"
        validate_stream_page "$output" 900
        [[ $(uint_field "$output" page_index 127) -eq $((pages - 1)) ]] ||
            fail "stream page index is not contiguous for $id"
        [[ $(field "$output" data.schema) = zcl.dev_retrieval_benchmark.v2 &&
           $(bool_field "$output" data.observational) = true &&
           $(bool_field "$output" data.production_ordering_changed) = true &&
           $(bool_field "$output" data.promotion_authorized) = false &&
           $(bool_field "$output" data.native_execution) = true &&
           $(bool_field "$output" data.ready_to_benchmark) = true &&
           $(field "$output" data.gold_basis) = not_supplied_rank_only &&
           $(field "$output" data.scope_basis) = unavailable &&
           $(field "$output" data.context_basis) = full_file_bytes &&
           $(field "$output" data.context_cost_kind) = projected_not_read &&
           $(field "$output" data.token_basis) = 'ceil(context_bytes/4)' &&
           $(field "$output" data.literal_selector_basis) = frozen_pre_story_token_order_v1 &&
           $(field "$output" data.production_selector_basis) = hybrid_literal_bm25_story_v1 &&
           $(field "$output" data.identifier_graph_basis) = bm25_top20_rare_identifier_atom_df16_observed_reverse_refs_context_guard_v1 &&
           $(field "$output" data.index_scan_completeness) = unobserved &&
           $(field "$output" data.graph_evidence_kind) = observed_reverse_refs_not_resolved_calls &&
           $(field "$output" data.vector_evidence) = not_used ]] ||
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
        record_invariant "$output" identifier_seed_symbols data.identifier_seed_symbols uint
        record_invariant "$output" reverse_ref_files data.observed_reverse_ref_files uint
        record_invariant "$output" query_lookup_saturated data.query_lookup_saturated bool
        record_invariant "$output" graph_fallback_reason data.graph_fallback_reason string
        record_invariant "$output" graph_evidence_available \
            data.identifier_graph.evidence_available bool
        for arm in literal bm25 identifier_graph; do
            record_invariant "$output" "${arm}_count" "data.$arm.ranked_files" uint
            record_invariant "$output" "${arm}_complete" "data.$arm.ranking_complete" bool
            record_invariant "$output" "${arm}_root" "data.$arm.ranking_root_sha3" root
            record_invariant "$output" "${arm}_context" "data.$arm.context_bytes_at_5" uint
            record_invariant "$output" "${arm}_tokens" "data.$arm.approximate_tokens_at_5" uint
        done
        ((invariant_literal_count <= 128 && invariant_bm25_count <= 128 &&
          invariant_identifier_graph_count <= 128 &&
          invariant_corpus_files > 0)) || fail "ranking count is outside its bound"
        [[ $invariant_task_id = "$id" && $invariant_query = "$query" &&
           $invariant_expected_root = "$expected_root" &&
           $invariant_pre_root = "$expected_root" &&
           $invariant_post_root = "$expected_root" &&
           $invariant_document_profile = path+group+purpose+symbol_name+signature+doc+guard ]] ||
            fail "ranking is not bound to the reviewed task/source root"
        append_arm_page "$output" literal "$offset" "$page_limit" "$literal_file"
        append_arm_page "$output" bm25 "$offset" "$page_limit" "$bm25_file"
        append_arm_page "$output" identifier_graph "$offset" "$page_limit" "$graph_file"
        literal_display=$(uint_field "$output" data.literal.displayed_files 20)
        bm25_display=$(uint_field "$output" data.bm25.displayed_files 20)
        graph_display=$(uint_field "$output" data.identifier_graph.displayed_files 20)
        ((literal_display > bm25_display)) && max_display=$literal_display || max_display=$bm25_display
        ((graph_display > max_display)) && max_display=$graph_display
        span=$(uint_field "$output" data.page_span 20)
        ((invariant_literal_count > invariant_bm25_count)) &&
            max_count=$invariant_literal_count || max_count=$invariant_bm25_count
        ((invariant_identifier_graph_count > max_count)) &&
            max_count=$invariant_identifier_graph_count
        remaining=0; ((max_count > offset)) && remaining=$((max_count - offset))
        expected_span=$remaining; ((expected_span > page_limit)) && expected_span=$page_limit
        [[ $span -eq $max_display && $span -eq $expected_span ]] ||
            fail "page span mismatch for $id"
        elapsed_us=$(uint_field "$output" ranking_elapsed_us 9223372036854775807)
        budget_ms=$(uint_field "$output" ranking_budget_ms 9223372036854775807)
        exceeded=$(bool_field "$output" ranking_budget_exceeded)
        set_invariant stream_elapsed_us "$elapsed_us"
        set_invariant stream_budget_ms "$budget_ms"
        set_invariant stream_budget_exceeded "$exceeded"
        [[ $exceeded = true ]] && any_budget_exceeded=true
        if ((pages == 1)); then
            total_elapsed=$elapsed_us; total_wall=$process_wall_us
        fi
        has_more=$(bool_field "$output" data.has_more)
        next=$(uint_field "$output" data.next_offset 127)
        expected_more=false
        ((offset + span < max_count)) && expected_more=true
        [[ $has_more = "$expected_more" ]] || fail "has_more formula mismatch for $id"
        if [[ $has_more = false ]]; then
            [[ $next -eq 0 && $((offset + span)) -eq $max_count ]] ||
                fail "terminal page does not close the retained ranking"
            terminal=true
            continue
        fi
        [[ $has_more = true && $span -gt 0 && $next -eq $((offset + span)) &&
           $next -gt $offset && $next -le 127 ]] ||
            fail "invalid pagination continuation for $id"
        offset=$next
    done <"$stream_file"
    ((pages > 0)) && [[ $terminal = true ]] ||
        fail "ranking stream did not contain one terminal page for $id"
    check_rank_file literal "$literal_file" "$invariant_literal_count" \
        "$invariant_literal_context" "$invariant_literal_complete" \
        "$invariant_literal_root"
    check_rank_file bm25 "$bm25_file" "$invariant_bm25_count" \
        "$invariant_bm25_context" "$invariant_bm25_complete" \
        "$invariant_bm25_root"
    check_rank_file identifier_graph "$graph_file" \
        "$invariant_identifier_graph_count" "$invariant_identifier_graph_context" \
        "$invariant_identifier_graph_complete" "$invariant_identifier_graph_root"
    validate_identifier_graph_contract \
        "$bm25_file" "$graph_file" "$invariant_bm25_count" \
        "$invariant_identifier_graph_count" "$invariant_bm25_complete" \
        "$invariant_identifier_graph_complete" "$invariant_bm25_context" \
        "$invariant_identifier_graph_context" "$invariant_identifier_seed_symbols" \
        "$invariant_reverse_ref_files" "$invariant_query_lookup_saturated" \
        "$invariant_graph_fallback_reason" "$invariant_graph_evidence_available"
    [[ $invariant_literal_tokens -eq $(((invariant_literal_context + 3) / 4)) &&
       $invariant_bm25_tokens -eq $(((invariant_bm25_context + 3) / 4)) &&
       $invariant_identifier_graph_tokens -eq $(((invariant_identifier_graph_context + 3) / 4)) ]] ||
        fail "token approximation does not rederive for $id"
    literal_take=$invariant_literal_count; ((literal_take > 5)) && literal_take=5
    bm25_take=$invariant_bm25_count; ((bm25_take > 5)) && bm25_take=5
    graph_take=$invariant_identifier_graph_count; ((graph_take > 5)) && graph_take=5
    literal_eval_files=$((literal_eval_files + literal_take))
    bm25_eval_files=$((bm25_eval_files + bm25_take))
    graph_eval_files=$((graph_eval_files + graph_take))
    literal_eval_context=$((literal_eval_context + invariant_literal_context))
    bm25_eval_context=$((bm25_eval_context + invariant_bm25_context))
    graph_eval_context=$((graph_eval_context + invariant_identifier_graph_context))
    membership_check "$row" c23_codeindex "$scope_groups"
    sort -u -o "$scope_groups" "$scope_groups"
    [[ -s $scope_groups ]] || fail "eligible task has no reviewed code.room groups: $id"
    emit_batch_task "$row" "$id" "$literal_file" "$invariant_literal_count" \
        "$invariant_literal_complete" "$bm25_file" "$invariant_bm25_count" \
        "$invariant_bm25_complete" "$graph_file" \
        "$invariant_identifier_graph_count" "$invariant_identifier_graph_complete" \
        "$scope_groups"
    verify_checkout "$(field "$row" parent_commit)"
    [[ $(capture_root) = "$expected_root" ]] || fail "post-task source root changed for $id"
    printf '{"record":"task","schema":"zcl.retrieval_gold_benchmark_task.v4","id":"%s","status":"observed","expected_vcs_root":"%s","shared_codeindex_source_root_sha3":"%s","membership_tree_root_sha3":"%s","membership_join_basis":"source_stability_backed_separate_indexes","pages":%d,"ranking_compute":{"elapsed_us":%s,"budget_ms":%s,"budget_exceeded":%s},"all_pages":{"wall_us":%s,"single_process":true,"buffered_before_write":true},"literal":{"retained_files":%s,"ranking_complete":%s,"ranking_root_sha3":"%s","projected_context_bytes_at_5":%s,"approximate_tokens_at_5":%s},"bm25":{"retained_files":%s,"ranking_complete":%s,"ranking_root_sha3":"%s","projected_context_bytes_at_5":%s,"approximate_tokens_at_5":%s},"identifier_graph":{"retained_files":%s,"ranking_complete":%s,"ranking_root_sha3":"%s","projected_context_bytes_at_5":%s,"approximate_tokens_at_5":%s,"basis":"bm25_top20_rare_identifier_atom_df16_observed_reverse_refs_context_guard_v1","identifier_seed_symbols":%s,"observed_reverse_ref_files":%s,"query_lookup_saturated":%s,"index_scan_completeness":"unobserved","graph_evidence_kind":"observed_reverse_refs_not_resolved_calls","evidence_available":%s,"fallback_reason":"%s","vector_evidence":"not_used","candidate_set":"strict_bm25_retained_permutation"},"scope_available":true,"scope_basis":"reviewed_relevant_codeindex_group_membership_v1","scope_interpretation":"directory_taxonomy_proxy_not_semantic_scope","scope_classifier_epoch":"current_driver_over_exact_parent_source","files_read_observed":false,"reuse_success_available":false,"unique_loc_avoided_available":false}\n' \
        "$(json_escape "$id")" "$expected_root" "$invariant_codeindex_root" \
        "$invariant_membership_tree_root" "$pages" "$total_elapsed" \
        "$invariant_stream_budget_ms" "$any_budget_exceeded" "$total_wall" \
        "$invariant_literal_count" "$invariant_literal_complete" \
        "$invariant_literal_root" "$invariant_literal_context" \
        "$invariant_literal_tokens" "$invariant_bm25_count" \
        "$invariant_bm25_complete" "$invariant_bm25_root" \
        "$invariant_bm25_context" "$invariant_bm25_tokens" \
        "$invariant_identifier_graph_count" "$invariant_identifier_graph_complete" \
        "$invariant_identifier_graph_root" "$invariant_identifier_graph_context" \
        "$invariant_identifier_graph_tokens" "$invariant_identifier_seed_symbols" \
        "$invariant_reverse_ref_files" "$invariant_query_lookup_saturated" \
        "$invariant_graph_evidence_available" \
        "$(json_escape "$invariant_graph_fallback_reason")" >>"$task_rows"
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
graph_batch="$run_root/eval-graph.body"; : >"$graph_batch"
declared_tasks=$(sed -n '1p' "$corpus" | "$jsonq" get task_count) ||
    fail "corpus task count is unavailable"
[[ $declared_tasks =~ ^[1-9][0-9]*$ ]] || fail "corpus task count is invalid"
tasks=0; eligible=0; unsupported=0
literal_eval_files=0; bm25_eval_files=0; graph_eval_files=0
literal_eval_context=0; bm25_eval_context=0; graph_eval_context=0
corpus_commit_subject=0; corpus_same_commit=0
evaluated_commit_subject=0; evaluated_same_commit=0
eligible_relevance_judgments=0

while IFS= read -r row || [[ -n $row ]]; do
    [[ $(field "$row" record) = task ]] || continue
    tasks=$((tasks + 1))
    id=$(field "$row" id); parent=$(field "$row" parent_commit)
    expected_root=$(field "$row" expected_vcs_root)
    eligibility=$(field "$row" index_eligibility)
    stratum=$(query_stratum "$(field "$row" query_provenance)")
    relevant_count=$(array_count "$row" relevant_paths)
    case "$stratum" in
        commit_subject_only) corpus_commit_subject=$((corpus_commit_subject + 1)) ;;
        same_commit_unordered) corpus_same_commit=$((corpus_same_commit + 1)) ;;
        *) fail "internal query-stratum classification error: $id" ;;
    esac
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
        printf '{"record":"task","schema":"zcl.retrieval_gold_benchmark_task.v4","id":"%s","status":"unsupported","reason":"outside_c23_codeindex","expected_vcs_root":"%s","membership_tree_root_sha3":"%s","membership_absence_observed":true,"literal":null,"bm25":null,"identifier_graph":null}\n' \
            "$(json_escape "$id")" "$expected_root" \
            "$invariant_membership_tree_root" >>"$task_rows"
    else
        [[ $eligibility = c23_codeindex ]] || fail "unknown eligibility for $id"
        case "$stratum" in
            commit_subject_only)
                evaluated_commit_subject=$((evaluated_commit_subject + 1)) ;;
            same_commit_unordered)
                evaluated_same_commit=$((evaluated_same_commit + 1)) ;;
            *) fail "internal evaluated query-stratum classification error: $id" ;;
        esac
        eligible_relevance_judgments=$((eligible_relevance_judgments + relevant_count))
        query=$(field "$row" query)
        run_eligible_task "$row" "$id" "$query" "$expected_root" "$task_dir"
        eligible=$((eligible + 1))
    fi
    cleanup_workspace
done <"$corpus"

[[ $tasks -eq $declared_tasks &&
   $((eligible + unsupported)) -eq $declared_tasks &&
   $((corpus_commit_subject + corpus_same_commit)) -eq $declared_tasks &&
   $((evaluated_commit_subject + evaluated_same_commit)) -eq $eligible ]] ||
    fail "task classification changed"
((eligible_relevance_judgments > 0)) ||
    fail "eligible task set has no relevance judgments"
batch_body=$batch
batch="$run_root/eval.batch"
printf 'zcl.retrieval_eval_batch.v3 tasks=%s eligible_relevance_judgments=%s\n' \
    "$eligible" "$eligible_relevance_judgments" >"$batch"
cat "$batch_body" >>"$batch"
printf 'end\n' >>"$batch"
graph_batch_body=$graph_batch
graph_batch="$run_root/eval-graph.batch"
printf 'zcl.retrieval_eval_batch.v3 tasks=%s eligible_relevance_judgments=%s\n' \
    "$eligible" "$eligible_relevance_judgments" >"$graph_batch"
cat "$graph_batch_body" >>"$graph_batch"
printf 'end\n' >>"$graph_batch"
batch_sha3=$(hash_file "$batch")
batch_bytes=$(wc -c <"$batch"); batch_bytes=${batch_bytes//[[:space:]]/}
[[ $batch_bytes =~ ^[1-9][0-9]*$ ]] || fail "evaluator batch byte count is invalid"
batch_base64=$(encode_base64_file "$batch") || fail "could not encode evaluator batch"
expected_base64_chars=$((4 * ((batch_bytes + 2) / 3)))
[[ ${#batch_base64} -eq $expected_base64_chars &&
   $batch_base64 =~ ^[A-Za-z0-9+/]*={0,2}$ ]] ||
    fail "evaluator batch base64 encoding is malformed"
graph_batch_sha3=$(hash_file "$graph_batch")
graph_batch_bytes=$(wc -c <"$graph_batch"); graph_batch_bytes=${graph_batch_bytes//[[:space:]]/}
[[ $graph_batch_bytes =~ ^[1-9][0-9]*$ ]] ||
    fail "identifier-graph evaluator batch byte count is invalid"
graph_batch_base64=$(encode_base64_file "$graph_batch") ||
    fail "could not encode identifier-graph evaluator batch"
expected_graph_base64_chars=$((4 * ((graph_batch_bytes + 2) / 3)))
[[ ${#graph_batch_base64} -eq $expected_graph_base64_chars &&
   $graph_batch_base64 =~ ^[A-Za-z0-9+/]*={0,2}$ ]] ||
    fail "identifier-graph evaluator batch base64 encoding is malformed"
metrics=$("$evaluator" <"$batch") || fail "maintained evaluator adapter failed"
graph_metrics=$("$evaluator" <"$graph_batch") ||
    fail "maintained evaluator adapter refused identifier-graph batch"
keys_exact "$metrics" . "$eval_base_result_keys"
keys_exact "$graph_metrics" . "$eval_base_result_keys"
validate_eval_result_envelope "$metrics" "$eligible" \
    "$eligible_relevance_judgments" baseline
validate_eval_arm "$metrics" literal "$literal_eval_files" "$literal_eval_context"
validate_eval_arm "$metrics" bm25 "$bm25_eval_files" "$bm25_eval_context"
validate_eval_result_envelope "$graph_metrics" "$eligible" \
    "$eligible_relevance_judgments" identifier-graph
validate_eval_arm "$graph_metrics" bm25 "$graph_eval_files" "$graph_eval_context"
[[ $(raw_field "$metrics" bm25.recall_at_20) = \
   $(raw_field "$graph_metrics" bm25.recall_at_20) ]] ||
    fail "identifier-graph Recall@20 differs despite the sealed top-20 set"
graph_arm=$(raw_field "$graph_metrics" bm25)
metrics=${metrics/"zcl.retrieval_eval_batch_result.v3"/"zcl.retrieval_eval_batch_result.v4"}
metrics="${metrics%?},\"identifier_graph\":$graph_arm}"
keys_exact "$metrics" . "$eval_result_keys"
[[ $(hash_file "$rank_bin") = "$rank_sha3" &&
   $(hash_file "$capture_bin") = "$capture_sha3" &&
   $(hash_file "$evaluator") = "$evaluator_sha3" &&
   $(hash_file "$jsonq") = "$jsonq_sha3" &&
   $(hash_file "$sha3") = "$sha3_sha3" &&
   $(hash_file "$corpus_check") = "$checker_sha3" &&
   $(hash_file "$corpus") = "$corpus_sha3" &&
   $(hash_file "$runner_path") = "$runner_sha3" &&
   $(hash_file "$batch") = "$batch_sha3" &&
   $(hash_file "$graph_batch") = "$graph_batch_sha3" &&
   $(wc -c <"$batch" | tr -d '[:space:]') = "$batch_bytes" &&
   $(wc -c <"$graph_batch" | tr -d '[:space:]') = "$graph_batch_bytes" &&
   $(encode_base64_file "$batch") = "$batch_base64" &&
   $(encode_base64_file "$graph_batch") = "$graph_batch_base64" ]] ||
    fail "benchmark input, executable, or batch changed during the run"
[[ $(git -C "$repo_root" rev-parse HEAD) = "$driver_commit" &&
   $(git -C "$repo_root" rev-parse origin/main) = "$remote_commit" &&
   $(hash_text "$(git -C "$repo_root" status --porcelain --untracked-files=all)") = "$driver_status_sha3" ]] ||
    fail "benchmark implementation identity changed during the run"

printf -v benchmark_record '{"record":"benchmark","schema":"zcl.retrieval_gold_benchmark.v2","corpus_id":"z23-historical-agent-tasks-v1","mode":"%s","publishable":%s,"publication_admission":"%s","promotion_authorized":false,"driver_commit":"%s","driver_commit_semantics":"display_only_github_trace_metadata","observed_origin_main":"%s","driver_clean":%s,"driver_status_sha3":"%s","tasks_declared":%s,"tasks_evaluated":%s,"tasks_unsupported":%s,"source_epoch_kind":"git_parent_commit","source_root_basis":"vcs_manifest_v1_nonignored_filesystem","relevance_judgment":"landed_changed_path_present_in_parent","query_strata":{"commit_subject_only":%s,"same_commit_unordered":%s},"evaluated_query_strata":{"commit_subject_only":%s,"same_commit_unordered":%s},"original_prompts_available":false,"canonical_task_roots_available":false,"ranking_may_read_relevance":false,"rank_binary_sha3":"%s","capture_binary_sha3":"%s","evaluator_binary_sha3":"%s","jsonq_binary_sha3":"%s","sha3_helper_binary_sha3":"%s","corpus_checker_script_sha3":"%s","corpus_sha3":"%s","runner_sha3":"%s","evaluator_batch_bytes":%s,"evaluator_batch_encoding":"base64_rfc4648","evaluator_batch_base64":"%s","evaluator_batch_root_sha3":"%s","identifier_graph_evaluator_batch_bytes":%s,"identifier_graph_evaluator_batch_encoding":"base64_rfc4648","identifier_graph_evaluator_batch_base64":"%s","identifier_graph_evaluator_batch_root_sha3":"%s"}' \
    "${mode#--}" "$publishable" "$publication_admission" "$driver_commit" \
    "$remote_commit" "$driver_clean" "$driver_status_sha3" "$declared_tasks" \
    "$eligible" "$unsupported" \
    "$corpus_commit_subject" "$corpus_same_commit" \
    "$evaluated_commit_subject" "$evaluated_same_commit" "$rank_sha3" \
    "$capture_sha3" "$evaluator_sha3" "$jsonq_sha3" "$sha3_sha3" \
    "$checker_sha3" "$corpus_sha3" "$runner_sha3" \
    "$batch_bytes" "$batch_base64" "$batch_sha3" \
    "$graph_batch_bytes" "$graph_batch_base64" "$graph_batch_sha3"
[[ $(root_field "$benchmark_record" jsonq_binary_sha3) = "$jsonq_sha3" &&
   $(root_field "$benchmark_record" sha3_helper_binary_sha3) = "$sha3_sha3" &&
   $(root_field "$benchmark_record" corpus_checker_script_sha3) = "$checker_sha3" ]] ||
    fail "benchmark tool identity fields do not match their observed inputs"
printf '%s\n' "$benchmark_record"
cat "$task_rows"
printf '{"record":"aggregate","schema":"zcl.retrieval_gold_benchmark_aggregate.v3","metrics":%s,"files_read_observed":false,"observed_token_count_available":false,"wrong_scope_basis":"reviewed_relevant_codeindex_group_membership_v1","wrong_scope_interpretation":"directory_taxonomy_proxy_not_semantic_scope","wrong_scope_classifier_epoch":"current_driver_over_exact_parent_source","wrong_scope_aggregation_kind":"micro_task_file_selections_at_5","wrong_scope_denominator_kind":"sum_of_task_unique_file_selections_at_5","reuse_success_available":false,"duplicate_avoidance_available":false,"new_unique_loc_avoided_available":false}\n' \
    "$(raw_field "$metrics" .)"
