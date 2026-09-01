#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Verify the frozen ten-task publishable identifier-graph retrieval benchmark
# by replaying both sealed evaluator batches without rerunning ranking.

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
. "$repo_root/tools/scripts/source_identity_lib.sh" # zcl_is_sha256
readonly driver=25fe3e353288d2f52e7f5fc07b7b722b27e71f1a
readonly receipt_name=retrieval-gold-benchmark-25fe3e353288.jsonl
readonly receipt="$repo_root/docs/work/retrieval-gold-evidence/$receipt_name"
readonly receipt_sha3=5f1f8ff22867f2937cbffc61200affe30f8aed49c2456e79923f83a212adf455
readonly empty_sha3=a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
readonly corpus_path=docs/work/RETRIEVAL_GOLD_CORPUS.jsonl
readonly runner_path=tools/dev/retrieval-gold-benchmark.sh
readonly corpus_checker_path=tools/dev/retrieval-gold-corpus-check.sh
readonly group_source_path=lib/codeindex/src/codeindex_group.c
readonly group_source_sha3=346e4747ce682533e9812d5fd9063ae8e82a9281fdf0b2a82bc869379ba58bc9
jsonq=${ZCL_JSONQ:-$repo_root/build/bin/jsonq}
sha3=${ZCL_AGENT_SHA3:-$repo_root/build/bin/agent_sha3}
evaluator=${ZCL_RETRIEVAL_EVAL:-$repo_root/build/bin/retrieval-eval}
tmp=''

readonly benchmark_keys='record,schema,corpus_id,mode,publishable,publication_admission,promotion_authorized,driver_commit,driver_commit_semantics,observed_origin_main,driver_clean,driver_status_sha3,tasks_declared,tasks_evaluated,tasks_unsupported,source_epoch_kind,source_root_basis,relevance_judgment,query_strata,commit_subject_only,same_commit_unordered,evaluated_query_strata,commit_subject_only,same_commit_unordered,original_prompts_available,canonical_task_roots_available,ranking_may_read_relevance,rank_binary_sha3,capture_binary_sha3,evaluator_binary_sha3,jsonq_binary_sha3,sha3_helper_binary_sha3,corpus_checker_script_sha3,corpus_sha3,runner_sha3,evaluator_batch_bytes,evaluator_batch_encoding,evaluator_batch_base64,evaluator_batch_root_sha3,identifier_graph_evaluator_batch_bytes,identifier_graph_evaluator_batch_encoding,identifier_graph_evaluator_batch_base64,identifier_graph_evaluator_batch_root_sha3'
readonly observed_task_v4_keys='record,schema,id,status,expected_vcs_root,shared_codeindex_source_root_sha3,membership_tree_root_sha3,membership_join_basis,pages,ranking_compute,elapsed_us,budget_ms,budget_exceeded,all_pages,wall_us,single_process,buffered_before_write,literal,retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,bm25,retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,identifier_graph,retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,basis,identifier_seed_symbols,observed_reverse_ref_files,query_lookup_saturated,index_scan_completeness,graph_evidence_kind,evidence_available,fallback_reason,vector_evidence,candidate_set,scope_available,scope_basis,scope_interpretation,scope_classifier_epoch,files_read_observed,reuse_success_available,unique_loc_avoided_available'
readonly unsupported_task_keys='record,schema,id,status,reason,expected_vcs_root,membership_tree_root_sha3,membership_absence_observed,literal,bm25,identifier_graph'
readonly arm_keys='retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5'
readonly graph_arm_keys='retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,basis,identifier_seed_symbols,observed_reverse_ref_files,query_lookup_saturated,index_scan_completeness,graph_evidence_kind,evidence_available,fallback_reason,vector_evidence,candidate_set'
readonly metric_keys='available,basis_points'
readonly eval_arm_keys='recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly eval_base_keys='schema,tasks_evaluated,aggregation_kind,tasks_denominator,eligible_relevance_judgments,binding_kind,context_cost_kind,token_basis,literal,recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points,bm25,recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly eval_keys="$eval_base_keys,identifier_graph,$eval_arm_keys"
readonly aggregate_keys="record,schema,metrics,$eval_keys,files_read_observed,observed_token_count_available,wrong_scope_basis,wrong_scope_interpretation,wrong_scope_classifier_epoch,wrong_scope_aggregation_kind,wrong_scope_denominator_kind,reuse_success_available,duplicate_avoidance_available,new_unique_loc_avoided_available"

fail() { printf 'retrieval-gold-identifier-graph-receipt-check: FAIL — %s\n' "$*" >&2; exit 1; }

field() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" get "$2") ||
        fail "missing or malformed field: $2"
    printf '%s' "$value"
}

raw_field() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" raw "$2") ||
        fail "missing or malformed value: $2"
    printf '%s' "$value"
}

field_type() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" type "$2") ||
        fail "missing type: $2"
    printf '%s' "$value"
}

array_count() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" count "$2") ||
        fail "missing array: $2"
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || fail "invalid array count: $2"
    printf '%s' "$value"
}

keys_exact() {
    local observed
    observed=$(printf '%s\n' "$1" | "$jsonq" keys "$2" | paste -sd, -) ||
        fail "cannot enumerate keys: $2"
    [[ $observed = "$3" ]] || fail "unexpected object shape: $2"
}

uint_field() {
    local value
    [[ $(field_type "$1" "$2") = number ]] || fail "not a number: $2"
    value=$(field "$1" "$2")
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || fail "not a canonical integer: $2"
    ((${#value} < ${#3} || (${#value} == ${#3} && 10#$value <= 10#$3))) ||
        fail "integer exceeds bound: $2"
    printf '%s' "$value"
}

bool_field() {
    local value
    [[ $(field_type "$1" "$2") = bool ]] || fail "not a boolean: $2"
    value=$(field "$1" "$2")
    [[ $value = true || $value = false ]] || fail "invalid boolean: $2"
    printf '%s' "$value"
}

root_field() {
    local value
    [[ $(field_type "$1" "$2") = string ]] || fail "not a root string: $2"
    value=$(field "$1" "$2")
    zcl_is_sha256 "$value" || fail "invalid 64-hex SHA3 root: $2"
    printf '%s' "$value"
}

hash_file() {
    local output root
    output=$("$sha3" "$1") || fail "cannot hash file: $1"
    root=${output%% *}
    zcl_is_sha256 "$root" || fail "malformed 64-hex file hash: $1"
    printf '%s' "$root"
}

check_hash() {
    [[ $(hash_file "$1") = "$2" ]] || fail "SHA3 differs: $1"
}

validate_metric() {
    local available
    keys_exact "$1" "$2" "$metric_keys"
    available=$(bool_field "$1" "$2.available")
    if [[ $available = true ]]; then
        uint_field "$1" "$2.basis_points" 10000 >/dev/null
    else
        [[ $(field_type "$1" "$2.basis_points") = null ]] ||
            fail "unavailable metric carries a value: $2"
    fi
}

validate_eval_arm() {
    local document=$1 arm=$2 expected_files=$3 expected_context=$4 expected_wrong_bp=$5
    local actual_files actual_context actual_tokens
    keys_exact "$document" "$arm" "$eval_arm_keys"
    validate_metric "$document" "$arm.recall_at_5"
    validate_metric "$document" "$arm.recall_at_20"
    validate_metric "$document" "$arm.mrr"
    validate_metric "$document" "$arm.wrong_scope_at_5"
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = true &&
       $(uint_field "$document" "$arm.wrong_scope_at_5.basis_points" 10000) -eq $expected_wrong_bp ]] ||
        fail "$arm wrong-directory-group metric differs"
    actual_files=$(uint_field "$document" "$arm.task_unique_file_selections_at_5" 3840)
    actual_context=$(uint_field "$document" "$arm.projected_context_bytes_at_5" 9223372036854775807)
    actual_tokens=$(uint_field "$document" "$arm.approximate_tokens_at_5" 9223372036854775807)
    [[ $actual_files -eq $expected_files && $actual_context -eq $expected_context &&
       $actual_tokens -eq $(((expected_context + 3) / 4)) ]] ||
        fail "$arm aggregate cost formula differs"
}

validate_eval_replay_envelope() {
    local document=$1 label=$2
    keys_exact "$document" . "$eval_base_keys"
    [[ $(field "$document" schema) = zcl.retrieval_eval_batch_result.v3 &&
       $(uint_field "$document" tasks_evaluated 32) -eq 9 &&
       $(field "$document" aggregation_kind) = macro_equal_task_weight &&
       $(uint_field "$document" tasks_denominator 32) -eq 9 &&
       $(uint_field "$document" eligible_relevance_judgments 4096) -eq 43 &&
       $(field "$document" binding_kind) = metrics_only_runner_seals_provenance &&
       $(field "$document" context_cost_kind) = projected_not_read &&
       $(field "$document" token_basis) = 'ceil(context_bytes/4)' ]] ||
        fail "$label evaluator replay envelope differs"
}

decode_base64() {
    local help
    help=$(base64 --help 2>&1 || true)
    if grep -q -- '--decode' <<<"$help"; then
        base64 --decode
    else
        base64 -D
    fi
}

decode_sealed_batch() {
    local document=$1 prefix=$2 expected_bytes=$3 expected_root=$4 output=$5
    local encoded="$tmp/$prefix.base64" reencoded="$tmp/$prefix.reencoded"
    local bytes encoded_chars
    [[ $(field "$document" "${prefix}_encoding") = base64_rfc4648 ]] ||
        fail "unknown $prefix encoding"
    bytes=$(uint_field "$document" "${prefix}_bytes" 1048576)
    [[ $bytes -eq $expected_bytes ]] || fail "$prefix byte count differs"
    case "$prefix" in
        evaluator_batch)
            printf '%s\n' "$document" | sed -n \
                's|^.*"evaluator_batch_encoding":"base64_rfc4648","evaluator_batch_base64":"\([A-Za-z0-9+/]*=\{0,2\}\)","evaluator_batch_root_sha3":"[0-9a-f]\{64\}","identifier_graph_evaluator_batch_bytes":.*$|\1|p' \
                >"$encoded" ;;
        identifier_graph_evaluator_batch)
            printf '%s\n' "$document" | sed -n \
                's|^.*"identifier_graph_evaluator_batch_encoding":"base64_rfc4648","identifier_graph_evaluator_batch_base64":"\([A-Za-z0-9+/]*=\{0,2\}\)","identifier_graph_evaluator_batch_root_sha3":"[0-9a-f]\{64\}"}$|\1|p' \
                >"$encoded" ;;
        *) fail "unknown sealed batch prefix: $prefix" ;;
    esac
    [[ -s $encoded && $(wc -l <"$encoded" | tr -d '[:space:]') -eq 1 ]] ||
        fail "$prefix base64 is noncanonical"
    encoded_chars=$(wc -c <"$encoded"); encoded_chars=${encoded_chars//[[:space:]]/}
    encoded_chars=$((encoded_chars - 1))
    ((encoded_chars > 0 && encoded_chars % 4 == 0)) ||
        fail "$prefix base64 length is noncanonical"
    tr -d '\n' <"$encoded" | decode_base64 >"$output" ||
        fail "cannot decode $prefix"
    [[ $(wc -c <"$output" | tr -d '[:space:]') -eq $bytes ]] ||
        fail "$prefix decoded byte count differs"
    base64 <"$output" | tr -d '\n' >"$reencoded"
    tr -d '\n' <"$encoded" | cmp -s - "$reencoded" ||
        fail "$prefix base64 does not round-trip canonically"
    check_hash "$output" "$(root_field "$document" "${prefix}_root_sha3")"
    [[ $(root_field "$document" "${prefix}_root_sha3") = "$expected_root" ]] ||
        fail "$prefix root differs from reviewed KAT"
    [[ $(head -n 1 "$output") = \
       'zcl.retrieval_eval_batch.v3 tasks=9 eligible_relevance_judgments=43' ]] ||
        fail "$prefix header differs"
}

validate_batch_scope() {
    local candidate=$1 counts=$2
    awk '
        function refuse(message) {
            print "retrieval-gold-scope-receipt-check: scope bits: " message > "/dev/stderr"
            bad = 1
            exit 1
        }
        ($1 == "literal" || $1 == "bm25") && $2 == "observed" {
            arm = $1
            rank = 0
            next
        }
        $1 == "rank" {
            if (arm == "" || NF != 5) refuse("rank outside an observed arm")
            rank++
            if (rank <= 5) {
                if ($3 != 1 || ($4 != 0 && $4 != 1))
                    refuse("top-five rank lacks an exact scope classification")
                selected[arm]++
                if ($4 == 0) wrong[arm]++
            } else if ($3 != 0 || $4 != 0) {
                refuse("post-five rank carries undeclared scope evidence")
            }
            next
        }
        END {
            if (!bad) {
                print "literal\t" selected["literal"] + 0 "\t" wrong["literal"] + 0
                print "bm25\t" selected["bm25"] + 0 "\t" wrong["bm25"] + 0
            }
        }
    ' "$candidate" >"$counts" || fail "sealed batch scope classification is invalid"
}

# Shell mirror of the exact driver source pinned by group_source_sha3. The
# receipt's scope evidence is a directory-taxonomy proxy, so replay that
# classifier rather than trusting the sealed per-rank bits or their totals.
group_for_path() {
    local path=$1 rest
    case "$path" in
        lib/*|app/*|domain/*)
            rest=${path#*/}
            printf '%s/%s' "${path%%/*}" "${rest%%/*}" ;;
        core/*) printf 'core' ;;
        config/*) printf 'config' ;;
        tools/*) printf 'tools' ;;
        adapters/*) printf 'adapters' ;;
        ports/*) printf 'ports' ;;
        application/*) printf 'application' ;;
        *) printf 'root' ;;
    esac
}

validate_scope_rank_contract() {
    local ranking=$1 groups=$2 task_id=$3 arm=$4
    local rank context available in_scope path group expected
    while IFS=$'\t' read -r rank context available in_scope path; do
        if ((rank <= 5)); then
            group=$(group_for_path "$path")
            expected=0
            grep -Fqx -- "$group" "$groups" && expected=1
            [[ $available = 1 && $in_scope -eq $expected ]] ||
                fail "$arm scope classification differs: $task_id rank=$rank"
        else
            [[ $available = 0 && $in_scope = 0 ]] ||
                fail "$arm post-five scope evidence differs: $task_id rank=$rank"
        fi
    done <"$ranking"
}

extract_batch_rankings() {
    local candidate=$1 prefix=$2 task_map=$3
    : >"$task_map"
    awk -v out="$tmp" -v prefix="$prefix" -v task_map="$task_map" '
        function refuse(message) {
            print "retrieval-gold-identifier-graph-receipt-check: batch ranks: " message > "/dev/stderr"
            bad = 1
            exit 1
        }
        function finish_arm() {
            if (arm != "" && ranks != declared)
                refuse("rank count differs from declaration")
        }
        $1 == "task" {
            finish_arm()
            if (arm != "" && arm != "bm25") refuse("task ended before bm25")
            task++
            if (NF != 3) refuse("malformed task declaration")
            print task "\t" $2 >> task_map
            arm = ""
            next
        }
        ($1 == "literal" || $1 == "bm25") && $2 == "observed" {
            finish_arm()
            if (task == 0 || NF != 4) refuse("malformed arm declaration")
            if ($1 == "literal" && arm != "") refuse("duplicate literal arm")
            if ($1 == "bm25" && arm != "literal") refuse("bm25 before literal")
            arm = $1
            complete = $3
            declared = $4
            ranks = 0
            meta = out "/" prefix "-rank-" task "-" arm ".meta"
            file = out "/" prefix "-rank-" task "-" arm ".tsv"
            print complete "\t" declared > meta
            close(meta)
            printf "%s", "" > file
            close(file)
            next
        }
        $1 == "rank" {
            if (arm == "" || NF != 5) refuse("rank outside an arm")
            ranks++
            file = out "/" prefix "-rank-" task "-" arm ".tsv"
            print ranks "\t" $2 "\t" $3 "\t" $4 "\t" $5 >> file
            close(file)
            next
        }
        END {
            if (!bad) {
                finish_arm()
                if (task != 9 || arm != "bm25") refuse("incomplete task/arm sequence")
            }
        }
    ' "$candidate" || fail "could not extract exact rankings from $prefix batch"
}

validate_graph_rank_contract() {
    local bm25_tsv=$1 graph_tsv=$2 task_id=$3
    local bm25_complete=$4 graph_complete=$5 bm25_count=$6 graph_count=$7
    local bm25_context=$8 graph_context=$9 seed_count=${10} ref_files=${11}
    local saturated=${12} fallback=${13} evidence=${14}
    [[ $graph_count -eq $bm25_count && $graph_complete = "$bm25_complete" &&
       $graph_context -le $bm25_context && $seed_count -le 512 &&
       $ref_files -le $bm25_count ]] ||
        fail "graph bound differs from BM25: $task_id"
    [[ $(awk -F '\t' '$1 <= 5 { sum += $2 } END { print sum + 0 }' "$bm25_tsv") \
       -eq $bm25_context &&
       $(awk -F '\t' '$1 <= 5 { sum += $2 } END { print sum + 0 }' "$graph_tsv") \
       -eq $graph_context ]] || fail "top-five context does not rederive: $task_id"
    cmp -s \
        <(awk -F '\t' '{ print $5 "\t" $2 }' "$bm25_tsv" | sort) \
        <(awk -F '\t' '{ print $5 "\t" $2 }' "$graph_tsv" | sort) ||
        fail "graph changed a BM25 path/context binding: $task_id"
    cmp -s \
        <(awk -F '\t' '$1 <= 20 { print $5 }' "$bm25_tsv" | sort) \
        <(awk -F '\t' '$1 <= 20 { print $5 }' "$graph_tsv" | sort) ||
        fail "graph changed the BM25 top-20 set: $task_id"
    case "$fallback:$saturated" in
        none:false)
            [[ $evidence = true && $seed_count -gt 0 ]] ||
                fail "applied graph evidence state differs: $task_id" ;;
        query_atom_cap:true|symbol_cap:true|identifier_seed_cap:true|caller_cap:true)
            [[ $evidence = false && $seed_count -eq 0 && $ref_files -eq 0 ]] ||
                fail "saturated graph retained partial evidence: $task_id"
            cmp -s "$bm25_tsv" "$graph_tsv" ||
                fail "saturated graph changed BM25 order: $task_id" ;;
        no_window_evidence:false|context_guard_fallback:false)
            [[ $evidence = false ]] || fail "graph fallback claimed evidence: $task_id"
            cmp -s "$bm25_tsv" "$graph_tsv" ||
                fail "graph fallback changed BM25 order: $task_id" ;;
        *) fail "invalid graph fallback state: $task_id" ;;
    esac
}

validate_semantics() {
    local candidate=$1 benchmark aggregate batch graph_batch replay graph_replay
    local metrics graph_arm row_schema
    local bytes corpus runner checker i row corpus_row id eligibility relevant_count
    local corpus_subject=0 corpus_same=0 eval_subject=0 eval_same=0
    local observed=0 unsupported=0 relevance_total=0
    local literal_files=0 bm25_files=0 graph_files=0
    local literal_context=0 bm25_context=0 graph_context=0
    local retained context tokens take elapsed budget exceeded expected_exceeded
    local all_wall
    local complete ranking_root rank_index arm_index meta_complete meta_count
    local batch_task_id observed_root
    local literal_scope_files literal_wrong_files literal_wrong_bp
    local bm25_scope_files bm25_wrong_files bm25_wrong_bp
    local graph_scope_files graph_wrong_files graph_wrong_bp
    local corpus_file="$tmp/corpus.jsonl" runner_file="$tmp/runner.sh"
    local checker_file="$tmp/corpus-checker.sh" projection="$tmp/expected.projection"
    local group_source_file="$tmp/codeindex_group.c" scope_group_file relevant_path
    local observed_projection="$tmp/observed.projection"
    local rank_task_map="$tmp/rank-tasks.tsv"
    local scope_counts="$tmp/scope-counts.tsv"
    local graph_scope_counts="$tmp/graph-scope-counts.tsv"
    local -a rank_task_ids literal_roots literal_complete literal_counts
    local -a bm25_roots bm25_complete bm25_counts bm25_contexts
    local -a graph_roots graph_complete graph_counts graph_contexts graph_seed_counts
    local -a graph_ref_files graph_saturated graph_fallback graph_evidence

    [[ -f $candidate ]] || fail "receipt is absent: $candidate"
    [[ $(tail -c 1 "$candidate" | od -An -tuC | tr -d '[:space:]') = 10 ]] ||
        fail "receipt lacks one canonical final newline"
    mapfile -t rows <"$candidate"
    [[ ${#rows[@]} -eq 12 ]] || fail "receipt must contain exactly twelve records"
    for row in "${rows[@]}"; do [[ -n $row ]] || fail "receipt contains a blank record"; done
    benchmark=${rows[0]}; aggregate=${rows[11]}
    keys_exact "$benchmark" . "$benchmark_keys"
    [[ $(field "$benchmark" record) = benchmark &&
       $(field "$benchmark" schema) = zcl.retrieval_gold_benchmark.v2 &&
       $(field "$benchmark" corpus_id) = z23-historical-agent-tasks-v1 &&
       $(field "$benchmark" mode) = run &&
       $(bool_field "$benchmark" publishable) = true &&
       $(field "$benchmark" publication_admission) = exact_observed_origin_main &&
       $(bool_field "$benchmark" promotion_authorized) = false &&
       $(field "$benchmark" driver_commit) = "$driver" &&
       $(field "$benchmark" observed_origin_main) = "$driver" &&
       $(field "$benchmark" driver_commit_semantics) = display_only_github_trace_metadata &&
       $(bool_field "$benchmark" driver_clean) = true &&
       $(root_field "$benchmark" driver_status_sha3) = "$empty_sha3" &&
       $(uint_field "$benchmark" tasks_declared 32) -eq 10 &&
       $(uint_field "$benchmark" tasks_evaluated 32) -eq 9 &&
       $(uint_field "$benchmark" tasks_unsupported 32) -eq 1 &&
       $(field "$benchmark" source_epoch_kind) = git_parent_commit &&
       $(field "$benchmark" source_root_basis) = vcs_manifest_v1_nonignored_filesystem &&
       $(field "$benchmark" relevance_judgment) = landed_changed_path_present_in_parent &&
       $(bool_field "$benchmark" original_prompts_available) = false &&
       $(bool_field "$benchmark" canonical_task_roots_available) = false &&
       $(bool_field "$benchmark" ranking_may_read_relevance) = false ]] ||
        fail "benchmark publication boundary differs"
    keys_exact "$benchmark" query_strata commit_subject_only,same_commit_unordered
    keys_exact "$benchmark" evaluated_query_strata commit_subject_only,same_commit_unordered
    [[ $(uint_field "$benchmark" query_strata.commit_subject_only 10) -eq 1 &&
       $(uint_field "$benchmark" query_strata.same_commit_unordered 10) -eq 9 &&
       $(uint_field "$benchmark" evaluated_query_strata.commit_subject_only 9) -eq 1 &&
       $(uint_field "$benchmark" evaluated_query_strata.same_commit_unordered 9) -eq 8 ]] ||
        fail "query strata differ"

    git -C "$repo_root" cat-file -e "$driver^{commit}" || fail "driver commit is unavailable"
    git -C "$repo_root" show "$driver:$corpus_path" >"$corpus_file"
    git -C "$repo_root" show "$driver:$runner_path" >"$runner_file"
    git -C "$repo_root" show "$driver:$corpus_checker_path" >"$checker_file"
    git -C "$repo_root" show "$driver:$group_source_path" >"$group_source_file"
    check_hash "$corpus_file" "$(root_field "$benchmark" corpus_sha3)"
    check_hash "$runner_file" "$(root_field "$benchmark" runner_sha3)"
    check_hash "$checker_file" "$(root_field "$benchmark" corpus_checker_script_sha3)"
    check_hash "$group_source_file" "$group_source_sha3"
    # These executable bytes were observed and sealed by the whole-receipt KAT,
    # but were not archived. Mutable build aliases are not historical evidence:
    # a later maintained build may replay the batch without becoming the binary
    # that produced it. Keep the observations well-formed and no stronger.
    for historical_binary_root in rank_binary_sha3 capture_binary_sha3 \
        evaluator_binary_sha3 jsonq_binary_sha3 sha3_helper_binary_sha3; do
        root_field "$benchmark" "$historical_binary_root" >/dev/null
    done

    mapfile -t corpus_rows <"$corpus_file"
    [[ ${#corpus_rows[@]} -eq 11 ]] || fail "driver corpus is not eleven records"
    : >"$projection"
    for ((i = 0; i < 10; i++)); do
        row=${rows[i + 1]}; corpus_row=${corpus_rows[i + 1]}
        row_schema=$(field "$row" schema)
        [[ $row_schema = zcl.retrieval_gold_benchmark_task.v4 ]] ||
            fail "task receipt is not v4 at record $((i + 2))"
        [[ $(field "$row" record) = task ]] ||
            fail "record $((i + 2)) is not a task receipt"
        id=$(field "$corpus_row" id)
        [[ $(field "$row" id) = "$id" &&
           $(root_field "$row" expected_vcs_root) = $(root_field "$corpus_row" expected_vcs_root) ]] ||
            fail "task row is not bound to corpus order/root: $id"
        eligibility=$(field "$corpus_row" index_eligibility)
        relevant_count=$(array_count "$corpus_row" relevant_paths)
        case $(field "$corpus_row" query_provenance) in
            commit_subject_only) corpus_subject=$((corpus_subject + 1)) ;;
            same_commit_unordered_*) corpus_same=$((corpus_same + 1)) ;;
            *) fail "unknown corpus query stratum: $id" ;;
        esac
        if [[ $eligibility = outside_c23_codeindex ]]; then
            keys_exact "$row" . "$unsupported_task_keys"
            [[ $(field "$row" status) = unsupported &&
               $(field "$row" reason) = outside_c23_codeindex &&
               $(bool_field "$row" membership_absence_observed) = true &&
               $(field_type "$row" literal) = null &&
               $(field_type "$row" bm25) = null &&
               $(field_type "$row" identifier_graph) = null ]] ||
                fail "unsupported task weakens its null/refusal boundary: $id"
            root_field "$row" membership_tree_root_sha3 >/dev/null
            unsupported=$((unsupported + 1))
            continue
        fi
        [[ $eligibility = c23_codeindex ]] || fail "unknown corpus eligibility: $id"
        keys_exact "$row" . "$observed_task_v4_keys"
        [[ $(field "$row" status) = observed &&
           $(field "$row" membership_join_basis) = source_stability_backed_separate_indexes &&
           $(bool_field "$row" scope_available) = true &&
           $(field "$row" scope_basis) = reviewed_relevant_codeindex_group_membership_v1 &&
           $(field "$row" scope_interpretation) = directory_taxonomy_proxy_not_semantic_scope &&
           $(field "$row" scope_classifier_epoch) = current_driver_over_exact_parent_source &&
           $(bool_field "$row" files_read_observed) = false &&
           $(bool_field "$row" reuse_success_available) = false &&
           $(bool_field "$row" unique_loc_avoided_available) = false ]] ||
            fail "observed task scope/evidence boundary differs: $id"
        root_field "$row" shared_codeindex_source_root_sha3 >/dev/null
        root_field "$row" membership_tree_root_sha3 >/dev/null
        (( $(uint_field "$row" pages 128) >= 1 )) || fail "task has zero pages: $id"
        keys_exact "$row" ranking_compute elapsed_us,budget_ms,budget_exceeded
        keys_exact "$row" all_pages wall_us,single_process,buffered_before_write
        elapsed=$(uint_field "$row" ranking_compute.elapsed_us 9223372036854775807)
        budget=$(uint_field "$row" ranking_compute.budget_ms 9223372036854)
        exceeded=$(bool_field "$row" ranking_compute.budget_exceeded)
        expected_exceeded=false
        ((elapsed > budget * 1000)) && expected_exceeded=true
        [[ $exceeded = "$expected_exceeded" ]] ||
            fail "ranking-compute budget formula differs: $id"
        all_wall=$(uint_field "$row" all_pages.wall_us 9223372036854775807)
        ((all_wall >= elapsed)) ||
            fail "all-page wall time is below ranking compute: $id"
        [[ $(bool_field "$row" all_pages.single_process) = true &&
           $(bool_field "$row" all_pages.buffered_before_write) = true ]] ||
            fail "v4 all-page transport boundary differs: $id"
        for arm in literal bm25; do
            keys_exact "$row" "$arm" "$arm_keys"
            retained=$(uint_field "$row" "$arm.retained_files" 128)
            complete=$(bool_field "$row" "$arm.ranking_complete")
            ranking_root=$(root_field "$row" "$arm.ranking_root_sha3")
            context=$(uint_field "$row" "$arm.projected_context_bytes_at_5" 9223372036854775807)
            tokens=$(uint_field "$row" "$arm.approximate_tokens_at_5" 9223372036854775807)
            [[ $tokens -eq $(((context + 3) / 4)) ]] || fail "$arm task token formula differs: $id"
            take=$retained; ((take > 5)) && take=5
            if [[ $arm = literal ]]; then
                literal_roots[$observed]=$ranking_root
                literal_complete[$observed]=$complete
                literal_counts[$observed]=$retained
                literal_files=$((literal_files + take)); literal_context=$((literal_context + context))
            else
                bm25_roots[$observed]=$ranking_root
                bm25_complete[$observed]=$complete
                bm25_counts[$observed]=$retained
                bm25_contexts[$observed]=$context
                bm25_files=$((bm25_files + take)); bm25_context=$((bm25_context + context))
            fi
        done
        keys_exact "$row" identifier_graph "$graph_arm_keys"
        retained=$(uint_field "$row" identifier_graph.retained_files 128)
        complete=$(bool_field "$row" identifier_graph.ranking_complete)
        ranking_root=$(root_field "$row" identifier_graph.ranking_root_sha3)
        context=$(uint_field "$row" identifier_graph.projected_context_bytes_at_5 9223372036854775807)
        tokens=$(uint_field "$row" identifier_graph.approximate_tokens_at_5 9223372036854775807)
        [[ $tokens -eq $(((context + 3) / 4)) &&
           $(field "$row" identifier_graph.basis) = bm25_top20_rare_identifier_atom_df16_observed_reverse_refs_context_guard_v1 &&
           $(field "$row" identifier_graph.index_scan_completeness) = unobserved &&
           $(field "$row" identifier_graph.graph_evidence_kind) = observed_reverse_refs_not_resolved_calls &&
           $(field "$row" identifier_graph.vector_evidence) = not_used &&
           $(field "$row" identifier_graph.candidate_set) = strict_bm25_retained_permutation ]] ||
            fail "identifier-graph evidence boundary differs: $id"
        graph_roots[$observed]=$ranking_root
        graph_complete[$observed]=$complete
        graph_counts[$observed]=$retained
        graph_contexts[$observed]=$context
        graph_seed_counts[$observed]=$(uint_field "$row" identifier_graph.identifier_seed_symbols 512)
        graph_ref_files[$observed]=$(uint_field "$row" identifier_graph.observed_reverse_ref_files 128)
        graph_saturated[$observed]=$(bool_field "$row" identifier_graph.query_lookup_saturated)
        graph_fallback[$observed]=$(field "$row" identifier_graph.fallback_reason)
        graph_evidence[$observed]=$(bool_field "$row" identifier_graph.evidence_available)
        take=$retained; ((take > 5)) && take=5
        graph_files=$((graph_files + take)); graph_context=$((graph_context + context))
        rank_task_ids[$observed]=$id
        printf 'task %s %s\nquery %s\n' "$id" "$relevant_count" "$(field "$corpus_row" query)" >>"$projection"
        scope_group_file="$tmp/scope-groups-$observed"
        : >"$scope_group_file"
        for ((retained = 0; retained < relevant_count; retained++)); do
            relevant_path=$(field "$corpus_row" "relevant_paths[$retained]")
            printf 'relevant %s\n' "$relevant_path" >>"$projection"
            group_for_path "$relevant_path" >>"$scope_group_file"
            printf '\n' >>"$scope_group_file"
        done
        sort -u -o "$scope_group_file" "$scope_group_file"
        relevance_total=$((relevance_total + relevant_count)); observed=$((observed + 1))
        case $(field "$corpus_row" query_provenance) in
            commit_subject_only) eval_subject=$((eval_subject + 1)) ;;
            same_commit_unordered_*) eval_same=$((eval_same + 1)) ;;
        esac
    done
    [[ $observed -eq 9 && $unsupported -eq 1 && $relevance_total -eq 43 &&
       $corpus_subject -eq 1 && $corpus_same -eq 9 &&
       $eval_subject -eq 1 && $eval_same -eq 8 ]] || fail "task/strata/relevance denominator differs"

    batch="$tmp/evaluator.batch"
    graph_batch="$tmp/identifier-graph-evaluator.batch"
    decode_sealed_batch "$benchmark" evaluator_batch 73408 \
        abd5b8845eaa99ab67966d0050e962df1c44598e8c35e6613a397818ff21c250 \
        "$batch"
    decode_sealed_batch "$benchmark" identifier_graph_evaluator_batch 73408 \
        1bf1809102bc4534b3dfb34be6f407992d86e536989bdf2e21a44fc5574c0f1c \
        "$graph_batch"
    for observed_batch in "$batch" "$graph_batch"; do
        awk '
        $1 == "task" { remaining=$3; print; want_query=1; next }
        want_query { print; want_query=0; next }
        remaining > 0 { print; remaining--; next }
        ' "$observed_batch" >"$observed_projection"
        cmp -s "$projection" "$observed_projection" ||
            fail "sealed batch tasks/query/relevance differ from corpus"
    done
    validate_batch_scope "$batch" "$scope_counts"
    IFS=$'\t' read -r _ literal_scope_files literal_wrong_files <"$scope_counts" ||
        fail "literal scope counts are unavailable"
    IFS=$'\t' read -r _ bm25_scope_files bm25_wrong_files < <(sed -n '2p' "$scope_counts") ||
        fail "bm25 scope counts are unavailable"
    [[ $literal_scope_files -eq $literal_files && $bm25_scope_files -eq $bm25_files ]] ||
        fail "scope denominator differs from task-unique file selections"
    literal_wrong_bp=$((literal_wrong_files * 10000 / literal_scope_files))
    bm25_wrong_bp=$((bm25_wrong_files * 10000 / bm25_scope_files))
    [[ $literal_wrong_files -eq 31 && $literal_wrong_bp -eq 7209 &&
       $bm25_wrong_files -eq 22 && $bm25_wrong_bp -eq 4888 ]] ||
        fail "wrong-directory-group known answer changed"
    replay=$("$evaluator" <"$batch") || fail "maintained evaluator refused sealed batch"
    validate_batch_scope "$graph_batch" "$graph_scope_counts"
    IFS=$'\t' read -r _ graph_literal_scope_files graph_literal_wrong_files \
        <"$graph_scope_counts" || fail "graph-batch literal scope counts are unavailable"
    IFS=$'\t' read -r _ graph_scope_files graph_wrong_files \
        < <(sed -n '2p' "$graph_scope_counts") ||
        fail "identifier-graph scope counts are unavailable"
    [[ $graph_literal_scope_files -eq $literal_files &&
       $graph_literal_wrong_files -eq $literal_wrong_files &&
       $graph_scope_files -eq $graph_files ]] ||
        fail "identifier-graph scope denominator differs"
    graph_wrong_bp=$((graph_wrong_files * 10000 / graph_scope_files))
    [[ $graph_wrong_files -eq 21 && $graph_wrong_bp -eq 4666 ]] ||
        fail "identifier-graph wrong-directory-group known answer changed"
    graph_replay=$("$evaluator" <"$graph_batch") ||
        fail "maintained evaluator refused sealed identifier-graph batch"

    # Reconstruct strict rank TSVs from both independently sealed batches.
    extract_batch_rankings "$batch" baseline "$rank_task_map"
    local graph_rank_task_map="$tmp/graph-rank-tasks.tsv"
    extract_batch_rankings "$graph_batch" graph "$graph_rank_task_map"
    [[ $(wc -l <"$rank_task_map" | tr -d '[:space:]') -eq $observed &&
       $(wc -l <"$graph_rank_task_map" | tr -d '[:space:]') -eq $observed ]] ||
        fail "sealed batch task count differs from observed receipts"
    for ((rank_index = 0; rank_index < observed; rank_index++)); do
        arm_index=$((rank_index + 1))
        batch_task_id=$(awk -F '\t' -v wanted="$arm_index" \
            '$1 == wanted { print $2 }' "$rank_task_map")
        graph_batch_task_id=$(awk -F '\t' -v wanted="$arm_index" \
            '$1 == wanted { print $2 }' "$graph_rank_task_map")
        [[ $batch_task_id = "${rank_task_ids[$rank_index]}" &&
           $graph_batch_task_id = "$batch_task_id" ]] ||
            fail "sealed batch task order differs at rank task $arm_index"
        for arm in literal bm25; do
            IFS=$'\t' read -r meta_complete meta_count \
                <"$tmp/baseline-rank-$arm_index-$arm.meta" ||
                fail "missing sealed $arm rank metadata: $batch_task_id"
            if [[ $arm = literal ]]; then
                complete=${literal_complete[$rank_index]}
                retained=${literal_counts[$rank_index]}
                ranking_root=${literal_roots[$rank_index]}
            else
                complete=${bm25_complete[$rank_index]}
                retained=${bm25_counts[$rank_index]}
                ranking_root=${bm25_roots[$rank_index]}
            fi
            [[ $complete = true ]] && complete=1 || complete=0
            [[ $meta_complete = "$complete" && $meta_count = "$retained" ]] ||
                fail "$arm batch declaration differs from task receipt: $batch_task_id"
            observed_root=$(awk -F '\t' '{ print $1 "\t" $2 "\t" $5 }' \
                "$tmp/baseline-rank-$arm_index-$arm.tsv" | \
                "$evaluator" --rank-root "$complete") ||
                fail "$arm batch ranking-root replay failed: $batch_task_id"
            [[ $observed_root = "$ranking_root" ]] ||
                fail "$arm batch ranking root differs from task receipt: $batch_task_id"
        done

        # Graph-batch literal is a control and must be byte-identical to the
        # baseline literal. Its bm25 slot carries the identifier-graph arm.
        cmp -s "$tmp/baseline-rank-$arm_index-literal.tsv" \
            "$tmp/graph-rank-$arm_index-literal.tsv" ||
            fail "graph-batch literal diverges: $batch_task_id"
        cmp -s "$tmp/baseline-rank-$arm_index-literal.meta" \
            "$tmp/graph-rank-$arm_index-literal.meta" ||
            fail "graph-batch literal metadata diverges: $batch_task_id"
        validate_scope_rank_contract \
            "$tmp/baseline-rank-$arm_index-literal.tsv" \
            "$tmp/scope-groups-$rank_index" "$batch_task_id" literal
        validate_scope_rank_contract \
            "$tmp/baseline-rank-$arm_index-bm25.tsv" \
            "$tmp/scope-groups-$rank_index" "$batch_task_id" bm25
        validate_scope_rank_contract \
            "$tmp/graph-rank-$arm_index-bm25.tsv" \
            "$tmp/scope-groups-$rank_index" "$batch_task_id" identifier-graph
        IFS=$'\t' read -r meta_complete meta_count \
            <"$tmp/graph-rank-$arm_index-bm25.meta" ||
            fail "missing graph rank metadata: $batch_task_id"
        complete=${graph_complete[$rank_index]}
        [[ $complete = true ]] && complete=1 || complete=0
        [[ $meta_complete = "$complete" &&
           $meta_count = "${graph_counts[$rank_index]}" ]] ||
            fail "graph batch declaration differs from task receipt: $batch_task_id"
        observed_root=$(awk -F '\t' '{ print $1 "\t" $2 "\t" $5 }' \
            "$tmp/graph-rank-$arm_index-bm25.tsv" | \
            "$evaluator" --rank-root "$complete") ||
            fail "graph batch ranking-root replay failed: $batch_task_id"
        [[ $observed_root = "${graph_roots[$rank_index]}" ]] ||
            fail "graph batch ranking root differs from task receipt: $batch_task_id"

        local bm25_tsv="$tmp/baseline-rank-$arm_index-bm25.tsv"
        local graph_tsv="$tmp/graph-rank-$arm_index-bm25.tsv"
        validate_graph_rank_contract "$bm25_tsv" "$graph_tsv" \
            "$batch_task_id" "${bm25_complete[$rank_index]}" \
            "${graph_complete[$rank_index]}" "${bm25_counts[$rank_index]}" \
            "${graph_counts[$rank_index]}" "${bm25_contexts[$rank_index]}" \
            "${graph_contexts[$rank_index]}" "${graph_seed_counts[$rank_index]}" \
            "${graph_ref_files[$rank_index]}" "${graph_saturated[$rank_index]}" \
            "${graph_fallback[$rank_index]}" "${graph_evidence[$rank_index]}"
    done

    keys_exact "$aggregate" . "$aggregate_keys"
    [[ $(field "$aggregate" record) = aggregate &&
       $(field "$aggregate" schema) = zcl.retrieval_gold_benchmark_aggregate.v3 &&
       $(bool_field "$aggregate" files_read_observed) = false &&
       $(bool_field "$aggregate" observed_token_count_available) = false &&
       $(field "$aggregate" wrong_scope_basis) = reviewed_relevant_codeindex_group_membership_v1 &&
       $(field "$aggregate" wrong_scope_interpretation) = directory_taxonomy_proxy_not_semantic_scope &&
       $(field "$aggregate" wrong_scope_classifier_epoch) = current_driver_over_exact_parent_source &&
       $(field "$aggregate" wrong_scope_aggregation_kind) = micro_task_file_selections_at_5 &&
       $(field "$aggregate" wrong_scope_denominator_kind) = sum_of_task_unique_file_selections_at_5 &&
       $(bool_field "$aggregate" reuse_success_available) = false &&
       $(bool_field "$aggregate" duplicate_avoidance_available) = false &&
       $(bool_field "$aggregate" new_unique_loc_avoided_available) = false ]] ||
        fail "aggregate scope/evidence boundary differs"
    metrics=$(raw_field "$aggregate" metrics)
    validate_eval_replay_envelope "$replay" baseline
    validate_eval_replay_envelope "$graph_replay" identifier-graph
    [[ $(raw_field "$graph_replay" literal) = $(raw_field "$replay" literal) ]] ||
        fail "graph evaluator literal metrics diverge from baseline"
    graph_arm=$(raw_field "$graph_replay" bm25)
    expected_metrics=${replay/"zcl.retrieval_eval_batch_result.v3"/"zcl.retrieval_eval_batch_result.v4"}
    expected_metrics="${expected_metrics%?},\"identifier_graph\":$graph_arm}"
    [[ $metrics = "$expected_metrics" ]] ||
        fail "aggregate metrics differ from the two evaluator replays"
    keys_exact "$metrics" . "$eval_keys"
    [[ $(field "$metrics" schema) = zcl.retrieval_eval_batch_result.v4 &&
       $(uint_field "$metrics" tasks_evaluated 32) -eq 9 &&
       $(field "$metrics" aggregation_kind) = macro_equal_task_weight &&
       $(uint_field "$metrics" tasks_denominator 32) -eq 9 &&
       $(uint_field "$metrics" eligible_relevance_judgments 4096) -eq 43 &&
       $(field "$metrics" binding_kind) = metrics_only_runner_seals_provenance &&
       $(field "$metrics" context_cost_kind) = projected_not_read &&
       $(field "$metrics" token_basis) = 'ceil(context_bytes/4)' ]] ||
        fail "evaluator aggregation contract differs"
    validate_eval_arm "$metrics" literal "$literal_files" "$literal_context" "$literal_wrong_bp"
    validate_eval_arm "$metrics" bm25 "$bm25_files" "$bm25_context" "$bm25_wrong_bp"
    validate_eval_arm "$metrics" identifier_graph "$graph_files" "$graph_context" "$graph_wrong_bp"
    [[ $(raw_field "$metrics" bm25.recall_at_20) = \
       $(raw_field "$metrics" identifier_graph.recall_at_20) ]] ||
        fail "identifier-graph Recall@20 differs from BM25"
}

validate_canonical() {
    [[ $receipt = "$repo_root/docs/work/retrieval-gold-evidence/$receipt_name" ]] ||
        fail "internal canonical receipt path differs"
    [[ ${receipt##*/} = *"${driver:0:12}"* ]] || fail "receipt filename omits driver prefix"
    check_hash "$receipt" "$receipt_sha3"
    validate_semantics "$receipt"
}

expect_semantic_refusal() {
    local name=$1 candidate=$2
    if "$0" --semantic-fixture "$candidate" >/dev/null 2>&1; then
        fail "mutation was accepted: $name"
    fi
}

selftest() {
    local bad bad_replay benchmark replay i bytes available in_scope path mutations=0
    local base_tsv="$tmp/graph-contract-base.tsv"
    local graph_tsv="$tmp/graph-contract-graph.tsv"
    local groups="$tmp/graph-contract.groups"
    "$0" --semantic-fixture "$receipt" >/dev/null
    benchmark=$(sed -n '1p' "$receipt")
    decode_sealed_batch "$benchmark" evaluator_batch 73408 \
        abd5b8845eaa99ab67966d0050e962df1c44598e8c35e6613a397818ff21c250 \
        "$tmp/evaluator.batch"
    decode_sealed_batch "$benchmark" identifier_graph_evaluator_batch 73408 \
        1bf1809102bc4534b3dfb34be6f407992d86e536989bdf2e21a44fc5574c0f1c \
        "$tmp/graph.batch"
    for sealed in "$tmp/evaluator.batch" "$tmp/graph.batch"; do
        bad="$tmp/top-five-scope-$mutations.batch"
        sed '0,/^rank \([0-9][0-9]*\) 1 [01] /s//rank \1 0 0 /' "$sealed" >"$bad"
        if (validate_batch_scope "$bad" "$tmp/scope.counts" >/dev/null 2>&1); then
            fail "top-five missing-scope mutation was accepted"
        fi
        mutations=$((mutations + 1))
        bad="$tmp/post-five-scope-$mutations.batch"
        awk 'BEGIN { OFS=" " } $1 == "rank" { seen++; if (seen == 6) { $3=1; $4=0 } } { print }' \
            "$sealed" >"$bad"
        if (validate_batch_scope "$bad" "$tmp/scope.counts" >/dev/null 2>&1); then
            fail "post-five invented-scope mutation was accepted"
        fi
        mutations=$((mutations + 1))
    done

    replay=$("$evaluator" <"$tmp/graph.batch") ||
        fail "selftest evaluator refused canonical graph batch"
    bad_replay=${replay/zcl.retrieval_eval_batch_result.v3/zcl.retrieval_eval_batch_result.v2}
    if (validate_eval_replay_envelope "$bad_replay" selftest-schema >/dev/null 2>&1); then
        fail "graph evaluator schema mutation was accepted"
    fi
    mutations=$((mutations + 1))
    bad_replay=${replay/\"tasks_denominator\":9/\"tasks_denominator\":8}
    if (validate_eval_replay_envelope "$bad_replay" selftest-denominator >/dev/null 2>&1); then
        fail "graph evaluator denominator mutation was accepted"
    fi
    mutations=$((mutations + 1))

    : >"$base_tsv"
    printf 'lib/net\n' >"$groups"
    for ((i = 1; i <= 21; i++)); do
        bytes=10; ((i == 6)) && bytes=100
        if ((i % 2)); then
            in_scope=1; path=$(printf 'lib/net/file-%02d.c' "$i")
        else
            in_scope=0; path=$(printf 'lib/test/file-%02d.c' "$i")
        fi
        available=1
        if ((i > 5)); then available=0; in_scope=0; fi
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$i" "$bytes" "$available" "$in_scope" "$path" >>"$base_tsv"
    done
    cp -- "$base_tsv" "$graph_tsv"
    validate_scope_rank_contract "$base_tsv" "$groups" selftest bm25
    validate_graph_rank_contract "$base_tsv" "$graph_tsv" selftest \
        false false 21 21 50 50 1 0 false none true
    bad="$tmp/graph-byte.tsv"; cp -- "$graph_tsv" "$bad"
    sed '21s/10/11/' "$bad" >"$bad.next" && mv -- "$bad.next" "$bad"
    if (validate_graph_rank_contract "$base_tsv" "$bad" byte \
        false false 21 21 50 50 1 0 false none true >/dev/null 2>&1); then
        fail "graph path/context mutation was accepted"
    fi
    mutations=$((mutations + 1))
    bad="$tmp/graph-scope.tsv"
    awk -F '\t' 'BEGIN { OFS="\t" } $1 == 1 { s=$4; $4=0 }
        $1 == 2 { $4=s } { print }' "$graph_tsv" >"$bad"
    if (validate_scope_rank_contract "$bad" "$groups" scope-binding graph \
        >/dev/null 2>&1); then
        fail "graph path/scope mutation was accepted"
    fi
    mutations=$((mutations + 1))
    bad="$tmp/graph-top20.tsv"
    awk -F '\t' 'BEGIN { OFS="\t" } $1 == 20 { p=$5; $5="lib/net/file-21.c" }
        $1 == 21 { $5=p } { print }' "$graph_tsv" >"$bad"
    if (validate_graph_rank_contract "$base_tsv" "$bad" top20 \
        false false 21 21 50 50 1 0 false none true >/dev/null 2>&1); then
        fail "graph top-20 mutation was accepted"
    fi
    mutations=$((mutations + 1))
    bad="$tmp/graph-context.tsv"
    awk -F '\t' 'BEGIN { OFS="\t" } $1 == 5 { p=$5; b=$2; s=$4; $5="lib/test/file-06.c"; $2=100; $4=0 }
        $1 == 6 { $5=p; $2=b; $4=s } { print }' "$graph_tsv" >"$bad"
    if (validate_graph_rank_contract "$base_tsv" "$bad" context \
        false false 21 21 50 140 1 0 false none true >/dev/null 2>&1); then
        fail "graph context-ceiling mutation was accepted"
    fi
    mutations=$((mutations + 1))
    for contract_case in \
        'false true 21 21 50 50 1 0 false none true' \
        'false false 21 20 50 50 1 0 false none true' \
        'false false 21 21 50 50 513 0 false none true' \
        'false false 21 21 50 50 1 22 false none true' \
        'false false 21 21 50 50 0 0 false none true' \
        'false false 21 21 50 50 1 0 false none false' \
        'false false 21 21 50 50 1 0 true caller_cap false' \
        'false false 21 21 50 50 0 1 true caller_cap false' \
        'false false 21 21 50 50 1 0 false no_window_evidence true' \
        'false false 21 21 50 50 1 0 false mystery false'; do
        read -r -a args <<<"$contract_case"
        if (validate_graph_rank_contract "$base_tsv" "$graph_tsv" state \
            "${args[@]}" >/dev/null 2>&1); then
            fail "graph contract-state mutation was accepted: $contract_case"
        fi
        mutations=$((mutations + 1))
    done

    bad="$tmp/publishable.jsonl"; sed 's/"publishable":true/"publishable":false/' "$receipt" >"$bad"
    expect_semantic_refusal publishable "$bad"; mutations=$((mutations + 1))
    bad="$tmp/benchmark-schema.jsonl"; sed '1s/zcl.retrieval_gold_benchmark.v2/zcl.retrieval_gold_benchmark.v1/' "$receipt" >"$bad"
    expect_semantic_refusal benchmark-schema "$bad"; mutations=$((mutations + 1))
    bad="$tmp/task-schema.jsonl"; sed '2s/zcl.retrieval_gold_benchmark_task.v4/zcl.retrieval_gold_benchmark_task.v3/' "$receipt" >"$bad"
    expect_semantic_refusal task-schema "$bad"; mutations=$((mutations + 1))
    bad="$tmp/driver.jsonl"; sed 's/25fe3e353288d2f52e7f5fc07b7b722b27e71f1a/25fe3e353288d2f52e7f5fc07b7b722b27e71f1b/' "$receipt" >"$bad"
    expect_semantic_refusal driver "$bad"; mutations=$((mutations + 1))
    bad="$tmp/graph-bytes.jsonl"; sed 's/"identifier_graph_evaluator_batch_bytes":73408/"identifier_graph_evaluator_batch_bytes":73409/' "$receipt" >"$bad"
    expect_semantic_refusal graph-bytes "$bad"; mutations=$((mutations + 1))
    bad="$tmp/graph-base64.jsonl"; sed 's/"identifier_graph_evaluator_batch_base64":"e/"identifier_graph_evaluator_batch_base64":"!/' "$receipt" >"$bad"
    expect_semantic_refusal graph-base64 "$bad"; mutations=$((mutations + 1))
    bad="$tmp/graph-root.jsonl"; sed 's/1bf1809102bc4534b3dfb34be6f407992d86e536989bdf2e21a44fc5574c0f1c/0bf1809102bc4534b3dfb34be6f407992d86e536989bdf2e21a44fc5574c0f1c/' "$receipt" >"$bad"
    expect_semantic_refusal graph-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/unsupported-graph.jsonl"; sed '0,/"identifier_graph":null/s//"identifier_graph":{}/' "$receipt" >"$bad"
    expect_semantic_refusal unsupported-graph "$bad"; mutations=$((mutations + 1))
    bad="$tmp/basis.jsonl"; sed '2s/bm25_top20_rare_identifier_atom_df16_observed_reverse_refs_context_guard_v1/bm25_top20_identifier_v0/' "$receipt" >"$bad"
    expect_semantic_refusal basis "$bad"; mutations=$((mutations + 1))
    bad="$tmp/vector.jsonl"; sed '2s/"vector_evidence":"not_used"/"vector_evidence":"proof"/' "$receipt" >"$bad"
    expect_semantic_refusal vector "$bad"; mutations=$((mutations + 1))
    bad="$tmp/saturation.jsonl"; sed '2s/"query_lookup_saturated":false/"query_lookup_saturated":true/' "$receipt" >"$bad"
    expect_semantic_refusal saturation "$bad"; mutations=$((mutations + 1))
    bad="$tmp/evidence.jsonl"; sed '2s/"evidence_available":true/"evidence_available":false/' "$receipt" >"$bad"
    expect_semantic_refusal evidence "$bad"; mutations=$((mutations + 1))
    bad="$tmp/fallback.jsonl"; sed '2s/"fallback_reason":"none"/"fallback_reason":"mystery"/' "$receipt" >"$bad"
    expect_semantic_refusal fallback "$bad"; mutations=$((mutations + 1))
    bad="$tmp/aggregate-schema.jsonl"; sed '$s/zcl.retrieval_gold_benchmark_aggregate.v3/zcl.retrieval_gold_benchmark_aggregate.v2/' "$receipt" >"$bad"
    expect_semantic_refusal aggregate-schema "$bad"; mutations=$((mutations + 1))
    bad="$tmp/aggregate-graph.jsonl"; sed '$s/"basis_points":1243/"basis_points":1244/' "$receipt" >"$bad"
    expect_semantic_refusal aggregate-graph "$bad"; mutations=$((mutations + 1))
    bad="$tmp/delete.jsonl"; sed '2d' "$receipt" >"$bad"
    expect_semantic_refusal record-deletion "$bad"; mutations=$((mutations + 1))
    printf 'retrieval-gold-identifier-graph-receipt-check: SELFTEST PASS mutations=%s\n' \
        "$mutations"
}

cleanup() { [[ -z ${tmp:-} ]] || rm -r -- "$tmp"; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-identifier-graph-receipt-check.XXXXXX")
trap cleanup EXIT HUP INT TERM
for executable in "$jsonq" "$sha3" "$evaluator"; do
    [[ -x $executable ]] || fail "required executable is unavailable: $executable"
done
command -v base64 >/dev/null 2>&1 || fail "base64 is unavailable"

case ${1:---check} in
    --check)
        [[ $# -eq 1 ]] || fail "--check takes no receipt override"
        validate_canonical
        printf 'retrieval-gold-identifier-graph-receipt-check: PASS records=12 tasks=10 evaluated=9 unsupported=1 relevance=43 two_batch_replay=true graph_contract=top20_context_guard vector_evidence=not_used historical_binary_identity=observation_unverified receipt_sha3=%s\n' "$receipt_sha3" ;;
    --selftest)
        [[ $# -eq 1 ]] || fail "--selftest takes no arguments"
        selftest ;;
    --semantic-fixture)
        [[ $# -eq 2 ]] || fail "--semantic-fixture requires one path"
        validate_semantics "$2" ;;
    *)
        printf 'usage: %s [--check|--selftest]\n' "$0" >&2
        exit 64 ;;
esac
