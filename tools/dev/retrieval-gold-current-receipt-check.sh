#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Verify the frozen ten-task publishable retrieval benchmark without rerunning
# ranking.  The earlier b663 receipt has a separate immutable checker.

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
. "$repo_root/tools/scripts/source_identity_lib.sh" # zcl_is_sha256
readonly driver=476e6666152337f2419236601dceee793d6a980a
readonly receipt_name=retrieval-gold-benchmark-476e66661523.jsonl
readonly receipt="$repo_root/docs/work/retrieval-gold-evidence/$receipt_name"
readonly receipt_sha3=acc6a9d8c9af5fbb17d3598abb39075e49dc27a4ae9445184bcb045beb99e491
readonly empty_sha3=a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
readonly corpus_path=docs/work/RETRIEVAL_GOLD_CORPUS.jsonl
readonly runner_path=tools/dev/retrieval-gold-benchmark.sh
readonly corpus_checker_path=tools/dev/retrieval-gold-corpus-check.sh
jsonq=${ZCL_JSONQ:-$repo_root/build/bin/jsonq}
sha3=${ZCL_AGENT_SHA3:-$repo_root/build/bin/agent_sha3}
evaluator=${ZCL_RETRIEVAL_EVAL:-$repo_root/build/bin/retrieval-eval}
tmp=''

readonly benchmark_keys='record,schema,corpus_id,mode,publishable,publication_admission,promotion_authorized,driver_commit,driver_commit_semantics,observed_origin_main,driver_clean,driver_status_sha3,tasks_declared,tasks_evaluated,tasks_unsupported,source_epoch_kind,source_root_basis,relevance_judgment,query_strata,commit_subject_only,same_commit_unordered,evaluated_query_strata,commit_subject_only,same_commit_unordered,original_prompts_available,canonical_task_roots_available,ranking_may_read_relevance,rank_binary_sha3,capture_binary_sha3,evaluator_binary_sha3,jsonq_binary_sha3,sha3_helper_binary_sha3,corpus_checker_script_sha3,corpus_sha3,runner_sha3,evaluator_batch_bytes,evaluator_batch_encoding,evaluator_batch_base64,evaluator_batch_root_sha3'
readonly observed_task_v2_keys='record,schema,id,status,expected_vcs_root,shared_codeindex_source_root_sha3,membership_tree_root_sha3,membership_join_basis,pages,ranking_compute,elapsed_us,budget_ms,budget_exceeded,all_pages,wall_us,single_process,buffered_before_write,literal,retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,bm25,retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5,scope_available,files_read_observed,reuse_success_available,unique_loc_avoided_available'
readonly unsupported_task_keys='record,schema,id,status,reason,expected_vcs_root,membership_tree_root_sha3,membership_absence_observed,literal,bm25'
readonly arm_keys='retained_files,ranking_complete,ranking_root_sha3,projected_context_bytes_at_5,approximate_tokens_at_5'
readonly metric_keys='available,basis_points'
readonly eval_arm_keys='recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly eval_keys='schema,tasks_evaluated,aggregation_kind,tasks_denominator,eligible_relevance_judgments,binding_kind,context_cost_kind,token_basis,literal,recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points,bm25,recall_at_5,available,basis_points,recall_at_20,available,basis_points,mrr,available,basis_points,task_unique_file_selections_at_5,projected_context_bytes_at_5,approximate_tokens_at_5,wrong_scope_at_5,available,basis_points'
readonly aggregate_keys="record,schema,metrics,$eval_keys,files_read_observed,observed_token_count_available,wrong_scope_basis,reuse_success_available,duplicate_avoidance_available,new_unique_loc_avoided_available"

fail() { printf 'retrieval-gold-current-receipt-check: FAIL — %s\n' "$*" >&2; exit 1; }

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
    zcl_is_sha256 "$value" || fail "invalid SHA3 root: $2"
    printf '%s' "$value"
}

hash_file() {
    local output root
    output=$("$sha3" "$1") || fail "cannot hash file: $1"
    root=${output%% *}
    zcl_is_sha256 "$root" || fail "malformed file hash: $1"
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
    local document=$1 arm=$2 expected_files=$3 expected_context=$4
    local actual_files actual_context actual_tokens
    keys_exact "$document" "$arm" "$eval_arm_keys"
    validate_metric "$document" "$arm.recall_at_5"
    validate_metric "$document" "$arm.recall_at_20"
    validate_metric "$document" "$arm.mrr"
    validate_metric "$document" "$arm.wrong_scope_at_5"
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = false &&
       $(field_type "$document" "$arm.wrong_scope_at_5.basis_points") = null ]] ||
        fail "$arm wrong-scope overclaims unavailable evidence"
    actual_files=$(uint_field "$document" "$arm.task_unique_file_selections_at_5" 3840)
    actual_context=$(uint_field "$document" "$arm.projected_context_bytes_at_5" 9223372036854775807)
    actual_tokens=$(uint_field "$document" "$arm.approximate_tokens_at_5" 9223372036854775807)
    [[ $actual_files -eq $expected_files && $actual_context -eq $expected_context &&
       $actual_tokens -eq $(((expected_context + 3) / 4)) ]] ||
        fail "$arm aggregate cost formula differs"
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

validate_semantics() {
    local candidate=$1 benchmark aggregate batch replay metrics row_schema
    local bytes encoded_chars corpus runner checker i row corpus_row id eligibility relevant_count
    local corpus_subject=0 corpus_same=0 eval_subject=0 eval_same=0
    local observed=0 unsupported=0 relevance_total=0
    local literal_files=0 bm25_files=0 literal_context=0 bm25_context=0
    local retained context tokens take elapsed budget exceeded expected_exceeded
    local all_wall
    local complete ranking_root rank_index arm_index meta_complete meta_count
    local batch_task_id observed_root
    local corpus_file="$tmp/corpus.jsonl" runner_file="$tmp/runner.sh"
    local checker_file="$tmp/corpus-checker.sh" projection="$tmp/expected.projection"
    local encoded_file="$tmp/evaluator.batch.base64" reencoded_file="$tmp/evaluator.batch.reencoded"
    local observed_projection="$tmp/observed.projection"
    local rank_task_map="$tmp/rank-tasks.tsv"
    local -a rank_task_ids literal_roots literal_complete literal_counts
    local -a bm25_roots bm25_complete bm25_counts

    [[ -f $candidate ]] || fail "receipt is absent: $candidate"
    [[ $(tail -c 1 "$candidate" | od -An -tuC | tr -d '[:space:]') = 10 ]] ||
        fail "receipt lacks one canonical final newline"
    mapfile -t rows <"$candidate"
    [[ ${#rows[@]} -eq 12 ]] || fail "receipt must contain exactly twelve records"
    for row in "${rows[@]}"; do [[ -n $row ]] || fail "receipt contains a blank record"; done
    benchmark=${rows[0]}; aggregate=${rows[11]}
    keys_exact "$benchmark" . "$benchmark_keys"
    [[ $(field "$benchmark" record) = benchmark &&
       $(field "$benchmark" schema) = zcl.retrieval_gold_benchmark.v1 &&
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
    check_hash "$corpus_file" "$(root_field "$benchmark" corpus_sha3)"
    check_hash "$runner_file" "$(root_field "$benchmark" runner_sha3)"
    check_hash "$checker_file" "$(root_field "$benchmark" corpus_checker_script_sha3)"
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
        [[ $row_schema = zcl.retrieval_gold_benchmark_task.v2 ]] ||
            fail "task receipt is not v2 at record $((i + 2))"
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
               $(field_type "$row" bm25) = null ]] ||
                fail "unsupported task weakens its null/refusal boundary: $id"
            root_field "$row" membership_tree_root_sha3 >/dev/null
            unsupported=$((unsupported + 1))
            continue
        fi
        [[ $eligibility = c23_codeindex ]] || fail "unknown corpus eligibility: $id"
        keys_exact "$row" . "$observed_task_v2_keys"
        [[ $(field "$row" status) = observed &&
           $(field "$row" membership_join_basis) = source_stability_backed_separate_indexes &&
           $(bool_field "$row" scope_available) = false &&
           $(bool_field "$row" files_read_observed) = false &&
           $(bool_field "$row" reuse_success_available) = false &&
           $(bool_field "$row" unique_loc_avoided_available) = false ]] ||
            fail "observed task overclaims unavailable evidence: $id"
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
            fail "v2 all-page transport boundary differs: $id"
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
                bm25_files=$((bm25_files + take)); bm25_context=$((bm25_context + context))
            fi
        done
        rank_task_ids[$observed]=$id
        printf 'task %s %s\nquery %s\n' "$id" "$relevant_count" "$(field "$corpus_row" query)" >>"$projection"
        for ((retained = 0; retained < relevant_count; retained++)); do
            printf 'relevant %s\n' "$(field "$corpus_row" "relevant_paths[$retained]")" >>"$projection"
        done
        relevance_total=$((relevance_total + relevant_count)); observed=$((observed + 1))
        case $(field "$corpus_row" query_provenance) in
            commit_subject_only) eval_subject=$((eval_subject + 1)) ;;
            same_commit_unordered_*) eval_same=$((eval_same + 1)) ;;
        esac
    done
    [[ $observed -eq 9 && $unsupported -eq 1 && $relevance_total -eq 43 &&
       $corpus_subject -eq 1 && $corpus_same -eq 9 &&
       $eval_subject -eq 1 && $eval_same -eq 8 ]] || fail "task/strata/relevance denominator differs"

    [[ $(field "$benchmark" evaluator_batch_encoding) = base64_rfc4648 ]] ||
        fail "unknown evaluator batch encoding"
    bytes=$(uint_field "$benchmark" evaluator_batch_bytes 1048576)
    [[ $bytes -eq 73408 ]] || fail "sealed evaluator batch byte count differs"
    # jsonq intentionally bounds returned string values below this embedded
    # batch's size.  The exact-key/type checks above establish the JSON shape;
    # extract this RFC4648-only field by its fixed adjacent keys and keep the
    # large value out of a shell variable.
    printf '%s\n' "$benchmark" | sed -n \
        's|^.*"evaluator_batch_encoding":"base64_rfc4648","evaluator_batch_base64":"\([A-Za-z0-9+/]*=\{0,2\}\)","evaluator_batch_root_sha3":"[0-9a-f]\{64\}"}$|\1|p' \
        >"$encoded_file"
    [[ -s $encoded_file && $(wc -l <"$encoded_file" | tr -d '[:space:]') -eq 1 ]] ||
        fail "evaluator batch base64 is noncanonical"
    encoded_chars=$(wc -c <"$encoded_file"); encoded_chars=${encoded_chars//[[:space:]]/}
    encoded_chars=$((encoded_chars - 1))
    ((encoded_chars > 0 && encoded_chars % 4 == 0)) ||
        fail "evaluator batch base64 length is noncanonical"
    batch="$tmp/evaluator.batch"
    tr -d '\n' <"$encoded_file" | decode_base64 >"$batch" || fail "cannot decode evaluator batch"
    [[ $(wc -c <"$batch" | tr -d '[:space:]') -eq $bytes ]] || fail "decoded batch byte count differs"
    base64 <"$batch" | tr -d '\n' >"$reencoded_file"
    tr -d '\n' <"$encoded_file" | cmp -s - "$reencoded_file" ||
        fail "batch base64 does not round-trip canonically"
    check_hash "$batch" "$(root_field "$benchmark" evaluator_batch_root_sha3)"
    [[ $(root_field "$benchmark" evaluator_batch_root_sha3) = 9c3fb75aea6cb8a486226f35e462198f33dd0f4bce6aac2cd157191e032ee6ef ]] ||
        fail "batch root differs from reviewed KAT"
    [[ $(head -n 1 "$batch") = 'zcl.retrieval_eval_batch.v3 tasks=9 eligible_relevance_judgments=43' ]] ||
        fail "evaluator batch header differs"
    awk '
        $1 == "task" { remaining=$3; print; want_query=1; next }
        want_query { print; want_query=0; next }
        remaining > 0 { print; remaining--; next }
    ' "$batch" >"$observed_projection"
    cmp -s "$projection" "$observed_projection" || fail "batch tasks/query/relevance differ from corpus"
    replay=$("$evaluator" <"$batch") || fail "maintained evaluator refused sealed batch"

    # The batch carries the complete retained rank lists. Reconstruct the same
    # strict TSV consumed by retrieval-eval --rank-root so each task receipt's
    # ranking identity is independently bound to those bytes, not merely
    # preserved by the outer whole-file KAT.
    awk -v out="$tmp" -v task_map="$rank_task_map" '
        function refuse(message) {
            print "retrieval-gold-current-receipt-check: batch rank extraction: " message > "/dev/stderr"
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
            meta = out "/rank-" task "-" arm ".meta"
            file = out "/rank-" task "-" arm ".tsv"
            print complete "\t" declared > meta
            close(meta)
            printf "%s", "" > file
            close(file)
            next
        }
        $1 == "rank" {
            if (arm == "" || NF != 5) refuse("rank outside an arm")
            ranks++
            file = out "/rank-" task "-" arm ".tsv"
            print ranks "\t" $2 "\t" $5 >> file
            close(file)
            next
        }
        END {
            if (!bad) {
                finish_arm()
                if (task != 9 || arm != "bm25") refuse("incomplete task/arm sequence")
            }
        }
    ' "$batch" || fail "could not extract exact task rankings from sealed batch"
    [[ $(wc -l <"$rank_task_map" | tr -d '[:space:]') -eq $observed ]] ||
        fail "sealed batch task count differs from observed receipts"
    for ((rank_index = 0; rank_index < observed; rank_index++)); do
        arm_index=$((rank_index + 1))
        batch_task_id=$(awk -F '\t' -v wanted="$arm_index" \
            '$1 == wanted { print $2 }' "$rank_task_map")
        [[ $batch_task_id = "${rank_task_ids[$rank_index]}" ]] ||
            fail "sealed batch task order differs at rank task $arm_index"
        for arm in literal bm25; do
            IFS=$'\t' read -r meta_complete meta_count \
                <"$tmp/rank-$arm_index-$arm.meta" ||
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
            observed_root=$("$evaluator" --rank-root "$complete" \
                <"$tmp/rank-$arm_index-$arm.tsv") ||
                fail "$arm batch ranking-root replay failed: $batch_task_id"
            [[ $observed_root = "$ranking_root" ]] ||
                fail "$arm batch ranking root differs from task receipt: $batch_task_id"
        done
    done

    keys_exact "$aggregate" . "$aggregate_keys"
    [[ $(field "$aggregate" record) = aggregate &&
       $(field "$aggregate" schema) = zcl.retrieval_gold_benchmark_aggregate.v1 &&
       $(bool_field "$aggregate" files_read_observed) = false &&
       $(bool_field "$aggregate" observed_token_count_available) = false &&
       $(field "$aggregate" wrong_scope_basis) = unavailable &&
       $(bool_field "$aggregate" reuse_success_available) = false &&
       $(bool_field "$aggregate" duplicate_avoidance_available) = false &&
       $(bool_field "$aggregate" new_unique_loc_avoided_available) = false ]] ||
        fail "aggregate overclaims unavailable evidence"
    metrics=$(raw_field "$aggregate" metrics)
    [[ $metrics = "$replay" ]] || fail "aggregate metrics differ from evaluator replay"
    keys_exact "$metrics" . "$eval_keys"
    [[ $(field "$metrics" schema) = zcl.retrieval_eval_batch_result.v3 &&
       $(uint_field "$metrics" tasks_evaluated 32) -eq 9 &&
       $(field "$metrics" aggregation_kind) = macro_equal_task_weight &&
       $(uint_field "$metrics" tasks_denominator 32) -eq 9 &&
       $(uint_field "$metrics" eligible_relevance_judgments 4096) -eq 43 &&
       $(field "$metrics" binding_kind) = metrics_only_runner_seals_provenance &&
       $(field "$metrics" context_cost_kind) = projected_not_read &&
       $(field "$metrics" token_basis) = 'ceil(context_bytes/4)' ]] ||
        fail "evaluator aggregation contract differs"
    validate_eval_arm "$metrics" literal "$literal_files" "$literal_context"
    validate_eval_arm "$metrics" bm25 "$bm25_files" "$bm25_context"
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
    local bad mutations=0
    "$0" --semantic-fixture "$receipt" >/dev/null
    bad="$tmp/wrong-path.jsonl"; sed 's/"publishable":true/"publishable":false/' "$receipt" >"$bad"
    [[ $(hash_file "$bad") != "$receipt_sha3" ]] || fail "whole-file KAT mutation did not change hash"
    expect_semantic_refusal publishable "$bad"; mutations=$((mutations + 1))
    bad="$tmp/boolean-type.jsonl"; sed 's/"publishable":true/"publishable":"true"/' "$receipt" >"$bad"
    expect_semantic_refusal boolean-type "$bad"; mutations=$((mutations + 1))
    bad="$tmp/integer-type.jsonl"; sed 's/"tasks_declared":10/"tasks_declared":"10"/' "$receipt" >"$bad"
    expect_semantic_refusal integer-type "$bad"; mutations=$((mutations + 1))
    bad="$tmp/string-type.jsonl"; sed 's/"mode":"run"/"mode":true/' "$receipt" >"$bad"
    expect_semantic_refusal string-type "$bad"; mutations=$((mutations + 1))
    bad="$tmp/root-type.jsonl"; sed 's/"driver_status_sha3":"[0-9a-f]*"/"driver_status_sha3":false/' "$receipt" >"$bad"
    expect_semantic_refusal root-type "$bad"; mutations=$((mutations + 1))
    bad="$tmp/null-type.jsonl"; sed '0,/"basis_points":null/s//"basis_points":"null"/' "$receipt" >"$bad"
    expect_semantic_refusal null-type "$bad"; mutations=$((mutations + 1))
    bad="$tmp/unknown-key.jsonl"; sed '1s/^{/{"unexpected":0,/' "$receipt" >"$bad"
    expect_semantic_refusal unknown-key "$bad"; mutations=$((mutations + 1))
    bad="$tmp/duplicate-key.jsonl"; sed '1s/"mode":"run"/"mode":"run","mode":"run"/' "$receipt" >"$bad"
    expect_semantic_refusal duplicate-key "$bad"; mutations=$((mutations + 1))
    bad="$tmp/driver.jsonl"; sed 's/476e6666152337f2419236601dceee793d6a980a/476e6666152337f2419236601dceee793d6a980b/' "$receipt" >"$bad"
    expect_semantic_refusal driver "$bad"; mutations=$((mutations + 1))
    bad="$tmp/count.jsonl"; sed 's/"tasks_evaluated":9/"tasks_evaluated":8/' "$receipt" >"$bad"
    expect_semantic_refusal count "$bad"; mutations=$((mutations + 1))
    bad="$tmp/stratum.jsonl"; sed 's/"same_commit_unordered":8/"same_commit_unordered":7/' "$receipt" >"$bad"
    expect_semantic_refusal stratum "$bad"; mutations=$((mutations + 1))
    bad="$tmp/bytes.jsonl"; sed 's/"evaluator_batch_bytes":73408/"evaluator_batch_bytes":73409/' "$receipt" >"$bad"
    expect_semantic_refusal batch-bytes "$bad"; mutations=$((mutations + 1))
    bad="$tmp/base64.jsonl"; sed 's/"evaluator_batch_base64":"e/"evaluator_batch_base64":"!/' "$receipt" >"$bad"
    expect_semantic_refusal base64 "$bad"; mutations=$((mutations + 1))
    bad="$tmp/batch-root.jsonl"; sed 's/9c3fb75aea6cb8a486226f35e462198f33dd0f4bce6aac2cd157191e032ee6ef/0c3fb75aea6cb8a486226f35e462198f33dd0f4bce6aac2cd157191e032ee6ef/' "$receipt" >"$bad"
    expect_semantic_refusal batch-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/historical-binary-root.jsonl"
    sed 's/e20b7336d85fda706a0763daa86992bd554e9522a94b4b4f321333fa16fc29b4/g20b7336d85fda706a0763daa86992bd554e9522a94b4b4f321333fa16fc29b4/' \
        "$receipt" >"$bad"
    expect_semantic_refusal historical-binary-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/denominator.jsonl"; sed 's/"tasks_denominator":9/"tasks_denominator":8/' "$receipt" >"$bad"
    expect_semantic_refusal denominator "$bad"; mutations=$((mutations + 1))
    bad="$tmp/relevance.jsonl"; sed 's/"eligible_relevance_judgments":43/"eligible_relevance_judgments":42/' "$receipt" >"$bad"
    expect_semantic_refusal relevance "$bad"; mutations=$((mutations + 1))
    bad="$tmp/aggregate-metric.jsonl"; sed '$s/"basis_points":936/"basis_points":937/' "$receipt" >"$bad"
    expect_semantic_refusal aggregate-metric "$bad"; mutations=$((mutations + 1))
    bad="$tmp/unsupported.jsonl"; sed '0,/"literal":null/s//"literal":{}/' "$receipt" >"$bad"
    expect_semantic_refusal unsupported-null "$bad"; mutations=$((mutations + 1))
    bad="$tmp/unavailable.jsonl"; sed 's/"observed_token_count_available":false/"observed_token_count_available":true/' "$receipt" >"$bad"
    expect_semantic_refusal unavailable "$bad"; mutations=$((mutations + 1))
    bad="$tmp/token.jsonl"; sed '0,/"approximate_tokens_at_5":[0-9][0-9]*/s//"approximate_tokens_at_5":0/' "$receipt" >"$bad"
    expect_semantic_refusal token-formula "$bad"; mutations=$((mutations + 1))
    bad="$tmp/ranking-root.jsonl"
    sed '0,/038b674ae2ade35f3ff02d6e89271501c6ad0ca4dec30ee318250b33dd69b196/s//138b674ae2ade35f3ff02d6e89271501c6ad0ca4dec30ee318250b33dd69b196/' \
        "$receipt" >"$bad"
    expect_semantic_refusal ranking-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/late-ranking-root.jsonl"
    sed '11s/00df2d4b42721aa81037dd147c5b5a6f213fcbbd691bae0dc02cb0028ebb2715/10df2d4b42721aa81037dd147c5b5a6f213fcbbd691bae0dc02cb0028ebb2715/' \
        "$receipt" >"$bad"
    expect_semantic_refusal late-ranking-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/ranking-budget.jsonl"
    sed '2s/"budget_exceeded":true/"budget_exceeded":false/' \
        "$receipt" >"$bad"
    expect_semantic_refusal ranking-budget "$bad"; mutations=$((mutations + 1))
    bad="$tmp/single-process.jsonl"
    sed '2s/"single_process":true/"single_process":false/' \
        "$receipt" >"$bad"
    expect_semantic_refusal single-process "$bad"; mutations=$((mutations + 1))
    bad="$tmp/buffered-before-write.jsonl"
    sed '2s/"buffered_before_write":true/"buffered_before_write":false/' \
        "$receipt" >"$bad"
    expect_semantic_refusal buffered-before-write "$bad"; mutations=$((mutations + 1))
    bad="$tmp/task-id.jsonl"
    sed '2s/"id":"zcode_embedded_nul"/"id":"zcode_embedded_null"/' \
        "$receipt" >"$bad"
    expect_semantic_refusal task-id "$bad"; mutations=$((mutations + 1))
    bad="$tmp/task-root.jsonl"
    sed '2s/e2d4ace399b8a175410076aaa7473f411efb2dead74f1f9a803487580dbbb79f/f2d4ace399b8a175410076aaa7473f411efb2dead74f1f9a803487580dbbb79f/' \
        "$receipt" >"$bad"
    expect_semantic_refusal task-root "$bad"; mutations=$((mutations + 1))
    bad="$tmp/record-deletion.jsonl"; sed '2d' "$receipt" >"$bad"
    expect_semantic_refusal record-deletion "$bad"; mutations=$((mutations + 1))
    bad="$tmp/order.jsonl"
    awk 'NR == 2 { saved = $0; next } NR == 3 { print; print saved; next } { print }' \
        "$receipt" >"$bad"
    expect_semantic_refusal task-order "$bad"; mutations=$((mutations + 1))
    bad="$tmp/mixed-task-schema.jsonl"
    sed '0,/zcl.retrieval_gold_benchmark_task.v2/s//zcl.retrieval_gold_benchmark_task.v1/' \
        "$receipt" >"$bad"
    expect_semantic_refusal mixed-task-schema "$bad"; mutations=$((mutations + 1))
    printf 'retrieval-gold-current-receipt-check: SELFTEST PASS mutations=%s\n' "$mutations"
}

cleanup() { [[ -z ${tmp:-} ]] || rm -r -- "$tmp"; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-current-receipt-check.XXXXXX")
trap cleanup EXIT HUP INT TERM
for executable in "$jsonq" "$sha3" "$evaluator"; do
    [[ -x $executable ]] || fail "required executable is unavailable: $executable"
done
command -v base64 >/dev/null 2>&1 || fail "base64 is unavailable"

case ${1:---check} in
    --check)
        [[ $# -eq 1 ]] || fail "--check takes no receipt override"
        validate_canonical
        printf 'retrieval-gold-current-receipt-check: PASS records=12 tasks=10 evaluated=9 unsupported=1 relevance=43 maintained_evaluator_replay=true historical_binary_identity=observation_unverified receipt_sha3=%s\n' "$receipt_sha3" ;;
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
