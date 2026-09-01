#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Explore context-only profiles over one exact frozen BM25 ranking cohort.

set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/../.." && pwd -P)
receipt="$root/docs/work/retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl"
checker="$root/tools/dev/retrieval-gold-identifier-graph-receipt-check.sh"
evaluator=${ZCL_RETRIEVAL_EVAL:-$root/build/bin/retrieval-eval}
jsonq=${ZCL_JSONQ:-$root/build/bin/jsonq}
sha3=${ZCL_AGENT_SHA3:-$root/build/bin/agent_sha3}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-profile-sweep.XXXXXX")
trap 'case ${tmp:-} in "${TMPDIR:-/tmp}"/z23-retrieval-profile-sweep.*) rm -r -- "$tmp" ;; esac' EXIT HUP INT TERM

fail() { printf 'retrieval-profile-sweep: FAIL — %s\n' "$*" >&2; exit 1; }
hash_file() { local value; value=$("$sha3" "$1") || return 1; printf '%s' "${value%% *}"; }

[[ ${1:-} = --check && $# -eq 1 ]] || fail "usage: $0 --check"
[[ -x $checker && -x $evaluator && -x $jsonq && -x $sha3 ]] ||
    fail "build jsonq, agent-sha3, and retrieval-eval first"
"$checker" --emit-evaluator-batches "$tmp" >/dev/null ||
    fail "frozen BM25 evidence did not verify or decode"
batch="$tmp/evaluator.batch"
[[ -s $batch ]] || fail "verified checker emitted no evaluator batch"

# Canonical context-only profile: weight=1, top_k=5, scale=1. Byte 43 is
# rerank_window and is the sole swept parameter here. This is exploratory
# replay over frozen rows, not a current-generation or holdout experiment.
base_profile=5a435250524f310a010000040000000000000000000000000000000000000000010000000000000000000006050000000100000000000000
evaluator_root=$(hash_file "$evaluator") || fail "cannot hash evaluator"
batch_root=$(hash_file "$batch") || fail "cannot hash reconstructed batch"
declare -a recall bytes pareto
transcript="$tmp/profile-transcript.jsonl"
: >"$transcript"
for ((window = 5; window <= 20; window++)); do
    printf -v window_hex '%02x' "$window"
    profile=${base_profile:0:86}${window_hex}${base_profile:88}
    row=$("$evaluator" --profile-hex "$profile" \
        --evaluator-root "$evaluator_root" <"$batch") ||
        fail "window $window evaluation was refused"
    [[ $(printf '%s\n' "$row" | "$jsonq" get schema) = zcl.retrieval_context_profile_replay.v1 &&
       $(printf '%s\n' "$row" | "$jsonq" get tasks_evaluated) = 9 &&
       $(printf '%s\n' "$row" | "$jsonq" get input_arm_binding) = bm25_is_profile_baseline &&
       $(printf '%s\n' "$row" | "$jsonq" get candidate.recall_at_20.basis_points) = 3502 &&
       $(printf '%s\n' "$row" | "$jsonq" get candidate.wrong_scope_at_5.available) = false &&
       $(printf '%s\n' "$row" | "$jsonq" get top20_membership_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get full_retained_set_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get context_ceiling_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get generation_binding) = unavailable_in_frozen_v3 &&
       $(printf '%s\n' "$row" | "$jsonq" get chronology_status) = unverified &&
       $(printf '%s\n' "$row" | "$jsonq" get holdout_independence_status) = unverified &&
       $(printf '%s\n' "$row" | "$jsonq" get replication_status) = not_run &&
       $(printf '%s\n' "$row" | "$jsonq" get promotion_authorized) = false ]] ||
        fail "window $window evidence boundary differs"
    observed_batch_root=$(printf '%s\n' "$row" | "$jsonq" get raw_batch_root_sha3)
    observed_evaluator_root=$(printf '%s\n' "$row" | "$jsonq" get caller_supplied_evaluator_root_sha3)
    result_root=$(printf '%s\n' "$row" | "$jsonq" get evaluation_result_root_sha3)
    [[ $observed_batch_root = "$batch_root" &&
       $observed_evaluator_root = "$evaluator_root" &&
       $result_root =~ ^[0-9a-f]{64}$ ]] ||
        fail "window $window exact root binding differs"
    recall[$window]=$(printf '%s\n' "$row" | "$jsonq" get candidate.recall_at_5.basis_points)
    bytes[$window]=$(printf '%s\n' "$row" | "$jsonq" get candidate.projected_context_bytes_at_5)
    printf '%s\n' "$row" >>"$transcript"
done

for ((candidate = 5; candidate <= 20; candidate++)); do
    dominated=false
    for ((peer = 5; peer <= 20; peer++)); do
        if ((recall[peer] >= recall[candidate] && bytes[peer] <= bytes[candidate] &&
             (recall[peer] > recall[candidate] || bytes[peer] < bytes[candidate]))); then
            dominated=true
        fi
    done
    [[ $dominated = true ]] || pareto+=("$candidate")
done
[[ ${recall[5]} = 936 && ${bytes[5]} = 853082 &&
   ${recall[7]} = 962 && ${bytes[7]} = 567606 &&
   ${recall[20]} = 555 && ${bytes[20]} = 226991 ]] ||
    fail "reviewed window known answers changed"
[[ ${pareto[*]} = '7 8 9 12 20' ]] ||
    fail "reviewed Pareto window set changed: ${pareto[*]}"

cat "$transcript"
receipt_root=$(hash_file "$receipt") || fail "cannot hash receipt"
script_root=$(hash_file "$root/tools/dev/retrieval-profile-sweep.sh") ||
    fail "cannot hash sweep script"
jsonq_root=$(hash_file "$jsonq") || fail "cannot hash JSON parser"
transcript_root=$(hash_file "$transcript") || fail "cannot hash transcript"
printf '{"schema":"zcl.retrieval_context_profile_sweep.v1","input_receipt_sha3":"%s","reconstructed_batch_sha3":"%s","evaluator_binary_sha3":"%s","json_parser_binary_sha3":"%s","sweep_script_sha3":"%s","candidate_transcript_sha3":"%s","windows_evaluated":16,"tasks_evaluated":9,"primary_metric":"recall_at_5","cost_metric":"projected_context_bytes_at_5","baseline_window":5,"baseline_recall_at_5_bp":936,"baseline_projected_context_bytes_at_5":853082,"exploratory_window":7,"exploratory_recall_at_5_bp":962,"exploratory_projected_context_bytes_at_5":567606,"pareto_windows":[7,8,9,12,20],"claim_scope":"counterfactual_replay_conditional_on_frozen_v3_rows","generation_binding":"unavailable","chronology_status":"unverified","holdout_independence_status":"unverified","selection_status":"retain_for_independent_replication_not_promotion","replication_status":"not_run","promotion_authorized":false}\n' \
    "$receipt_root" "$batch_root" "$evaluator_root" "$jsonq_root" \
    "$script_root" "$transcript_root"
