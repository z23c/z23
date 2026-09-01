#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Replay the one-parameter retrieval experiment over frozen reviewed evidence.

set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/../.." && pwd -P)
receipt="$root/docs/work/retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl"
checker="$root/tools/dev/retrieval-gold-identifier-graph-receipt-check.sh"
evaluator=${ZCL_RETRIEVAL_EVAL:-$root/build/bin/retrieval-eval}
jsonq=${ZCL_JSONQ:-$root/build/bin/jsonq}
sha3=${ZCL_AGENT_SHA3:-$root/build/bin/agent_sha3}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-prefix-sweep.XXXXXX")
trap 'case ${tmp:-} in "${TMPDIR:-/tmp}"/z23-retrieval-prefix-sweep.*) rm -r -- "$tmp" ;; esac' EXIT HUP INT TERM

fail() { printf 'retrieval-prefix-sweep: FAIL — %s\n' "$*" >&2; exit 1; }
[[ ${1:-} = --check && $# -eq 1 ]] || fail "usage: $0 --check"
[[ -x $checker && -x $evaluator && -x $jsonq && -x $sha3 ]] ||
    fail "build jsonq, agent-sha3, and retrieval-eval first"
"$checker" --emit-evaluator-batches "$tmp" >/dev/null ||
    fail "frozen parent evidence did not verify or decode"
mv "$tmp/evaluator.batch" "$tmp/base.batch"
mv "$tmp/identifier-graph-evaluator.batch" "$tmp/graph.batch"

# Each immutable v3 batch has two arms. Rebind the baseline batch's BM25 arm
# as the experiment base and the graph batch's BM25 slot as its parent. The
# reviewed task/query/relevance preamble comes only from the baseline batch;
# the parent checker above already proved both preambles byte-identical.
awk -v out="$tmp" '
function append(file,line) { print line >> file; close(file) }
$1 == "task" { task++; file=out "/pre-" task; append(file,$0); pre=1; rel=$3; next }
pre && $1 == "query" { append(file,$0); next }
pre && $1 == "relevant" { append(file,$0); rel--; if (rel == 0) pre=0; next }
$1 == "literal" { arm="skip"; next }
$1 == "bm25" { arm="take"; file=out "/base-" task; append(file,"literal " $2 " " $3 " " $4); next }
$1 == "rank" && arm == "take" { append(file,$0); next }
' "$tmp/base.batch"
awk -v out="$tmp" '
function append(file,line) { print line >> file; close(file) }
$1 == "task" { task++; next }
$1 == "literal" { arm="skip"; next }
$1 == "bm25" { arm="take"; file=out "/parent-" task; append(file,$0); next }
$1 == "rank" && arm == "take" { append(file,$0); next }
' "$tmp/graph.batch"

batch="$tmp/experiment.batch"
printf '%s\n' 'zcl.retrieval_eval_batch.v3 tasks=9 eligible_relevance_judgments=43' >"$batch"
for task in 1 2 3 4 5 6 7 8 9; do
    [[ -s $tmp/pre-$task && -s $tmp/base-$task && -s $tmp/parent-$task ]] ||
        fail "task $task did not reconstruct completely"
    cat "$tmp/pre-$task" "$tmp/base-$task" "$tmp/parent-$task" >>"$batch"
done
printf '%s\n' end >>"$batch"

declare -a recall bytes pareto
transcript="$tmp/candidate-transcript.jsonl"
: >"$transcript"
for prefix in 0 1 2 3 4 5; do
    row=$($evaluator --experiment-prefix "$prefix" <"$batch") ||
        fail "prefix $prefix evaluation was refused"
    [[ $(printf '%s\n' "$row" | "$jsonq" get schema) = zcl.retrieval_experiment_eval_result.v1 &&
       $(printf '%s\n' "$row" | "$jsonq" get bm25_prefix) = "$prefix" &&
       $(printf '%s\n' "$row" | "$jsonq" get tasks_evaluated) = 9 &&
       $(printf '%s\n' "$row" | "$jsonq" get candidate.recall_at_20.basis_points) = 3502 &&
       $(printf '%s\n' "$row" | "$jsonq" get top20_membership_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get full_retained_set_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get context_ceiling_preserved) = true &&
       $(printf '%s\n' "$row" | "$jsonq" get candidate.wrong_scope_at_5.available) = false &&
       $(printf '%s\n' "$row" | "$jsonq" get projector_gold_input) = none &&
       $(printf '%s\n' "$row" | "$jsonq" get promotion_authorized) = false ]] ||
        fail "prefix $prefix evidence boundary differs"
    recall[$prefix]=$(printf '%s\n' "$row" | "$jsonq" get candidate.recall_at_5.basis_points)
    bytes[$prefix]=$(printf '%s\n' "$row" | "$jsonq" get candidate.projected_context_bytes_at_5)
    printf '%s\n' "$row" >>"$transcript"
done

# Preserve the measured Pareto set: maximize Recall@5, minimize projected
# context bytes. This is a ranking view over observations, never promotion.
for candidate in 0 1 2 3 4 5; do
    dominated=false
    for peer in 0 1 2 3 4 5; do
        if ((recall[peer] >= recall[candidate] && bytes[peer] <= bytes[candidate] &&
             (recall[peer] > recall[candidate] || bytes[peer] < bytes[candidate]))); then
            dominated=true
        fi
    done
    [[ $dominated = true ]] || pareto+=("$candidate")
done
[[ ${pareto[*]} = 0 ]] || fail "reviewed Pareto known answer changed"
cat "$transcript"
receipt_root=$($sha3 "$receipt"); receipt_root=${receipt_root%% *}
evaluator_root=$($sha3 "$evaluator"); evaluator_root=${evaluator_root%% *}
script_root=$($sha3 "$root/tools/dev/retrieval-prefix-sweep.sh"); script_root=${script_root%% *}
batch_root=$($sha3 "$batch"); batch_root=${batch_root%% *}
jsonq_root=$($sha3 "$jsonq"); jsonq_root=${jsonq_root%% *}
transcript_root=$($sha3 "$transcript"); transcript_root=${transcript_root%% *}
printf '{"schema":"zcl.retrieval_prefix_sweep.v1","input_receipt_sha3":"%s","reconstructed_batch_sha3":"%s","evaluator_binary_sha3":"%s","json_parser_binary_sha3":"%s","sweep_script_sha3":"%s","candidate_transcript_sha3":"%s","prefixes_evaluated":6,"tasks_evaluated":9,"primary_metric":"recall_at_5","cost_metric":"projected_context_bytes_at_5","pareto_prefixes":[0],"selection_status":"retain_for_replication_not_promotion","replication_status":"not_run","promotion_authorized":false}\n' "$receipt_root" "$batch_root" "$evaluator_root" "$jsonq_root" "$script_root" "$transcript_root"
