#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Mutation checks for the strict retrieval evaluator batch adapter.

set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd -P)
evaluator=${ZCL_RETRIEVAL_EVAL:-$root/build/bin/retrieval-eval}
jsonq=${ZCL_JSONQ:-$root/build/bin/jsonq}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-eval-selftest.XXXXXX")
trap 'case ${tmp:-} in "${TMPDIR:-/tmp}"/z23-retrieval-eval-selftest.*) rm -r -- "$tmp" ;; esac' EXIT HUP INT TERM

fail() { printf 'retrieval-eval-selftest: FAIL — %s\n' "$*" >&2; exit 1; }
[[ -x $evaluator && -x $jsonq ]] || fail "build retrieval-eval and jsonq first"

fixture="$tmp/valid.batch"
printf '%s\n' \
    'zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=1' \
    'task task_a 1' \
    'query find a' \
    'relevant a.c' \
    'literal observed 1 2' \
    'rank 10 1 0 x.c' \
    'rank 20 1 1 a.c' \
    'bm25 observed 1 1' \
    'rank 5 0 0 a.c' \
    'end' >"$fixture"
output=$("$evaluator" <"$fixture") || fail "valid fixture was refused"
[[ $(printf '%s\n' "$output" | "$jsonq" get schema) = zcl.retrieval_eval_batch_result.v3 &&
   $(printf '%s\n' "$output" | "$jsonq" get tasks_evaluated) = 1 &&
   $(printf '%s\n' "$output" | "$jsonq" get aggregation_kind) = macro_equal_task_weight &&
   $(printf '%s\n' "$output" | "$jsonq" get tasks_denominator) = 1 &&
   $(printf '%s\n' "$output" | "$jsonq" get eligible_relevance_judgments) = 1 &&
   $(printf '%s\n' "$output" | "$jsonq" get literal.recall_at_5.basis_points) = 10000 &&
   $(printf '%s\n' "$output" | "$jsonq" get literal.mrr.basis_points) = 5000 &&
   $(printf '%s\n' "$output" | "$jsonq" get literal.wrong_scope_at_5.available) = true &&
   $(printf '%s\n' "$output" | "$jsonq" get literal.wrong_scope_at_5.basis_points) = 5000 &&
   $(printf '%s\n' "$output" | "$jsonq" get bm25.wrong_scope_at_5.available) = false ]] ||
    fail "valid fixture metrics differ from the maintained evaluator"

rank_root=$(printf '1\t10\tx.c\n2\t20\ta.c\n' | \
    "$evaluator" --rank-root 1) || fail "valid ranking-root fixture was refused"
[[ $rank_root = b78e5feb676ba4b2d2e3032d269d929a79a49a71ff9932901b037f0466a861ec ]] ||
    fail "ranking-root known answer changed"

bad="$tmp/duplicate.batch"
sed 's/rank 20 1 1 a.c/rank 20 1 1 x.c/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "duplicate ranked path was accepted"
fi
bad="$tmp/negative.batch"
sed 's/rank 10 1 0 x.c/rank -1 1 0 x.c/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "negative context bytes were accepted"
fi
bad="$tmp/trailing.batch"
{ sed '$d' "$fixture"; printf '%s\n' end trailing; } >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "trailing evidence was accepted"
fi
bad="$tmp/task-count.batch"
sed 's/tasks=1/tasks=2/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "false task count was accepted"
fi
bad="$tmp/relevance-count.batch"
sed 's/eligible_relevance_judgments=1/eligible_relevance_judgments=2/' \
    "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "false eligible relevance-judgment count was accepted"
fi
bad="$tmp/task-count-overflow.batch"
sed 's/tasks=1/tasks=18446744073709551616/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "overflowing task count was accepted"
fi
bad="$tmp/relevance-count-overflow.batch"
sed 's/eligible_relevance_judgments=1/eligible_relevance_judgments=18446744073709551616/' \
    "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "overflowing eligible relevance-judgment count was accepted"
fi

bad="$tmp/noncanonical-number.batch"
sed 's/rank 10 1 0 x.c/rank 010 1 0 x.c/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "noncanonical numeric token was accepted"
fi
bad="$tmp/traversal.batch"
sed 's#rank 10 1 0 x.c#rank 10 1 0 x/..#' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "terminal traversal component was accepted"
fi
bad="$tmp/scope.batch"
sed 's/rank 5 0 0 a.c/rank 5 0 1 a.c/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "contradictory scope bits were accepted"
fi
bad="$tmp/unobserved.batch"
sed 's/literal observed 1 2/literal unobserved 1 2/' "$fixture" >"$bad"
if "$evaluator" <"$bad" >/dev/null 2>&1; then
    fail "unobserved arm was accepted for evaluation"
fi
if printf '2\t10\tx.c\n' | "$evaluator" --rank-root 1 >/dev/null 2>&1; then
    fail "non-contiguous rank-root row was accepted"
fi
if printf '1 10 x.c\n' | "$evaluator" --rank-root 1 >/dev/null 2>&1; then
    fail "non-tab rank-root row was accepted"
fi

experiment="$tmp/experiment.batch"
printf '%s\n' \
    'zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=1' \
    'task task_a 1' \
    'query find a' \
    'relevant a.c' \
    'literal observed 1 6' \
    'rank 10 1 1 b.c' \
    'rank 20 1 1 c.c' \
    'rank 30 1 1 d.c' \
    'rank 40 1 1 e.c' \
    'rank 50 1 1 f.c' \
    'rank 10 1 1 a.c' \
    'bm25 observed 1 6' \
    'rank 10 1 1 a.c' \
    'rank 10 1 1 b.c' \
    'rank 20 1 1 c.c' \
    'rank 30 1 1 d.c' \
    'rank 40 1 1 e.c' \
    'rank 50 1 1 f.c' \
    'end' >"$experiment"
parent=$($evaluator --experiment-prefix 0 <"$experiment") ||
    fail "parent experiment fixture was refused"
base=$($evaluator --experiment-prefix 5 <"$experiment") ||
    fail "BM25 experiment fixture was refused"
[[ $(printf '%s\n' "$parent" | "$jsonq" get schema) = zcl.retrieval_experiment_eval_result.v1 &&
   $(printf '%s\n' "$parent" | "$jsonq" get candidate.recall_at_5.basis_points) = 10000 &&
   $(printf '%s\n' "$base" | "$jsonq" get candidate.recall_at_5.basis_points) = 0 &&
   $(printf '%s\n' "$parent" | "$jsonq" get candidate.wrong_scope_at_5.available) = false &&
   $(printf '%s\n' "$parent" | "$jsonq" get projector_gold_input) = none &&
   $(printf '%s\n' "$parent" | "$jsonq" get promotion_authorized) = false ]] ||
    fail "experiment evaluation boundary or metric differs"
if "$evaluator" --experiment-prefix 6 <"$experiment" >/dev/null 2>&1; then
    fail "out-of-range experiment prefix was accepted"
fi

profile=5a435250524f310a010000040000000000000000000000000000000000000000010000000000000000000006050000000100000000000000
evaluator_root=1111111111111111111111111111111111111111111111111111111111111111
profile_output=$("$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$experiment") ||
    fail "context-only profile replay was refused"
[[ $(printf '%s\n' "$profile_output" | "$jsonq" get schema) = zcl.retrieval_context_profile_replay.v1 &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get input_arm_binding) = bm25_is_profile_baseline &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get generation_binding) = unavailable_in_frozen_v3 &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get projector_relevance_input_channel) = none &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get gold_separation) = api_surface_only_same_process &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get candidate.recall_at_5.basis_points) = 10000 &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get candidate.wrong_scope_at_5.available) = false &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get replay_hypothesis_root_sha3) = 863e3921f6e6375d0f6354629334723cb18ef6b14c01be3502244b56605e2354 &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get candidate_batch_root_sha3) = a6d5b8d292ed781c7ef7b5fd272c850a34bedf0b481144ee9b5207e684e460f5 &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get evaluation_result_root_sha3) = 35faf9e287186608513df3c43f7f0ffb6ad28f21751f3cd4f1b4ad785b1b4bef &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get chronology_status) = unverified &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get holdout_independence_status) = unverified &&
   $(printf '%s\n' "$profile_output" | "$jsonq" get promotion_authorized) = false ]] ||
    fail "profile replay identity or evidence boundary differs"
[[ $("$evaluator" --profile-hex "$profile" \
       --evaluator-root "$evaluator_root" <"$experiment") = "$profile_output" ]] ||
    fail "profile replay is not deterministic"

gold_mutation="$tmp/profile-gold-mutation.batch"
sed 's/relevant a.c/relevant f.c/' "$experiment" >"$gold_mutation"
gold_output=$("$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$gold_mutation") ||
    fail "valid gold mutation was refused"
[[ $(printf '%s\n' "$gold_output" | "$jsonq" get replay_hypothesis_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get replay_hypothesis_root_sha3) &&
   $(printf '%s\n' "$gold_output" | "$jsonq" get candidate_batch_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get candidate_batch_root_sha3) &&
   $(printf '%s\n' "$gold_output" | "$jsonq" get evaluation_input_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get evaluation_input_root_sha3) &&
   $(printf '%s\n' "$gold_output" | "$jsonq" get evaluation_result_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get evaluation_result_root_sha3) ]] ||
    fail "gold mutation crossed the proposal/evaluation boundary"

literal_mutation="$tmp/profile-literal-mutation.batch"
sed '0,/rank 10 1 1 b.c/s//rank 11 1 1 b.c/' \
    "$experiment" >"$literal_mutation"
literal_output=$("$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$literal_mutation") ||
    fail "valid irrelevant-arm mutation was refused"
[[ $(printf '%s\n' "$literal_output" | "$jsonq" get replay_hypothesis_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get replay_hypothesis_root_sha3) &&
   $(printf '%s\n' "$literal_output" | "$jsonq" get candidate_batch_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get candidate_batch_root_sha3) &&
   $(printf '%s\n' "$literal_output" | "$jsonq" get evaluation_input_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get evaluation_input_root_sha3) ]] ||
    fail "literal arm mutation crossed the profile proposal boundary"

scope_mutation="$tmp/profile-scope-mutation.batch"
sed '0,/rank 10 1 1 a.c/! s/rank 10 1 1 a.c/rank 10 0 0 a.c/' \
    "$experiment" >"$scope_mutation"
scope_output=$("$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$scope_mutation") ||
    fail "valid ignored-scope mutation was refused"
[[ $(printf '%s\n' "$scope_output" | "$jsonq" get replay_hypothesis_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get replay_hypothesis_root_sha3) &&
   $(printf '%s\n' "$scope_output" | "$jsonq" get candidate_batch_root_sha3) = \
       $(printf '%s\n' "$profile_output" | "$jsonq" get candidate_batch_root_sha3) &&
   $(printf '%s\n' "$scope_output" | "$jsonq" get raw_batch_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get raw_batch_root_sha3) &&
   $(printf '%s\n' "$scope_output" | "$jsonq" get evaluation_result_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get evaluation_result_root_sha3) ]] ||
    fail "scope mutation entered proposal identity or missed evaluation identity"

bm25_mutation="$tmp/profile-bm25-mutation.batch"
sed '0,/rank 10 1 1 a.c/! s/rank 10 1 1 a.c/rank 11 1 1 a.c/' \
    "$experiment" >"$bm25_mutation"
bm25_output=$("$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$bm25_mutation") ||
    fail "valid baseline mutation was refused"
[[ $(printf '%s\n' "$bm25_output" | "$jsonq" get replay_hypothesis_root_sha3) != \
       $(printf '%s\n' "$profile_output" | "$jsonq" get replay_hypothesis_root_sha3) ]] ||
    fail "BM25 baseline mutation did not move the replay hypothesis"

uppercase_profile=${profile/a/A}
if "$evaluator" --profile-hex "$uppercase_profile" \
    --evaluator-root "$evaluator_root" <"$experiment" >"$tmp/refused.out" 2>/dev/null; then
    fail "uppercase profile wire was accepted"
fi
[[ ! -s $tmp/refused.out ]] || fail "profile refusal emitted partial evidence"
top_four=${profile/06050000/06040000}
if "$evaluator" --profile-hex "$top_four" \
    --evaluator-root "$evaluator_root" <"$experiment" >"$tmp/refused.out" 2>/dev/null; then
    fail "top-four profile was presented as at-five evidence"
fi
[[ ! -s $tmp/refused.out ]] || fail "top-k refusal emitted partial evidence"
if "$evaluator" --profile-hex "$profile" \
    --evaluator-root "$evaluator_root" <"$fixture" >"$tmp/refused.out" 2>/dev/null; then
    fail "short baseline was presented as at-five evidence"
fi
[[ ! -s $tmp/refused.out ]] || fail "short-baseline refusal emitted partial evidence"

printf 'retrieval-eval-selftest: PASS mutations=21 experiment_prefixes=2 profile_replays=6\n'
