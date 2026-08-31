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
    'zcl.retrieval_eval_batch.v2 tasks=1' \
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
[[ $(printf '%s\n' "$output" | "$jsonq" get tasks_evaluated) = 1 &&
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

printf 'retrieval-eval-selftest: PASS mutations=10\n'
