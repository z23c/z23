#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Validate the immutable historical retrieval corpus against exact Git epochs.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
canonical_corpus="$repo_root/docs/work/RETRIEVAL_GOLD_CORPUS.jsonl"
corpus=${ZCL_RETRIEVAL_GOLD_CORPUS:-$canonical_corpus}
jsonq=${ZCL_JSONQ:-$repo_root/build/bin/jsonq}
line_no=0

fail() { printf 'retrieval-gold-corpus-check: FAIL — %s\n' "$*" >&2; return 1; }
field() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" get "$2") ||
        fail "line $line_no has no valid $2 field" || return 1
    printf '%s' "$value"
}
array_count() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" count "$2") ||
        fail "line $line_no has no valid $2 array" || return 1
    [[ $value =~ ^[0-9]+$ ]] || fail "line $line_no has invalid $2 count" || return 1
    printf '%s' "$value"
}
canonical_path() {
    [[ -n $1 && $1 != /* && $1 != ./* && $1 != */ && $1 != *//* &&
       $1 != *\\* && $1 =~ ^[A-Za-z0-9][A-Za-z0-9._/+@-]*$ ]] || return 1
    if [[ $1 =~ (^|/)(\.|\.\.)($|/) ]]; then
        return 1
    fi
}
commit_exact() {
    local resolved
    [[ $1 =~ ^[0-9a-f]{40}$ ]] || return 1
    resolved=$(git -C "$repo_root" rev-parse --verify "$1^{commit}" 2>/dev/null) || return 1
    [[ $resolved = "$1" ]]
}
blob_exists() {
    [[ $(git -C "$repo_root" cat-file -t "$1:$2" 2>/dev/null || true) = blob ]]
}
changed_in_landing() {
    [[ $(git -C "$repo_root" diff-tree --no-commit-id --name-only -r \
        "$2" "$1" -- "$3") = "$3" ]]
}
section_paragraph() {
    git -C "$repo_root" show "$1:$2" | awk -v heading="## $3" '
        $0 == heading { inside = 1; next }
        inside && /^## / { exit }
        inside && /^[[:space:]]*$/ { if (started) exit; next }
        inside {
            line = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "") next
            if (started) printf " "; printf "%s", line; started = 1
        }
        END { if (!started) exit 1; printf "\n" }
    '
}
check_provenance() {
    local row=$1 id=$2 landed=$3 parent=$4 query=$5 provenance=$6
    local path section expected observed
    path=$(field "$row" query_origin_path); section=$(field "$row" query_origin_section)
    case "$provenance" in
        commit_subject_only)
            [[ -z $path && $section = commit_subject ]] ||
                fail "task $id has contradictory commit-subject origin" || return 1
            [[ $query = "$(git -C "$repo_root" show -s --format=%s "$landed")" ]] ||
                fail "task $id query differs from the landed subject" || return 1
            return 0 ;;
        same_commit_unordered_question) expected=Question ;;
        same_commit_unordered_intent) expected=Intent ;;
        same_commit_unordered_intention) expected=Intention ;;
        *) fail "task $id has unknown query provenance: $provenance" || return 1 ;;
    esac
    [[ $section = "$expected" ]] || fail "task $id provenance and section disagree" || return 1
    canonical_path "$path" || fail "task $id has non-canonical origin: $path" || return 1
    ! blob_exists "$parent" "$path" || fail "task $id origin existed in its parent" || return 1
    blob_exists "$landed" "$path" || fail "task $id origin is absent at landing" || return 1
    changed_in_landing "$landed" "$parent" "$path" ||
        fail "task $id origin was not added by its landing" || return 1
    observed=$(section_paragraph "$landed" "$path" "$section") ||
        fail "task $id origin section is missing" || return 1
    [[ $query = "$observed" ]] || fail "task $id query differs from its origin paragraph" || return 1
}
check_paths() {
    local row=$1 id=$2 landed=$3 parent=$4 eligibility=$5 count i path key
    declare -A seen=()
    count=$(array_count "$row" relevant_paths)
    ((count > 0)) || fail "task $id has no relevant paths" || return 1
    for ((i = 0; i < count; i++)); do
        path=$(field "$row" "relevant_paths[$i]"); key="relevant:$path"
        canonical_path "$path" || fail "task $id has non-canonical relevant path: $path" || return 1
        [[ ! -v seen[$key] ]] || fail "task $id duplicates relevant path: $path" || return 1
        seen[$key]=1
        blob_exists "$parent" "$path" || fail "task $id path absent at parent: $path" || return 1
        blob_exists "$landed" "$path" || fail "task $id path absent at landing: $path" || return 1
        changed_in_landing "$landed" "$parent" "$path" ||
            fail "task $id path was not changed by landing: $path" || return 1
        case "$eligibility" in
            c23_codeindex) [[ $path = *.c || $path = *.h ]] ||
                fail "task $id marks a non-C/H path indexable: $path" || return 1 ;;
            outside_c23_codeindex) [[ $path != *.c && $path != *.h ]] ||
                fail "task $id marks a C/H path outside the index: $path" || return 1 ;;
            *) fail "task $id has unknown index eligibility: $eligibility" || return 1 ;;
        esac
    done
    count=$(array_count "$row" expected_new_paths)
    for ((i = 0; i < count; i++)); do
        path=$(field "$row" "expected_new_paths[$i]"); key="new:$path"
        canonical_path "$path" || fail "task $id has non-canonical new path: $path" || return 1
        [[ ! -v seen[$key] && ! -v seen["relevant:$path"] ]] ||
            fail "task $id duplicates or overlaps new path: $path" || return 1
        seen[$key]=1
        ! blob_exists "$parent" "$path" || fail "task $id new path existed at parent: $path" || return 1
        blob_exists "$landed" "$path" || fail "task $id new path absent at landing: $path" || return 1
        changed_in_landing "$landed" "$parent" "$path" ||
            fail "task $id new path was not added by landing: $path" || return 1
    done
}
validate() {
    local row record schema expected=0 tasks=0 headers=0 id landed parent actual query provenance eligibility key
    declare -A ids=() epochs=()
    [[ -x $jsonq ]] || fail "build/bin/jsonq is unavailable; run make jsonq" || return 1
    [[ -f $corpus ]] || fail "corpus unavailable: $corpus" || return 1
    line_no=0
    while IFS= read -r row || [[ -n $row ]]; do
        line_no=$((line_no + 1)); [[ -n $row ]] || fail "line $line_no is blank" || return 1
        record=$(field "$row" record); schema=$(field "$row" schema)
        case "$record" in
            corpus)
                ((headers == 0 && line_no == 1)) || fail "header must be the unique first record" || return 1
                [[ $schema = zcl.retrieval_gold_corpus.v1 ]] || fail "unknown corpus schema" || return 1
                expected=$(field "$row" task_count)
                [[ $expected =~ ^[0-9]+$ && $expected -gt 0 ]] || fail "invalid task_count" || return 1
                [[ $(field "$row" source_epoch_kind) = git_parent_commit &&
                   $(field "$row" relevance_judgment) = landed_changed_path_present_in_parent &&
                   $(field "$row" original_prompts_available) = false &&
                   $(field "$row" canonical_task_roots_available) = false &&
                   $(field "$row" ranking_may_read_relevance) = false ]] ||
                    fail "corpus header weakens the evidence boundary" || return 1
                headers=$((headers + 1)) ;;
            task)
                ((headers == 1)) || fail "task precedes header" || return 1
                [[ $schema = zcl.retrieval_gold_task.v1 ]] || fail "unknown task schema" || return 1
                id=$(field "$row" id); [[ $id =~ ^[a-z0-9][a-z0-9_]*$ ]] || fail "invalid id: $id" || return 1
                [[ ! -v ids[$id] ]] || fail "duplicate task id: $id" || return 1; ids[$id]=1
                landed=$(field "$row" landed_commit); parent=$(field "$row" parent_commit)
                commit_exact "$landed" || fail "task $id has unavailable landed commit" || return 1
                commit_exact "$parent" || fail "task $id has unavailable parent commit" || return 1
                actual=$(git -C "$repo_root" show -s --format=%P "$landed")
                [[ $actual = "$parent" ]] || fail "task $id does not name its single exact parent" || return 1
                key="$landed:$parent"; [[ ! -v epochs[$key] ]] || fail "duplicate epoch pair: $key" || return 1
                epochs[$key]=1
                query=$(field "$row" query); [[ -n $query ]] || fail "task $id has empty query" || return 1
                [[ $(field "$row" original_prompt_available) = false &&
                   $(field "$row" canonical_task_root_available) = false ]] ||
                    fail "task $id overclaims prompt or task-root evidence" || return 1
                provenance=$(field "$row" query_provenance); eligibility=$(field "$row" index_eligibility)
                check_provenance "$row" "$id" "$landed" "$parent" "$query" "$provenance"
                check_paths "$row" "$id" "$landed" "$parent" "$eligibility"
                tasks=$((tasks + 1)) ;;
            *) fail "unknown record on line $line_no: $record" || return 1 ;;
        esac
    done <"$corpus"
    ((headers == 1 && tasks == expected && tasks == 7)) ||
        fail "expected seven tasks; header=$expected validated=$tasks" || return 1
    printf 'retrieval-gold-corpus-check: PASS tasks=%d exact_parent_epochs=%d\n' "$tasks" "$tasks"
}
selftest() {
    local tmp bad old new
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/z23-retrieval-corpus-selftest.XXXXXX")
    trap '[[ -z ${tmp:-} ]] || rm -r -- "$tmp"' EXIT HUP INT TERM
    ZCL_RETRIEVAL_GOLD_CORPUS="$canonical_corpus" "$0" --check >/dev/null
    old=3f60fe3014c77c0d73bdbf51ee63d258b82e11eb; new=ac2709e190e9d9734cc88e1b6c649e1aa0280588
    bad="$tmp/parent"; sed "0,/$old/s//$new/" "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted false parent" || return 1
    fi
    bad="$tmp/path"; sed '0,/tiny_lines.c/s#lib/test/fixtures#./lib/test/fixtures#' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted non-canonical path" || return 1
    fi
    bad="$tmp/id"; sed '0,/api_cache_cooperative_shutdown/s//zcode_embedded_nul/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted duplicate id" || return 1
    fi
    bad="$tmp/provenance"; sed '0,/same_commit_unordered_question/s//same_commit_unordered_intent/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted false provenance" || return 1
    fi
    printf 'retrieval-gold-corpus-check: SELFTEST PASS mutations=4\n'
}
case ${1:---check} in
    --check) validate ;;
    --selftest) selftest ;;
    *) printf 'usage: %s [--check|--selftest]\n' "$0" >&2; exit 64 ;;
esac
