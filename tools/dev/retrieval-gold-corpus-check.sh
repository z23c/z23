#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Validate the immutable historical retrieval corpus against exact Git epochs.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
canonical_corpus="$repo_root/docs/work/RETRIEVAL_GOLD_CORPUS.jsonl"
corpus=${ZCL_RETRIEVAL_GOLD_CORPUS:-$canonical_corpus}
jsonq=${ZCL_JSONQ:-$repo_root/build/bin/jsonq}
sha3=${ZCL_AGENT_SHA3:-$repo_root/build/bin/agent_sha3}
line_no=0
readonly corpus_id=z23-historical-agent-tasks-v1
readonly lineage_commit=fff77e30c30157113c7dced2f0179c92980f6481
readonly corpus_keys='record,schema,corpus_id,benchmark_lineage_commit,task_count,source_epoch_kind,source_root_basis,relevance_judgment,original_prompts_available,canonical_task_roots_available,ranking_may_read_relevance'
readonly task_keys='record,schema,id,landed_commit,parent_commit,expected_vcs_root,query,query_provenance,query_origin_path,query_origin_section,original_prompt_available,canonical_task_root_available,index_eligibility,relevant_paths_root_sha3,relevant_paths,expected_new_paths'

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
check_keys() {
    local row=$1 expected=$2 observed
    observed=$(printf '%s\n' "$row" | "$jsonq" keys . | paste -sd, -) ||
        fail "line $line_no has no valid top-level object keys" || return 1
    [[ $observed = "$expected" ]] ||
        fail "line $line_no has unknown, missing, reordered, or duplicate keys" || return 1
}
check_type() {
    local row=$1 key=$2 expected=$3 observed
    observed=$(printf '%s\n' "$row" | "$jsonq" type "$key") ||
        fail "line $line_no has no typed $key field" || return 1
    [[ $observed = "$expected" ]] ||
        fail "line $line_no field $key is $observed, expected $expected" || return 1
}
check_corpus_types() {
    local row=$1 key
    for key in record schema corpus_id benchmark_lineage_commit \
        source_epoch_kind source_root_basis relevance_judgment; do
        check_type "$row" "$key" string || return 1
    done
    check_type "$row" task_count number || return 1
    for key in original_prompts_available canonical_task_roots_available \
        ranking_may_read_relevance; do
        check_type "$row" "$key" bool || return 1
    done
}
check_task_types() {
    local row=$1 key
    for key in record schema id landed_commit parent_commit expected_vcs_root \
        query query_provenance query_origin_path query_origin_section \
        index_eligibility relevant_paths_root_sha3; do
        check_type "$row" "$key" string || return 1
    done
    for key in original_prompt_available canonical_task_root_available; do
        check_type "$row" "$key" bool || return 1
    done
    check_type "$row" relevant_paths array || return 1
    check_type "$row" expected_new_paths array || return 1
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
relevance_root() {
    local row=$1 count=$2 payload='zcl.retrieval_gold_relevance.v1' path i
    for ((i = 0; i < count; i++)); do
        path=$(field "$row" "relevant_paths[$i]") || return 1
        payload+=$'\n'$path
    done
    printf '%s\n' "$payload" | "$sha3"
}
check_task_kat() {
    local id=$1 landed=$2 parent=$3 source_root=$4 count=$5 paths_root=$6
    local new_count=$7 eligibility=$8 provenance=$9 kat
    local want_landed want_parent want_source want_count want_paths want_new want_eligibility want_provenance
    case "$id" in
        zcode_embedded_nul)
            kat='ac2709e190e9d9734cc88e1b6c649e1aa0280588|3f60fe3014c77c0d73bdbf51ee63d258b82e11eb|3b1a1f8ca2d0b8307f48c885cf79ec64b3cc0230eabfb0f167d012b226c2d82e|2|aa73daaf144faa76c553e58d69a5ed88134d15caca138110720fe8162a8be1f1|0|c23_codeindex|commit_subject_only' ;;
        api_cache_cooperative_shutdown)
            kat='63cf3fd5831fa292ab8b2814599e16896ec6de7b|e5d3744212448a1c308954a688f3e7ab49455e35|b53d54675735547b74762aae5811368d7d0c9ef25ab501d241f4e0dc963cd2c8|5|f8aabb5b5875245abd7d79db86de7ff2523e634ce59a357a0ad431814183e35c|0|c23_codeindex|same_commit_unordered_question' ;;
        package_verifier_object_reuse)
            kat='4295fc4bb158e0d28bc5965fbb7400b76fe8ffd9|07aefda3252e69253a937984bf0438bc787d2697|af2bf91e1952a98647bc0696175d87b13b68fc9af010079e6466dfd16073335e|3|0538197175a506c9a95416df33460547508301891a92e40350cb004b1585c614|0|outside_c23_codeindex|same_commit_unordered_question' ;;
        connected_peer_manifest_refresh)
            kat='ebd4c85cb1bb8e37afb44e97d7409ee94a917e26|25d291c97803905e4a144a56c1016efbb0388d1c|281a04ad9933de7e674949d2d484a50da5cb3d70bc8b8949d969a5fcbed85b6c|6|e2508da2e4cd6c5daa15da35633ffe94ee5aaaee776eebd4e72667d1f11ad140|0|c23_codeindex|same_commit_unordered_intention' ;;
        private_object_grant_encryption_order)
            kat='5743e7a75fcdfe77b04a57a1d82e9ca96b56812d|ee2d958bb116f073804f71998dad06ac60d12ea6|d6b3b9eca293c9a0f1fb1182110027bdddc839b7db673ebb3fa412be103ccb3a|3|79c500ba8012480f8fbc41327439a4049a0ebf034cfb63dbb4217356d16d57d3|1|c23_codeindex|same_commit_unordered_intent' ;;
        sync_discovery_liveness)
            kat='134c2862d4b1bd5444cca8b6d037645b7d5250a2|051e7bb31984820dffe0281f1217899b2ff30576|4c013bf5550d5088ccf15f39144e43de016f1e17dc69aa0a8f622721a53ae891|6|ae6a934c11b9b79d0ac1835bcaa46550aa97c0596aa639f61387dc53c96b7b83|0|c23_codeindex|same_commit_unordered_question' ;;
        windows_verified_checkout)
            kat='faed9950007ecc9b280ff9cb675136c5ea52b1df|e237d660837f873502aadec9d0e5b28002ab0b93|9517cb0430a35104a50ee28e1930ea811f8bd39b5b31bab79b7f8504da5c95eb|6|3564b3382a77efc272f1b70b264c9e0de00b9419cd561df991946b02b4994eee|0|c23_codeindex|same_commit_unordered_intent' ;;
        *) fail "task $id is not in the reviewed task-set KAT" || return 1 ;;
    esac
    IFS='|' read -r want_landed want_parent want_source want_count want_paths \
        want_new want_eligibility want_provenance <<<"$kat"
    [[ $landed = "$want_landed" && $parent = "$want_parent" &&
       $source_root = "$want_source" && $count = "$want_count" &&
       $paths_root = "$want_paths" && $new_count = "$want_new" &&
       $eligibility = "$want_eligibility" &&
       $provenance = "$want_provenance" ]] ||
        fail "task $id differs from the reviewed epoch/relevance KAT" || return 1
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
        check_type "$row" "relevant_paths[$i]" string || return 1
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
        check_type "$row" "expected_new_paths[$i]" string || return 1
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
    if [[ $id = private_object_grant_encryption_order ]]; then
        [[ $count -eq 1 &&
           $(field "$row" 'expected_new_paths[0]') = lib/test/src/test_mesh_private_object_grant_pipeline.c ]] ||
            fail "task $id differs from the reviewed new-path KAT" || return 1
    else
        ((count == 0)) || fail "task $id unexpectedly declares new paths" || return 1
    fi
}
validate() {
    local row record schema expected=0 tasks=0 headers=0 id landed parent actual query provenance eligibility key
    local source_root paths_root relevant_count new_count subject_tasks=0 same_commit_tasks=0 task_order=''
    declare -A ids=() epochs=()
    [[ -x $jsonq ]] || fail "build/bin/jsonq is unavailable; run make jsonq" || return 1
    [[ -x $sha3 ]] || fail "build/bin/agent_sha3 is unavailable; run make agent-sha3" || return 1
    [[ -f $corpus ]] || fail "corpus unavailable: $corpus" || return 1
    line_no=0
    while IFS= read -r row || [[ -n $row ]]; do
        line_no=$((line_no + 1)); [[ -n $row ]] || fail "line $line_no is blank" || return 1
        record=$(field "$row" record); schema=$(field "$row" schema)
        case "$record" in
            corpus)
                ((headers == 0 && line_no == 1)) || fail "header must be the unique first record" || return 1
                check_keys "$row" "$corpus_keys"
                check_corpus_types "$row"
                [[ $schema = zcl.retrieval_gold_corpus.v1 ]] || fail "unknown corpus schema" || return 1
                [[ $(field "$row" corpus_id) = "$corpus_id" ]] ||
                    fail "unknown corpus_id" || return 1
                [[ $(field "$row" benchmark_lineage_commit) = "$lineage_commit" ]] ||
                    fail "unknown benchmark lineage" || return 1
                commit_exact "$lineage_commit" || fail "benchmark lineage is unavailable" || return 1
                expected=$(field "$row" task_count)
                [[ $expected =~ ^[0-9]+$ && $expected -gt 0 ]] || fail "invalid task_count" || return 1
                [[ $(field "$row" source_epoch_kind) = git_parent_commit &&
                   $(field "$row" source_root_basis) = vcs_manifest_v1_nonignored_filesystem &&
                   $(field "$row" relevance_judgment) = landed_changed_path_present_in_parent &&
                   $(field "$row" original_prompts_available) = false &&
                   $(field "$row" canonical_task_roots_available) = false &&
                   $(field "$row" ranking_may_read_relevance) = false ]] ||
                    fail "corpus header weakens the evidence boundary" || return 1
                headers=$((headers + 1)) ;;
            task)
                ((headers == 1)) || fail "task precedes header" || return 1
                check_keys "$row" "$task_keys"
                check_task_types "$row"
                [[ $schema = zcl.retrieval_gold_task.v1 ]] || fail "unknown task schema" || return 1
                id=$(field "$row" id); [[ $id =~ ^[a-z0-9][a-z0-9_]*$ ]] || fail "invalid id: $id" || return 1
                [[ ! -v ids[$id] ]] || fail "duplicate task id: $id" || return 1; ids[$id]=1
                landed=$(field "$row" landed_commit); parent=$(field "$row" parent_commit)
                commit_exact "$landed" || fail "task $id has unavailable landed commit" || return 1
                commit_exact "$parent" || fail "task $id has unavailable parent commit" || return 1
                actual=$(git -C "$repo_root" show -s --format=%P "$landed")
                [[ $actual = "$parent" ]] || fail "task $id does not name its single exact parent" || return 1
                git -C "$repo_root" merge-base --is-ancestor "$landed" "$lineage_commit" ||
                    fail "task $id landing is outside the fixed benchmark lineage" || return 1
                key="$landed:$parent"; [[ ! -v epochs[$key] ]] || fail "duplicate epoch pair: $key" || return 1
                epochs[$key]=1
                query=$(field "$row" query); [[ -n $query ]] || fail "task $id has empty query" || return 1
                [[ $(field "$row" original_prompt_available) = false &&
                   $(field "$row" canonical_task_root_available) = false ]] ||
                    fail "task $id overclaims prompt or task-root evidence" || return 1
                provenance=$(field "$row" query_provenance); eligibility=$(field "$row" index_eligibility)
                check_provenance "$row" "$id" "$landed" "$parent" "$query" "$provenance"
                check_paths "$row" "$id" "$landed" "$parent" "$eligibility"
                source_root=$(field "$row" expected_vcs_root)
                paths_root=$(field "$row" relevant_paths_root_sha3)
                [[ $source_root =~ ^[0-9a-f]{64}$ && $paths_root =~ ^[0-9a-f]{64}$ ]] ||
                    fail "task $id has malformed source or relevance root" || return 1
                relevant_count=$(array_count "$row" relevant_paths)
                new_count=$(array_count "$row" expected_new_paths)
                [[ $(relevance_root "$row" "$relevant_count") = "$paths_root" ]] ||
                    fail "task $id relevant-path root does not rederive" || return 1
                check_task_kat "$id" "$landed" "$parent" "$source_root" \
                    "$relevant_count" "$paths_root" "$new_count" "$eligibility" "$provenance"
                task_order+="${task_order:+,}$id"
                if [[ $provenance = commit_subject_only ]]; then
                    subject_tasks=$((subject_tasks + 1))
                else
                    same_commit_tasks=$((same_commit_tasks + 1))
                fi
                tasks=$((tasks + 1)) ;;
            *) fail "unknown record on line $line_no: $record" || return 1 ;;
        esac
    done <"$corpus"
    ((headers == 1 && tasks == expected && tasks == 7)) ||
        fail "expected seven tasks; header=$expected validated=$tasks" || return 1
    ((subject_tasks == 1 && same_commit_tasks == 6)) ||
        fail "query provenance strata changed" || return 1
    [[ $task_order = 'zcode_embedded_nul,api_cache_cooperative_shutdown,package_verifier_object_reuse,connected_peer_manifest_refresh,private_object_grant_encryption_order,sync_discovery_liveness,windows_verified_checkout' ]] ||
        fail "reviewed task order changed" || return 1
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
    bad="$tmp/corpus-id"; sed '0,/z23-historical-agent-tasks-v1/s//changed-corpus/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted changed corpus_id" || return 1
    fi
    bad="$tmp/deleted-relevance"; awk '{ sub(",\"lib/test/fixtures/zcode/tiny-lines/tests/test_tiny_lines.c\"", ""); print }' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted deleted relevant path" || return 1
    fi
    bad="$tmp/duplicate-key"; awk '{ sub("\"id\":\"zcode_embedded_nul\"", "\"id\":\"zcode_embedded_nul\",\"id\":\"zcode_embedded_nul\""); print }' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted duplicate JSON key" || return 1
    fi
    bad="$tmp/unknown-key"; awk 'NR == 1 { sub(/}$/, ",\"unexpected\":true}") } { print }' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted unknown JSON key" || return 1
    fi
    bad="$tmp/source-root"; sed '0,/3b1a1f8ca2d0b8307f48c885cf79ec64b3cc0230eabfb0f167d012b226c2d82e/s//0b1a1f8ca2d0b8307f48c885cf79ec64b3cc0230eabfb0f167d012b226c2d82e/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted changed source-root KAT" || return 1
    fi
    bad="$tmp/relevance-root"; sed '0,/aa73daaf144faa76c553e58d69a5ed88134d15caca138110720fe8162a8be1f1/s//0a73daaf144faa76c553e58d69a5ed88134d15caca138110720fe8162a8be1f1/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted changed relevance-root KAT" || return 1
    fi
    bad="$tmp/lineage"; sed '0,/fff77e30c30157113c7dced2f0179c92980f6481/s//9663101fb513a659cd7a5b03295f871e17784407/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted changed benchmark lineage" || return 1
    fi
    bad="$tmp/order"; awk 'NR == 2 { first = $0; next } NR == 3 { print; print first; next } { print }' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted reordered reviewed task set" || return 1
    fi
    bad="$tmp/bool-type"; sed '0,/"original_prompts_available":false/s//"original_prompts_available":"false"/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted a string in a boolean field" || return 1
    fi
    bad="$tmp/path-type"; sed '0,/"lib\/test\/fixtures\/zcode\/tiny-lines\/src\/tiny_lines.c"/s//23/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted a non-string array element" || return 1
    fi
    bad="$tmp/new-path-kat"; sed '0,/lib\/test\/src\/test_mesh_private_object_grant_pipeline.c/s//docs\/experiments\/2026-08-29-private-object-grant-encryption-order.md/' "$canonical_corpus" >"$bad"
    if ZCL_RETRIEVAL_GOLD_CORPUS="$bad" "$0" --check >/dev/null 2>&1; then
        fail "accepted changed new-path KAT" || return 1
    fi
    printf 'retrieval-gold-corpus-check: SELFTEST PASS mutations=15\n'
}
case ${1:---check} in
    --check) validate ;;
    --selftest) selftest ;;
    *) printf 'usage: %s [--check|--selftest]\n' "$0" >&2; exit 64 ;;
esac
