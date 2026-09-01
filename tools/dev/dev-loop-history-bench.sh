#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Freeze and classify the most recent production-C change history.  This is a
# measurement input, never reload authority: manifests and runtime admission
# remain the only things that can activate code.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMITS="${ZCL_DEV_HISTORY_COMMITS:-100}"
HISTORY_BASE="${ZCL_DEV_HISTORY_BASE_REF:-cdb0305a7a68544cdd26209e9074adaeda24a1a9}"
OUTPUT="${ZCL_DEV_HISTORY_OUTPUT:-$ROOT/build/dev-loop/history-benchmark.json}"
MODE="${1:-run}"

fail()
{
    printf 'dev-loop-history-bench: %s\n' "$*" >&2
    exit 2
}

[[ "$COMMITS" =~ ^[1-9][0-9]*$ ]] || fail 'commit count must be positive'
command -v jq >/dev/null || fail 'jq is required'
git -C "$ROOT" rev-parse --verify "$HISTORY_BASE^{commit}" >/dev/null 2>&1 ||
    fail "frozen history base is unavailable: $HISTORY_BASE"

is_production_tu()
{
    case "$1" in
        src/*.c|app/*/src/*.c|engine/composition/src/*.c|lib/*/src/*.c|\
        domain/*/src/*.c|engine/application/*/src/*.c|platform/ports/*/src/*.c|\
        platform/adapters/*/src/*.c|tools/command/*.c|tools/dev/*.c|tools/*.c)
            case "$1" in tests/harness/include/test/*|tools/fuzz/*|tools/sim/*) return 1;; esac
            return 0
            ;;
    esac
    return 1
}

is_forbidden_authority()
{
    case "$1" in
        core/*|lib/consensus/*|core/modules/validation/*|engine/modules/storage/*|core/modules/coins/*|\
        core/modules/chain/*|core/modules/mining/*|contexts/wallet/*|core/modules/net/*|engine/jobs/*|\
        engine/models/*|engine/supervisors/*|engine/composition/src/*)
            return 0
            ;;
    esac
    return 1
}

has_mutable_file_static()
{
    [ -f "$ROOT/$1" ] || return 1
    awk '
      /hotswap-static-ok:/ { next }
      /^static[ \t]/ {
        line=$0
        if (line ~ /\<const\>/ || line ~ /\(/) next
        if (line ~ /=/ || line ~ /\[/ || line ~ /\{[ \t]*$/) found=1
      }
      END { exit found ? 0 : 1 }
    ' "$ROOT/$1"
}

has_direct_state_access()
{
    [ -f "$ROOT/$1" ] || return 1
    grep -Eq '#include "(storage|wallet|net|coins|models)/|\b(sqlite3_|node_db_|wallet_[a-z].*save|broadcast_transaction)\b' \
        "$ROOT/$1"
}

is_pure_candidate_root()
{
    case "$1" in
        platform/modules/base/src/*.c|platform/modules/codec/src/*.c|platform/modules/json/src/*.c|\
        platform/domain/encoding/src/*.c|contexts/explorer/views/src/*.c|engine/conditions/src/*.c)
            return 0
            ;;
    esac
    return 1
}

declare -A LIVE=()
declare -A SHADOW=()
declare -A HOT_EXECUTE=()
declare -A SERVICE_SOURCE=()
declare -A HOT_FORK=()
load_live_manifest()
{
    local value path
    while IFS= read -r value; do
        for path in $value; do
            case "$path" in *.c) LIVE["$path"]=1;; esac
        done
    done < <(awk '
      { text=text $0 "\n" }
      END {
        while (match(text, /"[^"]*\.c([^"]*)?"/)) {
          value=substr(text, RSTART+1, RLENGTH-2)
          print value
          text=substr(text, RSTART+RLENGTH)
        }
      }
    ' "$ROOT/engine/composition/hotswap_swappable.def" \
      "$ROOT/engine/composition/hotswap_islands.def" \
      "$ROOT/engine/composition/hotswap_services.def")
}

load_shadow_manifest()
{
    local owner service
    while IFS=$'\t' read -r owner service; do
        [[ -n "$owner" && -n "$service" ]] || continue
        SHADOW["$owner"]="$service"
    done < <(awk '
      /^HOTSHADOW_OWNER\(/ { active=1; count=0 }
      active {
        rest=$0
        while (match(rest,/"[^"]+"/)) {
          value=substr(rest,RSTART+1,RLENGTH-2)
          if (count==0) owner=value; else if (count==1) service=value
          count++; rest=substr(rest,RSTART+RLENGTH)
        }
        if (active && count>=2) { print owner "\t" service; active=0 }
      }
    ' "$ROOT/engine/composition/hotswap_shadow_owners.def")
    while IFS=$'\t' read -r service members; do
        for owner in $members; do HOT_EXECUTE["$owner"]="$service"; done
    done < <(awk '
      /^HOTSHADOW_SERVICE_MEMBERS\(/ { active=1; count=0 }
      active {
        rest=$0
        while (match(rest,/"[^"]+"/)) {
          value=substr(rest,RSTART+1,RLENGTH-2)
          if (count==0) service=value; else if (count==1) members=value
          count++; rest=substr(rest,RSTART+RLENGTH)
        }
        if (active && count>=2) { print service "\t" members; active=0 }
      }
    ' "$ROOT/engine/composition/hotswap_shadow_owners.def")
}

load_service_manifest()
{
    local source
    while IFS= read -r source; do
        [[ -n "$source" ]] && SERVICE_SOURCE["$source"]=1
    done < <(awk '
      /^HOTSWAP_SERVICE\(/ { active=1; count=0 }
      active {
        rest=$0
        while (match(rest,/"[^"]+"/)) {
          value=substr(rest,RSTART+1,RLENGTH-2)
          count++; if (count==2) { print value; active=0; break }
          rest=substr(rest,RSTART+RLENGTH)
        }
      }
    ' "$ROOT/engine/composition/hotswap_services.def")
}

load_hotfork_manifest()
{
    local source
    while IFS= read -r source; do
        [[ -n "$source" ]] && HOT_FORK["$source"]=1
    done < <(awk '
      /^HOTFORK_CAPSULE\(/ { active=1; count=0 }
      active {
        rest=$0
        while (match(rest,/"[^"]+"/)) {
          value=substr(rest,RSTART+1,RLENGTH-2)
          count++; if (count==3) { print value; active=0; break }
          rest=substr(rest,RSTART+RLENGTH)
        }
      }
    ' "$ROOT/engine/composition/hotfork_capsules.def")
}

classify()
{
    local path="$1"
    if [ -n "${HOT_FORK[$path]:-}" ]; then
        printf 'HOT_FORK\texact candidate executes in a sandboxed disposable child story'
    elif [ -n "${HOT_EXECUTE[$path]:-}" ]; then
        printf 'HOT_SHADOW_CORE\tpure candidate implementation executed by its frozen owner story'
    elif [ -n "${SHADOW[$path]:-}" ]; then
        printf 'COMPILE_ONLY\tstatic authority shell candidate is compiled but not executed'
    elif [ -n "${SERVICE_SOURCE[$path]:-}" ]; then
        printf 'HOT_SHADOW_CORE\texact service candidate executed by its frozen owner story'
    elif [ -n "${LIVE[$path]:-}" ]; then
        printf 'COMPILE_ONLY\tcompiled allowlist candidate has no owner-bound local story'
    elif is_forbidden_authority "$path"; then
        printf 'forbidden_authority_surface\tconsensus or durable-state owner'
    elif has_mutable_file_static "$path"; then
        printf 'blocked_mutable_file_scope_state\tmodule-owned mutable static'
    elif has_direct_state_access "$path"; then
        printf 'blocked_direct_global_state_access\tdirect state-owner dependency'
    elif is_pure_candidate_root "$path"; then
        printf 'eligible_but_unregistered\tpure candidate outside current islands'
    else
        case "$path" in
            tools/command/*.c|engine/controllers/*.c|engine/controllers/src/*.c)
                printf 'blocked_whole_node_build_assumptions\thost command ABI coupling'
                ;;
            *)
                printf 'requires_fast_restart\tnot admitted by existing module ABI'
                ;;
        esac
    fi
}

load_live_manifest
load_shadow_manifest
load_service_manifest
load_hotfork_manifest

if [ "$MODE" = "--self-test" ]; then
    [ "$(classify core/consensus/src/example.c | cut -f1)" = forbidden_authority_surface ] ||
        fail 'forbidden authority classification regressed'
    [ "$(classify platform/modules/codec/src/cursor.c | cut -f1)" = eligible_but_unregistered ] ||
        fail 'pure codec classification regressed'
    [ "$(classify engine/controllers/src/status_native_handlers.c | cut -f1)" = COMPILE_ONLY ] ||
        fail 'compiled island classification regressed'
    [ "$(classify contexts/commons/services/src/zcode_c23_corpus_service.c | cut -f1)" = HOT_SHADOW_CORE ] ||
        fail 'service island classification regressed'
    [ "$(classify contexts/wallet/services/src/vault_intent_decision_service.c | cut -f1)" = HOT_SHADOW_CORE ] ||
        fail 'shadow service classification regressed'
    [ "$(classify tools/dev/devloop_cycle.c | cut -f1)" = COMPILE_ONLY ] ||
        fail 'static-shell compile-only classification regressed'
    [ "$(classify contexts/commons/modules/vcs/src/source_package_checkout.c | cut -f1)" = HOT_FORK ] ||
        fail 'HOT_FORK capsule classification regressed'
    [ "$(classify tools/command/native_dev_command.c | cut -f1)" = HOT_FORK ] ||
        fail 'highest-churn HOT_FORK owner classification regressed'
    [ "$(classify tools/command/native_dev_hotswap.c | cut -f1)" = HOT_FORK ] ||
        fail 'hot-swap receipt HOT_FORK owner classification regressed'
    [ "$(classify contexts/commons/modules/vcs/src/vcs_devloop.c | cut -f1)" = HOT_FORK ] ||
        fail 'ZVCS envelope HOT_FORK owner classification regressed'
    printf 'dev-loop-history-bench: self-test PASS\n'
    exit 0
fi
[ "$MODE" = run ] || fail 'usage: dev-loop-history-bench.sh [run|--self-test]'

scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-history.XXXXXX")"
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT INT TERM
commits_file="$scratch/commits"
rows_file="$scratch/rows.tsv"
entries_file="$scratch/entries.json"
: >"$commits_file"
: >"$rows_file"

selected=0
while IFS= read -r commit; do
    production=0
    while IFS= read -r path; do
        is_production_tu "$path" || continue
        [ -f "$ROOT/$path" ] || continue
        production=1
        result="$(classify "$path")"
        printf '%s\t%s\t%s\n' "$commit" "$path" "$result" >>"$rows_file"
    done < <(git -C "$ROOT" diff-tree --root --no-commit-id --name-only -r "$commit" -- '*.c')
    [ "$production" -eq 1 ] || continue
    printf '%s\n' "$commit" >>"$commits_file"
    selected=$((selected + 1))
    [ "$selected" -ge "$COMMITS" ] && break
done < <(git -C "$ROOT" log --format='%H' "$HISTORY_BASE" -- '*.c')

[ "$selected" -eq "$COMMITS" ] || fail "history contains only $selected production-C commits"
[ -s "$rows_file" ] || fail 'benchmark parsed zero production C edits'

jq -Rn '[inputs | split("\t") |
  {commit:.[0], path:.[1], class:.[2], reason:.[3]}]' \
  <"$rows_file" >"$entries_file"

mkdir -p "$(dirname "$OUTPUT")"
head_sha="$(git -C "$ROOT" rev-parse HEAD)"
history_base_sha="$(git -C "$ROOT" rev-parse "$HISTORY_BASE^{commit}")"
oldest="$(tail -1 "$commits_file")"
newest="$(head -1 "$commits_file")"
history_digest="$(sha256sum "$rows_file" | awk '{print $1}')"

jq -n \
  --arg schema 'zcl.dev_loop_history_benchmark.v2' \
  --arg head "$head_sha" --arg history_base "$history_base_sha" \
  --arg newest "$newest" --arg oldest "$oldest" \
  --arg digest "$history_digest" --argjson commit_count "$selected" \
  --slurpfile entries "$entries_file" '
  ($entries[0]) as $e |
  ($e | length) as $edits |
  ($e | map(select(.class == "HOT_EXECUTE" or
                   .class == "HOT_SHADOW_CORE" or
                   .class == "HOT_FORK" or
                   .class == "FOCUSED_PROOF")) | length) as $behavior |
  ($e | map(select(.class == "eligible_but_unregistered")) | length) as $eligible |
  ($e | map(select(.class != "forbidden_authority_surface")) | length) as $nonforbidden |
  {schema:$schema, source_head:$head,
   history:{base_commit:$history_base,newest_commit:$newest,oldest_commit:$oldest,
            production_c_commits:$commit_count,edit_occurrences:$edits,
            frozen_rows_sha256:$digest},
   classification:($e | group_by(.class) |
      map({class:.[0].class, edit_occurrences:length,
           unique_translation_units:(map(.path)|unique|length)})),
   coverage:{
      eligible_behavior_feedback_percent:
        (if ($behavior+$eligible)>0 then (10000*$behavior/($behavior+$eligible)|round/100) else 0 end),
      nonforbidden_behavior_feedback_percent:
        (if $nonforbidden>0 then (10000*$behavior/$nonforbidden|round/100) else 0 end),
      behavior_feedback_edit_occurrences:$behavior,
      eligible_unregistered_edit_occurrences:$eligible,
      nonforbidden_edit_occurrences:$nonforbidden},
   representative_benchmark:($e |
      map(select(.class != "forbidden_authority_surface")) |
      group_by(.path) |
      map({path:.[0].path,class:.[0].class,frequency:length}) |
      sort_by([-.frequency,.path]) | .[0:16]),
   latency:{status:"not_measured_by_history_analysis",
            next_action:"run the resident replay benchmark"},
   entries:$e}' >"$OUTPUT"

jq -r --arg receipt "$OUTPUT" \
  '"dev-loop-history-bench: commits=\(.history.production_c_commits) edits=\(.history.edit_occurrences) eligible_behavior=\(.coverage.eligible_behavior_feedback_percent)% nonforbidden_behavior=\(.coverage.nonforbidden_behavior_feedback_percent)% receipt=\($receipt)"' \
  "$OUTPUT"
