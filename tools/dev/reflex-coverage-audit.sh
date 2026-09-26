#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Measure useful reflex coverage over a recent production-C window.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/zclassic23-dev}"
HISTORY="${ZCL_REFLEX_HISTORY:-$ROOT/build/dev-loop/substrate-history-benchmark.json}"
OUTPUT="${ZCL_REFLEX_COVERAGE_OUTPUT:-$ROOT/build/dev-loop/reflex-coverage-audit.json}"
ONLY_PATH="${ZCL_REFLEX_COVERAGE_ONLY:-}"
MODE="${1:-run}"

fail() { printf 'reflex-coverage-audit: %s\n' "$*" >&2; exit 2; }

aggregate()
{
    local history="$1" samples="$2" output="$3"
    jq -n --slurpfile history "$history" --slurpfile samples "$samples" '
      ($history[0]) as $h | ($samples) as $s |
      def observed($path): first($s[] | select(.path==$path)) // null;
      [$h.entries[] | select(.class!="forbidden_authority_surface") |
       . as $entry | (observed(.path)) as $sample |
       $entry + {sample:$sample,
         useful:($sample != null and $sample.result_bound and
                 ($sample.feedback_us//0)>0),
         feedback_us:($sample.feedback_us//null),
         fallback_reason:(if $sample == null then
             (.class + ": " + .reason)
           elif $sample.result_bound then ""
           else ($sample.failure//"registered fast owner returned no bound story")
           end)}] as $rows |
      ($rows|length) as $total |
      def covered($limit): [$rows[]|select(.useful and .feedback_us<$limit)]|length;
      {schema:"zcl.reflex_coverage_audit.v2",status:
         (if all($rows[] | select(.class=="COMPILE_ONLY" or
                                  .class=="HOT_EXECUTE" or
                                  .class=="HOT_SHADOW_CORE" or
                                  .class=="HOT_FORK"); .sample!=null)
          then "complete" else "partial" end),
       source_head:$h.source_head,
       history_rows_sha256:$h.history.frozen_rows_sha256,
       production_c_commits:$h.history.production_c_commits,
       nonforbidden_edit_occurrences:$total,
       measured_fast_paths:($s|length),
       coverage:{under_100ms_occurrences:covered(100000),
         under_100ms_percent:(10000*covered(100000)/$total|round/100),
         under_250ms_occurrences:covered(250000),
         under_250ms_percent:(10000*covered(250000)/$total|round/100),
         under_1s_occurrences:covered(1000000),
         under_1s_percent:(10000*covered(1000000)/$total|round/100),
         slower_fallback_occurrences:([$rows[]|select(.useful|not)]|length),
         slower_fallback_percent:
           (10000*([$rows[]|select(.useful|not)]|length)/$total|round/100)},
       fallbacks:([$rows[]|select(.useful|not)]|group_by(.fallback_reason)|
         map({reason:.[0].fallback_reason,edit_occurrences:length,
              unique_paths:(map(.path)|unique|length)})|
         sort_by([-.edit_occurrences,.reason])),
       fast_paths:($s|sort_by([-.frequency,.path])),rows:$rows}' >"$output"
}

self_test()
{
    local scratch history samples output
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-reflex-coverage-selftest.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    history="$scratch/history.json"; samples="$scratch/samples.jsonl"
    output="$scratch/output.json"
    printf '%s\n' '{"source_head":"abc","history":{"frozen_rows_sha256":"def","production_c_commits":2},"entries":[{"path":"a.c","class":"HOT_SHADOW_CORE","reason":"registered"},{"path":"a.c","class":"HOT_SHADOW_CORE","reason":"registered"},{"path":"b.c","class":"requires_fast_restart","reason":"restart"},{"path":"c.c","class":"forbidden_authority_surface","reason":"forbidden"}]}' >"$history"
    printf '%s\n' '{"path":"a.c","frequency":2,"result_bound":true,"feedback_class":"HOT_SHADOW_CORE","feedback_us":90000,"event":"STORY_GREEN","failure":""}' >"$samples"
    aggregate "$history" "$samples" "$output"
    jq -e '.status=="complete" and .nonforbidden_edit_occurrences==3 and
      .coverage.under_100ms_occurrences==2 and
      .coverage.under_100ms_percent==66.67 and
      .coverage.slower_fallback_occurrences==1 and
      .fallbacks[0].edit_occurrences==1' "$output" >/dev/null ||
        fail 'aggregation contract regressed'
    printf 'reflex-coverage-audit: self-test PASS\n'
}

if [[ "$MODE" == --self-test ]]; then self_test; exit 0; fi
[[ "$MODE" == run ]] || fail 'usage: reflex-coverage-audit.sh [run|--self-test]'
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
jq -e '.schema=="zcl.dev_loop_history_benchmark.v2" and
       (.entries|type)=="array"' "$HISTORY" >/dev/null ||
    fail 'current production history receipt is missing or invalid'

scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-reflex-coverage.XXXXXX")"
rows="$scratch/rows.jsonl"; samples="$scratch/samples.jsonl"
current_source=""; current_backup=""; watcher_id=0; watcher_session=""
stop_watcher()
{
    if [[ "$watcher_id" -gt 1 ]]; then
        "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" \
            >/dev/null 2>&1 || true
        watcher_id=0
    fi
}
restore_current()
{
    if [[ -n "$current_source" && -f "$current_backup" ]]; then
        cp -p -- "$current_backup" "$current_source"
    fi
}
cleanup()
{
    stop_watcher
    restore_current
    rm -rf -- "$scratch"
}
trap cleanup EXIT INT TERM

drive_to_terminal()
{
    local wait_for_edit="$1" input loops drive_rc
    result=''; event=''; drive_rc=0
    for ((loops = 0; loops < 16; loops++)); do
        input="$(jq -cn --argjson after "$after" \
          --argjson wait "$wait_for_edit" \
          '{after_epoch:$after,wait_for_edit:$wait,timeout_ms:5000}')"
        drive_rc=0
        result="$($BIN dev drive --input="$input")" || drive_rc=$?
        event="$(jq -r '.data.event//""' <<<"$result" 2>/dev/null || true)"
        next="$(jq -r '.data.epoch//0' <<<"$result" 2>/dev/null || printf 0)"
        if [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$after" ]]; then
            after="$next"
        else
            break
        fi
        case "$event" in
            STORY_GREEN|STORY_RED|FOCUSED_GREEN|FOCUSED_PARTIAL|FOCUSED_RED|COMPILE_GREEN|COMPILE_RED)
                break;;
            PROOF_PENDING|"") break;;
        esac
        wait_for_edit=false
    done
    rc="$drive_rc"
}

    jq -c --arg only "$ONLY_PATH" '.entries|map(select(
                               ($only=="" or .path==$only) and
                               (.class=="COMPILE_ONLY" or
                               .class=="HOT_EXECUTE" or
                               .class=="HOT_SHADOW_CORE" or
                               .class=="HOT_FORK")))|
  group_by(.path)|map({path:.[0].path,frequency:length})|
  sort_by([-.frequency,.path])[]' "$HISTORY" >"$rows"
[[ -s "$rows" ]] || fail 'history window has no registered fast owners'

sample_no=0
while IFS= read -r row; do
    sample_no=$((sample_no + 1))
    path="$(jq -r '.path' <<<"$row")"
    frequency="$(jq -r '.frequency' <<<"$row")"
    case "$path" in /*|*..*|*[!A-Za-z0-9_./-]*) fail "unsafe path: $path";; esac
    current_source="$ROOT/$path"
    [[ -f "$current_source" && ! -L "$current_source" ]] ||
        fail "fast owner is not a regular file: $path"
    # The audit is often run against the candidate being measured. Preserve
    # its exact current bytes rather than requiring a clean Git baseline.
    current_backup="$scratch/backup-$sample_no.c"
    cp -p -- "$current_source" "$current_backup"

    begin="$($BIN dev begin)"
    watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")"
    watcher_session="$(jq -er '.data.watcher_session' <<<"$begin")"
    after="$(jq -er '.data.epoch' <<<"$begin")"
    begin_cursor="$after"
    # Prime the owner once. This admits dependency baselines and contracts in
    # the resident service; it is intentionally outside the timed sample.
    staged="$(mktemp "$(dirname "$current_source")/.reflex-coverage.XXXXXX")"
    cp -p -- "$current_backup" "$staged"
    printf '\n/* ZCL_REFLEX_COVERAGE_WARM:%02d:%s */\n' "$sample_no" "$$" >>"$staged"
    chmod --reference="$current_source" "$staged"
    mv -f -- "$staged" "$current_source"
    drive_to_terminal true
    warm_event="$event"
    warm_cursor="$after"

    # A second distinct candidate is the measured warm edit.
    staged="$(mktemp "$(dirname "$current_source")/.reflex-coverage.XXXXXX")"
    cp -p -- "$current_backup" "$staged"
    printf '\n/* ZCL_REFLEX_COVERAGE_TIMED:%02d:%s */\n' "$sample_no" "$$" >>"$staged"
    chmod --reference="$current_source" "$staged"
    measured_start_cursor="$after"
    start_ns="$(date +%s%N)"
    mv -f -- "$staged" "$current_source"
    drive_to_terminal true
    end_ns="$(date +%s%N)"
    result_bound=false
    feedback_class="$(jq -r '.data.feedback_class//""' <<<"$result" 2>/dev/null || true)"
    candidate_executed="$(jq -r '.data.candidate_bytes_executed//false' <<<"$result" 2>/dev/null || true)"
    object_root="$(jq -r '.data.candidate_object_root//""' <<<"$result" 2>/dev/null || true)"
    module_root="$(jq -r '.data.candidate_module_root//""' <<<"$result" 2>/dev/null || true)"
    story_root="$(jq -r '.data.story_root//""' <<<"$result" 2>/dev/null || true)"
    fixture_root="$(jq -r '.data.story_fixture_root//""' <<<"$result" 2>/dev/null || true)"
    observation_root="$(jq -r '.data.observation_root//""' <<<"$result" 2>/dev/null || true)"
    case "$event:$feedback_class:$candidate_executed" in
      STORY_GREEN:HOT_EXECUTE:true|STORY_GREEN:HOT_SHADOW_CORE:true|STORY_GREEN:HOT_FORK:true|FOCUSED_GREEN:FOCUSED_PROOF:true)
        if [[ "$object_root" =~ ^[0-9a-f]{64}$ &&
              "$module_root" =~ ^[0-9a-f]{64}$ &&
              "$story_root" =~ ^[0-9a-f]{64}$ &&
              "$fixture_root" =~ ^[0-9a-f]{64}$ &&
              "$observation_root" =~ ^[0-9a-f]{64}$ ]]; then
          result_bound=true
        fi;;
    esac
    feedback_us="$(jq -r '.data.feedback_us//0' <<<"$result" 2>/dev/null || printf 0)"
    failure="$(jq -r 'if (.error.code//"")!="" then
      (.error.code+": "+(.error.message//""))
      else (.data.why_not_live//.data.blocker//"") end' <<<"$result" 2>/dev/null || true)"
    jq -cn --arg path "$path" --argjson frequency "$frequency" \
      --arg event "$event" --argjson result_bound "$result_bound" \
      --arg feedback_class "$feedback_class" \
      --argjson feedback_us "$feedback_us" \
      --argjson wall_us "$(((end_ns-start_ns)/1000))" \
      --argjson exit_code "$rc" --arg failure "$failure" \
      --argjson begin_cursor "$begin_cursor" \
      --arg warm_event "$warm_event" --argjson warm_cursor "$warm_cursor" \
      --argjson measured_start_cursor "$measured_start_cursor" \
      --argjson end_cursor "$after" \
      '{path:$path,frequency:$frequency,event:$event,
        feedback_class:$feedback_class,
        result_bound:$result_bound,feedback_us:$feedback_us,wall_us:$wall_us,
        exit_code:$exit_code,failure:$failure,begin_cursor:$begin_cursor,
        warm_event:$warm_event,warm_cursor:$warm_cursor,
        measured_start_cursor:$measured_start_cursor,end_cursor:$end_cursor}' \
        >>"$samples"
    printf 'coverage %02d %-62s %8sus %s\n' "$sample_no" "$path" \
      "$feedback_us" "${event:-UNBOUND}" >&2

    stop_watcher
    restore_current
    cmp -s -- "$current_backup" "$current_source" ||
        fail "source restoration mismatch: $path"
    current_source=""; current_backup=""
done <"$rows"

mkdir -p "$(dirname "$OUTPUT")"
aggregate "$HISTORY" "$samples" "$OUTPUT.tmp"
mv "$OUTPUT.tmp" "$OUTPUT"
trap - EXIT INT TERM
rm -rf -- "$scratch"
jq -r --arg output "$OUTPUT" '
  "reflex-coverage-audit: under100=\(.coverage.under_100ms_percent)% under250=\(.coverage.under_250ms_percent)% under1s=\(.coverage.under_1s_percent)% fallback=\(.coverage.slower_fallback_percent)% receipt=\($output)"' "$OUTPUT"
