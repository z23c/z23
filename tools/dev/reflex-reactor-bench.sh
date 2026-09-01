#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Reproduce the 20-distinct-edit zero-wait reactor latency gate.

set -euo pipefail

ROOT="${ZCL_SOURCE_ROOT:-$(pwd -P)}"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/zclassic23-dev}"
SOURCE="$ROOT/contexts/wallet/services/src/vault_intent_decision_service.c"
RUNS="${ZCL_REFLEX_BENCH_RUNS:-20}"
OUTPUT="${ZCL_REFLEX_BENCH_OUTPUT:-$ROOT/build/dev-loop/reflex-reactor-benchmark.json}"
MARKER='ZCL_REFLEX_BENCH:'

fail() { printf 'reflex-reactor-bench: %s\n' "$*" >&2; exit 2; }
proc_cpu_ticks()
{
    local pid="$1"
    [[ -r "/proc/$pid/stat" ]] || fail "watcher /proc/$pid/stat unavailable"
    perl -e '
      my $line = <>; $line =~ s/^.*\) // or die "bad stat";
      my @f = split / /, $line;
      print $f[11] + $f[12] + $f[13] + $f[14], "\n";
    ' "/proc/$pid/stat"
}
[[ "$RUNS" =~ ^[0-9]+$ && "$RUNS" -ge 1 && "$RUNS" -le 99 ]] ||
    fail 'RUNS must be 1..99'
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
[[ "$(LC_ALL=C grep -c "${MARKER} 00000000" "$SOURCE")" == 1 ]] ||
    fail 'benchmark marker is absent or already modified'
command -v jq >/dev/null || fail 'jq is required'

backup="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-source.XXXXXX")"
samples="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-samples.XXXXXX")"
events="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-events.XXXXXX")"
cache_samples="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-cache.XXXXXX")"
watcher_id=0
cleanup()
{
    if [[ "$watcher_id" -gt 0 ]]; then
        "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id}" \
            >/dev/null 2>&1 || true
    fi
    cp -p "$backup" "$SOURCE"
    rm -f "$backup" "$samples" "$events" "$cache_samples"
}
trap cleanup EXIT INT TERM
cp -p "$SOURCE" "$backup"

begin="$($BIN dev begin)"
watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")" ||
    fail 'warm watcher did not return an id'
after="$(jq -er '.data.epoch' <<<"$begin")" ||
    fail 'warm watcher did not return its event cursor'
first_epoch="$after"
nonce_base="$(( $(date +%s%N) % 99999900 ))"
clock_ticks="$(getconf CLK_TCK)"
[[ "$clock_ticks" =~ ^[1-9][0-9]*$ ]] || fail 'CLK_TCK unavailable'
cpu_start_ticks="$(proc_cpu_ticks "$watcher_id")"
main_start_ns="$(date +%s%N)"

for ((i = 1; i <= RUNS; i++)); do
    nonce="$(printf '%08d' $(((nonce_base + i) % 100000000)))"
    staged="$(mktemp "$ROOT/engine/services/src/.reflex-bench.XXXXXX")"
    sed "s/${MARKER} 00000000/${MARKER} ${nonce}/" "$backup" >"$staged"
    chmod --reference="$SOURCE" "$staged"
    start_ns="$(date +%s%N)"
    mv -f "$staged" "$SOURCE"
    result="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":true,\"timeout_ms\":5000}")"
    end_ns="$(date +%s%N)"
    jq -e '.ok == true and .data.event == "STORY_GREEN" and
           .data.runtime_published == false and
           (.data.edit_epoch | test("^[0-9a-f]{64}$"))' \
        <<<"$result" >/dev/null || fail "run $i did not return STORY_GREEN"
    after="$(jq -r '.data.epoch' <<<"$result")"
    jq -c --argjson run "$i" \
        --argjson wall_us "$(((end_ns - start_ns) / 1000))" \
        '{run:$run,epoch:.data.epoch,edit_epoch:.data.edit_epoch,
          story_us:.data.feedback_us,drive_dispatch_us:.elapsed_us,
          wall_us:$wall_us}' <<<"$result" >>"$samples"
done

# Prove the useful-RED budget with a compile-valid behavior regression. This
# changes only the proposal returned by the pure shadow core; the static vault
# authority shell is never loaded, invoked, or published by the benchmark.
staged="$(mktemp "$ROOT/engine/services/src/.reflex-bench-red.XXXXXX")"
red_nonce="$(printf '%08d' $(((nonce_base + RUNS + 1) % 100000000)))"
sed -e "s/${MARKER} 00000000/${MARKER} ${red_nonce}/" \
    -e 's/decision->code = VAULT_INTENT_DECISION_ALLOW;/decision->code = VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS;/' \
    "$backup" >"$staged"
[[ "$(LC_ALL=C grep -c 'decision->code = VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS;' "$staged")" == 1 ]] ||
    fail 'could not stage the behavior-red candidate'
chmod --reference="$SOURCE" "$staged"
red_start_ns="$(date +%s%N)"
mv -f "$staged" "$SOURCE"
red_result="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":true,\"timeout_ms\":5000}")"
red_end_ns="$(date +%s%N)"
jq -e '.ok == true and .data.event == "STORY_RED" and
       .data.runtime_published == false and
       (.data.edit_epoch | test("^[0-9a-f]{64}$")) and
       .data.feedback_us < 1000000' <<<"$red_result" >/dev/null ||
    fail 'compile-valid behavior regression did not return STORY_RED under 1s'
red_feedback_us="$(jq -er '.data.feedback_us' <<<"$red_result")"
red_wall_us="$(((red_end_ns - red_start_ns) / 1000))"
after="$(jq -r '.data.epoch' <<<"$red_result")"
last_epoch="$after"
main_end_ns="$(date +%s%N)"
cpu_end_ticks="$(proc_cpu_ticks "$watcher_id")"
cpu_time_us="$(((cpu_end_ticks - cpu_start_ticks) * 1000000 / clock_ticks))"
main_wall_us="$(((main_end_ns - main_start_ns) / 1000))"

# Measure exact edit/revert cache service on the same warm watcher. Two
# distinct green candidates are admitted once, then alternated. Every timed
# cycle must reuse the verified module with no compiler or linker child while
# still running a fresh forked story.
candidate_a="$(printf '%08d' $(((nonce_base + RUNS + 2) % 100000000)))"
candidate_b="$(printf '%08d' $(((nonce_base + RUNS + 3) % 100000000)))"
run_green_candidate()
{
    local nonce="$1" label="${2:-}" staged start_ns end_ns result raw epoch
    staged="$(mktemp "$ROOT/engine/services/src/.reflex-cache.XXXXXX")"
    sed "s/${MARKER} 00000000/${MARKER} ${nonce}/" "$backup" >"$staged"
    chmod --reference="$SOURCE" "$staged"
    start_ns="$(date +%s%N)"
    mv -f "$staged" "$SOURCE"
    result="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":true,\"timeout_ms\":5000}")"
    end_ns="$(date +%s%N)"
    jq -e '.ok == true and .data.event == "STORY_GREEN" and
           .data.runtime_published == false' <<<"$result" >/dev/null ||
        fail "cache candidate $nonce did not return STORY_GREEN"
    after="$(jq -er '.data.epoch' <<<"$result")"
    [[ -z "$label" ]] && return 0
    epoch="$after"
    raw="$($BIN dev loop wait --input="{\"after_epoch\":$((epoch - 1)),\"timeout_ms\":100}")"
    jq -e '.ok == true and .data.phase == "STORY_GREEN" and
           .data.build_receipt.artifact_cache_hit == true and
           .data.build_receipt.compiler_processes == 0 and
           .data.build_receipt.linker_processes == 0 and
           .data.resident.forked == true' <<<"$raw" >/dev/null ||
        fail "$label did not use the exact verified cache"
    jq -cn --arg label "$label" --argjson epoch "$epoch" \
      --argjson feedback_us "$(jq -r '.data.elapsed_us' <<<"$raw")" \
      --argjson runner_us "$(jq -r '.data.resident.elapsed_us' <<<"$raw")" \
      --argjson wall_us "$(((end_ns - start_ns) / 1000))" \
      '{label:$label,epoch:$epoch,feedback_us:$feedback_us,
        runner_us:$runner_us,wall_us:$wall_us,
        compiler_processes:0,linker_processes:0}' >>"$cache_samples"
}

run_green_candidate "$candidate_a"
run_green_candidate "$candidate_b"
for ((i = 1; i <= 10; i++)); do
    run_green_candidate "$candidate_a" exact_revert
    run_green_candidate "$candidate_b" exact_edit
done

# Freeze the event range before restoring the benchmark source. The sealed
# journal remains readable after the watcher stops.
"$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id}" >/dev/null
watcher_id=0
cp -p "$backup" "$SOURCE"

cursor="$first_epoch"
while [[ "$cursor" -lt "$last_epoch" ]]; do
    result="$($BIN dev loop wait --input="{\"after_epoch\":$cursor,\"timeout_ms\":100}")"
    jq -e '.ok == true' <<<"$result" >/dev/null ||
        fail "sealed event $((cursor + 1)) was unavailable"
    cursor="$(jq -r '.data.epoch' <<<"$result")"
    jq -c '.data' <<<"$result" >>"$events"
done

mkdir -p "$(dirname "$OUTPUT")"
jq -n --slurpfile samples "$samples" --slurpfile events "$events" \
    --slurpfile cache_samples "$cache_samples" \
    --arg source_tu 'contexts/wallet/services/src/vault_intent_decision_service.c' \
    --argjson runs "$RUNS" \
    --argjson red_feedback_us "$red_feedback_us" \
    --argjson red_wall_us "$red_wall_us" \
    --argjson cpu_time_us "$cpu_time_us" \
    --argjson main_wall_us "$main_wall_us" '
  def pct($v; $p):
    ($v | sort) as $s |
    $s[((((($s|length)*$p)+99)/100|floor)-1)];
  def metric($v):
    {count:($v|length),min_us:($v|min),p50_us:pct($v;50),
     p95_us:pct($v;95),max_us:($v|max)};
  def byte_metric($v):
    {count:($v|length),min_bytes:($v|min),p50_bytes:pct($v;50),
     p95_bytes:pct($v;95),max_bytes:($v|max)};
  [$events[]|select(.phase=="EDIT_SEEN")|.elapsed_us] as $edit |
  [$events[]|select(.phase=="IMPACT_READY")|.elapsed_us] as $impact |
  [$events[]|select(.phase=="IMPACT_READY")|
    .immutable_epoch_creation_us] as $epoch_create |
  [$events[]|select(.phase=="IMPACT_READY")|
    .impact_calculation_us] as $impact_calc |
  [$events[]|select(.phase=="IMPACT_READY")|
    .changed_bytes_read] as $bytes_read |
  [$events[]|select(.phase=="COMPILE_GREEN")|.elapsed_us] as $compile |
  [$events[]|select(.phase=="COMPILE_GREEN")|
    .build_receipt.compile_us] as $compiler |
  [$events[]|select(.phase=="STORY_GREEN")|.elapsed_us] as $story |
  [$events[]|select(.phase=="STORY_GREEN")|
    .resident.elapsed_us] as $shadow_runner |
  [range(1; $events|length) as $i |
    select($events[$i].phase=="IMPACT_READY" and
           $events[$i-1].phase=="SUPERSEDED") |
    $events[$i].elapsed_us] as $cancel |
  [$samples[]|.wall_us] as $wall |
  {schema:"zcl.reflex_reactor_benchmark.v1",source_tu:$source_tu,
   runs:$runs,
   latency:{edit_seen:metric($edit),impact_ready:metric($impact),
            immutable_epoch_creation:metric($epoch_create),
            impact_calculation:metric($impact_calc),
            compile_diagnostic:metric($compile),compiler:metric($compiler),
            hot_shadow_story:metric($story),
            hot_shadow_runner:metric($shadow_runner),
            cancellation_to_new_impact:metric($cancel),
            edit_to_drive_reply:metric($wall),
            first_useful_red:(metric([$red_feedback_us]) +
              {feedback_us:$red_feedback_us,
               edit_to_drive_reply_us:$red_wall_us})},
   resources:{cpu:{scope:"resident_watcher_plus_reaped_children",
                  cpu_time_us:$cpu_time_us,wall_us:$main_wall_us,
                  usage_percent:(100*$cpu_time_us/$main_wall_us)},
              changed_bytes_read:byte_metric($bytes_read)},
   exact_cache:{edit:{feedback:metric([$cache_samples[]|
                       select(.label=="exact_edit")|.feedback_us]),
                      runner:metric([$cache_samples[]|
                       select(.label=="exact_edit")|.runner_us]),
                      wall:metric([$cache_samples[]|
                       select(.label=="exact_edit")|.wall_us])},
                revert:{feedback:metric([$cache_samples[]|
                         select(.label=="exact_revert")|.feedback_us]),
                        runner:metric([$cache_samples[]|
                         select(.label=="exact_revert")|.runner_us]),
                        wall:metric([$cache_samples[]|
                         select(.label=="exact_revert")|.wall_us])},
                compiler_processes:([$cache_samples[]|
                  .compiler_processes]|add),
                linker_processes:([$cache_samples[]|
                  .linker_processes]|add)},
   targets_us:{edit_seen_p95:10000,impact_ready_p95:50000,
               compile_diagnostic:250000,hot_shadow_story:1000000,
               first_useful_red:1000000},
   target_pass:{edit_seen:(pct($edit;95)<10000),
                impact_ready:(pct($impact;95)<50000),
                compile_diagnostic:(pct($compile;95)<250000),
                hot_shadow_story:(pct($story;95)<1000000),
                first_useful_red:($red_feedback_us<1000000)},
   latency_firewall:{make_processes:([$events[]|.make_processes//0]|add),
     shell_processes:([$events[]|.shell_processes//0]|add),
     git_operations:([$events[]|.git_operations//0]|add),
     publication_operations:([$events[]|.publication_operations//0]|add),
     remote_operations:([$events[]|.remote_operations//0]|add),
     network_operations:([$events[]|.network_operations//0]|add),
     storage_ack_waits:([$events[]|.storage_ack_waits//0]|add),
     sqlite_operations:([$events[]|.sqlite_operations//0]|add),
     full_program_links:([$events[]|.full_program_links//0]|add),
     full_tree_scans:([$events[]|.full_tree_scans//0]|add)},
   process_trace:{
     compiler_processes:([$events[]|select(.phase=="COMPILE_GREEN")|
       .build_receipt.compiler_processes]|add),
     module_linker_processes:([$events[]|select(.phase=="COMPILE_GREEN")|
       .build_receipt.linker_processes]|add),
     shadow_forks:([$events[]|select(.phase=="STORY_GREEN" or
       .phase=="STORY_RED")|select(.resident.forked==true)]|length),
     foreground_test_processes:0},
   event_counts:($events|group_by(.phase)|map({key:.[0].phase,value:length})|
     from_entries),samples:$samples}' >"$OUTPUT"

jq -e --argjson runs "$RUNS" '
  .runs==$runs and .event_counts.EDIT_SEEN==($runs+1) and
  .event_counts.IMPACT_READY==($runs+1) and
  .event_counts.COMPILE_GREEN==($runs+1) and
  .event_counts.STORY_GREEN==$runs and .event_counts.STORY_RED==1 and
  .process_trace.compiler_processes==($runs+1) and
  .process_trace.module_linker_processes==($runs+1) and
  .process_trace.shadow_forks==($runs+1) and
  .process_trace.foreground_test_processes==0 and
  .latency.immutable_epoch_creation.count==($runs+1) and
  .latency.impact_calculation.count==($runs+1) and
  .latency.cancellation_to_new_impact.count==$runs and
  .resources.changed_bytes_read.count==($runs+1) and
  .resources.cpu.wall_us>0 and .resources.cpu.cpu_time_us>0 and
  .exact_cache.edit.feedback.count==10 and
  .exact_cache.revert.feedback.count==10 and
  .exact_cache.compiler_processes==0 and
  .exact_cache.linker_processes==0 and
  (.target_pass|to_entries|all(.value==true)) and
  (.latency_firewall|to_entries|all(.value==0))' "$OUTPUT" >/dev/null ||
    fail 'latency, event-count, or firewall gate failed'
jq -r --arg output "$OUTPUT" '
  "reflex-reactor-bench: edit_p95=\(.latency.edit_seen.p95_us)us impact_p95=\(.latency.impact_ready.p95_us)us compile_p95=\(.latency.compile_diagnostic.p95_us)us story_p95=\(.latency.hot_shadow_story.p95_us)us red=\(.latency.first_useful_red.feedback_us)us reply_p95=\(.latency.edit_to_drive_reply.p95_us)us receipt=\($output)"' "$OUTPUT"
