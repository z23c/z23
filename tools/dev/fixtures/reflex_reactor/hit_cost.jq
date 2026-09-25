# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# purpose: Join reflex A/B samples with their sealed cycle events into per-stage MISS/HIT rows.
#
# Inputs: $samples (bench drive samples), $events (sealed dev_cycle events),
# $source_tu, $artifact_cache, $pairs. Times are monotonic microseconds.

def pct($v; $p):
  ($v | sort) as $s |
  if ($s | length) == 0 then null
  else $s[(((($s | length) * $p) + 99) / 100 | floor) - 1] end;
def metric($v):
  {count: ($v | length), min_us: ($v | min), p50_us: pct($v; 50),
   p95_us: pct($v; 95), max_us: ($v | max)};
def diff($a; $b): if $a == null or $b == null or $a == 0 or $b == 0
  then null else $a - $b end;

def stage_fields:
  ["wall_us", "detect_us", "idle_after_edit_us", "impact_us",
   "source_epoch_hash_us", "impact_calc_us", "reflex_us",
   "plan_load_us", "inputs_us", "dependency_hash_us", "key_us",
   "lookup_us", "verify_us", "materialize_us", "compile_us", "link_us",
   "build_total_us", "load_us", "execute_us", "module_hash_us",
   "runner_us", "reply_us", "story_flush_us", "tail_us",
   "proof_schedule_us", "watcher_cpu_us", "children_cpu_us",
   "cycle_cpu_us", "cgroup_throttled_us", "proof_spawn_after_story_us",
   "proof_run_us", "proof_exit_after_cancel_us", "proof_cpu_us",
   "compiler_processes", "linker_processes", "shadow_forks",
   "proof_workers", "process_spawns"];

($events | map(select(.phase == "IMPACT_READY"))) as $impacts |
([$impacts[] | .prior_cycle | select(. != null)] |
  map({key: .edit_epoch, value: .}) | from_entries) as $traces |
([$impacts[] | .proof_workers_reaped[]?] |
  map({key: .edit_epoch, value: .}) | from_entries) as $proofs |
[$samples[] as $s |
  ([$events[] | select(.edit_epoch == $s.edit_epoch)]) as $bound |
  ([$bound[] | select(.phase == "IMPACT_READY")][0]) as $impact |
  ([$bound[] | select(.build_stages != null)][0]) as $compile |
  ([$bound[] | select(.phase == "STORY_GREEN")][0]) as $story |
  ($traces[$s.edit_epoch]) as $t |
  ($proofs[$s.edit_epoch]) as $p |
  ($compile.build_stages // {}) as $b |
  ($story.resident // {}) as $r |
  {kind: $s.kind, pair: $s.pair, edit_epoch: $s.edit_epoch,
   source_root: $impact.blobs[0].new_blob_sha3,
   action_key: $compile.build_receipt.artifact_cache_key,
   candidate_object_root: $story.candidate_object_root,
   candidate_module_root: $story.candidate_module_root,
   loaded_mapping_root: $story.loaded_mapping_root,
   artifact_path: $compile.build_receipt.artifact_path,
   candidate_bytes_executed: $story.candidate_bytes_executed,
   artifact_cache_hit: $compile.build_receipt.artifact_cache_hit,
   start_monotonic_us: $s.start_monotonic_us,
   end_monotonic_us: $s.end_monotonic_us,
   wall_us: ($s.end_monotonic_us - $s.start_monotonic_us),
   detect_us: diff($t.fs_event_us; $s.start_monotonic_us),
   idle_after_edit_us: diff($t.idle_wait_us; $s.start_monotonic_us),
   impact_us: diff($t.impact_ready_us; $t.fs_event_us),
   source_epoch_hash_us: $impact.immutable_epoch_creation_us,
   impact_calc_us: $impact.impact_calculation_us,
   reflex_us: diff($story.event_monotonic_us; $t.impact_ready_us),
   plan_load_us: $b.plan_load_us, inputs_us: $b.inputs_us,
   dependency_hash_us: $b.dependency_hash_us, key_us: $b.key_us,
   lookup_us: $b.lookup_us, verify_us: $b.verify_us,
   materialize_us: $b.materialize_us, compile_us: $b.compile_us,
   link_us: $b.link_us, build_total_us: $b.build_total_us,
   load_us: $r.load_or_spawn_us, execute_us: $r.execute_us,
   module_hash_us: $r.module_hash_us, runner_us: $r.elapsed_us,
   reply_us: diff($s.end_monotonic_us; $story.event_monotonic_us),
   story_flush_us: diff($t.reflex_return_us; $story.event_monotonic_us),
   tail_us: diff($t.cycle_end_us; $t.reflex_return_us),
   proof_schedule_us: diff($t.proof_scheduled_us; $t.stream_flushed_us),
   watcher_cpu_us: (if $t == null then null
     else $t.watcher_user_us + $t.watcher_sys_us end),
   children_cpu_us: (if $t == null then null
     else $t.children_user_us + $t.children_sys_us end),
   cycle_cpu_us: (if $t == null then null
     else $t.watcher_user_us + $t.watcher_sys_us +
          $t.children_user_us + $t.children_sys_us end),
   cgroup_throttled_us: $t.cgroup_throttled_us,
   proof_spawn_after_story_us: diff($p.spawned_us; $story.event_monotonic_us),
   proof_run_us: (if $p == null then null
     elif $p.cancel_us > 0 then $p.cancel_us - $p.spawned_us
     else $p.reaped_us - $p.spawned_us end),
   proof_exit_after_cancel_us: diff($p.reaped_us; $p.cancel_us),
   proof_cpu_us: (if $p == null or $p.user_us < 0 then null
     else $p.user_us + $p.sys_us end),
   proof_cancelled: (if $p == null then null else $p.cancel_us > 0 end),
   proof_exit_code: $p.exit_code, proof_signal: $p.signal,
   compiler_processes: $compile.build_receipt.compiler_processes,
   linker_processes: $compile.build_receipt.linker_processes,
   shadow_forks: (if $r.forked == true then 1 else 0 end),
   proof_workers: $t.proof_workers_spawned,
   process_spawns: (($compile.build_receipt.compiler_processes // 0) +
     ($compile.build_receipt.linker_processes // 0) +
     (if $r.forked == true then 1 else 0 end) +
     ($t.proof_workers_spawned // 0) + 1),
   cycle_trace: $t, proof_worker: $p,
   build_stages: $b}] as $rows |
def summarize($kind):
  [$rows[] | select(.kind == $kind)] as $k |
  reduce stage_fields[] as $f ({};
    .[$f] = metric([$k[] | .[$f] | select(. != null)]));
{schema: "zcl.reflex_hit_cost_benchmark.v1", source_tu: $source_tu,
 artifact_cache: $artifact_cache, pairs: $pairs,
 order: "warmup A, warmup B, then (MISS nonce_i, HIT exact A) x pairs, two trailers",
 distinct_edit_epochs: ([$rows[] | .edit_epoch] | unique | length),
 hit_artifact_cache_hits: ([$rows[] | select(.kind == "hit" and
   .artifact_cache_hit == true)] | length),
 miss_artifact_cache_hits: ([$rows[] | select(.kind == "miss" and
   .artifact_cache_hit == true)] | length),
 traced_samples: ([$rows[] | select(.cycle_trace != null)] | length),
 proof_samples: ([$rows[] | select(.proof_worker != null)] | length),
 summary: {miss: summarize("miss"), hit: summarize("hit")},
 samples: [$rows[] | select(.kind == "miss" or .kind == "hit")],
 warmup_and_trailers: [$rows[] | select(.kind != "miss" and .kind != "hit")]}
