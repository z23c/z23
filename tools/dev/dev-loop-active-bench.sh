#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Measure recent/current C23+ZCODE live-lane coverage and receipts.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMITS="${ZCL_DEV_ACTIVE_COMMITS:-20}"
OUTPUT="${ZCL_DEV_ACTIVE_OUTPUT:-$ROOT/build/dev-loop/active-benchmark.json}"
NATIVE_LOG="${ZCL_DEV_ACTIVE_NATIVE_LOG:-${HOME:?}/.local/state/zclassic23-dev/native-watch.log}"
LINKER="$ROOT/.cache/zcl-dev-loop/linker-shootout.json"
MODE="${1:-run}"

fail()
{
    printf 'dev-loop-active-bench: %s\n' "$*" >&2
    exit 2
}

is_source_path()
{
    case "$1" in
        *.c|*.h) return 0;;
    esac
    return 1
}

is_c23_zcode_path()
{
    case "$1" in
        *zcode*|*c23*|*market*|*shop*|engine/composition/hotswap_services.def|\
        engine/composition/hotswap_probe_cases.def)
            return 0
            ;;
    esac
    return 1
}

is_forbidden_path()
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

declare -A LIVE_PATH=()

load_live_paths()
{
    local quoted path
    while IFS= read -r quoted; do
        path="${quoted#\"}"
        path="${path%\"}"
        case "$path" in
            *.c|*/src/*.h) LIVE_PATH["$path"]=1;;
        esac
    done < <(git -C "$ROOT" grep -h -o '"[^"]*\.[ch]"' -- \
        engine/composition/hotswap_swappable.def engine/composition/hotswap_islands.def \
        engine/composition/hotswap_services.def)
}

classify_path()
{
    local path="$1"
    if is_forbidden_path "$path"; then
        printf 'forbidden'
    elif [ -n "${LIVE_PATH[$path]:-}" ]; then
        printf 'hot_swap'
    else
        printf 'dev_restart'
    fi
}

extract_active_session_samples()
{
    local native_window="$1" samples="$2" session="$3"
    jq -Rs '
      split("\n") | map(fromjson? | select(type=="object")) as $rows |
      ([range(0; $rows|length) as $i |
        select($rows[$i].schema=="zcl.dev_watch_heartbeat.v1") | $i] |
       last // -1) as $at |
      if $at < 0 then
        {schema:"zcl.dev_active_watcher_session.v1",status:"not_observed",
         selection:"latest_heartbeat",log_record_index:null}
      else
        $rows[$at] +
        {schema:"zcl.dev_active_watcher_session.v1",
         selection:"latest_heartbeat",log_record_index:$at}
      end' "$native_window" >"$session"
    jq -cRs '
      split("\n") | map(fromjson? | select(type=="object")) as $rows |
      ([range(0; $rows|length) as $i |
        select($rows[$i].schema=="zcl.dev_watch_heartbeat.v1") | $i] |
       last // -1) as $at |
      if $at < 0 then empty
      elif (($rows[$at].status//"")=="watching" or
            ($rows[$at].state//"")=="running") then
        $rows[($at+1):][] |
        select(.schema=="zcl.dev_cycle.v1" and
               ((.source_tu//.service_source//"")|
                test("zcode|c23|market|shop")))
      else empty end' "$native_window" >"$samples"
}

aggregate_samples()
{
    local samples="$1" output="$2"
    jq -s '
      def percentile($v; $p):
        if ($v|length) == 0 then null else
          ($v|sort) as $s |
          $s[((((($s|length)*$p)+99)/100|floor)-1)]
        end;
      map(select(type == "object" and
                 (.schema == "zcl.dev_cycle.v1" or
                  .schema == "zcl.dev_active_sample.v1"))) as $s |
      [$s[] | select((.action // "") == "hotswap" and
                     (.status // "") == "passed" and
                     (.runtime_published // false) == true and
                     (.changed_path_count // 1) <= 1) |
        (.elapsed_us // ((.elapsed_ms // 0)*1000))] as $hot |
      [$s[] | select((.action // "") == "restart" and
                     ((.status // "") == "passed" or
                      (.status // "") == "feedback_ready")) |
        (.elapsed_us // ((.elapsed_ms // 0)*1000))] as $restart |
      [$s[] | select((.action // "") == "hotswap" and
                     (.status // "") == "passed" and
                     (.runtime_published // false) == true and
                     (.changed_path_count // 0) > 1) |
        (.elapsed_us // ((.elapsed_ms // 0)*1000))] as $multi |
      {sample_count:($s|length),
       published_sample_count:([$s[]|select(
          (.status//"")=="passed" and (.runtime_published//false))]|length),
       hot_swap:{count:($hot|length),p50_us:percentile($hot;50),
                 p95_us:percentile($hot;95),target_us:250000,
                 target_pass:(if ($hot|length)>0
                              then percentile($hot;95)<250000 else null end)},
       restart:{count:($restart|length),p50_us:percentile($restart;50),
                p95_us:percentile($restart;95)},
       same_island_multi_file:{count:($multi|length),
          p50_us:percentile($multi;50),p95_us:percentile($multi;95),
          target_us:1000000,
          target_pass:(if ($multi|length)>0
                       then percentile($multi;95)<1000000 else null end)},
       processes:{compiler:([$s[]|(.build_receipt.compiler_processes//0)]|add//0),
                  linker:([$s[]|(.build_receipt.linker_processes//0)]|add//0),
                  test:([$s[]|(.proof_receipt.test_processes//0)]|add//0),
                  make:([$s[]|(.make_processes//0)]|add//0),
                  shell:([$s[]|(.shell_processes//0)]|add//0),
                  lto:([$s[]|(.lto_processes//.lto_invocations//0)]|add//0)},
       source_bytes:{complete:all($s[];
          has("source_guard_bytes_read") or (.source_byte_accounting_complete//false)),
          read:([$s[]|(.source_guard_bytes_read//0)]|add//0)},
       cache_hits:([$s[]|select(.build_receipt.artifact_cache_hit//false)]|length),
       deferred_groups:([$s[]|(.proof_receipt.deferred_group_count//0)]|add//0),
       refusals:([$s[]|select((.status//"") != "passed" and
                              (.status//"") != "feedback_ready")]|length),
       refusal_explanations:{complete:all($s[];
          ((.status//"")=="passed" or (.status//"")=="feedback_ready") or
          ((.why_not_live//"")|length)>0),
          missing:([$s[]|select((.status//"")!="passed" and
            (.status//"")!="feedback_ready" and
            ((.why_not_live//"")|length)==0)]|length),
          reasons:([$s[]|select((.status//"")!="passed" and
            (.status//"")!="feedback_ready")|
            {status,action,source_tu:(.source_tu//.service_source//null),
             why_not_live:(.why_not_live//null)}])}}' \
      "$samples" >"$output"
}

self_test()
{
    load_live_paths
    [ "$(classify_path contexts/commons/services/src/zcode_c23_corpus_service.c)" = hot_swap ] ||
        fail 'corpus service source is not live'
    [ "$(classify_path contexts/commons/services/src/zcode_c23_economics_internal.h)" = hot_swap ] ||
        fail 'economics private header is not live'
    [ "$(classify_path contexts/commons/services/include/services/zcode_c23_corpus_service.h)" = dev_restart ] ||
        fail 'public service contract did not select restart'
    [ "$(classify_path core/consensus/src/check_block.c)" = forbidden ] ||
        fail 'consensus path is not forbidden'

    local scratch native_log samples receipt session
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-active-selftest.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    samples="$scratch/samples.jsonl"
    receipt="$scratch/receipt.json"
    native_log="$scratch/native-watch.log"
    session="$scratch/session.json"
    printf '%s\n' \
      '{"schema":"zcl.dev_watch_heartbeat.v1","status":"watching","pid":101}' \
      '{"schema":"zcl.dev_cycle.v1","status":"passed","action":"hotswap","elapsed_us":900000,"runtime_published":true,"source_tu":"contexts/commons/services/src/zcode_c23_corpus_service.c"}' \
      '{"schema":"zcl.dev_watch_heartbeat.v1","status":"stopped","pid":101}' \
      '{"schema":"zcl.dev_watch_heartbeat.v1","status":"watching","pid":202}' \
      'not-json' \
      '{"schema":"zcl.dev_cycle.v1","status":"rejected","action":"hotswap","elapsed_us":800000,"runtime_published":false,"source_tu":"contexts/commons/services/src/zcode_c23_corpus_service.c","why_not_live":"candidate KAT refused publication"}' \
      '{"schema":"zcl.dev_cycle.v1","status":"passed","action":"hotswap","elapsed_us":100000,"runtime_published":true,"source_tu":"contexts/commons/services/src/zcode_c23_corpus_service.c"}' \
      '{"schema":"zcl.dev_cycle.v1","status":"passed","action":"hotswap","elapsed_us":120000,"runtime_published":true,"source_tu":"contexts/market/services/src/shop_reputation_view_service.c"}' \
      '{"schema":"zcl.dev_cycle.v1","status":"blocked","action":"reload","runtime_published":false,"service_source":"contexts/market/services/src/shop_want_view_service.c","why_not_live":"frozen service contract changed"}' \
      >"$native_log"
    extract_active_session_samples "$native_log" "$samples" "$session"
    jq -e '.status == "watching" and .pid == 202' "$session" >/dev/null ||
        fail 'active watcher session selection regressed'
    [ "$(wc -l <"$samples")" -eq 4 ] ||
        fail 'stale watcher samples leaked into the active session'
    printf '%s\n' \
      '{"schema":"zcl.dev_active_sample.v1","status":"passed","action":"hotswap","elapsed_us":100000,"runtime_published":true,"changed_path_count":1,"source_guard_bytes_read":10,"build_receipt":{"compiler_processes":1,"linker_processes":1,"artifact_cache_hit":false}}' \
      '{"schema":"zcl.dev_active_sample.v1","status":"passed","action":"hotswap","elapsed_us":800000,"runtime_published":true,"changed_path_count":2,"source_guard_bytes_read":20,"build_receipt":{"compiler_processes":1,"linker_processes":1,"artifact_cache_hit":true}}' \
      '{"schema":"zcl.dev_active_sample.v1","status":"rejected","action":"hotswap","elapsed_us":900000,"runtime_published":false,"changed_path_count":1,"source_guard_bytes_read":5,"why_not_live":"candidate compile failed","build_receipt":{"compiler_processes":1,"linker_processes":0,"artifact_cache_hit":false}}' \
      '{"schema":"zcl.dev_active_sample.v1","status":"blocked","action":"restart","elapsed_us":4000000,"changed_path_count":1,"source_guard_bytes_read":30,"why_not_live":"restart proof group cap exceeded","build_receipt":{"compiler_processes":0,"linker_processes":0,"artifact_cache_hit":false},"proof_receipt":{"deferred_group_count":3}}' \
      >>"$samples"
    aggregate_samples "$samples" "$receipt"
    jq -e '
      .sample_count == 8 and .hot_swap.count == 3 and
      .hot_swap.p50_us == 100000 and
      .hot_swap.p95_us == 120000 and
      .same_island_multi_file.p95_us == 800000 and
      .same_island_multi_file.target_pass == true and
      .hot_swap.target_pass == true and
      .processes.compiler == 3 and .processes.linker == 2 and
      .source_bytes.complete == false and .source_bytes.read == 65 and
      .cache_hits == 1 and .deferred_groups == 3 and .refusals == 4 and
      .refusal_explanations.complete == true and
      .refusal_explanations.missing == 0' \
      "$receipt" >/dev/null || fail 'sample aggregation contract regressed'
    printf 'dev-loop-active-bench: self-test PASS\n'
}

run_benchmark()
{
    [[ "$COMMITS" =~ ^[1-9][0-9]*$ ]] ||
        fail 'ZCL_DEV_ACTIVE_COMMITS must be positive'
    command -v jq >/dev/null || fail 'jq is required'
    load_live_paths

    local scratch rows commits_file native_window samples metrics entries
    local head diff_digest snapshot session linker_receipt
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-active-bench.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    rows="$scratch/rows.tsv"
    commits_file="$scratch/commits"
    samples="$scratch/samples.jsonl"
    native_window="$scratch/native-watch.jsonl"
    metrics="$scratch/metrics.json"
    session="$scratch/session.json"
    entries="$scratch/entries.json"
    : >"$rows"
    : >"$samples"

    git -C "$ROOT" log -n "$COMMITS" --format='%H' -- '*.c' '*.h' \
        >"$commits_file"
    while IFS= read -r commit; do
        while IFS= read -r path; do
            is_source_path "$path" || continue
            printf '%s\t%s\t%s\t%s\n' "$commit" "$path" \
                "$(classify_path "$path")" \
                "$(is_c23_zcode_path "$path" && printf true || printf false)" \
                >>"$rows"
        done < <(git -C "$ROOT" diff-tree --root --no-commit-id --name-only \
                 -r "$commit" -- '*.c' '*.h')
    done <"$commits_file"
    while IFS= read -r path; do
        is_source_path "$path" || continue
        printf 'WORKTREE\t%s\t%s\t%s\n' "$path" \
            "$(classify_path "$path")" \
            "$(is_c23_zcode_path "$path" && printf true || printf false)" \
            >>"$rows"
    done < <(git -C "$ROOT" diff --name-only HEAD -- '*.c' '*.h')
    [ -s "$rows" ] || fail 'active window contains no C23 source edits'

    jq -Rn '[inputs | split("\t") |
      {source:.[0],path:.[1],action:.[2],c23_zcode:(.[3]=="true")}]' \
      <"$rows" >"$entries"

    if [ -r "$NATIVE_LOG" ]; then
        tail -n 4096 "$NATIVE_LOG" >"$native_window"
        extract_active_session_samples "$native_window" "$samples" "$session"
        snapshot="$(jq -Rs '
          split("\n") | map(fromjson? | select(type=="object" and
            .schema=="zcl.dev_source_snapshot.v1")) | last //
          {status:"not_observed"}' "$native_window")"
    else
        snapshot='{"status":"not_observed"}'
        printf '%s\n' \
          '{"schema":"zcl.dev_active_watcher_session.v1","status":"not_observed","selection":"latest_heartbeat","log_record_index":null}' \
          >"$session"
    fi
    aggregate_samples "$samples" "$metrics"
    if [ -r "$LINKER" ] && jq -e '
         .schema=="zcl.dev_linker_shootout.v1" and .status=="complete"' \
         "$LINKER" >/dev/null 2>&1; then
        linker_receipt="$(jq -c '{status,selected,results}' "$LINKER")"
    else
        linker_receipt='{"status":"not_run"}'
    fi

    head="$(git -C "$ROOT" rev-parse HEAD)"
    diff_digest="$({ git -C "$ROOT" diff --binary HEAD; } | sha256sum | awk '{print $1}')"
    mkdir -p "$(dirname "$OUTPUT")"
    jq -n --arg head "$head" --arg diff "$diff_digest" \
      --argjson commits "$COMMITS" --argjson snapshot "$snapshot" \
      --argjson session "$(<"$session")" \
      --argjson linker "$linker_receipt" --slurpfile entries "$entries" \
      --slurpfile metrics "$metrics" '
      ($entries[0]) as $e | ($metrics[0]) as $m |
      [$e[]|select(.action!="forbidden")] as $nf |
      [$nf[]|select(.action=="hot_swap")] as $hot |
      [$nf[]|select(.c23_zcode)] as $zc |
      [$zc[]|select(.action=="hot_swap")] as $zchot |
      {schema:"zcl.dev_loop_active_benchmark.v1",source_head:$head,
       current_diff_sha256:$diff,recent_commits_requested:$commits,
       coverage:{nonforbidden_occurrences:($nf|length),
         hot_swap_occurrences:($hot|length),
         hot_swap_percent:(if ($nf|length)>0 then
           (10000*($hot|length)/($nf|length)|round/100) else 0 end),
         restart_percent:(if ($nf|length)>0 then
           (10000*([$nf[]|select(.action=="dev_restart")]|length)/($nf|length)|round/100)
           else 0 end),
         c23_zcode_nonforbidden_occurrences:($zc|length),
         c23_zcode_hot_swap_occurrences:($zchot|length),
         c23_zcode_hot_swap_percent:(if ($zc|length)>0 then
           (10000*($zchot|length)/($zc|length)|round/100) else 0 end),
         target_percent:70,
         target_pass:(($zc|length)>0 and (($zchot|length)*100 >= ($zc|length)*70))},
       observations:($m+{watcher_session:$session,
                          watcher_source_snapshot:$snapshot}),
       linker_shootout:$linker,
       frozen_history:{path:"build/dev-loop/history-benchmark.json",
         status:"preserved_separate"},entries:$e}' >"$OUTPUT"
    jq -r --arg output "$OUTPUT" '
      "dev-loop-active-bench: c23_zcode_live=\(.coverage.c23_zcode_hot_swap_percent)% all_live=\(.coverage.hot_swap_percent)% samples=\(.observations.sample_count) receipt=\($output)"' \
      "$OUTPUT"
}

case "$MODE" in
    --self-test) self_test;;
    run) run_benchmark;;
    *) fail 'usage: dev-loop-active-bench.sh [run|--self-test]';;
esac
