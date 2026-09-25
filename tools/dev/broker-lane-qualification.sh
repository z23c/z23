#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Measure compact broker lanes beside one isolated node under a hotload lease.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd -P)

if [[ ${1:-} == --node ]]; then
    [[ $# == 3 ]] || exit 2
    output=$2
    ISO_KIND=soak
    ISO_PORT_BASE=$3
    # shellcheck source=tools/scripts/isolated_node_env.sh
    . "$root/tools/scripts/isolated_node_env.sh"
    iso_init >"$output/isolation.log"
    iso_spawn_node
    ready=0
    for ((attempt=1; attempt<=90; attempt++)); do
        reply=$(ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" \
            "$ISO_RPC_BIN" getblockcount 2>/dev/null || true)
        if [[ $reply == *'"result":0'* ]]; then ready=1; break; fi
        sleep 1
    done
    printf 'ready=%s attempts=%s node_pid=%s\n' "$ready" "$attempt" \
        "$ISO_NODE_PID" >"$output/boot.tsv"
    [[ $ready == 1 ]] || { cp "$ISO_DD/node.log" "$output/node.log"; exit 1; }
    printf 'phase\tindex\tlatency_ms\trpc_exit\tobserved\n' >"$output/rpc.tsv"
    snapshot_pressure() {
        local phase=$1 kind
        for kind in cpu io memory; do
            cp "/proc/pressure/$kind" "$output/pressure-$phase-$kind"
        done
        cp /proc/loadavg "$output/loadavg-$phase"
    }
    sample_rpc() {
        local phase=$1 index=$2 begin end reply rc=0 observed=unavailable
        begin=$(date +%s%N)
        reply=$(ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" \
            "$ISO_RPC_BIN" getblockcount 2>"$output/rpc-error-$phase-$index") || rc=$?
        end=$(date +%s%N)
        [[ $rc != 0 || $reply != *'"result":0'* ]] || observed=height0
        printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$index" \
            "$(((end - begin) / 1000000))" "$rc" "$observed" >>"$output/rpc.tsv"
    }
    snapshot_pressure baseline_start
    for ((i=1; i<=100; i++)); do sample_rpc baseline "$i"; sleep 0.1; done
    snapshot_pressure load_start
    : >"$output/node-ready"
    for ((i=1; i<=900; i++)); do
        [[ ! -e $output/stop-sampling ]] || break
        sample_rpc load "$i"
        sleep 0.1
    done
    snapshot_pressure load_end
    node_alive=0
    if kill -0 "$ISO_NODE_PID"; then node_alive=1; sample_rpc after 1; fi
    cp "$ISO_DD/node.log" "$output/node.log"
    printf 'node_alive=%s\n' "$node_alive" >"$output/node-verdict"
    [[ $node_alive == 1 ]]
    exit
fi

if [[ $# != 3 || ! $2 =~ ^(1|2|4|8)$ || ! $3 =~ ^[0-9]+$ ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR WIDTH(1|2|4|8) ISOLATED_PORT_BASE\n' "$0" >&2
    exit 2
fi
if grep -Fq '/development.slice/' /proc/self/cgroup; then
    printf 'broker-lane-qualification: coordinator must launch outside a devbuild scope\n' >&2
    exit 2
fi
output=$(realpath -m "$1")
width=$2
port_base=$3
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
cd "$root"
sha256sum "$0" tools/dev/factory-throughput-qualification.sh >"$output/harness.sha256"
git rev-parse HEAD >"$output/checkout-commit"
git status --short >"$output/checkout-status"
date -u --iso-8601=seconds >"$output/utc-time"
run_start_ns=$(date +%s%N)
node_pid=
pids=()
cleanup() {
    : >"$output/stop-sampling"
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    [[ -z $node_pid ]] || kill "$node_pid" 2>/dev/null || true
}
trap cleanup INT TERM EXIT
devbuild --wait --class hotload bash "$0" --node "$output" "$port_base" \
    >"$output/node-scope.log" 2>&1 & node_pid=$!
for ((attempt=1; attempt<=180; attempt++)); do
    [[ ! -e $output/node-ready ]] || break
    kill -0 "$node_pid" 2>/dev/null || { cat "$output/node-scope.log" >&2; exit 1; }
    sleep 1
done
[[ -e $output/node-ready ]] || { printf 'node readiness timed out\n' >&2; exit 1; }
work_start_ns=$(date +%s%N)
width_args=()
if ((width > 2)); then width_args=(--qualification-width "$width"); fi
for ((lane=0; lane<width; lane++)); do
    mkdir "$output/lane-$lane"
    devbuild --wait --class normal --compact "${width_args[@]}" bash \
        tools/dev/factory-throughput-qualification.sh \
        "$output/lane-$lane/factory" 2 "$(((lane * 2) % 8))" \
        >"$output/lane-$lane/broker.log" 2>&1 & pids+=("$!")
done
failed=0
admission_complete=0
for ((attempt=1; attempt<=300; attempt++)); do
    admitted=0
    for ((lane=0; lane<width; lane++)); do
        if grep -q 'admitted after' "$output/lane-$lane/broker.log"; then
            ((admitted+=1))
        fi
    done
    if ((admitted == width)); then admission_complete=1; break; fi
    kill -0 "$node_pid" 2>/dev/null || break
    sleep 0.1
done
if (( ! admission_complete )); then
    printf 'qualification admission timed out: %s/%s lanes entered\n' \
        "$admitted" "$width" >&2
    failed=1
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
fi
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
pids=()
work_end_ns=$(date +%s%N)
: >"$output/stop-sampling"
wait "$node_pid" || failed=1
node_pid=
run_end_ns=$(date +%s%N)
printf 'run_start_ns\twork_start_ns\twork_end_ns\trun_end_ns\n%s\t%s\t%s\t%s\n' \
    "$run_start_ns" "$work_start_ns" "$work_end_ns" "$run_end_ns" \
    >"$output/times.tsv"
printf 'admission_complete=%s\n' "$admission_complete" >"$output/admission-verdict"
printf 'lane\tbroker_id\tqueue_wait_ns\n' >"$output/lanes.tsv"
: >"$output/broker-ids"
for ((lane=0; lane<width; lane++)); do
    line=$(sed -n 's/^devbuild: id=\([^ ]*\) .* admitted after \([0-9]*\) ns,.*/\1\t\2/p' \
        "$output/lane-$lane/broker.log" | head -1)
    if [[ -z $line ]]; then
        queued_id=$(sed -n 's/^devbuild: id=\([^ ]*\) .* queued at [0-9]* ns/\1/p' \
            "$output/lane-$lane/broker.log" | head -1)
        printf '%s\t%s\tunavailable\n' "$lane" "${queued_id:-unavailable}" \
            >>"$output/lanes.tsv"
        [[ -z $queued_id ]] || printf '%s\n' "$queued_id" >>"$output/broker-ids"
        failed=1
        continue
    fi
    printf '%s\t%s\n' "$lane" "$line" >>"$output/lanes.tsv"
    printf '%s\n' "${line%%$'\t'*}" >>"$output/broker-ids"
done
node_id=$(sed -n 's/^devbuild: id=\([^ ]*\) .* admitted after [0-9]* ns,.*/\1/p' \
    "$output/node-scope.log" | head -1)
[[ -z $node_id ]] || printf '%s\n' "$node_id" >>"$output/broker-ids"
events=${DEVBUILD_BROKER_STATE:-$HOME/.local/state/development/broker-v1}/events.tsv
if [[ -f $events ]]; then
    awk -F '\t' 'NR==FNR {ids[$1]=1; next} $2 in ids' \
        "$output/broker-ids" "$events" >"$output/broker-events.tsv"
fi
printf 'lane\tjob\trevision\tsource_sha256\tfactory_ok\tuser_s\tsystem_s\tmax_rss_kb\tfs_in\tfs_out\n' \
    >"$output/jobs.tsv"
for ((lane=0; lane<width; lane++)); do
    ledger="$output/lane-$lane/factory/ledger.tsv"
    [[ -f $ledger ]] || { failed=1; continue; }
    awk -F '\t' -v lane="$lane" 'NR>1 {print lane "\t" $1 "\t" $2 "\t" $10 "\t" $19 "\t" $21 "\t" $22 "\t" $23 "\t" $24 "\t" $25}' \
        "$ledger" >>"$output/jobs.tsv"
done
awk -F '\t' -v width="$width" -v elapsed="$((work_end_ns-work_start_ns))" '
    NR>1 {jobs++; good+=$5; unique[$4]=1; cpu+=$6+$7; if($8>rss)rss=$8; fsin+=$9; fsout+=$10}
    END {for (k in unique) distinct++; printf "width=%d jobs=%d factory_good=%d distinct_sources=%d duplicates=%d work_s=%.6f distinct_per_hour=%.3f cpu_s=%.3f peak_job_rss_kb=%d fs_in=%d fs_out=%d\n", width,jobs,good,distinct,jobs-distinct,elapsed/1000000000,distinct*3600000000000/elapsed,cpu,rss,fsin,fsout}' \
    "$output/jobs.tsv" >"$output/summary"
for phase in baseline load; do
    awk -F '\t' -v phase="$phase" '$1==phase {n++; x[n]=$3; if($4!=0||$5!="height0")bad++} END {asort(x); printf "%s_n=%d p95_ms=%d max_ms=%d errors=%d\n",phase,n,x[int(n*.95+0.999)],x[n],bad}' \
        "$output/rpc.tsv" >>"$output/summary"
done
for kind in cpu io memory; do
    before=$(awk '$1=="some" {split($5,a,"="); print a[2]}' \
        "$output/pressure-load_start-$kind")
    after=$(awk '$1=="some" {split($5,a,"="); print a[2]}' \
        "$output/pressure-load_end-$kind")
    printf 'pressure_%s_some_us=%s\n' "$kind" "$((after-before))" \
        >>"$output/summary"
done
cat "$output/admission-verdict" "$output/node-verdict" "$output/summary"
exit "$failed"
