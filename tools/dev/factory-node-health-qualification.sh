#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Measure an isolated regtest node while a bounded package workload runs.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 || ! $2 =~ ^([1-9]|[1-9][0-9]|100)$ ||
      ( ${4:-evolving} != evolving && ${4:-evolving} != throughput ) ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR COUNT(1..100) [PORT_BASE] [evolving|throughput]\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
output=$(realpath -m "$1")
count=$2
workload=${4:-evolving}
if [[ $workload == throughput && ! $count =~ ^(1|2|4|8|16)$ ]]; then
    printf 'throughput concurrency must be 1, 2, 4, 8, or 16\n' >&2
    exit 2
fi
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
cd "$root"
sha256sum "$0" > "$output/harness.sha256"
git rev-parse HEAD > "$output/checkout-commit"
git status --short > "$output/checkout-status"
date --iso-8601=seconds > "$output/local-time"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"

ISO_KIND=soak
ISO_PORT_BASE="${3:-39680}"
# shellcheck source=tools/scripts/isolated_node_env.sh
. tools/scripts/isolated_node_env.sh
iso_init > "$output/isolation.log"
iso_spawn_node

ready=0
for ((attempt=1; attempt<=90; attempt++)); do
    reply=$(ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" \
        "$ISO_RPC_BIN" getblockcount 2>/dev/null || true)
    if [[ $reply == *'"result":0'* ]]; then ready=1; break; fi
    sleep 1
done
printf 'ready=%s attempts=%s node_pid=%s\n' \
    "$ready" "$attempt" "$ISO_NODE_PID" > "$output/boot.tsv"
if [[ $ready != 1 ]]; then
    cp "$ISO_DD/node.log" "$output/node.log"
    exit 1
fi

printf 'phase\tindex\tlatency_ms\trpc_exit\tobserved\n' > "$output/rpc.tsv"
sample_rpc()
{
    local phase=$1 index=$2 begin end reply rc=0 observed=unavailable
    begin=$(date +%s%N)
    reply=$(ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" \
        "$ISO_RPC_BIN" getblockcount 2> "$output/$phase-error-$index") || rc=$?
    end=$(date +%s%N)
    if [[ $rc == 0 && $reply == *'"result":0'* ]]; then observed=height0; fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$index" \
        "$(((end - begin) / 1000000))" "$rc" "$observed" \
        >> "$output/rpc.tsv"
}

for ((i=1; i<=100; i++)); do
    sample_rpc baseline "$i"
    sleep 0.2
done
kill -0 "$ISO_NODE_PID"
(
    for ((i=1; i<=600; i++)); do
        [[ ! -e $output/stop-sampling ]] || break
        sample_rpc load "$i"
        sleep 0.2
    done
) &
sampler_pid=$!
factory_rc=0
if [[ $workload == evolving ]]; then
    tools/dev/factory-evolving-qualification.sh \
        "$output/factory" "$count" build/bin \
        > "$output/factory.stdout" 2> "$output/factory.stderr" || factory_rc=$?
else
    bash tools/dev/factory-throughput-qualification.sh \
        "$output/factory" "$count" \
        > "$output/factory.stdout" 2> "$output/factory.stderr" || factory_rc=$?
fi
: > "$output/stop-sampling"
wait "$sampler_pid"
node_alive=0
if kill -0 "$ISO_NODE_PID"; then
    node_alive=1
    sample_rpc after 1
fi
cp "$ISO_DD/node.log" "$output/node.log"
printf 'factory_exit=%s node_alive=%s\n' "$factory_rc" "$node_alive" \
    > "$output/verdict"
sha256sum "$output/rpc.tsv" "$output/node.log" \
    > "$output/artifacts.sha256"
if [[ -f $output/factory/ledger.tsv ]]; then
    sha256sum "$output/factory/ledger.tsv" >> "$output/artifacts.sha256"
fi
cat "$output/boot.tsv" "$output/verdict"
[[ $node_alive == 1 ]] || exit 1
exit "$factory_rc"
