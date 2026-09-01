#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Prove 20 warm edit-to-visible resident hot-swap cycles under 250 ms p95.

set -euo pipefail

ROOT="${ZCL_SOURCE_ROOT:-$(pwd -P)}"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/zclassic23-dev}"
DATADIR="${ZCL_DEV_DATADIR:-${HOME:?}/.zclassic-c23-dev}"
RPC_PORT="${ZCL_DEV_RPC_PORT:-18252}"
SOURCE="$ROOT/engine/controllers/src/status_native_handlers.c"
RUNS="${ZCL_HOTSWAP_BENCH_RUNS:-20}"
TARGET_US="${ZCL_HOTSWAP_BENCH_TARGET_US:-250000}"
MARKER='ZCL_HOTSWAP_BENCH:'

fail() { printf 'hotswap-resident-bench: %s\n' "$*" >&2; exit 1; }
[[ "$RUNS" =~ ^[0-9]+$ && "$RUNS" -ge 1 ]] || fail 'RUNS must be positive'
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
[[ -f "$SOURCE" ]] || fail "missing benchmark source: $SOURCE"
[[ "$(LC_ALL=C grep -c "${MARKER}00000000" "$SOURCE")" == 1 ]] ||
    fail 'benchmark marker is absent or already modified'
command -v jq >/dev/null || fail 'jq is required'
command -v openssl >/dev/null || fail 'openssl is required'

canonical_root="$(realpath "$ROOT")"
workspace_id="$({
    printf 'domain\0zcl.dev_workspace.v1\0canonical_root\0%s\0' "$canonical_root"
} | openssl dgst -sha3-256 -r | awk '{print $1}')"
STATE="$HOME/.local/state/zclassic23-dev/workspaces/$workspace_id/native-cycle.json"

backup="$(mktemp "${TMPDIR:-/tmp}/zcl-hotswap-bench.XXXXXX")"
cp -p "$SOURCE" "$backup"
watcher_id=0
cleanup() {
    cp -p "$backup" "$SOURCE"
    rm -f "$backup"
    if [[ "$watcher_id" -gt 0 ]]; then
        "$BIN" -datadir="$DATADIR" -rpcport="$RPC_PORT" dev loop stop \
            --input="{\"watcher_id\":$watcher_id}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

"$BIN" -datadir="$DATADIR" -rpcport="$RPC_PORT" core status >/dev/null ||
    fail 'isolated dev node is not serving its native status leaf'
ensure="$($BIN -datadir="$DATADIR" -rpcport="$RPC_PORT" dev loop ensure \
    --input="{\"root\":\"$canonical_root\",\"mode\":\"auto\"}")"
watcher_id="$(jq -er '.data.watcher_id' <<<"$ensure")" ||
    fail 'auto watcher did not return an id'
[[ "$(jq -r '.data.runtime_publication' <<<"$ensure")" == true ]] ||
    fail 'auto watcher is not armed for isolated runtime publication'

mkdir -p "$ROOT/build/hotswap"
samples="$(mktemp "${TMPDIR:-/tmp}/zcl-hotswap-samples.XXXXXX")"
trap 'rm -f "$samples"; cleanup' EXIT INT TERM
previous_epoch="$(jq -r '.epoch // 0' "$STATE" 2>/dev/null || printf 0)"
previous_hash=''
nonce_base=$(( $(date +%s%N) % 90000000 ))

for ((i = 1; i <= RUNS; i++)); do
    nonce="$(printf '%08d' $(((nonce_base + i) % 100000000)))"
    staged="$(mktemp "$ROOT/engine/controllers/src/.status-bench.XXXXXX")"
    sed "s/${MARKER}00000000/${MARKER}${nonce}/" "$backup" >"$staged"
    chmod --reference="$SOURCE" "$staged"
    start_ns="$(date +%s%N)"
    mv -f "$staged" "$SOURCE"

    deadline_ns=$((start_ns + 5000000000))
    while :; do
        if [[ -r "$STATE" ]]; then
            epoch="$(jq -r '.epoch // 0' "$STATE" 2>/dev/null || printf 0)"
            producer="$(jq -r '.cycle.producer // ""' "$STATE" 2>/dev/null || true)"
            published="$(jq -r '.cycle.runtime_published // false' "$STATE" 2>/dev/null || true)"
            source_tu="$(jq -r '.cycle.source_tu // ""' "$STATE" 2>/dev/null || true)"
            hash="$(jq -r '.cycle.build_receipt.artifact_sha256 // ""' "$STATE" 2>/dev/null || true)"
            if [[ "$epoch" -gt "$previous_epoch" &&
                  "$producer" == resident-build-authority &&
                  "$published" == true &&
                  "$source_tu" == engine/controllers/src/status_native_handlers.c &&
                  "$hash" =~ ^[0-9a-f]{64}$ && "$hash" != "$previous_hash" ]]; then
                break
            fi
        fi
        now_ns="$(date +%s%N)"
        [[ "$now_ns" -lt "$deadline_ns" ]] ||
            fail "cycle $i did not publish within 5 seconds"
        sleep 0.001
    done
    end_ns="$(date +%s%N)"
    elapsed_us=$(((end_ns - start_ns) / 1000))
    compile_us="$(jq -r '.cycle.build_receipt.compile_us' "$STATE")"
    link_us="$(jq -r '.cycle.build_receipt.link_us' "$STATE")"
    activation_us="$(jq -r '.cycle.build_receipt.activation_us' "$STATE")"
    printf '%s %s %s %s %s %s\n' "$i" "$elapsed_us" "$compile_us" \
        "$link_us" "$activation_us" "$hash" >>"$samples"
    printf 'cycle %02d: %6d us (compile=%d link=%d activate=%d)\n' \
        "$i" "$elapsed_us" "$compile_us" "$link_us" "$activation_us" >&2
    previous_epoch="$epoch"
    previous_hash="$hash"

    # Return to the canonical marker without generating a second inotify
    # event: each next staged file is built from the untouched backup.
done

rank95=$(((RUNS * 95 + 99) / 100))
rank50=$(((RUNS + 1) / 2))
p95_us="$(awk '{print $2}' "$samples" | sort -n | sed -n "${rank95}p")"
p50_us="$(awk '{print $2}' "$samples" | sort -n | sed -n "${rank50}p")"
receipt="$ROOT/build/hotswap/resident-benchmark.json"
jq -n \
    --arg schema 'zcl.hotswap_edit_bench.v1' \
    --arg source_tu 'engine/controllers/src/status_native_handlers.c' \
    --argjson runs "$RUNS" --argjson target_us "$TARGET_US" \
    --argjson p50_us "$p50_us" --argjson p95_us "$p95_us" \
    --argjson passed "$([[ "$p95_us" -le "$TARGET_US" ]] && printf true || printf false)" \
    --rawfile rows "$samples" '
      def sample($line):
        ($line | split(" ")) as $v |
        {run:($v[0]|tonumber), edit_to_visible_us:($v[1]|tonumber),
         compile_us:($v[2]|tonumber), link_us:($v[3]|tonumber),
         activation_us:($v[4]|tonumber), artifact_sha256:$v[5]};
      {schema:$schema, source_tu:$source_tu, runs:$runs,
       target_us:$target_us, p50_us:$p50_us, p95_us:$p95_us,
       passed:$passed,
       samples:($rows | split("\n") | map(select(length > 0) | sample(.)))}' \
    >"$receipt"
printf 'hotswap-resident-bench: p50=%sus p95=%sus target=%sus receipt=%s\n' \
    "$p50_us" "$p95_us" "$TARGET_US" "$receipt"
[[ "$p95_us" -le "$TARGET_US" ]] || exit 1
