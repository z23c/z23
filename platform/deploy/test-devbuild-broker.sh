#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/devbuild-broker-test.XXXXXX")
export DEVBUILD_BROKER_STATE="$scratch/state"
one= two= hot= third= proof=
cleanup() {
    for pid in "$one" "$two" "$hot" "$third" "$proof"; do
        [[ -z $pid ]] || wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$scratch"
}
trap cleanup EXIT

"$root/devbuild-broker" --wait --project z23 --class normal sleep 2 >"$scratch/one.log" 2>&1 & one=$!
"$root/devbuild-broker" --wait --project z23 --class normal sleep 2 >"$scratch/two.log" 2>&1 & two=$!
for _ in {1..100}; do
    admitted=$(awk -F '\t' '$3 == "admitted" && $5 == "normal" {n++} END {print n+0}' \
        "$DEVBUILD_BROKER_STATE/events.tsv" 2>/dev/null || true)
    [[ $admitted == 2 ]] && break
    sleep 0.05
done
[[ ${admitted:-0} == 2 ]] || { printf 'two normal lanes did not overlap\n' >&2; exit 1; }

"$root/devbuild-broker" --wait --project z23 --class hotload sleep 0.2 >"$scratch/hot.log" 2>&1 & hot=$!
"$root/devbuild-broker" --wait --project z23 --class normal sleep 0.1 >"$scratch/third.log" 2>&1 & third=$!
wait "$hot"
if ! kill -0 "$one" 2>/dev/null || ! kill -0 "$two" 2>/dev/null; then
    printf 'normal lanes ended before hotload admission could be checked\n' >&2
    exit 1
fi
if awk -F '\t' '$3 == "admitted" && $5 == "normal" {n++} END {exit n == 2 ? 0 : 1}' \
    "$DEVBUILD_BROKER_STATE/events.tsv"; then
    :
else
    printf 'third normal lane bypassed the two-lane cap\n' >&2
    exit 1
fi
wait "$one" "$two" "$third"
awk -F '\t' '
    $3 == "admitted" && $5 == "normal" {normal++}
    $3 == "admitted" && $5 == "hotload" {hot++}
    $3 == "release" {released++}
    END {if (normal != 3 || hot != 1 || released != 4) exit 1}
' "$DEVBUILD_BROKER_STATE/events.tsv" || {
    printf 'missing admission or release events\n' >&2; exit 1;
}
printf 'devbuild broker: two normal lanes, reserved hotload lane, queue and release PASS\n'

"$root/devbuild-broker" --wait --project z23 --class normal sleep 1 >"$scratch/four.log" 2>&1 & one=$!
"$root/devbuild-broker" --wait --project z23 --class normal sleep 1 >"$scratch/five.log" 2>&1 & two=$!
for _ in {1..100}; do
    admitted=$(awk -F '\t' '$3 == "admitted" && $5 == "normal" {n++} END {print n+0}' \
        "$DEVBUILD_BROKER_STATE/events.tsv")
    [[ $admitted == 5 ]] && break
    sleep 0.05
done
[[ $admitted == 5 ]] || { printf 'priority fixture lanes did not enter\n' >&2; exit 1; }
"$root/devbuild-broker" --wait --project z23 --class release sleep 0.2 >"$scratch/proof.log" 2>&1 & proof=$!
sleep 0.1
"$root/devbuild-broker" --wait --project z23 --class normal sleep 0.1 >"$scratch/six.log" 2>&1 & third=$!
wait "$one" "$two" "$proof" "$third"
awk -F '\t' '
    $3 == "admitted" && $5 == "release" {release_at=NR}
    $3 == "admitted" && $5 == "normal" {normal++; if (normal == 6) sixth_at=NR}
    END {if (!release_at || !sixth_at || release_at >= sixth_at) exit 1}
' "$DEVBUILD_BROKER_STATE/events.tsv" || {
    printf 'release proof was overtaken by ordinary work\n' >&2; exit 1;
}
awk -F '\t' '
    $3 == "queued" {queued[$2]=$1; count++}
    $3 == "admitted" {
        if (!($2 in queued) || $1 < queued[$2] || $6 !~ /^[0-9]+$/) bad=1
        admitted++
    }
    END {if (bad || count != 8 || admitted != 8) exit 1}
' "$DEVBUILD_BROKER_STATE/events.tsv" || {
    printf 'queue timestamps do not bind admission waits\n' >&2; exit 1;
}
printf 'devbuild broker: release proof priority PASS\n'

printf '#!/usr/bin/env bash\nsleep 1.5\n' >"$scratch/legacy.sh"
bash "$scratch/legacy.sh" & legacy=$!
sleep 0.1
printf '%s %s\n' "$(stat -Lc '%d:%i' "$scratch/legacy.sh")" "$(date +%s%N)" \
    >"$DEVBUILD_BROKER_STATE/legacy-inode"
gate_start=$(date +%s%N)
"$root/devbuild-broker" --wait --project z23 --class hotload sleep 0.1 \
    >"$scratch/post-upgrade.log" 2>&1
gate_end=$(date +%s%N)
wait "$legacy"
[[ ! -e $DEVBUILD_BROKER_STATE/legacy-inode ]] &&
    ((gate_end - gate_start >= 1000000000)) || {
        printf 'new admission crossed the old-wrapper drain gate\n' >&2
        exit 1
    }
printf 'devbuild broker: old-wrapper drain gate PASS\n'

"$root/devbuild-broker" --wait --project z23 sleep 1 >"$scratch/z23-legacy.log" 2>&1 & one=$!
"$root/devbuild-broker" --wait --project qedc sleep 1 >"$scratch/qedc-legacy.log" 2>&1 & two=$!
for _ in {1..100}; do
    legacy_admitted=$(awk -F '\t' '$3 == "admitted" && $5 == "legacy" {n++} END {print n+0}' \
        "$DEVBUILD_BROKER_STATE/events.tsv")
    [[ $legacy_admitted == 2 ]] && break
    sleep 0.05
done
[[ $legacy_admitted == 2 ]] || {
    printf 'old default project jobs did not overlap\n' >&2; exit 1;
}
wait "$one" "$two"
grep -q 'RAM 24G' "$scratch/z23-legacy.log"
grep -q 'RAM 24G' "$scratch/qedc-legacy.log"
printf 'devbuild broker: legacy 24 GiB project compatibility PASS\n'
