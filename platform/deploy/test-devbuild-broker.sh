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
cc -std=c23 -Wall -Wextra -Werror -pedantic \
    "$root/../../tools/dev/fixtures/devbuild_broker/identity.c" \
    -o "$scratch/identity"
[[ $("$root/devbuild-broker" --plan --project z23 make commons-demo) == *'class=background '* ]] || {
    printf 'commons-demo did not select background admission\n' >&2; exit 1;
}
[[ $("$root/devbuild-broker" --plan --project z23 build/bin/z23-dev dev proof step) == *'class=release '* ]] || {
    printf 'direct proof step did not select release admission\n' >&2; exit 1;
}
[[ $("$root/devbuild-broker" --plan --project z23 --class legacy build/bin/z23-dev dev proof step) == *'class=legacy '* ]] || {
    printf 'explicit proof class was overridden\n' >&2; exit 1;
}

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

"$root/devbuild-broker" --wait --project qedc --class normal sleep 2 \
    >"$scratch/qedc-head-running.log" 2>&1 & one=$!
for _ in {1..100}; do
    grep -q 'admitted' "$scratch/qedc-head-running.log" 2>/dev/null && break
    sleep 0.05
done
grep -q 'admitted' "$scratch/qedc-head-running.log" || {
    printf 'QEDC head fixture did not enter\n' >&2; exit 1;
}
"$root/devbuild-broker" --wait --project qedc --class legacy true \
    >"$scratch/qedc-head-blocked.log" 2>&1 & two=$!
sleep 0.1
"$root/devbuild-broker" --wait --project z23 --class normal true \
    >"$scratch/z23-behind-head.log" 2>&1
kill -0 "$one" 2>/dev/null || {
    printf 'incompatible QEDC queue head blocked fitting Z23 work\n' >&2
    exit 1
}
wait "$one" "$two"
printf 'devbuild broker: incompatible queue head does not block fitting work PASS\n'

old_tick=$(awk '{print $22}' "/proc/$$/stat")
printf '%s %s %s qedc legacy 8 24 1 100 %s broker-v2\n' \
    "$$" "$old_tick" old-queue.scope "$(( $(date +%s%N) - 10000000000 ))" \
    >"$DEVBUILD_BROKER_STATE/queue/old-queue"
"$root/devbuild-broker" --wait --project z23 --class normal true \
    >"$scratch/old-queue-bypass.log" 2>&1
[[ -e $DEVBUILD_BROKER_STATE/queue/old-queue ]] || {
    printf 'new broker rewrote a prior wrapper queue entry\n' >&2; exit 1;
}
rm -f -- "$DEVBUILD_BROKER_STATE/queue/old-queue"
printf 'devbuild broker: prior-wrapper queue stays isolated during upgrade PASS\n'

"$root/devbuild-broker" --wait --project z23 --class normal \
    bash -c 'sleep 20 & exit 0' >"$scratch/orphan.log" 2>&1
orphan_id=$(awk -F '\t' '$3 == "queued" {id=$2} END {print id}' \
    "$DEVBUILD_BROKER_STATE/events.tsv")
for _ in {1..40}; do
    scope_state=$(systemctl --user show "devbuild-$orphan_id.scope" \
        -p ActiveState --value 2>/dev/null || true)
    [[ $scope_state == inactive || $scope_state == failed ]] && break
    sleep 0.1
done
[[ $scope_state == inactive || $scope_state == failed ]] || {
    printf 'detached child held the completed scope open\n' >&2; exit 1;
}
"$root/devbuild-broker" --wait --project z23 --class normal true \
    >"$scratch/post-orphan.log" 2>&1
[[ ! -e $DEVBUILD_BROKER_STATE/running/$orphan_id ]] || {
    printf 'completed scope retained its broker lease\n' >&2; exit 1;
}
printf 'devbuild broker: completed scope contains detached child PASS\n'

printf '#!/usr/bin/env bash\nsleep 1.5\n:\n' >"$scratch/legacy.sh"
bash "$scratch/legacy.sh" & legacy=$!
sleep 0.1
printf '%s %s\n' "$("$scratch/identity" "$scratch/legacy.sh")" "$(date +%s%N)" \
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

legacy_before=$(awk -F '\t' '$3 == "admitted" && $5 == "legacy" {n++} END {print n+0}' \
    "$DEVBUILD_BROKER_STATE/events.tsv")
"$root/devbuild-broker" --wait --project z23 sleep 1 >"$scratch/z23-legacy.log" 2>&1 & one=$!
"$root/devbuild-broker" --wait --project qedc sleep 1 >"$scratch/qedc-legacy.log" 2>&1 & two=$!
for _ in {1..100}; do
    legacy_admitted=$(awk -F '\t' '$3 == "admitted" && $5 == "legacy" {n++} END {print n+0}' \
        "$DEVBUILD_BROKER_STATE/events.tsv")
    [[ $legacy_admitted == $((legacy_before + 2)) ]] && break
    sleep 0.05
done
[[ $legacy_admitted == $((legacy_before + 2)) ]] || {
    printf 'old default project jobs did not overlap\n' >&2; exit 1;
}
wait "$one" "$two"
grep -q 'RAM 24G' "$scratch/z23-legacy.log"
grep -q 'RAM 24G' "$scratch/qedc-legacy.log"
printf 'devbuild broker: legacy 24 GiB project compatibility PASS\n'

printf '#!/usr/bin/env bash\nsleep 5\n:\n' >"$scratch/qedc-legacy.sh"
bash "$scratch/qedc-legacy.sh" --project qedc & legacy=$!
sleep 0.1
printf '%s %s\n' "$("$scratch/identity" "$scratch/qedc-legacy.sh")" "$(date +%s%N)" \
    >"$DEVBUILD_BROKER_STATE/legacy-inode"
old_tick=$(awk '{print $22}' "/proc/$$/stat")
printf '%s %s %s z23 legacy 12 24 1 100 %s\n' \
    "$$" "$old_tick" old-waiter.scope "$(( $(date +%s%N) - 10000000000 ))" \
    >"$DEVBUILD_BROKER_STATE/queue/old-waiter"
"$root/devbuild-broker" --wait --project z23 --class normal sleep 2 \
    >"$scratch/foreign-one.log" 2>&1 & one=$!
"$root/devbuild-broker" --wait --project z23 --class normal sleep 2 \
    >"$scratch/foreign-two.log" 2>&1 & two=$!
"$root/devbuild-broker" --wait --project z23 --class hotload sleep 0.1 \
    >"$scratch/foreign-upgrade.log" 2>&1
kill -0 "$legacy" 2>/dev/null || {
    printf 'foreign-project work waited for old QEDC wrapper\n' >&2; exit 1;
}
kill -0 "$one" 2>/dev/null && kill -0 "$two" 2>/dev/null || {
    printf 'two normal lanes did not overlap with hotload and old QEDC\n' >&2
    exit 1
}
wait "$one" "$two"
rm -f -- "$DEVBUILD_BROKER_STATE/queue/old-waiter"
wait "$legacy"
"$root/devbuild-broker" --wait --project z23 --class normal true \
    >"$scratch/drained-upgrade.log" 2>&1
[[ ! -e $DEVBUILD_BROKER_STATE/legacy-inode ]] || {
    printf 'foreign-project marker did not drain\n' >&2; exit 1;
}
printf 'devbuild broker: bounded Z23 overlap during old QEDC drain PASS\n'
