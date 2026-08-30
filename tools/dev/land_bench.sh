#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# land_bench.sh — how long does the landing queue actually make you wait?
#
# WHY THIS IS A SCRIPT AND NOT AN ASSERTION IN THE TEST GROUP
# ------------------------------------------------------------
# The obvious way to defend "submitting never blocks" is a test that times a
# submit and fails over a threshold. tools/lint/check_no_wallclock_assertion.sh
# forbids that, and its reasoning is this project's own: a duration bound
# grades the MACHINE, not the code. This fleet keeps 7200rpm boxes ON PURPOSE
# because a slow box is the only instrument that reveals where the code
# assumes fast storage, and a millisecond ceiling would report those honest
# machines as broken. The same rule this project applies to peers —
# reachability and speed must never collapse into one pass/fail scalar —
# applies to contributors' boxes.
#
# So the invariant is asserted structurally in test_land_queue.c (one submit
# writes exactly ONE frame; its cost does not grow with queue depth or with a
# gate run outstanding), and the latency is MEASURED here and reported as
# data: n samples, min / median / p95 / max. A number that is data can be
# read; a number that is a verdict can only be obeyed or ignored.
#
# WHAT IT MEASURES
#   submit  end-to-end `land.sh submit`, the thing an agent runs and waits for
#   status  end-to-end `land.sh status --branch`, the "is it done yet" read
#
# Both are deliberately measured through the SHELL FRONT DOOR rather than in
# C: what matters is the wall time the agent experiences, which includes bash
# startup and the git rev-parse. Measuring the library call alone would
# flatter the result by hiding the part the user actually pays.
#
# Run it against a live queue with a lander mid-gate and the submit column is
# the anti-convoy evidence: if submitters serialised behind gate runs, this
# is where a 15-minute number would appear.
#
# Usage:
#   land_bench.sh [--n 100] [--queue PATH] [--label TEXT]
#
# Exit: 0 measured, 2 usage or environment. It grades nothing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

N=100
LABEL="land_bench"
BENCH_QUEUE=""

die() { printf 'land_bench: %s\n' "$*" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --n)     N="${2:-}";           shift 2 || die "--n needs a value" ;;
        --queue) BENCH_QUEUE="${2:-}"; shift 2 || die "--queue needs a value" ;;
        --label) LABEL="${2:-}";       shift 2 || die "--label needs a value" ;;
        *) die "unknown option: $1" ;;
    esac
done
case "$N" in
    ''|*[!0-9]*) die "--n must be a positive integer" ;;
esac
[ "$N" -ge 1 ] || die "--n must be at least 1"

# Its own queue by default. Benchmarking into the real one would fill a
# working queue with a hundred branches nobody asked to land.
STATE_ROOT="${ZCL_LAND_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-land}"
if [ -z "$BENCH_QUEUE" ]; then
    BENCH_QUEUE="$STATE_ROOT/bench/queue.chainlog"
fi
mkdir -p "$(dirname "$BENCH_QUEUE")" || die "cannot create the bench directory"

SAMPLES="$(dirname "$BENCH_QUEUE")/samples.$$"
trap 'rm -f "$SAMPLES".* ' EXIT

# A real commit to submit. Any commit in this checkout will do — the queue
# records the sha, it does not fetch it here.
HEAD_SHA="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null)" ||
    die "not a git checkout: $ROOT"

# ── statistics, in shell, over a sorted file of integers ──────────────────
# No awk one-liner and no floating point: these are nanosecond counts, and
# integer arithmetic on them is exact. Percentile is the nearest-rank
# definition (index = ceil(p * n)), which is the one that needs no
# interpolation and therefore no rounding decision to argue about.
percentile_ns() {  # percentile_ns <sorted-file> <count> <percent>
    local file="$1" count="$2" pct="$3" idx
    idx=$(( (count * pct + 99) / 100 ))
    [ "$idx" -ge 1 ] || idx=1
    [ "$idx" -le "$count" ] || idx="$count"
    sed -n "${idx}p" "$file"
}

report() {  # report <name> <sorted-file> <count>
    local name="$1" file="$2" count="$3"
    local min med p95 max
    min="$(sed -n '1p' "$file")"
    med="$(percentile_ns "$file" "$count" 50)"
    p95="$(percentile_ns "$file" "$count" 95)"
    max="$(sed -n "${count}p" "$file")"
    # Nanoseconds in, milliseconds out, to one decimal, in integer maths.
    printf '%-8s n=%-5s min=%s.%sms  median=%s.%sms  p95=%s.%sms  max=%s.%sms\n' \
        "$name" "$count" \
        $((min / 1000000)) $(((min / 100000) % 10)) \
        $((med / 1000000)) $(((med / 100000) % 10)) \
        $((p95 / 1000000)) $(((p95 / 100000) % 10)) \
        $((max / 1000000)) $(((max / 100000) % 10))
}

printf 'land_bench: label=%s n=%s queue=%s\n' "$LABEL" "$N" "$BENCH_QUEUE"
printf 'land_bench: measured through the shell front door, so these are the\n'
printf '            wall times an agent actually experiences.\n\n'

# ── phase 1: submit ───────────────────────────────────────────────────────
: > "$SAMPLES.submit"
i=0
failed=0
while [ "$i" -lt "$N" ]; do
    i=$((i + 1))
    start="$(date +%s%N)"
    ZCL_LAND_QUEUE="$BENCH_QUEUE" \
    ZCL_LAND_TIMING="$(dirname "$BENCH_QUEUE")/timing.journal" \
    ZCL_LAND_SUBMITTER="bench" \
        "$ROOT/tools/dev/land.sh" submit --branch "bench/$LABEL-$i" \
            --head "$HEAD_SHA" --note "land_bench" >/dev/null 2>&1 ||
        failed=$((failed + 1))
    end="$(date +%s%N)"
    printf '%s\n' "$((end - start))" >> "$SAMPLES.submit"
done
sort -n "$SAMPLES.submit" -o "$SAMPLES.submit"
report submit "$SAMPLES.submit" "$N"
[ "$failed" -eq 0 ] || printf 'land_bench: %s submit(s) FAILED\n' "$failed"

# ── phase 2: "is it done yet" ─────────────────────────────────────────────
: > "$SAMPLES.status"
i=0
while [ "$i" -lt "$N" ]; do
    i=$((i + 1))
    start="$(date +%s%N)"
    ZCL_LAND_QUEUE="$BENCH_QUEUE" \
        "$ROOT/tools/dev/land.sh" status --branch "bench/$LABEL-$i" \
            >/dev/null 2>&1
    end="$(date +%s%N)"
    printf '%s\n' "$((end - start))" >> "$SAMPLES.status"
done
sort -n "$SAMPLES.status" -o "$SAMPLES.status"
report status "$SAMPLES.status" "$N"

printf '\nland_bench: the queue now holds %s bench submissions; it is a\n' "$N"
printf '            throwaway at %s and nothing lands from it.\n' "$BENCH_QUEUE"
exit 0
