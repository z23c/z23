#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Linux compile-reuse A/B fixture; all caches and outputs are isolated.
set -euo pipefail
unset ZCC_DISABLE ZCC_AUDIT

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 BEFORE_ZCC AFTER_ZCC" >&2
    exit 2
fi
before="$(realpath "$1")"
after="$(realpath "$2")"
[ -x "$before" ] && [ -x "$after" ]
work="$(mktemp -d "${TMPDIR:-/tmp}/z23-zcc-reuse-bench.XXXXXX")"
trap 'exit 2' HUP INT TERM
printf 'results=%s\n' "$work"
{
    date --iso-8601=seconds
    date -u --iso-8601=seconds
    uname -srm
    awk '/Cpus_allowed_list/ {print}' /proc/self/status
    cc --version | head -1
    awk -F ': ' '/model name/ {print "cpu=" $2; exit}' /proc/cpuinfo
    sha256sum "$before" "$after"
} > "$work/environment.txt"
awk 'BEGIN {for (i=0;i<1000;i++)
    printf "unsigned fixture_%d(unsigned x) { return (x * %du) ^ (x >> 3); }\n", i, i+1
}' > "$work/fixture.c"
wc -c < "$work/fixture.c" > "$work/source-bytes.txt"
sha256sum "$work/fixture.c" > "$work/source-sha256.txt"
printf 'round,version,state,wall_ms,user_s,system_s,hits,misses,waits\n' > "$work/results.csv"

batch()
{
    local round="$1" version="$2" binary="$3" state="$4" dir="$5"
    local start end status=0 hits misses waits user system
    local -a children=()
    : > "$dir/$state.log"
    start="$(date +%s%N)"
    for index in 1 2 3 4; do
        {
            TIMEFORMAT='%U %S'
            time ZCC_DIR="$dir/cache" ZCC_STRICT=1 ZCC_LOG="$dir/$state.log" \
                "$binary" cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
                -c "$work/fixture.c" -o "$dir/out$index.o" \
                > "$dir/$state.$index.stdout" 2> "$dir/$state.$index.stderr"
        } 2> "$dir/$state.$index.time" &
        children+=("$!")
    done
    for child in "${children[@]}"; do wait "$child" || status=1; done
    end="$(date +%s%N)"
    [ "$status" -eq 0 ] || { echo "Compile failed: $dir" >&2; exit 1; }
    for index in 1 2 3 4; do
        cmp "$dir/out1.o" "$dir/out$index.o"
    done
    if [ -f "$work/oracle.o" ]; then
        cmp "$work/oracle.o" "$dir/out1.o"
    else
        cp "$dir/out1.o" "$work/oracle.o"
    fi
    read -r hits misses waits < <(awk '
        $1=="HIT" {h++} $1=="MISS" {m++} $1=="WAIT" {w++}
        END {print h+0,m+0,w+0}' "$dir/$state.log")
    read -r user system < <(awk '{u+=$1;s+=$2} END {printf "%.2f %.2f\n",u,s}' "$dir/$state."*.time)
    [ "$((hits + misses))" -eq 4 ]
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$round" "$version" "$state" \
        "$(((end-start)/1000000))" "$user" "$system" "$hits" "$misses" "$waits" >> "$work/results.csv"
}

for round in 1 2 3 4 5; do
    order=(before after)
    if [ "$((round % 2))" -eq 0 ]; then order=(after before); fi
    for version in "${order[@]}"; do
        binary="$before"
        if [ "$version" = after ]; then binary="$after"; fi
        dir="$work/$round.$version"
        mkdir "$dir"
        batch "$round" "$version" "$binary" cold "$dir"
        batch "$round" "$version" "$binary" warm "$dir"
    done
done
sha256sum "$work/oracle.o" > "$work/output-sha256.txt"
cat "$work/environment.txt" "$work/source-bytes.txt" "$work/results.csv"
