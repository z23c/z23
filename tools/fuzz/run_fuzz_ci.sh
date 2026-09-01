#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# run_fuzz_ci.sh — run every libFuzzer harness for a fixed slot AND report
# how much fuzzing each one actually did.
#
# WHY THIS EXISTS. `make fuzz-ci` used to run nine harnesses for 60 s each and
# print nothing but "no crash". Measured on 2026-07-29, five of the nine
# managed between 11 and 145 executions in their whole 60-second slot. They
# passed. They passed honestly. They were also testing essentially nothing: a
# harness at 11 inputs/minute needs years to reach what a healthy one reaches
# in a minute, and it reports green the entire time. That is the same failure
# shape as a crash report nobody reads — coverage-looking output that is not
# coverage.
#
# So this runner does two things the old inline loop did not:
#
#   1. It stops paying for a log line nobody asked for. libFuzzer symbolizes
#      the "NEW_FUNC" lines it prints when a unit reaches a function for the
#      first time. Against these binaries — one 82 MB whole-program object per
#      harness, built -g with ~1174 translation units of DWARF — each of those
#      lines costs a spawn of llvm-symbolizer and hundreds of milliseconds
#      blocked in poll() waiting for it. strace on fuzz_script, 200 runs:
#      90.06 s in poll across 201 calls, plus 1,048,572 EBADF close() calls
#      from the sanitizer's spawn helper walking RLIMIT_NOFILE. The measured
#      cost of that decoration was 4 to 5 orders of magnitude of throughput:
#      fuzz_block went 25 -> 697,333 executions in the same 60 s slot with
#      -print_funcs=0 and nothing else changed. NEW_FUNC lines are cosmetic;
#      coverage is still collected, the corpus still grows identically, and a
#      CRASH still prints a fully symbolized file:line stack trace (verified
#      against a deliberate heap-buffer-overflow target with -print_funcs=0).
#      Set FUZZ_CI_PRINT_FUNCS=2 to get the old lines back for one run.
#
#   2. It prints the executions-per-second each harness achieved and fails the
#      run when one falls under FUZZ_CI_MIN_EXEC_PER_SEC. A green run that
#      names its own weak harnesses is worth more than a green run that does
#      not. The floor is a throughput regression detector, not a quality bar:
#      it is set far below every harness's measured rate so that only a real
#      collapse — a fixture rebuilt per iteration, a new fsync on the hot
#      path, another accidental symbolizer spawn — trips it.
#
# Usage: run_fuzz_ci.sh <slot-seconds> <wall-timeout-seconds> <min-exec-per-sec>
#                       <print-funcs> <leak-detection:0|1> <bin>...
set -u

SLOT="$1"; WALL="$2"; FLOOR="$3"; PRINT_FUNCS="$4"; LEAKS="$5"; shift 5
TARGETS=("$@")

if [ "$LEAKS" = "1" ]; then
    SUFFIX="_leaks"; LABEL=", leak detection ON"; ASAN_ENV=""
else
    SUFFIX=""; LABEL=""; ASAN_ENV="detect_leaks=0"
fi

names=(); rates=(); execs=()
status=0

for t in "${TARGETS[@]}"; do
    echo "=== $t (${SLOT}s${LABEL}) ==="
    base=$(basename "$t"); kind="${base#fuzz_}"
    seed_dir="tests/harness/fuzz_seeds/$kind"
    work_dir="/tmp/zcl_fuzz_${kind}${SUFFIX}"
    log="$work_dir.log"
    rm -rf "$work_dir"; mkdir -p "$work_dir"

    if [ -n "$ASAN_ENV" ]; then
        timeout "${WALL}s" env ASAN_OPTIONS="$ASAN_ENV" "$t" \
            -max_total_time="$SLOT" -timeout=1 -print_final_stats=1 \
            -print_funcs="$PRINT_FUNCS" \
            -artifact_prefix="$work_dir/" "$work_dir" "$seed_dir" 2>&1 | tee "$log"
    else
        timeout "${WALL}s" "$t" \
            -max_total_time="$SLOT" -timeout=1 -print_final_stats=1 \
            -print_funcs="$PRINT_FUNCS" \
            -artifact_prefix="$work_dir/" "$work_dir" "$seed_dir" 2>&1 | tee "$log"
    fi
    rc=${PIPESTATUS[0]}
    if [ "$rc" -ne 0 ]; then
        echo "fuzz-ci: FAIL: $base exited $rc — full output kept at $log,"
        echo "fuzz-ci:       any artifact written under $work_dir/"
        exit "$rc"
    fi

    n=$(sed -n 's/^stat::number_of_executed_units: *\([0-9][0-9]*\).*/\1/p' "$log" | tail -1)
    r=$(sed -n 's/^stat::average_exec_per_sec: *\([0-9][0-9]*\).*/\1/p' "$log" | tail -1)
    names+=("$base"); execs+=("${n:-0}"); rates+=("${r:-0}")
    rm -rf "$work_dir" "$log"
    # fuzz_http mkdirs a per-pid empty $HOME so it can never resolve to a real
    # node datadir (tools/fuzz/fuzz_http.c). It has no exit hook — an abort is
    # the case that matters and would skip one anyway — so reclaim the empty
    # ones here. -empty means a directory a harness is still using cannot lose
    # content, and the directory is only ever a dead end for $HOME lookups.
    find /tmp -maxdepth 1 -type d -name 'zcl_fuzz_http_home_*' -empty \
        -delete 2>/dev/null || true
done

echo
echo "── fuzz-ci throughput (executions in a ${SLOT}s slot; floor ${FLOOR}/s) ──"
for i in "${!names[@]}"; do
    verdict="ok"
    if [ "${rates[$i]}" -lt "$FLOOR" ]; then
        verdict="UNDER-COVERED"
        status=1
    fi
    printf '  %-22s %12s execs  %8s exec/s  %s\n' \
        "${names[$i]}" "${execs[$i]}" "${rates[$i]}" "$verdict"
done

if [ "$status" -ne 0 ]; then
    echo
    echo "fuzz-ci: FAIL: a harness ran under ${FLOOR} executions/second."
    echo "fuzz-ci:       It did not crash — it barely ran, which is worse,"
    echo "fuzz-ci:       because it reports green while testing almost nothing."
    echo "fuzz-ci:       Profile the harness (strace -c -w is usually enough)"
    echo "fuzz-ci:       and hoist whatever it repeats per iteration into"
    echo "fuzz-ci:       LLVMFuzzerInitialize. Do NOT lower this floor."
fi
exit "$status"
