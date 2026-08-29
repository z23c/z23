#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# first_build_timing.sh — `make first-build-timing`. Answers the one question a
# newcomer asks before cloning: how long does the first build take, and which
# stage is the long pole.
#
# It measures, it does not estimate. It clones this repository into a scratch
# directory, runs the real fresh-clone sequence in order, and times each stage
# with a wall clock:
#
#   clone   git clone            (local clone by default — a remote clone also
#                                 pays network time for the objects)
#   vendor  make vendor          (fetch + build the static third-party archives;
#                                 needs the network and a Rust toolchain)
#   setup   make setup           (arm hooks, write compile_commands.json)
#   build   make -j<cores>       (the binaries)
#   tests   make -j<cores> test-parallel   (the full suite)
#
# vendor runs before setup on purpose. `make setup` regenerates
# compile_commands.json, which crosses the Makefile's vendor barrier and drags
# the whole vendored-archive build in with it, so measuring setup first would
# bill the long pole to the wrong stage. Whichever of the two a newcomer types
# first is the one that pays; the doc says so.
#
# The compiler cache is disabled for the whole measurement. A host that has
# built this project before has a warm ccache, and a warm cache reports a
# build time no newcomer will ever see.
#
# The result lands in .cache/first-build-timing/last-run.json, which
# `make timings` reads. That is the whole point of writing an artifact: the
# published figure is refreshed by running a command, never by editing prose.
#
# The scratch clone is built with its OWN empty vendor/.cache and vendor/lib,
# so the vendored-dependency stage is a genuine cold cost and not a copy of an
# already-primed checkout.
#
# Cost: this runs a complete build and the complete test suite. It is not a
# quick command; that is the number it exists to report.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${ZCL_TIMINGS_CACHE:-$ROOT/.cache}"
OUT_DIR="$CACHE/first-build-timing"
OUT="$OUT_DIR/last-run.json"

CORES="$(nproc 2>/dev/null || echo 1)"
ORIGIN="${ZCL_FIRST_BUILD_ORIGIN:-$ROOT}"
CLONE_SOURCE=local
case "$ORIGIN" in *://*|*@*:*) CLONE_SOURCE=remote ;; esac
KEEP=0

say() { printf '%s\n' "$*" >&2; }
die() { printf 'first-build-timing: FATAL — %s\n' "$*" >&2; exit 2; }

json_escape() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# --- stage plan -------------------------------------------------------------
# One "name<TAB>command" line per stage, in the order a fresh clone runs them.
# The clone itself is stage 1 and is handled by the caller (there is no
# working tree to run a command in yet).
#
# ZCL_FIRST_BUILD_FAKE swaps in trivial commands so --self-test can exercise
# the recording, artifact and failure paths without a 20-minute build. It is a
# test hook only: the real run has no way to reach it by accident because
# nothing in the Makefile sets it.
stage_plan() {
    case "${ZCL_FIRST_BUILD_FAKE:-}" in
        ok)   printf 'vendor\ttrue\nsetup\ttrue\nbuild\ttrue\ntests\ttrue\n'; return ;;
        fail) printf 'vendor\tfalse\nsetup\ttrue\nbuild\ttrue\ntests\ttrue\n'; return ;;
    esac
    printf 'vendor\tmake vendor\n'
    printf 'setup\tmake setup\n'
    printf 'build\tmake -j%s\n' "$CORES"
    # -j on the test stage too: the ~1400-TU test tree compiles as ordinary
    # Make prerequisites, so a bare `make test-parallel` builds it one file at
    # a time. Measuring the serial form would publish a number produced by a
    # missing flag rather than by the work.
    printf 'tests\tmake -j%s test-parallel\n' "$CORES"
}

now_ms() { date +%s%3N; }

dir_bytes() { du -sb "$1" 2>/dev/null | awk '{print $1}'; }

# --- the measurement --------------------------------------------------------
measure() {
    local work clone rc_total=0
    work="${ZCL_FIRST_BUILD_WORKDIR:-}"
    if [ -n "$work" ]; then
        mkdir -p "$work" || die "cannot create workdir: $work"
    else
        work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-first-build.XXXXXX")" ||
            die "cannot create a scratch directory"
    fi
    clone="$work/zclassic23"
    rm -rf "$clone"

    say "══ first-build-timing: measuring a fresh clone on $(uname -n) ══"
    say "  scratch:  $clone"
    say "  origin:   $ORIGIN ($CLONE_SOURCE)"
    say "  cores:    $CORES"
    say "  ccache:   disabled for this measurement"

    # A newcomer's machine has never compiled this project. Neither, for the
    # duration of this measurement, does this one.
    export CCACHE_DISABLE=1 RUSTC_WRAPPER=

    # A shared machine inflates every stage below. Record the 1-minute load
    # average at both ends so a reader can tell a quiet host from a busy one
    # instead of guessing why two runs disagree.
    local load_start load_end
    load_start="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"

    local names=() cmds=() secs=() rcs=() disks=()

    # Stage 1: clone.
    local t0 t1
    t0="$(now_ms)"
    git clone --quiet "$ORIGIN" "$clone" >/dev/null 2>&1
    local clone_rc=$?
    t1="$(now_ms)"
    [ "$clone_rc" -eq 0 ] || die "git clone $ORIGIN failed"
    names+=(clone); cmds+=("git clone $ORIGIN"); secs+=($(( (t1 - t0 + 500) / 1000 )))
    rcs+=(0); disks+=("$(dir_bytes "$clone")")
    say "  clone     $(( (t1 - t0 + 500) / 1000 ))s"

    # A fresh clone has no vendor archives and no download cache. Assert that,
    # rather than assume it: measuring a "cold" vendor build against a warm
    # cache is exactly the lie this script exists to prevent.
    if [ -z "${ZCL_FIRST_BUILD_FAKE:-}" ]; then
        [ -e "$clone/vendor/.cache" ] &&
            die "scratch clone already has vendor/.cache — not a cold measurement"
        ls "$clone"/vendor/lib/*.a >/dev/null 2>&1 && {
            # libsecp256k1.a is committed and is expected; anything else is not.
            local extra
            extra="$(ls "$clone"/vendor/lib/*.a | grep -v 'libsecp256k1\.a$' | grep -c .)"
            [ "$extra" -eq 0 ] ||
                die "scratch clone already has $extra built vendor archive(s) — not a cold measurement"
        }
    fi

    # Stages 2..n: run in the clone.
    local name cmd rc
    while IFS=$'\t' read -r name cmd; do
        [ -n "$name" ] || continue
        say "  running   $cmd"
        t0="$(now_ms)"
        ( cd "$clone" && eval "$cmd" ) > "$work/$name.log" 2>&1
        rc=$?
        t1="$(now_ms)"
        names+=("$name"); cmds+=("$cmd"); secs+=($(( (t1 - t0 + 500) / 1000 )))
        rcs+=("$rc"); disks+=("$(dir_bytes "$clone")")
        say "  $name     $(( (t1 - t0 + 500) / 1000 ))s  rc=$rc  (log: $work/$name.log)"
        [ "$rc" -eq 0 ] || rc_total=1
    done <<<"$(stage_plan)"

    # The tests stage is only trustworthy if the runner said so in its own
    # words. A zero exit with no pass token is recorded as a failure.
    if [ -z "${ZCL_FIRST_BUILD_FAKE:-}" ] && [ -f "$work/tests.log" ]; then
        if ! grep -aq 'ALL TESTS PASSED' "$work/tests.log" ||
             grep -aq 'SOME TESTS FAILED' "$work/tests.log"; then
            say "  tests     did not print the pass token — recording as failed"
            local i=0
            for i in "${!names[@]}"; do
                [ "${names[$i]}" = tests ] && rcs[$i]=1
            done
            rc_total=1
        fi
    fi

    # --- write the artifact -------------------------------------------------
    load_end="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
    mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"
    local commit total=0 peak=0 i
    commit="$(git -C "$ROOT" log -1 --format='%H' 2>/dev/null || echo unknown)"
    for i in "${!names[@]}"; do
        total=$(( total + secs[i] ))
        [ "${disks[$i]:-0}" -gt "$peak" ] && peak="${disks[$i]}"
    done

    {
        printf '{"schema":"zcl.first_build_timing.v1"'
        printf ',"generated_at_utc":"%s"' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf ',"host":"%s","cores":%s' "$(json_escape "$(uname -n)")" "$CORES"
        printf ',"commit":"%s"' "$(json_escape "$commit")"
        printf ',"clone_source":"%s","compiler_cache":"disabled"' "$CLONE_SOURCE"
        printf ',"cc":"%s"' "$(json_escape "$(cc --version 2>/dev/null | head -1)")"
        printf ',"loadavg_start":"%s","loadavg_end":"%s"' \
            "$(json_escape "$load_start")" "$(json_escape "$load_end")"
        printf ',"total_seconds":%s,"peak_disk_bytes":%s' "$total" "$peak"
        printf ',"stages":['
        for i in "${!names[@]}"; do
            [ "$i" -gt 0 ] && printf ','
            printf '{"name":"%s","command":"%s","seconds":%s,"rc":%s,"disk_bytes":%s}' \
                "$(json_escape "${names[$i]}")" "$(json_escape "${cmds[$i]}")" \
                "${secs[$i]}" "${rcs[$i]}" "${disks[$i]:-0}"
        done
        printf ']}\n'
    } > "$OUT" || die "cannot write $OUT"

    say ""
    say "wrote ${OUT#"$ROOT"/}  (read it with: make timings)"
    if [ "$KEEP" -eq 1 ]; then
        say "kept scratch clone: $clone"
    elif [ -z "${ZCL_FIRST_BUILD_WORKDIR:-}" ]; then
        # The suite leaves read-only fixture trees under test-tmp/ (0444 files
        # in write-protected directories). A plain rm -rf fails on them and
        # would silently leave a ~1.5 GB clone behind.
        chmod -R u+w "$work" 2>/dev/null
        rm -rf "$work" || say "could not remove scratch dir: $work"
    fi
    return "$rc_total"
}

# --- self-test --------------------------------------------------------------
run_selftest() {
    local tmp out self
    # The cleanup trap fires after this function's locals are gone, so the
    # path it removes has to be a global.
    SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-fbt-selftest.XXXXXX")"
    trap 'rm -rf "${SELFTEST_TMP:-}"' EXIT HUP INT TERM
    tmp="$SELFTEST_TMP"
    self="${BASH_SOURCE[0]}"

    # (1) A successful run records every stage, in order, with a real command.
    out="$(ZCL_FIRST_BUILD_FAKE=ok ZCL_TIMINGS_CACHE="$tmp/ok" \
           ZCL_FIRST_BUILD_WORKDIR="$tmp/w1" bash "$self" 2>&1)"
    local rc=$?
    [ "$rc" -eq 0 ] ||
        { echo "first-build-timing selftest: FAIL — clean run exited $rc: $out" >&2; exit 1; }
    local art="$tmp/ok/first-build-timing/last-run.json"
    [ -f "$art" ] ||
        { echo "first-build-timing selftest: FAIL — no artifact written" >&2; exit 1; }
    local n
    n="$(grep -o '"name":"[a-z]*"' "$art" | wc -l)"
    [ "$n" -eq 5 ] ||
        { echo "first-build-timing selftest: FAIL — expected 5 stages, got $n" >&2; exit 1; }
    for stage in clone setup vendor build tests; do
        grep -q "\"name\":\"$stage\"" "$art" ||
            { echo "first-build-timing selftest: FAIL — stage $stage missing" >&2; exit 1; }
    done
    grep -q '"schema":"zcl.first_build_timing.v1"' "$art" ||
        { echo "first-build-timing selftest: FAIL — wrong schema" >&2; exit 1; }
    grep -q '"cores":[0-9]' "$art" ||
        { echo "first-build-timing selftest: FAIL — no core count recorded" >&2; exit 1; }

    # (2) A failing stage is recorded with its nonzero rc AND fails the command.
    #     A build that did not work must never publish a duration as if it did.
    if ZCL_FIRST_BUILD_FAKE=fail ZCL_TIMINGS_CACHE="$tmp/bad" \
       ZCL_FIRST_BUILD_WORKDIR="$tmp/w2" bash "$self" >/dev/null 2>&1; then
        echo "first-build-timing selftest: FAIL — a failing stage exited 0" >&2; exit 1
    fi
    grep -q '"name":"vendor","command":"false","seconds":[0-9]*,"rc":1' \
        "$tmp/bad/first-build-timing/last-run.json" ||
        { echo "first-build-timing selftest: FAIL — failing stage not recorded with rc=1" >&2
          exit 1; }

    # (3) The reader must be able to see the failure. `make timings` is the
    #     published surface, so prove it labels this artifact rather than
    #     quoting its numbers as a clean first build.
    out="$(ZCL_TIMINGS_CACHE="$tmp/bad" bash "$ROOT/tools/scripts/timings.sh" 2>&1)"
    grep -q 'FAILED' <<<"$out" ||
        { echo "first-build-timing selftest: FAIL — make timings did not label a failed run: $out" >&2
          exit 1; }

    echo "first-build-timing selftest: PASS"
}

case "${1:-}" in
    --self-test) run_selftest; exit 0 ;;
    --keep)      KEEP=1 ;;
    '')          ;;
    *)           die "unknown argument: $1 (usage: $0 [--keep|--self-test])" ;;
esac

measure
