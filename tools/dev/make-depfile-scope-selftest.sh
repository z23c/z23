#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove single-goal depfile narrowing retains header invalidation and that every
# ambiguous invocation falls back to all compile profiles.
#
# node-c23 is the SHIPPED CONSENSUS BINARY's profile. Its objects are compiled
# per-TU, so header invalidation for it rides `-include $(NODE_C23_OBJS:.o=.d)`
# exactly like every other profile — and losing that include is silent: the .d
# files are still WRITTEN by -MD, every build still succeeds, and the only
# symptom is a node binary that quietly does not contain a header edit. That is
# the one staleness in this repository that reaches consensus, so it is probed
# here rather than left to a human remembering to check it.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-depfile-scope.XXXXXX")"
ZERO=0000000000000000000000000000000000000000000000000000000000000000
SOURCE_RECORD="$ZERO 1 $ZERO"

cleanup()
{
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

fail()
{
    printf 'make-depfile-scope-selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

profiles=(build-only dev test-fast test-strict node-c23)
for profile in "${profiles[@]}"; do
    object="$WORK/$profile.o"
    header="$WORK/$profile.h"
    depfile="$WORK/$profile.d"
    : > "$object"
    : > "$header"
    printf '%s: %s\n' "$object" "$header" > "$depfile"
    touch -t 202001010000 -- "$object" "$depfile"
    touch -t 202101010000 -- "$header"
done
for ready in dev.complete test-fast.candidate test-fast.rsp \
        test-strict.candidate test-strict.rsp node-c23.rsp; do
    : > "$WORK/$ready"
    touch -t 202201010000 -- "$WORK/$ready"
done

# Include the real Makefile so the test exercises its selection logic rather
# than a copied model.  Every profile object is an explicit prerequisite of the
# probe goals, but only a loaded .d file makes that existing object stale.  A
# printed rebuild marker therefore proves a newer header was observed.
PROBE_MK="$WORK/probe.mk"
{
    printf 'include %s/Makefile\n' "$ROOT"
    for profile in "${profiles[@]}"; do
        printf '%s/%s.o:\n\t@echo ZCL_DEP_REBUILD=%s\n' \
            "$WORK" "$profile" "$profile"
    done
    printf 'ZCL_DEP_PROBE_OBJECTS := '
    for profile in "${profiles[@]}"; do
        printf '%s/%s.o ' "$WORK" "$profile"
    done
    printf '\n'
    printf 'fast-compile build-only t-fast t dev-failure-execution-id: $(ZCL_DEP_PROBE_OBJECTS)\n'
    printf 'zclassic23 z23 zclassic23-package-verify: $(ZCL_DEP_PROBE_OBJECTS)\n'
    printf 'zcl-depfile-unknown zcl-depfile-default: $(ZCL_DEP_PROBE_OBJECTS)\n'
    printf '\t@:\n'
    printf '.DEFAULT_GOAL := zcl-depfile-default\n'
} > "$PROBE_MK"

run_probe()
{
    local output="$1"
    shift
    (
        cd "$ROOT"
        make -f "$PROBE_MK" --no-print-directory -n \
            ZCL_STANDALONE_CLEAN=1 \
            BUILD_SOURCE_RECORD="$SOURCE_RECORD" \
            BUILD_DIR="$WORK/build" \
            BIN_DIR="$WORK/build/bin" \
            VIEW_GEN_HEADERS= VIEW_GEN_HEADERS_EARLY= \
            VENDOR_LIBS= \
            ALL_OBJS="$WORK/build-only.o" \
            DEV_OBJS="$WORK/dev.o" \
            DEV_OBJ_COMPLETE="$WORK/dev.complete" \
            TEST_PARALLEL_FAST_OBJS="$WORK/test-fast.o" \
            TEST_PARALLEL_FAST_CANDIDATE="$WORK/test-fast.candidate" \
            TEST_PARALLEL_FAST_LINK_RSP="$WORK/test-fast.rsp" \
            TEST_PARALLEL_REL_OBJS="$WORK/test-strict.o" \
            TEST_PARALLEL_REL_CANDIDATE="$WORK/test-strict.candidate" \
            TEST_PARALLEL_REL_LINK_RSP="$WORK/test-strict.rsp" \
            NODE_C23_OBJS="$WORK/node-c23.o" \
            NODE_C23_PACKAGE_VERIFY_OBJ="$WORK/node-c23.o" \
            NODE_C23_LINK_RSP="$WORK/node-c23.rsp" \
            "$@"
    ) > "$output" 2>&1 || {
        sed -n '1,120p' "$output" >&2
        fail "Make probe failed: ${*:-default goal}"
    }
}

assert_exact_profiles()
{
    local output="$1" expected="$2" profile present should
    for profile in "${profiles[@]}"; do
        present=0
        grep -Fq "ZCL_DEP_REBUILD=$profile" "$output" && present=1
        should=0
        case " $expected " in *" $profile "*) should=1 ;; esac
        [ "$present" -eq "$should" ] || {
            sed -n '1,160p' "$output" >&2
            fail "profile=$profile present=$present expected=$should ($expected)"
        }
    done
}

run_probe "$WORK/dev.out" fast-compile
assert_exact_profiles "$WORK/dev.out" dev
run_probe "$WORK/build.out" build-only
assert_exact_profiles "$WORK/build.out" build-only
# t / t-fast now validate ONLY= at Makefile PARSE time (see the ONLY_REQUIRED_GOALS
# block in the Makefile), so naming either as a probe goal without one is a
# parse error before any depfile logic is reached. ONLY= is a command-line
# VARIABLE, not a goal, so it does not enter MAKECMDGOALS and cannot change
# which depfile scope is selected — which is the only thing these two probes
# measure. Any registered group name works; boot_phase is small and stable.
run_probe "$WORK/fast.out" t-fast ONLY=boot_phase
assert_exact_profiles "$WORK/fast.out" test-fast
run_probe "$WORK/strict.out" t ONLY=boot_phase
assert_exact_profiles "$WORK/strict.out" test-strict
run_probe "$WORK/failure-id.out" dev-failure-execution-id
assert_exact_profiles "$WORK/failure-id.out" ""

# The shipped node binary, under both spellings of its goal. Narrowing to
# node-c23 alone is the point: a missing exact-goal branch would silently widen
# this to every profile, and a missing -include would silently empty it.
run_probe "$WORK/node.out" zclassic23
assert_exact_profiles "$WORK/node.out" node-c23
run_probe "$WORK/node-alias.out" z23
assert_exact_profiles "$WORK/node-alias.out" node-c23
run_probe "$WORK/verifier.out" zclassic23-package-verify
assert_exact_profiles "$WORK/verifier.out" node-c23

# Two goals, an unknown goal, and no explicit goal are all ambiguous.  They
# must import every depfile, so all four newer headers schedule rebuilds.
run_probe "$WORK/mixed.out" fast-compile build-only
assert_exact_profiles "$WORK/mixed.out" "build-only dev test-fast test-strict node-c23"
run_probe "$WORK/unknown.out" zcl-depfile-unknown
assert_exact_profiles "$WORK/unknown.out" "build-only dev test-fast test-strict node-c23"
run_probe "$WORK/default.out"
assert_exact_profiles "$WORK/default.out" "build-only dev test-fast test-strict node-c23"

printf '%s\n' \
    'make-depfile-scope-selftest: PASS header_rebuild=true single_goal_scoped=true node_c23_scoped=true mixed_unknown_default_all=true'
