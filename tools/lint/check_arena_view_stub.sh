#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_arena_view_stub.sh — tools/arena_view.c must keep compiling against
# the hand-written raylib 6.0 stub (tools/arena_view_raylib_stub.h).
#
# WHY THIS EXISTS
# The raylib window is optional; the stub is how a host without raylib keeps
# the window TU compiling (ARENA_VIEW_RAYLIB_STUB), and it is 175 lines of
# hand-maintained API surface, not a generated binding. Until this gate,
# nothing automated compiled that path: the stub's only consumer was the
# manual `make arena-view-syntax`, which SKIPPED the stub compile on exactly
# the hosts that have raylib installed. A window-side edit adding one new
# raylib call, or a stub edit drifting from the TU, broke only raylib-less
# hosts, and no lane could see it. The window path's refusal logic
# (av_require_label / av_fonts_load) likewise had no automated compile lane
# at all — the hosted arena_frame path never reaches it.
#
# This gate compiles the TU against the stub UNCONDITIONALLY: raylib
# presence is irrelevant to the stub's contract. The linked window binary
# stays a separate, raylib-present-only build (make tools/arena-view).
#
# Usage:
#   tools/lint/check_arena_view_stub.sh             # the gate
#   tools/lint/check_arena_view_stub.sh --selftest  # prove it can go red
#
# Env:
#   CC  compiler (default: cc). The compile is a fresh syntax observation,
#       not a cached build. -fsyntax-only runs no optimizer pass, so the
#       -Wno-stringop-overflow the linked arena builds carry for a GCC
#       stringop false positive is not needed here (verified with GCC 14:
#       clean at -Wall -Wextra -Werror -pedantic).
#
# Exit: 0 the TU and the stub still compile together; 1 violation named in
#       the log; 2 misconfiguration (missing inputs, drifted extractor).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

GATE="check-arena-view-stub"
CC_BIN="${CC:-cc}"
TU="tools/arena_view.c"
STUB="tools/arena_view_raylib_stub.h"
WORK=""

cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT

# ARENA_VIEW_INCLUDES is read out of the Makefile — the same
# backslash-block extraction idiom check_lint_gate_wiring.sh and
# check_doc_accuracy.sh use — so the include path has one source of truth.
# An empty extraction is a REFUSAL, never a silent bare compile.
arena_view_includes() {
    awk '
        /^ARENA_VIEW_INCLUDES[[:space:]]*=[[:space:]]*/ { inblock = 1 }
        inblock {
            print
            if ($0 !~ /\\[[:space:]]*$/) exit
        }
    ' Makefile | sed 's/^[^=]*=//' | sed 's/\\[[:space:]]*$//' | tr '\n' ' '
}

# stub_compile <tu-path> [extra -I dirs first...]
# Extra include dirs come BEFORE the Makefile set so a fixture-planted stub
# header shadows the tracked one for the selftest.
stub_compile() {
    local tu="$1"; shift
    "$CC_BIN" -std=c23 -fsyntax-only -Wall -Wextra -Werror -pedantic \
        -D_POSIX_C_SOURCE=200809L -DARENA_VIEW_RAYLIB_STUB \
        "$@" $(arena_view_includes) "$tu"
}

run_gate() {
    local includes log
    includes="$(arena_view_includes)"
    if [ -z "${includes//[[:space:]]/}" ]; then
        echo "$GATE: FAIL — ARENA_VIEW_INCLUDES unreadable in Makefile." >&2
        echo "  The extractor drifted, not the sources; fix the extractor," >&2
        echo "  never widen or bypass it." >&2
        exit 2
    fi
    if [ ! -f "$TU" ] || [ ! -f "$STUB" ]; then
        echo "$GATE: FAIL — $TU or $STUB is missing from the tree." >&2
        exit 2
    fi

    log="$(mktemp "${TMPDIR:-/tmp}/arena-view-stub.XXXXXX")" || exit 2
    WORK="$log"
    if stub_compile "$TU" >"$log" 2>&1; then
        echo "$GATE: OK — arena_view.c compiles against the raylib 6.0 stub"
        return 0
    fi
    echo "$GATE: FAIL — arena_view.c no longer compiles against the raylib" >&2
    echo "  stub. Every raylib call in the TU needs a declaration in" >&2
    echo "  $STUB, with a signature that matches how the TU calls it." >&2
    echo "  On raylib hosts the linked build cannot catch this; raylib-less" >&2
    echo "  hosts are where this drift lands. Compiler log:" >&2
    sed 's/^/  /' "$log" >&2
    return 1
}

# A gate nobody has seen fail is a gate nobody should trust. Each case plants
# ONE defect in a throwaway fixture copy of the TU + stub and asserts the
# compile goes red AND names the planted symbol; the untouched fixture must
# stay green, so nothing here can be an unconditional failure. The fixture
# lives outside the repository (mktemp) — a planted file inside it would be
# scanned by other gates mid-run.
run_selftest() {
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/arena-view-stub-selftest.XXXXXX")" || exit 2
    echo "══ $GATE selftest ══"
    local rc=0

    # The TU includes "../vendor/typography/*.inc" relative to its own file,
    # so the fixture must reproduce that directory shape.
    mkdir -p "$WORK/t" "$WORK/vendor/typography"
    cp "$TU" "$WORK/t/arena_view.c"
    cp vendor/typography/inter_medium_ascii.inc \
       vendor/typography/inter_semibold_ascii.inc "$WORK/vendor/typography/"

    # A: positive control — the fixture copy compiles against the tracked
    # stub, so the plants below fail for the planted reason only.
    cp "$STUB" "$WORK/t/arena_view_raylib_stub.h"
    if stub_compile "$WORK/t/arena_view.c" -I"$WORK/t" >"$WORK/a.log" 2>&1; then
        echo "  selftest ok: fixture copy compiles against the tracked stub"
    else
        echo "SELFTEST FAIL: fixture copy does not compile — harness bug:" >&2
        sed 's/^/  /' "$WORK/a.log" >&2
        rc=1
    fi

    # B: a raylib call whose declaration was dropped from the stub — the
    # exact drift this gate exists for (LoadFontFromMemory spans 3 lines).
    awk '/LoadFontFromMemory/,/codepointCount\);/ { next } { print }' \
        "$STUB" > "$WORK/t/arena_view_raylib_stub.h"
    if stub_compile "$WORK/t/arena_view.c" -I"$WORK/t" >"$WORK/b.log" 2>&1; then
        echo "SELFTEST FAIL: stub missing LoadFontFromMemory still compiled." >&2
        rc=1
    elif grep -q LoadFontFromMemory "$WORK/b.log"; then
        echo "  selftest ok: a dropped stub declaration is caught by name"
    else
        echo "SELFTEST FAIL: compile failed, but not on LoadFontFromMemory:" >&2
        sed 's/^/  /' "$WORK/b.log" >&2
        rc=1
    fi

    # C: signature drift — the declaration survives with the wrong shape.
    awk '/^void InitWindow\(/ { print "void InitWindow(void);"; next } { print }' \
        "$STUB" > "$WORK/t/arena_view_raylib_stub.h"
    if stub_compile "$WORK/t/arena_view.c" -I"$WORK/t" >"$WORK/c.log" 2>&1; then
        echo "SELFTEST FAIL: stub's InitWindow(void) prototype was accepted." >&2
        rc=1
    elif grep -q InitWindow "$WORK/c.log"; then
        echo "  selftest ok: stub signature drift is caught by name"
    else
        echo "SELFTEST FAIL: compile failed, but not on InitWindow:" >&2
        sed 's/^/  /' "$WORK/c.log" >&2
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (3/3) ══"
    else
        echo "══ selftest: FAIL ══" >&2
    fi
    return "$rc"
}

case "${1:-}" in
    --selftest) run_selftest; exit $? ;;
    "")         run_gate;     exit $? ;;
    *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
