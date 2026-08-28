#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# doctor-build.sh — build-host accelerator health for the Z23 inner
# loop (`make doctor-build`). One command that answers: "which accelerators
# does this host have, and what does each missing one COST me per iteration?"
# Read-only and advisory: always exits 0 (missing tools are reported, never
# fatal — the tree builds without all of them, just slower).
#
# Each entry names the consumer (Makefile line / tool) and the concrete
# iteration-time consequence of the tool being absent, so an operator can
# judge whether installing it pays for itself.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

have() { command -v "$1" >/dev/null 2>&1; }

ok=0
missing=0

found() {
    # found <label> <path-or-detail> <what-it-accelerates>
    printf '  [ok]      %-12s %s — %s\n' "$1" "$2" "$3"
    ok=$((ok + 1))
}

absent() {
    # absent <label> <what-is-lost> <concrete consequence>
    printf '  [MISSING] %-12s %s\n' "$1" "$2"
    printf '            cost: %s\n' "$3"
    missing=$((missing + 1))
}

echo "doctor-build: accelerator health for the Z23 inner loop"
echo "  host: $(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?') online CPUs — width for \`make -j\` build-only / test-fast per-TU compiles"
echo ""

# ccache/sccache — per-TU compile cache wrapped around CC (ZCL_USE_CCACHE guard,
# ZCL_USE_CCACHE ?= 1). The whole dev loop (build-only, test-fast, dev-bin)
# recompiles translation units through it.
if have ccache; then
    found ccache "$(command -v ccache) ($(ccache --version 2>/dev/null | sed -n '1p'))" \
        "per-TU compile cache around CC (ZCL_USE_CCACHE) — repeat build-only/test-fast compiles hit the cache instead of rerunning the front-end"
elif have sccache; then
    found sccache "$(command -v sccache)" \
        "per-TU compile cache around CC (ZCL_USE_CCACHE) — repeat build-only/test-fast compiles hit the cache instead of rerunning the front-end"
else
    absent ccache/sccache "no per-TU compile cache (ZCL_USE_CCACHE=0 leaves CC unwrapped)" \
        "every build-only/test-fast/dev-bin epoch reruns the full C front-end for every recompiled TU (~0.5-2 s per TU x hundreds on a header edit) instead of ~50-200 ms cache hits"
fi

# mold/lld/gold — fast linker selected for the DEV (non-LTO) binary link
# (ZCL_DEV_LINKER).
if have mold; then
    found mold "$(command -v mold) ($(mold --version 2>/dev/null | sed -n '1p'))" \
        "fast link of the non-LTO dev binary (ZCL_DEV_LINKER=-fuse-ld=mold)"
elif have ld.lld; then
    found ld.lld "$(command -v ld.lld)" \
        "faster link of the non-LTO dev binary (ZCL_DEV_LINKER=-fuse-ld=lld)"
elif have ld.gold; then
    found ld.gold "$(command -v ld.gold)" \
        "faster link of the non-LTO dev binary (ZCL_DEV_LINKER=-fuse-ld=gold)"
else
    absent mold/lld/gold "dev-bin non-LTO link falls back to GNU ld (ZCL_DEV_LINKER finds none)" \
        "the hot dev-reload/dev-bin link over ~1000 objects misses the fastest installed linker on every edit-link cycle"
fi

# clang — libFuzzer + ASan/UBSan toolchain (FUZZ_CC ?= clang).
if have clang; then
    found clang "$(command -v clang) ($(clang --version 2>/dev/null | sed -n '1p'))" \
        "libFuzzer+ASan/UBSan fuzz targets (FUZZ_CC)"
else
    absent clang "fuzz/fuzz-ci targets cannot build (FUZZ_CC)" \
        "\`make ci\` must run with SKIP_FUZZ=1; the fuzz corpus and sanitizer coverage never execute on this host"
fi

# inotifywait — event-driven save detection for the dev watcher
# (tools/dev/watch-dev-lane.sh:556, ZCL_DEV_WATCH_BACKEND=auto).
if have inotifywait; then
    found inotifywait "$(command -v inotifywait)" \
        "event-driven save detection for \`make dev-watch\` (watch-dev-lane.sh:556)"
else
    absent inotifywait "dev watcher falls back to polling (ZCL_DEV_WATCH_BACKEND=auto -> poll)" \
        "save-to-check latency grows by up to ZCL_DEV_WATCH_POLL_MS (default 500 ms) on every edit, plus a steady polling wake instead of sleeping on inotify"
fi

# lcov (or gcovr) — coverage rendering (coverage target).
if have lcov; then
    found lcov "$(command -v lcov) ($(lcov --version 2>/dev/null | sed -n '1p'))" \
        "coverage report rendering for \`make coverage\` (coverage target)"
elif have gcovr; then
    found gcovr "$(command -v gcovr)" \
        "coverage report rendering for \`make coverage\` (lcov absent; gcovr fallback path)"
else
    absent lcov/gcovr "no coverage renderer for \`make coverage\` (coverage target)" \
        "the coverage stage in \`make ci\` cannot render reports — run with SKIP_COV=1 or lose coverage evidence"
fi

# clangd — optional C23 index consumer of the root compile_commands.json
# (regenerate with \`make agent-index\`; the ff ladder warns when it goes stale).
if have clangd; then
    found clangd "$(command -v clangd)" \
        "C23 language server over compile_commands.json (make agent-index; ff warns when stale)"
else
    absent clangd "no language-server indexing of the tree" \
        "no iteration-time cost — clangd is optional; lib/codeindex + \`make agent-index\` cover agent-side navigation. Install only if you want IDE go-to-def"
fi

echo ""
echo "doctor-build: $ok present, $missing missing (advisory only; the tree builds without all of these)"
exit 0
