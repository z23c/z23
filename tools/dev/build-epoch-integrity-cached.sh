#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Cached, concurrent driver for check-build-epoch-integrity's two
# compile-probe selftests (build-epoch-selftest.sh,
# make-depfile-scope-selftest.sh).
#
# Why: both selftests do real `cc` compiles / `make -n` dry runs and
# together dominate `make lint` wall time (measured 2026-07-19: 16,971 ms of
# a 16,996 ms total, everything else in the 8-way pool effectively free).
# Neither probe's verdict depends on anything but its own inputs: the two
# selftest scripts, the four build-epoch tool scripts
# (build-epoch-key.sh / publish-build-alias.sh / compile-epoch-object.sh /
# build-epoch-session.sh) that build-epoch-selftest.sh drives, the root
# Makefile (make-depfile-scope-selftest.sh `include`s it directly and
# build-epoch-selftest.sh's fixture flags mirror it), the active compiler's
# identity (fingerprinted the same way build-epoch-key.sh itself does --
# binary bytes + relevant environment, e.g. CPATH), and `make`'s version. On
# a routine dev loop none of that changes between lint runs, so a warm cache
# keyed on all of it reproduces the identical verdict at near-zero cost. Any
# drift in any of those inputs changes the key -> cache MISS -> both probes
# rerun for real.
#
# Fail-open, by construction: every step that could make the cache LIE is
# wrapped so a failure there falls through to running both probes for real
# instead of trusting the cache. A stale/corrupt/missing cache can only cost
# time, never mask a real regression. `rm -rf .cache/build-epoch-integrity`
# (or delete the one file inside it) trivially forces a full rerun.
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
CACHE_DIR="${ZCL_BUILD_EPOCH_CACHE_DIR:-$ROOT/.cache/build-epoch-integrity}"
CACHE_FILE="$CACHE_DIR/verdict.key"
CC_COMMAND="${CC:-cc}"

BUILD_EPOCH_SELFTEST="$SELF_DIR/build-epoch-selftest.sh"
DEPFILE_SCOPE_SELFTEST="$SELF_DIR/make-depfile-scope-selftest.sh"
KEY_TOOL="$SELF_DIR/build-epoch-key.sh"

# Every file whose bytes the two probes' behavior can depend on. Order is
# fixed so the concatenation (and therefore the hash) is deterministic.
KEY_INPUT_FILES=(
    "$BUILD_EPOCH_SELFTEST"
    "$KEY_TOOL"
    "$SELF_DIR/publish-build-alias.sh"
    "$SELF_DIR/compile-epoch-object.sh"
    "$SELF_DIR/build-epoch-session.sh"
    "$SELF_DIR/build-epoch-open-file-identity.sh"
    "$DEPFILE_SCOPE_SELFTEST"
    "$ROOT/Makefile"
)

# Run both probes concurrently -- they are independent (separate mktemp
# work dirs, no shared mutable state) -- and stream both logs through on
# completion so a failure still points straight at its FAIL line.
run_probes()
{
    local build_log depfile_log build_pid depfile_pid build_rc depfile_rc
    build_log="$(mktemp "${TMPDIR:-/tmp}/build-epoch-probe.XXXXXX")"
    depfile_log="$(mktemp "${TMPDIR:-/tmp}/depfile-scope-probe.XXXXXX")"
    "$BUILD_EPOCH_SELFTEST" > "$build_log" 2>&1 &
    build_pid=$!
    "$DEPFILE_SCOPE_SELFTEST" > "$depfile_log" 2>&1 &
    depfile_pid=$!
    wait "$build_pid"
    build_rc=$?
    wait "$depfile_pid"
    depfile_rc=$?
    cat -- "$build_log"
    cat -- "$depfile_log"
    rm -f -- "$build_log" "$depfile_log"
    [ "$build_rc" -eq 0 ] && [ "$depfile_rc" -eq 0 ]
}

write_cache()
{
    local key="$1" tmp
    mkdir -p -- "$CACHE_DIR" 2>/dev/null || return 0
    tmp="$(mktemp "$CACHE_DIR/.verdict.XXXXXX" 2>/dev/null)" || return 0
    printf '%s\n' "$key" > "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 0; }
    mv -f -- "$tmp" "$CACHE_FILE" 2>/dev/null || rm -f -- "$tmp"
    return 0
}

# ── Compute the cache key. Any failure here leaves key_ok=0, which skips
#    the cache read AND the cache write below -- fail open. ─────────────
key=""
key_ok=1
for f in "${KEY_INPUT_FILES[@]}"; do
    [ -f "$f" ] || { key_ok=0; break; }
done
content_hash=""
if [ "$key_ok" -eq 1 ]; then
    content_hash="$(cat -- "${KEY_INPUT_FILES[@]}" 2>/dev/null | sha256sum | awk '{print $1}')"
    [[ "$content_hash" =~ ^[0-9a-f]{64}$ ]] || key_ok=0
fi
compiler_id=""
if [ "$key_ok" -eq 1 ]; then
    compiler_id="$("$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND" 2>/dev/null)"
    [[ "$compiler_id" =~ ^[0-9a-f]{64}$ ]] || key_ok=0
fi
make_version=""
if [ "$key_ok" -eq 1 ]; then
    make_version="$(make --version 2>/dev/null | head -n1)"
    [ -n "$make_version" ] || key_ok=0
fi
[ "$key_ok" -eq 1 ] &&
    key="v1 cc=[$CC_COMMAND] content=$content_hash compiler=$compiler_id make=[$make_version]"

if [ "$key_ok" -eq 1 ] && [ -f "$CACHE_FILE" ]; then
    cached_key="$(cat -- "$CACHE_FILE" 2>/dev/null)"
    if [ -n "$cached_key" ] && [ "$cached_key" = "$key" ]; then
        printf 'build-epoch-selftest: PASS (cached; identical inputs -- rm -rf %s to force a rerun)\n' \
            "$CACHE_DIR"
        printf 'make-depfile-scope-selftest: PASS (cached; identical inputs -- rm -rf %s to force a rerun)\n' \
            "$CACHE_DIR"
        exit 0
    fi
fi

if [ "$key_ok" -eq 1 ]; then
    echo "check-build-epoch-integrity: cache MISS (first run or an input changed) -- running both probes" >&2
else
    echo "check-build-epoch-integrity: cache key unavailable -- running both probes (fail open)" >&2
fi

if run_probes; then
    [ "$key_ok" -eq 1 ] && write_cache "$key"
    exit 0
fi
exit 1
