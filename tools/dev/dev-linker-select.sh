#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Select a verified host-local dev linker, with portable fallback.
# usage: dev-linker-select.sh [--selftest]
#
# No persistent selection cache: this runs from $(shell) at Makefile parse
# time and re-probes every invocation (a few tiny `int main` links, well
# under a second). A cached `-fuse-ld=mold` value outlived the mold binary
# on this host and broke every dev/test link with
# `collect2: fatal error: cannot find 'ld'`; re-probing cannot go stale.
#
# It probes with the compiler that will link. The Makefile passes its own CC
# (the real compiler word, without the compile-cache wrapper); a process that
# only inherits an environment keeps CC from it. A Clang driver takes lld
# only: it rejects -fuse-ld=mold outright, and its LTO objects link with
# nothing but lld.

set -euo pipefail

# Prove the selection with compilers whose only behaviour is which -fuse-ld
# they accept. A copy of this exact file runs under the temporary root, so the
# probes write there and no host linker or compiler is consulted. Each row is
# label | CC | expected output; each fake compiler accepts the -fuse-ld
# values named after it, so the first Clang would also link through mold.
if [[ "${1:-}" == --selftest ]]; then
    work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-linker-select.XXXXXX")"
    trap 'rm -rf -- "$work"' EXIT
    mkdir -p "$work/tools/dev" "$work/bin"
    cp "$0" "$work/tools/dev/dev-linker-select.sh"
    chmod +x "$work/tools/dev/dev-linker-select.sh"
    for spec in clang:mold,lld clang-none:none gcc-both:mold,lld gcc-lld:lld gcc-gold:gold cc:lld; do
        pats="-fuse-ld=${spec#*:}"
        printf '%s\n' '#!/usr/bin/env bash' 'for argument in "$@"; do' \
            "    case \"\$argument\" in ${pats//,/|-fuse-ld=}) exit 0;; esac" 'done' 'exit 1' \
            > "$work/bin/${spec%%:*}"
    done
    chmod +x "$work/bin/"*
    while IFS='|' read -r label cc expected; do
        if [ -n "$cc" ]; then export CC="$cc"; else unset CC; fi
        actual="$(cd "$work" && PATH="$work/bin:$PATH" "$work/tools/dev/dev-linker-select.sh")"
        if [ "$actual" != "$expected" ]; then
            printf 'dev-linker-select: self-test FAIL %s: expected [%s], got [%s]\n' \
                "$label" "$expected" "$actual" >&2
            exit 1
        fi
    done <<CASES
Clang takes lld|$work/bin/clang|-fuse-ld=lld
a compile-cache wrapper is not the compiler|$work/bin/zcc $work/bin/clang|-fuse-ld=lld
Clang with no lld selects nothing|$work/bin/clang-none|
gcc takes mold first|$work/bin/gcc-both|-fuse-ld=mold
gcc falls back to lld|$work/bin/gcc-lld|-fuse-ld=lld
gcc falls back to threaded gold|$work/bin/gcc-gold|-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9
with no CC named the default is cc||-fuse-ld=lld
CASES
    printf 'dev-linker-select: self-test PASS\n'
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The last word is the compiler; a compile-cache wrapper may precede it.
CC="${CC:-}"
CC="${CC##* }"
CC="${CC:-cc}"

probe_fuse_ld()
{
    local ld="$1"
    local out="$ROOT/build/.ld-probe-$ld"
    mkdir -p "$ROOT/build" || return 1
    if printf 'int main(void){return 0;}\n' |
        "$CC" -fuse-ld="$ld" -x c - -o "$out" >/dev/null 2>&1; then
        rm -f "$out"
        return 0
    fi
    rm -f "$out"
    return 1
}

case "$(basename -- "${CC##* }")" in
    *clang*)
        if probe_fuse_ld lld; then
            printf '%s' '-fuse-ld=lld'
        fi
        exit 0
        ;;
esac

if probe_fuse_ld mold; then
    printf '%s' '-fuse-ld=mold'
elif probe_fuse_ld lld; then
    printf '%s' '-fuse-ld=lld'
elif probe_fuse_ld gold; then
    # gold defaults to --no-threads; mold and lld parallelize internally
    # with no flag needed, but gold's monolithic test_parallel_fast /
    # z23-dev links (hundreds of objects, one shot, every edit) pay for
    # single-threaded symbol resolution on every dev-loop link unless
    # asked. --thread-count matches the devbuild scheduler's per-lane CPU
    # share (28 logical CPUs / 3 z23 lanes), not the host's full core
    # count, so a link never bids for CPU another lane already holds.
    printf '%s' '-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9'
fi
