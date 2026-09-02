#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — the in-tree compile cache serves correct bytes (HARD).
#
# THE BUG THIS PREVENTS. tools/zcc.c wraps every compile in this repository.
# Its first version keyed its fast path on the stat triples of the files named
# on the command line, which does not include headers: editing a header left
# the .c file's (size, mtime, inode) untouched, so the cache served the OLD
# object and the build silently produced a binary that did not match the
# source. A compile cache that can do that is worse than no cache, because
# every downstream proof in this project is a statement about bytes.
#
# This gate builds a fixture five ways and requires the cache to be both fast
# and RIGHT: identical bytes when nothing changed, different bytes when a
# header changed, warnings replayed on a hit, and a real hit actually taken
# (a cache that misses every time would pass a correctness-only test while
# quietly costing every developer the speed this exists for).
#
# Everything happens in a mktemp dir with ZCC_DIR pointed inside it, so the
# gate never reads or writes the developer's real cache.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*)
        echo "check_zcc_cache: SKIP — POSIX compile-cache process backend is unavailable on native Windows"
        exit 0
        ;;
esac

ZCC="$("$ROOT/tools/dev/zcc_bootstrap.sh")"
if [ -z "$ZCC" ] || [ ! -x "$ZCC" ]; then
    echo "check_zcc_cache: FAIL — could not build tools/zcc.c" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-zcc-gate.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
trap 'exit 2' HUP INT TERM

export ZCC_DIR="$WORK/cache"
LOG="$WORK/zcc.log"
export ZCC_LOG="$LOG"

failures=0
fail()
{
    echo "check_zcc_cache: FAIL — $*" >&2
    failures=$((failures + 1))
}

cat > "$WORK/dep.h" <<'HDR'
#define ZCL_GATE_VALUE 42
HDR
cat > "$WORK/main.c" <<'SRC'
#include <stdio.h>
#include "dep.h"
/* deliberately unused: this gate asserts the warning is replayed on a hit */
static int never_called(void) { return 1; }
int main(void)
{
    printf("%d\n", ZCL_GATE_VALUE);
    return 0;
}
SRC

build()
{
    local label="$1"
    if ! "$ZCC" cc -std=c23 -O1 -Wall -I"$WORK" \
            "$WORK/main.c" -o "$WORK/prog" 2>"$WORK/stderr.$label"; then
        fail "$label: the compile itself failed"
        cat "$WORK/stderr.$label" >&2
        return 1
    fi
    sha256sum < "$WORK/prog" | awk '{print $1}'
}

last_disposition() { tail -1 "$LOG" | awk '{print $1}'; }

# 1. cold: a miss that compiles for real.
a="$(build cold)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "a cold build was not a MISS"
[ "$("$WORK/prog")" = 42 ] || fail "the cold build did not behave correctly"

# 2. nothing changed: the level-1 probe must serve identical bytes.
b="$(build warm)" || exit 1
[ "$(last_disposition)" = HIT ] || fail "an unchanged rebuild was not a HIT"
[ "$a" = "$b" ] || fail "a cache hit produced different bytes than the compile"

# 3. the warning must be replayed, or a hit silently hides diagnostics.
grep -q 'never_called' "$WORK/stderr.cold" ||
    fail "the fixture stopped producing the warning this gate depends on"
grep -q 'never_called' "$WORK/stderr.warm" ||
    fail "a cache hit did not replay the compiler's warning"

# 4. touch the source without changing a byte: level 1 misses, level 2 serves.
touch "$WORK/main.c"
c="$(build touched)" || exit 1
[ "$(last_disposition)" = HIT ] || fail "a touched-but-unchanged source was not a HIT"
[ "$a" = "$c" ] || fail "a content hit produced different bytes"

# 5. THE REGRESSION: edit a HEADER. The command line is byte-identical and the
#    .c file has not moved, so only a recorded include set can catch this.
cat > "$WORK/dep.h" <<'HDR'
#define ZCL_GATE_VALUE 100
HDR
d="$(build header)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "a changed header was served from cache"
[ "$a" != "$d" ] || fail "a changed header produced the same object bytes"
[ "$("$WORK/prog")" = 100 ] || fail "the build after a header edit used stale code"


# 6. THE SECOND REGRESSION: the node compiles every object into a FRESH
#    mktemp staging directory and publishes atomically, so `-o` and `-MF`
#    carry a different random path on every invocation, and `-MT` names the
#    final target. Two bugs lived in that shape at once — the -MT value was
#    read as a phantom input file, which failed the -E probe and silently
#    dropped every node object out of the cache, and the -MF staging path
#    went into the key, which gave 1733 objects a 0% hit rate while the cache
#    looked healthy. Same source, different staging paths, must HIT.
stage_build()
{
    local tag="$1" dir
    dir="$WORK/stage.$tag"
    mkdir -p "$dir"
    "$ZCC" cc -std=c23 -O1 -Wall -I"$WORK" \
        -MD -MP -MF "$dir/main.d" -MT "$WORK/final/main.o" \
        -c "$WORK/main.c" -o "$dir/main.o" 2>/dev/null || return 1
    sha256sum < "$dir/main.o" | awk '{print $1}'
}
mkdir -p "$WORK/final"
s1="$(stage_build one)" || fail "staged compile failed"
[ "$(last_disposition)" = MISS ] || fail "the first staged compile was not a MISS"
[ -s "$WORK/stage.one/main.d" ] || fail "the compiler wrote no depfile"
s2="$(stage_build two)" || fail "second staged compile failed"
[ "$(last_disposition)" = HIT ] ||
    fail "a staged rebuild missed: the random -o/-MF paths are in the key"
[ "$s1" = "$s2" ] || fail "a staged cache hit produced different object bytes"
[ -s "$WORK/stage.two/main.d" ] || fail "a cache hit did not restore the depfile"
grep -q 'main.o' "$WORK/stage.two/main.d" ||
    fail "the restored depfile does not name its target"

# 7. THE THIRD REGRESSION: a link that names its objects through an
#    @response-file, which is how this tree links 2 667 test objects without
#    overflowing ARG_MAX. The link command line is byte-identical between
#    runs and so is the response file — only the OBJECTS it lists change. A
#    cache that keys on argv alone therefore sees nothing move and serves the
#    previous binary: an edited source recompiled, relinked, and still ran
#    the old code, and the test suite reported results for a function that no
#    longer existed. The response file must be expanded and its inputs keyed.
cat > "$WORK/rsplib.c" <<'SRC'
int rsp_value(void) { return 1; }
SRC
cat > "$WORK/rspmain.c" <<'SRC'
#include <stdio.h>
int rsp_value(void);
int main(void) { printf("%d\n", rsp_value()); return 0; }
SRC
"$ZCC" cc -std=c23 -O1 -c "$WORK/rsplib.c" -o "$WORK/rsplib.o" 2>/dev/null ||
    fail "the response-file fixture library did not compile"
"$ZCC" cc -std=c23 -O1 -c "$WORK/rspmain.c" -o "$WORK/rspmain.o" 2>/dev/null ||
    fail "the response-file fixture main did not compile"
printf '%s %s\n' "$WORK/rsplib.o" "$WORK/rspmain.o" > "$WORK/link.rsp"

"$ZCC" cc -std=c23 -O1 "@$WORK/link.rsp" -o "$WORK/rspprog" 2>/dev/null ||
    fail "the response-file link failed"
[ "$(last_disposition)" = MISS ] || fail "the first response-file link was not a MISS"
[ "$("$WORK/rspprog")" = 1 ] || fail "the response-file link produced the wrong program"

cat > "$WORK/rsplib.c" <<'SRC'
int rsp_value(void) { return 2; }
SRC
"$ZCC" cc -std=c23 -O1 -c "$WORK/rsplib.c" -o "$WORK/rsplib.o" 2>/dev/null ||
    fail "the edited response-file fixture library did not compile"
"$ZCC" cc -std=c23 -O1 "@$WORK/link.rsp" -o "$WORK/rspprog" 2>/dev/null ||
    fail "the relink after an object edit failed"
[ "$(last_disposition)" = MISS ] ||
    fail "a link whose objects changed was served from cache"
[ "$("$WORK/rspprog")" = 2 ] ||
    fail "the relinked program still runs the object bytes it was built from before"

# 8. THE FOURTH REGRESSION: the epoch object publisher passes -MT with the
#    final object path, which contains the compile-epoch hash. A Makefile
#    comment re-keys every epoch even when flags are unchanged, so hashing
#    -MT verbatim made a new epoch a 100% miss of otherwise identical
#    objects. Different -MT, same source, must HIT; the restored depfile
#    must name the CURRENT target, not the one from the first compile.
epoch_build()
{
    local tag="$1" dir mt
    dir="$WORK/epoch.$tag"
    mt="$WORK/epochs/$tag/main.o"
    mkdir -p "$dir" "$(dirname "$mt")"
    "$ZCC" cc -std=c23 -O1 -Wall -DZCL_GATE_EPOCH_MT=1 -I"$WORK" \
        -MD -MP -MF "$dir/main.d" -MT "$mt" \
        -c "$WORK/main.c" -o "$dir/main.o" 2>/dev/null || return 1
    sha256sum < "$dir/main.o" | awk '{print $1}'
}
e1="$(epoch_build aaaa)" || fail "epoch-a compile failed"
[ "$(last_disposition)" = MISS ] || fail "the first epoch-shaped -MT compile was not a MISS"
e2="$(epoch_build bbbb)" || fail "epoch-b compile failed"
[ "$(last_disposition)" = HIT ] ||
    fail "a rebuild whose only change was the -MT epoch path missed the cache"
[ "$e1" = "$e2" ] || fail "an epoch-path cache hit produced different object bytes"
[ -s "$WORK/epoch.bbbb/main.d" ] || fail "the epoch-path hit did not restore a depfile"
grep -q "epochs/bbbb/main.o" "$WORK/epoch.bbbb/main.d" ||
    fail "the restored depfile does not name the current -MT target"
if grep -q "epochs/aaaa/main.o" "$WORK/epoch.bbbb/main.d"; then
    fail "the restored depfile still names the previous epoch's -MT target"
fi

# 9. Nothing may take the unkeyable path
: it means the -E probe failed and
#    the compile ran uncached. Bug 1 above sat there, silent, until this
#    counter existed.
unkey="$("$ZCC" --zcc-stats | awk '/unkeyable/ {print $2}')"
[ "${unkey:-0}" = 0 ] || fail "$unkey compile(s) could not be keyed at all"

if [ "$failures" -ne 0 ]; then
    echo "check_zcc_cache: $failures failure(s); the compile cache is NOT trustworthy" >&2
    echo "  clear it now: make cc-cache-clear" >&2
    exit 1
fi

echo "check_zcc_cache: OK — hits are byte-identical, header edits are misses"
