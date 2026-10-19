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
# This gate exercises unchanged, edited, and concurrent builds. It requires
# identical bytes when nothing changed, different bytes when a
# header changed, warnings replayed on a hit, and a real hit actually taken
# (a cache that misses every time would pass a correctness-only test while
# quietly costing every developer the speed this exists for).
#
# Everything happens in a mktemp dir with ZCC_DIR pointed inside it, so the
# gate never reads or writes the developer's real cache.

set -euo pipefail

# The proof builds cold with ZCC_VERIFIED, but this fixture first tests the
# ordinary cache and sets proof mode explicitly for its refusal cases.
unset ZCC_VERIFIED

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

# Same inode, length, and restored timestamp still changes the real input.
cp -p "$WORK/dep.h" "$WORK/header-time"
printf '%s\n' '#define ZCL_GATE_VALUE 101' > "$WORK/dep.h"
touch -r "$WORK/header-time" "$WORK/dep.h"
same_meta="$(build same-meta)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "same-metadata header edit was served"
[ "$same_meta" != "$d" ] || fail "same-metadata header edit kept old bytes"
[ "$("$WORK/prog")" = 101 ] || fail "same-metadata edit kept old behavior"

mv "$WORK/dep.h" "$WORK/dep-one.h"
printf '%s\n' '#define ZCL_GATE_VALUE 102' > "$WORK/dep-two.h"
ln -s dep-one.h "$WORK/dep.h"
symlink_one="$(build symlink-one)" || exit 1
ln -sfn dep-two.h "$WORK/dep.h"
symlink_two="$(build symlink-two)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "retargeted header symlink was served"
[ "$symlink_one" != "$symlink_two" ] || fail "symlink retarget did not change output"
[ "$("$WORK/prog")" = 102 ] || fail "symlink retarget kept old behavior"
rm "$WORK/dep.h"
cp "$WORK/dep-one.h" "$WORK/dep.h"

if [ "$(uname -s)" = Linux ]; then
    linux_cc="$(command -v gcc-14 || command -v gcc)"
    linux_as="$("$linux_cc" -print-prog-name=as)"
    linux_as="$(command -v "$linux_as")"
    mkdir -p "$WORK/linux-tools"
    printf 'int zcc_selected_tool(void) { return 7; }\n' > "$WORK/linux-tool.c"
    linux_log="$WORK/linux-tool.log"
    linux_wrapper_write()
    {
        printf '#!/bin/sh\nexec "%s" --defsym ZCC_BACKEND_TEST=%s "$@"\n' \
            "$linux_as" "$1" > "$WORK/linux-tools/as"
        chmod 700 "$WORK/linux-tools/as"
    }
    linux_tool_compile()
    {
        ZCC_DIR="$WORK/linux-tool-cache" ZCC_LOG="$linux_log" \
            "$ZCC" "$linux_cc" -std=c23 -O1 -B"$WORK/linux-tools/" \
            -c "$WORK/linux-tool.c" -o "$WORK/linux-tool.o"
    }
    linux_wrapper_write 1
    "$linux_cc" -B"$WORK/linux-tools/" -E "$WORK/linux-tool.c" > "$WORK/linux-before.i"
    linux_tool_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = MISS ] ||
        fail 'Linux selected assembler cold compile was not a MISS'
    cp "$WORK/linux-tool.o" "$WORK/linux-first.o"
    linux_tool_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = HIT ] ||
        fail 'Linux selected assembler warm compile was not a HIT'
    cp -p "$WORK/linux-tools/as" "$WORK/linux-as-before"
    linux_wrapper_write 2
    touch -r "$WORK/linux-as-before" "$WORK/linux-tools/as"
    "$linux_cc" -B"$WORK/linux-tools/" -E "$WORK/linux-tool.c" > "$WORK/linux-after.i"
    cmp "$WORK/linux-before.i" "$WORK/linux-after.i" ||
        fail 'Linux assembler fixture unexpectedly changed preprocessing'
    linux_tool_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = MISS ] ||
        fail 'mutated Linux assembler with restored mtime was served from cache'
    cp "$WORK/linux-tool.o" "$WORK/linux-cached.o"
    ZCC_DISABLE=1 linux_tool_compile
    cmp "$WORK/linux-cached.o" "$WORK/linux-tool.o" ||
        fail 'Linux selected assembler cache differs from cold output'
    if cmp -s "$WORK/linux-first.o" "$WORK/linux-tool.o"; then
        fail 'Linux assembler fixture did not change object bytes'
    fi
    linux_tool_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = HIT ] ||
        fail 'stable Linux selected assembler did not return to HIT'

    # These code-generation flags change symbol names, while -E stays equal.
    # The driver itself and its version reply remain untouched.
    linux_frontend="$("$linux_cc" -print-prog-name=cc1)"
    [ -x "$linux_frontend" ] || fail 'Linux selected frontend is unavailable'
    linux_frontend_write()
    {
        printf '#!/bin/sh\nexec "%s" "$@" %s\n' "$linux_frontend" "$1" \
            > "$WORK/linux-tools/cc1"
        chmod 700 "$WORK/linux-tools/cc1"
    }
    linux_frontend_compile()
    {
        ZCC_DIR="$WORK/linux-frontend-cache" ZCC_LOG="$linux_log" \
            "$ZCC" "$linux_cc" -std=c23 -O1 -B"$WORK/linux-tools/" \
            -c "$WORK/linux-tool.c" -o "$WORK/linux-tool.o"
    }
    linux_frontend_write -fno-leading-underscore
    [ "$("$linux_cc" -B"$WORK/linux-tools/" -print-prog-name=cc1)" = \
        "$WORK/linux-tools/cc1" ] || fail 'Linux driver did not select fixture frontend'
    "$linux_cc" -B"$WORK/linux-tools/" -E "$WORK/linux-tool.c" > "$WORK/linux-before.i"
    linux_frontend_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = MISS ] ||
        fail 'Linux selected frontend cold compile was not a MISS'
    cp "$WORK/linux-tool.o" "$WORK/linux-first.o"
    linux_frontend_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = HIT ] ||
        fail 'Linux selected frontend warm compile was not a HIT'
    linux_frontend_write -fleading-underscore
    "$linux_cc" -B"$WORK/linux-tools/" -E "$WORK/linux-tool.c" > "$WORK/linux-after.i"
    cmp "$WORK/linux-before.i" "$WORK/linux-after.i" ||
        fail 'Linux frontend fixture unexpectedly changed preprocessing'
    linux_frontend_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = MISS ] ||
        fail 'changed Linux frontend bytes were served from cache'
    cp "$WORK/linux-tool.o" "$WORK/linux-cached.o"
    ZCC_DISABLE=1 linux_frontend_compile
    cmp "$WORK/linux-cached.o" "$WORK/linux-tool.o" ||
        fail 'Linux selected frontend cache differs from cold output'
    if cmp -s "$WORK/linux-first.o" "$WORK/linux-tool.o"; then
        fail 'Linux frontend fixture did not change object bytes'
    fi
    linux_frontend_compile
    [ "$(tail -1 "$linux_log" | awk '{print $1}')" = HIT ] ||
        fail 'stable Linux selected frontend did not return to HIT'
fi

if [ "$(uname -s)" = Darwin ]; then
    # /usr/bin/cc may be only a launcher. Keep the driver and version reply
    # fixed while changing the bytes of the selected executable it invokes.
    mkdir -p "$WORK/apple-backend-cache"
    cat > "$WORK/apple-backend-driver" <<'WRAPPER'
#!/bin/sh
for arg in "$@"; do
    case "$arg" in
        -print-prog-name=clang) printf '%s\n' "$ZCC_APPLE_BACKEND"; exit 0 ;;
    esac
done
exec "$ZCC_APPLE_BACKEND" "$@"
WRAPPER
    cat > "$WORK/apple-backend" <<'WRAPPER'
#!/bin/sh
exec /usr/bin/cc "$@"
WRAPPER
    chmod +x "$WORK/apple-backend-driver" "$WORK/apple-backend"
    printf 'int zcc_apple_backend(void) { return 23; }\n' > "$WORK/apple-backend.c"
    backend_log="$WORK/apple-backend.log"
    apple_backend_compile()
    {
        ZCC_APPLE_BACKEND="$WORK/apple-backend" \
            ZCC_DIR="$WORK/apple-backend-cache" ZCC_LOG="$backend_log" \
            "$ZCC" "$WORK/apple-backend-driver" -std=c23 \
            -c "$WORK/apple-backend.c" -o "$WORK/apple-backend.o" ||
            fail 'Apple selected backend compile failed'
    }
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = MISS ] ||
        fail 'Apple backend cold compile was not a MISS'
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = HIT ] ||
        fail 'Apple backend warm compile was not a HIT'
    printf '# backend body changed; version reply stays constant\n' >> "$WORK/apple-backend"
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = MISS ] ||
        fail 'changed Apple backend bytes were served from cache'
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = HIT ] ||
        fail 'unchanged Apple backend did not return to HIT'
    cp -p "$WORK/apple-backend" "$WORK/apple-backend-time"
    backend_size="$(wc -c < "$WORK/apple-backend")"
    sed 's/body changed/body altered/' "$WORK/apple-backend-time" \
        > "$WORK/apple-backend-new"
    cat "$WORK/apple-backend-new" > "$WORK/apple-backend"
    touch -r "$WORK/apple-backend-time" "$WORK/apple-backend"
    [ "$(wc -c < "$WORK/apple-backend")" = "$backend_size" ] ||
        fail 'Apple backend same-size fixture changed length'
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = MISS ] ||
        fail 'same-size backend edit with restored mtime was served from cache'
    apple_backend_compile
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = HIT ] ||
        fail 'same-size backend did not return to HIT'

    # The selected backend may change after key derivation but before the
    # real compiler exits. A successful compile under that race must not
    # publish an object under the earlier toolchain key.
    mkdir -p "$WORK/apple-backend-race-cache"
    cat > "$WORK/apple-backend-race" <<'WRAPPER'
#!/bin/sh
case " $* " in
    *' -E '*) exec /usr/bin/cc "$@" ;;
esac
printf 'compile\n' >> "$APPLE_RACE_COMPILES"
if [ ! -e "$APPLE_RACE_MARK" ]; then
    : > "$APPLE_RACE_MARK"
    printf '# changed during physical compile\n' >> "$0"
fi
exec /usr/bin/cc "$@"
WRAPPER
    chmod +x "$WORK/apple-backend-race"
    cp -p "$WORK/apple-backend-race" "$WORK/apple-backend-race-original"
    race_log="$WORK/apple-backend-race.log"
    race_compiles="$WORK/apple-backend-race.compiles"
    : > "$race_compiles"
    apple_backend_race_compile()
    {
        ZCC_APPLE_BACKEND="$WORK/apple-backend-race" \
            APPLE_RACE_MARK="$WORK/apple-backend-race.once" \
            APPLE_RACE_COMPILES="$race_compiles" \
            ZCC_DIR="$WORK/apple-backend-race-cache" ZCC_LOG="$race_log" \
            "$ZCC" "$WORK/apple-backend-driver" -std=c23 \
            -c "$WORK/apple-backend.c" -o "$WORK/apple-backend-race.o" ||
            fail 'Apple backend race compile failed'
    }
    apple_backend_race_compile
    grep -Fq 'compiled; inputs changed during compilation' "$race_log" ||
        fail 'mid-compile backend mutation was not detected'
    cp -p "$WORK/apple-backend-race" "$WORK/apple-backend-race-changed"
    cat "$WORK/apple-backend-race-original" > "$WORK/apple-backend-race"
    apple_backend_race_compile
    [ "$(tail -1 "$race_log" | awk '{print $1}')" = MISS ] ||
        fail 'the old backend key was published despite a mid-compile mutation'
    cat "$WORK/apple-backend-race-changed" > "$WORK/apple-backend-race"
    apple_backend_race_compile
    [ "$(tail -1 "$race_log" | awk '{print $1}')" = MISS ] ||
        fail 'mid-compile backend mutation seeded a stale cache hit'
    apple_backend_race_compile
    [ "$(tail -1 "$race_log" | awk '{print $1}')" = HIT ] ||
        fail 'stable backend after the race did not return to HIT'
    [ "$(wc -l < "$race_compiles")" = 3 ] ||
        fail 'Apple backend race did not execute exactly three physical compiles'

    # A default backend selector may resolve clang through PATH. Making an
    # earlier candidate executable changes that selection without changing
    # PATH's text or the selected tool's directory stamp.
    mkdir -p "$WORK/apple-path-first" "$WORK/apple-path-second" \
        "$WORK/apple-path-cache"
    printf '#!/bin/sh\nexec /usr/bin/cc "$@"\n' > "$WORK/apple-path-first/clang"
    cp "$WORK/apple-path-first/clang" "$WORK/apple-path-second/clang"
    chmod +x "$WORK/apple-path-second/clang"
    cat > "$WORK/apple-path-driver" <<'WRAPPER'
#!/bin/sh
case "$1" in
    -print-prog-name=clang)
        printf 'query\n' >> "$APPLE_PATH_QUERIES"
        command -v clang
        exit $? ;;
esac
selected="$(command -v clang)" || exit 1
exec "$selected" "$@"
WRAPPER
    chmod +x "$WORK/apple-path-driver"
    apple_path_log="$WORK/apple-path.log"
    apple_path_queries="$WORK/apple-path-queries"
    : > "$apple_path_queries"
    apple_path_compile()
    {
        PATH="$WORK/apple-path-first:$WORK/apple-path-second:$PATH" \
            COMPILER_PATH= APPLE_PATH_QUERIES="$apple_path_queries" \
            ZCC_DIR="$WORK/apple-path-cache" ZCC_LOG="$apple_path_log" \
            "$ZCC" "$WORK/apple-path-driver" -std=c23 \
            -c "$WORK/apple-backend.c" -o "$WORK/apple-backend.o" ||
            fail 'Apple PATH backend compile failed'
    }
    apple_path_compile
    [ "$(tail -1 "$apple_path_log" | awk '{print $1}')" = MISS ] ||
        fail 'Apple PATH backend cold compile was not a MISS'
    apple_path_compile
    [ "$(tail -1 "$apple_path_log" | awk '{print $1}')" = HIT ] ||
        fail 'Apple PATH backend warm compile was not a HIT'
    [ "$(wc -l < "$apple_path_queries")" = 1 ] ||
        fail 'Apple default backend memo launched a warm driver query'
    chmod +x "$WORK/apple-path-first/clang"
    apple_path_compile
    [ "$(tail -1 "$apple_path_log" | awk '{print $1}')" = MISS ] ||
        fail 'newly executable Apple PATH backend was served from cache'
    apple_path_compile
    [ "$(tail -1 "$apple_path_log" | awk '{print $1}')" = HIT ] ||
        fail 'unchanged Apple PATH backend did not return to HIT'
    [ "$(wc -l < "$apple_path_queries")" = 2 ] ||
        fail 'Apple default backend memo did not requery exactly after chmod'

    cat > "$WORK/apple-unknown-backend" <<'WRAPPER'
#!/bin/sh
case " $* " in
    *' -print-prog-name=clang '*) exit 0 ;;
esac
exec /usr/bin/cc "$@"
WRAPPER
    chmod +x "$WORK/apple-unknown-backend"
    ZCC_DIR="$WORK/apple-backend-cache" ZCC_LOG="$backend_log" \
        "$ZCC" "$WORK/apple-unknown-backend" -std=c23 \
        -c "$WORK/apple-backend.c" -o "$WORK/apple-backend.o" ||
        fail 'Apple missing-backend-fact compile failed'
    [ "$(tail -1 "$backend_log" | awk '{print $1}')" = UNKEY ] ||
        fail 'missing Apple backend fact did not fail cache admission'

    # -fno-integrated-as dispatches a separate executable on Apple Clang.
    # Editing its bytes at the same path must invalidate the level-1 key.
    apple_as="$(cc -print-prog-name=as)"
    [ -x "$apple_as" ] || fail 'Apple assembler could not be resolved'
    mkdir -p "$WORK/apple-as" "$WORK/apple-as-cache"
    printf '#!/bin/sh\n# first body\nexec "%s" "$@"\n' "$apple_as" > "$WORK/apple-as/as"
    chmod +x "$WORK/apple-as/as"
    printf 'int zcc_apple_as(void) { return 23; }\n' > "$WORK/apple-as.c"
    apple_log="$WORK/apple-as.log"
    apple_compile()
    {
        ZCC_DIR="$WORK/apple-as-cache" ZCC_LOG="$apple_log" \
            "$ZCC" cc -std=c23 -fno-integrated-as -B"$WORK/apple-as" \
            -c "$WORK/apple-as.c" -o "$WORK/apple-as.o" ||
            fail 'Apple external assembler compile failed'
    }
    cc -### -std=c23 -fno-integrated-as -B"$WORK/apple-as" \
        -c "$WORK/apple-as.c" -o "$WORK/apple-as.o" \
        > "$WORK/apple-as-driver" 2>&1 ||
        fail 'Apple assembler driver query failed'
    grep -Fq "$WORK/apple-as/as" "$WORK/apple-as-driver" ||
        fail 'Apple driver did not select the fixture assembler'
    apple_compile
    [ "$(tail -1 "$apple_log" | awk '{print $1}')" = MISS ] ||
        fail 'Apple assembler cold compile was not a MISS'
    apple_compile
    [ "$(tail -1 "$apple_log" | awk '{print $1}')" = HIT ] ||
        fail 'Apple assembler warm compile was not a HIT'
    printf '# changed body; version output is unchanged\n' >> "$WORK/apple-as/as"
    apple_compile
    [ "$(tail -1 "$apple_log" | awk '{print $1}')" = MISS ] ||
        fail 'changed Apple assembler bytes were served from cache'

    mkdir -p "$WORK/apple-as-race" "$WORK/apple-as-race-cache"
    cat > "$WORK/apple-as-race/as" <<'WRAPPER'
#!/bin/sh
printf 'assemble\n' >> "$APPLE_AS_RACE_CALLS"
if [ ! -e "$APPLE_AS_RACE_MARK" ]; then
    : > "$APPLE_AS_RACE_MARK"
    printf '# changed during physical assembly\n' >> "$0"
fi
exec "$APPLE_AS_REAL" "$@"
WRAPPER
    chmod +x "$WORK/apple-as-race/as"
    cp -p "$WORK/apple-as-race/as" "$WORK/apple-as-race-original"
    as_race_log="$WORK/apple-as-race.log"
    as_race_calls="$WORK/apple-as-race.calls"
    : > "$as_race_calls"
    apple_as_race_compile()
    {
        APPLE_AS_REAL="$apple_as" \
            APPLE_AS_RACE_MARK="$WORK/apple-as-race.once" \
            APPLE_AS_RACE_CALLS="$as_race_calls" \
            ZCC_DIR="$WORK/apple-as-race-cache" ZCC_LOG="$as_race_log" \
            "$ZCC" cc -std=c23 -fno-integrated-as -B"$WORK/apple-as-race" \
            -c "$WORK/apple-as.c" -o "$WORK/apple-as-race.o" ||
            fail 'Apple assembler race compile failed'
    }
    apple_as_race_compile
    grep -Fq 'compiled; inputs changed during compilation' "$as_race_log" ||
        fail 'mid-compile assembler mutation was not detected'
    cp -p "$WORK/apple-as-race/as" "$WORK/apple-as-race-changed"
    cat "$WORK/apple-as-race-original" > "$WORK/apple-as-race/as"
    apple_as_race_compile
    [ "$(tail -1 "$as_race_log" | awk '{print $1}')" = MISS ] ||
        fail 'the old assembler key was published despite mutation'
    cat "$WORK/apple-as-race-changed" > "$WORK/apple-as-race/as"
    apple_as_race_compile
    [ "$(tail -1 "$as_race_log" | awk '{print $1}')" = MISS ] ||
        fail 'mid-compile assembler mutation seeded a stale cache hit'
    apple_as_race_compile
    [ "$(tail -1 "$as_race_log" | awk '{print $1}')" = HIT ] ||
        fail 'stable assembler after the race did not return to HIT'
    [ "$(wc -l < "$as_race_calls")" = 3 ] ||
        fail 'Apple assembler race did not execute exactly three assemblies'

    # -B is a compiler prefix selector, so zcc queries the driver every time.
    # Making an earlier candidate executable must still invalidate the key.
    mkdir -p "$WORK/apple-first" "$WORK/apple-second" \
        "$WORK/apple-selection-cache"
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$apple_as" \
        > "$WORK/apple-first/as"
    cp "$WORK/apple-first/as" "$WORK/apple-second/as"
    chmod +x "$WORK/apple-second/as"
    [ "$(cc -B"$WORK/apple-first" -B"$WORK/apple-second" \
            -print-prog-name=as)" = "$WORK/apple-second/as" ] ||
        fail 'Apple selector fixture did not initially choose the later tool'
    apple_selection_log="$WORK/apple-selection.log"
    apple_selection_compile()
    {
        ZCC_DIR="$WORK/apple-selection-cache" ZCC_LOG="$apple_selection_log" \
            "$ZCC" cc -std=c23 -fno-integrated-as \
            -B"$WORK/apple-first" -B"$WORK/apple-second" \
            -c "$WORK/apple-as.c" -o "$WORK/apple-as.o" ||
            fail 'Apple selection-change compile failed'
    }
    apple_selection_compile
    [ "$(tail -1 "$apple_selection_log" | awk '{print $1}')" = MISS ] ||
        fail 'Apple later-assembler cold compile was not a MISS'
    apple_selection_compile
    [ "$(tail -1 "$apple_selection_log" | awk '{print $1}')" = HIT ] ||
        fail 'Apple later-assembler warm compile was not a HIT'
    chmod +x "$WORK/apple-first/as"
    [ "$(cc -B"$WORK/apple-first" -B"$WORK/apple-second" \
            -print-prog-name=as)" = "$WORK/apple-first/as" ] ||
        fail 'Apple selector fixture did not switch to the earlier tool'
    apple_selection_compile
    [ "$(tail -1 "$apple_selection_log" | awk '{print $1}')" = MISS ] ||
        fail 'newly executable Apple assembler was served from cache'
    apple_selection_compile
    [ "$(tail -1 "$apple_selection_log" | awk '{print $1}')" = HIT ] ||
        fail 'unchanged Apple assembler selection did not return to HIT'

    cat > "$WORK/apple-unknown-compiler" <<'WRAPPER'
#!/bin/sh
case " $* " in
    *' -print-prog-name=as '*) exit 0 ;;
esac
exec cc "$@"
WRAPPER
    chmod +x "$WORK/apple-unknown-compiler"
    ZCC_DIR="$WORK/apple-as-cache" ZCC_LOG="$apple_log" \
        "$ZCC" "$WORK/apple-unknown-compiler" -std=c23 \
        -fno-integrated-as -B"$WORK/apple-as" \
        -c "$WORK/apple-as.c" -o "$WORK/apple-as.o" ||
        fail 'Apple missing-fact compile failed'
    [ "$(tail -1 "$apple_log" | awk '{print $1}')" = UNKEY ] ||
        fail 'missing Apple assembler fact did not fail cache admission'
fi

# Make control values change with an unrelated edit. The compiler child must
# never see them if the cache key omits them; a real compiler selector remains
# visible and changes the key. This fixture refuses if the child sees the
# source record, so a hash-only exclusion cannot pass.
saved_cache="$ZCC_DIR"
export ZCC_DIR="$WORK/environment-cache"
cat > "$WORK/compiler-environment" <<'WRAPPER'
#!/bin/sh
[ -z "${BUILD_SOURCE_RECORD+x}" ] || exit 71
exec cc "-DZCC_ENV_VALUE=${ZCC_REAL_FLAG:-1}" "$@"
WRAPPER
chmod +x "$WORK/compiler-environment"
printf '%s\n' 'int environment(void) { return ZCC_ENV_VALUE; }' > "$WORK/environment.c"
BUILD_SOURCE_RECORD=first ZCC_REAL_FLAG=1 \
    "$ZCC" "$WORK/compiler-environment" -c "$WORK/environment.c" \
    -o "$WORK/environment.o" || fail "filtered environment cold compile failed"
[ "$(last_disposition)" = MISS ] || fail "environment fixture did not start cold"
env_one="$(sha256sum < "$WORK/environment.o")"
BUILD_SOURCE_RECORD=second ZCC_REAL_FLAG=1 \
    "$ZCC" "$WORK/compiler-environment" -c "$WORK/environment.c" \
    -o "$WORK/environment.o" || fail "filtered environment warm compile failed"
[ "$(last_disposition)" = HIT ] || fail "Make source record changed the cache key"
BUILD_SOURCE_RECORD=third ZCC_REAL_FLAG=2 \
    "$ZCC" "$WORK/compiler-environment" -c "$WORK/environment.c" \
    -o "$WORK/environment.o" || fail "real environment changed compile failed"
[ "$(last_disposition)" = MISS ] || fail "compiler-visible environment change was served"
env_two="$(sha256sum < "$WORK/environment.o")"
[ "$env_one" != "$env_two" ] || fail "compiler-visible environment changed no bytes"
export ZCC_DIR="$saved_cache"

# A compiler script edited in place is a toolchain change even if its stat
# triple is restored. Both the preprocessor and code generator use it.
cat > "$WORK/compiler-version" <<'WRAPPER'
#!/usr/bin/env bash
exec cc -DZCC_COMPILER_VERSION=1 "$@"
WRAPPER
chmod +x "$WORK/compiler-version"
printf '%s\n' 'int version(void) { return ZCC_COMPILER_VERSION; }' > "$WORK/version.c"
"$ZCC" "$WORK/compiler-version" -c "$WORK/version.c" -o "$WORK/version.o" ||
    fail "compiler-change cold fixture failed"
[ "$(last_disposition)" = MISS ] || fail "compiler-change fixture did not start cold"
cp -p "$WORK/compiler-version" "$WORK/compiler-time"
sed 's/VERSION=1/VERSION=2/' "$WORK/compiler-version" > "$WORK/compiler-new"
cat "$WORK/compiler-new" > "$WORK/compiler-version"
touch -r "$WORK/compiler-time" "$WORK/compiler-version"
"$ZCC" "$WORK/compiler-version" -c "$WORK/version.c" -o "$WORK/version.o" ||
    fail "compiler-change fresh fixture failed"
[ "$(last_disposition)" = MISS ] || fail "same-metadata compiler edit was served"

# Source compiles cannot publish a probe manifest: an absent include-search
# candidate could appear without changing any previously opened file.
# A changed header still has to compile the new behavior.
saved_cache="$ZCC_DIR"
export ZCC_DIR="$WORK/truncated-cache"
poison_cold="$(build poison-cold)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "poison fixture did not start cold"
[ ! -d "$ZCC_DIR/man" ] ||
    fail "source compile published a probe manifest"
printf '%s\n' '#define ZCL_GATE_VALUE 777' > "$WORK/dep.h"
poison_fresh="$(build poison-fresh)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "changed header served an old binary"
[ "$poison_cold" != "$poison_fresh" ] || fail "poison fixture missed its header edit"
[ "$("$WORK/prog")" = 777 ] || fail "header edit did not reach execution"

# The header vanishes after the real compiler exits but before zcc publishes
# its probe manifest. A partial manifest must be refused. Restoring a changed
# header then has to compile the new behavior, not reuse the old artifact.
export ZCC_DIR="$WORK/racing-cache"
export ZCC_RACE_CC="$(command -v cc)" ZCC_RACE_HEADER="$WORK/dep.h"
cat > "$WORK/racing-cc" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
has_output=0
for arg in "$@"; do
    [ "$arg" = -E ] && exec "$ZCC_RACE_CC" "$@"
    [ "$arg" = -o ] && has_output=1
done
"$ZCC_RACE_CC" "$@"
if [ "$has_output" = 1 ] && [ "${ZCC_RACE_REMOVE:-0}" = 1 ]; then
    mv "$ZCC_RACE_HEADER" "$ZCC_RACE_HEADER.hidden"
fi
WRAPPER
chmod +x "$WORK/racing-cc"
ZCC_RACE_REMOVE=1 "$ZCC" "$WORK/racing-cc" -std=c23 -O1 -I"$WORK" \
    "$WORK/main.c" -o "$WORK/raceprog" 2>"$WORK/stderr.race-cold" ||
    fail "racing fixture did not compile"
[ "$(last_disposition)" = MISS ] || fail "racing fixture did not start cold"
[ ! -e "$WORK/dep.h" ] || fail "racing compiler did not remove the header"
printf '%s\n' '#define ZCL_GATE_VALUE 888' > "$WORK/dep.h"
"$ZCC" "$WORK/racing-cc" -std=c23 -O1 -I"$WORK" \
    "$WORK/main.c" -o "$WORK/raceprog" 2>"$WORK/stderr.race-fresh" ||
    fail "racing fixture did not rebuild"
[ "$(last_disposition)" = MISS ] || fail "partial manifest served an old binary"
[ "$("$WORK/raceprog")" = 888 ] || fail "partial manifest hid the edited result"
export ZCC_DIR="$saved_cache"
printf '%s\n' '#define ZCL_GATE_VALUE 100' > "$WORK/dep.h"
# A proof is hostile to this account's cache. Give the cache an unchanged
# size/inode/mtime header with changed behavior: its fast manifest may still
# name the old object. Verified mode must launch the compiler and never serve
# that object, even on its second invocation.
cp -p "$WORK/dep.h" "$WORK/dep.saved"
printf '#define ZCL_GATE_VALUE 200\n' > "$WORK/dep.h"
touch -r "$WORK/dep.saved" "$WORK/dep.h"
v1="$(ZCC_VERIFIED=1 build verified_first)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "verified compile used the same-account cache"
[ "$("$WORK/prog")" = 200 ] || fail "verified compile executed stale cached behavior"
v2="$(ZCC_VERIFIED=1 build verified_second)" || exit 1
[ "$(last_disposition)" = MISS ] || fail "verified rebuild reused a same-account object"
[ "$v1" = "$v2" ] || fail "verified rebuild changed identical output bytes"

# An absent optional header is an input too. A manifest of files the first
# preprocess opened cannot name a file that did not exist at the time; adding
# it must invalidate the probe shortcut and change executable behavior.
cat > "$WORK/optional.c" <<'SRC'
#if __has_include("optional.h")
#include "optional.h"
#else
#define OPTIONAL_VALUE 1
#endif
#include <stdio.h>
int main(void) { printf("%d\n", OPTIONAL_VALUE); return 0; }
SRC
"$ZCC" cc -std=c23 -O1 -I"$WORK" "$WORK/optional.c" \
    -o "$WORK/optional" 2>"$WORK/optional.first.err" ||
    fail "optional-header baseline compile failed"
[ "$("$WORK/optional")" = 1 ] || fail "optional-header baseline behavior was wrong"
cat > "$WORK/optional.h" <<'HDR'
#define OPTIONAL_VALUE 2
HDR
"$ZCC" cc -std=c23 -O1 -I"$WORK" "$WORK/optional.c" \
    -o "$WORK/optional" 2>"$WORK/optional.second.err" ||
    fail "optional-header changed compile failed"
[ "$(last_disposition)" = MISS ] ||
    fail "new __has_include header was served from a stale probe manifest"
[ "$("$WORK/optional")" = 2 ] ||
    fail "new __has_include header did not change executed behavior"

# An ordinary include can also switch resolution when a file appears in an
# earlier search directory. This needs no __has_include token in source.
mkdir -p "$WORK/search-first" "$WORK/search-second"
cat > "$WORK/search-second/choice.h" <<'HDR'
#define CHOICE_VALUE 1
HDR
cat > "$WORK/search.c" <<'SRC'
#include <choice.h>
#include <stdio.h>
int main(void) { printf("%d\n", CHOICE_VALUE); return 0; }
SRC
"$ZCC" cc -std=c23 -O1 -I"$WORK/search-first" \
    -I"$WORK/search-second" "$WORK/search.c" -o "$WORK/search" \
    2>"$WORK/search.first.err" || fail "include-search baseline compile failed"
[ "$("$WORK/search")" = 1 ] || fail "include-search baseline behavior was wrong"
cat > "$WORK/search-first/choice.h" <<'HDR'
#define CHOICE_VALUE 2
HDR
"$ZCC" cc -std=c23 -O1 -I"$WORK/search-first" \
    -I"$WORK/search-second" "$WORK/search.c" -o "$WORK/search" \
    2>"$WORK/search.second.err" || fail "include-search changed compile failed"
[ "$(last_disposition)" = MISS ] ||
    fail "new earlier header was served from a stale probe manifest"
[ "$("$WORK/search")" = 2 ] ||
    fail "new earlier header did not change executed behavior"

# A named library without explicit search directories cannot enter this
# cache. Reject that shape before compiler queries or preprocessing, while
# preserving the original compiler's output and exit status.
cat > "$WORK/named.c" <<'SRC'
#include <math.h>
#include <stdio.h>
int main(void)
{
    volatile double value = 81.0;
    printf("%.0f\n", sqrt(value));
    return 7;
}
SRC
"$ZCC" cc -std=c23 -O1 "$WORK/named.c" -lm -o "$WORK/named" \
    2>"$WORK/named.err" || fail "named-library bypass compile failed"
[ "$(last_disposition)" = BYPASS ] || fail "named library without -L was not bypassed"
named_status=0
"$WORK/named" >"$WORK/named.out" || named_status=$?
[ "$named_status" = 7 ] || fail "named-library program exit status changed"
[ "$(cat "$WORK/named.out")" = 9 ] || fail "named-library program output changed"
cat > "$WORK/named-error.c" <<'SRC'
#error ZCC_NAMED_LIBRARY_DIAGNOSTIC
SRC
named_direct_status=0
cc -std=c23 "$WORK/named-error.c" -lm -o "$WORK/named-error" \
    >"$WORK/named-direct.out" 2>"$WORK/named-direct.err" || named_direct_status=$?
named_cached_status=0
"$ZCC" cc -std=c23 "$WORK/named-error.c" -lm -o "$WORK/named-error" \
    >"$WORK/named-cached.out" 2>"$WORK/named-cached.err" || named_cached_status=$?
[ "$named_direct_status" != 0 ] || fail "named-library error fixture unexpectedly compiled"
[ "$named_cached_status" = "$named_direct_status" ] || fail "named-library compiler status changed"
cmp -s "$WORK/named-direct.out" "$WORK/named-cached.out" || fail "named-library compiler stdout changed"
cmp -s "$WORK/named-direct.err" "$WORK/named-cached.err" || fail "named-library compiler diagnostics changed"
[ "$(last_disposition)" = BYPASS ] || fail "named-library error was not bypassed"

# A -L appearing after -l, separated or joined, still permits archive reuse.
cat > "$WORK/named-lib.c" <<'SRC'
int named_value(void) { return 23; }
SRC
cat > "$WORK/named-main.c" <<'SRC'
#include <stdio.h>
int named_value(void);
int main(void) { printf("%d\n", named_value()); return 0; }
SRC
cc -std=c23 -c "$WORK/named-lib.c" -o "$WORK/named-lib.o" || fail "named archive fixture compile failed"
ar rcs "$WORK/libzccnamed.a" "$WORK/named-lib.o" || fail "named archive fixture creation failed"
for named_style in separated joined; do
    if [ "$named_style" = separated ]; then
        named_search=(-L "$WORK")
    else
        named_search=("-L$WORK")
    fi
    for named_expected in MISS HIT; do
        "$ZCC" cc -std=c23 -O1 "$WORK/named-main.c" -lzccnamed \
            "${named_search[@]}" -o "$WORK/named-archive" 2>"$WORK/named-archive.err" ||
            fail "later $named_style -L compile failed"
        [ "$(last_disposition)" = "$named_expected" ] || fail "later $named_style -L did not retain $named_expected"
        [ "$("$WORK/named-archive")" = 23 ] || fail "later $named_style -L produced wrong behavior"
    done
done

# -x can make a non-.c file a C source. It must bypass both levels: the
# ordinary content key treats that suffix as a raw blob and would miss its
# include closure as well.
cat > "$WORK/explicit.txt" <<'SRC'
#if __has_include("explicit.h")
#include "explicit.h"
#else
#define EXPLICIT_VALUE 1
#endif
#include <stdio.h>
int main(void) { printf("%d\n", EXPLICIT_VALUE); return 0; }
SRC
"$ZCC" cc -std=c23 -x c -I"$WORK" "$WORK/explicit.txt" \
    -o "$WORK/explicit" 2>"$WORK/explicit.first.err" ||
    fail "explicit-language baseline compile failed"
[ "$(last_disposition)" = BYPASS ] ||
    fail "explicit language mode entered an incomplete content cache"
[ "$("$WORK/explicit")" = 1 ] ||
    fail "explicit-language baseline behavior was wrong"
cat > "$WORK/explicit.h" <<'HDR'
#define EXPLICIT_VALUE 2
HDR
"$ZCC" cc -std=c23 -x c -I"$WORK" "$WORK/explicit.txt" \
    -o "$WORK/explicit" 2>"$WORK/explicit.second.err" ||
    fail "explicit-language changed compile failed"
[ "$(last_disposition)" = BYPASS ] ||
    fail "explicit language mode reused an incomplete content key"
[ "$("$WORK/explicit")" = 2 ] ||
    fail "explicit-language edit did not change executed behavior"


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

# A key alone cannot certify stored bytes. Corrupt each cached artifact in an
# isolated entry; the next invocation must compile rather than serve poison.
for suffix in bin dep err meta; do
    export ZCC_DIR="$WORK/poison-$suffix"
    poison_clean="$(stage_build "poison-$suffix-cold")" ||
        fail "$suffix poison fixture did not compile"
    cached_artifact="$(find "$ZCC_DIR/obj" -name "*.$suffix" -type f -print | head -n1)"
    [ -n "$cached_artifact" ] && [ -f "$cached_artifact" ] ||
        fail "$suffix poison fixture wrote no artifact"
    if [ -f "$cached_artifact" ]; then
        printf 'poison\n' > "$cached_artifact"
    fi
    lookup_start=$(wc -l < "$LOG")
    poison_fresh="$(stage_build "poison-$suffix-fresh")" ||
        fail "$suffix poison fixture did not rebuild"
    [ "$(last_disposition)" = MISS ] ||
        fail "corrupted $suffix was served as a HIT"
    [ "$poison_clean" = "$poison_fresh" ] ||
        fail "$suffix poison repair changed the clean object bytes"
    lookup_reason="$suffix-integrity"
    [ "$suffix" != meta ] || lookup_reason=meta-invalid
    lookup_lines=$(tail -n +"$((lookup_start + 1))" "$LOG")
    grep -Eq "^LOOKUP[[:space:]]+reason=$lookup_reason key=[0-9a-f]{64}[[:space:]]" <<<"$lookup_lines" ||
        fail "$suffix poison repair did not name its exact-key lookup failure"
    stage_build "poison-$suffix-warm" >/dev/null ||
        fail "$suffix poison repair could not be reused"
    [ "$(last_disposition)" = HIT ] ||
        fail "$suffix poison repair did not restore cache reuse"
    rm "$cached_artifact"
    lookup_start=$(wc -l < "$LOG")
    stage_build "missing-$suffix-fresh" >/dev/null ||
        fail "$suffix missing artifact did not rebuild"
    [ "$(last_disposition)" = MISS ] ||
        fail "missing $suffix was served as a HIT"
    lookup_reason="$suffix-unavailable"
    [ "$suffix" != meta ] || lookup_reason=meta-missing
    lookup_lines=$(tail -n +"$((lookup_start + 1))" "$LOG")
    grep -Eq "^LOOKUP[[:space:]]+reason=$lookup_reason key=[0-9a-f]{64}[[:space:]]" <<<"$lookup_lines" ||
        fail "$suffix missing artifact did not name its exact-key lookup failure"
done
export ZCC_DIR="$saved_cache"

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

# A NUL in a response-file token must not let the wrapper classify only its
# prefix while the compiler sees different bytes.
printf '%s\0%s\n' "$WORK/rsplib.o" "$WORK/rspmain.o" > "$WORK/nul.rsp"
"$ZCC" cc -std=c23 -O1 "@$WORK/nul.rsp" -o "$WORK/nulprog" \
    >"$WORK/nul.stdout" 2>"$WORK/nul.stderr" || :
[ "$(last_disposition)" = BYPASS ] ||
    fail "NUL response-file token entered the cache"

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

# Same-content requests share one compile; independent keys and audit requests
# retain their own compiler execution. Barriers follow real compilation so a
# header edit while a follower waits cannot change the owner's fixture bytes.
SF_ROOT="$WORK/singleflight"
mkdir -p "$SF_ROOT"
export SF_CC="$(command -v cc)"
cat > "$SF_ROOT/compiler" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
    case "$argument" in -E|--version|-dump*|-print-prog-name=*) exec "$SF_CC" "$@" ;; esac
done
: > "$SF_STATE/compile.$$"
owner=0
if [ "${SF_HOLD:-0}" = 1 ] && mkdir "$SF_STATE/owner" 2>/dev/null; then
    owner=1
fi
result=0
if [ "$owner" = 1 ] && [ "${SF_FAIL:-0}" = 1 ]; then
    result=75
else
    "$SF_CC" "$@" || result=$?
fi
: > "$SF_STATE/finished.$$"
if [ "$owner" = 1 ]; then
    printf '%s\n' "$PPID" > "$SF_STATE/owner.zccpid"
    : > "$SF_STATE/held"
    for ((attempt = 0; attempt < 400; attempt++)); do
        if [ -e "$SF_STATE/release" ]; then
            : > "$SF_STATE/released"
            exit "$result"
        fi
        sleep 0.025
    done
    echo 'singleflight fixture release timed out' >&2
    exit 76
fi
exit "$result"
WRAPPER
chmod +x "$SF_ROOT/compiler"

sf_ready()
{
    local path="$1" attempt
    for ((attempt = 0; attempt < 400; attempt++)); do
        [ -e "$path" ] && return 0
        sleep 0.025
    done
    fail "singleflight barrier timed out: $path"
    return 1
}

sf_count()
{
    local kind="$1" paths
    shopt -s nullglob
    paths=("$SF_STATE/$kind."*)
    shopt -u nullglob
    printf '%s\n' "${#paths[@]}"
}

sf_waiting()
{
    local output="$1" attempt
    for ((attempt = 0; attempt < 400; attempt++)); do
        if grep -q '^WAIT ' "$SF_STATE/log.$output" 2>/dev/null; then return 0; fi
        sleep 0.025
    done
    fail "singleflight $output did not observe contention"
    return 1
}

sf_case()
{
    export SF_STATE="$SF_ROOT/$1"
    mkdir -p "$SF_STATE"
    printf '#define VALUE 42\n' > "$SF_STATE/value.h"
    printf '#include "value.h"\nstatic int sf_unused(void) { return 0; }\nint value(void) { return VALUE; }\n' > "$SF_STATE/value.c"
}

sf_compile()
(
    local output="$1" definition="${2:-1}" audit="${3:-0}" hold="${4:-0}" reject="${5:-0}"
    unset ZCC_AUDIT
    if [ "$audit" = 1 ]; then export ZCC_AUDIT=1; fi
    ZCC_DIR="$SF_STATE/cache" ZCC_LOG="$SF_STATE/log.$output" \
        SF_HOLD="$hold" SF_FAIL="$reject" \
        "$ZCC" "$SF_ROOT/compiler" -std=c23 -O1 -Wall -DSF_KEY="$definition" \
        -MD -MF "$SF_STATE/$output.d" -MT "$SF_STATE/$output.o" \
        -c "$SF_STATE/value.c" -o "$SF_STATE/$output.o" \
        > "$SF_STATE/stdout.$output" 2> "$SF_STATE/stderr.$output"
)

sf_join()
{
    local process="$1" label="$2"
    wait "$process" || fail "singleflight $label compile failed"
}

sf_case shared
sf_compile owner 1 0 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile follower 1 0 1 & sf_follower=$!
sf_waiting follower || exit 1
# Independent-key completion proves there is no fleet-wide compile lock.
sf_compile independent 2 & sf_independent=$!
sf_join "$sf_independent" independent
[ "$(sf_count compile)" = 2 ] || fail 'same-key follower compiled while its owner was active'
: > "$SF_STATE/release"
sf_join "$sf_owner" owner
sf_join "$sf_follower" follower
[ "$(sf_count compile)" = 2 ] || fail 'identical cold requests did not share one compile'
cmp -s "$SF_STATE/owner.o" "$SF_STATE/follower.o" || fail 'shared compile output bytes differ'
grep -Fq "$SF_STATE/follower.o:" "$SF_STATE/follower.d" ||
    fail 'shared compile depfile does not name the follower target'
grep -Fq "$SF_STATE/value.h" "$SF_STATE/follower.d" ||
    fail 'shared compile depfile lost a header dependency'
grep -q 'sf_unused' "$SF_STATE/stderr.owner" || fail 'shared compile warning fixture produced no warning'
cmp -s "$SF_STATE/stderr.owner" "$SF_STATE/stderr.follower" ||
    fail 'shared compile did not replay exact compiler diagnostics'
grep -q '^HIT ' "$SF_STATE/log.follower" || fail 'same-key follower did not report a cache hit'

sf_case audit
sf_compile warm
sf_compile audit_owner 1 1 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile audit_peer 1 1 & sf_follower=$!
sf_join "$sf_follower" audit-peer
[ "$(sf_count compile)" = 3 ] || fail 'audit did not independently compile both requests'
: > "$SF_STATE/release"
sf_join "$sf_owner" audit-owner
cmp -s "$SF_STATE/audit_owner.o" "$SF_STATE/audit_peer.o" || fail 'independent audit output bytes differ'

sf_case failed
sf_compile failed_owner 1 0 1 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile retry 1 0 1 1 & sf_follower=$!
sf_waiting retry || exit 1
: > "$SF_STATE/release"
if wait "$sf_owner"; then fail 'failed compiler owner unexpectedly succeeded'; fi
sf_join "$sf_follower" recovery
[ "$(sf_count compile)" = 2 ] || fail 'failed owner did not release its compile claim'
[ -s "$SF_STATE/retry.o" ] || fail 'failed owner prevented successful follower output'

sf_case changed
sf_compile owner 1 0 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile follower 1 0 1 & sf_follower=$!
sf_waiting follower || exit 1
printf '#define VALUE 100\n' > "$SF_STATE/value.h"
: > "$SF_STATE/release"
sf_join "$sf_owner" changed-owner
sf_join "$sf_follower" changed-follower
"$SF_CC" -std=c23 -O1 -DSF_KEY=1 -c "$SF_STATE/value.c" -o "$SF_STATE/expected.o"
cmp -s "$SF_STATE/follower.o" "$SF_STATE/expected.o" ||
    fail 'inputs changed during wait but the follower returned stale bytes'
if cmp -s "$SF_STATE/owner.o" "$SF_STATE/follower.o"; then
    fail 'changed-input fixture did not distinguish old and new outputs'
fi
[ "$(sf_count compile)" = 2 ] || fail 'changed-input follower did not compile current inputs'

for sf_shape in symlink directory; do
    sf_case "unavailable-$sf_shape"
    mkdir -p "$SF_STATE/cache"
    printf 'untouched\n' > "$SF_STATE/sentinel"
    if [ "$sf_shape" = symlink ]; then
        ln -s "$SF_STATE/sentinel" "$SF_STATE/cache/flight.lock"
    else
        mkdir "$SF_STATE/cache/flight.lock"
    fi
    sf_compile first
    sf_compile second
    [ "$(sf_count compile)" = 2 ] || fail "$sf_shape lock refusal did not compile independently"
    cmp -s "$SF_STATE/first.o" "$SF_STATE/second.o" || fail "$sf_shape lock refusal changed output bytes"
    [ "$(cat "$SF_STATE/sentinel")" = untouched ] || fail 'lock refusal changed the symlink target'
    grep -q '^BYPASS ' "$SF_STATE/log.second" || fail "$sf_shape lock refusal did not report bypass"
done

sf_case killed
sf_compile owner 1 0 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile follower 1 0 1 & sf_follower=$!
sf_waiting follower || exit 1
sf_native="$(cat "$SF_STATE/owner.zccpid")"
case "$sf_native" in ''|*[!0-9]*) fail 'compiler wrapper did not identify its owner process'; exit 1 ;; esac
kill -KILL "$sf_native"
if wait "$sf_owner"; then fail 'killed compiler owner unexpectedly succeeded'; fi
sf_join "$sf_follower" killed-owner-recovery
[ "$(sf_count compile)" = 2 ] || fail 'killed owner did not release the compile claim'
[ -s "$SF_STATE/follower.o" ] || fail 'killed owner prevented follower output'
: > "$SF_STATE/release"
sf_ready "$SF_STATE/released" || exit 1

# The bootstrap executable is itself a compiler-identity input. Rebuilding
# its unchanged sources must not alter that identity because a private
# staging filename or a different physical checkout leaked into its bytes.
bootstrap_fixture()
{
    local destination="$1" input
    while IFS= read -r input || [ -n "$input" ]; do
        case "$input" in license=*) continue ;; esac
        mkdir -p "$destination/$(dirname "$input")"
        cp "$ROOT/$input" "$destination/$input"
    done < "$ROOT/tools/dev/zcc-bootstrap-inputs.list"
}

bootstrap_run()
{
    local checkout="$1" output="$2" built
    built="$(ZCL_BIN_DIR="$output" "$checkout/tools/dev/zcc_bootstrap.sh")"
    [ "$built" = "$output/zcc" ] && [ -x "$built" ] || {
        fail 'isolated bootstrap did not publish its executable'
        return 1
    }
}

bootstrap_one="$WORK/bootstrap-one"
bootstrap_two="$WORK/bootstrap-two"
bootstrap_fixture "$bootstrap_one"
bootstrap_fixture "$bootstrap_two"
bootstrap_run "$bootstrap_one" "$WORK/bootstrap-out-one" || exit 1
bootstrap_run "$bootstrap_one" "$WORK/bootstrap-out-repeat" || exit 1
bootstrap_run "$bootstrap_two" "$WORK/bootstrap-out-two" || exit 1
bootstrap_bin="$WORK/bootstrap-out-one/zcc"
cmp -s "$bootstrap_bin" "$WORK/bootstrap-out-repeat/zcc" ||
    fail 'identical bootstrap sources rebuilt to different compiler bytes'
cmp -s "$bootstrap_bin" "$WORK/bootstrap-out-two/zcc" ||
    fail 'physical checkout location changed bootstrap compiler bytes'
bootstrap_hash="$(sha256sum < "$bootstrap_bin" | awk '{print $1}')"

if [ "$(uname -s)" = Darwin ]; then
    for built in "$bootstrap_bin" "$WORK/bootstrap-out-repeat/zcc" \
            "$WORK/bootstrap-out-two/zcc"; do
        codesign --verify --strict "$built" || fail 'bootstrap signature is invalid'
        codesign -dvv "$built" > "$WORK/bootstrap-signature" 2>&1
        grep -Fxq 'Identifier=zcc' "$WORK/bootstrap-signature" ||
            fail 'bootstrap signature identity depends on its staging filename'
        uuid="$(otool -l "$built" | awk '/LC_UUID/{getline;getline;print $2}')"
        [ -n "$uuid" ] && [ "$uuid" != 00000000-0000-0000-0000-000000000000 ] ||
            fail 'bootstrap lost its nonzero content-derived UUID'
    done
fi

# A source edit must invalidate freshness and alter actual behavior; restoring
# exactly the original source must restore exactly the original executable.
sed 's/usage: zcc <compiler>/usage: zcc-fixture <compiler>/' \
    "$bootstrap_one/tools/zcc.c" > "$WORK/bootstrap-source"
mv "$WORK/bootstrap-source" "$bootstrap_one/tools/zcc.c"
bootstrap_run "$bootstrap_one" "$WORK/bootstrap-out-one" || exit 1
"$bootstrap_bin" > "$WORK/bootstrap-usage" 2>&1 || true
grep -Fq 'usage: zcc-fixture <compiler>' "$WORK/bootstrap-usage" ||
    fail 'bootstrap source edit did not change the published behavior'
[ "$(sha256sum < "$bootstrap_bin" | awk '{print $1}')" != "$bootstrap_hash" ] ||
    fail 'bootstrap source edit did not change compiler bytes'
cp "$ROOT/tools/zcc.c" "$bootstrap_one/tools/zcc.c"
bootstrap_run "$bootstrap_one" "$WORK/bootstrap-out-one" || exit 1
[ "$(sha256sum < "$bootstrap_bin" | awk '{print $1}')" = "$bootstrap_hash" ] ||
    fail 'restoring bootstrap source did not restore compiler bytes'

# Build flags live in the bootstrap script, which the input catalog includes.
# Its optimization change must invalidate a previously published executable.
sed 's/BOOTSTRAP_FLAGS=(-std=c23 -O2 /BOOTSTRAP_FLAGS=(-std=c23 -O0 /' \
    "$bootstrap_one/tools/dev/zcc_bootstrap.sh" > "$WORK/bootstrap-flags"
cat "$WORK/bootstrap-flags" > "$bootstrap_one/tools/dev/zcc_bootstrap.sh"
bootstrap_run "$bootstrap_one" "$WORK/bootstrap-out-one" || exit 1
[ "$(sha256sum < "$bootstrap_bin" | awk '{print $1}')" != "$bootstrap_hash" ] ||
    fail 'bootstrap flag edit did not change compiler bytes'

if [ "$failures" -ne 0 ]; then
    echo "check_zcc_cache: $failures failure(s); the compile cache is NOT trustworthy" >&2
    echo "  clear it now: make cc-cache-clear" >&2
    exit 1
fi

echo "check_zcc_cache: OK — hits are byte-identical; concurrent requests share compilation, audits remain independent, failed owners recover, changed inputs stay fresh; bootstrap bytes reproduce and retain source/flag sensitivity"
