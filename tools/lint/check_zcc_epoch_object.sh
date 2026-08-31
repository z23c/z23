#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Focused parity and fail-closed gate for native compile-epoch publication.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -n "${ZCC_EPOCH_TEST_BIN:-}" ]; then
    ZCC="$ZCC_EPOCH_TEST_BIN"
else
    ZCC="$("$ROOT/tools/dev/zcc_bootstrap.sh")"
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-zcc-epoch.XXXXXX")"
LOCK_HOLDER_PID=""
LOCKED_COMPILE_PID=""
cleanup()
{
    [ -z "$LOCKED_COMPILE_PID" ] || kill "$LOCKED_COMPILE_PID" 2>/dev/null || true
    [ -z "$LOCK_HOLDER_PID" ] || kill "$LOCK_HOLDER_PID" 2>/dev/null || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail()
{
    printf 'check_zcc_epoch_object: FAIL: %s\n' "$*" >&2
    exit 1
}

sha_label()
{
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        fail 'SHA-256 tool is unavailable'
    fi
}

file_stamp()
{
    stat -Lc '%d:%i:%s:%Y:%Z' "$1" 2>/dev/null ||
        stat -f '%d:%i:%z:%m:%c' "$1"
}

[ -x "$ZCC" ] || fail 'zcc bootstrap is unavailable'
command -v cc >/dev/null 2>&1 || fail 'C23 compiler is unavailable'

SOURCE_ID="$(sha_label source)"
MUTATION="$(sha_label mutation)"
EPOCH="$(sha_label epoch)"
COMPILER_ID="$(sha_label compiler)"
SOURCE="$WORK/main.c"
OBJECT_BASE="$WORK/objects"
OBJECT_ROOT="$OBJECT_BASE/epochs/$EPOCH"
ADMISSION_LOCK_ROOT="$OBJECT_BASE/.epoch-admission"
ADMISSION_LOCK="$ADMISSION_LOCK_ROOT/$EPOCH.lock"
SESSION="$OBJECT_ROOT/.build-session"
UNVERIFIED="$OBJECT_ROOT/.unverified"
OBJECT="$OBJECT_ROOT/main.o"
mkdir -p "$OBJECT_ROOT" "$ADMISSION_LOCK_ROOT"
export ZCC_DIR="$WORK/cache"
export ZCC_LOG="$WORK/zcc.log"

write_session()
{
    printf '%s\n' \
        'schema=zcl.build_epoch_session.v1' \
        "source_id=$SOURCE_ID" \
        'complete=1' \
        "mutation=$MUTATION" \
        "compiler_id=$COMPILER_ID" \
        "epoch=$EPOCH" \
        'profile=fixture-v1' \
        "flags_sha256=$(sha_label flags)" > "$SESSION"
}

write_expected_unverified()
{
    printf '%s\n' \
        'schema=zcl.build_epoch_unverified.v1' \
        "source_id=$SOURCE_ID" \
        "mutation=$MUTATION" \
        "compiler_id=$COMPILER_ID" \
        "epoch=$EPOCH" > "$WORK/unverified.expected"
}

wait_for_file()
{
    local path="$1" attempt
    for ((attempt = 0; attempt < 1000; attempt++)); do
        [ -e "$path" ] && return 0
        sleep 0.01
    done
    return 1
}

compile()
{
    local mode="$1" output="$2"
    shift 2
    "$ZCC" --epoch-object "$mode" "$output" "$SOURCE" \
        "$SOURCE_ID" 1 "$MUTATION" "$EPOCH" "$COMPILER_ID" \
        "$SESSION" -- "$@"
}

legacy_compile()
{
    local mode="$1" output="$2"
    shift 2
    "$ROOT/tools/dev/compile-epoch-object.sh" "$mode" "$output" "$SOURCE" \
        "$SOURCE_ID" 1 "$MUTATION" "$EPOCH" "$COMPILER_ID" \
        "$SESSION" -- "$@"
}

backend_compile()
{
    local backend="$1"
    shift
    if [ "$backend" = native ]; then
        compile "$@"
    else
        legacy_compile "$@"
    fi
}

printf '%s\n' \
    '#include <stdio.h>' \
    'int main(void) { puts("native-epoch"); return 0; }' > "$SOURCE"
write_session
write_expected_unverified

COUNTING_COMPILER="$WORK/counting-compiler.sh"
COMPILER_LAUNCHES="$WORK/compiler-launches"
cat > "$COUNTING_COMPILER" <<'COUNTING'
#!/usr/bin/env bash
set -euo pipefail
printf 'launch\n' >> "$COMPILER_LAUNCHES"
is_compile=0
for argument in "$@"; do
    [ "$argument" != -c ] || is_compile=1
done
cc "$@"
if [ "$is_compile" = 1 ] && [ -n "${COMPILER_COMPLETED:-}" ]; then
    : > "$COMPILER_COMPLETED"
fi
COUNTING
chmod +x "$COUNTING_COMPILER"

# A PE loader failure can terminate cc1 without writing a GCC-style
# diagnostic. The legacy epoch compiler must still name the source and exit
# status so Make never reports an unexplained generic Error 2.
SILENT_COMPILER="$WORK/silent-compiler.sh"
cat > "$SILENT_COMPILER" <<'SILENT_COMPILER'
#!/usr/bin/env bash
exit 2
SILENT_COMPILER
chmod +x "$SILENT_COMPILER"
SILENT_OBJECT="$OBJECT_ROOT/silent-compiler.o"
if legacy_compile dep "$SILENT_OBJECT" "$SILENT_COMPILER" \
        >"$WORK/silent-compiler.log" 2>&1; then
    fail 'legacy epoch object accepted a silent compiler failure'
fi
grep -Fq "compiler exited rc=2 source=$SOURCE" \
    "$WORK/silent-compiler.log" || {
    sed -n '1,80p' "$WORK/silent-compiler.log" >&2
    fail 'silent compiler failure lacked source and exit-status context'
}
[ ! -e "$SILENT_OBJECT" ] && [ ! -e "${SILENT_OBJECT%.o}.d" ] ||
    fail 'silent compiler failure published stable artifacts'

# Hold the descriptor-relative admission lock across a completed compiler.
# Stable artifacts and the durable marker must remain absent until release.
LOCK_HOLDER_SOURCE="$WORK/lock-holder.c"
LOCK_HOLDER="$WORK/lock-holder"
cat > "$LOCK_HOLDER_SOURCE" <<'LOCK_HOLDER'
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc != 4)
        return 2;
    int fd = open(argv[1], O_RDWR | O_CREAT, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0)
        return 2;
    int ready = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ready < 0 || close(ready) != 0)
        return 2;
    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
    while (access(argv[3], F_OK) != 0) {
        if (errno != ENOENT || nanosleep(&pause, NULL) != 0)
            return 2;
    }
    return close(fd) == 0 ? 0 : 2;
}
LOCK_HOLDER
cc -std=c23 -Wall -Wextra -Werror -pedantic -o "$LOCK_HOLDER" \
    "$LOCK_HOLDER_SOURCE"
LOCK_READY="$WORK/admission-lock-ready"
LOCK_RELEASE="$WORK/admission-lock-release"
LOCK_COMPILE_DONE="$WORK/admission-compiler-complete"
"$LOCK_HOLDER" "$ADMISSION_LOCK" "$LOCK_READY" \
    "$LOCK_RELEASE" &
LOCK_HOLDER_PID=$!
wait_for_file "$LOCK_READY" || fail 'admission lock holder did not start'
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
COMPILER_COMPLETED="$LOCK_COMPILE_DONE" \
compile dep "$OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror \
    "-frandom-seed=$SOURCE" > "$WORK/locked-compile.log" 2>&1 &
LOCKED_COMPILE_PID=$!
wait_for_file "$LOCK_COMPILE_DONE" ||
    fail 'compiler did not finish before admission serialization check'
kill -0 "$LOCKED_COMPILE_PID" 2>/dev/null ||
    fail 'epoch object did not wait for the held admission lock'
[ ! -e "$OBJECT" ] && [ ! -e "${OBJECT%.o}.d" ] &&
[ ! -e "$UNVERIFIED" ] ||
    fail 'stable epoch state appeared while admission lock was held'
: > "$LOCK_RELEASE"
wait "$LOCK_HOLDER_PID" || fail 'admission lock holder failed'
LOCK_HOLDER_PID=""
wait "$LOCKED_COMPILE_PID" || {
    sed -n '1,80p' "$WORK/locked-compile.log" >&2
    fail 'serialized epoch compile failed after lock release'
}
LOCKED_COMPILE_PID=""
[ ! -e "$OBJECT_ROOT/.admission.lock" ] &&
[ ! -e "$OBJECT_ROOT/.admission.lock.d" ] ||
    fail 'epoch publisher created a quarantine-splittable admission lock'
[ -s "$OBJECT" ] && [ -s "${OBJECT%.o}.d" ] ||
    fail 'native dep compile did not publish both artifacts'
cmp -s "$WORK/unverified.expected" "$UNVERIFIED" ||
    fail 'successful publication did not leave exact unverified authority'
grep -Fq "$OBJECT:" "${OBJECT%.o}.d" ||
    fail 'native depfile does not name the final object'
cc -o "$WORK/program" "$OBJECT"
[ "$("$WORK/program")" = native-epoch ] ||
    fail 'native object did not execute the source behavior'

# Existing marker state is authority, not scratch space. A malformed file or
# symlink refuses stable publication instead of being silently overwritten.
printf 'malformed\n' > "$UNVERIFIED"
for backend in native legacy; do
    MALFORMED_MARKER_OBJECT="$OBJECT_ROOT/malformed-marker-$backend.o"
    if backend_compile "$backend" dep "$MALFORMED_MARKER_OBJECT" cc \
            -std=c23 -O2 -Wall -Wextra -Werror \
            "-frandom-seed=$SOURCE" >/dev/null 2>&1; then
        fail "$backend epoch object overwrote a malformed unverified marker"
    fi
    [ ! -e "$MALFORMED_MARKER_OBJECT" ] &&
    [ ! -e "${MALFORMED_MARKER_OBJECT%.o}.d" ] ||
        fail "$backend malformed marker allowed stable artifact publication"
done
cp -- "$WORK/unverified.expected" "$UNVERIFIED"
rm -- "$UNVERIFIED"
printf 'redirect-target\n' > "$WORK/unverified-redirect"
ln -s "$WORK/unverified-redirect" "$UNVERIFIED"
for backend in native legacy; do
    SYMLINK_MARKER_OBJECT="$OBJECT_ROOT/symlink-marker-$backend.o"
    if backend_compile "$backend" dep "$SYMLINK_MARKER_OBJECT" cc \
            -std=c23 -O2 -Wall -Wextra -Werror \
            "-frandom-seed=$SOURCE" >/dev/null 2>&1; then
        fail "$backend epoch object followed an unverified marker symlink"
    fi
    [ ! -e "$SYMLINK_MARKER_OBJECT" ] &&
    [ ! -e "${SYMLINK_MARKER_OBJECT%.o}.d" ] ||
        fail "$backend symlink marker allowed stable artifact publication"
done
rm -- "$UNVERIFIED"
cp -- "$WORK/unverified.expected" "$UNVERIFIED"
UNVERIFIED_STAMP="$(file_stamp "$UNVERIFIED")" ||
    fail 'could not capture unverified marker identity'
LEGACY_MARKER_REUSE="$OBJECT_ROOT/legacy-marker-reuse.o"
legacy_compile dep "$LEGACY_MARKER_REUSE" cc \
    -std=c23 -O2 -Wall -Wextra -Werror "-frandom-seed=$SOURCE"
[ "$(file_stamp "$UNVERIFIED")" = "$UNVERIFIED_STAMP" ] ||
    fail 'legacy same-authority publication rewrote the durable marker'

# A fresh staging directory for identical inputs must be served from zcc's
# in-process cache and still restore both artifacts.
COLD_LAUNCHES="$(wc -l < "$COMPILER_LAUNCHES")"
rm -f -- "$OBJECT" "${OBJECT%.o}.d"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror \
    "-frandom-seed=$SOURCE"
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = HIT ] ||
    fail 'identical epoch compile did not use the in-process cache'
[ "$(wc -l < "$COMPILER_LAUNCHES")" = "$COLD_LAUNCHES" ] ||
    fail 'cache hit launched a compiler or preprocessor child'
[ -s "$OBJECT" ] && [ -s "${OBJECT%.o}.d" ] ||
    fail 'cache hit did not restore both epoch artifacts'
[ "$(file_stamp "$UNVERIFIED")" = "$UNVERIFIED_STAMP" ] ||
    fail 'same-authority publication rewrote the durable unverified marker'

# Make passes its selected compiler as `zcc COMPILER ...`. The epoch command
# must unwrap that exact admitted self-wrapper in-process: one coordinator on
# both cold and warm attempts, and no compiler child on the warm hit.
MAKE_STYLE="$OBJECT_ROOT/make-style.o"
LOG_BEFORE="$(wc -l < "$ZCC_LOG")"
LAUNCHES_BEFORE="$(wc -l < "$COMPILER_LAUNCHES")"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_STYLE" "$ZCC" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_STYLE_EPOCH=1 \
    "-frandom-seed=$SOURCE"
[ "$(wc -l < "$ZCC_LOG")" = "$((LOG_BEFORE + 1))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = MISS ] ||
    fail 'Make-style cold compile used more than one zcc coordinator'
MAKE_COLD_LAUNCHES="$(wc -l < "$COMPILER_LAUNCHES")"
[ "$MAKE_COLD_LAUNCHES" -gt "$LAUNCHES_BEFORE" ] ||
    fail 'Make-style cold compile launched no compiler child'
rm -f -- "$MAKE_STYLE" "${MAKE_STYLE%.o}.d"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_STYLE" "$ZCC" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_STYLE_EPOCH=1 \
    "-frandom-seed=$SOURCE"
[ "$(wc -l < "$ZCC_LOG")" = "$((LOG_BEFORE + 2))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = HIT ] ||
    fail 'Make-style warm compile used more than one zcc coordinator'
[ "$(wc -l < "$COMPILER_LAUNCHES")" = "$MAKE_COLD_LAUNCHES" ] ||
    fail 'Make-style warm hit launched a compiler child'

# The legacy shell oracle and the native path must publish identical object
# bytes for the same compiler inputs.
LEGACY="$OBJECT_ROOT/legacy.o"
legacy_compile dep "$LEGACY" \
    cc -std=c23 -O2 -Wall -Wextra -Werror "-frandom-seed=$SOURCE"
cmp -s "$OBJECT" "$LEGACY" || fail 'native and legacy object bytes diverged'

# -MMD keeps every project-like input while moving system-header authority to
# BUILD_COMPILER_ID. Exercise both epoch executors with the exact same target:
# their depfile and object bytes must match under GCC and available Clang.
MMD_LOCAL="$WORK/mmd/local"
MMD_GENERATED="$WORK/mmd/generated"
MMD_VENDOR="$WORK/mmd/vendor"
MMD_SYSTEM="$WORK/mmd/system"
mkdir -p "$MMD_LOCAL" "$MMD_GENERATED" "$MMD_VENDOR" "$MMD_SYSTEM"
printf '#define MMD_LOCAL_VALUE 1\n' > "$MMD_LOCAL/local_header.h"
printf '#define MMD_GENERATED_VALUE 2\n' > "$MMD_GENERATED/generated_header.h"
printf '#define MMD_VENDOR_VALUE 4\n' > "$MMD_VENDOR/vendor_header.h"
printf '#define MMD_SYSTEM_VALUE 8\n' > "$MMD_SYSTEM/system_header.h"
MMD_SOURCE="$WORK/mmd/main.c"
printf '%s\n' \
    '#include <stdio.h>' \
    '#include "local_header.h"' \
    '#include <generated_header.h>' \
    '#include <vendor_header.h>' \
    '#include <system_header.h>' \
    'int mmd_value(void) {' \
    ' return MMD_LOCAL_VALUE + MMD_GENERATED_VALUE +' \
    '        MMD_VENDOR_VALUE + MMD_SYSTEM_VALUE;' \
    '}' > "$MMD_SOURCE"

check_mmd_compiler()
{
    local compiler="$1" label="$2"
    local output="$OBJECT_ROOT/mmd-$label.o"
    local native_object="$WORK/mmd-$label.native.o"
    local native_dep="$WORK/mmd-$label.native.d"
    C_INCLUDE_PATH="$MMD_SYSTEM" compile dep "$output" "$compiler" \
        -std=c23 -O2 -Wall -Wextra -Werror \
        -I"$MMD_LOCAL" -I"$MMD_GENERATED" -I"$MMD_VENDOR"
    cp -- "$output" "$native_object"
    cp -- "${output%.o}.d" "$native_dep"
    rm -f -- "$output" "${output%.o}.d"
    C_INCLUDE_PATH="$MMD_SYSTEM" legacy_compile dep "$output" "$compiler" \
        -std=c23 -O2 -Wall -Wextra -Werror \
        -I"$MMD_LOCAL" -I"$MMD_GENERATED" -I"$MMD_VENDOR"
    cmp -s "$native_object" "$output" ||
        fail "$label native/legacy MMD object bytes diverged"
    cmp -s "$native_dep" "${output%.o}.d" ||
        fail "$label native/legacy MMD depfile bytes diverged"
    for retained in "$MMD_LOCAL/local_header.h" \
            "$MMD_GENERATED/generated_header.h" \
            "$MMD_VENDOR/vendor_header.h"; do
        grep -Fq "$retained" "$native_dep" ||
            fail "$label MMD depfile omitted project input $retained"
    done
    if grep -Fq "$MMD_SYSTEM/system_header.h" "$native_dep" ||
       grep -Fq 'stdio.h' "$native_dep"; then
        fail "$label MMD depfile retained a system header"
    fi
}

SOURCE_ORIGINAL="$SOURCE"
SOURCE="$MMD_SOURCE"
check_mmd_compiler cc gcc
if command -v clang >/dev/null 2>&1; then
    check_mmd_compiler clang clang
fi
SOURCE="$SOURCE_ORIGINAL"

BAD="$OBJECT_ROOT/bad.o"
REFUSAL_MARKER="$WORK/compiler-ran"
REFUSAL_COMPILER="$WORK/refusal-compiler.sh"
cat > "$REFUSAL_COMPILER" <<'REFUSAL'
#!/usr/bin/env bash
set -euo pipefail
: > "$REFUSAL_MARKER"
exit 0
REFUSAL
chmod +x "$REFUSAL_COMPILER"
if REFUSAL_MARKER="$REFUSAL_MARKER" \
    "$ZCC" --epoch-object dep "$BAD" "$SOURCE" \
        "$(sha_label wrong-source)" 1 "$MUTATION" "$EPOCH" "$COMPILER_ID" \
        "$SESSION" -- "$REFUSAL_COMPILER" >/dev/null 2>&1; then
    fail 'mismatched session authority was accepted'
fi
[ ! -e "$BAD" ] || fail 'authority refusal published an object'
for backend in native legacy; do
    rm -f -- "$REFUSAL_MARKER"
    if REFUSAL_MARKER="$REFUSAL_MARKER" backend_compile "$backend" dep \
            "$WORK/outside-$backend.o" "$REFUSAL_COMPILER" \
            >/dev/null 2>&1; then
        fail "$backend accepted output outside the epoch"
    fi
    if REFUSAL_MARKER="$REFUSAL_MARKER" backend_compile "$backend" dep \
            "$OBJECT_ROOT/../escaped-$backend.o" "$REFUSAL_COMPILER" \
            >/dev/null 2>&1; then
        fail "$backend accepted parent traversal in the epoch namespace"
    fi
    [ ! -e "$REFUSAL_MARKER" ] ||
        fail "$backend containment refusal launched the compiler"
done

printf 'source_id=%s\n' "$(sha_label conflicting-source)" >> "$SESSION"
for backend in native legacy; do
    rm -f -- "$REFUSAL_MARKER"
    if REFUSAL_MARKER="$REFUSAL_MARKER" backend_compile "$backend" dep \
            "$BAD-$backend" "$REFUSAL_COMPILER" >/dev/null 2>&1; then
        fail "$backend accepted conflicting duplicate session authority"
    fi
    [ ! -e "$REFUSAL_MARKER" ] ||
        fail "$backend duplicate-key refusal launched the compiler"
done
write_session

# Binary and structurally incomplete stamps refuse before compiler authority.
printf '\0' >> "$SESSION"
for backend in native legacy; do
    rm -f -- "$REFUSAL_MARKER"
    if REFUSAL_MARKER="$REFUSAL_MARKER" backend_compile "$backend" dep \
            "$BAD-nul-$backend" "$REFUSAL_COMPILER" >/dev/null 2>&1; then
        fail "$backend accepted a NUL-bearing session"
    fi
    [ ! -e "$REFUSAL_MARKER" ] ||
        fail "$backend NUL refusal launched the compiler"
done
write_session
printf '%s\n' \
    'schema=zcl.build_epoch_session.v1' \
    "source_id=$SOURCE_ID" \
    'complete=1' \
    "mutation=$MUTATION" \
    "compiler_id=$COMPILER_ID" \
    "epoch=$EPOCH" \
    'profile=fixture-v1' > "$SESSION"
for backend in native legacy; do
    rm -f -- "$REFUSAL_MARKER"
    if REFUSAL_MARKER="$REFUSAL_MARKER" backend_compile "$backend" dep \
            "$BAD-malformed-$backend" "$REFUSAL_COMPILER" \
            >/dev/null 2>&1; then
        fail "$backend accepted a session without its flags binding"
    fi
    [ ! -e "$REFUSAL_MARKER" ] ||
        fail "$backend malformed-session refusal launched the compiler"
done
write_session

printf '%s\n' 'unknown=authority-expansion' >> "$SESSION"
for backend in native legacy; do
    if backend_compile "$backend" dep "$BAD-extra-$backend" \
            "$REFUSAL_COMPILER" >/dev/null 2>&1; then
        fail "$backend accepted an unknown session row"
    fi
done
write_session
SESSION_TEXT="$(< "$SESSION")"
printf '%s' "$SESSION_TEXT" > "$SESSION"
for backend in native legacy; do
    if backend_compile "$backend" dep "$BAD-newline-$backend" \
            "$REFUSAL_COMPILER" >/dev/null 2>&1; then
        fail "$backend accepted a session without its final newline"
    fi
done
write_session

mkdir "$OBJECT_ROOT/real-directory"
ln -s real-directory "$OBJECT_ROOT/symlink-directory"
for backend in native legacy; do
    if backend_compile "$backend" dep \
            "$OBJECT_ROOT/symlink-directory/$backend.o" \
            "$REFUSAL_COMPILER" >/dev/null 2>&1; then
        fail "$backend accepted a symlink in the object path"
    fi
done

# Native compilation writes only through the already-open staging directory.
# Replacing its parent with a symlink while the compiler runs must neither
# redirect a compiler write nor publish into the renamed original directory.
SWAP_CONTAINER="$OBJECT_ROOT/swap-container"
SWAP_PARENT="$SWAP_CONTAINER/parent"
SWAP_SAVED="$SWAP_CONTAINER/held-parent"
SWAP_ESCAPE="$WORK/swap-escape"
SWAP_DONE="$WORK/swap-compiler-complete"
SWAP_OBJECT="$SWAP_PARENT/swap.o"
mkdir -p "$SWAP_PARENT" "$SWAP_ESCAPE"
SWAP_COMPILER="$WORK/swap-compiler.sh"
cat > "$SWAP_COMPILER" <<'SWAP'
#!/usr/bin/env bash
set -euo pipefail
mv -- "$SWAP_PARENT" "$SWAP_SAVED"
ln -s -- "$SWAP_ESCAPE" "$SWAP_PARENT"
cc "$@"
: > "$SWAP_DONE"
SWAP
chmod +x "$SWAP_COMPILER"
if ZCC_DISABLE=1 SWAP_PARENT="$SWAP_PARENT" SWAP_SAVED="$SWAP_SAVED" \
        SWAP_ESCAPE="$SWAP_ESCAPE" SWAP_DONE="$SWAP_DONE" \
        compile dep "$SWAP_OBJECT" \
        "$SWAP_COMPILER" -std=c23 -O2 -Wall -Wextra -Werror \
        "-frandom-seed=$SOURCE" >/dev/null 2>&1; then
    fail 'native publication accepted a swapped output parent'
fi
[ -L "$SWAP_PARENT" ] || fail 'adversarial compiler did not swap the parent'
[ -f "$SWAP_DONE" ] || fail 'adversarial compiler did not finish its write'
[ -z "$(find "$SWAP_ESCAPE" -type f -print -quit)" ] ||
    fail 'native compiler write escaped through a swapped parent symlink'
[ -z "$(find "$SWAP_SAVED" -type f -print -quit)" ] ||
    fail 'native refusal retained artifacts in the renamed output parent'
[ ! -e "$SWAP_OBJECT" ] && [ ! -e "${SWAP_OBJECT%.o}.d" ] ||
    fail 'native parent-swap refusal published final artifacts'
rm -- "$SWAP_PARENT"
mv -- "$SWAP_SAVED" "$SWAP_PARENT"

# Mutating the session after compiler start is an ABA boundary: compilation
# may finish, but its stale authority cannot publish.
ABA_COMPILER="$WORK/aba-compiler.sh"
cat > "$ABA_COMPILER" <<'ABA'
#!/usr/bin/env bash
set -euo pipefail
cc "$@"
printf '%s\n' 'changed-during-compile' >> "$SESSION_PATH"
ABA
chmod +x "$ABA_COMPILER"
ABA_OBJECT="$OBJECT_ROOT/aba.o"
for backend in native legacy; do
    write_session
    ABA_OBJECT="$OBJECT_ROOT/aba-$backend.o"
    if SESSION_PATH="$SESSION" backend_compile "$backend" dep "$ABA_OBJECT" \
            "$ABA_COMPILER" -std=c23 -O2 -Wall -Wextra -Werror \
            "-frandom-seed=$SOURCE" >/dev/null 2>&1; then
        fail "$backend published after its session changed"
    fi
    [ ! -e "$ABA_OBJECT" ] || fail "$backend ABA refusal published an object"
done
if [ -n "$(find "$OBJECT_ROOT" -maxdepth 1 -name '.zcc-epoch.*' \
        -print -quit)" ]; then
    fail 'failed native compile leaked a staging directory'
fi
write_session

COVERAGE="$OBJECT_ROOT/coverage.o"
for backend in native legacy; do
    PARTIAL="$OBJECT_ROOT/partial-$backend.o"
    mkdir "${PARTIAL%.o}.gcno-path"
    if backend_compile "$backend" coverage "$PARTIAL" cc --coverage \
            -std=c23 -O0 >/dev/null 2>&1; then
        fail "$backend coverage accepted a blocked admission record"
    fi
    [ ! -e "$PARTIAL" ] && [ ! -e "${PARTIAL%.o}.d" ] ||
        fail "$backend failed coverage admission partially published artifacts"
    rmdir "${PARTIAL%.o}.gcno-path"
done
compile coverage "$COVERAGE" cc --coverage -std=c23 -O0
read -r COVERAGE_NOTE < "${COVERAGE%.o}.gcno-path"
[ -s "$COVERAGE" ] && [ -s "${COVERAGE%.o}.d" ] &&
[ -s "$COVERAGE_NOTE" ] || fail 'coverage publication is incomplete'
for backend in native legacy; do
    if backend_compile "$backend" coverage "$COVERAGE" /bin/false \
            >/dev/null 2>&1; then
        fail "$backend coverage reused an artifact without invocation-bound authority"
    fi
done
rm -f -- "$COVERAGE_NOTE"
if compile coverage "$COVERAGE" /bin/false >/dev/null 2>&1; then
    fail 'coverage object with a missing note was accepted'
fi
compile coverage "$COVERAGE" cc --coverage -std=c23 -O0
read -r REPAIRED_NOTE < "${COVERAGE%.o}.gcno-path"
[ -s "$REPAIRED_NOTE" ] || fail 'coverage compile did not repair its note'

printf 'check_zcc_epoch_object: PASS cache=hit mmd_dep_parity=exact system_authority=closed path_swap=closed admission_lock=serialized unverified=durable coverage_record=last\n'
