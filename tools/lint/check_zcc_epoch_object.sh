#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Focused parity and fail-closed gate for native compile-epoch publication.

set -euo pipefail

# Test ordinary epoch-cache hits even when the proof runner is compiling
# cold; the verified-mode case below sets ZCC_VERIFIED explicitly.
unset ZCC_VERIFIED

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -n "${ZCC_EPOCH_TEST_BIN:-}" ]; then
    ZCC="$ZCC_EPOCH_TEST_BIN"
else
    ZCC="$("$ROOT/tools/dev/zcc_bootstrap.sh")"
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-zcc-epoch.XXXXXX")"
# Darwin exposes /var as a symlink to /private/var; use the physical path so
# this gate tests the epoch compiler rather than tripping path containment on
# the host's compatibility alias.
WORK="$(cd "$WORK" && pwd -P)"
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

expect_log_output()
{
    local line
    line="$(tail -1 "$ZCC_LOG")"
    case "$line" in
        *" $1") ;;
        *) fail "cache diagnostic did not name expected output: $1" ;;
    esac
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

# Waits for a marker written by a process the script started. The wait ends on
# the marker (0) or on that process exiting without it (2); the attempt bound
# only guards a hung process (1) and is not a speed expectation.
wait_for_file()
{
    local path="$1" pid="$2" attempt
    for ((attempt = 0; attempt < 60000; attempt++)); do
        [ -e "$path" ] && return 0
        kill -0 "$pid" 2>/dev/null || return 2
        sleep 0.01
    done
    return 1
}

wait_for_marker()
{
    local path="$1" pid="$2" what="$3" status=0
    wait_for_file "$path" "$pid" || status=$?
    case "$status" in
        0) ;;
        2) fail "$what exited before signalling" ;;
        *) fail "$what did not signal within the hung-process bound" ;;
    esac
}

# Establishes that the compile is blocked on the held admission lock. Linux
# lists blocked flock requests in /proc/locks, which makes the block an
# observed fact. Hosts without that table get a short settle, after which the
# liveness and absence checks that follow still apply.
wait_for_lock_waiter()
{
    local lock="$1" pid="$2" inode attempt
    if [ ! -r /proc/locks ]; then
        sleep 0.5
        return 0
    fi
    read -r inode _ < <(ls -Lid -- "$lock") || inode=
    case "$inode" in
        ''|*[!0-9]*) fail 'could not identify the admission lock' ;;
    esac
    for ((attempt = 0; attempt < 60000; attempt++)); do
        grep -Eq -- "-> *FLOCK.*:$inode " /proc/locks && return 0
        kill -0 "$pid" 2>/dev/null ||
            fail 'locked epoch compile ended without blocking on the held admission lock'
        sleep 0.01
    done
    fail 'locked epoch compile did not block within the hung-process bound'
}

make_test_directory_link()
{
    local link="$1" target="$2" host_system native_link native_target
    host_system="$(uname -s 2>/dev/null || printf unknown)"
    case "$host_system" in
        MSYS*|MINGW*|CYGWIN*)
            native_link="$(cygpath -w "$link")" || return 1
            native_target="$(cygpath -w "$target")" || return 1
            MSYS2_ARG_CONV_EXCL='*' cmd.exe /d /c mklink /J \
                "$native_link" "$native_target" >/dev/null || return 1
            ;;
        *) ln -s -- "$target" "$link" || return 1 ;;
    esac
    [ -L "$link" ]
}

remove_test_directory_link()
{
    local link="$1" host_system
    host_system="$(uname -s 2>/dev/null || printf unknown)"
    case "$host_system" in
        MSYS*|MINGW*|CYGWIN*) rmdir -- "$link" ;;
        *)                    rm -- "$link" ;;
    esac
}
export -f make_test_directory_link

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
    '#if __has_include("epoch-choice.h")' \
    '#include "epoch-choice.h"' \
    '#else' \
    '#define EPOCH_LABEL "native-epoch"' \
    '#endif' \
    '#include <stdio.h>' \
    'int main(void) { puts(EPOCH_LABEL); return 0; }' > "$SOURCE"
write_session
write_expected_unverified

COUNTING_COMPILER="$WORK/counting-compiler.sh"
COMPILER_LAUNCHES="$WORK/compiler-launches"
cat > "$COUNTING_COMPILER" <<'COUNTING'
#!/usr/bin/env bash
set -euo pipefail
kind=other
is_compile=0
for argument in "$@"; do
    if [ "$argument" = -c ]; then
        is_compile=1
        kind=compile
    elif [ "$argument" = -E ]; then
        kind=preprocess
    fi
done
printf '%s\n' "$kind" >> "$COMPILER_LAUNCHES"
cc "$@"
if [ "$is_compile" = 1 ] && [ -n "${COMPILER_COMPLETED:-}" ]; then
    : > "$COMPILER_COMPLETED"
fi
COUNTING
chmod +x "$COUNTING_COMPILER"

launch_count()
{
    grep -cx -- "$1" "$COMPILER_LAUNCHES" || true
}

cache_outcome_count()
{
    # Lookup diagnostics describe probes; only disposition rows count a
    # coordinator's compile/cache outcome.
    grep -Ec '^(HIT|MISS|BYPASS|UNKEY)[[:space:]]' "$ZCC_LOG" || true
}

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
#define _DARWIN_C_SOURCE
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
POSIX_CC=cc
case "$(uname -s 2>/dev/null || printf unknown)" in
    MSYS*|MINGW*|CYGWIN*) POSIX_CC="${ZCC_POSIX_CC:-/usr/bin/cc}" ;;
esac
"$POSIX_CC" -std=c23 -Wall -Wextra -Werror -pedantic -o "$LOCK_HOLDER" \
    "$LOCK_HOLDER_SOURCE"
LOCK_READY="$WORK/admission-lock-ready"
LOCK_RELEASE="$WORK/admission-lock-release"
LOCK_COMPILE_DONE="$WORK/admission-compiler-complete"
"$LOCK_HOLDER" "$ADMISSION_LOCK" "$LOCK_READY" \
    "$LOCK_RELEASE" &
LOCK_HOLDER_PID=$!
wait_for_marker "$LOCK_READY" "$LOCK_HOLDER_PID" 'admission lock holder'
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
COMPILER_COMPLETED="$LOCK_COMPILE_DONE" \
compile dep "$OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror \
    "-frandom-seed=$SOURCE" > "$WORK/locked-compile.log" 2>&1 &
LOCKED_COMPILE_PID=$!
wait_for_marker "$LOCK_COMPILE_DONE" "$LOCKED_COMPILE_PID" \
    'locked epoch compile'
wait_for_lock_waiter "$ADMISSION_LOCK" "$LOCKED_COMPILE_PID"
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
mkdir "$WORK/unverified-redirect"
make_test_directory_link "$UNVERIFIED" "$WORK/unverified-redirect" ||
    fail 'could not create a real unverified-marker link fixture'
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
remove_test_directory_link "$UNVERIFIED"
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
# Keep the compiler-visible completion marker identical to the cold call;
# the cache correctly binds this variable even though it only signals a test.
COLD_PREPROCESS="$(launch_count preprocess)"
COLD_COMPILE="$(launch_count compile)"
rm -f -- "$OBJECT" "${OBJECT%.o}.d"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
COMPILER_COMPLETED="$LOCK_COMPILE_DONE" \
compile dep "$OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror \
    "-frandom-seed=$SOURCE"
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = HIT ] ||
    fail 'identical epoch compile did not use the in-process cache'
[ "$(launch_count preprocess)" = "$((COLD_PREPROCESS + 1))" ] ||
    fail 'source cache hit did not recheck the include search'
[ "$(launch_count compile)" = "$COLD_COMPILE" ] ||
    fail 'unchanged source cache hit launched an object compiler'
[ -s "$OBJECT" ] && [ -s "${OBJECT%.o}.d" ] ||
    fail 'cache hit did not restore both epoch artifacts'
[ "$(file_stamp "$UNVERIFIED")" = "$UNVERIFIED_STAMP" ] ||
    fail 'same-authority publication rewrote the durable unverified marker'

# The proof's verified mode must also bypass the epoch object's cache hit.
# Count the actual compiler child, not merely the wrapper invocation.
VERIFIED_LAUNCHES="$(wc -l < "$COMPILER_LAUNCHES")"
rm -f -- "$OBJECT" "${OBJECT%.o}.d"
ZCC_VERIFIED=1 COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror "-frandom-seed=$SOURCE"
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = MISS ] ||
    fail 'verified epoch compile served a same-account cache entry'
expect_log_output "$OBJECT"
[ "$(wc -l < "$COMPILER_LAUNCHES")" = "$((VERIFIED_LAUNCHES + 1))" ] ||
    fail 'verified epoch compile skipped the real compiler'
[ -s "$OBJECT" ] && [ -s "${OBJECT%.o}.d" ] ||
    fail 'verified epoch compile did not publish complete fresh artifacts'

# Make passes its selected compiler as `zcc COMPILER ...`. The epoch command
# must unwrap that exact admitted self-wrapper in-process: one coordinator on
# both cold and warm attempts, and no compiler child on the warm hit.
MAKE_STYLE="$OBJECT_ROOT/make-style.o"
LOG_BEFORE="$(cache_outcome_count)"
LAUNCHES_BEFORE="$(wc -l < "$COMPILER_LAUNCHES")"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_STYLE" "$ZCC" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_STYLE_EPOCH=1 \
    "-frandom-seed=$SOURCE"
[ "$(cache_outcome_count)" = "$((LOG_BEFORE + 1))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = MISS ] ||
    fail 'Make-style cold compile used more than one zcc coordinator'
expect_log_output "$MAKE_STYLE"
MAKE_COLD_LAUNCHES="$(wc -l < "$COMPILER_LAUNCHES")"
[ "$MAKE_COLD_LAUNCHES" -gt "$LAUNCHES_BEFORE" ] ||
    fail 'Make-style cold compile launched no compiler child'
MAKE_COLD_PREPROCESS="$(launch_count preprocess)"
MAKE_COLD_COMPILE="$(launch_count compile)"
rm -f -- "$MAKE_STYLE" "${MAKE_STYLE%.o}.d"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_STYLE" "$ZCC" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_STYLE_EPOCH=1 \
    "-frandom-seed=$SOURCE"
[ "$(cache_outcome_count)" = "$((LOG_BEFORE + 2))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = HIT ] ||
    fail 'Make-style warm compile used more than one zcc coordinator'
expect_log_output "$MAKE_STYLE"
[ "$(launch_count preprocess)" = "$((MAKE_COLD_PREPROCESS + 1))" ] ||
    fail 'Make-style warm hit did not recheck includes'
[ "$(launch_count compile)" = "$MAKE_COLD_COMPILE" ] ||
    fail 'Make-style warm hit launched an object compiler'

# Distinct canonical paths must survive reused descriptor numbers/basenames.
for leaf in first second; do
    compile dep "$OBJECT_ROOT/$leaf/same.o" cc -std=c23 -O2 -Wall
    expect_log_output "$OBJECT_ROOT/$leaf/same.o"
done
# A valid real path on Darwin (PATH_MAX=1024) can render beyond the old
# diagnostic buffer once literal backslashes are escaped. Test both lengths.
LONG_OUTPUT="$OBJECT_ROOT"
LONG_EXPECTED="$OBJECT_ROOT"
LONG_PART="$(awk 'BEGIN { for (i=0; i<160; i++) printf "%c", 92 }')"
LONG_ESCAPED_PART="$(awk 'BEGIN { for (i=0; i<320; i++) printf "%c", 92 }')"
for part in 1 2 3 4; do
    LONG_OUTPUT="$LONG_OUTPUT/$LONG_PART"
    LONG_EXPECTED="$LONG_EXPECTED/$LONG_ESCAPED_PART"
done
LONG_OUTPUT="$LONG_OUTPUT/long.o"
LONG_EXPECTED="$LONG_EXPECTED/long.o"
[ "${#LONG_OUTPUT}" -lt 1024 ] || fail 'long diagnostic fixture real path exceeds Darwin bound'
[ "${#LONG_EXPECTED}" -gt 1024 ] || fail 'long diagnostic fixture did not exceed old log bound'
printf 'check_zcc_epoch_object: long diagnostic real=%s rendered=%s bytes\n' \
    "${#LONG_OUTPUT}" "${#LONG_EXPECTED}"
LONG_COMPILES_BEFORE="$(launch_count compile)"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$LONG_OUTPUT" "$COUNTING_COMPILER" -std=c23 -O2 -Wall -DZCL_LONG_DIAGNOSTIC=1
[ "$(launch_count compile)" = "$((LONG_COMPILES_BEFORE + 1))" ] ||
    fail 'long diagnostic fixture did not execute an object compiler'
expect_log_output "$LONG_EXPECTED"

# Backslash and controls have one unambiguous textual representation; the
# compiler still receives the original path, not its diagnostic spelling.
CONTROL_OUTPUT="$(printf '%s/diagnostic\\tab\tline\nreturn\r.o' "$OBJECT_ROOT")"
CONTROL_EXPECTED="$OBJECT_ROOT/diagnostic\\\\tab\\x09line\\x0areturn\\x0d.o"
CONTROL_BEFORE="$(wc -l < "$ZCC_LOG")"
compile dep "$CONTROL_OUTPUT" cc -std=c23 -O2 -Wall
expect_log_output "$CONTROL_EXPECTED"
[ "$(wc -l < "$ZCC_LOG")" -gt "$CONTROL_BEFORE" ] || fail 'control-path log missing'
! grep -q '^return' "$ZCC_LOG" || fail 'control path injected a log row'

# A following ordinary compile retains its actual standalone output spelling.
"$ZCC" cc -std=c23 -O2 -c "$SOURCE" -o "$WORK/standalone.o"
expect_log_output "$WORK/standalone.o"

# A separate BUILD_DIR publishes a byte-identical zcc at a different inode.
# It must unwrap exactly like the same-file wrapper above, without issuing
# a driver query to zcc itself or adding another cache coordinator.
ZCC_COPY="$WORK/zcc-copy"
cp "$ZCC" "$ZCC_COPY"
[ ! "$ZCC" -ef "$ZCC_COPY" ] || fail 'copied zcc shares the original inode'
cmp "$ZCC" "$ZCC_COPY" || fail 'copied zcc bytes differ'
MAKE_COPY="$OBJECT_ROOT/make-copy.o"
LOG_BEFORE="$(cache_outcome_count)"
LAUNCHES_BEFORE="$(wc -l < "$COMPILER_LAUNCHES")"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_COPY" "$ZCC_COPY" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_COPY_EPOCH=1 \
    "-frandom-seed=$SOURCE" 2>"$WORK/make-copy-cold.err"
[ "$(cache_outcome_count)" = "$((LOG_BEFORE + 1))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = MISS ] ||
    fail 'copied-wrapper cold compile used more than one zcc coordinator'
[ "$(wc -l < "$COMPILER_LAUNCHES")" -gt "$LAUNCHES_BEFORE" ] ||
    fail 'copied-wrapper cold compile launched no compiler child'
! grep -F 'zcc: cannot execute -print-prog-name=' "$WORK/make-copy-cold.err" ||
    fail 'copied-wrapper cold compile queried zcc as the compiler driver'
COPY_COLD_PREPROCESS="$(launch_count preprocess)"
COPY_COLD_COMPILE="$(launch_count compile)"
rm -f -- "$MAKE_COPY" "${MAKE_COPY%.o}.d"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_COPY" "$ZCC_COPY" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_COPY_EPOCH=1 \
    "-frandom-seed=$SOURCE" 2>"$WORK/make-copy-warm.err"
[ "$(cache_outcome_count)" = "$((LOG_BEFORE + 2))" ] &&
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = HIT ] ||
    fail 'copied-wrapper warm compile used more than one zcc coordinator'
[ "$(launch_count preprocess)" = "$((COPY_COLD_PREPROCESS + 1))" ] &&
[ "$(launch_count compile)" = "$COPY_COLD_COMPILE" ] ||
    fail 'copied-wrapper warm hit failed fresh preprocess or compiled an object'
! grep -F 'zcc: cannot execute -print-prog-name=' "$WORK/make-copy-warm.err" ||
    fail 'copied-wrapper warm compile queried zcc as the compiler driver'

# Equal size alone must not unwrap a different, working compiler forwarder.
cat > "$WORK/different-wrapper.c" <<'DIFFERENT_WRAPPER'
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    const char *log = getenv("COMPILER_LAUNCHES");
    if (argc < 2 || !log) return 2;
    FILE *f = fopen(log, "a");
    if (!f) return 2;
    int wrote = fputs("different-wrapper\n", f);
    int closed = fclose(f);
    if (wrote < 0 || closed != 0) return 2;
    execvp(argv[1], argv + 1);
    perror("different-wrapper: compiler");
    return 2;
}
DIFFERENT_WRAPPER
DIFFERENT_WRAPPER="$WORK/different-wrapper"
"$POSIX_CC" -std=c23 -O1 -Wall -Wextra -Werror \
    "$WORK/different-wrapper.c" -o "$DIFFERENT_WRAPPER"
ZCC_SIZE="$(wc -c < "$ZCC")"
[ "$(wc -c < "$DIFFERENT_WRAPPER")" -lt "$ZCC_SIZE" ] ||
    fail 'different-wrapper fixture cannot be padded to zcc size'
dd if=/dev/zero of="$DIFFERENT_WRAPPER" bs=1 count=1 \
    seek="$((ZCC_SIZE - 1))" conv=notrunc 2>/dev/null
[ "$(wc -c < "$DIFFERENT_WRAPPER")" = "$ZCC_SIZE" ] ||
    fail 'different-wrapper size differs from zcc'
! cmp -s "$ZCC" "$DIFFERENT_WRAPPER" || fail 'different-wrapper bytes equal zcc'
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
    "$DIFFERENT_WRAPPER" "$POSIX_CC" --version >"$WORK/different-wrapper-version"
DIFFERENT_BEFORE="$(grep -c '^different-wrapper$' "$COMPILER_LAUNCHES")"
MAKE_DIFFERENT="$OBJECT_ROOT/make-different.o"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$MAKE_DIFFERENT" "$DIFFERENT_WRAPPER" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_COPY_EPOCH=1 \
    "-frandom-seed=$SOURCE" 2>"$WORK/make-different.err"
[ "$(grep -c '^different-wrapper$' "$COMPILER_LAUNCHES")" -gt "$DIFFERENT_BEFORE" ] ||
    fail 'same-size different executable was incorrectly unwrapped'
cmp -s "$MAKE_COPY" "$MAKE_DIFFERENT" ||
    fail 'same-size different executable changed forwarded compile output'

if [ "${ZCC_EPOCH_TIMING:-0}" = 1 ]; then
    # Opt-in whole-invocation timing: includes fresh preprocessing and cache
    # validation, not an isolated digest cost or a throughput comparison.
    TIMING_REFERENCE="$WORK/timing-reference.o"
    cp "$MAKE_COPY" "$TIMING_REFERENCE"
    for TIMING_KIND in same-inode identical-copy; do
        TIMING_WRAPPER="$ZCC"
        [ "$TIMING_KIND" != identical-copy ] || TIMING_WRAPPER="$ZCC_COPY"
        TIMING_OUT="$OBJECT_ROOT/timing-$TIMING_KIND.o"
        COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
        compile dep "$TIMING_OUT" "$TIMING_WRAPPER" "$COUNTING_COMPILER" \
            -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_COPY_EPOCH=1 \
            "-frandom-seed=$SOURCE" 2>"$WORK/timing-warmup.err"
        TIMING_HITS_BEFORE="$(awk '$1 == "HIT" {n++} END {print n+0}' "$ZCC_LOG")"
        TIMING_PREPROCESS_BEFORE="$(launch_count preprocess)"
        TIMING_COMPILE_BEFORE="$(launch_count compile)"
        TIMEFORMAT="epoch-wrapper-timing $TIMING_KIND n=5 real_s=%R user_s=%U sys_s=%S"
        { time {
            for TIMING_SAMPLE in 1 2 3 4 5; do
                rm -f -- "$TIMING_OUT" "${TIMING_OUT%.o}.d"
                COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
                compile dep "$TIMING_OUT" "$TIMING_WRAPPER" "$COUNTING_COMPILER" \
                    -std=c23 -O2 -Wall -Wextra -Werror -DMAKE_COPY_EPOCH=1 \
                    "-frandom-seed=$SOURCE" 2>"$WORK/timing-sample.err"
                cmp -s "$TIMING_REFERENCE" "$TIMING_OUT" ||
                    fail 'timed invocation changed object bytes'
            done
        }; } 2>"$WORK/timing-$TIMING_KIND.txt"
        cat "$WORK/timing-$TIMING_KIND.txt"
        [ "$(awk '$1 == "HIT" {n++} END {print n+0}' "$ZCC_LOG")" = "$((TIMING_HITS_BEFORE + 5))" ] ||
            fail 'timing batch did not produce five warm hits'
        [ "$(launch_count preprocess)" = "$((TIMING_PREPROCESS_BEFORE + 5))" ] ||
            fail 'timing batch did not freshly preprocess every invocation'
        [ "$(launch_count compile)" = "$TIMING_COMPILE_BEFORE" ] ||
            fail 'timing batch launched an object compiler'
    done
    printf '%s\n' 'epoch-wrapper-timing scope=whole-invocation-plus-output-check; includes preprocessing, not isolated hashing'
fi

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
make_test_directory_link "$OBJECT_ROOT/symlink-directory" \
    "$OBJECT_ROOT/real-directory" ||
    fail 'could not create a real object-path link fixture'
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
make_test_directory_link "$SWAP_PARENT" "$SWAP_ESCAPE"
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
remove_test_directory_link "$SWAP_PARENT"
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

# A previously absent local header is a real input lookup. Its appearance
# must leave the old cached object behind and change executable behavior.
cat > "$WORK/epoch-choice.h" <<'HDR'
#define EPOCH_LABEL "native-epoch-shadow"
HDR
SHADOW_OBJECT="$OBJECT_ROOT/shadow.o"
SHADOW_COMPILE_BEFORE="$(launch_count compile)"
COMPILER_LAUNCHES="$COMPILER_LAUNCHES" \
compile dep "$SHADOW_OBJECT" "$COUNTING_COMPILER" \
    -std=c23 -O2 -Wall -Wextra -Werror "-frandom-seed=$SOURCE"
[ "$(tail -1 "$ZCC_LOG" | awk '{print $1}')" = MISS ] ||
    fail 'new local header was served from the old source cache key'
[ "$(launch_count compile)" = "$((SHADOW_COMPILE_BEFORE + 1))" ] ||
    fail 'new local header did not launch a fresh object compile'
cc -o "$WORK/shadow-program" "$SHADOW_OBJECT"
[ "$("$WORK/shadow-program")" = native-epoch-shadow ] ||
    fail 'new local header did not change executed behavior'

! grep -E '/proc/self/fd/[0-9]+/|/dev/fd/[0-9]+' "$ZCC_LOG" ||
    fail 'native diagnostic exposed an ephemeral descriptor output'
printf 'check_zcc_epoch_object: PASS cache=content_hit fresh_preprocess=observed object_compile_avoided=observed shadow_behavior=executed mmd_dep_parity=exact system_authority=closed path_swap=closed admission_lock=serialized unverified=durable coverage_record=last\n'
