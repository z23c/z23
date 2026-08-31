#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Executable regression for toolchain+flags-keyed compile epochs: the epoch
# namespace is STABLE across source edits (incremental rebuilds ride make's
# timestamp+depfile graph), moves on toolchain/flags/profile/build-system
# changes, and atomic candidate publication remains bound to the exact source
# record via the session stamp + publish-time verify-record.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
if ! cd "$ROOT"; then
    printf 'build-epoch-selftest: FAIL: cannot enter repository root\n' >&2
    exit 1
fi
KEY_TOOL="$SELF_DIR/build-epoch-key.sh"
PUBLISH_TOOL="$SELF_DIR/publish-build-alias.sh"
OBJECT_TOOL="$SELF_DIR/compile-epoch-object.sh"
SESSION_TOOL="$SELF_DIR/build-epoch-session.sh"
IDENTITY_TOOL="$SELF_DIR/build-epoch-open-file-identity.sh"
CC_COMMAND="${CC:-cc}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-build-epoch-selftest.XXXXXX")"
# Darwin exposes /var as a compatibility symlink to /private/var.  Exercise
# the production no-symlink path contract through the physical temp path.
WORK="$(cd "$WORK" && pwd -P)"
CHILD_PIDS=()

cleanup()
{
    local pid
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${CHILD_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

PROFILE=fixture-v1
COMPILE_FLAGS='-std=c23 -O2 -Wall'
LINK_FLAGS='-pthread -Wl,-z,now'

fail()
{
    printf 'build-epoch-selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

sha_label()
{
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

epoch_key()
{
    "$KEY_TOOL" key "$1" "$2" "$3" "$4" "$5"
}

build_candidate()
{
    local epoch="$1" payload="$2" source candidate
    local temporary
    source="$WORK/fixture-$epoch.c"
    candidate="$WORK/candidates/epochs/$epoch/fixture"
    mkdir -p "$(dirname "$candidate")" "$WORK/objects/epochs/$epoch"
    printf '#include <stdio.h>\nint main(void) { puts("%s"); return 0; }\n' \
        "$payload" > "$source"
    temporary="$(mktemp "$WORK/objects/epochs/$epoch/fixture.XXXXXX")"
    # The fixture intentionally uses the same compiler command fingerprinted
    # by the key tool.  Whitespace-only CC wrappers match Make's CC contract.
    read -r -a cc_argv <<< "$CC_COMMAND"
    "${cc_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror \
        -o "$temporary" "$source"
    mv -f -- "$temporary" "$candidate"
    printf '%s\n' "$candidate"
}

[ -x "$KEY_TOOL" ] || fail 'key tool is not executable'
[ -x "$PUBLISH_TOOL" ] || fail 'publisher is not executable'
[ -x "$OBJECT_TOOL" ] || fail 'object compiler is not executable'
[ -x "$SESSION_TOOL" ] || fail 'session tool is not executable'
[ -f "$IDENTITY_TOOL" ] || fail 'open-file identity helper is missing'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

source "$IDENTITY_TOOL"
z23_build_epoch_identity_values_match 0x10 00042 16 42 ||
    fail 'equivalent device/inode values did not match'
if z23_build_epoch_identity_values_match 0x10 42 17 42; then
    fail 'same inode on a different device was accepted'
fi
if z23_build_epoch_identity_values_match 0x10 42 16 43; then
    fail 'different inode on the same device was accepted'
fi
if z23_build_epoch_identity_values_match invalid 42 16 42 ||
   z23_build_epoch_identity_values_match 0x10 invalid 16 42 ||
   z23_build_epoch_identity_values_match 0x10 42 invalid 42; then
    fail 'malformed device/inode values were accepted'
fi
IDENTITY_PATH="$WORK/open-file-identity"
IDENTITY_OLD="$WORK/open-file-identity.old"
printf '%s\n' original > "$IDENTITY_PATH"
exec 9< "$IDENTITY_PATH"
HOST_SYSTEM="$(uname -s 2>/dev/null || printf unknown)"
z23_build_epoch_open_fd_matches_path "$IDENTITY_PATH" 9 "$HOST_SYSTEM" ||
    fail 'opened file did not match its path'
mv -- "$IDENTITY_PATH" "$IDENTITY_OLD"
printf '%s\n' replacement > "$IDENTITY_PATH"
if z23_build_epoch_open_fd_matches_path "$IDENTITY_PATH" 9 "$HOST_SYSTEM"; then
    fail 'renamed and replaced path matched the old descriptor'
fi
exec 9<&-

COMPILER_ID="$($KEY_TOOL compiler-id "$CC_COMMAND" "$CC_COMMAND")" ||
    fail 'compiler fingerprint failed'
[[ "$COMPILER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid compiler fingerprint'

mkdir -p "$WORK/env-include"
printf '#define EPOCH_ENV_PROBE 1\n' > "$WORK/env-include/probe.h"
ENV_COMPILER_ID="$(CPATH="$WORK/env-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")"
[ "$ENV_COMPILER_ID" != "$COMPILER_ID" ] ||
    fail 'CPATH was omitted from compiler fingerprint'
printf '#define EPOCH_ENV_PROBE 2\n' > "$WORK/env-include/probe.h"
ENV_MUTATED_COMPILER_ID="$(CPATH="$WORK/env-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")"
[ "$ENV_MUTATED_COMPILER_ID" != "$ENV_COMPILER_ID" ] ||
    fail 'compiler include-root mutation was omitted from fingerprint'

# -MMD excludes a header found through C_INCLUDE_PATH, so compiler-id is its
# sole rebuild authority. Prove both an ordinary edit and edit/revert ABA with
# the original bytes and mtime restored; ctime/inode inventory must still move.
mkdir -p "$WORK/system-include"
SYSTEM_HEADER="$WORK/system-include/probe.h"
SYSTEM_MTIME="$WORK/system-include/mtime.reference"
printf '#define EPOCH_SYSTEM_PROBE 1\n' > "$SYSTEM_HEADER"
touch -r "$SYSTEM_HEADER" "$SYSTEM_MTIME"
SYSTEM_COMPILER_ID="$(C_INCLUDE_PATH="$WORK/system-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")"
printf '#define EPOCH_SYSTEM_PROBE 2\n' > "$SYSTEM_HEADER"
SYSTEM_MUTATED_COMPILER_ID="$(C_INCLUDE_PATH="$WORK/system-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")"
[ "$SYSTEM_MUTATED_COMPILER_ID" != "$SYSTEM_COMPILER_ID" ] ||
    fail 'system include-root mutation was omitted from compiler fingerprint'
printf '#define EPOCH_SYSTEM_PROBE 1\n' > "$SYSTEM_HEADER"
touch -r "$SYSTEM_MTIME" "$SYSTEM_HEADER"
SYSTEM_REVERTED_COMPILER_ID="$(C_INCLUDE_PATH="$WORK/system-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")"
[ "$SYSTEM_REVERTED_COMPILER_ID" != "$SYSTEM_COMPILER_ID" ] ||
    fail 'system include-root edit/revert ABA was omitted from compiler fingerprint'
mkdir -p "$WORK/cyclic-include/nested"
printf '#define EPOCH_CYCLE_PROBE 1\n' > "$WORK/cyclic-include/probe.h"
ln -s .. "$WORK/cyclic-include/nested/parent"
CYCLIC_COMPILER_ID="$(CPATH="$WORK/cyclic-include" \
    "$KEY_TOOL" compiler-id "$CC_COMMAND" "$CC_COMMAND")" ||
    fail 'compiler fingerprint rejected a safely detected include-root cycle'
[[ "$CYCLIC_COMPILER_ID" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'cyclic include-root produced an invalid compiler fingerprint'
if "$KEY_TOOL" compiler-id 'cc; printf unsafe' "$CC_COMMAND" \
        >/dev/null 2>&1; then
    fail 'shell-active CC string was accepted'
fi

# Compile-only search roots and indirect tool loaders are not inputs to
# compiler-id's probes. Every joined and separate spelling must refuse before
# an epoch can be minted; ordinary project flags remain admitted.
FORBIDDEN_COMPILE_FLAGS=(
    '-isystem /tmp/include' '-isystem/tmp/include'
    '-idirafter /tmp/include' '-idirafter/tmp/include'
    '--sysroot /tmp/sdk' '--sysroot=/tmp/sdk'
    '-isysroot /tmp/sdk' '-isysroot/tmp/sdk'
    '-iframework /tmp/frameworks' '-iframework/tmp/frameworks'
    '-F /tmp/frameworks' '-F/tmp/frameworks'
    '-nostdinc' '-nostdinc++'
    '-iprefix /tmp/prefix' '-iwithprefix include'
    '-iwithprefixbefore include' '-B /tmp/programs'
    '-resource-dir=/tmp/resource' '--gcc-toolchain=/tmp/toolchain'
    '-specs=/tmp/specs' '--specs /tmp/specs'
    '-fplugin=/tmp/plugin.so' '-fpass-plugin=/tmp/pass.so'
    '-load=/tmp/plugin.so' '-plugin /tmp/plugin.so'
    '-wrapper=/tmp/wrapper' '-Xclang -load'
    '-Xpreprocessor -isystem' '-Xassembler /tmp/args'
    '-Wp,-isystem,/tmp/include' '-Wa,@/tmp/args' '@/tmp/flags'
    '-include-pch /tmp/header.pch' '-fmodule-file=/tmp/module.pcm'
    'normal=-isystem/tmp/include -O2'
)
for forbidden in "${FORBIDDEN_COMPILE_FLAGS[@]}"; do
    if "$KEY_TOOL" key "$COMPILER_ID" selftest \
            "-std=c23 $forbidden" no-link "$COMPILER_ID" \
            >/dev/null 2>&1; then
        fail "compile epoch accepted un-inventoried modifier: $forbidden"
    fi
done
"$KEY_TOOL" key "$COMPILER_ID" selftest \
    '-std=c23 -O2 -Ilib/base/include -include test/windows_compat.h' \
    no-link "$COMPILER_ID" >/dev/null ||
    fail 'compile epoch rejected ordinary tracked include flags'

# The build-system fingerprint is real (the checkout's own Makefile + epoch
# scripts); synthetic labels below prove it is bound into the key.
BSYS_REAL="$("$KEY_TOOL" build-system-id)" || fail 'build-system-id failed'
[[ "$BSYS_REAL" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid build-system fingerprint'
[ "$BSYS_REAL" = "$("$KEY_TOOL" build-system-id)" ] ||
    fail 'build-system fingerprint was not deterministic'

# Source/mutation labels remain the session/publish authority states. They
# deliberately play NO role in epoch selection anymore.
SOURCE_A="$(sha_label source-A)"
SOURCE_B="$(sha_label source-B)"
MUTATION_A1="$(sha_label mutation-A-session-1)"
MUTATION_B="$(sha_label mutation-B-session)"
MUTATION_A2="$(sha_label mutation-A-session-2)"

# One stable epoch for every source state under one toolchain+flags+build
# system; a second namespace exists only when the flags themselves differ.
EPOCH_MAIN="$(epoch_key "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$BSYS_REAL")"
EPOCH_ALT="$(epoch_key "$COMPILER_ID" "$PROFILE" '-std=c23 -O3 -Wall' "$LINK_FLAGS" "$BSYS_REAL")"
[ "$EPOCH_MAIN" = "$(epoch_key "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$BSYS_REAL")" ] ||
    fail 'identical compile record was not deterministic'
[ "$EPOCH_ALT" != "$EPOCH_MAIN" ] || fail 'compile flags were omitted from key'
PROFILE_EPOCH="$(epoch_key "$COMPILER_ID" fixture-v2 "$COMPILE_FLAGS" "$LINK_FLAGS" "$BSYS_REAL")"
[ "$PROFILE_EPOCH" != "$EPOCH_MAIN" ] || fail 'compile profile was omitted from key'
LINK_EPOCH="$(epoch_key "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" '-pthread -fuse-ld=lld' "$BSYS_REAL")"
[ "$LINK_EPOCH" != "$EPOCH_MAIN" ] || fail 'effective linker flags were omitted from key'
COMPILER_EPOCH="$(epoch_key "$(sha_label other-compiler)" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$BSYS_REAL")"
[ "$COMPILER_EPOCH" != "$EPOCH_MAIN" ] || fail 'compiler fingerprint was omitted from key'
BSYS_EPOCH="$(epoch_key "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$(sha_label other-build-system)")"
[ "$BSYS_EPOCH" != "$EPOCH_MAIN" ] ||
    fail 'build-system fingerprint was omitted from key (a Makefile flags edit would leave stale objects)'
if epoch_key "$COMPILER_ID" fixture-v1 '@compiler-response' links "$BSYS_REAL" \
        >/dev/null 2>&1; then
    fail 'unhashed compiler response file was accepted'
fi
if epoch_key "$COMPILER_ID" fixture-v1 flags links not-a-sha >/dev/null 2>&1; then
    fail 'non-SHA-256 build-system fingerprint was accepted'
fi
# The retired source-keyed derivation must stay rejected: its old argv shape
# (SOURCE COMPLETE MUTATION COMPILER PROFILE FLAGS LINKS) shifts a non-SHA
# token into the build-system slot and has to fail closed.
if "$KEY_TOOL" key "$SOURCE_A" 1 "$MUTATION_A1" "$COMPILER_ID" \
        fixture-v1 flags links >/dev/null 2>&1; then
    fail 'retired source-keyed epoch derivation was accepted'
fi

STABLE="$WORK/bin/fixture"
STATE="$WORK/source.state"
VERIFY="$WORK/verify-record.sh"

cat > "$VERIFY" <<'VERIFY_EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 4 ] && [ "$1" = verify-record ] || exit 2
if [ -n "${BLOCK_SOURCE:-}" ] && [ "$2" = "$BLOCK_SOURCE" ] &&
   [ "$4" = "${BLOCK_MUTATION:-}" ] && [ ! -e "${BLOCK_ONCE:-}" ]; then
    : > "$BLOCK_ONCE"
    : > "$BLOCK_MARKER"
    while [ ! -e "$BLOCK_RELEASE" ]; do sleep 0.01; done
fi
read -r actual_source actual_complete actual_mutation < "$STATE_FILE"
[ "$2" = "$actual_source" ] && [ "$3" = "$actual_complete" ] &&
    [ "$4" = "$actual_mutation" ]
VERIFY_EOF
chmod +x "$VERIFY"

set_state()
{
    printf '%s %s %s\n' "$1" 1 "$2" > "$STATE"
}

# Every Make invocation re-acquires its session (the lease is an order-only
# FORCE prerequisite), so the shared stable-epoch session stamp always names
# the CURRENT source record before any compile or publish under it.
SESSION_MAIN="$WORK/sessions/epochs/$EPOCH_MAIN/.build-session"
SESSION_EPOCH_ROOT="$WORK/sessions/epochs/$EPOCH_MAIN"
start_session()
{
    local source_id="$1" mutation="$2"
    local root="$WORK/sessions"
    local lease="$root/epochs/$EPOCH_MAIN/.leases/selftest-$$"
    set_state "$source_id" "$mutation"
    STATE_FILE="$STATE" "$SESSION_TOOL" acquire "$SESSION_MAIN" "$lease" \
        "$root" "$WORK/candidates" 5 "$source_id" 1 "$mutation" \
        "$COMPILER_ID" "$EPOCH_MAIN" "$PROFILE" "$COMPILE_FLAGS" \
        "$LINK_FLAGS" "$CC_COMMAND" "$CC_COMMAND" "$$" "$VERIFY" \
        >/dev/null
    [ -d "$WORK/candidates/epochs/$EPOCH_MAIN" ] ||
        fail 'session published a dangling candidate epoch pointer'
    [ "$(cat "$WORK/candidates/.current-epoch")" = "$EPOCH_MAIN" ] ||
        fail 'session candidate pointer does not name its generation'
    printf '%s\n' "$SESSION_MAIN"
}

finish_session()
{
    local source_id="$1" mutation="$2"
    local root="$WORK/sessions"
    local lease="$root/epochs/$EPOCH_MAIN/.leases/selftest-$$"
    set_state "$source_id" "$mutation"
    STATE_FILE="$STATE" "$SESSION_TOOL" verify "$SESSION_MAIN" "$lease" \
        "$root" "$WORK/candidates" 5 "$source_id" 1 "$mutation" \
        "$COMPILER_ID" "$EPOCH_MAIN" "$PROFILE" "$COMPILE_FLAGS" \
        "$LINK_FLAGS" "$CC_COMMAND" "$CC_COMMAND" "$$" "$VERIFY" \
        >/dev/null
}

compile_graph_object()
{
    local payload="$1" source_id="$2" mutation="$3"
    local source="$WORK/graph-$EPOCH_MAIN.c"
    local object="$SESSION_EPOCH_ROOT/graph/graph.o"
    local binary="$SESSION_EPOCH_ROOT/graph/graph"
    local -a cc_argv
    start_session "$source_id" "$mutation" >/dev/null
    mkdir -p "$(dirname "$object")"
    printf '#include <stdio.h>\nint main(void) { puts("%s"); return 0; }\n' \
        "$payload" > "$source"
    read -r -a cc_argv <<< "$CC_COMMAND"
    "$OBJECT_TOOL" dep "$object" "$source" \
        "$source_id" 1 "$mutation" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- \
        "${cc_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror
    "${cc_argv[@]}" -o "$binary" "$object"
    [ "$("$binary")" = "$payload" ] ||
        fail "epoch graph object did not execute payload $payload"
    [ -s "${object%.o}.d" ] || fail 'epoch graph dependency file is missing'
    finish_session "$source_id" "$mutation"
    printf '%s\n' "$object"
}

# The stable-epoch contract: sequential source states A -> B -> A all reuse
# ONE object namespace, and each recompile atomically replaces the object.
# This is the incremental-rebuild path the re-keying exists to enable.
GRAPH_A1="$(compile_graph_object A "$SOURCE_A" "$MUTATION_A1")"
GRAPH_B="$(compile_graph_object B "$SOURCE_B" "$MUTATION_B")"
GRAPH_A2="$(compile_graph_object A "$SOURCE_A" "$MUTATION_A2")"
[ "$GRAPH_A1" = "$GRAPH_B" ] && [ "$GRAPH_A1" = "$GRAPH_A2" ] ||
    fail 'stable epoch did not reuse one object namespace across source states'

# ...but a per-TU compile is still source-bound: the session stamp must name
# the exact source record the compile claims, or the object tool refuses.
start_session "$SOURCE_A" "$MUTATION_A2" >/dev/null
if "$OBJECT_TOOL" dep "$SESSION_EPOCH_ROOT/mismatch/mismatch.o" \
        "$WORK/graph-$EPOCH_MAIN.c" \
        "$SOURCE_B" 1 "$MUTATION_B" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- /bin/true >/dev/null 2>&1; then
    fail 'object compile accepted a session stamp from another source record'
fi

# Bash line reads discard embedded NUL bytes. A binary-tampered session must
# refuse before that normalization can turn a malformed field into a match.
printf '\0' >> "$SESSION_MAIN"
read -r -a cc_argv <<< "$CC_COMMAND"
if "$OBJECT_TOOL" dep "$SESSION_EPOCH_ROOT/nul-session/nul.o" \
        "$WORK/graph-$EPOCH_MAIN.c" \
        "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- \
        "${cc_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror \
        >/dev/null 2>&1; then
    fail 'object compile accepted a session stamp containing a NUL byte'
fi

# Two Make-like processes may schedule the same missing object before either
# publishes it.  Force one compiler to pause, let the other publish, then let
# the first finish.  Both .d and .o must remain complete atomic files.
CONCURRENT_SOURCE="$WORK/concurrent.c"
CONCURRENT_OBJECT="$SESSION_EPOCH_ROOT/concurrent/concurrent.o"
COMPILER_WRAPPER="$WORK/compiler-wrapper.sh"
mkdir -p "$(dirname "$CONCURRENT_OBJECT")"
printf '#include <stdio.h>\nint main(void) { puts("A"); return 0; }\n' \
    > "$CONCURRENT_SOURCE"
cat > "$COMPILER_WRAPPER" <<'COMPILER_EOF'
#!/usr/bin/env bash
set -euo pipefail
if mkdir "$COMPILER_BLOCK_ONCE" 2>/dev/null; then
    : > "$COMPILER_BLOCK_MARKER"
    while [ ! -e "$COMPILER_BLOCK_RELEASE" ]; do sleep 0.01; done
fi
read -r -a real_cc <<< "$REAL_CC_COMMAND"
exec "${real_cc[@]}" "$@"
COMPILER_EOF
chmod +x "$COMPILER_WRAPPER"
COMPILER_BLOCK_ONCE="$WORK/compiler-block-once"
COMPILER_BLOCK_MARKER="$WORK/compiler-blocked"
COMPILER_BLOCK_RELEASE="$WORK/compiler-release"
start_session "$SOURCE_A" "$MUTATION_A2" >/dev/null
    REAL_CC_COMMAND="$CC_COMMAND" \
    COMPILER_BLOCK_ONCE="$COMPILER_BLOCK_ONCE" \
    COMPILER_BLOCK_MARKER="$COMPILER_BLOCK_MARKER" \
    COMPILER_BLOCK_RELEASE="$COMPILER_BLOCK_RELEASE" \
    "$OBJECT_TOOL" dep "$CONCURRENT_OBJECT" "$CONCURRENT_SOURCE" \
        "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- \
        "$COMPILER_WRAPPER" -std=c23 -O2 -Wall -Wextra -Werror &
OBJECT_PID_1=$!
CHILD_PIDS+=("$OBJECT_PID_1")
# Wait for the wrapper to REACH its rendezvous, guarded by the child being
# alive — not by a 5s iteration budget. The old fixed 500-iteration poll gave
# a just-forked compiler wrapper 5 wall-clock seconds to get scheduled and
# create a file; on a loaded or slow-disk box that budget expires while the
# child is perfectly healthy and still starting, and the assertion below
# then reports a code defect that does not exist. Exhaustion is no longer a
# possible outcome: this loop ends when the marker appears (success) or when
# the child dies without it (a real defect, and load-independent). A child
# that neither writes nor dies is a genuine hang, and is caught by the
# runner-level progress watchdog in test_parallel.c, which reports it AS a
# hang instead of disguising it as a failed assertion.
while [ ! -e "$COMPILER_BLOCK_MARKER" ]; do
    kill -0 "$OBJECT_PID_1" 2>/dev/null || break
    sleep 0.01
done
[ -e "$COMPILER_BLOCK_MARKER" ] || fail 'first object compiler did not block'
REAL_CC_COMMAND="$CC_COMMAND" \
    COMPILER_BLOCK_ONCE="$COMPILER_BLOCK_ONCE" \
    COMPILER_BLOCK_MARKER="$COMPILER_BLOCK_MARKER" \
    COMPILER_BLOCK_RELEASE="$COMPILER_BLOCK_RELEASE" \
    "$OBJECT_TOOL" dep "$CONCURRENT_OBJECT" "$CONCURRENT_SOURCE" \
        "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- \
        "$COMPILER_WRAPPER" -std=c23 -O2 -Wall -Wextra -Werror &
OBJECT_PID_2=$!
CHILD_PIDS+=("$OBJECT_PID_2")
set +e
wait "$OBJECT_PID_2"
OBJECT_RC_2=$?
set -e
: > "$COMPILER_BLOCK_RELEASE"
set +e
wait "$OBJECT_PID_1"
OBJECT_RC_1=$?
set -e
[ "$OBJECT_RC_1" -eq 0 ] && [ "$OBJECT_RC_2" -eq 0 ] ||
    fail 'same-epoch concurrent object compile failed'
[ -s "$CONCURRENT_OBJECT" ] && [ -s "${CONCURRENT_OBJECT%.o}.d" ] ||
    fail 'same-epoch object/dependency publication was incomplete'
grep -Fq "$CONCURRENT_OBJECT:" "${CONCURRENT_OBJECT%.o}.d" ||
    fail 'dependency target does not name the final object'
if [ -n "$(find "$(dirname "$CONCURRENT_OBJECT")" -maxdepth 1 \
        -name '.concurrent.o.compile.*' -print -quit)" ]; then
    fail 'successful atomic object compile leaked staging directories'
fi
read -r -a cc_argv <<< "$CC_COMMAND"
"${cc_argv[@]}" -o "$WORK/concurrent-bin" "$CONCURRENT_OBJECT"
[ "$($WORK/concurrent-bin)" = A ] || fail 'concurrent object was corrupted'

# Compiler failure must not leak a same-directory staging tree that a later
# graph walk could mistake for a valid object input.
FAILED_OBJECT="$SESSION_EPOCH_ROOT/failure/failure.o"
mkdir -p "$(dirname "$FAILED_OBJECT")"
if "$OBJECT_TOOL" dep "$FAILED_OBJECT" "$CONCURRENT_SOURCE" \
        "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- /bin/false >/dev/null 2>&1; then
    fail 'failing compiler unexpectedly published an object'
fi
if [ -n "$(find "$(dirname "$FAILED_OBJECT")" -maxdepth 1 \
        -name '.failure.o.compile.*' -print -quit)" ]; then
    fail 'failing compiler leaked its staging directory'
fi

# Coverage cache hits require the separately retained .gcno. Delete it and
# prove the helper repairs the cache instead of accepting an unusable object.
COVERAGE_OBJECT="$SESSION_EPOCH_ROOT/coverage/coverage.o"
mkdir -p "$(dirname "$COVERAGE_OBJECT")"
"$OBJECT_TOOL" coverage "$COVERAGE_OBJECT" "$CONCURRENT_SOURCE" \
    "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
    "$SESSION_MAIN" -- "${cc_argv[@]}" --coverage -std=c23 -O0
read -r COVERAGE_NOTE < "${COVERAGE_OBJECT%.o}.gcno-path"
[ -s "$COVERAGE_NOTE" ] || fail 'coverage compile did not retain its .gcno'
rm -f "$COVERAGE_NOTE"
"$OBJECT_TOOL" coverage "$COVERAGE_OBJECT" "$CONCURRENT_SOURCE" \
    "$SOURCE_A" 1 "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" \
    "$SESSION_MAIN" -- "${cc_argv[@]}" --coverage -std=c23 -O0
read -r COVERAGE_NOTE_REPAIRED < "${COVERAGE_OBJECT%.o}.gcno-path"
[ -s "$COVERAGE_NOTE_REPAIRED" ] ||
    fail 'coverage cache did not repair its missing .gcno'
finish_session "$SOURCE_A" "$MUTATION_A2"

# Bounded GC removes dead epochs/candidates while preserving an epoch leased
# by a live Make-like owner, even when it lies outside the retention count.
GC_ROOT="$WORK/gc-objects"
GC_CANDIDATES="$WORK/gc-candidates"
GC_LIVE="$(sha_label gc-live)"
GC_DEAD_1="$(sha_label gc-dead-1)"
GC_DEAD_2="$(sha_label gc-dead-2)"
OWNER_START="$("$SELF_DIR/process-start-token.sh" "$$")"
for old in "$GC_LIVE" "$GC_DEAD_1" "$GC_DEAD_2"; do
    mkdir -p "$GC_ROOT/epochs/$old/.leases" "$GC_CANDIDATES/epochs/$old"
    : > "$GC_CANDIDATES/epochs/$old/candidate"
done
printf 'pid=%s\nstart=%s\n' "$$" "$OWNER_START" \
    > "$GC_ROOT/epochs/$GC_LIVE/.leases/live"
printf 'pid=99999999\nstart=1\n' \
    > "$GC_ROOT/epochs/$GC_DEAD_1/.leases/dead"
printf 'pid=99999998\nstart=1\n' \
    > "$GC_ROOT/epochs/$GC_DEAD_2/.leases/dead"
set_state "$SOURCE_A" "$MUTATION_A2"
STATE_FILE="$STATE" "$SESSION_TOOL" acquire \
    "$GC_ROOT/epochs/$EPOCH_MAIN/.build-session" \
    "$GC_ROOT/epochs/$EPOCH_MAIN/.leases/current" \
    "$GC_ROOT" "$GC_CANDIDATES" 1 "$SOURCE_A" 1 "$MUTATION_A2" \
    "$COMPILER_ID" "$EPOCH_MAIN" "$PROFILE" "$COMPILE_FLAGS" \
    "$LINK_FLAGS" "$CC_COMMAND" "$CC_COMMAND" "$$" "$VERIFY" >/dev/null
[ -d "$GC_ROOT/epochs/$GC_LIVE" ] &&
[ -d "$GC_CANDIDATES/epochs/$GC_LIVE" ] ||
    fail 'epoch GC removed a live leased epoch'
[ ! -e "$GC_ROOT/epochs/$GC_DEAD_1" ] &&
[ ! -e "$GC_ROOT/epochs/$GC_DEAD_2" ] &&
[ ! -e "$GC_CANDIDATES/epochs/$GC_DEAD_1" ] &&
[ ! -e "$GC_CANDIDATES/epochs/$GC_DEAD_2" ] ||
    fail 'epoch GC retained dead epochs beyond its bound'

# A writer can die after invalidating an epoch but before aggregate verify.
# The next acquire must discard every artifact and candidate from that epoch
# before it publishes a fresh session and lease for the same stable key.
QUARANTINE_ROOT="$WORK/quarantine-objects"
QUARANTINE_CANDIDATES="$WORK/quarantine-candidates"
QUARANTINE_EPOCH_DIR="$QUARANTINE_ROOT/epochs/$EPOCH_MAIN"
QUARANTINE_CANDIDATE_DIR="$QUARANTINE_CANDIDATES/epochs/$EPOCH_MAIN"
QUARANTINE_SESSION="$QUARANTINE_EPOCH_DIR/.build-session"
QUARANTINE_LEASE="$QUARANTINE_EPOCH_DIR/.leases/dead-writer"
mkdir -p "$QUARANTINE_EPOCH_DIR/.leases" "$QUARANTINE_CANDIDATE_DIR"
printf 'poisoned object\n' > "$QUARANTINE_EPOCH_DIR/poisoned.o"
printf 'stale candidate\n' > "$QUARANTINE_CANDIDATE_DIR/stale"
printf 'pid=99999997\nstart=1\n' > "$QUARANTINE_LEASE"
printf 'schema=zcl.build_epoch_unverified.v1\nsource_id=%s\nmutation=%s\ncompiler_id=%s\nepoch=%s\n' \
    "$SOURCE_A" "$MUTATION_A2" "$COMPILER_ID" "$EPOCH_MAIN" \
    > "$QUARANTINE_EPOCH_DIR/.unverified"
set_state "$SOURCE_A" "$MUTATION_A2"
STATE_FILE="$STATE" "$SESSION_TOOL" recover \
    "$QUARANTINE_SESSION" "$QUARANTINE_LEASE" \
    "$QUARANTINE_ROOT" "$QUARANTINE_CANDIDATES" 2 \
    "$SOURCE_A" 1 "$MUTATION_A2" "$COMPILER_ID" "$EPOCH_MAIN" \
    "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
    "$CC_COMMAND" "$$" "$VERIFY" >/dev/null
[ ! -e "$QUARANTINE_EPOCH_DIR/poisoned.o" ] &&
[ ! -e "$QUARANTINE_CANDIDATE_DIR/stale" ] &&
[ ! -e "$QUARANTINE_EPOCH_DIR/.unverified" ] ||
    fail 'dead unverified epoch artifacts were reused'
cmp -s "$QUARANTINE_SESSION" "$SESSION_MAIN" ||
    fail 'dead unverified epoch did not receive a fresh exact session'
[ -s "$QUARANTINE_LEASE" ] ||
    fail 'dead unverified epoch did not receive a fresh live lease'
[ -d "$QUARANTINE_CANDIDATE_DIR" ] ||
    fail 'dead unverified epoch candidate generation was not recreated'
[ -f "$QUARANTINE_ROOT/.epoch-admission/$EPOCH_MAIN.lock" ] &&
[ ! -e "$QUARANTINE_EPOCH_DIR/.admission.lock" ] &&
[ ! -e "$QUARANTINE_EPOCH_DIR/.admission.lock.d" ] ||
    fail 'epoch admission lock was not retained outside quarantine scope'
[ -z "$(find "$QUARANTINE_ROOT/.failed-epochs" -mindepth 1 -print -quit)" ] ||
    fail 'dead unverified epoch quarantine was not removed after recovery'

# Exercise the Make integration, not only the session helper.  The stale object
# is newer than its source, so Make initially classifies it as current.  The
# included recovery witness must acquire and quarantine before ordinary target
# update, restart parsing exactly once, and let the restarted graph rebuild the
# replacement object before the response-file link consumes it.
MAKE_RECOVERY="$WORK/make-recovery"
MAKE_RECOVERY_OBJ_ROOT="$MAKE_RECOVERY/objects"
MAKE_RECOVERY_EPOCH_DIR="$MAKE_RECOVERY_OBJ_ROOT/epochs/$EPOCH_MAIN"
MAKE_RECOVERY_OBJECT="$MAKE_RECOVERY_EPOCH_DIR/probe.o"
MAKE_RECOVERY_DEPFILE="${MAKE_RECOVERY_OBJECT%.o}.d"
MAKE_RECOVERY_SESSION="$MAKE_RECOVERY_EPOCH_DIR/.build-session"
MAKE_RECOVERY_LEASE="$MAKE_RECOVERY_EPOCH_DIR/.leases/make-recovery"
MAKE_RECOVERY_READY="$MAKE_RECOVERY/epoch-recovery-ready.mk"
MAKE_RECOVERY_SOURCE="$MAKE_RECOVERY/probe.c"
MAKE_RECOVERY_RSP="$MAKE_RECOVERY/link.rsp"
MAKE_RECOVERY_BINARY="$MAKE_RECOVERY/probe"
MAKE_RECOVERY_ACTIONS="$MAKE_RECOVERY/actions.log"
MAKE_RECOVERY_MK="$MAKE_RECOVERY/probe.mk"
MAKE_RECOVERY_VIEW_READY="$MAKE_RECOVERY/view-ready.mk"
MAKE_RECOVERY_RACE_ARM="$MAKE_RECOVERY/race-armed"
MAKE_RECOVERY_RACE_LOG="$MAKE_RECOVERY/race.log"
MAKE_RECOVERY_FIRST_LOG="$MAKE_RECOVERY/first.log"
MAKE_RECOVERY_WARM_LOG="$MAKE_RECOVERY/warm.log"
MAKE_SOURCE_RECORD="$("$ROOT/tools/dev/source-identity.sh" capture-record)" ||
    fail 'Make recovery fixture could not capture repository source identity'
read -r MAKE_SOURCE_ID MAKE_SOURCE_COMPLETE MAKE_SOURCE_MUTATION \
    <<< "$MAKE_SOURCE_RECORD"
[ "$MAKE_SOURCE_COMPLETE" = 1 ] ||
    fail 'Make recovery fixture source identity is incomplete'

mkdir -p "$MAKE_RECOVERY_EPOCH_DIR/.leases" \
    "$MAKE_RECOVERY/bin/test-fast/epochs/$EPOCH_MAIN"
printf 'int main(void) { return 0; }\n' > "$MAKE_RECOVERY_SOURCE"
printf 'stale object that must never reach the linker\n' > "$MAKE_RECOVERY_OBJECT"
printf '%s\n' "$MAKE_RECOVERY_OBJECT" > "$MAKE_RECOVERY_RSP"
printf '%s\n' '# fixture view inputs are already ready' \
    > "$MAKE_RECOVERY_VIEW_READY"

cat > "$MAKE_RECOVERY_MK" <<MAKE_RECOVERY_EOF
include $ROOT/Makefile

.PHONY: epoch-recovery-probe
epoch-recovery-probe: $MAKE_RECOVERY_BINARY
	@printf 'epoch-recovery-probe: restarts=%s\n' '\$(if \$(strip \$(MAKE_RESTARTS)),\$(MAKE_RESTARTS),0)'

\$(TEST_FAST_LEASE): | $MAKE_RECOVERY_RACE_ARM

$MAKE_RECOVERY_RACE_ARM:
	@printf 'pid=99999996\nstart=1\n' > '$MAKE_RECOVERY_LEASE'
	@printf 'schema=zcl.build_epoch_unverified.v1\nsource_id=%s\nmutation=%s\ncompiler_id=%s\nepoch=%s\n' \
	  '$MAKE_SOURCE_ID' '$MAKE_SOURCE_MUTATION' '$COMPILER_ID' '$EPOCH_MAIN' \
	  > '$MAKE_RECOVERY_EPOCH_DIR/.unverified'
	@: > '$MAKE_RECOVERY_RACE_ARM'

$MAKE_RECOVERY_OBJECT: $MAKE_RECOVERY_SOURCE | \$(TEST_FAST_LEASE)
	@printf '%s\n' compile >> '$MAKE_RECOVERY_ACTIONS'
	@\$(BUILD_EPOCH_OBJECT_TOOL) dep '\$@' '\$<' \
	  '\$(BUILD_SOURCE_ID)' '\$(BUILD_CLEAN)' '\$(BUILD_MUTATION)' \
	  '\$(TEST_FAST_COMPILE_EPOCH)' '\$(BUILD_COMPILER_ID)' \
	  '\$(TEST_FAST_SESSION)' -- \
	  \$(CC) -std=c23 -O0 -Wall -Wextra -Werror

$MAKE_RECOVERY_BINARY: $MAKE_RECOVERY_OBJECT $MAKE_RECOVERY_RSP
	@printf '%s\n' link >> '$MAKE_RECOVERY_ACTIONS'
	@\$(CC) -o '\$@' '@$MAKE_RECOVERY_RSP'
	@\$(BUILD_EPOCH_SESSION_TOOL) verify \
	  '\$(TEST_FAST_SESSION)' '\$(TEST_FAST_LEASE)' \
	  '\$(TEST_FAST_OBJ_ROOT)' '\$(BIN_DIR)/test-fast' \
	  '\$(BUILD_EPOCH_KEEP)' '\$(BUILD_SOURCE_ID)' \
	  '\$(BUILD_CLEAN)' '\$(BUILD_MUTATION)' '\$(BUILD_COMPILER_ID)' \
	  '\$(TEST_FAST_COMPILE_EPOCH)' '\$(TEST_FAST_PROFILE)' \
	  '\$(TEST_FAST_EPOCH_COMPILE_FLAGS)' \
	  '\$(TEST_FAST_EPOCH_LINK_FLAGS)' '\$(CC)' '\$(CXX)' "\$\$PPID" \
	  >/dev/null
MAKE_RECOVERY_EOF

run_make_recovery()
{
    local log="$1"
    (
        cd "$ROOT"
        make -f "$MAKE_RECOVERY_MK" --no-print-directory \
            ZCL_EPOCH_PROFILES=test-fast ZCL_DEPFILE_PROFILES= \
            BUILD_DIR="$MAKE_RECOVERY" BIN_DIR="$MAKE_RECOVERY/bin" \
            VIEW_GEN_HEADERS_EARLY= VIEW_GEN_HEADERS= \
            VIEW_BOOTSTRAP_MK="$MAKE_RECOVERY_VIEW_READY" \
            BUILD_SOURCE_RECORD="$MAKE_SOURCE_RECORD" \
            BUILD_COMPILER_ID="$COMPILER_ID" BUILD_SYSTEM_ID="$BSYS_REAL" \
            TEST_FAST_OBJ_ROOT="$MAKE_RECOVERY_OBJ_ROOT" \
            TEST_FAST_OBJ_DIR="$MAKE_RECOVERY_EPOCH_DIR" \
            TEST_FAST_COMPILE_EPOCH="$EPOCH_MAIN" \
            TEST_FAST_PROFILE="$PROFILE" \
            TEST_FAST_EPOCH_COMPILE_FLAGS="$COMPILE_FLAGS" \
            TEST_FAST_EPOCH_LINK_FLAGS="$LINK_FLAGS" \
            TEST_FAST_SESSION="$MAKE_RECOVERY_SESSION" \
            TEST_FAST_LEASE="$MAKE_RECOVERY_LEASE" \
            BUILD_EPOCH_RECOVERY_READY="$MAKE_RECOVERY_READY" \
            CC="$CC_COMMAND" CXX="$CC_COMMAND" epoch-recovery-probe
    ) > "$log" 2>&1
}

if run_make_recovery "$MAKE_RECOVERY_RACE_LOG"; then
    fail 'post-parse unverified marker unexpectedly reached the linker'
fi
grep -Fq 'unverified compile epoch appeared after recovery admission; rerun make' \
    "$MAKE_RECOVERY_RACE_LOG" ||
    fail 'post-parse unverified marker did not produce the named retry refusal'
grep -Fq 'stale object that must never reach the linker' \
    "$MAKE_RECOVERY_OBJECT" ||
    fail 'ordinary acquire changed a generation after Make classified it'
[ -f "$MAKE_RECOVERY_EPOCH_DIR/.unverified" ] &&
[ -f "$MAKE_RECOVERY_LEASE" ] ||
    fail 'ordinary acquire discarded the late recovery evidence'
[ ! -e "$MAKE_RECOVERY_READY" ] &&
[ ! -s "$MAKE_RECOVERY_ACTIONS" ] ||
    fail 'late-marker refusal performed compile or link work'

run_make_recovery "$MAKE_RECOVERY_FIRST_LOG" || {
    sed 's/^/build-epoch-selftest: make recovery: /' \
        "$MAKE_RECOVERY_FIRST_LOG" >&2
    fail 'Make recovery fixture failed after the named retry'
}
grep -Fqx 'epoch-recovery-probe: restarts=1' "$MAKE_RECOVERY_FIRST_LOG" ||
    fail 'stale epoch did not cause exactly one Make parse restart'
[ "$(grep -Fc 'build-epoch-session: acquired' "$MAKE_RECOVERY_FIRST_LOG")" -eq 1 ] ||
    fail 'restarted Make acquired the recovery lease more than once'
[ -s "$MAKE_RECOVERY_OBJECT" ] && [ -s "$MAKE_RECOVERY_DEPFILE" ] &&
[ -x "$MAKE_RECOVERY_BINARY" ] ||
    fail 'restarted Make did not publish the replacement object and consumer'
"$MAKE_RECOVERY_BINARY" || fail 'response-file consumer did not link the replacement object'
[ ! -e "$MAKE_RECOVERY_EPOCH_DIR/.unverified" ] ||
    fail 'Make recovery did not admit the completed replacement generation'
[ "$(wc -l < "$MAKE_RECOVERY_ACTIONS")" -eq 2 ] ||
    fail 'Make recovery did not compile and link exactly once'

artifact_stamp()
{
    stat -Lc '%d:%i:%s:%Y:%Z:%y:%z' "$1" 2>/dev/null ||
        stat -f '%d:%i:%z:%m:%c' "$1"
}
MAKE_RECOVERY_ARTIFACTS=(
    "$MAKE_RECOVERY_OBJECT" "$MAKE_RECOVERY_DEPFILE"
    "$MAKE_RECOVERY_RSP" "$MAKE_RECOVERY_BINARY" "$MAKE_RECOVERY_READY"
)
MAKE_RECOVERY_BEFORE=()
for artifact in "${MAKE_RECOVERY_ARTIFACTS[@]}"; do
    MAKE_RECOVERY_BEFORE+=("$(artifact_stamp "$artifact")")
done

run_make_recovery "$MAKE_RECOVERY_WARM_LOG" || {
    sed 's/^/build-epoch-selftest: warm recovery: /' \
        "$MAKE_RECOVERY_WARM_LOG" >&2
    fail 'marker-free warm Make recovery fixture failed'
}
grep -Fqx 'epoch-recovery-probe: restarts=0' "$MAKE_RECOVERY_WARM_LOG" ||
    fail 'marker-free warm Make unexpectedly restarted'
[ "$(grep -Fc 'build-epoch-session: acquired' "$MAKE_RECOVERY_WARM_LOG")" -eq 1 ] ||
    fail 'marker-free warm Make did not acquire exactly one ordinary lease'
[ "$(wc -l < "$MAKE_RECOVERY_ACTIONS")" -eq 2 ] ||
    fail 'marker-free warm Make recompiled or relinked'
for index in "${!MAKE_RECOVERY_ARTIFACTS[@]}"; do
    [ "$(artifact_stamp "${MAKE_RECOVERY_ARTIFACTS[$index]}")" = \
      "${MAKE_RECOVERY_BEFORE[$index]}" ] ||
        fail "marker-free warm Make rewrote ${MAKE_RECOVERY_ARTIFACTS[$index]}"
done

expect_generation_symlink_refused()
{
    local surface="$1" base object_root candidate_root outside session lease log
    base="$WORK/symlinked-$surface-generation"
    object_root="$base/objects"
    candidate_root="$base/candidates"
    outside="$base/outside"
    session="$object_root/epochs/$EPOCH_MAIN/.build-session"
    lease="$object_root/epochs/$EPOCH_MAIN/.leases/selftest"
    log="$base/session.log"
    mkdir -p "$object_root/epochs" "$candidate_root/epochs" "$outside"
    case "$surface" in
        object) ln -s "$outside" "$object_root/epochs/$EPOCH_MAIN" ;;
        candidate) ln -s "$outside" "$candidate_root/epochs/$EPOCH_MAIN" ;;
        *) fail "unknown symlinked generation surface $surface" ;;
    esac
    set_state "$SOURCE_A" "$MUTATION_A2"
    if STATE_FILE="$STATE" "$SESSION_TOOL" acquire \
        "$session" "$lease" "$object_root" "$candidate_root" 2 \
        "$SOURCE_A" 1 "$MUTATION_A2" "$COMPILER_ID" "$EPOCH_MAIN" \
        "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
        "$CC_COMMAND" "$$" "$VERIFY" >"$log" 2>&1; then
        fail "symlinked $surface epoch generation was accepted"
    fi
    grep -Fq "$surface epoch generation is not a regular directory" "$log" ||
        fail "symlinked $surface epoch generation did not fail closed"
    [ -z "$(find "$outside" -mindepth 1 -print -quit)" ] ||
        fail "symlinked $surface epoch generation received build state"
    [ ! -e "$object_root/.current-epoch" ] &&
    [ ! -e "$candidate_root/.current-epoch" ] ||
        fail "symlinked $surface epoch generation was published"
}

expect_generation_symlink_refused object
expect_generation_symlink_refused candidate

expect_verify_root_symlink_refused()
{
    local base object_root outside session lease log
    base="$WORK/symlinked-verify-root"
    object_root="$base/objects"
    outside="$base/outside"
    session="$object_root/epochs/$EPOCH_MAIN/.build-session"
    lease="$object_root/epochs/$EPOCH_MAIN/.leases/selftest"
    log="$base/session.log"
    mkdir -p "$outside/epochs/$EPOCH_MAIN"
    ln -s "$outside" "$object_root"
    if STATE_FILE="$STATE" "$SESSION_TOOL" verify \
        "$session" "$lease" "$object_root" - 2 \
        "$SOURCE_A" 1 "$MUTATION_A2" "$COMPILER_ID" "$EPOCH_MAIN" \
        "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
        "$CC_COMMAND" "$$" "$VERIFY" >"$log" 2>&1; then
        fail 'symlinked verify object root was accepted'
    fi
    grep -Fq 'object root is not a regular directory' "$log" ||
        fail 'symlinked verify object root did not fail closed'
    [ ! -e "$outside/.epoch-admission" ] &&
    [ ! -e "$outside/epochs/$EPOCH_MAIN/.build-session" ] &&
    [ ! -e "$outside/epochs/$EPOCH_MAIN/.leases" ] ||
        fail 'symlinked verify object root received build state'
}

expect_verify_root_symlink_refused

publish()
{
    STATE_FILE="$STATE" "$PUBLISH_TOOL" "$1" "$STABLE" "$5" "$2" 1 "$3" "$4" \
        "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" \
        "$CC_COMMAND" "$CC_COMMAND" "$VERIFY" \
        >/dev/null
}

# Publish across source states A -> B -> A inside the ONE stable epoch. Each
# transition re-acquires the session and rebuilds the candidate, exactly as a
# Make invocation refreshes its lease and relinks before publishing.
SESSION_MAIN="$(start_session "$SOURCE_A" "$MUTATION_A1")"
CANDIDATE_A1="$(build_candidate "$EPOCH_MAIN" A)"
publish "$CANDIDATE_A1" "$SOURCE_A" "$MUTATION_A1" "$EPOCH_MAIN" "$SESSION_MAIN"
[ "$($STABLE)" = A ] || fail 'A candidate was not published'
SESSION_MAIN="$(start_session "$SOURCE_B" "$MUTATION_B")"
CANDIDATE_B="$(build_candidate "$EPOCH_MAIN" B)"
publish "$CANDIDATE_B" "$SOURCE_B" "$MUTATION_B" "$EPOCH_MAIN" "$SESSION_MAIN"
[ "$($STABLE)" = B ] || fail 'B candidate was not published'
SESSION_MAIN="$(start_session "$SOURCE_A" "$MUTATION_A2")"
CANDIDATE_A2="$(build_candidate "$EPOCH_MAIN" A)"
publish "$CANDIDATE_A2" "$SOURCE_A" "$MUTATION_A2" "$EPOCH_MAIN" "$SESSION_MAIN"
[ "$($STABLE)" = A ] || fail 'restored A candidate was not published'

# Deterministically hold a stale A publisher inside the alias lock, advance
# the source record to B (with B's session re-acquire and candidate relink,
# as a real B Make invocation would do), and start B behind it.  A must fail
# its source check and B must be the only process allowed to publish.
BLOCK_MARKER="$WORK/stale-a-blocked"
BLOCK_RELEASE="$WORK/release-stale-a"
BLOCK_ONCE="$WORK/stale-a-blocked-once"
STALE_LOG="$WORK/stale-a-publisher.log"
STATE_FILE="$STATE" BLOCK_SOURCE="$SOURCE_A" \
    BLOCK_MUTATION="$MUTATION_A2" BLOCK_MARKER="$BLOCK_MARKER" \
    BLOCK_RELEASE="$BLOCK_RELEASE" BLOCK_ONCE="$BLOCK_ONCE" \
    "$PUBLISH_TOOL" "$CANDIDATE_A2" "$STABLE" "$SESSION_MAIN" "$SOURCE_A" 1 \
        "$MUTATION_A2" "$EPOCH_MAIN" "$COMPILER_ID" "$PROFILE" \
        "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" "$CC_COMMAND" \
        "$VERIFY" > /dev/null 2> "$STALE_LOG" &
STALE_PID=$!
CHILD_PIDS+=("$STALE_PID")

# Same liveness-guarded wait as the compiler rendezvous above: ends on the
# marker or on the child dying, never on a wall-clock budget.
while [ ! -e "$BLOCK_MARKER" ]; do
    kill -0 "$STALE_PID" 2>/dev/null || break
    sleep 0.01
done
if [ ! -e "$BLOCK_MARKER" ]; then
    sed 's/^/build-epoch-selftest: stale publisher: /' "$STALE_LOG" >&2
    fail 'stale publisher did not enter the locked verifier'
fi

(
    SESSION_B="$(start_session "$SOURCE_B" "$MUTATION_B")"
    CANDIDATE_B2="$(build_candidate "$EPOCH_MAIN" B)"
    STATE_FILE="$STATE" "$PUBLISH_TOOL" "$CANDIDATE_B2" "$STABLE" \
        "$SESSION_B" "$SOURCE_B" 1 "$MUTATION_B" "$EPOCH_MAIN" \
        "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" \
        "$CC_COMMAND" "$CC_COMMAND" "$VERIFY" >/dev/null
) &
CURRENT_PID=$!
CHILD_PIDS+=("$CURRENT_PID")
# The new source state is written before B waits on A's admission lock. Wait
# for that transition so releasing A deterministically makes its exact source
# verification fail rather than racing the background scheduler.
while :; do
    read -r state_source _ < "$STATE"
    [ "$state_source" = "$SOURCE_B" ] && break
    kill -0 "$CURRENT_PID" 2>/dev/null ||
        fail 'current B publisher died before advancing source state'
    sleep 0.01
done
: > "$BLOCK_RELEASE"

set +e
wait "$STALE_PID"
STALE_RC=$?
wait "$CURRENT_PID"
CURRENT_RC=$?
set -e
[ "$STALE_RC" -ne 0 ] || fail 'stale A publisher succeeded after B became current'
[ "$CURRENT_RC" -eq 0 ] || fail 'current B publisher failed behind stale A'
[ "$($STABLE)" = B ] || fail 'stale A overwrote the current B alias'

printf 'build-epoch-selftest: PASS toolchain_keyed=true stable_namespace=true source_bound_publish=true concurrent_publish=true late_marker_refusal=true make_recovery=true warm_no_rewrite=true compiler_id=%s\n' \
    "$COMPILER_ID"
