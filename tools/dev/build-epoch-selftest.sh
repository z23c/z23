#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Executable regression for toolchain+flags-keyed compile epochs: the epoch
# namespace is STABLE across source edits (incremental rebuilds ride make's
# timestamp+depfile graph), moves on toolchain/flags/profile/build-system
# changes, and atomic candidate publication remains bound to the exact source
# record via the session stamp + publish-time verify-record.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_TOOL="$SELF_DIR/build-epoch-key.sh"
PUBLISH_TOOL="$SELF_DIR/publish-build-alias.sh"
OBJECT_TOOL="$SELF_DIR/compile-epoch-object.sh"
SESSION_TOOL="$SELF_DIR/build-epoch-session.sh"
CC_COMMAND="${CC:-cc}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-build-epoch-selftest.XXXXXX")"
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
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

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

compile_graph_object()
{
    local payload="$1" source_id="$2" mutation="$3"
    local source="$WORK/graph-$EPOCH_MAIN.c"
    local object="$WORK/graph/epochs/$EPOCH_MAIN/graph.o"
    local binary="$WORK/graph/epochs/$EPOCH_MAIN/graph"
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
if "$OBJECT_TOOL" dep "$WORK/mismatch/epochs/$EPOCH_MAIN/mismatch.o" \
        "$WORK/graph-$EPOCH_MAIN.c" \
        "$SOURCE_B" 1 "$MUTATION_B" "$EPOCH_MAIN" "$COMPILER_ID" \
        "$SESSION_MAIN" -- /bin/true >/dev/null 2>&1; then
    fail 'object compile accepted a session stamp from another source record'
fi

# Two Make-like processes may schedule the same missing object before either
# publishes it.  Force one compiler to pause, let the other publish, then let
# the first finish.  Both .d and .o must remain complete atomic files.
CONCURRENT_SOURCE="$WORK/concurrent.c"
CONCURRENT_OBJECT="$WORK/concurrent/epochs/$EPOCH_MAIN/concurrent.o"
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
FAILED_OBJECT="$WORK/failure/epochs/$EPOCH_MAIN/failure.o"
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
COVERAGE_OBJECT="$WORK/coverage/epochs/$EPOCH_MAIN/coverage.o"
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

SESSION_B="$(start_session "$SOURCE_B" "$MUTATION_B")"
CANDIDATE_B2="$(build_candidate "$EPOCH_MAIN" B)"
STATE_FILE="$STATE" "$PUBLISH_TOOL" "$CANDIDATE_B2" "$STABLE" \
    "$SESSION_B" "$SOURCE_B" 1 "$MUTATION_B" "$EPOCH_MAIN" \
    "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
    "$CC_COMMAND" "$VERIFY" >/dev/null &
CURRENT_PID=$!
CHILD_PIDS+=("$CURRENT_PID")
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

printf 'build-epoch-selftest: PASS toolchain_keyed=true stable_namespace=true source_bound_publish=true concurrent_publish=true compiler_id=%s\n' \
    "$COMPILER_ID"
