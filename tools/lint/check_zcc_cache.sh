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
    case "$argument" in -E|--version|-dump*) exec "$SF_CC" "$@" ;; esac
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
sf_compile follower & sf_follower=$!
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
sf_compile retry & sf_follower=$!
sf_waiting retry || exit 1
: > "$SF_STATE/release"
if wait "$sf_owner"; then fail 'failed compiler owner unexpectedly succeeded'; fi
sf_join "$sf_follower" recovery
[ "$(sf_count compile)" = 2 ] || fail 'failed owner did not release its compile claim'
[ -s "$SF_STATE/retry.o" ] || fail 'failed owner prevented successful follower output'

sf_case changed
sf_compile owner 1 0 1 & sf_owner=$!
sf_ready "$SF_STATE/held" || exit 1
sf_compile follower & sf_follower=$!
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
sf_compile follower & sf_follower=$!
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
