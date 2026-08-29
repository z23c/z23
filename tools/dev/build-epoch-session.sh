#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify one compile profile, acquire a live-Make lease, and prune old epochs.

set -euo pipefail

EXPECTED=""
tmp_session=""
tmp_lease=""
cleanup()
{
    [ -z "$EXPECTED" ] || rm -f -- "$EXPECTED"
    [ -z "$tmp_session" ] || rm -f -- "$tmp_session"
    [ -z "$tmp_lease" ] || rm -f -- "$tmp_lease"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail()
{
    printf 'build-epoch-session: %s\n' "$*" >&2
    exit 2
}

is_sha256()
{
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

[ "$#" -ge 17 ] && [ "$#" -le 18 ] ||
    fail 'usage: build-epoch-session.sh MODE SESSION LEASE OBJECT_ROOT CANDIDATE_ROOT KEEP SOURCE COMPLETE MUTATION COMPILER EPOCH PROFILE COMPILE_FLAGS LINK_FLAGS CC CXX OWNER_PID [VERIFY_TOOL]'

MODE="$1"
SESSION="$2"
LEASE="$3"
OBJECT_ROOT="$4"
CANDIDATE_ROOT="$5"
KEEP="$6"
SOURCE_ID="$7"
COMPLETE="$8"
MUTATION="$9"
COMPILER_ID="${10}"
EPOCH="${11}"
PROFILE="${12}"
COMPILE_FLAGS="${13}"
LINK_FLAGS="${14}"
CC_COMMAND="${15}"
CXX_COMMAND="${16}"
OWNER_PID="${17}"
VERIFY_TOOL="${18:-tools/dev/source-identity.sh}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_TOOL="$SELF_DIR/build-epoch-key.sh"

case "$MODE" in acquire|check|verify) ;; *) fail "unknown mode: $MODE" ;; esac

find_make_owner()
{
    local candidate comm parent owner="" depth=0
    candidate="$(process_parent "$$")"
    candidate="${candidate//[[:space:]]/}"
    while [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [ "$depth" -lt 16 ]; do
        comm="$(process_comm "$candidate")"
        comm="${comm##*/}"
        comm="${comm//[[:space:]]/}"
        case "$comm" in
        make|gmake) owner="$candidate" ;;
        esac
        parent="$(process_parent "$candidate")"
        parent="${parent//[[:space:]]/}"
        [ "$parent" != "$candidate" ] || break
        candidate="$parent"
        depth=$((depth + 1))
    done
    [ -n "$owner" ] || return 1
    printf '%s\n' "$owner"
}

process_parent()
{
    local pid="$1" ppid=""
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*)
            ppid=$(sed -n '1p' "/proc/$pid/ppid" 2>/dev/null)
            # MSYS/Cygwin /proc is sparse for orphan or init-parented
            # processes; fall back to the native ps listing.
            [ -n "$ppid" ] || ppid=$(ps -p "$pid" -f 2>/dev/null | awk 'NR==2 {print $3}')
            printf '%s\n' "$ppid"
            ;;
        *) ps -p "$pid" -o ppid= 2>/dev/null || true ;;
    esac
}

process_comm()
{
    local pid="$1" comm=""
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*)
            comm=$(sed -n 's/^Name:[[:space:]]*//p' "/proc/$pid/status" \
                2>/dev/null)
            [ -n "$comm" ] || comm=$(ps -p "$pid" -f 2>/dev/null | awk 'NR==2 {sub(/^[^ ]+[ ]+[0-9]+[ ]+[0-9]+[ ]+[^ ]+[ ]+[^ ]+[ ]+/, ""); print}')
            printf '%s\n' "$comm"
            ;;
        *) ps -p "$pid" -o comm= 2>/dev/null || true ;;
    esac
}

process_ancestry()
{
    local candidate comm parent depth=0 chain=""
    candidate="$(process_parent "$$")"
    candidate="${candidate//[[:space:]]/}"
    while [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [ "$depth" -lt 8 ]; do
        comm="$(process_comm "$candidate")"
        comm="${comm##*/}"
        comm="${comm//[[:space:]]/}"
        chain="${chain:+$chain,}${candidate}:${comm:-unknown}"
        parent="$(process_parent "$candidate")"
        parent="${parent//[[:space:]]/}"
        [ "$parent" != "$candidate" ] || break
        candidate="$parent"
        depth=$((depth + 1))
    done
    printf '%s\n' "${chain:-unavailable}"
}

# A PID captured by a parse-time $(shell ...) can name a short-lived helper on
# Darwin. Resolve the live Make ancestor while this recipe is executing. The
# explicit PID remains a fallback for direct self-tests that do not run below
# Make.
resolved_owner="$(find_make_owner || true)"
if [ -n "$resolved_owner" ]; then
    OWNER_PID="$resolved_owner"
elif "$SELF_DIR/process-start-token.sh" "$OWNER_PID" >/dev/null 2>&1; then
    :
# Some execution environments (headless MSYS2/Git Bash launched by a service
# wrapper) orphan every shell so the Make ancestor is not visible through
# /proc.  In that case the current recipe shell is still a live child of Make
# and is a safe-enough owner token for this build.
elif "$SELF_DIR/process-start-token.sh" "$$" >/dev/null 2>&1; then
    OWNER_PID="$$"
elif [ "$MODE" != acquire ]; then
    OWNER_PID="$$"
else
    fail "could not identify live Make owner process; ancestry=$(process_ancestry)"
fi

for value in "$SOURCE_ID" "$MUTATION" "$COMPILER_ID" "$EPOCH"; do
    is_sha256 "$value" || fail 'authority field is not lowercase SHA-256'
done
[ "$COMPLETE" = 1 ] || fail 'source capture is incomplete'
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || fail 'epoch retention must be positive'
[[ "$OWNER_PID" =~ ^[1-9][0-9]*$ ]] || fail 'owner pid must be positive'
[ -n "$PROFILE" ] || fail 'profile is empty'
[ -x "$KEY_TOOL" ] && [ -x "$VERIFY_TOOL" ] || fail 'authority helper is unavailable'
case "$SESSION" in "$OBJECT_ROOT"/epochs/"$EPOCH"/*) ;; *) fail 'session path is outside epoch' ;; esac
case "$LEASE" in "$OBJECT_ROOT"/epochs/"$EPOCH"/.leases/*) ;; *) fail 'lease path is outside epoch' ;; esac

FLAGS_SHA="$(printf '%s\0%s' "$COMPILE_FLAGS" "$LINK_FLAGS" | sha256sum | awk '{print $1}')"
EXPECTED="$(mktemp "${TMPDIR:-/tmp}/zcl-build-session.expected.XXXXXX")"
printf '%s\n' \
    'schema=zcl.build_epoch_session.v1' \
    "source_id=$SOURCE_ID" \
    "complete=$COMPLETE" \
    "mutation=$MUTATION" \
    "compiler_id=$COMPILER_ID" \
    "epoch=$EPOCH" \
    "profile=$PROFILE" \
    "flags_sha256=$FLAGS_SHA" > "$EXPECTED"

check_stamp()
{
    [ -f "$SESSION" ] && cmp -s "$EXPECTED" "$SESSION" ||
        fail 'compile-session stamp does not match the requested epoch'
}

verify_authority()
{
    local actual_compiler actual_epoch actual_build_system
    actual_compiler="$("$KEY_TOOL" compiler-id "$CC_COMMAND" "$CXX_COMMAND")" ||
        fail 'compiler fingerprint revalidation failed'
    [ "$actual_compiler" = "$COMPILER_ID" ] ||
        fail "compiler/toolchain changed during build expected=$COMPILER_ID actual=$actual_compiler"
    actual_build_system="$("$KEY_TOOL" build-system-id)" ||
        fail 'build-system fingerprint revalidation failed'
    actual_epoch="$("$KEY_TOOL" key \
        "$COMPILER_ID" "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" \
        "$actual_build_system")" ||
        fail 'compile epoch recomputation failed'
    [ "$actual_epoch" = "$EPOCH" ] || fail 'profile/flags do not derive the requested epoch'
    "$VERIFY_TOOL" verify-record "$SOURCE_ID" "$COMPLETE" "$MUTATION" >/dev/null
}

if [ "$MODE" = check ]; then
    check_stamp
    exit 0
fi

# Every acquire/verify call re-derives and re-checks the full authority
# (compiler fingerprint + compile epoch + source record) via verify_authority
# below -- that check itself is unchanged. What we skip is redundant *work*:
# OWNER_PID identifies the one live Make process driving this whole
# invocation, and tools/dev/source-identity.sh capture-record/verify-record is
# a full git-ls-files+find+sha256 walk of every build input. A single `make
# build-only`/`make t-fast` calls into this script's acquire/verify path
# several times per invocation even with zero source changes, so hand the
# VERIFY_TOOL call inside verify_authority a session token (this pid + its
# /proc start-time, computed once, here, before the first of those calls) so
# it can reuse whichever call in this same session already paid for the walk
# instead of repeating it. A pid gets reused eventually; the start-time half
# of the token means a dead process's cache entry never matches a new one.
OWNER_START="$("$SELF_DIR/process-start-token.sh" "$OWNER_PID" 2>/dev/null)" ||
    fail "could not identify live Make owner pid=$OWNER_PID; ancestry=$(process_ancestry)"
[[ "$OWNER_START" =~ ^[0-9a-f]+$ ]] || fail 'invalid Make owner start time'
export ZCL_SOURCE_IDENTITY_SESSION="$OWNER_PID:$OWNER_START"

verify_authority
[ "$MODE" = verify ] && { check_stamp; exit 0; }

command -v flock >/dev/null 2>&1 || fail 'flock is required for epoch leases'

mkdir -p "$OBJECT_ROOT/epochs/$EPOCH/.leases"
exec 9> "$OBJECT_ROOT/.epoch-gc.lock"
flock -x 9

tmp_session="$(mktemp "$(dirname "$SESSION")/.build-session.XXXXXX")"
cp -- "$EXPECTED" "$tmp_session"
mv -f -- "$tmp_session" "$SESSION"
tmp_session=""
tmp_lease="$(mktemp "$(dirname "$LEASE")/.lease.XXXXXX")"
printf 'pid=%s\nstart=%s\n' "$OWNER_PID" "$OWNER_START" > "$tmp_lease"
mv -f -- "$tmp_lease" "$LEASE"
tmp_lease=""

# Name the epoch this build compiles into, at the root of the generation
# directory, while still holding the lock that mints it.  Every profile reaches
# a compiler only through this acquire, so a compile cannot land in an epoch
# this file does not name, and the file cannot name an epoch no build claimed.
# The retained generations beside it are receipts of trees that are no longer
# checked out; a reader that wants the live build inputs -- the code index's
# include graph, above all -- reads this one name instead of guessing from
# mtimes or scanning every generation.
publish_current_epoch()
{
    local root="$1" tmp
    [ -n "$root" ] && [ "$root" != - ] || return 0
    # The pointer and the generation directory are one atomic claim from a
    # reader's perspective: never publish a name that codeindex (or another
    # concurrent observer) can resolve only to ENOENT. The candidate may not
    # contain its linked executable yet, but its immutable generation exists
    # before it is named and the later link publishes within that directory.
    mkdir -p "$root/epochs/$EPOCH"
    tmp="$(mktemp "$root/.current-epoch.XXXXXX")" ||
        fail "could not stage the current-epoch pointer under $root"
    printf '%s\n' "$EPOCH" > "$tmp"
    mv -f -- "$tmp" "$root/.current-epoch"
}
publish_current_epoch "$OBJECT_ROOT"
publish_current_epoch "$CANDIDATE_ROOT"

lease_is_live()
{
    local lease="$1" pid start actual
    pid="$(sed -n 's/^pid=//p' "$lease" 2>/dev/null)"
    start="$(sed -n 's/^start=//p' "$lease" 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$start" =~ ^[0-9a-f]+$ ]] || return 1
    actual="$("$SELF_DIR/process-start-token.sh" "$pid" 2>/dev/null)" || return 1
    [ "$actual" = "$start" ]
}

# Keep the current epoch plus the newest KEEP-1 inactive epochs. A directory
# with any live Make lease is never removed. Dead leases are self-healing.
mapfile -t epochs < <(
    find "$OBJECT_ROOT/epochs" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' 2>/dev/null |
        LC_ALL=C sort -rn | awk '{print $2}'
)
kept=1
for old in "${epochs[@]}"; do
    [ "$old" = "$EPOCH" ] && continue
    old_dir="$OBJECT_ROOT/epochs/$old"
    live=0
    if [ -d "$old_dir/.leases" ]; then
        while IFS= read -r -d '' old_lease; do
            if lease_is_live "$old_lease"; then
                live=1
            else
                rm -f -- "$old_lease"
            fi
        done < <(find "$old_dir/.leases" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    if [ "$live" -eq 1 ]; then
        continue
    fi
    if [ "$kept" -lt "$KEEP" ]; then
        kept=$((kept + 1))
        continue
    fi
    rm -rf -- "$old_dir"
    [ "$CANDIDATE_ROOT" = - ] || rm -rf -- "$CANDIDATE_ROOT/epochs/$old"
done

printf 'build-epoch-session: acquired profile=%s epoch=%s lease=%s\n' \
    "$PROFILE" "$EPOCH" "$LEASE"
