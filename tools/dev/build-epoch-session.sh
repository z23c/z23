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
HOST_SYSTEM="$(uname -s 2>/dev/null || printf 'unknown')"
HOST_IS_MSYS=0
case "$HOST_SYSTEM" in MINGW*|MSYS*) HOST_IS_MSYS=1 ;; esac

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
    case "$HOST_SYSTEM" in
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
    case "$HOST_SYSTEM" in
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
# Headless MSYS2 service wrappers can hide the Make ancestor from /proc and
# native ps.  Accept the live recipe process only on that host and only when
# Make exported a positive nesting level.  Other hosts retain the strict
# ancestor-or-explicit-owner requirement.
elif [ "$HOST_IS_MSYS" = 1 ] &&
     [[ "${MAKELEVEL:-}" =~ ^[1-9][0-9]*$ ]] &&
     "$SELF_DIR/process-start-token.sh" "$$" >/dev/null 2>&1; then
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

ensure_directory()
{
    local path="$1" description="$2"
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -d "$path" ] && [ ! -L "$path" ] ||
            fail "$description is not a regular directory"
        return 0
    fi
    mkdir -- "$path" || fail "could not create $description"
}

ensure_root_directory()
{
    local path="$1" description="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        mkdir -p -- "$path" || fail "could not create $description"
    fi
    [ -d "$path" ] && [ ! -L "$path" ] ||
        fail "$description is not a regular directory"
}

ensure_epoch_generation()
{
    local root="$1" description="$2"
    [ -n "$root" ] && [ "$root" != - ] || return 0
    ensure_root_directory "$root" "$description root"
    ensure_directory "$root/epochs" "$description epoch namespace"
    ensure_directory "$root/epochs/$EPOCH" "$description epoch generation"
}

EPOCH_DIR="$OBJECT_ROOT/epochs/$EPOCH"
UNVERIFIED="$EPOCH_DIR/.unverified"
ADMISSION_LOCK_ROOT="$OBJECT_ROOT/.epoch-admission"
ADMISSION_LOCK_FILE="$ADMISSION_LOCK_ROOT/$EPOCH.lock"
ADMISSION_LOCK_DIR="$ADMISSION_LOCK_ROOT/$EPOCH.lock.d"
ADMISSION_LOCK_OWNER="$ADMISSION_LOCK_DIR/owner"
ADMISSION_LOCK_HELD=0

admission_lock_matches_fd()
{
    local fd_inode path_inode
    if [ "$HOST_SYSTEM" = Darwin ]; then
        [ -x /usr/sbin/lsof ] || return 1
        fd_inode=$(/usr/sbin/lsof -a -p "$$" -d 8 -Fi 2>/dev/null |
            sed -n 's/^i//p')
        path_inode=$(/usr/bin/stat -f '%i' "$ADMISSION_LOCK_FILE" 2>/dev/null)
        [ -n "$fd_inode" ] && [ "$fd_inode" = "$path_inode" ]
        return
    fi
    [ "$ADMISSION_LOCK_FILE" -ef /dev/fd/8 ]
}

acquire_admission_lock()
{
    local empty_deadline pid start actual owner_start now
    local verify_pid verify_start verify_actual
    local stale_pid= stale_start= stale_deadline=0
    [ -d "$OBJECT_ROOT" ] && [ ! -L "$OBJECT_ROOT" ] ||
        fail 'object root is not a regular directory'
    [ -d "$OBJECT_ROOT/epochs" ] && [ ! -L "$OBJECT_ROOT/epochs" ] ||
        fail 'object epoch namespace is not a regular directory'
    [ -d "$EPOCH_DIR" ] && [ ! -L "$EPOCH_DIR" ] ||
        fail 'object epoch generation is not a regular directory'
    if [ -e "$ADMISSION_LOCK_ROOT" ] || [ -L "$ADMISSION_LOCK_ROOT" ]; then
        [ -d "$ADMISSION_LOCK_ROOT" ] && [ ! -L "$ADMISSION_LOCK_ROOT" ] ||
            fail 'epoch admission lock root is not a regular directory'
    else
        mkdir -p "$ADMISSION_LOCK_ROOT" ||
            fail 'could not create epoch admission lock root'
    fi
    if [ "$HOST_IS_MSYS" = 0 ]; then
        command -v flock >/dev/null 2>&1 ||
            fail 'flock is required for epoch admission'
        [ ! -L "$ADMISSION_LOCK_FILE" ] ||
            fail 'epoch admission lock is a symbolic link'
        exec 8> "$ADMISSION_LOCK_FILE"
        [ -f "$ADMISSION_LOCK_FILE" ] && [ ! -L "$ADMISSION_LOCK_FILE" ] &&
            admission_lock_matches_fd || {
            exec 8>&-
            fail 'epoch admission lock is not a regular file'
        }
        flock -x 8
        [ -f "$ADMISSION_LOCK_FILE" ] && [ ! -L "$ADMISSION_LOCK_FILE" ] &&
            admission_lock_matches_fd || {
            exec 8>&-
            fail 'epoch admission lock changed while waiting'
        }
        return 0
    fi
    empty_deadline=0
    while :; do
        if mkdir "$ADMISSION_LOCK_DIR" 2>/dev/null; then
            owner_start="$("$SELF_DIR/process-start-token.sh" "$$")" ||
                fail 'could not identify epoch admission lock owner'
            [ -n "$owner_start" ] ||
                fail 'epoch admission lock owner start token is empty'
            printf 'pid=%s\nstart=%s\n' "$$" "$owner_start" \
                > "$ADMISSION_LOCK_OWNER"
            ADMISSION_LOCK_HELD=1
            return 0
        fi
        [ ! -L "$ADMISSION_LOCK_DIR" ] ||
            fail 'epoch admission lock directory is a symbolic link'
        pid="$(sed -n 's/^pid=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
        start="$(sed -n 's/^start=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
        if [ -z "$pid" ] || [ -z "$start" ]; then
            now="$(date +%s)"
            if [ "$empty_deadline" -eq 0 ]; then
                empty_deadline=$((now + 30))
            elif [ "$now" -ge "$empty_deadline" ]; then
                [ "$MODE" = acquire ] &&
                [ "${EPOCH_GC_LOCK_HELD:-0}" = 1 ] ||
                    fail 'epoch admission lock owner was not published'
                rm -f -- "$ADMISSION_LOCK_OWNER"
                rmdir "$ADMISSION_LOCK_DIR" 2>/dev/null ||
                    fail 'could not recover abandoned epoch admission lock'
                empty_deadline=0
            else
                sleep 0.05
            fi
            continue
        fi
        empty_deadline=0
        actual="$("$SELF_DIR/process-start-token.sh" "$pid" 2>/dev/null || true)"
        if [ -z "$actual" ] || [ "$actual" != "$start" ]; then
            now="$(date +%s)"
            if [ "$pid" != "$stale_pid" ] || [ "$start" != "$stale_start" ]; then
                stale_pid="$pid"
                stale_start="$start"
                stale_deadline=$((now + 30))
                sleep 0.05
                continue
            fi
            [ "$now" -ge "$stale_deadline" ] || {
                sleep 0.05
                continue
            }
            [ "$MODE" = acquire ] &&
            [ "${EPOCH_GC_LOCK_HELD:-0}" = 1 ] ||
                fail 'epoch admission lock owner remained stale'
            verify_pid="$(sed -n 's/^pid=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
            verify_start="$(sed -n 's/^start=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
            verify_actual="$("$SELF_DIR/process-start-token.sh" "$verify_pid" 2>/dev/null || true)"
            [ "$verify_pid" = "$pid" ] && [ "$verify_start" = "$start" ] &&
            { [ -z "$verify_actual" ] || [ "$verify_actual" != "$verify_start" ]; } ||
                continue
            rm -f -- "$ADMISSION_LOCK_OWNER"
            rmdir "$ADMISSION_LOCK_DIR" 2>/dev/null ||
                fail 'could not recover stale epoch admission lock'
            stale_pid=
            stale_start=
            stale_deadline=0
            continue
        fi
        stale_pid=
        stale_start=
        stale_deadline=0
        sleep 0.05
    done
}
release_admission_lock()
{
    if [ "$HOST_IS_MSYS" = 0 ]; then
        exec 8>&-
    elif [ "$ADMISSION_LOCK_HELD" = 1 ]; then
        rm -f -- "$ADMISSION_LOCK_OWNER"
        rmdir "$ADMISSION_LOCK_DIR" 2>/dev/null || true
        ADMISSION_LOCK_HELD=0
    fi
}

clear_unverified()
{
    local expected
    [ -e "$UNVERIFIED" ] || [ -L "$UNVERIFIED" ] || return 0
    [ -f "$UNVERIFIED" ] && [ ! -L "$UNVERIFIED" ] ||
        fail 'unverified epoch marker is not a regular file'
    expected="$(mktemp "${TMPDIR:-/tmp}/zcl-build-unverified.XXXXXX")"
    printf 'schema=zcl.build_epoch_unverified.v1\nsource_id=%s\nmutation=%s\ncompiler_id=%s\nepoch=%s\n' \
        "$SOURCE_ID" "$MUTATION" "$COMPILER_ID" "$EPOCH" > "$expected"
    cmp -s "$expected" "$UNVERIFIED" || {
        rm -f -- "$expected"
        fail 'unverified epoch marker does not match aggregate authority'
    }
    rm -f -- "$expected"
    rm -f -- "$UNVERIFIED" || fail 'could not admit verified compile epoch'
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

if [ "$MODE" = verify ]; then
    acquire_admission_lock
    trap 'release_admission_lock; cleanup' EXIT
    verify_authority
    check_stamp
    clear_unverified
    exit 0
fi

verify_authority

ensure_epoch_generation "$OBJECT_ROOT" object
ensure_epoch_generation "$CANDIDATE_ROOT" candidate
ensure_directory "$EPOCH_DIR/.leases" 'object epoch lease directory'

# MSYS2/Git Bash cannot reliably share inherited descriptors with the MSYS2
# util-linux flock binary. Keep the crash-safe descriptor lock on POSIX and
# use an identity-bearing atomic directory only on MSYS hosts.
EPOCH_GC_LOCK_FILE="$OBJECT_ROOT/.epoch-gc.lock"
EPOCH_GC_LOCK_DIR="$OBJECT_ROOT/.epoch-gc.lock.d"
EPOCH_GC_LOCK_OWNER="$EPOCH_GC_LOCK_DIR/owner"
EPOCH_GC_LOCK_HELD=0
epoch_gc_owner_live()
{
    local pid start actual
    pid="$(sed -n 's/^pid=//p' "$EPOCH_GC_LOCK_OWNER" 2>/dev/null)"
    start="$(sed -n 's/^start=//p' "$EPOCH_GC_LOCK_OWNER" 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$start" =~ ^[0-9a-f]+$ ]] ||
        return 1
    actual="$("$SELF_DIR/process-start-token.sh" "$pid" 2>/dev/null)" ||
        return 1
    [ "$actual" = "$start" ]
}
acquire_epoch_gc_lock()
{
    local deadline
    if [ "$HOST_IS_MSYS" = 0 ]; then
        command -v flock >/dev/null 2>&1 ||
            fail 'flock is required for epoch leases'
        exec 9> "$EPOCH_GC_LOCK_FILE"
        flock -x 9
        return 0
    fi
    deadline=$(($(date +%s) + 30))
    while :; do
        if mkdir "$EPOCH_GC_LOCK_DIR" 2>/dev/null; then
            if (set -o noclobber
                printf 'pid=%s\nstart=%s\n' "$OWNER_PID" "$OWNER_START" \
                    > "$EPOCH_GC_LOCK_OWNER") 2>/dev/null; then
                EPOCH_GC_LOCK_HELD=1
                return 0
            fi
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            if epoch_gc_owner_live; then
                fail "could not acquire epoch GC lock $EPOCH_GC_LOCK_DIR (another build is live)"
            fi
            rm -f -- "$EPOCH_GC_LOCK_OWNER"
            rmdir "$EPOCH_GC_LOCK_DIR" 2>/dev/null ||
                fail "could not recover stale epoch GC lock $EPOCH_GC_LOCK_DIR"
        fi
        sleep 0.2
    done
}
release_epoch_gc_lock()
{
    local pid start
    [ "$EPOCH_GC_LOCK_HELD" = 1 ] || return 0
    pid="$(sed -n 's/^pid=//p' "$EPOCH_GC_LOCK_OWNER" 2>/dev/null)"
    start="$(sed -n 's/^start=//p' "$EPOCH_GC_LOCK_OWNER" 2>/dev/null)"
    if [ "$pid" = "$OWNER_PID" ] && [ "$start" = "$OWNER_START" ]; then
        rm -f -- "$EPOCH_GC_LOCK_OWNER"
        rmdir "$EPOCH_GC_LOCK_DIR" 2>/dev/null || true
    fi
    EPOCH_GC_LOCK_HELD=0
}
trap 'release_admission_lock; release_epoch_gc_lock; cleanup' EXIT
trap 'exit 2' HUP INT TERM
acquire_epoch_gc_lock

# A prior writer publishes `.unverified` before it can replace any stable
# artifact and aggregate verification removes it only while holding the same
# admission lock. A dead build therefore leaves a durable reason to discard
# the entire shared epoch instead of reusing an unknown subset.
current_lease_is_live()
{
    local lease="$1" pid start actual
    pid="$(sed -n 's/^pid=//p' "$lease" 2>/dev/null)"
    start="$(sed -n 's/^start=//p' "$lease" 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$start" =~ ^[0-9a-f]+$ ]] ||
        return 1
    actual="$("$SELF_DIR/process-start-token.sh" "$pid" 2>/dev/null)" ||
        return 1
    [ "$actual" = "$start" ]
}
acquire_admission_lock
if [ -e "$UNVERIFIED" ] || [ -L "$UNVERIFIED" ]; then
    [ -f "$UNVERIFIED" ] && [ ! -L "$UNVERIFIED" ] ||
        fail 'unverified epoch marker is not a regular file'
    live_current_lease=0
    if [ -d "$EPOCH_DIR/.leases" ]; then
        while IFS= read -r -d '' current_lease; do
            if current_lease_is_live "$current_lease"; then
                live_current_lease=1
            else
                rm -f -- "$current_lease"
            fi
        done < <(find "$EPOCH_DIR/.leases" -maxdepth 1 -type f -print0 \
            2>/dev/null)
    fi
    [ "$live_current_lease" = 0 ] ||
        fail 'an unverified compile epoch still has a live build lease'
    failed_root="$OBJECT_ROOT/.failed-epochs"
    failed_epoch="$failed_root/$EPOCH.$OWNER_PID.$OWNER_START"
    mkdir -p "$failed_root"
    [ ! -e "$failed_epoch" ] && [ ! -L "$failed_epoch" ] ||
        fail 'failed-epoch quarantine destination already exists'
    mv -- "$EPOCH_DIR" "$failed_epoch" ||
        fail 'could not quarantine unverified compile epoch'
    if [ "$CANDIDATE_ROOT" != - ]; then
        candidate_epoch="$CANDIDATE_ROOT/epochs/$EPOCH"
        if [ -e "$candidate_epoch" ] || [ -L "$candidate_epoch" ]; then
            [ -d "$candidate_epoch" ] && [ ! -L "$candidate_epoch" ] ||
                fail 'unverified candidate epoch is not a regular directory'
            rm -rf -- "$candidate_epoch"
        fi
    fi
    ensure_epoch_generation "$OBJECT_ROOT" object
    ensure_directory "$EPOCH_DIR/.leases" 'object epoch lease directory'
    release_admission_lock
    rm -rf -- "$failed_epoch"
else
    release_admission_lock
fi

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
    ensure_epoch_generation "$root" current
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
