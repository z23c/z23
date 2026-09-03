#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Atomic cached-object compiler for one immutable host-local compile epoch.

set -euo pipefail
export LC_ALL=C
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SELF_DIR/build-epoch-open-file-identity.sh"
source "$SELF_DIR/build-epoch-lock-wait.sh"

fail()
{
    printf 'compile-epoch-object: %s\n' "$*" >&2
    exit 2
}

is_sha256()
{
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

[ "$#" -ge 10 ] ||
    fail 'usage: compile-epoch-object.sh MODE OUTPUT SOURCE SOURCE_ID COMPLETE MUTATION EPOCH COMPILER_ID SESSION -- COMPILER [ARG...]'

MODE="$1"
OUTPUT="$2"
SOURCE="$3"
SOURCE_ID="$4"
COMPLETE="$5"
MUTATION="$6"
EPOCH="$7"
COMPILER_ID="$8"
SESSION="$9"
shift 9
[ "${1:-}" = -- ] || fail 'missing compiler argv separator'
shift
[ "$#" -gt 0 ] || fail 'empty compiler argv'

# Every anticipated refusal below supplies its own context. This trap closes
# the remaining set -e gap: if an unanticipated top-level command dies,
# Make must still identify the source, output and exact script line instead of
# reducing the event to a generic "Error 2".
unexpected_failure()
{
    local rc=$1 line=$2
    printf 'compile-epoch-object: unexpected rc=%s source=%s output=%s line=%s\n' \
        "$rc" "$SOURCE" "$OUTPUT" "$line" >&2
    exit "$rc"
}
trap 'unexpected_failure "$?" "$LINENO"' ERR

case "$MODE" in dep|coverage) ;; *) fail "unknown compile mode: $MODE" ;; esac
is_sha256 "$SOURCE_ID" || fail 'source id is not lowercase SHA-256'
[ "$COMPLETE" = 1 ] || fail 'source capture is incomplete'
is_sha256 "$MUTATION" || fail 'mutation token is not lowercase SHA-256'
is_sha256 "$EPOCH" || fail 'compile epoch is not lowercase SHA-256'
is_sha256 "$COMPILER_ID" || fail 'compiler id is not lowercase SHA-256'
[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] ||
    fail "source is not a regular file: $SOURCE"

output_contained()
{
    local path="$1" part after_epochs=0 matched_epoch=0 has_descendant=0
    local -a parts=()
    EPOCH_ROOT=
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [ "$part" != . ] && [ "$part" != .. ] || return 1
        if [ "$matched_epoch" = 1 ] && [ -n "$part" ]; then
            has_descendant=1
        fi
        if [ "$after_epochs" = 1 ] && [ "$part" = "$EPOCH" ]; then
            matched_epoch=1
            EPOCH_ROOT="${path%%/epochs/$EPOCH/*}/epochs/$EPOCH"
            case "$path" in epochs/"$EPOCH"/*) EPOCH_ROOT="epochs/$EPOCH" ;; esac
        else
            matched_epoch=0
        fi
        [ "$part" = epochs ] && after_epochs=1 || after_epochs=0
    done
    [ "$has_descendant" = 1 ]
}

path_has_no_symlink()
{
    local path="$1" part current=
    local -a parts=()
    [ "${path:0:1}" != / ] || current=/
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [ -n "$part" ] || continue
        current="${current%/}${current:+/}$part"
        if [ -e "$current" ] || [ -L "$current" ]; then
            [ ! -L "$current" ] || return 1
        fi
    done
}

output_contained "$OUTPUT" || fail "object path is outside compile epoch $EPOCH"
OUTPUT_EPOCH_ROOT="$EPOCH_ROOT"
output_contained "$SESSION" || fail 'compile-session path is outside compile epoch'
[ "$OUTPUT_EPOCH_ROOT" = "$EPOCH_ROOT" ] ||
    fail 'object and compile-session do not share an exact epoch root'
case "$OUTPUT_EPOCH_ROOT" in
    epochs/"$EPOCH") OBJECT_ROOT=. ;;
    */epochs/"$EPOCH") OBJECT_ROOT="${OUTPUT_EPOCH_ROOT%/epochs/$EPOCH}" ;;
    *) fail 'could not derive stable object root from compile epoch' ;;
esac
[ -n "$OBJECT_ROOT" ] || OBJECT_ROOT=/
path_has_no_symlink "$OUTPUT" && path_has_no_symlink "$SESSION" ||
    fail 'object or compile-session path contains a symlink component'
ADMISSION_LOCK_ROOT="$OBJECT_ROOT/.epoch-admission"
[ ! -L "$ADMISSION_LOCK_ROOT" ] ||
    fail 'epoch admission lock root is a symlink'
mkdir -p "$ADMISSION_LOCK_ROOT" || fail 'could not create epoch admission lock root'
path_has_no_symlink "$ADMISSION_LOCK_ROOT" ||
    fail 'epoch admission lock root contains a symlink component'

# O(1) per-TU guard. The lease/session creator performs the expensive complete
# source + compiler + profile verification once; final aggregate/candidate
# publication verifies it again. Read the six bindings in one shell pass. The
# former six grep children multiplied across every object even though Bash can
# compare these fixed records directly.
[ -f "$SESSION" ] && [ ! -L "$SESSION" ] ||
    fail 'verified compile-session stamp is missing or not a regular file'
# Bash drops NUL bytes while reading a line. Detect one before line parsing so
# a binary-tampered value cannot collapse into an otherwise valid binding.
if IFS= read -r -d '' session_binary_prefix < "$SESSION"; then
    fail 'compile-session stamp contains a NUL byte'
fi

session_parse()
{
    local line= total=0 index=0 valid=1
    SESSION_CAPTURE=
    while IFS= read -r line; do
        total=$((total + ${#line} + 1))
        [ "$total" -le 65536 ] || return 1
        SESSION_CAPTURE+="$line"$'\n'
        index=$((index + 1))
        case "$index" in
            1) [ "$line" = 'schema=zcl.build_epoch_session.v1' ] || valid=0 ;;
            2) [ "$line" = "source_id=$SOURCE_ID" ] || valid=0 ;;
            3) [ "$line" = "complete=$COMPLETE" ] || valid=0 ;;
            4) [ "$line" = "mutation=$MUTATION" ] || valid=0 ;;
            5) [ "$line" = "compiler_id=$COMPILER_ID" ] || valid=0 ;;
            6) [ "$line" = "epoch=$EPOCH" ] || valid=0 ;;
            7) [[ "$line" =~ ^profile=.+$ ]] || valid=0 ;;
            8) [[ "$line" =~ ^flags_sha256=[0-9a-f]{64}$ ]] || valid=0 ;;
            *) valid=0 ;;
        esac
    done
    [ -z "$line" ] && [ "$valid" = 1 ] && [ "$index" = 8 ]
}

session_stamp()
{
    stat -Lc '%d:%i:%s:%Y:%Z:%y:%z' "$SESSION" 2>/dev/null ||
        stat -f '%d:%i:%z:%m:%c' "$SESSION" 2>/dev/null
}

exec 8< "$SESSION" || fail 'could not open compile-session stamp'
SESSION_INITIAL_STAMP="$(session_stamp)" ||
    fail 'could not capture compile-session metadata'
session_parse <&8 || fail 'compile-session stamp does not match object authority'
SESSION_INITIAL="$SESSION_CAPTURE"

session_unchanged()
{
    [ -f "$SESSION" ] && [ ! -L "$SESSION" ] &&
        z23_build_epoch_open_fd_matches_path "$SESSION" 8 \
            "$(uname -s 2>/dev/null || printf unknown)" || return 1
    if IFS= read -r -d '' session_binary_prefix < "$SESSION"; then
        return 1
    fi
    session_parse < "$SESSION" || return 1
    [ "$SESSION_CAPTURE" = "$SESSION_INITIAL" ] &&
        [ "$(session_stamp)" = "$SESSION_INITIAL_STAMP" ]
}

unverified_matches()
{
    local marker="$OUTPUT_EPOCH_ROOT/.unverified" line= index=0 valid=1
    [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
    if IFS= read -r -d '' marker_binary_prefix < "$marker"; then
        return 1
    fi
    while IFS= read -r line; do
        index=$((index + 1))
        case "$index" in
            1) [ "$line" = 'schema=zcl.build_epoch_unverified.v1' ] || valid=0 ;;
            2) [ "$line" = "source_id=$SOURCE_ID" ] || valid=0 ;;
            3) [ "$line" = "mutation=$MUTATION" ] || valid=0 ;;
            4) [ "$line" = "compiler_id=$COMPILER_ID" ] || valid=0 ;;
            5) [ "$line" = "epoch=$EPOCH" ] || valid=0 ;;
            *) valid=0 ;;
        esac
    done < "$marker"
    [ -z "$line" ] && [ "$valid" = 1 ] && [ "$index" = 5 ]
}

sync_unverified()
{
    local marker="$OUTPUT_EPOCH_ROOT/.unverified"
    sync "$marker" "$OUTPUT_EPOCH_ROOT" 2>/dev/null || sync
}

OUTPUT_DIR="${OUTPUT%/*}"
OUTPUT_BASE="${OUTPUT##*/}"
[ "$OUTPUT_DIR" != "$OUTPUT" ] || OUTPUT_DIR=.
[ -n "$OUTPUT_DIR" ] || OUTPUT_DIR=/
DEPFILE="${OUTPUT%.o}.d"
[ -d "$OUTPUT_DIR" ] || mkdir -p "$OUTPUT_DIR"
STAGING=""
ADMISSION_LOCK_HELD=0
ADMISSION_MARKER_TMP=""
ADMISSION_LOCK_FILE="$ADMISSION_LOCK_ROOT/$EPOCH.lock"
ADMISSION_LOCK_DIR="$ADMISSION_LOCK_ROOT/$EPOCH.lock.d"
ADMISSION_LOCK_OWNER="$ADMISSION_LOCK_DIR/owner"

cleanup()
{
    [ -z "$STAGING" ] || rm -rf -- "$STAGING"
    [ -z "$ADMISSION_MARKER_TMP" ] || rm -f -- "$ADMISSION_MARKER_TMP"
    if [ "$ADMISSION_LOCK_HELD" = 1 ]; then
        rm -f -- "$ADMISSION_LOCK_OWNER"
        rmdir "$ADMISSION_LOCK_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

compile_one()
{
    local staging staging_base object dep note_record note_tmp marker_tmp
    local compiler_rc
    local host_system empty_deadline pid start actual owner_start now
    local stale_pid= stale_start= stale_deadline=0
    # Long source filenames can make the staging directory path breach Windows
    # MAX_PATH. Use a short deterministic prefix derived from OUTPUT_BASE; the
    # XXXXXX suffix still gives mktemp its uniqueness.
    staging_base="${OUTPUT_BASE:0:16}"
    staging_base="${staging_base//[!A-Za-z0-9_.-]/_}"
    [ -n "$staging_base" ] || staging_base=object
    staging="$(mktemp -d "$OUTPUT_DIR/.${staging_base}.compile.XXXXXX")" ||
        fail 'could not create object staging directory'
    STAGING="$staging"
    object="$staging/$OUTPUT_BASE"
    dep="$staging/${OUTPUT_BASE%.o}.d"
    if "$@" -MMD -MP -MF "$dep" -MT "$OUTPUT" -c -o "$object" "$SOURCE"; then
        compiler_rc=0
    else
        compiler_rc=$?
    fi
    [ "$compiler_rc" = 0 ] ||
        fail "compiler exited rc=$compiler_rc source=$SOURCE; native loader or toolchain failure may have produced no diagnostic"
    [ -s "$object" ] || fail 'compiler did not create a nonempty object'
    [ -s "$dep" ] || fail 'compiler did not create a nonempty dependency file'

    if [ "$MODE" = coverage ]; then
        [ -s "$staging/${OUTPUT_BASE%.o}.gcno" ] ||
            fail 'coverage compiler did not create a .gcno note'
    fi
    session_unchanged || fail 'compile-session changed during compilation'

    if [ "$MODE" = coverage ]; then
        note_record="${OUTPUT%.o}.gcno-path"
        note_tmp="$staging/${OUTPUT_BASE%.o}.gcno-path"
        printf '%s\n' "$staging/${OUTPUT_BASE%.o}.gcno" > "$note_tmp"
    fi
    host_system="$(uname -s 2>/dev/null || printf unknown)"
    case "$host_system" in
        MINGW*|MSYS*)
            empty_deadline=0
            while ! mkdir "$ADMISSION_LOCK_DIR" 2>/dev/null; do
                [ ! -L "$ADMISSION_LOCK_DIR" ] ||
                    fail 'epoch admission lock directory is a symlink'
                pid="$(sed -n 's/^pid=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
                start="$(sed -n 's/^start=//p' "$ADMISSION_LOCK_OWNER" 2>/dev/null || true)"
                # mkdir publishes before the winner can write its identity.
                # An empty owner is therefore transitional, not proof of a
                # stale lock. Wait boundedly; only the deadline may recover
                # a creator that died in this narrow interval.
                if [ -z "$pid" ] || [ -z "$start" ]; then
                    now="$(date +%s)"
                    if [ "$empty_deadline" -eq 0 ]; then
                        empty_deadline=$((now + 30))
                    elif [ "$now" -ge "$empty_deadline" ]; then
                        fail 'epoch admission lock owner was not published; rerun for serialized recovery'
                    else
                        sleep 0.05
                    fi
                    continue
                fi
                empty_deadline=0
                actual="$("$SELF_DIR/process-start-token.sh" "$pid" 2>/dev/null || true)"
                if [ -z "$actual" ] || [ "$actual" != "$start" ]; then
                    now="$(date +%s)"
                    if [ "$pid" != "$stale_pid" ] ||
                       [ "$start" != "$stale_start" ]; then
                        stale_pid="$pid"
                        stale_start="$start"
                        stale_deadline=$((now + 30))
                    elif [ "$now" -ge "$stale_deadline" ]; then
                        fail 'epoch admission lock owner remained stale; rerun for serialized recovery'
                    fi
                    sleep 0.05
                    continue
                fi
                stale_pid=
                stale_start=
                stale_deadline=0
                sleep 0.05
            done
            [ -d "$ADMISSION_LOCK_DIR" ] && [ ! -L "$ADMISSION_LOCK_DIR" ] ||
                fail 'epoch admission lock directory is not regular'
            owner_start="$("$SELF_DIR/process-start-token.sh" "$$")" ||
                fail 'could not identify epoch admission lock owner'
            [ -n "$owner_start" ] ||
                fail 'epoch admission lock owner start token is empty'
            printf 'pid=%s\nstart=%s\n' "$$" "$owner_start" \
                > "$ADMISSION_LOCK_OWNER"
            ADMISSION_LOCK_HELD=1
            ;;
        *)
            command -v flock >/dev/null 2>&1 ||
                fail 'flock is required for epoch publication'
            [ ! -L "$ADMISSION_LOCK_FILE" ] ||
                fail 'epoch admission lock is a symlink'
            exec 6> "$ADMISSION_LOCK_FILE"
            [ -f "$ADMISSION_LOCK_FILE" ] &&
                z23_build_epoch_open_fd_matches_path \
                    "$ADMISSION_LOCK_FILE" 6 \
                    "$(uname -s 2>/dev/null || printf unknown)" ||
                fail 'epoch admission lock is not the opened regular file'
            z23_build_epoch_flock_bounded 'compile-epoch-object' 6 \
                "$ADMISSION_LOCK_FILE" 'epoch admission' || {
                exec 6>&-
                fail "could not acquire epoch admission lock $ADMISSION_LOCK_FILE"
            }
            [ -f "$ADMISSION_LOCK_FILE" ] &&
                [ ! -L "$ADMISSION_LOCK_FILE" ] &&
                z23_build_epoch_open_fd_matches_path \
                    "$ADMISSION_LOCK_FILE" 6 \
                    "$(uname -s 2>/dev/null || printf unknown)" ||
                fail 'epoch admission lock changed while waiting'
            ;;
    esac
    session_unchanged || fail 'compile-session changed before publication'
    path_has_no_symlink "$OUTPUT" && path_has_no_symlink "$SESSION" ||
        fail 'object or compile-session path changed before publication'
    if [ -e "$OUTPUT_EPOCH_ROOT/.unverified" ] ||
       [ -L "$OUTPUT_EPOCH_ROOT/.unverified" ]; then
        unverified_matches ||
            fail 'unverified epoch marker does not match object authority'
    else
        marker_tmp="$(mktemp "$OUTPUT_EPOCH_ROOT/.unverified.XXXXXX")" ||
            fail 'could not stage unverified epoch marker'
        ADMISSION_MARKER_TMP="$marker_tmp"
        printf 'schema=zcl.build_epoch_unverified.v1\nsource_id=%s\nmutation=%s\ncompiler_id=%s\nepoch=%s\n' \
            "$SOURCE_ID" "$MUTATION" "$COMPILER_ID" "$EPOCH" > "$marker_tmp"
        mv -- "$marker_tmp" "$OUTPUT_EPOCH_ROOT/.unverified" ||
            fail 'could not publish unverified epoch marker'
        ADMISSION_MARKER_TMP=""
        sync_unverified || fail 'could not sync unverified epoch marker'
    fi
    if [ "$MODE" = coverage ]; then
        rm -f -- "$note_record" ||
            fail 'could not clear coverage admission record'
    fi
    mv -f -- "$dep" "$DEPFILE"
    mv -f -- "$object" "$OUTPUT"
    if [ "$MODE" = coverage ]; then
        # Publish the admission record last. A consumer that observes it can
        # therefore rely on the dependency, object, and note already existing.
        mv -f -- "$note_tmp" "$note_record"
        # The object embeds this staging basename for its future .gcda. Keep
        # the matching .gcno beside it; the epoch root remains coverage's scan
        # root. The per-object lock below guarantees exactly one live staging
        # directory, while the .o itself is still atomically published.
        STAGING=""
    else
        rm -rf -- "$staging"
        STAGING=""
    fi
    if [ "$ADMISSION_LOCK_HELD" = 1 ]; then
        rm -f -- "$ADMISSION_LOCK_OWNER"
        rmdir "$ADMISSION_LOCK_DIR" 2>/dev/null || true
        ADMISSION_LOCK_HELD=0
    else
        exec 6>&-
    fi
}

if [ "$MODE" = coverage ]; then
    command -v flock >/dev/null 2>&1 || fail 'flock is required for coverage objects'
    exec 9> "$OUTPUT.lock"
    z23_build_epoch_flock_bounded 'compile-epoch-object' 9 \
        "$OUTPUT.lock" 'coverage object' ||
        fail "could not acquire coverage object lock $OUTPUT.lock"
fi

compile_one "$@"
