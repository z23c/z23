#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Atomic cached-object compiler for one immutable host-local compile epoch.

set -euo pipefail

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

case "$MODE" in dep|coverage) ;; *) fail "unknown compile mode: $MODE" ;; esac
is_sha256 "$SOURCE_ID" || fail 'source id is not lowercase SHA-256'
[ "$COMPLETE" = 1 ] || fail 'source capture is incomplete'
is_sha256 "$MUTATION" || fail 'mutation token is not lowercase SHA-256'
is_sha256 "$EPOCH" || fail 'compile epoch is not lowercase SHA-256'
is_sha256 "$COMPILER_ID" || fail 'compiler id is not lowercase SHA-256'
[ -f "$SOURCE" ] || fail "source is not a regular file: $SOURCE"
case "/$OUTPUT/" in
    *"/epochs/$EPOCH/"*) ;;
    *) fail "object path is outside compile epoch $EPOCH" ;;
esac

# O(1) per-TU guard. The lease/session creator performs the expensive complete
# source + compiler + profile verification once; final aggregate/candidate
# publication verifies it again. The session stamp still binds the exact
# source id/mutation, so a TU compile in a stable epoch can only proceed under
# a session authority that names the current source record.
[ -f "$SESSION" ] || fail 'verified compile-session stamp is missing'
grep -Fxq 'schema=zcl.build_epoch_session.v1' "$SESSION" &&
grep -Fxq "source_id=$SOURCE_ID" "$SESSION" &&
grep -Fxq "complete=$COMPLETE" "$SESSION" &&
grep -Fxq "mutation=$MUTATION" "$SESSION" &&
grep -Fxq "compiler_id=$COMPILER_ID" "$SESSION" &&
grep -Fxq "epoch=$EPOCH" "$SESSION" ||
    fail 'compile-session stamp does not match object authority'

OUTPUT_DIR="$(dirname -- "$OUTPUT")"
OUTPUT_BASE="$(basename -- "$OUTPUT")"
DEPFILE="${OUTPUT%.o}.d"
mkdir -p "$OUTPUT_DIR"
STAGING=""

cleanup()
{
    [ -z "$STAGING" ] || rm -rf -- "$STAGING"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

compile_one()
{
    local staging staging_base object dep note_record note_tmp
    # Long source filenames can make the staging directory path breach Windows
    # MAX_PATH. Use a short deterministic prefix derived from OUTPUT_BASE; the
    # XXXXXX suffix still gives mktemp its uniqueness.
    staging_base="$(printf '%s' "$OUTPUT_BASE" | sha256sum | cut -c1-16)" ||
        fail 'could not derive staging base'
    staging="$(mktemp -d "$OUTPUT_DIR/.${staging_base}.compile.XXXXXX")" ||
        fail 'could not create object staging directory'
    STAGING="$staging"
    object="$staging/$OUTPUT_BASE"
    dep="$staging/${OUTPUT_BASE%.o}.d"
    "$@" -MD -MP -MF "$dep" -MT "$OUTPUT" -c -o "$object" "$SOURCE"
    [ -s "$object" ] || fail 'compiler did not create a nonempty object'
    [ -s "$dep" ] || fail 'compiler did not create a nonempty dependency file'

    if [ "$MODE" = coverage ]; then
        [ -s "$staging/${OUTPUT_BASE%.o}.gcno" ] ||
            fail 'coverage compiler did not create a .gcno note'
    fi

    mv -f -- "$dep" "$DEPFILE"
    if [ "$MODE" = coverage ]; then
        note_record="${OUTPUT%.o}.gcno-path"
        note_tmp="$staging/${OUTPUT_BASE%.o}.gcno-path"
        printf '%s\n' "$staging/${OUTPUT_BASE%.o}.gcno" > "$note_tmp"
        mv -f -- "$note_tmp" "$note_record"
    fi
    mv -f -- "$object" "$OUTPUT"
    if [ "$MODE" = coverage ]; then
        # The object embeds this staging basename for its future .gcda. Keep
        # the matching .gcno beside it; the epoch root remains coverage's scan
        # root. The per-object lock below guarantees exactly one live staging
        # directory, while the .o itself is still atomically published.
        STAGING=""
    else
        rm -rf -- "$staging"
        STAGING=""
    fi
}

if [ "$MODE" = coverage ]; then
    command -v flock >/dev/null 2>&1 || fail 'flock is required for coverage objects'
    exec 9> "$OUTPUT.lock"
    flock -x 9
    # A peer Make may have completed this exact immutable epoch after this
    # recipe was scheduled. Never rewrite its coverage object/staging path.
    if [ -s "$OUTPUT" ] && [ -s "$DEPFILE" ] &&
       [ -s "${OUTPUT%.o}.gcno-path" ]; then
        read -r cached_note < "${OUTPUT%.o}.gcno-path"
        if [ -s "$cached_note" ]; then
            exit 0
        fi
    fi
fi

compile_one "$@"
