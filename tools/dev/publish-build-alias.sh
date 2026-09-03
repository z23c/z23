#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Publish one immutable compile-epoch candidate at a familiar build/bin alias.
# Cross-process publishers serialize on the alias lock. The exact session stamp
# is checked before copying; full source/compiler authority is revalidated
# immediately before the atomic rename. A stale A build therefore cannot
# overwrite B after an A -> B -> A race.

set -euo pipefail

TMP=""
cleanup()
{
    [ -z "$TMP" ] || rm -f -- "$TMP"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail()
{
    printf 'publish-build-alias: %s\n' "$*" >&2
    exit 2
}

is_sha256()
{
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

[ "$#" -ge 13 ] && [ "$#" -le 14 ] ||
    fail 'usage: publish-build-alias.sh CANDIDATE ALIAS SESSION SOURCE COMPLETE MUTATION EPOCH COMPILER_ID PROFILE COMPILE_FLAGS LINK_FLAGS CC CXX [VERIFY_TOOL]'

CANDIDATE="$1"
ALIAS="$2"
SESSION="$3"
SOURCE_ID="$4"
COMPLETE="$5"
MUTATION="$6"
EPOCH="$7"
COMPILER_ID="$8"
PROFILE="$9"
COMPILE_FLAGS="${10}"
LINK_FLAGS="${11}"
CC_COMMAND="${12}"
CXX_COMMAND="${13}"
VERIFY_TOOL="${14:-tools/dev/source-identity.sh}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_TOOL="$SELF_DIR/build-epoch-session.sh"
source "$SELF_DIR/build-epoch-lock-wait.sh"

is_sha256 "$SOURCE_ID" || fail 'source id is not lowercase SHA-256'
[ "$COMPLETE" = 1 ] || fail 'source capture is incomplete'
is_sha256 "$MUTATION" || fail 'mutation token is not lowercase SHA-256'
is_sha256 "$EPOCH" || fail 'compile epoch is not lowercase SHA-256'
is_sha256 "$COMPILER_ID" || fail 'compiler id is not lowercase SHA-256'
[ -x "$VERIFY_TOOL" ] || fail "source verifier is not executable: $VERIFY_TOOL"
[ -x "$SESSION_TOOL" ] || fail "epoch verifier is not executable: $SESSION_TOOL"
[ -f "$CANDIDATE" ] && [ -x "$CANDIDATE" ] ||
    fail "candidate is not a regular executable: $CANDIDATE"

# Make's candidate layout is part of the contract.  Refuse a caller that pairs
# an arbitrary binary with an unrelated epoch argument.
case "/$CANDIDATE/" in
    *"/epochs/$EPOCH/"*) ;;
    *) fail "candidate path is outside compile epoch $EPOCH" ;;
esac

command -v flock >/dev/null 2>&1 || fail 'flock is required for alias publication'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required for alias publication'

ALIAS_DIR="$(dirname -- "$ALIAS")"
mkdir -p "$ALIAS_DIR"
LOCK="$ALIAS.lock"
exec 9> "$LOCK"
# Bounded: a stuck publisher must turn this caller red (naming the lock and
# the holder) instead of hanging the lint gate behind an unbounded flock.
z23_build_epoch_flock_bounded 'publish-build-alias' 9 "$LOCK" 'alias' ||
    fail "could not acquire alias lock $LOCK"

OBJECT_ROOT="${SESSION%%/epochs/$EPOCH/*}"
[ "$OBJECT_ROOT" != "$SESSION" ] || fail 'could not derive object root from session path'
DUMMY_LEASE="$OBJECT_ROOT/epochs/$EPOCH/.leases/publisher-check"

"$SESSION_TOOL" check "$SESSION" "$DUMMY_LEASE" "$OBJECT_ROOT" - 1 \
    "$SOURCE_ID" "$COMPLETE" "$MUTATION" "$COMPILER_ID" "$EPOCH" \
    "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
    "$CXX_COMMAND" "$$" "$VERIFY_TOOL" >/dev/null

TMP="$(mktemp "$ALIAS_DIR/.build-alias.$(basename -- "$ALIAS").XXXXXX")" ||
    fail 'could not create alias publication temporary'
cp -p -- "$CANDIDATE" "$TMP"
chmod --reference="$CANDIDATE" "$TMP"

CANDIDATE_SHA="$(sha256sum < "$CANDIDATE" | awk '{print $1}')"
TMP_SHA="$(sha256sum < "$TMP" | awk '{print $1}')"
[ "$CANDIDATE_SHA" = "$TMP_SHA" ] ||
    fail 'candidate changed while it was copied'

# This is deliberately the final command before publication.  The mutation
# component catches same-content ABA, while the lock orders competing aliases.
"$SESSION_TOOL" verify "$SESSION" "$DUMMY_LEASE" "$OBJECT_ROOT" - 1 \
    "$SOURCE_ID" "$COMPLETE" "$MUTATION" "$COMPILER_ID" "$EPOCH" \
    "$PROFILE" "$COMPILE_FLAGS" "$LINK_FLAGS" "$CC_COMMAND" \
    "$CXX_COMMAND" "$$" "$VERIFY_TOOL" >/dev/null
mv -f -- "$TMP" "$ALIAS"
TMP=""

printf 'publish-build-alias: %s <= epoch %s sha256=%s\n' \
    "$ALIAS" "$EPOCH" "$TMP_SHA"
