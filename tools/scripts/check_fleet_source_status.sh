#!/usr/bin/env bash
# Hermetic regression checks for fleet_source_status.sh.  No network or node.
set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/fleet_source_status.sh"

TMP_REPO=$(mktemp -d "${TMPDIR:-/tmp}/z23-fleet-source-status-XXXXXX")
cleanup() {
    case "$TMP_REPO" in
        /tmp/z23-fleet-source-status-*) rm -rf "$TMP_REPO" ;;
        *) printf 'check_fleet_source_status: refusing cleanup of %s\n' "$TMP_REPO" >&2 ;;
    esac
}
trap cleanup EXIT INT TERM

git -C "$TMP_REPO" init -q -b main
git -C "$TMP_REPO" config user.name fleet-source-test
git -C "$TMP_REPO" config user.email fleet-source-test@example.invalid

commit_fixture() {
    local name=$1 stamp=$2
    printf '%s\n' "$name" >"$TMP_REPO/$name"
    git -C "$TMP_REPO" add "$name"
    GIT_AUTHOR_DATE="$stamp" GIT_COMMITTER_DATE="$stamp" \
        git -C "$TMP_REPO" commit -q -m "$name"
    git -C "$TMP_REPO" rev-parse HEAD
}

BASE=$(commit_fixture base 2026-08-20T01:02:03+00:00)
FLOOR=$(commit_fixture floor 2026-08-21T02:03:04+00:00)
HEAD_COMMIT=$(commit_fixture head 2026-08-22T03:04:05+00:00)
git -C "$TMP_REPO" switch -q --detach "$BASE"
FOREIGN=$(commit_fixture foreign 2026-08-20T06:07:08+00:00)
git -C "$TMP_REPO" switch -q main

fail=0
expect() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" = "$expected" ]; then
        printf '  ok: %s\n' "$label"
    else
        printf '  FAIL: %s expected=%s actual=%s\n' \
            "$label" "$expected" "$actual" >&2
        fail=1
    fi
}

fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$FLOOR" "$FLOOR" "$FLOOR"
expect direct_git_status CURRENT "$FLEET_SOURCE_STATUS"
expect direct_git_commit "$FLOOR" "$FLEET_SOURCE_COMMIT"
expect direct_source_kind legacy_40hex_source "$FLEET_SOURCE_KIND"
expect direct_git_date 2026-08-21T02:03:04+00:00 "$FLEET_SOURCE_COMMIT_DATE"
expect direct_git_behind 1 "$FLEET_SOURCE_BEHIND"

SOURCE_ID=$(printf 'a%.0s' {1..64})
fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$SOURCE_ID" "$HEAD_COMMIT" "$FLOOR"
expect bound_runtime_status CURRENT "$FLEET_SOURCE_STATUS"
expect bound_runtime_kind source_id_sha256 "$FLEET_SOURCE_KIND"
expect bound_runtime_date 2026-08-22T03:04:05+00:00 "$FLEET_SOURCE_COMMIT_DATE"

fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$SOURCE_ID" "" "$FLOOR"
expect unbound_runtime_status STALE "$FLEET_SOURCE_STATUS"
expect unbound_runtime_date UNKNOWN "$FLEET_SOURCE_COMMIT_DATE"
expect unbound_runtime_detail missing_or_invalid_git_sha "$FLEET_SOURCE_DETAIL"

MISSING=$(printf 'b%.0s' {1..40})
fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$SOURCE_ID" "$MISSING" "$FLOOR"
expect missing_commit_status STALE "$FLEET_SOURCE_STATUS"
expect missing_commit_date UNKNOWN "$FLEET_SOURCE_COMMIT_DATE"

fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$SOURCE_ID" "$FOREIGN" "$FLOOR"
expect nonancestor_status STALE "$FLEET_SOURCE_STATUS"
expect nonancestor_date 2026-08-20T06:07:08+00:00 "$FLEET_SOURCE_COMMIT_DATE"
expect nonancestor_detail source_commit_not_ancestor_of_observed_main "$FLEET_SOURCE_DETAIL"

fleet_source_status_audit "$TMP_REPO" "$HEAD_COMMIT" "$SOURCE_ID" "$BASE" "$FLOOR"
expect prefloor_status STALE "$FLEET_SOURCE_STATUS"
expect prefloor_flag yes "$FLEET_SOURCE_REQUIRED_FLOOR"

if [ "$fail" -ne 0 ]; then
    printf 'check_fleet_source_status: FAIL\n' >&2
    exit 1
fi
printf 'check_fleet_source_status: PASS\n'
