#!/usr/bin/env bash
# Hermetic first-4/4 capture and immutability checks.  No network or node.
set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/fleet_mesh_evidence.sh"
REFEREE="$SCRIPT_DIR/fleet_mesh_acceptance.sh"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/z23-fleet-mesh-evidence-XXXXXX")
cleanup() {
    case "$TMP_DIR" in
        /tmp/z23-fleet-mesh-evidence-*) rm -rf "$TMP_DIR" ;;
        *) printf 'check_fleet_mesh_evidence: refusing cleanup of %s\n' "$TMP_DIR" >&2 ;;
    esac
}
trap cleanup EXIT INT TERM

grep -q 'cli dumpstate status_frontdoor' "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: referee bypasses bounded status front door' >&2
    exit 1
}
if grep -q 'cli getblockchaininfo' "$REFEREE"; then
    echo 'check_fleet_mesh_evidence: recurring referee may exhaust RPC workers' >&2
    exit 1
fi

STATUS_FILE="$TMP_DIR/mesh.status"
EVIDENCE_FILE="$TMP_DIR/mesh.first-4of4.status"
printf 'MESH=3/4\nVERDICT=fail\n' >"$STATUS_FILE"
fleet_mesh_capture_first_full 3 4 "$STATUS_FILE" "$EVIDENCE_FILE" \
    2026-08-23T00:00:00Z "$(printf 'a%.0s' {1..40})"
[ ! -e "$EVIDENCE_FILE" ] || {
    echo 'check_fleet_mesh_evidence: captured a non-4/4 status' >&2
    exit 1
}

printf 'MESH=4/4\nVERDICT=pass\nNODE1_SOURCE_STATUS=CURRENT\nNODE2_SOURCE_STATUS=CURRENT\nNODE3_SOURCE_STATUS=CURRENT\nNODE4_SOURCE_STATUS=CURRENT\n' >"$STATUS_FILE"
FIRST_HEAD=$(printf 'b%.0s' {1..40})
fleet_mesh_capture_first_full 4 4 "$STATUS_FILE" "$EVIDENCE_FILE" \
    2026-08-23T01:02:03Z "$FIRST_HEAD"
[ "$FLEET_FIRST_FULL_CAPTURED" = yes ] || {
    echo 'check_fleet_mesh_evidence: first 4/4 was not captured' >&2
    exit 1
}
grep -q '^EVIDENCE_KIND=FIRST_MESH_4OF4$' "$EVIDENCE_FILE"
grep -q '^MESH=4/4$' "$EVIDENCE_FILE"
grep -q "^CAPTURED_HEAD=$FIRST_HEAD$" "$EVIDENCE_FILE"
FIRST_SHA=$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')

printf 'MESH=4/4\nVERDICT=pass\nOBSERVED_AT=later\n' >"$STATUS_FILE"
fleet_mesh_capture_first_full 4 4 "$STATUS_FILE" "$EVIDENCE_FILE" \
    2026-08-23T02:03:04Z "$(printf 'c%.0s' {1..40})"
[ "$FLEET_FIRST_FULL_CAPTURED" = no ] || {
    echo 'check_fleet_mesh_evidence: existing evidence reported recaptured' >&2
    exit 1
}
SECOND_SHA=$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')
[ "$FIRST_SHA" = "$SECOND_SHA" ] || {
    echo 'check_fleet_mesh_evidence: first 4/4 evidence was overwritten' >&2
    exit 1
}

fleet_mesh_silence_observe yes 0 NONE 2026-08-23T03:00:00Z 0 1000 240
[ "$FLEET_SILENT_COUNT" = 1 ]
[ "$FLEET_SILENT_SINCE" = 2026-08-23T03:00:00Z ]
case "$FLEET_SILENT_RECORD" in
    SILENT_PENDING:cycle=1/2:*:next_eligible_epoch=1240) ;;
    *) exit 1 ;;
esac

fleet_mesh_silence_observe yes "$FLEET_SILENT_COUNT" \
    "$FLEET_SILENT_SINCE" 2026-08-23T03:01:00Z 1000 1060 240
[ "$FLEET_SILENT_COUNT" = 1 ]
case "$FLEET_SILENT_RECORD" in
    SILENT_PENDING:cycle=1/2:*:next_eligible_epoch=1240) ;;
    *) exit 1 ;;
esac

fleet_mesh_silence_observe yes "$FLEET_SILENT_COUNT" \
    "$FLEET_SILENT_SINCE" 2026-08-23T03:05:00Z 1000 1300 240
[ "$FLEET_SILENT_COUNT" = 2 ]
case "$FLEET_SILENT_RECORD" in
    SILENT_PAST_TWO_CYCLES:since=2026-08-23T03:00:00Z:confirmed=2026-08-23T03:05:00Z:cycles=2) ;;
    *) exit 1 ;;
esac

fleet_mesh_silence_observe no "$FLEET_SILENT_COUNT" \
    "$FLEET_SILENT_SINCE" 2026-08-23T03:10:00Z 1300 1600 240
[ "$FLEET_SILENT_COUNT" = 0 ]
[ "$FLEET_SILENT_SINCE" = NONE ]
case "$FLEET_SILENT_RECORD" in ACTIVE:observed=*) ;; *) exit 1 ;; esac

printf 'check_fleet_mesh_evidence: PASS\n'
