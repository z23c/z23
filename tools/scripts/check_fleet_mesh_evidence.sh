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

# FACT 5 regression: the remote-peer path must not reintroduce a hard
# state==active requirement anywhere — that is the false negative that
# scored a healthy syncing_headers peer a failure.
if grep -q '"\$state" != active' "$REFEREE" || grep -q '"\$state" = active' "$REFEREE"; then
    echo 'check_fleet_mesh_evidence: remote-peer path hard-requires state==active' >&2
    exit 1
fi

# FACT 6 regression: a referee-local getblockcount failure must never be
# scored as a named gap against the remote node under test.
if grep -q 'local_tip_unreadable' "$REFEREE"; then
    echo 'check_fleet_mesh_evidence: referee-local read failure still misattributed to a remote node' >&2
    exit 1
fi
grep -q '^REFEREE_LOCAL_RPC_FAULT=""$' "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: missing single referee-local-fault field' >&2
    exit 1
}

# Extract one function's literal source text out of the referee script so
# these checks exercise the real implementation, not a hand-copied stand-in
# that could silently drift from it.
extract_fn() {
    local name="$1" file="$2"
    awk -v fn="$name" '
        $0 ~ "^" fn "\\(\\) \\{" { p = 1 }
        p { print }
        p && /^}/ { exit }
    ' "$file"
}

FN_SRC="$(extract_fn clean_detail "$REFEREE")"
[ -n "$FN_SRC" ] || {
    echo 'check_fleet_mesh_evidence: clean_detail not found in referee' >&2
    exit 1
}
eval "$FN_SRC"

FN_SRC="$(extract_fn classify_cli_failure "$REFEREE")"
[ -n "$FN_SRC" ] || {
    echo 'check_fleet_mesh_evidence: classify_cli_failure not found in referee' >&2
    exit 1
}
eval "$FN_SRC"

[ "$(classify_cli_failure 'Cannot connect to 127.0.0.1:18255')" = rpc_connection_failed ] || {
    echo 'check_fleet_mesh_evidence: connection failure misclassified' >&2
    exit 1
}
[ "$(classify_cli_failure 'RPC call failed')" = rpc_connection_failed ] || {
    echo 'check_fleet_mesh_evidence: connection failure misclassified' >&2
    exit 1
}
[ "$(classify_cli_failure 'Error: RPC server busy')" = 'rpc_error:RPC_server_busy' ] || {
    echo 'check_fleet_mesh_evidence: JSON-RPC error message not carried through' >&2
    exit 1
}
[ "$(classify_cli_failure 'Error: Method not found')" = 'rpc_error:Method_not_found' ] || {
    echo 'check_fleet_mesh_evidence: missing-leaf error message not carried through' >&2
    exit 1
}
[ "$(classify_cli_failure '')" = rpc_no_response ] || {
    echo 'check_fleet_mesh_evidence: silent failure misclassified' >&2
    exit 1
}

FN_SRC="$(extract_fn remote_peer_handshake_complete "$REFEREE")"
[ -n "$FN_SRC" ] || {
    echo 'check_fleet_mesh_evidence: remote_peer_handshake_complete not found in referee' >&2
    exit 1
}
eval "$FN_SRC"

# The product's ready ladder (app/controllers/src/status_native_helpers.c):
# every one of these states means VERSION/VERACK already completed.
for ready_state in handshake_complete active syncing_headers syncing_blocks \
    snapshot_serving snapshot_receiving; do
    remote_peer_handshake_complete "$ready_state" 170032 || {
        echo "check_fleet_mesh_evidence: $ready_state must be accepted (FACT 5)" >&2
        exit 1
    }
done
for not_ready_state in connecting version_sent version_received stale \
    disconnecting banned disconnected; do
    if remote_peer_handshake_complete "$not_ready_state" 170032; then
        echo "check_fleet_mesh_evidence: $not_ready_state must not be accepted" >&2
        exit 1
    fi
done
if remote_peer_handshake_complete active ""; then
    echo 'check_fleet_mesh_evidence: missing negotiated version must not be accepted' >&2
    exit 1
fi
if remote_peer_handshake_complete active 0; then
    echo 'check_fleet_mesh_evidence: zero protocol version must not be accepted' >&2
    exit 1
fi

# FACT 6: a referee-local RPC failure must classify honestly and never be
# silently swallowed. refresh_referee_local_tip is exercised against a
# stubbed cli() so this covers the real referee logic without a live node.
FN_SRC="$(extract_fn refresh_referee_local_tip "$REFEREE")"
[ -n "$FN_SRC" ] || {
    echo 'check_fleet_mesh_evidence: refresh_referee_local_tip not found in referee' >&2
    exit 1
}
eval "$FN_SRC"

REFEREE_LOCAL_TIP=""
REFEREE_LOCAL_RPC_FAULT=""
CLI_LAST_STDERR=""
# refresh_referee_local_tip calls cli() (which the real script runs inside a
# command substitution, i.e. a forked subshell) and then calls
# cli_read_stderr() as a separate, direct call to pull the diagnosis back
# into this shell — a subshell assignment inside cli() itself could never
# reach the caller. Stub the two functions apart, the same way.
cli() { printf '4242'; return 0; }
cli_read_stderr() { CLI_LAST_STDERR=""; }
refresh_referee_local_tip || {
    echo 'check_fleet_mesh_evidence: refresh_referee_local_tip should succeed on a clean read' >&2
    exit 1
}
[ "$REFEREE_LOCAL_TIP" = 4242 ] || {
    echo 'check_fleet_mesh_evidence: referee local tip not captured' >&2
    exit 1
}
[ -z "$REFEREE_LOCAL_RPC_FAULT" ] || {
    echo 'check_fleet_mesh_evidence: a clean read must not record a fault' >&2
    exit 1
}

REFEREE_LOCAL_TIP=""
REFEREE_LOCAL_RPC_FAULT=""
cli() { printf ''; return 1; }
cli_read_stderr() { CLI_LAST_STDERR='Error: RPC server busy'; }
if refresh_referee_local_tip; then
    echo 'check_fleet_mesh_evidence: refresh_referee_local_tip should fail on a busy RPC front door' >&2
    exit 1
fi
[ -z "$REFEREE_LOCAL_TIP" ] || {
    echo 'check_fleet_mesh_evidence: a failed read must not report a tip' >&2
    exit 1
}
[ "$REFEREE_LOCAL_RPC_FAULT" = 'rpc_error:RPC_server_busy' ] || {
    echo "check_fleet_mesh_evidence: got REFEREE_LOCAL_RPC_FAULT=$REFEREE_LOCAL_RPC_FAULT" >&2
    exit 1
}

# The field is reported once per cycle: a second, different failure must
# not overwrite the first diagnostic.
cli() { printf ''; return 1; }
cli_read_stderr() { CLI_LAST_STDERR='Cannot connect to 127.0.0.1:18255'; }
if refresh_referee_local_tip; then
    echo 'check_fleet_mesh_evidence: refresh_referee_local_tip should still fail' >&2
    exit 1
fi
[ "$REFEREE_LOCAL_RPC_FAULT" = 'rpc_error:RPC_server_busy' ] || {
    echo 'check_fleet_mesh_evidence: REFEREE_LOCAL_RPC_FAULT must record the first fault, not the latest' >&2
    exit 1
}

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
