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

REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
JSONQ="${FLEET_MESH_JSONQ:-$REPO_DIR/build/bin/jsonq}"
[ -x "$JSONQ" ] || {
    echo "check_fleet_mesh_evidence: jsonq is not built at $JSONQ (make jsonq)" >&2
    exit 1
}

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

# ── FACT 7: sync is judged on a CURRENT height, never the handshake one ──
#
# Same class as FACT 5. `startingheight` is the VERSION-message height, and
# lib/net/src/msgprocessor.c:2388 calls it handshake-static: it never updates
# for the life of the connection. Comparing it to our advancing tip could
# only hold by coincidence, and node2 — genuinely at the network tip — was
# scored tip_height_mismatch:peer=3225759 against a local 3226744 for it.
# These checks pin the replacement so it cannot be undone at one site.

grep -q 'remote_peer_at_local_tip "\$peer_height"' "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: remote-peer path does not judge tip parity through the shared predicate' >&2
    exit 1
}
if grep -q '\[ "\$peer_height" != "\$local_before" \]' "$REFEREE"; then
    echo 'check_fleet_mesh_evidence: remote-peer path still demands exact equality with a moving tip' >&2
    exit 1
fi
# The band is the product's own synced band. Widening it is the single edit
# that could convert a genuinely-behind peer into a mesh pass, so pin the
# literal and pin that it is not env-overridable.
grep -q '^MESH_TIP_LAG_BLOCKS=10$' "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: MESH_TIP_LAG_BLOCKS is not pinned to the node-health synced band (10)' >&2
    exit 1
}
grep -q "^#define ZCL_NODE_HEALTH_LAG_WARN_BLOCKS 10$" \
    "$REPO_DIR/app/services/include/services/node_health_service.h" || {
    echo 'check_fleet_mesh_evidence: node health synced band moved; MESH_TIP_LAG_BLOCKS must follow it' >&2
    exit 1
}

for fn in json_get json_count remote_peer_current_height \
    remote_peer_at_local_tip refresh_peer_height_votes; do
    FN_SRC="$(extract_fn "$fn" "$REFEREE")"
    [ -n "$FN_SRC" ] || {
        echo "check_fleet_mesh_evidence: $fn not found in referee" >&2
        exit 1
    }
    eval "$FN_SRC"
done

# Take the band from the referee itself rather than restating it here: the
# grep above already pins its value, and a second literal could drift.
eval "$(sed -n 's/^\(MESH_TIP_LAG_BLOCKS=[0-9][0-9]*\)$/\1/p' "$REFEREE")"
[ "${MESH_TIP_LAG_BLOCKS:-}" = 10 ] || {
    echo 'check_fleet_mesh_evidence: could not read MESH_TIP_LAG_BLOCKS from the referee' >&2
    exit 1
}

# One live accepted-header vote from peer id 7 at the network tip, and none
# for peer id 9. Same shape dumpstate quorum_oracle publishes
# (app/services/src/quorum_oracle_service.c:368-386).
VOTES='{"state":{"live_peer_votes":1,"peer_votes":[{"source_id":7,"source_class":"zclassic23_peer","height":3226744,"hash":"000005a174a85d15ad64000f70d81959a937af3f00f4e4e41c64fcbb36d9e546","ttl_age_seconds":42}]}}'
NO_VOTES='{"state":{"live_peer_votes":0,"peer_votes":[]}}'

# The live node2 case: handshake height a thousand blocks stale, current
# height at our tip. The old rule could not pass this and never would again.
NODE2_HANDSHAKE=3225759
LOCAL_BEFORE=3226744
LOCAL_AFTER=3226745
[ "$NODE2_HANDSHAKE" != "$LOCAL_BEFORE" ] && [ "$NODE2_HANDSHAKE" != "$LOCAL_AFTER" ] || {
    echo 'check_fleet_mesh_evidence: node2 fixture no longer reproduces the old false negative' >&2
    exit 1
}
RESOLVED="$(remote_peer_current_height "$VOTES" 7 "$NODE2_HANDSHAKE")"
[ "$RESOLVED" = "3226744:header_vote" ] || {
    echo "check_fleet_mesh_evidence: node2 current height resolved to $RESOLVED" >&2
    exit 1
}
remote_peer_at_local_tip "${RESOLVED%%:*}" "$LOCAL_BEFORE" "$LOCAL_AFTER" || {
    echo 'check_fleet_mesh_evidence: a peer at the network tip must pass' >&2
    exit 1
}
printf 'check_fleet_mesh_evidence: FIXTURE node2 handshake=%s current=%s local=%s/%s -> pass:version_verack:tip_height=%s:height_source=%s\n' \
    "$NODE2_HANDSHAKE" "${RESOLVED%%:*}" "$LOCAL_BEFORE" "$LOCAL_AFTER" \
    "${RESOLVED%%:*}" "${RESOLVED##*:}"

# The live node4 case: genuinely far behind and still catching up. It has no
# accepted-header vote because it has no chain to serve us, so it is judged
# on the handshake number and MUST still be a gap.
NODE4_HANDSHAKE=192
RESOLVED="$(remote_peer_current_height "$VOTES" 9 "$NODE4_HANDSHAKE")"
[ "$RESOLVED" = "192:handshake" ] || {
    echo "check_fleet_mesh_evidence: node4 current height resolved to $RESOLVED" >&2
    exit 1
}
if remote_peer_at_local_tip "${RESOLVED%%:*}" "$LOCAL_BEFORE" "$LOCAL_AFTER"; then
    echo 'check_fleet_mesh_evidence: a peer 3.2 million blocks behind must still be a gap' >&2
    exit 1
fi
printf 'check_fleet_mesh_evidence: FIXTURE node4 handshake=%s current=%s local=%s/%s -> fail:tip_height_mismatch:peer=%s:height_source=%s:handshake=%s:local_before=%s:local_after=%s\n' \
    "$NODE4_HANDSHAKE" "${RESOLVED%%:*}" "$LOCAL_BEFORE" "$LOCAL_AFTER" \
    "${RESOLVED%%:*}" "${RESOLVED##*:}" "$NODE4_HANDSHAKE" \
    "$LOCAL_BEFORE" "$LOCAL_AFTER"

# The gap token vocabulary is unchanged: the same condition keeps the same
# name, with the resolved height and its provenance added as detail.
grep -q 'tip_height_mismatch:peer=\$peer_height:height_source=\$height_source:handshake=\$peer_start_height' \
    "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: tip_height_mismatch detail no longer names the resolved height and its source' >&2
    exit 1
}

# One peer's vote must never vouch for another peer.
[ "$(remote_peer_current_height "$VOTES" 9 3226700)" = "3226700:handshake" ] || {
    echo "check_fleet_mesh_evidence: a vote leaked across source_id" >&2
    exit 1
}
# A vote can only ever RAISE the handshake height, never lower it.
[ "$(remote_peer_current_height "$VOTES" 7 3226800)" = "3226800:header_vote" ] || {
    echo 'check_fleet_mesh_evidence: a stale vote lowered a peer height' >&2
    exit 1
}
# No votes at all is the pre-existing handshake judgement, not an error.
[ "$(remote_peer_current_height "$NO_VOTES" 7 3226744)" = "3226744:handshake" ] || {
    echo 'check_fleet_mesh_evidence: an empty vote set must fall back to the handshake height' >&2
    exit 1
}
# An unreadable handshake height stays unreadable — never defaulted to zero.
if remote_peer_current_height "$VOTES" 7 absent; then
    echo 'check_fleet_mesh_evidence: an unreadable handshake height must not resolve' >&2
    exit 1
fi

# Band edges, both sides of the product's synced band.
remote_peer_at_local_tip 990 1000 1000 || {
    echo 'check_fleet_mesh_evidence: a peer exactly at the synced band edge must pass' >&2
    exit 1
}
if remote_peer_at_local_tip 989 1000 1000; then
    echo 'check_fleet_mesh_evidence: a peer one block past the synced band must fail' >&2
    exit 1
fi
# Ahead of us is not this peer's gap.
remote_peer_at_local_tip 1200 1000 1000 || {
    echo 'check_fleet_mesh_evidence: a peer ahead of our tip must pass' >&2
    exit 1
}
# The race window is judged against the height we held throughout it, in
# either sampling order, and it never manufactures a gap.
remote_peer_at_local_tip 1000 1000 1010 || {
    echo 'check_fleet_mesh_evidence: our own tip advancing must not score the peer a gap' >&2
    exit 1
}
remote_peer_at_local_tip 1000 1010 1000 || {
    echo 'check_fleet_mesh_evidence: the confirmed tip must be the lower of the two samples' >&2
    exit 1
}
# ...but a race must not launder a genuinely-behind peer into a pass.
if remote_peer_at_local_tip 500 1000 1010; then
    echo 'check_fleet_mesh_evidence: a behind peer passed through the race window' >&2
    exit 1
fi
# A stalled peer decays into a gap: its vote height freezes while our tip
# walks past the band.
remote_peer_at_local_tip 3226744 3226750 3226750 || {
    echo 'check_fleet_mesh_evidence: a peer still inside the band must pass' >&2
    exit 1
}
if remote_peer_at_local_tip 3226744 3226800 3226800; then
    echo 'check_fleet_mesh_evidence: a stalled peer must decay into a gap, not a pass' >&2
    exit 1
fi
# A non-numeric height is never a pass.
for bad in "" absent -1 3226744x; do
    if remote_peer_at_local_tip "$bad" 1000 1000; then
        echo "check_fleet_mesh_evidence: non-numeric peer height '$bad' passed" >&2
        exit 1
    fi
done

# The vote snapshot is read once per cycle and a failed read is THIS box's
# fault, classified exactly like a failed local tip read (FACT 6) so the
# caller records the node unknown instead of naming it in a gap.
PEER_HEIGHT_VOTES=""
PEER_HEIGHT_VOTES_STATE=unread
REFEREE_LOCAL_RPC_FAULT=""
CLI_LAST_STDERR=""
# The referee calls cli() inside a command substitution, i.e. a forked
# subshell, so a counter it incremented in a variable could never reach this
# shell. Tally the calls in a file, the same way the referee routes the CLI's
# stderr through one.
CLI_CALL_LOG="$TMP_DIR/cli_calls"
: >"$CLI_CALL_LOG"
cli() { printf 'x' >>"$CLI_CALL_LOG"; printf '%s' "$VOTES"; return 0; }
cli_read_stderr() { CLI_LAST_STDERR=""; }
refresh_peer_height_votes || {
    echo 'check_fleet_mesh_evidence: a healthy quorum_oracle read must succeed' >&2
    exit 1
}
[ "$PEER_HEIGHT_VOTES" = "$VOTES" ] || {
    echo 'check_fleet_mesh_evidence: vote snapshot not captured' >&2
    exit 1
}
refresh_peer_height_votes
CLI_CALLS="$(wc -c <"$CLI_CALL_LOG" | tr -d ' ')"
[ "$CLI_CALLS" = 1 ] || {
    echo "check_fleet_mesh_evidence: vote snapshot read $CLI_CALLS times in one cycle" >&2
    exit 1
}

PEER_HEIGHT_VOTES=""
PEER_HEIGHT_VOTES_STATE=unread
REFEREE_LOCAL_RPC_FAULT=""
cli() { printf ''; return 1; }
cli_read_stderr() { CLI_LAST_STDERR='Error: RPC server busy'; }
if refresh_peer_height_votes; then
    echo 'check_fleet_mesh_evidence: a failed quorum_oracle read must not report votes' >&2
    exit 1
fi
[ "$REFEREE_LOCAL_RPC_FAULT" = 'rpc_error:RPC_server_busy' ] || {
    echo "check_fleet_mesh_evidence: got REFEREE_LOCAL_RPC_FAULT=$REFEREE_LOCAL_RPC_FAULT" >&2
    exit 1
}

# A reply whose shape we cannot confirm fails closed. Reading it as "zero
# votes for everybody" would silently restore the handshake-height verdict
# for every peer, which is the defect this fact exists to prevent.
PEER_HEIGHT_VOTES=""
PEER_HEIGHT_VOTES_STATE=unread
REFEREE_LOCAL_RPC_FAULT=""
cli() { printf '%s' '{"state":{"peer_votes":[]}}'; return 0; }
cli_read_stderr() { CLI_LAST_STDERR=''; }
if refresh_peer_height_votes; then
    echo 'check_fleet_mesh_evidence: a reply without live_peer_votes must fail closed' >&2
    exit 1
fi
[ -n "$REFEREE_LOCAL_RPC_FAULT" ] || {
    echo 'check_fleet_mesh_evidence: an unconfirmed vote reply recorded no fault' >&2
    exit 1
}
# A node scored unknown on that failure must never be counted as a pass.
grep -q 'if ! refresh_peer_height_votes; then' "$REFEREE" || {
    echo 'check_fleet_mesh_evidence: remote-peer path does not gate on the vote snapshot' >&2
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
