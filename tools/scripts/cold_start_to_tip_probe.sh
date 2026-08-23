#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# cold_start_to_tip_probe.sh — empirical C3 settle: does a FRESH datadir boot
# from the current operator bundle, then forward-sync the remaining header/body
# delta from a serving zclassic23 peer, and reach at_tip at the peer tip within
# the budget? The fast cold_start gate proves only the seed authority (>1M
# UTXOs <90s) or the FSM transitions — neither proves the full operator claim
# (fresh datadir -> phase=at_tip). This probe is the long wall-clock proof for
# that full C3 claim.
#
# FULLY ISOLATED + NON-DESTRUCTIVE to the live node:
#   - /tmp-only datadir, isolated 39xxx ports (never the live 8033/18232 or the
#     soak 18242 or zclassicd 8034/8232),
#   - copies only public local fixtures (complete-state consensus-state-bundle
#     sqlite via the in-tree courier, or block_index.bin + utxo-seed snapshot),
#   - dials the serving zclassic23 peer (default P2P 8033) as a CLIENT only,
#   - -listen=0, -nolegacyimport (never reads ~/.zclassic), -nobgvalidation,
#   - process-group SIGKILL teardown on every exit.
#
# Fixture preference (product-aligned, never live datadir surgery):
#   1. consensus-state-bundle-<H>.sqlite  (complete-state; zero-flag autodetect
#      after deploy/zclassic23-bundle-bootstrap.sh stages it into
#      <datadir>/bundles/)
#   2. utxo-seed-*.snapshot + block_index.bin  (legacy assisted starter pack,
#      -load-snapshot-at-own-height)
#   3. consensus_snapshot.db  (legacy checkpoint snapshot)
#
# Complete-state install is a next-boot action (checkpoint_bundle_install_ready
# arms a durable request and self-respawns). This harness follows self_respawn_*
# breadcrumbs on the SAME datadir, same as systemd Restart=always.
#
# Exit: 0 reached at_tip at peer-tip within budget (C3 wrapper viable)
#       3 seeded authority but did NOT reach at_tip in budget (code seam)
#       2 SKIP (no bundle fixture / no serving peer / binaries absent, or the
#           legacy snapshot sits above the binary's compiled checkpoint
#           authority so consensus must refuse it — a stale-fixture/binary
#           mismatch, not a boot regression)
#       1 FAIL (harness/setup error)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
LEGACY_SNAPSHOT="${ZCL_C3_SNAPSHOT:-$HOME/.zclassic-c23/consensus_snapshot.db}"
BUNDLE_SNAP_CANDIDATES=(
    "$HOME"/.zclassic-c23-test/utxo-seed-*.snapshot
    "$HOME"/.zclassic-c23/utxo-seed-*.snapshot
)
CONSENSUS_BUNDLE_CANDIDATES=(
    "$HOME"/.zclassic-c23-test/bundles/consensus-state-bundle-*.sqlite
    "$HOME"/.zclassic-c23/bundles/consensus-state-bundle-*.sqlite
    "$HOME"/.zclassic-c23/consensus-state-bundle-*.sqlite
)
PEER="${ZCL_C3_PEER:-127.0.0.1:8033}"        # zclassic23 P2P — DIAL this for sync
# File-service seed for instant-on header-chain / ROM fetch. -connect=HOST:P2P
# is NOT a fileservice seed: boot_bundle_fetch_seeds refuses a -connect value
# that names a port (rewriting 8033→18034 previously pulled live chain state
# into sealed fixtures). Pass -fileservice explicitly. Default: same host as
# PEER, FS_PORT 18034. Set ZCL_C3_FILE_PEER empty to disable.
FS_PORT=18034
TIP_DATADIR="${ZCL_C3_TIP_DATADIR:-$HOME/.zclassic-c23}"
PEER_RPC="${ZCL_C3_PEER_RPC:-18232}"         # live zclassic23 RPC (read tip only)
BUDGET="${ZCL_C3_BUDGET_SECS:-600}"          # 10-minute MVP target
P2P=39070; RPC=39071; FS=39072; HTTPS=39073
BUNDLE_SUCCESS_PATTERN='-load-snapshot-at-own-height: coin set RE-SEEDED'
CONSENSUS_BUNDLE_SUCCESS_PATTERN='autodetected consensus bundle installed'
CONSENSUS_BUNDLE_REQUEST_PATTERN='install-on-next-boot request installed'
CONSENSUS_BUNDLE_MARKER='consensus-bundle-installed.marker'
BUNDLE_BOOTSTRAP="$REPO_ROOT/deploy/zclassic23-bundle-bootstrap.sh"
MAX_BOOTS="${ZCL_C3_MAX_BOOTS:-12}"
ARTIFACT_ROOT="${ZCL_C3_ARTIFACT_ROOT:-$REPO_ROOT/build/c3-probe}"
RUN_ID="${ZCL_C3_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"
DATADIR=""
PID=""
FILE_PEER=""
start=0
seeded=0
install_s=""
last_h=-1
last_hdr=-1
boots=1
declare -a LOAD_ARGS=()

# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$REPO_ROOT/tools/scripts/stopwatch_json_lib.sh"  # json_escape

json_string() {
    printf '"%s"' "$(json_escape "$1")"
}

json_number_or_null() {
    case "${1:-}" in
        ''|*[!0-9]*) printf 'null' ;;
        *) printf '%s' "$1" ;;
    esac
}

json_bool() {
    if [ "${1:-0}" = "1" ]; then
        printf 'true'
    else
        printf 'false'
    fi
}

write_artifact() {
    verdict="$1"
    rc="$2"
    reason="${3:-}"
    captured_at="$(date +%s)"
    elapsed=0
    if [ "${start:-0}" -gt 0 ]; then
        elapsed=$((captured_at - start))
    fi
    reached_at_tip=0
    [ "$verdict" = "pass" ] && reached_at_tip=1
    mkdir -p "$ARTIFACT_DIR" "$ARTIFACT_ROOT" 2>/dev/null || return 0
    {
        echo "schema=zcl.c3_probe_artifact.v1"
        echo "verdict=$verdict"
        echo "exit_code=$rc"
        echo "reason=$reason"
        echo "captured_at_unix=$captured_at"
        echo "elapsed_seconds=$elapsed"
        echo "peer=$PEER"
        echo "peer_tip=${PEER_TIP:-}"
        echo "budget_seconds=$BUDGET"
        echo "mode=${MODE:-unknown}"
        echo "seeded=$seeded"
        echo "install_seconds=${install_s:-}"
        echo "to_tip_seconds=$([ "$reached_at_tip" = 1 ] && echo "$elapsed" || echo "")"
        echo "reached_at_tip=$reached_at_tip"
        echo "last_height=$last_h"
        echo "last_headers=$last_hdr"
        echo "bundle_snapshot=${BUNDLE_SNAP:-}"
        echo "bundle_index=${BUNDLE_INDEX:-}"
        echo "file_peer=${FILE_PEER:-}"
        echo "scratch_datadir=${DATADIR:-}"
        echo "scratch_datadir_removed=true"
        echo "boots=$boots"
    } >"$ARTIFACT_DIR/summary.txt"
    {
        printf '{\n'
        printf '  "schema": "zcl.c3_probe_artifact.v2",\n'
        printf '  "api_version": "v1",\n'
        printf '  "verdict": %s,\n' "$(json_string "$verdict")"
        printf '  "exit_code": %s,\n' "$rc"
        printf '  "reason": %s,\n' "$(json_string "$reason")"
        printf '  "captured_at_unix": %s,\n' "$captured_at"
        printf '  "elapsed_seconds": %s,\n' "$elapsed"
        printf '  "budget_seconds": %s,\n' "$(json_number_or_null "$BUDGET")"
        printf '  "seed_authority_loaded": %s,\n' "$(json_bool "$seeded")"
        printf '  "install_seconds": %s,\n' "$(json_number_or_null "${install_s:-}")"
        printf '  "to_tip_seconds": %s,\n' "$(json_number_or_null "$([ "$reached_at_tip" = 1 ] && echo "$elapsed" || echo "")")"
        printf '  "reached_at_tip": %s,\n' "$(json_bool "$reached_at_tip")"
        printf '  "peer": %s,\n' "$(json_string "$PEER")"
        printf '  "peer_tip": %s,\n' "$(json_number_or_null "${PEER_TIP:-}")"
        printf '  "mode": %s,\n' "$(json_string "${MODE:-unknown}")"
        printf '  "last_height": %s,\n' "$(json_number_or_null "$last_h")"
        printf '  "last_headers": %s,\n' "$(json_number_or_null "$last_hdr")"
        printf '  "bundle_snapshot": %s,\n' "$(json_string "${BUNDLE_SNAP:-}")"
        printf '  "bundle_index": %s,\n' "$(json_string "${BUNDLE_INDEX:-}")"
        printf '  "file_peer": %s,\n' "$(json_string "${FILE_PEER:-}")"
        printf '  "scratch_datadir": %s,\n' "$(json_string "${DATADIR:-}")"
        printf '  "scratch_datadir_removed": true,\n'
        printf '  "boots": %s,\n' "$(json_number_or_null "$boots")"
        printf '  "artifacts": {\n'
        printf '    "summary_text": "summary.txt",\n'
        printf '    "probe_log": "probe.log",\n'
        printf '    "probe_tail": "probe.tail.log"\n'
        printf '  }\n'
        printf '}\n'
    } >"$ARTIFACT_DIR/proof.json"
    if [ -n "${DATADIR:-}" ] && [ -f "$DATADIR/probe.log" ]; then
        cp "$DATADIR/probe.log" "$ARTIFACT_DIR/probe.log" 2>/dev/null || true
        tail -80 "$DATADIR/probe.log" >"$ARTIFACT_DIR/probe.tail.log" 2>/dev/null || true
    fi
    printf '%s\n' "$ARTIFACT_DIR" >"$ARTIFACT_ROOT/latest.txt" 2>/dev/null || true
    echo "c3-probe: artifact=$ARTIFACT_DIR"
}

skip() { echo "c3-probe: SKIP ($*)"; write_artifact "skip" 2 "$*"; exit 2; }
die()  { echo "c3-probe: FAIL: $*" >&2; write_artifact "fail" 1 "$*"; exit 1; }

copy_fixture() {
    src="$1"
    dst="$2"
    cp --reflink=auto "$src" "$dst" 2>/dev/null || cp "$src" "$dst"
}

select_newest_bundle_snapshot() {
    newest_mtime=0
    newest_path=""
    for cand in "${BUNDLE_SNAP_CANDIDATES[@]}"; do
        [ -f "$cand" ] || continue
        size=$(stat -c %s "$cand" 2>/dev/null || echo 0)
        [ "$size" -gt $((10*1024*1024)) ] || continue
        mt=$(stat -c %Y "$cand" 2>/dev/null || echo 0)
        if [ "$mt" -ge "$newest_mtime" ]; then
            newest_mtime="$mt"
            newest_path="$cand"
        fi
    done
    printf '%s' "$newest_path"
}

# Parse height out of a canonical "consensus-state-bundle-<N>.sqlite" name,
# or -1 for any other name. Numeric, not lexicographic (unpadded heights
# lex-mis-sort: "...-9.sqlite" > "...-3056758.sqlite").
consensus_bundle_height() {
    local name="$1"
    local n
    case "$name" in
        consensus-state-bundle-*.sqlite)
            n="${name#consensus-state-bundle-}"
            n="${n%.sqlite}"
            case "$n" in
                ''|*[!0-9]*) printf '%s' '-1' ;;
                *) printf '%s' "$n" ;;
            esac
            ;;
        *) printf '%s' '-1' ;;
    esac
}

select_newest_consensus_bundle() {
    newest_h=-1
    newest_path=""
    newest_name=""
    for cand in "${CONSENSUS_BUNDLE_CANDIDATES[@]}"; do
        [ -f "$cand" ] || continue
        case "$cand" in
            *.sqlite) ;;
            *) continue ;;
        esac
        [ -e "${cand}.failed" ] && continue
        size=$(stat -c %s "$cand" 2>/dev/null || echo 0)
        [ "$size" -gt $((10*1024*1024)) ] || continue
        name="$(basename -- "$cand")"
        h="$(consensus_bundle_height "$name")"
        take=0
        if [ -z "$newest_path" ]; then
            take=1
        elif [ "$h" -ne "$newest_h" ]; then
            [ "$h" -gt "$newest_h" ] && take=1
        elif [ "$name" \> "$newest_name" ]; then
            take=1
        fi
        if [ "$take" = 1 ]; then
            newest_h="$h"
            newest_path="$cand"
            newest_name="$name"
        fi
    done
    printf '%s' "$newest_path"
}

# Same host as a P2P HOST:PORT, on the dedicated file-service port.
derive_file_peer() {
    local p2p="$1"
    local host="${p2p%:*}"
    [ -n "$host" ] && [ "$host" != "$p2p" ] || return 1
    printf '%s:%s' "$host" "$FS_PORT"
}

# True iff the boot-exit-reason.v1 `reason` is a supervised self-respawn
# request (self_respawn_tip_watchdog / self_respawn_supervisor_backstop /
# self_respawn_both). Matches tools/scripts/cold_start_to_tip_stopwatch.sh.
is_self_respawn_reason() {
    case "${1:-}" in
        self_respawn_*) return 0 ;;
        *)              return 1 ;;
    esac
}

read_exit_reason() {
    local f="${1:-$DATADIR/boot-exit-reason.v1}"
    [ -f "$f" ] || return 0
    sed -n 's/^reason=\(.*\)$/\1/p' "$f" 2>/dev/null | tail -1
}

run_selftest() {
    st_fail=0
    st_dir="$(mktemp -d /tmp/zcl-c3-probe-st.XXXXXX)" || {
        echo "c3-probe: --selftest FAIL: mktemp" >&2
        exit 1
    }
    st_check() {
        local name="$1" expected="$2" actual="$3"
        if [ "$expected" != "$actual" ]; then
            echo "c3-probe: --selftest FAIL: $name expected='$expected' got='$actual'" >&2
            st_fail=1
        fi
    }
    mkdir -p "$st_dir/bundles" "$st_dir/seed"
    CONSENSUS_BUNDLE_CANDIDATES=("$st_dir"/bundles/consensus-state-bundle-*.sqlite)
    got="$(select_newest_consensus_bundle)"
    st_check "empty bundles/ selects nothing" "" "$got"

    echo tiny >"$st_dir/bundles/consensus-state-bundle-9.sqlite"
    CONSENSUS_BUNDLE_CANDIDATES=("$st_dir"/bundles/consensus-state-bundle-*.sqlite)
    got="$(select_newest_consensus_bundle)"
    st_check "sub-10MiB sqlite is ignored" "" "$got"

    truncate -s 11M "$st_dir/bundles/consensus-state-bundle-9.sqlite"
    truncate -s 11M "$st_dir/bundles/consensus-state-bundle-3056758.sqlite"
    truncate -s 11M "$st_dir/bundles/consensus-state-bundle-100.sqlite"
    : >"$st_dir/bundles/consensus-state-bundle-100.sqlite.failed"
    CONSENSUS_BUNDLE_CANDIDATES=("$st_dir"/bundles/consensus-state-bundle-*.sqlite)
    got="$(select_newest_consensus_bundle)"
    case "$got" in
        */consensus-state-bundle-3056758.sqlite) got_ok=1 ;;
        *) got_ok=0 ;;
    esac
    st_check "numeric height wins (3056758 over 9; .failed 100 skipped)" "1" "$got_ok"

    is_self_respawn_reason "self_respawn_tip_watchdog"
    st_check "tip-watchdog respawn IS a respawn request" "0" "$?"
    is_self_respawn_reason "self_respawn_supervisor_backstop"
    st_check "backstop respawn IS a respawn request" "0" "$?"
    is_self_respawn_reason "self_respawn_both"
    st_check "both-respawn IS a respawn request" "0" "$?"
    is_self_respawn_reason "operator_or_external"
    st_check "operator/external exit is NOT a respawn request" "1" "$?"
    is_self_respawn_reason ""
    st_check "empty breadcrumb is NOT a respawn request" "1" "$?"
    is_self_respawn_reason "self_respawn"
    st_check "bare 'self_respawn' is NOT a known respawn reason" "1" "$?"

    printf 'reason=self_respawn_tip_watchdog\n' >"$st_dir/boot-exit-reason.v1"
    st_check "read_exit_reason parses breadcrumb" \
        "self_respawn_tip_watchdog" "$(read_exit_reason "$st_dir/boot-exit-reason.v1")"

    truncate -s 11M "$st_dir/seed/utxo-seed-100.snapshot"
    BUNDLE_SNAP_CANDIDATES=("$st_dir"/seed/utxo-seed-*.snapshot)
    got="$(select_newest_bundle_snapshot)"
    case "$got" in
        */utxo-seed-100.snapshot) got_ok=1 ;;
        *) got_ok=0 ;;
    esac
    st_check "utxo-seed fallback selector still works" "1" "$got_ok"

    st_check "derive_file_peer rewrites P2P host onto FS_PORT" \
        "127.0.0.1:18034" "$(derive_file_peer "127.0.0.1:8033")"
    st_check "derive_file_peer rejects a host with no port" \
        "" "$(derive_file_peer "127.0.0.1" || true)"

    rm -rf "$st_dir"
    if [ "$st_fail" != 0 ]; then
        echo "c3-probe: --selftest FAIL" >&2
        exit 1
    fi
    echo "c3-probe: --selftest PASS"
    exit 0
}

SELFTEST=0
for arg in "$@"; do
    case "$arg" in
        --selftest) SELFTEST=1 ;;
        --*) echo "c3-probe: unknown flag: $arg" >&2; exit 2 ;;
    esac
done
[ "$SELFTEST" = 1 ] && run_selftest

[ -x "$NODE_BIN" ] || skip "node binary absent: $NODE_BIN"
[ -x "$RPC_BIN" ]  || skip "zcl-rpc absent: $RPC_BIN"

peer_host="${PEER%:*}"
peer_port="${PEER##*:}"
[ -n "$peer_host" ] && [ -n "$peer_port" ] && [ "$peer_host" != "$peer_port" ] \
    || skip "invalid peer address: $PEER"
if ! timeout 3 bash -c "exec 3<>/dev/tcp/$peer_host/$peer_port" 2>/dev/null; then
    skip "serving peer not reachable: $PEER"
fi

# ZCL_C3_FILE_PEER unset → derive from PEER host + FS_PORT; empty → disable.
if [ -z "${ZCL_C3_FILE_PEER+x}" ]; then
    FILE_PEER="$(derive_file_peer "$PEER" || true)"
else
    FILE_PEER="${ZCL_C3_FILE_PEER}"
fi
if [ -n "$FILE_PEER" ]; then
    file_host="${FILE_PEER%:*}"
    file_port="${FILE_PEER##*:}"
    if [ -n "$file_host" ] && [ -n "$file_port" ] && [ "$file_host" != "$file_port" ] &&
       timeout 3 bash -c "exec 3<>/dev/tcp/$file_host/$file_port" 2>/dev/null; then
        echo "c3-probe: fileservice seed $FILE_PEER reachable — passing -fileservice (instant-on header/bundle fetch)"
    else
        echo "c3-probe: fileservice seed $FILE_PEER not reachable — continuing without -fileservice (P2P IBD only)"
        FILE_PEER=""
    fi
fi

# Reference peer tip (the target). zclassicd has no params on getblockcount.
PEER_TIP="$(ZCL_DATADIR="$TIP_DATADIR" ZCL_RPCPORT="$PEER_RPC" "$RPC_BIN" getblockcount 2>/dev/null \
            | sed -E 's/.*"result":(-?[0-9]+).*/\1/')"
printf '%s' "$PEER_TIP" | grep -qE '^[0-9]+$' || skip "tip source ($PEER_RPC) not answering getblockcount"
[ "$PEER_TIP" -gt 1000000 ] || skip "reference peer tip implausibly low ($PEER_TIP)"

DATADIR="$(mktemp -d /tmp/zcl-c3-probe.XXXXXX)" || die "mktemp datadir failed"
mkdir -p "$ARTIFACT_DIR" || die "artifact dir create failed: $ARTIFACT_DIR"
cleanup() {
    [ -n "$PID" ] && kill -KILL -- "-$PID" 2>/dev/null || true
    case "$DATADIR" in /tmp/zcl-c3-probe.*) rm -rf "$DATADIR" 2>/dev/null || true ;; esac
}
trap cleanup EXIT INT TERM

CONSENSUS_BUNDLE="${ZCL_C3_CONSENSUS_BUNDLE:-}"
if [ -z "$CONSENSUS_BUNDLE" ]; then
    CONSENSUS_BUNDLE="$(select_newest_consensus_bundle)"
fi

BUNDLE_SNAP="${ZCL_C3_BUNDLE_SNAPSHOT:-}"
BUNDLE_INDEX="${ZCL_C3_BLOCK_INDEX:-}"
if [ -z "$BUNDLE_SNAP" ]; then
    BUNDLE_SNAP="$(select_newest_bundle_snapshot)"
fi
if [ -n "$BUNDLE_SNAP" ] && [ -z "$BUNDLE_INDEX" ]; then
    BUNDLE_INDEX="$(dirname "$BUNDLE_SNAP")/block_index.bin"
fi

MODE="operator-bundle"
LOAD_ARGS=()
if [ -n "$CONSENSUS_BUNDLE" ] && [ -f "$CONSENSUS_BUNDLE" ] &&
   [ "$(stat -c %s "$CONSENSUS_BUNDLE" 2>/dev/null || echo 0)" -gt $((10*1024*1024)) ]; then
    MODE="consensus-state-bundle"
    BUNDLE_SNAP="$CONSENSUS_BUNDLE"
    BUNDLE_INDEX=""
    echo "c3-probe: peer=$PEER peer_tip=$PEER_TIP budget=${BUDGET}s datadir=$DATADIR"
    echo "c3-probe: using complete-state consensus-state-bundle: $CONSENSUS_BUNDLE"
    echo "c3-probe: bundle $(du -h "$CONSENSUS_BUNDLE" | cut -f1)"
    [ -x "$BUNDLE_BOOTSTRAP" ] || [ -f "$BUNDLE_BOOTSTRAP" ] \
        || die "in-tree courier absent: $BUNDLE_BOOTSTRAP"
    if ! bash "$BUNDLE_BOOTSTRAP" --source="$CONSENSUS_BUNDLE" --datadir="$DATADIR"; then
        die "consensus-state-bundle staging failed"
    fi
    staged="$(ls "$DATADIR"/bundles/consensus-state-bundle-*.sqlite 2>/dev/null | head -1)"
    [ -n "$staged" ] && [ -f "$staged" ] \
        || die "courier staged no consensus-state-bundle-*.sqlite under $DATADIR/bundles"
elif [ -n "$BUNDLE_SNAP" ] &&
   [ -f "$BUNDLE_SNAP" ] &&
   [ -f "$BUNDLE_INDEX" ] &&
   [ "$(stat -c %s "$BUNDLE_INDEX" 2>/dev/null || echo 0)" -gt $((10*1024*1024)) ]; then
    bundle_snap="$DATADIR/$(basename "$BUNDLE_SNAP")"
    echo "c3-probe: peer=$PEER peer_tip=$PEER_TIP budget=${BUDGET}s datadir=$DATADIR"
    echo "c3-probe: using operator bundle snapshot: $BUNDLE_SNAP"
    echo "c3-probe: using operator bundle block index: $BUNDLE_INDEX"
    echo "c3-probe: snapshot $(du -h "$BUNDLE_SNAP" | cut -f1), block_index $(du -h "$BUNDLE_INDEX" | cut -f1)"
    copy_fixture "$BUNDLE_SNAP" "$bundle_snap" || die "bundle snapshot copy failed"
    copy_fixture "$BUNDLE_INDEX" "$DATADIR/block_index.bin" || die "block_index.bin copy failed"
    LOAD_ARGS=("-load-snapshot-at-own-height=$bundle_snap")
elif [ -r "$LEGACY_SNAPSHOT" ]; then
    MODE="legacy-consensus-snapshot"
    echo "c3-probe: peer=$PEER peer_tip=$PEER_TIP budget=${BUDGET}s datadir=$DATADIR"
    echo "c3-probe: no complete operator bundle found; using legacy consensus snapshot: $LEGACY_SNAPSHOT"
    echo "c3-probe: legacy snapshot $(du -h "$LEGACY_SNAPSHOT" | cut -f1)"
    copy_fixture "$LEGACY_SNAPSHOT" "$DATADIR/consensus_snapshot.db" || die "legacy snapshot copy failed"
else
    skip "no operator bundle (consensus-state-bundle sqlite, or utxo-seed snapshot + block_index.bin) or legacy consensus_snapshot.db found"
fi

launch_node() {
    declare -a FILE_ARGS=()
    [ -n "${FILE_PEER:-}" ] && FILE_ARGS=(-fileservice="$FILE_PEER")
    setsid "$NODE_BIN" \
        -datadir="$DATADIR" \
        -port=$P2P \
        -rpcport=$RPC \
        -fsport=$FS \
        -httpsport=$HTTPS \
        -listen=0 \
        -connect="$PEER" \
        "${FILE_ARGS[@]}" \
        -nolegacyimport \
        -nobgvalidation \
        -showmetrics=0 \
        "${LOAD_ARGS[@]}" \
        >>"$DATADIR/probe.log" 2>&1 &
    PID=$!
}

mark_seeded() {
    [ "$seeded" = 0 ] || return 0
    seeded=1
    now=$(date +%s)
    if [ "${start:-0}" -gt 0 ]; then
        install_s=$((now - start))
    else
        install_s=0
    fi
    echo "c3-probe: C3_INSTALL_S=$install_s"
}

note_seed_ready() {
    [ "$seeded" = 0 ] || return 0
    if [ "$MODE" = "operator-bundle" ]; then
        seed_hit=$(grep -m1 -F -- "$BUNDLE_SUCCESS_PATTERN" "$DATADIR/probe.log" 2>/dev/null || true)
        if [ -n "$seed_hit" ]; then
            mark_seeded
            echo "c3-probe: seed authority ready — $seed_hit"
        fi
    elif [ "$MODE" = "consensus-state-bundle" ]; then
        if [ -f "$DATADIR/$CONSENSUS_BUNDLE_MARKER" ] ||
           grep -q -F -- "$CONSENSUS_BUNDLE_SUCCESS_PATTERN" "$DATADIR/probe.log" 2>/dev/null ||
           grep -q -F -- "$CONSENSUS_BUNDLE_REQUEST_PATTERN" "$DATADIR/probe.log" 2>/dev/null; then
            mark_seeded
            echo "c3-probe: seed authority ready — consensus-state-bundle installed"
        fi
    fi
}

echo "c3-probe: booting fresh node mode=$MODE (seed authority -> delta sync from $PEER) ..."
: >"$DATADIR/probe.log"
launch_node

start=$(date +%s)
reached=0
while :; do
    now=$(date +%s); elapsed=$((now - start))
    [ "$elapsed" -ge "$BUDGET" ] && break
    if ! kill -0 "$PID" 2>/dev/null; then
        reason="$(read_exit_reason)"
        if is_self_respawn_reason "$reason" && [ "$boots" -lt "$MAX_BOOTS" ]; then
            boots=$((boots + 1))
            echo "c3-probe: following self_respawn reason=$reason (boot $boots/$MAX_BOOTS t=${elapsed}s)"
            launch_node
            sleep 1
            continue
        fi
        echo "c3-probe: node EXITED early (t=${elapsed}s reason=${reason:-none}) — log tail:"
        tail -15 "$DATADIR/probe.log" | sed 's/^/  /'
        die "node process died before reaching at_tip"
    fi
    # getblockchaininfo is param-free and reports both blocks (connected tip)
    # and headers (header chain) — at_tip = both >= peer tip AND blocks==headers.
    note_seed_ready
    bci="$(ZCL_DATADIR="$DATADIR" ZCL_RPCPORT="$RPC" "$RPC_BIN" getblockchaininfo 2>/dev/null)"
    h="$(printf '%s' "$bci"   | sed -E 's/.*"blocks":(-?[0-9]+).*/\1/')"
    hdr="$(printf '%s' "$bci" | sed -E 's/.*"headers":(-?[0-9]+).*/\1/')"
    if printf '%s' "$h" | grep -qE '^[0-9]+$'; then
        last_hdr="${hdr:-?}"
        [ "$h" != "$last_h" ] && { echo "c3-probe: t=${elapsed}s blocks=$h headers=${hdr:-?}"; last_h="$h"; }
        [ "$h" -ge 1000000 ] && mark_seeded
        if [ "$h" -ge "$PEER_TIP" ] && printf '%s' "$hdr" | grep -qE '^[0-9]+$' \
           && [ "$hdr" -ge "$PEER_TIP" ] && [ "$h" -eq "$hdr" ]; then
            reached=1
            echo "c3-probe: REACHED at_tip blocks=$h headers=$hdr in ${elapsed}s"
            echo "c3-probe: C3_TO_TIP_S=$elapsed"
            break
        fi
    fi
    sleep 5
done

if [ "$reached" = 1 ]; then
    echo "=== c3-probe: PASS — fresh datadir -> snapshot import -> delta sync -> at_tip@$PEER_TIP within budget ==="
    write_artifact "pass" 0 "fresh datadir reached peer tip within budget"
    exit 0
fi
echo "c3-probe: did NOT reach at_tip in ${BUDGET}s (seeded=$seeded last_height=$last_h). Log tail:"
tail -20 "$DATADIR/probe.log" | sed 's/^/  /'
if [ "$seeded" = 1 ]; then
    echo "=== c3-probe: SEAM — seed authority loaded but forward-sync to at_tip did NOT complete within budget ==="
    write_artifact "seam" 3 "seed authority loaded but forward-sync did not complete within budget"
    exit 3
fi
if [ "$MODE" = "legacy-consensus-snapshot" ] && \
   grep -qE 'REFUSING peer snapshot.*above compiled checkpoint' "$DATADIR/probe.log" 2>/dev/null; then
    skip "legacy consensus snapshot is above this binary's compiled checkpoint authority — consensus correctly refused it (stale-fixture/binary mismatch, not a boot regression): remint the operator bundle (make bootstrap) or test a binary whose compiled checkpoints cover the snapshot"
fi
die "seed authority itself did not complete (<1M height/UTXOs) in budget"
