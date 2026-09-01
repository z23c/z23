#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# network_disruption_recovery_stopwatch.sh — PROOF B: the wall-clock
# network-disruption RECOVERY gate. An already-at-tip client node survives
# an upstream peer OUTAGE (the upstream process is frozen with SIGSTOP, not
# killed — a clean network partition, not a crash/OOM) and re-catches
# network_tip once the peer resumes. Gated exactly the way
# cold_start_to_tip_stopwatch.sh gates C3: H* (the reducer's authoritative,
# provable tip) reaching network_tip off `dumpstate reducer_frontier` —
# never on "the FSM says at_tip".
#
# Modeled structurally on cold_start_to_tip_stopwatch.sh: same helper
# shapes (json_string / json_number_or_null / write_artifact), same
# exit-code contract, same artifact conventions (RUN_ID dir under build/,
# latest.txt pointer, the failure-legibility bundle). The one structural
# difference: this harness does NOT spawn the client node — the client is
# an already-running, already-at-tip node under test. This harness only
# (a) verifies the client is at tip, (b) SIGSTOPs the configured upstream
# PEER pid to simulate an outage, (c) SIGCONTs it after --cut-secs, and
# (d) times the client's own recovery back to network_tip. The upstream is
# ALWAYS SIGCONT'd on exit (EXIT/INT/TERM trap) — this harness must never
# leave a peer parked STOPped, even on a hard failure or a Ctrl-C.
#
# SAFETY: the upstream pid arrives as a bare number from an env var or a pid
# file, and this harness FREEZES it. A refuse-guard in the preflight (search
# for "REFUSE-GUARD") reads the target's own /proc argv and refuses, loudly and
# non-zero, unless it names a -datadir under /tmp. A process with no -datadir
# in argv is running on the DEFAULT datadir — that is the operator's live node,
# and it is a refusal, not a pass.
#
# Inputs:
#   --bin=PATH                | ZCL_ND_NODE_BIN     (default $REPO_ROOT/build/bin/zclassic23;
#                                the CLI binary used ONLY to issue read-only
#                                CLI-mode RPC calls — dumpstate/ops logs —
#                                against the already-running client. It need
#                                not be the exact binary the client process
#                                was launched from.)
#   --upstream-pid-file=PATH  | ZCL_ND_UPSTREAM_PID (a bare PID, no file)
#   --client-rpc=PORT         | ZCL_ND_CLIENT_RPCPORT
#   --client-datadir=PATH     | ZCL_ND_CLIENT_DATADIR
#   --cut-secs=N               ZCL_ND_CUT_SECS      (default 600)
#   --budget=N                 ZCL_ND_BUDGET_SECS   (default 600)
#   --sample=N                 (default 5)
#
# Exit codes (same contract as cold_start_to_tip_stopwatch.sh):
#   0  PASS           — client H* re-reached network_tip within budget
#                        after the upstream outage ended.
#   3  SEAM           — H* climbed back (real recovery progress) but budget
#                        expired before it caught network_tip.
#   4  STALLED-NAMED  — no recovery progress across the whole window, but
#                        an active named blocker (dumpstate blocker)
#                        explains why.
#   1  FAIL           — H* regressed during recovery, the client process
#                        died, the upstream died while frozen (not a clean
#                        partition test), or no progress AND no named
#                        blocker.
#   2  SKIP           — a prerequisite fixture is absent/not ready: node
#                        binary, client not RPC-reachable, client not
#                        already AT TIP before the cut starts, or the
#                        upstream PID is not a live process. Not a verdict
#                        on the recovery claim either way.
#   5  FRONTIER-BUSY-TIMEOUT — `dumpstate reducer_frontier` kept returning a
#                        partial `{"snapshot_status":"progress_store_busy",
#                        "retryable":true}` doc (no "hstar" field) for the
#                        entire busy-timeout window (--busy-timeout=SECS /
#                        ZCL_ND_FRONTIER_BUSY_TIMEOUT_SECS, default 120s) —
#                        this harness never observed a real frontier sample
#                        during recovery. Distinct from FAIL: an instrument
#                        failure ("we could not read the client's state"),
#                        not a claim about the client's actual recovery.
#
# Artifact: build/c3-netdisrupt-stopwatch/<RUN_ID>/proof.json, schema
# zcl.c3_netdisrupt_stopwatch_artifact.v1. On any non-PASS verdict, the same
# RUN_ID dir also gets frontier.json / blocker.json / ops.log.tail.txt (a
# bundle_capture_failed:true field records when any piece could not be
# captured — never a silent drop).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$REPO_ROOT/tools/scripts/stopwatch_json_lib.sh"

NODE_BIN="${ZCL_ND_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
UPSTREAM_PID_FILE=""
UPSTREAM_PID="${ZCL_ND_UPSTREAM_PID:-}"
CLIENT_RPCPORT="${ZCL_ND_CLIENT_RPCPORT:-}"
CLIENT_DATADIR="${ZCL_ND_CLIENT_DATADIR:-}"
CUT_SECS="${ZCL_ND_CUT_SECS:-600}"
BUDGET="${ZCL_ND_BUDGET_SECS:-600}"
SAMPLE_SECS=5
# Bounded window a persistently-busy progress_store may occupy before this
# harness gives up observing and reports FRONTIER-BUSY-TIMEOUT instead of
# silently folding busy reads into "no recovery progress" (see D6 / the
# is_busy_response()/rpc_frontier() comment below).
FRONTIER_BUSY_TIMEOUT_SECS="${ZCL_ND_FRONTIER_BUSY_TIMEOUT_SECS:-120}"

# ── argv: --bin=PATH / --upstream-pid-file=PATH / --client-rpc=PORT /
#    --client-datadir=PATH / --cut-secs=N / --budget=N / --sample=N /
#    --busy-timeout=N / --selftest. Flags win over env vars; env vars win
#    over the defaults above. --selftest runs the hermetic busy-JSON
#    classification self-check (is_busy_response()) and exits — no binary,
#    upstream pid, or network touched.
SELFTEST=0
for arg in "$@"; do
    case "$arg" in
        --bin=*)               NODE_BIN="${arg#--bin=}" ;;
        --upstream-pid-file=*) UPSTREAM_PID_FILE="${arg#--upstream-pid-file=}" ;;
        --client-rpc=*)        CLIENT_RPCPORT="${arg#--client-rpc=}" ;;
        --client-datadir=*)    CLIENT_DATADIR="${arg#--client-datadir=}" ;;
        --cut-secs=*)          CUT_SECS="${arg#--cut-secs=}" ;;
        --budget=*)             BUDGET="${arg#--budget=}" ;;
        --sample=*)              SAMPLE_SECS="${arg#--sample=}" ;;
        --busy-timeout=*)      FRONTIER_BUSY_TIMEOUT_SECS="${arg#--busy-timeout=}" ;;
        --selftest)            SELFTEST=1 ;;
        --*) echo "netdisrupt-stopwatch: unknown flag: $arg" >&2; exit 2 ;;
        *)   echo "netdisrupt-stopwatch: unexpected positional arg: $arg" >&2; exit 2 ;;
    esac
done

RUN_ID="${ZCL_ND_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
ARTIFACT_ROOT="${ZCL_ND_ARTIFACT_ROOT:-$REPO_ROOT/build/c3-netdisrupt-stopwatch}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"

start=0
cut_started_ts=0
first_hstar=""
max_hstar="-1"
last_hstar="-1"
last_network_tip="-1"
last_blocker_ids="-"
last_blocker_count="0"
upstream_liveness_state="unknown"
DISRUPTION_MECHANISM="sigstop_upstream_peer"
busy_streak_start=0

# json_escape/json_string/json_number_or_null/is_busy_response/jget: see
# stopwatch_json_lib.sh (sourced above) — same contract as
# cold_start_to_tip_stopwatch.sh's helpers of the same name.

# --selftest: hermetic classification self-check for is_busy_response() /
# the "hstar" field detector rpc_frontier() uses — canned JSON fixtures,
# no binary/network/upstream-pid touched. Exits before any real infra setup.
if [ "$SELFTEST" = "1" ]; then
    st_fail=0
    st_check() {  # desc, expect_rc, actual_rc
        if [ "$3" = "$2" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 (expected rc=$2 got rc=$3)"
            st_fail=1
        fi
    }
    st_busy_json='{"snapshot_status":"progress_store_busy","retryable":true}'
    st_good_json='{"hstar":123,"network_tip":456,"network_tip_read_ok":true}'
    st_other_json='{"error":"method not found"}'

    echo "netdisrupt-stopwatch: --selftest running canned-JSON checks"
    is_busy_response "$st_busy_json";  st_check "busy fixture IS recognized as busy" 0 $?
    is_busy_response "$st_good_json";  st_check "good hstar fixture NOT recognized as busy" 1 $?
    is_busy_response "$st_other_json"; st_check "unrelated-error fixture NOT recognized as busy" 1 $?
    is_busy_response "";               st_check "empty response NOT recognized as busy" 1 $?
    printf '%s' "$st_good_json" | grep -q '"hstar"'; st_check "good fixture has hstar field" 0 $?
    printf '%s' "$st_busy_json" | grep -q '"hstar"'; st_check "busy fixture has NO hstar field (would retry, not misread as -1)" 1 $?

    if [ "$st_fail" = 0 ]; then
        echo "netdisrupt-stopwatch: --selftest PASS"
        exit 0
    fi
    echo "netdisrupt-stopwatch: --selftest FAIL" >&2
    exit 1
fi

# capture_failure_bundle — same contract as cold_start_to_tip_stopwatch.sh's
# helper of the same name: on any non-pass verdict, snapshot frontier.json /
# blocker.json / ops.log.tail.txt against the CLIENT (the node under test —
# the upstream is a bare pid, not something we can RPC into). Sets
# BUNDLE_CAPTURE_FAILED=true if any piece could not be captured.
# FRONTIER_BUSY_AT_CAPTURE=true when frontier.json WAS captured but its
# content is a progress_store-busy partial doc (still written, only
# labeled — see D6).
capture_failure_bundle() {
    BUNDLE_CAPTURE_FAILED="false"
    FRONTIER_BUSY_AT_CAPTURE="false"
    local got_frontier=0 got_blocker=0 got_logs=0
    if [ -x "${NODE_BIN:-}" ] && [ -n "${CLIENT_RPCPORT:-}" ] && [ -n "${CLIENT_DATADIR:-}" ]; then
        "$NODE_BIN" -rpcport="$CLIENT_RPCPORT" -datadir="$CLIENT_DATADIR" dumpstate reducer_frontier \
            >"$ARTIFACT_DIR/frontier.json" 2>/dev/null && [ -s "$ARTIFACT_DIR/frontier.json" ] && got_frontier=1
        if [ "$got_frontier" = 1 ] && is_busy_response "$(cat "$ARTIFACT_DIR/frontier.json" 2>/dev/null)"; then
            FRONTIER_BUSY_AT_CAPTURE="true"
        fi
        "$NODE_BIN" -rpcport="$CLIENT_RPCPORT" -datadir="$CLIENT_DATADIR" dumpstate blocker \
            >"$ARTIFACT_DIR/blocker.json" 2>/dev/null && [ -s "$ARTIFACT_DIR/blocker.json" ] && got_blocker=1
        "$NODE_BIN" -rpcport="$CLIENT_RPCPORT" -datadir="$CLIENT_DATADIR" ops logs \
            --pattern='.' --since_secs=3600 --max_lines=500 --level=all \
            >"$ARTIFACT_DIR/ops.log.tail.txt" 2>/dev/null && [ -s "$ARTIFACT_DIR/ops.log.tail.txt" ] && got_logs=1
    fi
    if [ "$got_logs" = 0 ] && [ -n "${CLIENT_DATADIR:-}" ] && [ -f "$CLIENT_DATADIR/node.log" ]; then
        tail -200 "$CLIENT_DATADIR/node.log" >"$ARTIFACT_DIR/ops.log.tail.txt" 2>/dev/null && got_logs=1
    fi
    [ "$got_frontier" = 1 ] && [ "$got_blocker" = 1 ] && [ "$got_logs" = 1 ] || BUNDLE_CAPTURE_FAILED="true"
}

# snapshot_upstream_state — refreshes upstream_liveness_state to the
# freshest live/dead fact right before every artifact write, UNLESS a more
# specific terminal fact (died_while_stopped / stop_signal_failed) already
# explains the run — those are not overwritten by a later generic check.
snapshot_upstream_state() {
    case "$upstream_liveness_state" in
        died_while_stopped|stop_signal_failed) return 0 ;;
    esac
    if [ -n "${UPSTREAM_PID:-}" ]; then
        if kill -0 "$UPSTREAM_PID" 2>/dev/null; then
            upstream_liveness_state="alive"
        else
            upstream_liveness_state="dead"
        fi
    fi
}

write_artifact() {
    verdict="$1"; rc="$2"; reason="${3:-}"
    captured_at="$(date +%s)"
    elapsed=0
    [ "${start:-0}" -gt 0 ] && elapsed=$((captured_at - start))
    mkdir -p "$ARTIFACT_DIR" 2>/dev/null || return 0
    snapshot_upstream_state
    BUNDLE_CAPTURE_FAILED="false"
    FRONTIER_BUSY_AT_CAPTURE="false"
    [ "$verdict" != "pass" ] && capture_failure_bundle
    {
        printf '{\n'
        printf '  "schema": "zcl.c3_netdisrupt_stopwatch_artifact.v1",\n'
        printf '  "verdict": %s,\n' "$(json_string "$verdict")"
        printf '  "exit_code": %s,\n' "$rc"
        printf '  "reason": %s,\n' "$(json_string "$reason")"
        printf '  "wall_clock_seconds": %s,\n' "$(json_number_or_null "$elapsed")"
        printf '  "budget_seconds": %s,\n' "$(json_number_or_null "$BUDGET")"
        printf '  "cut_seconds": %s,\n' "$(json_number_or_null "$CUT_SECS")"
        printf '  "upstream_pid": %s,\n' "$(json_number_or_null "${UPSTREAM_PID:-}")"
        printf '  "disruption_mechanism": %s,\n' "$(json_string "$DISRUPTION_MECHANISM")"
        printf '  "upstream_liveness_state": %s,\n' "$(json_string "$upstream_liveness_state")"
        printf '  "client_rpcport": %s,\n' "$(json_number_or_null "${CLIENT_RPCPORT:-}")"
        printf '  "client_datadir": %s,\n' "$(json_string "${CLIENT_DATADIR:-}")"
        printf '  "node_bin": %s,\n' "$(json_string "$NODE_BIN")"
        printf '  "first_hstar": %s,\n' "$(json_number_or_null "${first_hstar:-}")"
        printf '  "max_hstar": %s,\n' "$(json_number_or_null "$max_hstar")"
        printf '  "final_hstar": %s,\n' "$(json_number_or_null "$last_hstar")"
        printf '  "final_network_tip": %s,\n' "$(json_number_or_null "$last_network_tip")"
        printf '  "reached_network_tip": %s,\n' "$([ "$verdict" = "pass" ] && printf true || printf false)"
        printf '  "bundle_capture_failed": %s,\n' "$BUNDLE_CAPTURE_FAILED"
        printf '  "frontier_busy_at_capture": %s\n' "$FRONTIER_BUSY_AT_CAPTURE"
        printf '}\n'
    } >"$ARTIFACT_DIR/proof.json"
    printf '%s\n' "$ARTIFACT_DIR" >"$ARTIFACT_ROOT/latest.txt" 2>/dev/null || true
    echo "netdisrupt-stopwatch: artifact=$ARTIFACT_DIR"
}

skip() { echo "netdisrupt-stopwatch: SKIP ($*)"; write_artifact "skip" 2 "$*"; exit 2; }
die()  { echo "netdisrupt-stopwatch: FAIL: $*" >&2; write_artifact "fail" 1 "$*"; exit 1; }

# ── preflight: resolve + validate every input (SKIP=2 on anything absent) ──
[ -x "$NODE_BIN" ] || skip "node binary absent/not executable: $NODE_BIN"

case "$CLIENT_RPCPORT" in ''|*[!0-9]*) skip "no valid --client-rpc / ZCL_ND_CLIENT_RPCPORT given" ;; esac
[ -n "$CLIENT_DATADIR" ] && [ -d "$CLIENT_DATADIR" ] || skip "client datadir absent: ${CLIENT_DATADIR:-<unset>}"
case "$CUT_SECS" in ''|*[!0-9]*) skip "invalid --cut-secs/ZCL_ND_CUT_SECS: $CUT_SECS" ;; esac
case "$BUDGET" in ''|*[!0-9]*) skip "invalid --budget/ZCL_ND_BUDGET_SECS: $BUDGET" ;; esac
case "$SAMPLE_SECS" in ''|*[!0-9]*) skip "invalid --sample: $SAMPLE_SECS" ;; esac

if [ -n "$UPSTREAM_PID_FILE" ]; then
    [ -r "$UPSTREAM_PID_FILE" ] || skip "upstream pid file unreadable: $UPSTREAM_PID_FILE"
    UPSTREAM_PID="$(tr -d '[:space:]' <"$UPSTREAM_PID_FILE")"
fi
case "$UPSTREAM_PID" in
    ''|*[!0-9]*) skip "no valid upstream PID (--upstream-pid-file= / ZCL_ND_UPSTREAM_PID)" ;;
esac
kill -0 "$UPSTREAM_PID" 2>/dev/null || skip "upstream PID $UPSTREAM_PID is not a live process"

# ── REFUSE-GUARD: never signal anything that is not a /tmp fixture ─────────
# This script SIGSTOPs the pid it is handed, and it is handed a bare number
# from an env var or a pid file. A stale pid file, a copy-pasted command or a
# reused pid is enough to freeze whatever owns that number instead — and on an
# operator's workstation the likeliest victim is their LIVE node. So a pid is
# only signallable here if its OWN argv names a -datadir under /tmp.
#
# No -datadir in argv is a REFUSAL, not a pass: that is precisely the process
# running on the default datadir (~/.zclassic-c23), i.e. the live node. Same
# rule as every other fixture in tools/scripts — /tmp datadir or nothing.
upstream_datadir_of() {  # $1=pid -> echoes its -datadir= value ('' if none)
    tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | sed -n 's/^-datadir=//p' | head -n 1
}
UPSTREAM_DATADIR="$(upstream_datadir_of "$UPSTREAM_PID")"
case "$UPSTREAM_DATADIR" in
    /tmp/*/*|/tmp/*)
        : ;;
    '')
        die "REFUSING to signal pid $UPSTREAM_PID: its argv names no -datadir, so it is running on the DEFAULT datadir. This drill freezes the process it is given; it only ever does that to a fixture node under /tmp." ;;
    *)
        die "REFUSING to signal pid $UPSTREAM_PID: its datadir is '$UPSTREAM_DATADIR', which is not under /tmp. This drill freezes the process it is given; it only ever does that to a fixture node under /tmp." ;;
esac
echo "netdisrupt-stopwatch: upstream pid $UPSTREAM_PID cleared the /tmp-fixture refuse-guard (datadir=$UPSTREAM_DATADIR)"

rpc() { "$NODE_BIN" -rpcport="$CLIENT_RPCPORT" -datadir="$CLIENT_DATADIR" "$@" 2>/dev/null; }

# dumpstate reads can transiently miss while the reducer drive holds the
# progress_store lock — `dumpstate reducer_frontier` then returns a PARTIAL
# doc, {"snapshot_status":"progress_store_busy","retryable":true}, with NO
# "hstar" field. Retry with bounded, growing backoff (1,1,2,3,5s — ~12s
# worst case per call) so a lock-contention blip never reads as a
# regression or an empty sample. Sets the global FRONTIER_LAST_BUSY=1 when
# every retry within this call still came back busy (0 otherwise) — the
# caller tracks a busy STREAK across sample ticks so a progress_store that
# never clears gets its own named verdict (FRONTIER_BUSY_TIMEOUT_SECS in
# the main loop) instead of silently degrading into "no recovery progress,
# no blocker" (silent-stall FAIL) — see D6. Same pattern as
# cold_start_to_tip_stopwatch.sh's rpc_frontier().
FRONTIER_LAST_BUSY=0
rpc_frontier() {
    local out="" backoff
    for backoff in 1 1 2 3 5 0; do
        out="$(rpc dumpstate reducer_frontier)"
        if printf '%s' "$out" | grep -q '"hstar"'; then
            FRONTIER_LAST_BUSY=0
            printf '%s' "$out"
            return 0
        fi
        [ "$backoff" = 0 ] && break
        sleep "$backoff"
    done
    if is_busy_response "$out"; then
        FRONTIER_LAST_BUSY=1
    else
        FRONTIER_LAST_BUSY=0
    fi
    printf '%s' "$out"
}

# client_pid_alive — best-effort liveness check via the datadir's own
# boot_datadir_lock pidfile (engine/composition/src/boot_datadir_lock.c writes the
# holder's plain-text pid to <datadir>/zclassic23.pid). Returns success
# (treated as "can't tell, don't fail on this alone") when the pidfile is
# absent/unreadable — RPC unreachability is still caught separately by
# rpc_frontier() returning empty fields.
client_pidfile="$CLIENT_DATADIR/zclassic23.pid"
client_pid_alive() {
    [ -f "$client_pidfile" ] || return 0
    local p
    p="$(tr -d '[:space:]' <"$client_pidfile" 2>/dev/null)"
    case "$p" in ''|*[!0-9]*) return 0 ;; esac
    kill -0 "$p" 2>/dev/null
}

# ALWAYS resume the upstream on exit — never leave a peer parked STOPped,
# even on a hard failure, a Ctrl-C, or an unexpected script error.
cleanup() {
    if [ -n "${UPSTREAM_PID:-}" ] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill -CONT "$UPSTREAM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "netdisrupt-stopwatch: bin=$NODE_BIN client_rpc=$CLIENT_RPCPORT client_datadir=$CLIENT_DATADIR upstream_pid=$UPSTREAM_PID cut=${CUT_SECS}s budget=${BUDGET}s sample=${SAMPLE_SECS}s"

# ── 1. verify the client is AT TIP before touching anything ────────────
pre_fj="$(rpc_frontier)"
pre_hs="$(jget "$pre_fj" hstar)";        [ -z "$pre_hs" ] && pre_hs="-1"
pre_nt="$(jget "$pre_fj" network_tip)";  [ -z "$pre_nt" ] && pre_nt="-1"
pre_nt_ok="$(printf '%s' "$pre_fj" | grep -oE '"network_tip_read_ok"[[:space:]]*:[[:space:]]*true')"

if [ -z "$pre_nt_ok" ] || [ "$pre_hs" = "-1" ] || ! [ "$pre_nt" -gt 0 ] 2>/dev/null; then
    skip "client RPC not reachable / reducer_frontier unreadable before cut (hstar=$pre_hs network_tip=$pre_nt)"
fi
if ! [ "$pre_hs" -ge "$pre_nt" ] 2>/dev/null; then
    skip "client not AT TIP before the cut (hstar=$pre_hs < network_tip=$pre_nt) — this harness proves RECOVERY, not first sync"
fi
echo "netdisrupt-stopwatch: client confirmed AT TIP before cut (hstar=$pre_hs network_tip=$pre_nt)"

# ── 2. cut the upstream: SIGSTOP, sleep cut-secs, SIGCONT ──────────────
start=$(date +%s)
cut_started_ts=$start
if ! kill -STOP "$UPSTREAM_PID" 2>/dev/null; then
    upstream_liveness_state="stop_signal_failed"
    die "could not SIGSTOP upstream pid $UPSTREAM_PID"
fi
echo "netdisrupt-stopwatch: upstream pid=$UPSTREAM_PID STOPped at t=0 — sleeping ${CUT_SECS}s"
sleep "$CUT_SECS"
if kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    kill -CONT "$UPSTREAM_PID" 2>/dev/null || true
else
    upstream_liveness_state="died_while_stopped"
fi
echo "netdisrupt-stopwatch: upstream pid=$UPSTREAM_PID CONTinued after $(($(date +%s) - cut_started_ts))s (state=$upstream_liveness_state)"

if [ "$upstream_liveness_state" = "died_while_stopped" ]; then
    die "upstream pid $UPSTREAM_PID died while frozen — not a clean network-partition test"
fi

# ── 3. time recovery: poll until H* re-catches network_tip ─────────────
printf '%-8s %-8s %-10s %-8s %s\n' "t(s)" "hstar" "net_tip" "tip_ok" "blockers"
printf '%-8s %-8s %-10s %-8s %s\n' "----" "-----" "-------" "------" "--------"

reached=0
while :; do
    now=$(date +%s); elapsed=$((now - start))
    if ! client_pid_alive; then
        echo "netdisrupt-stopwatch: client process DIED during recovery window (t=${elapsed}s)"
        die "client process died during recovery"
    fi

    fj="$(rpc_frontier)"
    bj="$(rpc dumpstate blocker)"

    hs="$(jget "$fj" hstar)";              [ -z "$hs" ] && hs="-1"
    nt="$(jget "$fj" network_tip)";        [ -z "$nt" ] && nt="-1"
    nt_ok="$(printf '%s' "$fj" | grep -oE '"network_tip_read_ok"[[:space:]]*:[[:space:]]*true')"
    bc="$(jget "$bj" active_count)";       [ -z "$bc" ] && bc="0"
    bids="$(printf '%s' "$bj" | tr -d '\n' |
            grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' |
            sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | paste -sd, -)"
    [ -z "$bids" ] && bids="-"

    printf '%-8s %-8s %-10s %-8s %s\n' "$elapsed" "$hs" "$nt" "${nt_ok:+yes}" "b=$bc:$bids"

    # Bounded busy-streak check: a progress_store that stays busy
    # (retryable:true, no "hstar") across the ENTIRE FRONTIER_BUSY_TIMEOUT_SECS
    # window means this harness never observed a real frontier sample in
    # that time — an instrument failure, not evidence recovery stalled.
    # Reported as its own named verdict, never folded into hstar=-1 / "no
    # recovery progress, no blocker" (see D6).
    if [ "$hs" = "-1" ] && [ "$FRONTIER_LAST_BUSY" = "1" ]; then
        [ "$busy_streak_start" = 0 ] && busy_streak_start="$now"
        busy_elapsed=$((now - busy_streak_start))
        if [ "$busy_elapsed" -ge "$FRONTIER_BUSY_TIMEOUT_SECS" ]; then
            echo "=== netdisrupt-stopwatch: FRONTIER-BUSY-TIMEOUT — progress_store_busy persisted ${busy_elapsed}s (>= ${FRONTIER_BUSY_TIMEOUT_SECS}s) with no hstar sample ever observed in that window ==="
            write_artifact "frontier_busy_timeout" 5 \
                "progress_store_busy persisted >= ${FRONTIER_BUSY_TIMEOUT_SECS}s (--busy-timeout); last raw frontier response: $fj"
            exit 5
        fi
    else
        busy_streak_start=0
    fi

    # H* must never regress — a real regression is a correctness bug, not
    # a timing seam. Read-misses (-1) are excluded, they are not regressions.
    if [ "$hs" != "-1" ] && [ "$last_hstar" != "-1" ] && [ "$hs" -lt "$last_hstar" ] 2>/dev/null; then
        die "H* REGRESSED during recovery: $last_hstar -> $hs at t=${elapsed}s (this is a correctness bug, not a budget seam)"
    fi
    if [ "$hs" != "-1" ]; then
        [ -z "$first_hstar" ] && first_hstar="$hs"
        last_hstar="$hs"
        [ "$hs" -gt "$max_hstar" ] 2>/dev/null && max_hstar="$hs"
    fi
    [ "$nt" != "-1" ] && last_network_tip="$nt"
    last_blocker_ids="$bids"; last_blocker_count="$bc"

    if [ -n "$nt_ok" ] && [ "$nt" -gt 0 ] 2>/dev/null && [ "$hs" != "-1" ] && [ "$hs" -ge "$nt" ] 2>/dev/null; then
        reached=1
        break
    fi

    [ "$elapsed" -ge "$BUDGET" ] && break
    sleep "$SAMPLE_SECS"
done

now=$(date +%s); elapsed=$((now - start))

if [ "$reached" = 1 ]; then
    echo "WALL_CLOCK_SECONDS=$elapsed"
    echo "=== netdisrupt-stopwatch: PASS — client re-reached network_tip=$last_network_tip in ${elapsed}s after a ${CUT_SECS}s upstream outage (budget ${BUDGET}s) ==="
    write_artifact "pass" 0 "client recovered to network_tip within budget after upstream outage"
    exit 0
fi

echo "WALL_CLOCK_SECONDS=$elapsed"
climbed=0
if [ -n "$first_hstar" ] && [ "$max_hstar" -gt "$first_hstar" ] 2>/dev/null; then
    climbed=1
fi

if [ "$climbed" = 1 ]; then
    echo "=== netdisrupt-stopwatch: SEAM — H* climbed ($first_hstar -> $max_hstar) but did not reach network_tip=$last_network_tip within ${BUDGET}s ==="
    write_artifact "seam" 3 "H* made forward recovery progress but did not catch network_tip within budget"
    exit 3
fi

if [ "${last_blocker_count:-0}" -gt 0 ] 2>/dev/null; then
    echo "=== netdisrupt-stopwatch: STALLED-NAMED — no recovery progress in ${BUDGET}s; active blocker(s): $last_blocker_ids ==="
    write_artifact "stalled-named" 4 "no recovery progress; named blocker(s): $last_blocker_ids"
    exit 4
fi

echo "netdisrupt-stopwatch: last known frontier hs=$last_hstar network_tip=$last_network_tip"
die "no recovery progress AND no named blocker in ${BUDGET}s after the upstream outage ended (silent-stall failure class)"
