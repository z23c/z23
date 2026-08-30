#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# netdisrupt_two_node_drill.sh — PROOF B, the SELF-CONTAINED variant:
# the net-disruption RECOVERY drill on an ISOLATED two-node regtest fixture
# THIS harness spawns itself. It is the runnable, end-to-end companion to
# tools/scripts/network_disruption_recovery_stopwatch.sh (which never spawns
# a node — it drills an already-running live client + a caller-supplied
# upstream pid). This one needs no live fixture at all: it stands up a
# throwaway miner + follower under /tmp on non-live 39xxx ports, proves the
# follower reaches the miner's tip, YANKS the network (SIGSTOP the miner —
# a clean partition, not a crash), holds silence for --cut-secs, restores
# it (SIGCONT), mines a fresh gap so there is real work to climb, and times
# how long the follower takes to auto-resume and re-catch the miner's tip
# WITHOUT a restart.
#
# The plan's proof pillar (docs/work/stopwatch-gates.md, PROOF B / MVP C3's
# sibling): "yank the network mid-sync, confirm the node auto-resumes and
# climbs." The headline metric is the RESUME LATENCY — time from the
# network coming back until the follower's first resumed block — recorded
# so the recovery-constants tightening has a measured baseline.
#
# WHY getblockcount (peer-tip height), not hstar, is the verdict signal here:
# on the mainnet-scale live node the sibling harness gates on `dumpstate
# reducer_frontier`'s hstar reaching network_tip (never "the FSM says
# at_tip"). On an isolated REGTEST pair the reliably-advancing, provable
# "the follower actually accepted+connected every one of the miner's blocks"
# signal is the active-chain height (getblockcount) — exactly what the
# sibling C7 gate (tools/scripts/two_node_peer_tip.sh /
# `make test-two-node-peer-tip`) uses and which is proven to advance in
# regtest. getblockcount is a concrete accepted-block height, NOT a
# self-reported sync-phase flag, so it honors "gate on H* CLIMB, not booted-
# without-FATAL". hstar / network_tip are still captured into the artifact
# as corroborating frontier evidence, never as the gate.
#
# SAFETY (mirrors isolated_node_env.sh + two_node_peer_tip.sh verbatim):
#   - /tmp-only datadirs (mktemp -d under /tmp/zcl23-ndrill-*).
#   - 39xxx isolation ports ONLY; every chosen port is checked against the
#     live refuse-set, against the reserved sibling-fixture set
#     {39070,39071,39072,39073} (a concurrent stopwatch-peer / two-node lane
#     owns those), AND ss(8)-LISTEN-probed before spawn (the authoritative
#     collision guard — a busy port SKIPs, it is never silently dodged).
#   - Each node spawned under setsid → its OWN process group; the miner is
#     ALWAYS SIGCONT'd and both groups are killed + both /tmp datadirs
#     rm -rf'd on EXIT/INT/TERM — this harness never leaks a node and never
#     leaves the miner parked STOPped.
#   - Never touches the live node, live datadir, zclassicd, or any live port.
#
# Inputs (flags win over env vars win over defaults):
#   --bin=PATH          | ZCL_ND2_NODE_BIN   (default $REPO_ROOT/build/bin/zclassic23)
#   --rpc-bin=PATH      | ZCL_ND2_RPC_BIN    (default $REPO_ROOT/build/bin/zcl-rpc)
#   --a-base=N          | ZCL_ND2_A_BASE     miner port quad base   (default 39040)
#   --b-base=N          | ZCL_ND2_B_BASE     follower port quad base(default 39050)
#   --dead-sink=N       | ZCL_ND2_DEAD_SINK  miner's dead -connect sink (default 39099)
#   --seed-blocks=N     | ZCL_ND2_SEED_BLOCKS  blocks mined before B joins (default 10)
#   --gap-blocks=N      | ZCL_ND2_GAP_BLOCKS   blocks mined AFTER restore  (default 8)
#   --cut-secs=N        | ZCL_ND2_CUT_SECS     silence window seconds (default 30)
#   --budget=N          | ZCL_ND2_BUDGET_SECS  post-restore recovery budget (default 120)
#   --sync-deadline=N   | ZCL_ND2_SYNC_DEADLINE initial-sync budget (default 120)
#   --rpc-warmup=N      | ZCL_ND2_RPC_WARMUP  per-node RPC warmup budget (default 60)
#   --sample=N          | ZCL_ND2_SAMPLE      recovery poll interval (default 2)
#   --selftest          run hermetic classification checks; spawns nothing.
#
# Exit codes (same five-way contract as network_disruption_recovery_stopwatch.sh):
#   0  PASS          — follower re-reached the miner's new tip within budget.
#   3  SEAM          — follower climbed past the pre-outage tip (real recovery
#                       progress) but did not catch the new tip within budget.
#   4  STALLED-NAMED — no climb, but an active named blocker (dumpstate
#                       blocker) explains why.
#   1  FAIL          — follower regressed, a spawned node died during
#                       recovery, or no climb AND no named blocker.
#   2  SKIP          — a precondition could not be established (binary/rpc-bin
#                       absent, a chosen port already LISTENing, miner would
#                       not mine the seed, or the follower never reached the
#                       miner's tip for the initial at-tip precondition). Not
#                       a verdict on the recovery claim either way.
#
# Artifact: build/netdisrupt-stopwatch/<RUN_ID>/proof.json, schema
# zcl.netdisrupt_two_node_stopwatch_artifact.v1. On any non-PASS verdict the
# same RUN_ID dir also gets frontier.json / blocker.json / a.node.log.tail /
# b.node.log.tail (a bundle_capture_failed:true field records any piece that
# could not be captured — never a silent drop).

set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

NODE_BIN="${ZCL_ND2_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_ND2_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
A_BASE="${ZCL_ND2_A_BASE:-39040}"
B_BASE="${ZCL_ND2_B_BASE:-39050}"
DEAD_SINK="${ZCL_ND2_DEAD_SINK:-39099}"
SEED_BLOCKS="${ZCL_ND2_SEED_BLOCKS:-10}"
GAP_BLOCKS="${ZCL_ND2_GAP_BLOCKS:-8}"
CUT_SECS="${ZCL_ND2_CUT_SECS:-30}"
BUDGET="${ZCL_ND2_BUDGET_SECS:-120}"
SYNC_DEADLINE="${ZCL_ND2_SYNC_DEADLINE:-120}"
RPC_WARMUP="${ZCL_ND2_RPC_WARMUP:-60}"
SAMPLE_SECS="${ZCL_ND2_SAMPLE:-2}"
SELFTEST=0

for arg in "$@"; do
    case "$arg" in
        --bin=*)           NODE_BIN="${arg#--bin=}" ;;
        --rpc-bin=*)       RPC_BIN="${arg#--rpc-bin=}" ;;
        --a-base=*)        A_BASE="${arg#--a-base=}" ;;
        --b-base=*)        B_BASE="${arg#--b-base=}" ;;
        --dead-sink=*)     DEAD_SINK="${arg#--dead-sink=}" ;;
        --seed-blocks=*)   SEED_BLOCKS="${arg#--seed-blocks=}" ;;
        --gap-blocks=*)    GAP_BLOCKS="${arg#--gap-blocks=}" ;;
        --cut-secs=*)      CUT_SECS="${arg#--cut-secs=}" ;;
        --budget=*)        BUDGET="${arg#--budget=}" ;;
        --sync-deadline=*) SYNC_DEADLINE="${arg#--sync-deadline=}" ;;
        --rpc-warmup=*)    RPC_WARMUP="${arg#--rpc-warmup=}" ;;
        --sample=*)        SAMPLE_SECS="${arg#--sample=}" ;;
        --selftest)        SELFTEST=1 ;;
        --*) echo "netdisrupt-two-node: unknown flag: $arg" >&2; exit 2 ;;
        *)   echo "netdisrupt-two-node: unexpected positional arg: $arg" >&2; exit 2 ;;
    esac
done

RUN_ID="${ZCL_ND2_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
ARTIFACT_ROOT="${ZCL_ND2_ARTIFACT_ROOT:-$REPO_ROOT/build/netdisrupt-stopwatch}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"

# ── Live-port refuse-set (verbatim from isolated_node_env.sh) ──────────
ND2_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# Reserved sibling-fixture ports: a concurrent stopwatch-peer / two-node
# lane owns these; refuse them outright (belt-and-suspenders over the ss
# LISTEN guard) per the workflow's hard rule.
ND2_RESERVED_PORTS="39070 39071 39072 39073"

# ── JSON helpers (same shapes as the sibling stopwatch scripts) ────────
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr '\n' ' '; }
json_string() { printf '"%s"' "$(json_escape "$1")"; }
json_number_or_null() { case "${1:-}" in ''|*[!0-9-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

# is_named_blocker — true iff a `dumpstate blocker` body carries at least one
# active blocker (active_count > 0). Used to tell STALLED-NAMED (a named
# blocker explains a stall) from a silent-stall FAIL.
is_named_blocker() {
    local bc
    bc="$(printf '%s' "$1" | grep -oE '"active_count"[[:space:]]*:[[:space:]]*[0-9]+' | head -1 | grep -oE '[0-9]+$')"
    [ -n "$bc" ] && [ "$bc" -gt 0 ] 2>/dev/null
}

# nd2_classify_terminal — the pure terminal-verdict decision table, factored
# out of the recovery loop's tail so it can be exercised hermetically by
# --selftest (the recovery loop itself needs a mineable regtest fixture, so
# this is the only way to prove the decision logic on a host where regtest
# minting is gated off). Args are already-reduced booleans (0/1):
#   $1 reached  — follower's height re-caught the miner's post-outage tip
#   $2 climbed  — follower's max height rose above the pre-outage tip
#   $3 blocked  — a named blocker (dumpstate blocker active_count>0) is active
# Precedence: PASS wins over SEAM wins over STALLED-NAMED wins over FAIL.
nd2_classify_terminal() {
    if [ "$1" = 1 ]; then echo "pass"; return 0; fi
    if [ "$2" = 1 ]; then echo "seam"; return 0; fi
    if [ "$3" = 1 ]; then echo "stalled-named"; return 0; fi
    echo "fail"
}

# ── --selftest: hermetic checks, spawns nothing ────────────────────────
if [ "$SELFTEST" = "1" ]; then
    st_fail=0
    st_check() { if [ "$3" = "$2" ]; then echo "  ok: $1"; else echo "  FAIL: $1 (expected $2 got $3)"; st_fail=1; fi; }
    echo "netdisrupt-two-node: --selftest running hermetic checks"

    # blocker classification
    is_named_blocker '{"active_count":2,"blockers":[]}'; st_check "active_count=2 IS a named blocker" 0 $?
    is_named_blocker '{"active_count":0,"blockers":[]}'; st_check "active_count=0 is NOT a named blocker" 1 $?
    is_named_blocker '{"foo":1}';                        st_check "no active_count is NOT a named blocker" 1 $?
    is_named_blocker '';                                 st_check "empty is NOT a named blocker" 1 $?

    # json number sanitizer
    st_check "json_number_or_null 42 -> 42" "42" "$(json_number_or_null 42)"
    st_check "json_number_or_null '' -> null" "null" "$(json_number_or_null '')"
    st_check "json_number_or_null abc -> null" "null" "$(json_number_or_null abc)"

    # port-refusal logic (static, no network)
    reserved_hit=0; for p in $ND2_RESERVED_PORTS; do [ "$p" = "39072" ] && reserved_hit=1; done
    st_check "39072 IS in the reserved sibling set" "1" "$reserved_hit"
    live_hit=0; for p in $ND2_LIVE_PORTS; do [ "$p" = "8033" ] && live_hit=1; done
    st_check "8033 IS in the live refuse-set" "1" "$live_hit"

    # terminal-verdict decision table (reached, climbed, blocked)
    st_check "reached           -> pass"          "pass"          "$(nd2_classify_terminal 1 0 0)"
    st_check "reached wins over climbed+blocked"  "pass"          "$(nd2_classify_terminal 1 1 1)"
    st_check "climbed (no reach) -> seam"         "seam"          "$(nd2_classify_terminal 0 1 0)"
    st_check "climbed wins over blocked"          "seam"          "$(nd2_classify_terminal 0 1 1)"
    st_check "no climb + blocker -> stalled-named" "stalled-named" "$(nd2_classify_terminal 0 0 1)"
    st_check "no climb + no blocker -> fail"      "fail"          "$(nd2_classify_terminal 0 0 0)"

    if [ "$st_fail" = 0 ]; then echo "netdisrupt-two-node: --selftest PASS"; exit 0; fi
    echo "netdisrupt-two-node: --selftest FAIL" >&2; exit 1
fi

# ── State ──────────────────────────────────────────────────────────────
DD_A=""; DD_B=""
PID_A=""; PID_B=""
PGID_A=""; PGID_B=""
ND2_CLEANED=0
start=0                 # recovery clock: set at SIGCONT (outage end)
pre_outage_tip="-1"     # miner tip the follower reached before the cut
post_outage_tip="-1"    # miner tip after the post-restore gap mine
first_resume_hstar=""   # legacy field name kept for schema familiarity
first_climb_height=""   # follower height at first observed climb past pre_outage_tip
resume_latency="-1"     # seconds from restore to first resumed block
max_height="-1"
last_height="-1"
last_hstar="-1"
last_network_tip="-1"
last_blocker_ids="-"
last_blocker_count="0"
DISRUPTION_MECHANISM="sigstop_miner_peer_two_node_regtest"
BUNDLE_CAPTURE_FAILED="false"

A_PORT=""; A_RPC=""; A_FS=""; A_HTTPS=""
B_PORT=""; B_RPC=""; B_FS=""; B_HTTPS=""

# ── Cleanup: SIGCONT the miner, kill BOTH groups, rm BOTH /tmp datadirs ─
nd2_kill_group() {
    local pgid="$1"
    [ -n "$pgid" ] || return 0
    kill -TERM "-$pgid" 2>/dev/null || true
    local i
    for i in $(seq 1 25); do
        kill -0 "-$pgid" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}
nd2_rm_datadir() {
    local dd="$1"
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    case "$dd" in
        /tmp/zcl23-ndrill-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) echo "netdisrupt-two-node: WARN: refusing to rm non-/tmp datadir '$dd'" >&2 ;;
    esac
}
nd2_cleanup() {
    [ "$ND2_CLEANED" = "1" ] && return 0
    ND2_CLEANED=1
    # ALWAYS resume the miner first — never leave a peer parked STOPped,
    # even on a hard failure or Ctrl-C (the miner is killed right after).
    [ -n "$PID_A" ] && kill -CONT "$PID_A" 2>/dev/null || true
    nd2_kill_group "$PGID_A"
    nd2_kill_group "$PGID_B"
    [ -n "$DD_A" ] && pkill -KILL -f -- "-datadir=$DD_A" 2>/dev/null || true
    [ -n "$DD_B" ] && pkill -KILL -f -- "-datadir=$DD_B" 2>/dev/null || true
    nd2_rm_datadir "$DD_A"
    nd2_rm_datadir "$DD_B"
}
trap nd2_cleanup EXIT INT TERM

# ── RPC helpers ────────────────────────────────────────────────────────
# zcl-rpc for generate/getblockcount/getpeerinfo (matches two_node_peer_tip.sh),
# the zclassic23 binary in CLI mode for dumpstate reducer_frontier/blocker
# (matches network_disruption_recovery_stopwatch.sh).
nd2_rpc() {  # $1=datadir $2=rpcport $3.. method+args
    local dd="$1" rp="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$rp" "$RPC_BIN" "$@" 2>/dev/null || true
}
a_rpc() { nd2_rpc "$DD_A" "$A_RPC" "$@"; }
b_rpc() { nd2_rpc "$DD_B" "$B_RPC" "$@"; }
nd2_blockcount() {
    local out
    out="$(nd2_rpc "$1" "$2" getblockcount)"
    printf '%s' "$out" | sed -n 's/.*"result"[: ]*\([0-9-]*\).*/\1/p'
}
b_dumpstate() {  # $1=subcommand (reducer_frontier|blocker)
    "$NODE_BIN" -rpcport="$B_RPC" -datadir="$DD_B" dumpstate "$1" 2>/dev/null || true
}
jget() {  # $1=json $2=key -> first integer value
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+" | head -1 | grep -oE -- '-?[0-9]+$'
}

# Refresh the follower's frontier evidence (hstar / network_tip) — captured
# as corroboration only, never the gate. Read-misses leave the prior value.
refresh_follower_frontier() {
    local fj hs nt
    fj="$(b_dumpstate reducer_frontier)"
    hs="$(jget "$fj" hstar)";       [ -n "$hs" ] && last_hstar="$hs"
    nt="$(jget "$fj" network_tip)"; [ -n "$nt" ] && [ "$nt" -ge 0 ] 2>/dev/null && last_network_tip="$nt"
}

b_pid_alive() { [ -n "$PID_B" ] && kill -0 "$PID_B" 2>/dev/null; }
a_pid_alive() { [ -n "$PID_A" ] && kill -0 "$PID_A" 2>/dev/null; }

# ── Failure-legibility bundle (only on non-PASS) ───────────────────────
capture_failure_bundle() {
    BUNDLE_CAPTURE_FAILED="false"
    local got_frontier=0 got_blocker=0 got_alogs=0 got_blogs=0
    if [ -x "$NODE_BIN" ] && [ -n "$DD_B" ] && [ -n "$B_RPC" ]; then
        b_dumpstate reducer_frontier >"$ARTIFACT_DIR/frontier.json" 2>/dev/null \
            && [ -s "$ARTIFACT_DIR/frontier.json" ] && got_frontier=1
        b_dumpstate blocker >"$ARTIFACT_DIR/blocker.json" 2>/dev/null \
            && [ -s "$ARTIFACT_DIR/blocker.json" ] && got_blocker=1
    fi
    if [ -n "$DD_A" ] && [ -f "$DD_A/node.log" ]; then
        tail -200 "$DD_A/node.log" >"$ARTIFACT_DIR/a.node.log.tail" 2>/dev/null && got_alogs=1
    fi
    if [ -n "$DD_B" ] && [ -f "$DD_B/node.log" ]; then
        tail -200 "$DD_B/node.log" >"$ARTIFACT_DIR/b.node.log.tail" 2>/dev/null && got_blogs=1
    fi
    [ "$got_frontier" = 1 ] && [ "$got_blocker" = 1 ] && [ "$got_alogs" = 1 ] && [ "$got_blogs" = 1 ] \
        || BUNDLE_CAPTURE_FAILED="true"
}

write_artifact() {
    local verdict="$1" rc="$2" reason="${3:-}"
    local captured_at elapsed=0
    captured_at="$(date +%s)"
    [ "${start:-0}" -gt 0 ] && elapsed=$((captured_at - start))
    mkdir -p "$ARTIFACT_DIR" 2>/dev/null || return 0
    BUNDLE_CAPTURE_FAILED="false"
    [ "$verdict" != "pass" ] && capture_failure_bundle
    {
        printf '{\n'
        printf '  "schema": "zcl.netdisrupt_two_node_stopwatch_artifact.v1",\n'
        printf '  "verdict": %s,\n' "$(json_string "$verdict")"
        printf '  "exit_code": %s,\n' "$rc"
        printf '  "reason": %s,\n' "$(json_string "$reason")"
        printf '  "wall_clock_seconds": %s,\n' "$(json_number_or_null "$elapsed")"
        printf '  "resume_latency_seconds": %s,\n' "$(json_number_or_null "$resume_latency")"
        printf '  "budget_seconds": %s,\n' "$(json_number_or_null "$BUDGET")"
        printf '  "cut_seconds": %s,\n' "$(json_number_or_null "$CUT_SECS")"
        printf '  "seed_blocks": %s,\n' "$(json_number_or_null "$SEED_BLOCKS")"
        printf '  "gap_blocks": %s,\n' "$(json_number_or_null "$GAP_BLOCKS")"
        printf '  "disruption_mechanism": %s,\n' "$(json_string "$DISRUPTION_MECHANISM")"
        printf '  "pre_outage_tip": %s,\n' "$(json_number_or_null "$pre_outage_tip")"
        printf '  "post_outage_tip": %s,\n' "$(json_number_or_null "$post_outage_tip")"
        printf '  "first_climb_height": %s,\n' "$(json_number_or_null "${first_climb_height:-}")"
        printf '  "max_height": %s,\n' "$(json_number_or_null "$max_height")"
        printf '  "final_height": %s,\n' "$(json_number_or_null "$last_height")"
        printf '  "final_hstar": %s,\n' "$(json_number_or_null "$last_hstar")"
        printf '  "final_network_tip": %s,\n' "$(json_number_or_null "$last_network_tip")"
        printf '  "reached_peer_tip": %s,\n' "$([ "$verdict" = "pass" ] && printf true || printf false)"
        printf '  "miner_rpcport": %s,\n' "$(json_number_or_null "${A_RPC:-}")"
        printf '  "follower_rpcport": %s,\n' "$(json_number_or_null "${B_RPC:-}")"
        printf '  "miner_datadir": %s,\n' "$(json_string "${DD_A:-}")"
        printf '  "follower_datadir": %s,\n' "$(json_string "${DD_B:-}")"
        printf '  "node_bin": %s,\n' "$(json_string "$NODE_BIN")"
        printf '  "bundle_capture_failed": %s\n' "$BUNDLE_CAPTURE_FAILED"
        printf '}\n'
    } >"$ARTIFACT_DIR/proof.json"
    printf '%s\n' "$ARTIFACT_DIR" >"$ARTIFACT_ROOT/latest.txt" 2>/dev/null || true
    echo "netdisrupt-two-node: artifact=$ARTIFACT_DIR"
}

skip() { echo "netdisrupt-two-node: SKIP ($*)"; write_artifact "skip" 2 "$*"; exit 2; }
die()  { echo "netdisrupt-two-node: FAIL: $*" >&2; write_artifact "fail" 1 "$*"; exit 1; }

# ── Port guards ────────────────────────────────────────────────────────
nd2_check_port() {  # SKIP (not fatal) on any violation
    local p="$1" lp
    case "$p" in ''|*[!0-9]*) skip "non-numeric port '$p'" ;; esac
    [ "$p" -ge 39000 ] && [ "$p" -le 39990 ] || skip "port $p out of the 39000-39990 isolation band"
    for lp in $ND2_LIVE_PORTS;     do [ "$p" = "$lp" ] && skip "port $p is in the live refuse-set"; done
    for lp in $ND2_RESERVED_PORTS; do [ "$p" = "$lp" ] && skip "port $p is reserved for a sibling fixture (39070-39073)"; done
    if [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ]; then
        skip "port $p is already LISTENing — a sibling fixture likely owns it (refusing, never dodging)"
    fi
    return 0
}

# ── Preflight ──────────────────────────────────────────────────────────
command -v ss     >/dev/null 2>&1 || skip "ss(8) not found (need iproute2 for the port preflight)"
command -v mktemp >/dev/null 2>&1 || skip "mktemp not found"
[ -x "$NODE_BIN" ] || skip "node binary absent/not executable: $NODE_BIN"
[ -x "$RPC_BIN" ]  || skip "zcl-rpc binary absent/not executable: $RPC_BIN"
for v in "$A_BASE" "$B_BASE" "$DEAD_SINK" "$SEED_BLOCKS" "$GAP_BLOCKS" \
         "$CUT_SECS" "$BUDGET" "$SYNC_DEADLINE" "$RPC_WARMUP" "$SAMPLE_SECS"; do
    case "$v" in ''|*[!0-9]*) skip "invalid non-numeric tunable: '$v'" ;; esac
done
[ "$GAP_BLOCKS" -ge 1 ] || skip "gap-blocks must be >= 1 so there is a real climb to time"

A_PORT="$A_BASE"; A_RPC=$((A_BASE + 1)); A_FS=$((A_BASE + 2)); A_HTTPS=$((A_BASE + 3))
B_PORT="$B_BASE"; B_RPC=$((B_BASE + 1)); B_FS=$((B_BASE + 2)); B_HTTPS=$((B_BASE + 3))

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "$DEAD_SINK"; do
    nd2_check_port "$p"
done

DD_A="$(mktemp -d /tmp/zcl23-ndrill-A-XXXXXX)" || skip "mktemp A failed"
DD_B="$(mktemp -d /tmp/zcl23-ndrill-B-XXXXXX)" || skip "mktemp B failed"
case "$DD_A" in /tmp/zcl23-ndrill-A-*) : ;; *) die "bad A datadir $DD_A" ;; esac
case "$DD_B" in /tmp/zcl23-ndrill-B-*) : ;; *) die "bad B datadir $DD_B" ;; esac
if [ -n "${HOME:-}" ]; then
    case "$DD_A" in "$HOME"/.zclassic-c23*) die "A datadir under live tree — refusing" ;; esac
    case "$DD_B" in "$HOME"/.zclassic-c23*) die "B datadir under live tree — refusing" ;; esac
fi

echo "netdisrupt-two-node: A{dd=$DD_A p2p=$A_PORT rpc=$A_RPC} B{dd=$DD_B p2p=$B_PORT rpc=$B_RPC} cut=${CUT_SECS}s budget=${BUDGET}s seed=$SEED_BLOCKS gap=$GAP_BLOCKS"

# ── Spawn a node in its own process group ──────────────────────────────
nd2_spawn() {  # $1=dd $2=p2p $3=rpc $4=fs $5=https $6=connect-target -> echoes PID(==PGID)
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" conn="$6"
    setsid "$NODE_BIN" \
        -datadir="$dd" -regtest \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$conn" \
        -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
        >"$dd/node.log" 2>&1 &
    echo "$!"
}
nd2_wait_rpc() {  # $1=dd $2=rpc $3=pid $4=secs
    local dd="$1" rp="$2" pid="$3" secs="$4" deadline t
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "netdisrupt-two-node: node (pid $pid) exited during RPC warmup (see $dd/node.log)" >&2
            return 1
        fi
        if [ -f "$dd/.cookie" ]; then
            t="$(nd2_blockcount "$dd" "$rp")"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}
nd2_wait_height() {  # $1=dd $2=rpc $3=pid $4=target $5=secs -> echoes final height, rc 0 on match
    local dd="$1" rp="$2" pid="$3" target="$4" secs="$5" deadline h
    deadline=$(( $(date +%s) + secs )); h="?"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "netdisrupt-two-node: node (pid $pid) died while waiting for height $target" >&2
            echo "$h"; return 1
        fi
        h="$(nd2_blockcount "$dd" "$rp")"; [ -n "$h" ] || h="?"
        [ "$h" != "?" ] && [ "$h" -ge "$target" ] 2>/dev/null && { echo "$h"; return 0; }
        sleep 1
    done
    echo "$h"; return 1
}

# ── Step 1: spawn miner A, seed the chain ──────────────────────────────
echo "netdisrupt-two-node: [1] spawn miner A + mine $SEED_BLOCKS regtest blocks..."
PID_A="$(nd2_spawn "$DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
PGID_A="$PID_A"
nd2_wait_rpc "$DD_A" "$A_RPC" "$PID_A" "$RPC_WARMUP" || skip "miner A RPC never came up (see $DD_A/node.log)"
a_rpc generate "$SEED_BLOCKS" >/dev/null
A_TIP="$(nd2_blockcount "$DD_A" "$A_RPC")"
[ "$A_TIP" = "$SEED_BLOCKS" ] || skip "miner A did not mine to height $SEED_BLOCKS (got ${A_TIP:-?}) — regtest generate unavailable"
echo "netdisrupt-two-node:     miner A tip after seed = $A_TIP"

# ── Step 2: spawn follower B, prove initial peer sync (the precondition) ─
echo "netdisrupt-two-node: [2] spawn follower B (connect-only -> A); wait <= ${SYNC_DEADLINE}s for B == $A_TIP..."
PID_B="$(nd2_spawn "$DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
PGID_B="$PID_B"
nd2_wait_rpc "$DD_B" "$B_RPC" "$PID_B" "$RPC_WARMUP" || skip "follower B RPC never came up (see $DD_B/node.log)"
if ! B_INIT="$(nd2_wait_height "$DD_B" "$B_RPC" "$PID_B" "$A_TIP" "$SYNC_DEADLINE")"; then
    echo "netdisrupt-two-node:     B peer view:"; b_rpc getpeerinfo | head -c 400; echo ""
    echo "netdisrupt-two-node:     B log tail:"; tail -8 "$DD_B/node.log" 2>/dev/null || true
    skip "follower B never reached miner tip $A_TIP within ${SYNC_DEADLINE}s (stuck at ${B_INIT:-?}) — initial-sync precondition unmet (this gate proves RECOVERY, not first sync; see test-two-node-peer-tip for first sync)"
fi
pre_outage_tip="$A_TIP"
last_height="$B_INIT"; max_height="$B_INIT"
echo "netdisrupt-two-node:     B synced to miner tip $A_TIP over native P2P (at-tip precondition met)."
refresh_follower_frontier

# ── Step 3: YANK the network — SIGSTOP the miner, hold silence ──────────
echo "netdisrupt-two-node: [3] YANK: SIGSTOP miner A (pid $PID_A) — clean partition; holding silence ${CUT_SECS}s..."
if ! kill -STOP "$PID_A" 2>/dev/null; then
    die "could not SIGSTOP miner A pid $PID_A"
fi
sleep "$CUT_SECS"
# The miner must still be a live (merely stopped) process — SIGSTOP cannot
# kill it; a dead miner here means something external reaped it, which
# invalidates the clean-partition test.
if ! a_pid_alive; then
    die "miner A died while frozen — not a clean network-partition test"
fi
# Confirm the follower saw no forward progress during the blackout (its only
# peer was silent). Not a hard gate — just recorded / logged.
b_during="$(nd2_blockcount "$DD_B" "$B_RPC")"; [ -n "$b_during" ] || b_during="?"
echo "netdisrupt-two-node:     during blackout: follower height = $b_during (pre-outage tip $pre_outage_tip)"

# ── Step 4: RESTORE — SIGCONT the miner, mine a fresh gap, start clock ──
echo "netdisrupt-two-node: [4] RESTORE: SIGCONT miner A; mining +$GAP_BLOCKS so there is real work to climb..."
kill -CONT "$PID_A" 2>/dev/null || true
start="$(date +%s)"      # recovery clock starts the instant the network is back
a_rpc generate "$GAP_BLOCKS" >/dev/null
post_outage_tip="$(nd2_blockcount "$DD_A" "$A_RPC")"; [ -n "$post_outage_tip" ] || post_outage_tip="-1"
if ! [ "$post_outage_tip" -ge "$((pre_outage_tip + 1))" ] 2>/dev/null; then
    die "miner A did not advance past the gap after restore (pre=$pre_outage_tip post=${post_outage_tip})"
fi
echo "netdisrupt-two-node:     miner A new tip = $post_outage_tip (was $pre_outage_tip); timing follower recovery (budget ${BUDGET}s)..."

# ── Step 5: time the recovery — poll until B re-catches the new tip ────
printf '%-8s %-10s %-10s %-10s %s\n' "t(s)" "b_height" "b_hstar" "b_nettip" "blockers"
printf '%-8s %-10s %-10s %-10s %s\n' "----" "--------" "-------" "--------" "--------"

reached=0
while :; do
    now="$(date +%s)"; elapsed=$((now - start))
    if ! b_pid_alive; then
        echo "netdisrupt-two-node: follower B process DIED during recovery (t=${elapsed}s)"
        die "follower B process died during recovery"
    fi

    h="$(nd2_blockcount "$DD_B" "$B_RPC")"; [ -n "$h" ] || h="-1"
    refresh_follower_frontier
    bj="$(b_dumpstate blocker)"
    bc="$(jget "$bj" active_count)"; [ -z "$bc" ] && bc="0"
    bids="$(printf '%s' "$bj" | tr -d '\n' |
            grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' |
            sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | paste -sd, -)"
    [ -z "$bids" ] && bids="-"

    printf '%-8s %-10s %-10s %-10s %s\n' "$elapsed" "$h" "$last_hstar" "$last_network_tip" "b=$bc:$bids"

    # follower height must never regress below the pre-outage tip.
    if [ "$h" != "-1" ] && [ "$h" -lt "$pre_outage_tip" ] 2>/dev/null; then
        die "follower B height REGRESSED during recovery: $pre_outage_tip -> $h at t=${elapsed}s (correctness bug, not a budget seam)"
    fi
    if [ "$h" != "-1" ]; then
        last_height="$h"
        [ "$h" -gt "$max_height" ] 2>/dev/null && max_height="$h"
        # First resumed block: the instant B climbs past the pre-outage tip.
        if [ -z "$first_climb_height" ] && [ "$h" -gt "$pre_outage_tip" ] 2>/dev/null; then
            first_climb_height="$h"
            resume_latency="$elapsed"
            echo "netdisrupt-two-node:     >> FIRST RESUMED BLOCK at t=${elapsed}s (height $pre_outage_tip -> $h)"
        fi
    fi
    last_blocker_ids="$bids"; last_blocker_count="$bc"

    if [ "$h" != "-1" ] && [ "$h" -ge "$post_outage_tip" ] 2>/dev/null; then
        reached=1; break
    fi
    [ "$elapsed" -ge "$BUDGET" ] && break
    sleep "$SAMPLE_SECS"
done

now="$(date +%s)"; elapsed=$((now - start))

if [ "$reached" = 1 ]; then
    echo "WALL_CLOCK_SECONDS=$elapsed"
    echo "RESUME_LATENCY_SECONDS=$resume_latency"
    echo "=== netdisrupt-two-node: PASS — follower re-caught miner tip=$post_outage_tip in ${elapsed}s (first resumed block at ${resume_latency}s) after a ${CUT_SECS}s outage; no restart ==="
    write_artifact "pass" 0 "follower auto-resumed and re-caught the miner's new tip within budget after the outage"
    exit 0
fi

echo "WALL_CLOCK_SECONDS=$elapsed"
echo "RESUME_LATENCY_SECONDS=$resume_latency"

# Reduce the observed run to the three booleans the pure decision table reads.
nd2_climbed=0
[ "$max_height" != "-1" ] && [ "$max_height" -gt "$pre_outage_tip" ] 2>/dev/null && nd2_climbed=1
nd2_blocked=0
if is_named_blocker "$(b_dumpstate blocker)" || [ "${last_blocker_count:-0}" -gt 0 ] 2>/dev/null; then
    nd2_blocked=1
fi
case "$(nd2_classify_terminal 0 "$nd2_climbed" "$nd2_blocked")" in
    seam)
        echo "=== netdisrupt-two-node: SEAM — follower climbed ($pre_outage_tip -> $max_height) but did not catch tip=$post_outage_tip within ${BUDGET}s ==="
        write_artifact "seam" 3 "follower made forward recovery progress but did not catch the new tip within budget"
        exit 3 ;;
    stalled-named)
        echo "=== netdisrupt-two-node: STALLED-NAMED — no recovery climb in ${BUDGET}s; active blocker(s): $last_blocker_ids ==="
        write_artifact "stalled-named" 4 "no recovery climb; named blocker(s): $last_blocker_ids"
        exit 4 ;;
esac
echo "netdisrupt-two-node: last follower height=$last_height hstar=$last_hstar network_tip=$last_network_tip"
die "no recovery climb AND no named blocker in ${BUDGET}s after the outage ended (silent-stall failure class)"
