#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# node_slo_probe.sh — the EXTERNAL uptime prober (lane E3, Instant-Sync/
# Strength program). This is the scoreboard for "staying synced" that does
# NOT trust node self-reports: it is a separate client process that dials
# each local instance's RPC port the same way any outside caller would, and
# records what it actually got back — including nothing at all.
#
# Probes the DEPLOYED local instances by CLIENT-VIEWPOINT RPC (never
# in-process introspection):
#   canonical  rpcport 18232  datadir ~/.zclassic-c23      (platform/deploy/zclassic23.service)
#   dev        rpcport 18252  datadir ~/.zclassic-c23-dev  (platform/deploy/zcl23-dev.service)
# Ports/datadirs are hardcoded defaults (each also overridable via env, see
# below) rather than parsed from the unit files: the ports are a stable,
# documented contract (see CLAUDE.md "Running" + the unit files themselves),
# and a probe that could silently start reading a DIFFERENT port because a
# unit file comment changed is a worse failure mode than one that is
# explicit and greppable here.
#
# The instance table carries only instances that are actually DEPLOYED on
# this host. A row for an instance nobody runs answers reachable:false on
# every single poll forever, which (a) drags every uptime percentage derived
# from this ledger toward zero for a reason that has nothing to do with node
# health, and (b) trains every reader to ignore any_unreachable — the exact
# way a monitor goes blind. The soak lane (rpcport 18242, datadir
# ~/.zclassic-c23-soak) is such a case: its unit ships as an EXAMPLE
# (platform/deploy/examples/zclassic23-soak-node.service) and is not installed here,
# so it is not probed. Installing that unit means adding its row back to
# INSTANCES below — one line, and the example unit says so.
#
# Also reads the legacy zclassicd ORACLE as an external freshness reference —
# same oracle soak_evidence.sh uses. Its datadir/rpcport are resolved from the
# effective zclassicd.service command and zclassic.conf, with 8232 retained only
# as the compatibility fallback when neither source declares a port.
#
# Query mechanism: zcl-rpc getblockchaininfo (the same lightweight raw-RPC
# CLI soak_evidence.sh uses — NOT the native `z23 status` command,
# which returns the full ~15 KB diagnostic envelope and can take seconds to
# assemble on a loaded/wedged node; getblockchaininfo answers in single-digit
# milliseconds and carries both "blocks" (served height) and "headers"
# (validated header tip) in one call).
#
# Appends ONE JSON line per probe PER INSTANCE (one line per row of the
# instance table per collect run) to
# ~/.local/state/zclassic23-slo/uptime-ledger.jsonl:
#   ts               epoch the sample was taken
#   instance         "canonical" | "dev"
#   rpcport          the port probed
#   datadir          the datadir probed (client-side identity, not proof)
#   reachable        true iff the RPC answered with a parseable height
#   unreachable_streak
#                    how many CONSECUTIVE polls (this one included) this
#                    instance has failed to answer; 0 on a reachable
#                    sample. This is what separates "went down a minute
#                    ago" (streak 1) from "has been dark for a week"
#                    (streak 10000) without re-reading the whole ledger,
#                    and it is what makes a NEW outage legible next to an
#                    old one instead of both looking like one flat
#                    reachable:false wall
#   served_height    this instance's getblockchaininfo "blocks", or null
#   header_height    this instance's getblockchaininfo "headers"
#                    (validated header/target tip), or null
#   latency_ms       wall-clock round trip for the getblockchaininfo call,
#                    measured by THIS prober, or null when the call never
#                    returned (timeout) — measured even on failure so a
#                    slow-then-refused probe is distinguishable from an
#                    instant refusal
#   oracle_height    zclassicd getblockcount this cycle, or null
#   max_height       max(served_height) over all instances + oracle THIS
#                    cycle, or null if nothing answered
#   gap_vs_max       max_height - served_height, or null
#   gap_vs_oracle    oracle_height - served_height, or null (either side
#                    unreachable => null, never a fabricated 0)
#   error_detail     truncated raw RPC error/timeout text when unreachable,
#                    "" otherwise
#
# Six further dimensions, added because an availability ledger that carries
# only height cannot answer "was the node healthy while it was up". Each is
# read through tools/scripts/lib/evidence_sources.sh — the ONE reader per
# measurement in this repo — so this ledger can never disagree with
# lane_health.sh / soak_evidence.sh about the same host at the same instant:
#   peer_count       connected peers, counted client-side as the number of
#                    "addr" keys in getpeerinfo (evidence_peer_count_from_json,
#                    the definition lane_health.sh has always used). null
#                    when the instance was unreachable — 0 peers and
#                    "we could not ask" are different facts
#   rss_kb           VmRSS of the unit's MainPID from /proc/<pid>/status,
#                    the soak_harness-parity source (tools/soak/main.c)
#   datadir_bytes    `du -sb <datadir>` (evidence_dir_bytes). Measured at
#                    1 ms on the 18 GB canonical datadir (301 files), so it
#                    runs every sample; bounded by timeout regardless
#   nrestarts        systemd NRestarts for this instance's unit, or null.
#                    NOTE: this counts AUTOMATIC restarts only and a manual
#                    `systemctl restart` RESETS it — it is a hint here, not
#                    the intervention record. The record is
#                    tools/scripts/intervention_ledger.sh
#   active_enter_ts  epoch of systemd ActiveEnterTimestamp, or null
#   unit_active_state
#                    systemd ActiveState ("active"/"failed"/...), or ""
#
# ...plus three NODE SELF-REPORT fields, labelled as such because unlike
# everything above they are what the node says about itself rather than
# what this prober observed from outside. They are read ONLY when the
# client-viewpoint RPC already answered (asking a node that just refused a
# connection to describe its own health is both pointless and a way to turn
# one dead lane into a 10 s stall every minute):
#   onion_enabled    dumpstate explorer .onion_enabled — Tor health, true
#                    only when the embedded onion service is up
#   onion_address    dumpstate explorer .onion_address, "" when no onion
#   blocker_count    dumpstate blocker .active_count — the same call
#                    slo_page_if_stalled.sh already makes when it pages
#   blocker_primary  id of the first active blocker, "" when none
#   node_state_ok    true iff both self-report calls answered; false when
#                    the node was reachable for getblockchaininfo but could
#                    not answer dumpstate (a real and interesting state)
#
# An unreachable instance is NOT a probe failure — it IS the data point
# (same doctrine as soak_evidence.sh: a hole in the evidence is itself
# evidence). This script never exits non-zero because a NODE didn't answer;
# it exits non-zero only if it could not LOCK or APPEND to its own ledger.
#
# It does, however, get LOUDER rather than quieter as an outage ages: below
# ZCL_SLO_BLIND_STREAK consecutive misses an instance logs `WARN ...
# streak=N`, at or above it the line becomes `BLIND instance=... unreachable
# for N consecutive polls`, and the closing summary carries any_blind=1.
# A blind instance is either a node that needs fixing or a table row that
# needs deleting; both are actionable, and neither is background noise.
#
# Bounded ledger: rotates at 50 MB, keeping 2 rotated generations
# (uptime-ledger.jsonl.1, uptime-ledger.jsonl.2) plus the live file.
#
# Usage:
#   node_slo_probe.sh [collect]     # default action: one probe-and-append cycle
#   node_slo_probe.sh --selftest    # hermetic; fixture RPC commands, no nodes
#
# Env (test/operator injection seams):
#   ZCL_SLO_LEDGER_DIR      ledger dir (default ~/.local/state/zclassic23-slo)
#   ZCL_SLO_RPC_TIMEOUT_SEC per-instance RPC timeout (default 8)
#   ZCL_SLO_ROTATE_BYTES    rotation threshold (default 52428800 = 50 MiB)
#   ZCL_SLO_BLIND_STREAK    consecutive misses at which an instance is
#                           reported BLIND rather than merely unreachable
#                           (default 10 polls = 10 minutes at the standing
#                           60 s cadence)
#   ZCL_SLO_CANON_DATADIR / ZCL_SLO_CANON_RPCPORT
#                           explicit canonical binding; when absent, resolve
#                           the effective zclassic23.service ExecStart
#   ZCL_SLO_ORACLE_DATADIR / ZCL_SLO_ORACLE_RPCPORT
#                           explicit zclassicd binding; when absent, resolve
#                           the effective zclassicd.service ExecStart and its
#                           zclassic.conf
#   ZCL_SLO_CANON_CMD / ZCL_SLO_DEV_CMD / ZCL_SLO_ORACLE_CMD
#                           override the exact command run per instance
#                           (selftest injection seam — same pattern as
#                           soak_evidence.sh's ZCL_SOAK_RPC_CMD); the
#                           per-instance variable name is the 4th field of
#                           that instance's INSTANCES row
#   ZCL_SLO_CANON_PEERS_CMD / ZCL_SLO_DEV_PEERS_CMD
#                           same, for the getpeerinfo call (derived name:
#                           the row's command var with _CMD -> _PEERS_CMD)
#   ZCL_SLO_SHOW_CMD        override the systemd read; runs with the unit
#                           name exported as ZCL_SLO_UNIT
#   ZCL_SLO_RSS_CMD         override the VmRSS read; ZCL_SLO_PID exported
#   ZCL_SLO_DU_CMD          override the datadir size read; ZCL_SLO_DIR
#                           exported
#   ZCL_SLO_NODE_BIN        node binary used for the self-report dumpstate
#                           calls; set to "" to disable them entirely
#   ZCL_SLO_STATE_TIMEOUT_SEC
#                           per-dumpstate timeout (default 5). Two calls
#                           per REACHABLE instance, so this bounds the
#                           self-report cost of a hung-but-listening node
#
# No python (banned), no jq (installed but unused by repo convention) —
# bash + sed + flock only, same rule as soak_evidence.sh / replay_canary.sh.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# The ONE reader per measurement (peers, RSS, disk, systemd, node
# self-report, JSON emission). Sourcing is MANDATORY and its failure is
# fatal: silently losing six of this ledger's columns because a file moved
# is precisely the "we thought we were measuring it" failure this collector
# was extended to end.
EVIDENCE_LIB="$SCRIPT_DIR/lib/evidence_sources.sh"
if [ ! -r "$EVIDENCE_LIB" ]; then
    echo "node-slo-probe: FATAL missing reader library $EVIDENCE_LIB" >&2
    exit 3
fi
# shellcheck source=lib/evidence_sources.sh
. "$EVIDENCE_LIB"

LEDGER_DIR="${ZCL_SLO_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-slo}"
LEDGER_FILE="$LEDGER_DIR/uptime-ledger.jsonl"
STREAK_DIR="$LEDGER_DIR/streak"
RPC_TIMEOUT_SEC="${ZCL_SLO_RPC_TIMEOUT_SEC:-8}"
ROTATE_BYTES="${ZCL_SLO_ROTATE_BYTES:-52428800}"   # 50 MiB
BLIND_STREAK="${ZCL_SLO_BLIND_STREAK:-10}"
STATE_TIMEOUT_SEC="${ZCL_SLO_STATE_TIMEOUT_SEC:-5}"

# Cap on every host-side reader (systemctl, du, sha256). Deliberately
# tighter than the library default so this collector's WORST case stays
# under its unit's TimeoutStartSec:
#   per instance  = 8 (chaininfo) + 8 (peers) + 5 (systemctl) + 5 (du)
#                   + 2x5 (dumpstate)                      = 36 s
#   whole cycle   = 2 instances x 36 + 8 (oracle)          = 80 s
# against TimeoutStartSec=150 in deploy/zclassic23-slo-probe.service.
# Measured cost on a healthy box is ~0.25 s; these numbers exist so a
# wedged host cannot turn a 60 s collector into an overlapping one.
export ZCL_EVIDENCE_TIMEOUT_SEC="${ZCL_SLO_HOST_TIMEOUT_SEC:-5}"

# The canonical lane's datadir is an operator binding, not a repository
# default.  Read it from the effective unit so an A/B launcher or an
# isolated recovery lane is measured where it actually runs.  Selftests
# inject both values and therefore never inspect the host's live unit.
CANON_DATADIR="${ZCL_SLO_CANON_DATADIR:-}"
CANON_RPCPORT="${ZCL_SLO_CANON_RPCPORT:-}"
if [ "${1:-collect}" = "collect" ] &&
   { [ -z "$CANON_DATADIR" ] || [ -z "$CANON_RPCPORT" ]; }; then
    canonical_exec="$(evidence_systemd_show zclassic23.service ExecStart)"
    [ -n "$CANON_DATADIR" ] ||
        CANON_DATADIR="$(evidence_unit_exec_arg "$canonical_exec" datadir)"
    [ -n "$CANON_RPCPORT" ] ||
        CANON_RPCPORT="$(evidence_unit_exec_arg "$canonical_exec" rpcport)"
fi
[ -n "$CANON_DATADIR" ] || CANON_DATADIR="${HOME:-/root}/.zclassic-c23"
[ -n "$CANON_RPCPORT" ] || CANON_RPCPORT=18232

# zclassicd commonly carries rpcport in zclassic.conf rather than ExecStart.
# Read only an exact, uncommented numeric assignment; the last assignment wins,
# matching the daemon's normal config-file convention. This is display/routing
# input to a read-only probe, never authority over chain state.
oracle_rpcport_from_conf() {
    local conf="$1"
    [ -r "$conf" ] || return 0
    sed -n 's/^[[:space:]]*rpcport[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' \
        "$conf" | tail -n1
}

ORACLE_DATADIR="${ZCL_SLO_ORACLE_DATADIR:-}"
ORACLE_RPCPORT="${ZCL_SLO_ORACLE_RPCPORT:-}"
if [ "${1:-collect}" = "collect" ] &&
   { [ -z "$ORACLE_DATADIR" ] || [ -z "$ORACLE_RPCPORT" ]; }; then
    oracle_exec="$(evidence_systemd_show zclassicd.service ExecStart)"
    [ -n "$ORACLE_DATADIR" ] ||
        ORACLE_DATADIR="$(evidence_unit_exec_arg "$oracle_exec" datadir)"
    [ -n "$ORACLE_DATADIR" ] || ORACLE_DATADIR="${HOME:-/root}/.zclassic"
    if [ -z "$ORACLE_RPCPORT" ]; then
        ORACLE_RPCPORT="$(evidence_unit_exec_arg "$oracle_exec" rpcport)"
        if [ -z "$ORACLE_RPCPORT" ]; then
            oracle_conf="$(evidence_unit_exec_arg "$oracle_exec" conf)"
            [ -n "$oracle_conf" ] || oracle_conf="$ORACLE_DATADIR/zclassic.conf"
            case "$oracle_conf" in
                /*) ;;
                *) oracle_conf="$ORACLE_DATADIR/$oracle_conf" ;;
            esac
            ORACLE_RPCPORT="$(oracle_rpcport_from_conf "$oracle_conf")"
        fi
    fi
fi
[ -n "$ORACLE_DATADIR" ] || ORACLE_DATADIR="${HOME:-/root}/.zclassic"
case "$ORACLE_RPCPORT" in '' | *[!0-9]*) ORACLE_RPCPORT=8232 ;; esac

# ── instance table ────────────────────────────────────────────────────
# ONE list, probed in order. Row format:
#     name|rpcport|datadir|command-override-env-var|systemd-unit
#
# The 5th field is the systemd unit that owns the instance, and it is what
# makes rss_kb / nrestarts / active_enter_ts / unit_active_state
# attributable to a lane instead of to "the box". An empty 5th field means
# "not managed by a unit here" and those columns come out null.
# Membership rule: an instance belongs here only while it is DEPLOYED on
# this host. Deleting a lane means deleting its row (and the ledger stops
# carrying a permanently-null sample for it); installing a lane means adding
# one. Everything downstream — the ledger schema, the summary reader, the
# pager — is driven off whatever rows are here.
INSTANCES=(
    "canonical|$CANON_RPCPORT|$CANON_DATADIR|ZCL_SLO_CANON_CMD|zclassic23.service"
    "dev|18252|${HOME:-/root}/.zclassic-c23-dev|ZCL_SLO_DEV_CMD|zcl23-dev.service"
)
# systemd user services run with a minimal PATH that does not include
# ~/bin, so a bare `zcl-rpc` in the default probe commands would silently
# fail every probe under the installed timer even though it works fine
# from an interactive shell. Resolve an explicit path once: the operator's
# ~/bin/zcl-rpc symlink first (matches every interactive invocation on this
# box), then this checkout's own build output, then whatever PATH provides.
resolve_zcl_rpc_bin() {
    if [ -n "${ZCL_SLO_RPC_BIN:-}" ]; then printf '%s' "$ZCL_SLO_RPC_BIN"; return 0; fi
    local candidates=(
        "${HOME:-/root}/bin/zcl-rpc"
        "$SCRIPT_DIR/../../build/bin/zcl-rpc"
    )
    local c
    for c in "${candidates[@]}"; do
        [ -x "$c" ] && { printf '%s' "$c"; return 0; }
    done
    command -v zcl-rpc 2>/dev/null || printf 'zcl-rpc'
}
ZCL_RPC_BIN="$(resolve_zcl_rpc_bin)"

# Node binary for the two SELF-REPORT dumpstate calls (Tor health, typed
# blocker). Same resolution ladder and the same "explicit override always
# wins, even to empty" rule slo_page_if_stalled.sh uses, so setting
# ZCL_SLO_NODE_BIN= turns the self-report columns off rather than making
# them lie.
resolve_node_bin() {
    if [ -n "${ZCL_SLO_NODE_BIN+x}" ]; then printf '%s' "$ZCL_SLO_NODE_BIN"; return 0; fi
    local candidates=(
        "$SCRIPT_DIR/../../build/bin/zclassic23"
        "${HOME:-/root}/.local/bin/zclassic23-live"
    )
    local c
    for c in "${candidates[@]}"; do
        [ -x "$c" ] && { printf '%s' "$c"; return 0; }
    done
    command -v zclassic23 2>/dev/null || printf ''
}
NODE_BIN="$(resolve_node_bin)"

# ── helpers ────────────────────────────────────────────────────────────
# jnum/jstr/json_escape delegate to the shared readers so this ledger and
# every other one in tools/scripts escape identically. The local names stay
# because they are the vocabulary of the rest of this file.

# jnum <value>: print the value, or JSON null when empty/non-numeric.
jnum() { evidence_jnum "${1:-}"; }

# jstr <value>: print a JSON string literal (escaped), "" on empty.
json_escape() { evidence_json_escape "${1:-}"; }
jstr() { evidence_jstr "${1:-}"; }

# jbool <value>: JSON true/false, or null when the value was not measured.
jbool() { evidence_jbool "${1:-}"; }

# rpc_probe <default-cmd> <override-var-name>: run the (possibly overridden)
# command, print "<served>\x1f<header>\x1f<latency_ms>\x1f<raw-tail>". Never
# raises — a failing/timing-out command still yields a line with empty
# served/header, matching the soak_evidence.sh "|| true" doctrine so set -e
# cannot turn an unreachable node into a script abort.
rpc_probe() {
    local default_cmd="$1" override_var="$2" cmd
    cmd="${!override_var:-$default_cmd}"
    local t0 t1 out served header latency_ms
    t0="$(date +%s%N)"
    out="$(bash -c "$cmd" 2>&1 || true)"
    t1="$(date +%s%N)"
    latency_ms=$(( (t1 - t0) / 1000000 ))
    served="$(printf '%s' "$out" | sed -n 's/.*"blocks":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
    header="$(printf '%s' "$out" | sed -n 's/.*"headers":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
    local raw_tail=""
    if [ -z "$served" ]; then
        raw_tail="$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-200)"
        [ -n "$raw_tail" ] || raw_tail="empty_response"
    fi
    printf '%s\x1f%s\x1f%s\x1f%s' "$served" "$header" "$latency_ms" "$raw_tail"
}

field() { printf '%s' "$1" | cut -d $'\x1f' -f"$2"; }

# rotate_ledger_if_needed: logrotate-style, 2 kept generations, run BEFORE
# this cycle's lines are appended so a rotation never splits one run's
# 3 lines across two files.
rotate_ledger_if_needed() {
    [ -f "$LEDGER_FILE" ] || return 0
    local size
    size="$(stat -c %s "$LEDGER_FILE" 2>/dev/null || echo 0)"
    case "$size" in ''|*[!0-9]*) size=0 ;; esac
    if [ "$size" -ge "$ROTATE_BYTES" ]; then
        [ -f "$LEDGER_FILE.2" ] && rm -f "$LEDGER_FILE.2"
        [ -f "$LEDGER_FILE.1" ] && mv "$LEDGER_FILE.1" "$LEDGER_FILE.2"
        mv "$LEDGER_FILE" "$LEDGER_FILE.1"
        echo "node-slo-probe: rotated ledger (size=$size bytes >= $ROTATE_BYTES)" >&2
    fi
}

# append_line <json-line>: flock-serialized append (bounded -w 30, explicit
# failure) — the shared implementation, so a timer run and an ad-hoc
# operator run can never interleave a torn line.
append_line() { evidence_append_line "$LEDGER_FILE" "$1" "node-slo-probe"; }

# ── per-instance host + node facts ─────────────────────────────────────
# Everything below is measured through the shared readers. Nothing here can
# fail a collect: an unreadable /proc, an absent unit, a missing node binary
# each yield an empty string that becomes JSON null in the sample.

# host_facts <unit> <datadir>: one systemctl round trip for four properties
# plus the two filesystem reads, printed as
#   <nrestarts>\x1f<aet_epoch>\x1f<active_state>\x1f<rss_kb>\x1f<datadir_bytes>
# One round trip rather than four matters: at a 60 s cadence over two
# instances, four extra `systemctl show` forks per sample is most of the
# added cost of the whole extension.
host_facts() {
    local unit="$1" datadir="$2"
    local show_out="" nrestarts="" aet_epoch="" active_state="" mainpid=""
    local rss_kb="" dir_bytes=""

    if [ -n "${ZCL_SLO_SHOW_CMD:-}" ]; then
        show_out="$(ZCL_SLO_UNIT="$unit" bash -c "$ZCL_SLO_SHOW_CMD" 2>/dev/null || true)"
    elif [ -n "$unit" ]; then
        show_out="$(evidence_systemd_show "$unit" \
            NRestarts ActiveEnterTimestamp ActiveState MainPID)"
    fi
    if [ -n "$show_out" ]; then
        nrestarts="$(evidence_systemd_field "$show_out" NRestarts)"
        aet_epoch="$(evidence_ts_to_epoch \
            "$(evidence_systemd_field "$show_out" ActiveEnterTimestamp)")"
        active_state="$(evidence_systemd_field "$show_out" ActiveState)"
        mainpid="$(evidence_systemd_field "$show_out" MainPID)"
    fi
    case "$nrestarts" in *[!0-9]*) nrestarts="" ;; esac

    if [ -n "${ZCL_SLO_RSS_CMD:-}" ]; then
        rss_kb="$(ZCL_SLO_PID="$mainpid" bash -c "$ZCL_SLO_RSS_CMD" 2>/dev/null || true)"
    else
        rss_kb="$(evidence_rss_kb "$mainpid")"
    fi
    case "$rss_kb" in *[!0-9]*) rss_kb="" ;; esac

    if [ -n "${ZCL_SLO_DU_CMD:-}" ]; then
        dir_bytes="$(ZCL_SLO_DIR="$datadir" bash -c "$ZCL_SLO_DU_CMD" 2>/dev/null || true)"
    else
        dir_bytes="$(evidence_dir_bytes "$datadir")"
    fi
    case "$dir_bytes" in *[!0-9]*) dir_bytes="" ;; esac

    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' \
        "$nrestarts" "$aet_epoch" "$active_state" "$rss_kb" "$dir_bytes"
}

# peer_count <default-cmd> <override-var>: connected peers as counted by
# the ONE definition this repo uses (number of "addr" keys in getpeerinfo).
# "" when the call produced no JSON at all — distinguishing "asked, got
# nothing" from a genuine 0 peers, which is the difference between a broken
# probe and an eclipsed node.
peer_count() {
    local default_cmd="$1" override_var="$2" cmd out n
    cmd="${!override_var:-$default_cmd}"
    out="$(bash -c "$cmd" 2>/dev/null || true)"
    [ -n "$out" ] || { printf ''; return 0; }
    case "$out" in *'"addr"'*) ;; *) printf ''; return 0 ;; esac
    n="$(printf '%s' "$out" | evidence_peer_count_from_json)"
    case "${n:-}" in '' | *[!0-9]*) printf '' ;; *) printf '%s' "$n" ;; esac
}

# node_self_report <datadir> <rpcport>: the two dumpstate calls, printed as
#   <onion_enabled>\x1f<onion_address>\x1f<blocker_count>\x1f<blocker_primary>\x1f<ok>
# NEVER called for an unreachable instance — see the header note.
node_self_report() {
    local datadir="$1" rpcport="$2"
    local explorer_json="" blocker_json=""
    local onion_enabled="" onion_address="" blocker_count="" blocker_primary=""
    local ok="false"
    if [ -n "$NODE_BIN" ]; then
        explorer_json="$(ZCL_EVIDENCE_TIMEOUT_SEC="$STATE_TIMEOUT_SEC" \
            evidence_node_dumpstate "$NODE_BIN" explorer "$datadir" "$rpcport")"
        blocker_json="$(ZCL_EVIDENCE_TIMEOUT_SEC="$STATE_TIMEOUT_SEC" \
            evidence_node_dumpstate "$NODE_BIN" blocker "$datadir" "$rpcport")"
    fi
    if [ -n "$explorer_json" ]; then
        onion_enabled="$(evidence_json_bool "$explorer_json" onion_enabled)"
        onion_address="$(evidence_json_str "$explorer_json" onion_address)"
    fi
    if [ -n "$blocker_json" ]; then
        blocker_count="$(evidence_json_int "$blocker_json" active_count)"
        # First id inside the "blockers" array — the whole point is which
        # blocker is standing right now, not just how many there are.
        # Done with parameter expansion rather than one sed: the dump also
        # carries a "last_retired":{"id":...} object, and a greedy regex
        # cheerfully reports the blocker that just went AWAY as the one
        # standing. `#*"blockers":[` takes the SHORTEST prefix (so a later
        # key cannot win) and `%%}*` clips to the first element only.
        case "$blocker_json" in
            *'"blockers":['*)
                local barr="${blocker_json#*\"blockers\":[}"
                barr="${barr%%\}*}"
                blocker_primary="$(evidence_json_str "$barr" id)"
                ;;
        esac
    fi
    [ -n "$explorer_json" ] && [ -n "$blocker_json" ] && ok="true"
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' \
        "$onion_enabled" "$onion_address" "$blocker_count" "$blocker_primary" "$ok"
}

# streak_read <instance>: consecutive-miss count carried over from previous
# runs, 0 when absent/garbage. Kept in a tiny per-instance state file rather
# than derived from the ledger tail so a ledger ROTATION cannot reset a long
# outage back to "just went down" — the one moment the distinction matters
# most is exactly when the file rolls.
streak_read() {
    local f="$STREAK_DIR/$1" v=""
    [ -f "$f" ] && v="$(cat "$f" 2>/dev/null || true)"
    case "$v" in ''|*[!0-9]*) v=0 ;; esac
    printf '%s' "$v"
}

# streak_write <instance> <n>: atomic replace; a failure here degrades the
# streak counter, never the sample, so it can not fail a collect.
streak_write() {
    mkdir -p "$STREAK_DIR" 2>/dev/null || return 0
    local f="$STREAK_DIR/$1"
    printf '%s\n' "$2" > "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f" 2>/dev/null
    return 0
}

# max_of <a> <b> ...: print the max of the non-empty numeric args, or "".
max_of() {
    local best="" v
    for v in "$@"; do
        [ -n "$v" ] || continue
        if [ -z "$best" ] || [ "$v" -gt "$best" ]; then best="$v"; fi
    done
    printf '%s' "$best"
}

# ── collect ────────────────────────────────────────────────────────────

cmd_collect() {
    mkdir -p "$LEDGER_DIR"
    rotate_ledger_if_needed

    local ts; ts="$(date +%s)"

    local oracle_default="ZCL_DATADIR=\"$ORACLE_DATADIR\" ZCL_RPCPORT=$ORACLE_RPCPORT timeout $RPC_TIMEOUT_SEC \"$ZCL_RPC_BIN\" getblockchaininfo"
    local oracle; oracle="$(rpc_probe "$oracle_default" ZCL_SLO_ORACLE_CMD)"
    local oracle_served; oracle_served="$(field "$oracle" 1)"

    # Probe every row FIRST, then emit: max_height must be the max over the
    # whole cycle, so no line can be written before the last node answered.
    local -a names=() ports=() dirs=() units=() probes=() peers=()
    local row name rpcport datadir var unit default_cmd peers_cmd peers_var
    for row in "${INSTANCES[@]}"; do
        IFS='|' read -r name rpcport datadir var unit <<<"$row"
        default_cmd="ZCL_DATADIR=\"$datadir\" ZCL_RPCPORT=$rpcport timeout $RPC_TIMEOUT_SEC \"$ZCL_RPC_BIN\" getblockchaininfo"
        names+=("$name"); ports+=("$rpcport"); dirs+=("$datadir"); units+=("$unit")
        probes+=("$(rpc_probe "$default_cmd" "$var")")
        # Peers are only asked for when the cheap height call answered:
        # a refused port refuses getpeerinfo too, and paying a second
        # timeout per dead lane per minute buys nothing.
        peers_var="${var%_CMD}_PEERS_CMD"
        if [ -n "$(field "${probes[$((${#probes[@]} - 1))]}" 1)" ]; then
            peers_cmd="ZCL_DATADIR=\"$datadir\" ZCL_RPCPORT=$rpcport timeout $RPC_TIMEOUT_SEC \"$ZCL_RPC_BIN\" getpeerinfo"
            peers+=("$(peer_count "$peers_cmd" "$peers_var")")
        else
            peers+=("")
        fi
    done

    local max_height serveds=("$oracle_served") i
    for ((i = 0; i < ${#names[@]}; i++)); do serveds+=("$(field "${probes[$i]}" 1)"); done
    max_height="$(max_of "${serveds[@]}")"

    local any_unreachable=0 any_blind=0
    emit_instance() {
        # `peer_count` here is the already-measured VALUE, passed in from
        # the probe loop. Bash keeps function and variable namespaces
        # separate, so it does not shadow the peer_count() reader — but do
        # not call that reader from in here expecting this name to mean it.
        local name="$1" rpcport="$2" datadir="$3" probe="$4" unit="$5" peer_count="$6"
        local served header latency_ms detail reachable gap_max gap_oracle streak
        served="$(field "$probe" 1)"
        header="$(field "$probe" 2)"
        latency_ms="$(field "$probe" 3)"
        detail="$(field "$probe" 4)"
        streak="$(streak_read "$name")"
        if [ -n "$served" ]; then
            reachable="true"; streak=0
        else
            reachable="false"; any_unreachable=1; streak=$((streak + 1))
            if [ "$streak" -ge "$BLIND_STREAK" ]; then any_blind=1; fi
        fi
        streak_write "$name" "$streak"
        gap_max=""
        [ -n "$served" ] && [ -n "$max_height" ] && gap_max=$((max_height - served))
        gap_oracle=""
        [ -n "$served" ] && [ -n "$oracle_served" ] && gap_oracle=$((oracle_served - served))

        # Host-side facts: always measured, including for an unreachable
        # instance. "The RPC is dark AND the unit says active AND RSS is
        # 40 GB" is a far more useful line than a bare reachable:false.
        local hf nrestarts aet_epoch active_state rss_kb dir_bytes
        hf="$(host_facts "$unit" "$datadir")"
        nrestarts="$(field "$hf" 1)"
        aet_epoch="$(field "$hf" 2)"
        active_state="$(field "$hf" 3)"
        rss_kb="$(field "$hf" 4)"
        dir_bytes="$(field "$hf" 5)"

        # Node self-report: only for a lane that already answered.
        local nsr="" onion_enabled="" onion_address="" blocker_count=""
        local blocker_primary="" node_state_ok=""
        if [ "$reachable" = "true" ]; then
            nsr="$(node_self_report "$datadir" "$rpcport")"
            onion_enabled="$(field "$nsr" 1)"
            onion_address="$(field "$nsr" 2)"
            blocker_count="$(field "$nsr" 3)"
            blocker_primary="$(field "$nsr" 4)"
            node_state_ok="$(field "$nsr" 5)"
        fi

        local line
        line="$(printf '{"ts":%s,"instance":%s,"rpcport":%s,"datadir":%s,"reachable":%s,"unreachable_streak":%s,"served_height":%s,"header_height":%s,"latency_ms":%s,"oracle_height":%s,"max_height":%s,"gap_vs_max":%s,"gap_vs_oracle":%s,"peer_count":%s,"rss_kb":%s,"datadir_bytes":%s,"nrestarts":%s,"active_enter_ts":%s,"unit_active_state":%s,"onion_enabled":%s,"onion_address":%s,"blocker_count":%s,"blocker_primary":%s,"node_state_ok":%s,"error_detail":%s}' \
            "$ts" "$(jstr "$name")" "$rpcport" "$(jstr "$datadir")" "$reachable" "$streak" \
            "$(jnum "$served")" "$(jnum "$header")" "$(jnum "$latency_ms")" \
            "$(jnum "$oracle_served")" "$(jnum "$max_height")" \
            "$(jnum "$gap_max")" "$(jnum "$gap_oracle")" \
            "$(jnum "$peer_count")" "$(jnum "$rss_kb")" "$(jnum "$dir_bytes")" \
            "$(jnum "$nrestarts")" "$(jnum "$aet_epoch")" "$(jstr "$active_state")" \
            "$(jbool "$onion_enabled")" "$(jstr "$onion_address")" \
            "$(jnum "$blocker_count")" "$(jstr "$blocker_primary")" \
            "$(jbool "$node_state_ok")" "$(jstr "$detail")")"
        append_line "$line" || return 1
        echo "$line"
        if [ "$reachable" != "true" ]; then
            if [ "$streak" -ge "$BLIND_STREAK" ]; then
                echo "node-slo-probe: BLIND instance=$name unreachable for $streak consecutive polls (threshold $BLIND_STREAK) — fix the node or delete its row from the instance table detail=${detail:-none}" >&2
            else
                echo "node-slo-probe: WARN instance=$name unreachable streak=$streak detail=${detail:-none}" >&2
            fi
        fi
    }

    local rc=0
    for ((i = 0; i < ${#names[@]}; i++)); do
        emit_instance "${names[$i]}" "${ports[$i]}" "${dirs[$i]}" "${probes[$i]}" \
            "${units[$i]}" "${peers[$i]}" || rc=1
    done

    echo "node-slo-probe: collect done file=$LEDGER_FILE instances=${#names[@]} oracle_height=$(jnum "$oracle_served") max_height=$(jnum "$max_height") any_unreachable=$any_unreachable any_blind=$any_blind"
    return "$rc"
}

# ── selftest (hermetic; injected commands, no live nodes) ──────────────

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

# The instance table is the ONE place that says which nodes exist on this
# host. Downstream readers must ASK for it rather than infer it from ledger
# history: a retired lane's rows stay in the retained ledger forever, so an
# inferring reader treats a deleted node as a node that stopped answering.
# That is what the pager used to do, and retiring a lane would have made it
# page "prober may be dead" — falsely, forever.
cmd_list_instances() {
    local row
    for row in "${INSTANCES[@]}"; do
        printf '%s\n' "${row%%|*}"
    done
}

cmd_selftest() {
    ST_TMP="$(mktemp -d /tmp/zcl-node-slo-probe-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT

    # Hermetic by default: every host/node reader is stubbed for the whole
    # selftest so the cases below cannot read this box's real systemd,
    # /proc, datadirs, or node. Cases that care about the new columns
    # override these locally. A selftest that silently started measuring
    # the live host would pass on the developer's machine and fail in a
    # fresh clone, so this export block is load-bearing, not tidiness.
    export ZCL_SLO_SHOW_CMD='true'
    export ZCL_SLO_RSS_CMD='true'
    export ZCL_SLO_DU_CMD='true'
    export ZCL_SLO_NODE_BIN=''
    export ZCL_SLO_CANON_DATADIR='/fixture/canonical'
    export ZCL_SLO_CANON_RPCPORT=18232
    export ZCL_SLO_ORACLE_DATADIR='/fixture/oracle'
    export ZCL_SLO_ORACLE_RPCPORT=8232

    local bind_fixture bind_duplicate
    bind_fixture='ExecStart={ path=/fixture/launch ; argv[]=/fixture/launch /fixture/node -datadir=/fixture/live -rpcport=19001 ; ignore_errors=no ; }'
    [ "$(evidence_unit_exec_arg "$bind_fixture" datadir)" = "/fixture/live" ] ||
        st_fail "case=service-binding datadir was not parsed from argv[]"
    [ "$(evidence_unit_exec_arg "$bind_fixture" rpcport)" = "19001" ] ||
        st_fail "case=service-binding rpcport was not parsed from argv[]"
    bind_duplicate='ExecStart={ path=/fixture/node ; argv[]=/fixture/node -rpcport=1 -rpcport=2 ; }'
    [ -z "$(evidence_unit_exec_arg "$bind_duplicate" rpcport)" ] ||
        st_fail "case=service-binding duplicate rpcport must fail closed"
    printf '# fixture\nrpcport=8232\nrpcport = 8023\n' > "$ST_TMP/zclassic.conf"
    [ "$(oracle_rpcport_from_conf "$ST_TMP/zclassic.conf")" = "8023" ] ||
        st_fail "case=service-binding oracle rpcport was not read from config"
    echo "selftest: ok case=service-binding"

    # A) every instance + the oracle reachable, dev lagging.
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/a"
        export ZCL_SLO_CANON_CMD="echo '{\"result\":{\"blocks\":100,\"headers\":100}}'"
        export ZCL_SLO_DEV_CMD="echo '{\"result\":{\"blocks\":90,\"headers\":101}}'"
        # zclassic-cli emits spaces after JSON colons; the probe must accept
        # that normal pretty-printed shape without an operator-side `tr` shim.
        export ZCL_SLO_ORACLE_CMD="echo '{\"result\": {\"blocks\": 101, \"headers\": 101}}'"
        bash "$SELF" collect >/dev/null
    )
    local f="$ST_TMP/a/uptime-ledger.jsonl"
    [ -s "$f" ] || st_fail "case=all-reachable ledger file missing/empty"
    [ "$(wc -l < "$f")" -eq 2 ] || st_fail "case=all-reachable expected 2 lines, got $(wc -l < "$f")"
    grep -q '"instance":"dev".*"served_height":90.*"gap_vs_max":11.*"gap_vs_oracle":11' "$f" \
        || { cat "$f" >&2; st_fail "case=all-reachable dev gap math wrong"; }
    grep -q '"instance":"canonical".*"served_height":100.*"gap_vs_max":1.*"gap_vs_oracle":1' "$f" \
        || { cat "$f" >&2; st_fail "case=all-reachable canonical gap math wrong"; }
    grep -q '"reachable":true,"unreachable_streak":0' "$f" \
        || { cat "$f" >&2; st_fail "case=all-reachable streak must be 0 on a reachable sample"; }
    echo "selftest: ok case=all-reachable"

    # B) one instance unreachable (command fails) — still ONE line,
    # null-shaped (reachable:false, streak 1), the other instance
    # unaffected, exit 0 (a hole is not a script failure).
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/b"
        export ZCL_SLO_CANON_CMD="echo '{\"result\":{\"blocks\":200,\"headers\":200}}'"
        export ZCL_SLO_DEV_CMD="false"
        export ZCL_SLO_ORACLE_CMD="echo '{\"result\":{\"blocks\":200,\"headers\":200}}'"
        bash "$SELF" collect >/dev/null 2>&1
    ) || st_fail "case=dev-down collect must exit 0 on an unreachable node"
    f="$ST_TMP/b/uptime-ledger.jsonl"
    grep -q '"instance":"dev","rpcport":18252,"datadir":"[^"]*","reachable":false,"unreachable_streak":1,"served_height":null,"header_height":null,"latency_ms":[0-9]*,"oracle_height":200,"max_height":200,"gap_vs_max":null,"gap_vs_oracle":null' "$f" \
        || { cat "$f" >&2; st_fail "case=dev-down wrong null-shaped line"; }
    grep -q '"instance":"canonical".*"reachable":true.*"served_height":200' "$f" \
        || { cat "$f" >&2; st_fail "case=dev-down canonical line should still be reachable"; }
    echo "selftest: ok case=dev-down"

    # C) EVERYTHING unreachable — one null-shaped line per instance, ledger
    # still created, still exit 0 (the hole IS the evidence).
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/c"
        export ZCL_SLO_CANON_CMD="false"
        export ZCL_SLO_DEV_CMD="false"
        export ZCL_SLO_ORACLE_CMD="false"
        bash "$SELF" collect >/dev/null 2>&1
    ) || st_fail "case=all-down collect must exit 0"
    f="$ST_TMP/c/uptime-ledger.jsonl"
    [ "$(wc -l < "$f")" -eq 2 ] || st_fail "case=all-down expected 2 lines"
    [ "$(grep -c '"reachable":false' "$f")" -eq 2 ] \
        || { cat "$f" >&2; st_fail "case=all-down expected all lines reachable:false"; }
    echo "selftest: ok case=all-down"

    # D) rotation: pre-seed a ledger already past the (tiny, test-only)
    # rotation threshold; after collect, .1 exists and the live file holds
    # only this run's fresh lines.
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/d"
        mkdir -p "$ST_TMP/d"
        printf 'x%.0s' $(seq 1 200) > "$ST_TMP/d/uptime-ledger.jsonl"
        echo >> "$ST_TMP/d/uptime-ledger.jsonl"
        export ZCL_SLO_ROTATE_BYTES=100
        export ZCL_SLO_CANON_CMD="echo '{\"result\":{\"blocks\":5,\"headers\":5}}'"
        export ZCL_SLO_DEV_CMD="echo '{\"result\":{\"blocks\":5,\"headers\":5}}'"
        export ZCL_SLO_ORACLE_CMD="echo '{\"result\":{\"blocks\":5,\"headers\":5}}'"
        bash "$SELF" collect >/dev/null 2>&1
    ) || st_fail "case=rotation collect must exit 0"
    [ -f "$ST_TMP/d/uptime-ledger.jsonl.1" ] || st_fail "case=rotation expected .1 rotated file"
    [ "$(wc -l < "$ST_TMP/d/uptime-ledger.jsonl")" -eq 2 ] \
        || st_fail "case=rotation expected fresh live file with 2 lines"
    echo "selftest: ok case=rotation"

    # E) the retired soak lane is GONE from the ledger, not merely quiet: no
    # row means no sample, ever. This is the regression guard for the
    # permanently-unreachable instance that made any_unreachable meaningless.
    if grep -q '"instance":"soak"' "$ST_TMP"/*/uptime-ledger.jsonl; then
        st_fail "case=no-retired-rows an undeployed instance is still being probed"
    fi
    local healthy_out
    healthy_out="$(env "ZCL_SLO_LEDGER_DIR=$ST_TMP/e" \
        "ZCL_SLO_CANON_CMD=echo '{\"result\":{\"blocks\":7,\"headers\":7}}'" \
        "ZCL_SLO_DEV_CMD=echo '{\"result\":{\"blocks\":7,\"headers\":7}}'" \
        "ZCL_SLO_ORACLE_CMD=echo '{\"result\":{\"blocks\":7,\"headers\":7}}'" \
        bash "$SELF" collect 2>&1)"
    printf '%s' "$healthy_out" | grep -q 'any_unreachable=0 any_blind=0' \
        || { printf '%s\n' "$healthy_out" >&2; st_fail "case=no-retired-rows a healthy box must report any_unreachable=0"; }
    echo "selftest: ok case=no-retired-rows"

    # F) a long outage is distinguishable from a fresh one: the streak
    # climbs across polls, crosses ZCL_SLO_BLIND_STREAK into a BLIND line,
    # and snaps back to 0 the moment the node answers again.
    local streak_env=(
        "ZCL_SLO_LEDGER_DIR=$ST_TMP/f"
        "ZCL_SLO_BLIND_STREAK=3"
        "ZCL_SLO_CANON_CMD=echo '{\"result\":{\"blocks\":9,\"headers\":9}}'"
        "ZCL_SLO_ORACLE_CMD=echo '{\"result\":{\"blocks\":9,\"headers\":9}}'"
    )
    local blind_out="" i
    for i in 1 2 3; do
        blind_out="$(env "${streak_env[@]}" ZCL_SLO_DEV_CMD=false bash "$SELF" collect 2>&1)"
    done
    f="$ST_TMP/f/uptime-ledger.jsonl"
    grep -q '"instance":"dev".*"unreachable_streak":1' "$f" \
        || { cat "$f" >&2; st_fail "case=blind-streak first miss must record streak 1"; }
    grep -q '"instance":"dev".*"unreachable_streak":3' "$f" \
        || { cat "$f" >&2; st_fail "case=blind-streak third miss must record streak 3"; }
    printf '%s' "$blind_out" | grep -q 'BLIND instance=dev unreachable for 3 consecutive polls' \
        || { printf '%s\n' "$blind_out" >&2; st_fail "case=blind-streak must escalate to BLIND at the threshold"; }
    printf '%s' "$blind_out" | grep -q 'any_blind=1' \
        || { printf '%s\n' "$blind_out" >&2; st_fail "case=blind-streak summary must carry any_blind=1"; }
    local recover_out
    recover_out="$(env "${streak_env[@]}" "ZCL_SLO_DEV_CMD=echo '{\"result\":{\"blocks\":9,\"headers\":9}}'" \
        bash "$SELF" collect 2>&1)"
    printf '%s' "$recover_out" | grep -q '"instance":"dev".*"reachable":true,"unreachable_streak":0' \
        || { printf '%s\n' "$recover_out" >&2; st_fail "case=blind-streak recovery must reset the streak to 0"; }
    printf '%s' "$recover_out" | grep -q 'any_blind=0' \
        || { printf '%s\n' "$recover_out" >&2; st_fail "case=blind-streak recovery must clear any_blind"; }
    echo "selftest: ok case=blind-streak"

    # G) the six added dimensions are actually recorded, from the shared
    # readers, with the right shapes. Stubs stand in for systemd, /proc,
    # du, getpeerinfo and the node so the case is hermetic.
    local nodestub="$ST_TMP/nodestub"
    cat >"$nodestub" <<'STUB'
#!/usr/bin/env bash
# Fixture node: answers the two self-report dumpstate calls the collector
# makes, ignoring -datadir/-rpcport the way a real CLI would resolve them.
for a in "$@"; do :; done
sub="${!#}"
case "$sub" in
  explorer) echo '{"subsystem":"explorer","state":{"https_started":true,"onion_enabled":true,"onion_address":"abcxyz.onion"}}' ;;
  blocker)  echo '{"subsystem":"blocker","state":{"active_count":4,"blockers":[{"id":"tip_finalize.slow","class":"dependency"},{"id":"other.thing"}]}}' ;;
  *) exit 1 ;;
esac
STUB
    chmod +x "$nodestub"
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/g"
        export ZCL_SLO_CANON_CMD="echo '{\"result\":{\"blocks\":50,\"headers\":50}}'"
        export ZCL_SLO_DEV_CMD="false"
        export ZCL_SLO_ORACLE_CMD="echo '{\"result\":{\"blocks\":50,\"headers\":50}}'"
        export ZCL_SLO_CANON_PEERS_CMD='echo "[{\"id\":1,\"addr\":\"1.2.3.4:8033\"},{\"id\":2,\"addr\":\"5.6.7.8:8033\"},{\"id\":3,\"addr\":\"9.9.9.9:8033\"}]"'
        export ZCL_SLO_SHOW_CMD='printf "NRestarts=7\nActiveEnterTimestamp=Tue 2026-07-28 11:12:00 UTC\nActiveState=active\nMainPID=4242\n"'
        export ZCL_SLO_RSS_CMD='echo 1234567'
        export ZCL_SLO_DU_CMD='echo 18467158947'
        export ZCL_SLO_NODE_BIN="$nodestub"
        bash "$SELF" collect >/dev/null 2>&1
    ) || st_fail "case=added-dimensions collect must exit 0"
    f="$ST_TMP/g/uptime-ledger.jsonl"
    grep -q '"instance":"canonical".*"peer_count":3,' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions peer_count must come from the shared \"addr\" counter"; }
    grep -q '"rss_kb":1234567,"datadir_bytes":18467158947,"nrestarts":7,' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions rss/disk/restart columns missing"; }
    grep -q '"unit_active_state":"active"' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions unit_active_state missing"; }
    grep -q '"active_enter_ts":17[0-9]*,' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions ActiveEnterTimestamp must be parsed to an epoch"; }
    grep -q '"onion_enabled":true,"onion_address":"abcxyz.onion"' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions Tor columns missing"; }
    grep -q '"blocker_count":4,"blocker_primary":"tip_finalize.slow","node_state_ok":true' "$f" \
        || { cat "$f" >&2; st_fail "case=added-dimensions blocker columns missing/wrong"; }
    echo "selftest: ok case=added-dimensions"

    # H) the negative half, and the reason every added column is null-able:
    # an UNREACHABLE instance must record host facts (systemd still knows
    # things about a dark node) but must NOT fabricate peers or a node
    # self-report. A monitor that prints peer_count:0 for a node it never
    # managed to ask is worse than one that prints nothing.
    grep -q '"instance":"dev".*"peer_count":null,' "$f" \
        || { cat "$f" >&2; st_fail "case=unmeasured-is-null unreachable instance must have peer_count null, never 0"; }
    grep -q '"instance":"dev".*"onion_enabled":null,"onion_address":"","blocker_count":null,"blocker_primary":"","node_state_ok":null' "$f" \
        || { cat "$f" >&2; st_fail "case=unmeasured-is-null unreachable instance must not carry a node self-report"; }
    grep -q '"instance":"dev".*"rss_kb":1234567,"datadir_bytes":18467158947' "$f" \
        || { cat "$f" >&2; st_fail "case=unmeasured-is-null host facts must still be recorded for a dark node"; }
    echo "selftest: ok case=unmeasured-is-null"

    # I) every reader absent (no systemd, no /proc entry, no du, no node
    # binary): the sample still appends, every added column is null, and
    # the collect still exits 0. This is the fresh-clone / container shape.
    (
        export ZCL_SLO_LEDGER_DIR="$ST_TMP/i"
        export ZCL_SLO_CANON_CMD="echo '{\"result\":{\"blocks\":1,\"headers\":1}}'"
        export ZCL_SLO_DEV_CMD="echo '{\"result\":{\"blocks\":1,\"headers\":1}}'"
        export ZCL_SLO_ORACLE_CMD="echo '{\"result\":{\"blocks\":1,\"headers\":1}}'"
        export ZCL_SLO_CANON_PEERS_CMD='false'
        export ZCL_SLO_DEV_PEERS_CMD='false'
        export ZCL_SLO_SHOW_CMD='false'
        export ZCL_SLO_RSS_CMD='false'
        export ZCL_SLO_DU_CMD='false'
        export ZCL_SLO_NODE_BIN=''
        bash "$SELF" collect >/dev/null 2>&1
    ) || st_fail "case=readers-absent collect must exit 0 when every host reader is missing"
    f="$ST_TMP/i/uptime-ledger.jsonl"
    [ "$(grep -c '"peer_count":null,"rss_kb":null,"datadir_bytes":null,"nrestarts":null,"active_enter_ts":null,"unit_active_state":""' "$f")" -eq 2 ] \
        || { cat "$f" >&2; st_fail "case=readers-absent added columns must be null, not 0/false"; }
    [ "$(grep -c '"reachable":true' "$f")" -eq 2 ] \
        || { cat "$f" >&2; st_fail "case=readers-absent a missing host reader must not affect reachability"; }
    echo "selftest: ok case=readers-absent"

    echo "selftest: PASS"
}

# ── dispatch ─────────────────────────────────────────────────────────

case "${1:-collect}" in
    collect)    shift || true; cmd_collect "$@" ;;
    --selftest) shift; cmd_selftest "$@" ;;
    --list-instances) shift; cmd_list_instances "$@" ;;
    *)
        echo "usage: node_slo_probe.sh [collect] | --selftest | --list-instances" >&2
        exit 2
        ;;
esac
