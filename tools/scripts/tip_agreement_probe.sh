#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# tip_agreement_probe.sh — the OFF-HOST TIP-HASH AGREEMENT RECORDER.
#
# WHAT THIS IS FOR
# ----------------
# Every parity reference that existed before this file dialled 127.0.0.1:
#   app/services/src/zclassicd_oracle_service.c        ORACLE_DEFAULT_HOST
#   app/services/src/utxo_parity_service.c             PARITY_RPC_DEFAULT_HOST
#   app/services/src/utxo_reference_source_zclassicd.c same
# All three read the sibling zclassicd on THIS box — same disk, same clock,
# same operator, same binary lineage. docs/HANDOFF.md states the consequence
# plainly: gap_vs_oracle "is one network view from one box, and it compares
# numbers, not blocks". This recorder is the first thing in the repository
# that compares a BLOCK HASH against genuinely REMOTE peers, on a cadence,
# into evidence that outlives the node process.
#
# It is the FIRST RUNG only: per-height tip-hash agreement. It says nothing
# about the UTXO set root (no external reference for a zclassic23 SHA3
# exists — docs/MVP.md), nothing about shielded frontiers, and nothing about
# any state the header does not commit.
#
# WHERE THE REMOTE FACTS COME FROM
# --------------------------------
# app/services/src/network_monitor.c samples every connected peer every 30 s
# and persists one row per peer per tick to the peer_chain_observations
# table (10,000 rows retained): peer address, advertised best height, and the
# LEARNABLE TIP HASH — a real 32-byte block hash from a real remote node.
# That table is the only genuinely off-host block-identity data this stack
# holds, and until this file nothing read it as evidence.
#
# This prober is EXTERNAL to the node in the same sense node_slo_probe.sh is:
# a separate process, dialling the node's own operator surfaces the way any
# outside caller would (`core storage query` for the peer table, `dumpstate`
# for the fold, `zcl-rpc getblockhash` for our own hash), writing to a ledger
# under ~/.local/state that survives the node's death. It is READ-ONLY: it
# never restarts, signals, or writes to any node or datadir.
#
# THE THREE OUTCOMES — AND WHY THERE ARE THREE
# --------------------------------------------
# Every sample records `outcome` as exactly one of:
#
#   agrees          our block hash at height H is byte-identical to the hash
#                   that >= min_distinct_peers DISTINCT remote peers reported
#                   at H inside the window.
#   disagrees       we hold a hash at H and the qualifying remote hash at H
#                   is different. This is the signal the whole file exists
#                   to be able to raise.
#   could-not-ask   we did not obtain a comparable pair. NEVER an implicit
#                   pass, never a zero that reads like one.
#
# The third value is not politeness, it is the specific defect this repo has
# now shipped three times: a wallet rescan returned 0 for both "nothing of
# yours here" and "no block body on disk"; a fuzz replay gate exited 0 while
# hiding 14 hangs because an artifact with no verdict counted as nothing; a
# backfill fix was rejected because an unreadable index published "no hole".
#
# It is also not hypothetical HERE. Measured against the live node on
# 2026-07-29, `core storage query` returned this for a one-hour window:
#
#   "rows":[],"row_count":0,"truncated":false,"interrupted":true
#
# — an EMPTY ROW SET carrying interrupted:true, because the query exceeded
# the command's 250 ms budget. A reader that looked only at `rows` would
# have recorded "no remote peer reported any hash", i.e. silence, which is
# one careless line away from "no disagreement observed". Two runs in five
# came back that way. A second shape does the same damage differently: the
# native command envelope PAGES its own reply, and a 100-row result came
# back as `{"columns":[...],"_page":{"included":1,"truncated":true}}` with
# the `rows` key dropped entirely. Both are could-not-ask here, explicitly,
# and both are covered by tools/scripts/test_tip_agreement_evidence.sh.
#
# THE CONTROL: ONE PEER CANNOT MANUFACTURE AGREEMENT
# --------------------------------------------------
# A hash is only allowed to decide a sample once at least
# ZCL_PARITY_MIN_DISTINCT_PEERS (default 2) DISTINCT remote hosts have
# reported it inside the window. Two is not a taste: it is the number this
# codebase already uses everywhere a remote claim is allowed to matter —
# NM_FORK_MIN_CLUSTER (services/network_monitor.h) requires 2 peers behind
# each side before calling a fork, NM_NETSPLIT_MIN_RIVAL_PEERS/GROUPS
# requires 2 before peer testimony counts at all, and
# lib/net/include/net/header_corroboration.h holds a deep best-header switch
# until 2 distinct address groups vouch. One peer is an anecdote in all four
# places, and it is an anecdote here. Below the floor the sample records
# could-not-ask with reason no_hash_with_min_distinct_peers_<n> — NOT
# "agrees", even when our hash happens to match the single peer's.
#
# DISTINCTNESS IS BY REMOTE HOST, and it is load-bearing, not tidiness.
# Measured against the live node on 2026-07-29: inside a 15-minute window
# exactly ONE remote host was surfacing a tip hash at all, and it held THREE
# connections. A recorder counting distinct "ip:port" would have called that
# three independent witnesses and minted an "agrees" from one machine. It is
# one witness, the control refuses it, and the ledger says could-not-ask.
#
# HOW THE HOST KEY IS DERIVED, and why it is not a plain rtrim.
# The first cut of this file used rtrim(rtrim(addr,'0-9'),':'), which strips
# any trailing digits and then any trailing colons. That splits ONE machine
# into TWO witnesses in two shapes this codebase actually produces, both
# confirmed against the node's own SQLite:
#   * an addr with no ":port" at all — rtrim eats the last IPv4 octet, so
#     "198.51.100.10" keys as "198.51.100." while the same host's ported
#     row keys as "198.51.100.10". Two keys, one machine.
#   * IPv6 is rendered TWO different ways by two production paths. An
#     -addnode dial goes through net_service_to_string (connman_dialer.c,
#     connman_complete_dial) and BRACKETS the address: "[2001:...:0001]:8033".
#     An addrman dial or any inbound peer goes through p2p_node_create's
#     fallback (lib/net/src/net.c), which is net_addr_to_string + ":port" and
#     does NOT bracket: "2001:...:0001:8033". Under plain rtrim those are two
#     distinct keys, so one IPv6 machine reached both ways is two witnesses
#     and can mint an "agrees" on its own.
# The key below strips ":port" only when the trailing digits are actually
# preceded by a colon, then removes brackets and lowercases. It can only ever
# MERGE two spellings of one host, never split one host into two, so it can
# only make the control harder to satisfy.
#
# One consequence is worth stating rather than hiding: net_addr_to_string
# renders every torv3 peer as the literal "[torv3]", so ALL onion peers
# collapse to the single host key "torv3". That is the safe direction (many
# onion peers count as one witness, never the reverse), but it means a
# Tor-only peer set can never reach the two-distinct-host bar and will
# record could-not-ask forever. That is a real limit of rung 1 and the fix
# is a per-peer identity in the observation row, not a looser key here.
#
# That measurement carries a second, larger finding, and this file is where
# it is written down rather than smoothed over: the one host was the
# operator's OWN second server. At a two-distinct-host
# bar this node currently has NO off-host tip-hash agreement evidence, only
# its own infrastructure talking to itself one layer further out. That is
# the honest state of the network view, and the correct response is to get
# more peers surfacing hashes, never to lower the bar.
# ZCL_PARITY_EXCLUDE_HOSTS exists for exactly that: a comma-separated list
# of remote hosts whose testimony is discarded before any counting, so an
# operator can refuse to count their own boxes. It can only ever make the
# gate harder to pass. Each sample records excluded_hosts so a ledger says
# whether it was applied.
#
# The remaining ceiling of rung 1:
# The peer address is stored as "ip:port", so two connections to the same
# remote node would otherwise count as two witnesses; the SQL strips the
# port (rtrim of digits then ':') so they collapse to one. It does NOT
# collapse a /16: an operator running two nodes in one subnet counts as two
# distinct hosts. The stronger test — distinct ADDRESS GROUPS, the
# header_corroboration rule — is recorded per sample as
# modal_remote_groups (derived here, /16 for IPv4, whole host otherwise) so
# the next rung can enforce it, but it is NOT the enforced control today
# because it is derived from a second query that is allowed to fail without
# destroying the sample. Do not read modal_remote_groups as a gate.
#
# LEDGER — one JSON line per sample, appended under flock, to
# ~/.local/state/zclassic23-parity/agreement-ledger.jsonl:
#   ts                    epoch the sample was taken
#   instance/rpcport/datadir   which node was asked (client-side identity)
#   window_secs           how far back peer observations were considered
#   min_distinct_peers    the control IN FORCE for this sample. Recorded so
#                         the judge can refuse a ledger written with a
#                         weakened control instead of trusting its own flag
#   our_height            our active-chain height at sample time, or null
#   height                the height actually compared, or null
#   our_tip_hash          our block hash at `height`, or ""
#   modal_remote_hash     the qualifying remote hash at `height`, or ""
#   modal_remote_peers    distinct remote hosts that reported it, or null
#   modal_remote_groups   distinct address groups behind it, or null when
#                         the (optional) host-listing query did not answer
#   disagreeing_peers     remote witnesses at ANY height in the window
#                         holding a hash different from the one WE hold at
#                         that same height — the sum of the distinct-host
#                         counts of every rival cluster, or null. A host that
#                         reported two different hashes at one height inside
#                         the window is counted once per cluster, which can
#                         only OVERSTATE disagreement, never hide it
#   contested_peers       the subset of disagreeing_peers coming from rival
#                         clusters that themselves meet min_distinct_peers.
#                         This is the number a judge may grade on: one peer
#                         is an anecdote in BOTH directions, so a single
#                         remote host must not be able to mint agreement OR
#                         to hold the verdict red on its own
#   disagreeing_hashes    array of {"height":h,"hash":..,"peers":n}
#   rival_heights_unresolved
#                         heights at or below our own tip that carried a
#                         cluster we could NOT check, because our node would
#                         not answer getblockhash there. Never folded into
#                         "no rivals" — an unchecked height is unknown
#   heights_above_tip     clusters at heights above our own tip. Being behind
#                         is not disagreement; it is recorded, not counted
#   peers_total           connected peers in the node's current fold, null
#                         when dumpstate did not answer
#   peers_with_height     peers advertising a height in that fold, or null
#   peers_usable          distinct remote hosts that contributed ANY tip
#                         hash inside the window — the real denominator for
#                         a hash comparison, null when unmeasured
#   clusters_seen         distinct (height,hash) clusters in the window
#   excluded_hosts        how many hosts ZCL_PARITY_EXCLUDE_HOSTS removed
#                         from consideration for this sample (0 when unset)
#   outcome               agrees | disagrees | could-not-ask
#   reason                why, always populated
#   error_detail          truncated raw text when a reader failed, else ""
#
# Bounded ledger: rotates at 50 MB keeping 2 generations, same as the SLO
# uptime ledger.
#
# Usage:
#   tip_agreement_probe.sh [collect]   # one sample-and-append cycle
#   tip_agreement_probe.sh --selftest  # hermetic; delegates to
#                                      # test_tip_agreement_evidence.sh
#
# Env (test/operator injection seams):
#   ZCL_PARITY_LEDGER_DIR        default ~/.local/state/zclassic23-parity
#   ZCL_PARITY_WINDOW_SECS       peer-observation window (default 900)
#   ZCL_PARITY_MIN_DISTINCT_PEERS  the control (default 2)
#   ZCL_PARITY_EXCLUDE_HOSTS     comma-separated remote hosts (no port)
#                                whose testimony is discarded — e.g. your own
#                                other machines. Empty by default. Characters
#                                outside [0-9A-Za-z.:_-] are dropped before
#                                the list reaches SQL
#   ZCL_PARITY_RPC_TIMEOUT_SEC   per-call timeout (default 8)
#   ZCL_PARITY_ROTATE_BYTES      rotation threshold (default 52428800)
#   ZCL_PARITY_NOW               epoch override (hermetic tests)
#   ZCL_PARITY_SQL_CMD           override the peer-table read; the statement
#                                is exported as ZCL_PARITY_SQL
#   ZCL_PARITY_STATE_CMD         override the dumpstate read
#   ZCL_PARITY_HASH_CMD          override the getblockhash read; the height
#                                is exported as ZCL_PARITY_HEIGHT
#   ZCL_PARITY_NODE_BIN / ZCL_PARITY_RPC_BIN   binaries to use
#   ZCL_PARITY_CANON_DATADIR / ZCL_PARITY_CANON_RPCPORT
#                                explicit canonical binding; when absent,
#                                resolve zclassic23.service ExecStart
#
# This script exits non-zero ONLY if it could not append to its own ledger.
# A node that would not answer is DATA, not a script failure — same doctrine
# as node_slo_probe.sh and soak_evidence.sh.
#
# No python (banned), no jq — bash + sed + awk + flock only.

set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EVIDENCE_LIB="$SCRIPT_DIR/lib/evidence_sources.sh"
if [ ! -r "$EVIDENCE_LIB" ]; then
    echo "tip-agreement-probe: FATAL missing reader library $EVIDENCE_LIB" >&2
    exit 3
fi
# shellcheck source=lib/evidence_sources.sh
. "$EVIDENCE_LIB"

LEDGER_DIR="${ZCL_PARITY_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-parity}"
LEDGER_FILE="$LEDGER_DIR/agreement-ledger.jsonl"
WINDOW_SECS="${ZCL_PARITY_WINDOW_SECS:-900}"
MIN_DISTINCT_PEERS="${ZCL_PARITY_MIN_DISTINCT_PEERS:-2}"
RPC_TIMEOUT_SEC="${ZCL_PARITY_RPC_TIMEOUT_SEC:-8}"
ROTATE_BYTES="${ZCL_PARITY_ROTATE_BYTES:-52428800}"

for _cfg in WINDOW_SECS MIN_DISTINCT_PEERS RPC_TIMEOUT_SEC ROTATE_BYTES; do
    eval "_v=\"\$$_cfg\""
    case "$_v" in
        '' | *[!0-9]*)
            echo "tip-agreement-probe: $_cfg must be a non-negative integer (got '$_v')" >&2
            exit 2 ;;
    esac
done
if [ "$MIN_DISTINCT_PEERS" -lt 1 ]; then
    # A floor of 0 would let a hash with no witness at all decide a sample.
    echo "tip-agreement-probe: ZCL_PARITY_MIN_DISTINCT_PEERS must be >= 1" >&2
    exit 2
fi

# ── the host key ──────────────────────────────────────────────────────
# The distinctness control's unit. See the "HOW THE HOST KEY IS DERIVED"
# note above for the two one-machine-two-witnesses shapes a plain rtrim
# admits. Strip ":port" only when the trailing digits are actually preceded
# by a colon (so a portless "1.2.3.4" keeps its last octet), then drop any
# trailing colon, unbracket, and lowercase.
#   `replace()` is NOT available: `core storage query` blocks the REPLACE
#   keyword outright (app/controllers/src/dbquery_controller.c), so bracket
#   removal uses trim(X,'[]'), which is also what keeps this under the
#   1024-byte DBQUERY_MAX_SQL_LEN when it appears twice in one statement.
HOSTKEY="lower(trim(rtrim(CASE WHEN rtrim(addr,'0123456789')<>addr AND \
substr(rtrim(addr,'0123456789'),-1)=':' \
THEN substr(rtrim(addr,'0123456789'),1,length(rtrim(addr,'0123456789'))-1) \
ELSE addr END,':'),'[]'))"

# ── excluded-host filter ──────────────────────────────────────────────
# Built once into a SQL fragment. Every host is sanitised to
# [0-9A-Za-z.:_-] before it is interpolated: `core storage query` is
# SELECT-only and semicolon-rejecting, but a filter that can only ever
# NARROW the evidence must not be the thing that widens the surface.
EXCLUDE_SQL=""
EXCLUDED_HOSTS=0
if [ -n "${ZCL_PARITY_EXCLUDE_HOSTS:-}" ]; then
    _list=""
    while IFS= read -r _h; do
        _h="$(printf '%s' "$_h" | tr -cd '0-9A-Za-z.:_-' | tr 'A-Z' 'a-z')"
        [ -n "$_h" ] || continue
        _list="$_list,'$_h'"
        EXCLUDED_HOSTS=$((EXCLUDED_HOSTS + 1))
    done < <(printf '%s\n' "$ZCL_PARITY_EXCLUDE_HOSTS" | tr ',' '\n')
    if [ -n "$_list" ]; then
        EXCLUDE_SQL=" AND $HOSTKEY NOT IN (${_list#,})"
    fi
fi

# ── instance table ────────────────────────────────────────────────────
# name|rpcport|datadir. Membership rule is node_slo_probe.sh's: a row
# exists only while the instance is DEPLOYED on this host, so a permanently
# unreachable row can never train a reader to ignore could-not-ask. Only
# zclassic23.service (canonical, 18232) runs here; adding a lane is one
# line.
CANON_DATADIR="${ZCL_PARITY_CANON_DATADIR:-}"
CANON_RPCPORT="${ZCL_PARITY_CANON_RPCPORT:-}"
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
INSTANCES=(
    "canonical|$CANON_RPCPORT|$CANON_DATADIR"
)

resolve_bin() {
    local override_set="$1" override="$2"; shift 2
    if [ "$override_set" = "1" ]; then printf '%s' "$override"; return 0; fi
    local c
    for c in "$@"; do [ -x "$c" ] && { printf '%s' "$c"; return 0; }; done
    printf ''
}
NODE_BIN="$(resolve_bin "${ZCL_PARITY_NODE_BIN+1}" "${ZCL_PARITY_NODE_BIN:-}" \
    "$SCRIPT_DIR/../../build/bin/zclassic23" \
    "${HOME:-/root}/.local/bin/zclassic23-live")"
RPC_BIN="$(resolve_bin "${ZCL_PARITY_RPC_BIN+1}" "${ZCL_PARITY_RPC_BIN:-}" \
    "${HOME:-/root}/bin/zcl-rpc" \
    "$SCRIPT_DIR/../../build/bin/zcl-rpc")"

export ZCL_EVIDENCE_TIMEOUT_SEC="${ZCL_PARITY_RPC_TIMEOUT_SEC:-8}"

jnum() { evidence_jnum "${1:-}"; }
jstr() { evidence_jstr "${1:-}"; }

# ── storage-query envelope reader ─────────────────────────────────────
# run_sql <statement>  ->  returns
#   0  usable answer   (ok:true, interrupted:false, a "rows"/"row_count"
#                       pair actually present in the reply); stdout is the
#                       raw envelope
#   1  unusable        (no reply, ok:false, interrupted, or the envelope
#                       PAGED the rows key away); stdout is
#                       "SQLFAIL<US><reason>" — carried on stdout and not in
#                       a global because every call site captures this in a
#                       command substitution, and a subshell cannot hand a
#                       variable back to its parent. A failure reason that
#                       silently evaporated is exactly the class of bug this
#                       ledger exists to make impossible.
# The distinction is the whole point: `"rows":[]` with interrupted:true and
# `"rows":[]` with interrupted:false are different facts, and only the
# second one means "the network really said nothing".
SQL_FAIL_PREFIX="SQLFAIL"
run_sql() {
    local stmt="$1" out=""
    if [ -n "${ZCL_PARITY_SQL_CMD:-}" ]; then
        out="$(ZCL_PARITY_SQL="$stmt" bash -c "$ZCL_PARITY_SQL_CMD" 2>&1)"
    elif [ -n "$NODE_BIN" ]; then
        out="$(timeout "$RPC_TIMEOUT_SEC" "$NODE_BIN" \
            -datadir="$SAMPLE_DATADIR" -rpcport="$SAMPLE_RPCPORT" \
            core storage query --sql="$stmt" 2>&1)"
    fi
    if [ -z "$out" ]; then
        printf '%s\x1f%s' "$SQL_FAIL_PREFIX" "no_reply"; return 1
    fi
    case "$out" in
        *'"ok":true'*) ;;
        *) printf '%s\x1f%s' "$SQL_FAIL_PREFIX" \
               "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
           return 1 ;;
    esac
    case "$out" in
        *'"interrupted":true'*)
            printf '%s\x1f%s' "$SQL_FAIL_PREFIX" "query_interrupted_budget_exceeded"
            return 1 ;;
    esac
    # The reply must actually CARRY its rows. The native command envelope
    # drops trailing fields when the page budget is exceeded and reports
    # that only in _page.truncated; a missing row_count means the rows key
    # is gone, not that the result was empty.
    case "$out" in
        *'"row_count":'*) ;;
        *) printf '%s\x1f%s' "$SQL_FAIL_PREFIX" "envelope_paged_rows_key_absent"
           return 1 ;;
    esac
    printf '%s' "$out"
    return 0
}

# sql_fail_reason <run_sql-output>: the reason half of a SQLFAIL payload.
sql_fail_reason() {
    local s="${1:-}"
    case "$s" in
        "$SQL_FAIL_PREFIX"*) printf '%s' "${s#*$'\x1f'}" ;;
        *) printf 'unknown' ;;
    esac
}

# sql_rows: stdin envelope -> one line per row, fields separated by \x1f,
# quotes stripped. Handles the flat scalar rows this file asks for only.
# The closing `awk NF` is not decoration: it drops blank lines AND
# guarantees a terminating newline, so a `while read` consumer cannot
# silently lose the final row — which is exactly how the address-group
# column first came out one short.
sql_rows() {
    sed -n 's/.*"rows":\[\(.*\)\],"row_count".*/\1/p' |
        sed 's/\],\[/\n/g' |
        sed 's/^\[//; s/\]$//' |
        sed 's/","/\x1f/g; s/,"/\x1f/g; s/",/\x1f/g; s/,/\x1f/g; s/"//g' |
        awk 'NF'
}

SEP=$'\x1f'
f1() { printf '%s' "$1" | cut -d "$SEP" -f1; }
f2() { printf '%s' "$1" | cut -d "$SEP" -f2; }
f3() { printf '%s' "$1" | cut -d "$SEP" -f3; }

# our_hash_at <height>: our own block hash at <height>, lowercased, or "" if
# the node would not answer. "" means UNKNOWN and every caller treats it as
# unknown — it is never folded into "no rival here".
our_hash_at() {
    local hh="$1" out=""
    if [ -n "${ZCL_PARITY_HASH_CMD:-}" ]; then
        out="$(ZCL_PARITY_HEIGHT="$hh" bash -c "$ZCL_PARITY_HASH_CMD" 2>&1)"
    elif [ -n "$RPC_BIN" ]; then
        out="$(ZCL_DATADIR="$SAMPLE_DATADIR" ZCL_RPCPORT="$SAMPLE_RPCPORT" \
            timeout "$RPC_TIMEOUT_SEC" "$RPC_BIN" getblockhash "$hh" 2>&1)"
    fi
    printf '%s' "$out" |
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' |
        head -n1 | tr 'A-F' 'a-f'
}

# addr_group <host>: the address group used for modal_remote_groups.
# IPv4 dotted quad -> first two octets (/16, the header_corroboration
# grouping). Anything else (onion, IPv6, mangled) -> the host itself, which
# can only ever SPLIT nothing and MERGE nothing, i.e. it never inflates the
# count.
addr_group() {
    local h="${1:-}"
    case "$h" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*)
            printf '%s.%s' "${h%%.*}" "$(printf '%s' "${h#*.}" | cut -d. -f1)" ;;
        *) printf '%s' "$h" ;;
    esac
}

rotate_ledger_if_needed() {
    [ -f "$LEDGER_FILE" ] || return 0
    local size
    size="$(stat -c %s "$LEDGER_FILE" 2>/dev/null || echo 0)"
    case "$size" in '' | *[!0-9]*) size=0 ;; esac
    if [ "$size" -ge "$ROTATE_BYTES" ]; then
        [ -f "$LEDGER_FILE.2" ] && rm -f "$LEDGER_FILE.2"
        [ -f "$LEDGER_FILE.1" ] && mv "$LEDGER_FILE.1" "$LEDGER_FILE.2"
        mv "$LEDGER_FILE" "$LEDGER_FILE.1"
        echo "tip-agreement-probe: rotated ledger (size=$size >= $ROTATE_BYTES)" >&2
    fi
}

# ── one sample ────────────────────────────────────────────────────────

sample_instance() {
    local name="$1"
    SAMPLE_RPCPORT="$2"
    SAMPLE_DATADIR="$3"
    local ts="${ZCL_PARITY_NOW:-$(date +%s)}"
    local t0=$((ts - WINDOW_SECS))

    local outcome="could-not-ask" reason="" detail=""
    local our_height="" height="" our_hash="" modal_hash="" modal_peers=""
    local modal_groups="" disagree_peers="" disagree_json="[]"
    # Left empty (-> JSON null) on every early return: a sample that never
    # reached the rival scan has UNKNOWN rival counts, not zero ones.
    local contested_peers="" rival_unresolved="" heights_above=""
    local peers_total="" peers_with_height="" peers_usable="" clusters_seen=""

    # (a) the node's own fold — context columns only. Its failure never
    # decides the outcome; peers_total/peers_with_height simply stay null.
    local state_json=""
    if [ -n "${ZCL_PARITY_STATE_CMD:-}" ]; then
        state_json="$(bash -c "$ZCL_PARITY_STATE_CMD" 2>/dev/null | tr '\n\r\t' '   ')"
    elif [ -n "$NODE_BIN" ]; then
        state_json="$(ZCL_EVIDENCE_TIMEOUT_SEC="$RPC_TIMEOUT_SEC" \
            evidence_node_dumpstate "$NODE_BIN" network_monitor \
            "$SAMPLE_DATADIR" "$SAMPLE_RPCPORT")"
    fi
    if [ -n "$state_json" ]; then
        peers_total="$(evidence_json_int "$state_json" num_peers)"
        peers_with_height="$(evidence_json_int "$state_json" peers_with_height)"
        our_height="$(evidence_json_int "$state_json" our_height)"
    fi

    # (b) the remote clusters. Aggregated IN SQL so the reply stays small
    # enough to survive the envelope pager; distinct hosts, not "ip:port",
    # so one remote node behind two connections is one witness.
    local clusters_env=""
    clusters_env="$(run_sql "SELECT best_height AS h, lower(tip_hash) AS t, \
COUNT(DISTINCT $HOSTKEY) AS n \
FROM peer_chain_observations \
WHERE observed_at >= $t0 AND tip_hash <> ''$EXCLUDE_SQL \
GROUP BY h, t ORDER BY n DESC, h DESC LIMIT 12")"
    if [ $? -ne 0 ]; then
        reason="remote_observations_unavailable"
        detail="$(sql_fail_reason "$clusters_env")"
        emit_sample "$name" "$ts" "$outcome" "$reason" "$detail" \
            "$our_height" "$height" "$our_hash" "$modal_hash" "$modal_peers" \
            "$modal_groups" "$disagree_peers" "$disagree_json" \
            "$peers_total" "$peers_with_height" "$peers_usable" "$clusters_seen" \
            "$contested_peers" "$rival_unresolved" "$heights_above"
        return $?
    fi

    local rows; rows="$(printf '%s' "$clusters_env" | sql_rows)"
    # printf '%s\n', not '%s': command substitution has already eaten the
    # trailing newline, and `wc -l` counts newlines — so the plain form
    # reports N-1 clusters and calls a single cluster zero.
    clusters_seen="$(printf '%s\n' "$rows" | awk 'NF' | wc -l | tr -d ' ')"

    # (c) how many distinct remote hosts contributed ANY hash in the window
    # — the denominator. Optional: null when unmeasured, never 0.
    local usable_env
    usable_env="$(run_sql "SELECT COUNT(DISTINCT $HOSTKEY) AS n \
FROM peer_chain_observations WHERE observed_at >= $t0 AND tip_hash <> ''$EXCLUDE_SQL")"
    if [ $? -eq 0 ]; then
        peers_usable="$(printf '%s' "$usable_env" | sql_rows | head -n1)"
        case "$peers_usable" in '' | *[!0-9]*) peers_usable="" ;; esac
    fi

    # (d) the control. The winner is the largest qualifying cluster; ties
    # break to the higher height. A cluster below the floor is NOT a
    # winner even if our hash matches it — one peer never decides.
    local best_h="" best_t="" best_n=0 line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local h t n
        h="$(f1 "$line")"; t="$(f2 "$line")"; n="$(f3 "$line")"
        case "$h$n" in '' | *[!0-9]*) continue ;; esac
        [ -n "$t" ] || continue
        [ "$n" -ge "$MIN_DISTINCT_PEERS" ] || continue
        if [ "$n" -gt "$best_n" ] || { [ "$n" -eq "$best_n" ] && [ "$h" -gt "${best_h:-0}" ]; }; then
            best_n="$n"; best_h="$h"; best_t="$t"
        fi
    done <<<"$rows"

    if [ -z "$best_h" ]; then
        reason="no_hash_with_min_distinct_peers_${MIN_DISTINCT_PEERS}"
        emit_sample "$name" "$ts" "$outcome" "$reason" "$detail" \
            "$our_height" "$height" "$our_hash" "$modal_hash" "$modal_peers" \
            "$modal_groups" "$disagree_peers" "$disagree_json" \
            "$peers_total" "$peers_with_height" "$peers_usable" "$clusters_seen" \
            "$contested_peers" "$rival_unresolved" "$heights_above"
        return $?
    fi
    height="$best_h"; modal_hash="$best_t"; modal_peers="$best_n"

    # (e) address groups behind the winner — recorded, not enforced.
    local hosts_env
    hosts_env="$(run_sql "SELECT DISTINCT $HOSTKEY AS host \
FROM peer_chain_observations \
WHERE observed_at >= $t0 AND best_height = $height \
AND lower(tip_hash) = '$modal_hash'$EXCLUDE_SQL LIMIT 24")"
    if [ $? -eq 0 ]; then
        modal_groups="$(printf '%s' "$hosts_env" | sql_rows |
            while IFS= read -r hline; do
                [ -n "$hline" ] || continue
                printf '%s\n' "$(addr_group "$(f1 "$hline")")"
            done | sort -u | sed '/^$/d' | wc -l | tr -d ' ')"
        case "$modal_groups" in '' | 0) modal_groups="" ;; esac
    fi

    # (f) our own hash at that height. Its absence is could-not-ask — being
    # behind the network is not agreement and is not disagreement.
    local hash_out=""
    if [ -n "${ZCL_PARITY_HASH_CMD:-}" ]; then
        hash_out="$(ZCL_PARITY_HEIGHT="$height" bash -c "$ZCL_PARITY_HASH_CMD" 2>&1)"
    elif [ -n "$RPC_BIN" ]; then
        hash_out="$(ZCL_DATADIR="$SAMPLE_DATADIR" ZCL_RPCPORT="$SAMPLE_RPCPORT" \
            timeout "$RPC_TIMEOUT_SEC" "$RPC_BIN" getblockhash "$height" 2>&1)"
    fi
    # Lowercased on the way in. The extractor deliberately accepts [0-9a-fA-F]
    # (an RPC that answered in upper case is still a real answer), but the
    # comparison below is a byte compare and the SQL side is lower(tip_hash),
    # so an upper-case reply would otherwise record a FALSE "disagrees" —
    # a fabricated fork alarm.
    our_hash="$(printf '%s' "$hash_out" |
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' |
        head -n1 | tr 'A-F' 'a-f')"
    if [ -z "$our_hash" ]; then
        reason="our_hash_unavailable_at_height_${height}"
        detail="$(printf '%s' "$hash_out" | tr '\n' ' ' | cut -c1-160)"
        [ -n "$detail" ] || detail="no_reply"
        emit_sample "$name" "$ts" "$outcome" "$reason" "$detail" \
            "$our_height" "$height" "$our_hash" "$modal_hash" "$modal_peers" \
            "$modal_groups" "$disagree_peers" "$disagree_json" \
            "$peers_total" "$peers_with_height" "$peers_usable" "$clusters_seen" \
            "$contested_peers" "$rival_unresolved" "$heights_above"
        return $?
    fi

    # (g) RIVAL WITNESSES AT EVERY HEIGHT IN THE WINDOW — not only at the
    # winning one.
    #
    # This loop used to `continue` on every cluster whose height differed
    # from the winner's. That produced the exact defect this whole ledger
    # exists to prevent, and it was reproduced before this fix: with a
    # 3-witness cluster at an already-settled height and a 2-witness cluster
    # holding a DIFFERENT block at our own tip, the sample recorded
    #     "outcome":"agrees","disagreeing_peers":0,"disagreeing_hashes":[]
    # while two remote hosts were on another chain at the height we were
    # actually on. Zero rivals "at the one height I happened to pick" printed
    # as zero rivals, and the judge passed a window of them. An unexamined
    # height must read as UNKNOWN, never as no-disagreement.
    #
    # So: resolve OUR hash at every distinct height that carries a cluster,
    # and classify each one.
    #   * height above our own tip     -> heights_above_tip. Being behind the
    #                                     network is neither agreement nor
    #                                     disagreement; it is recorded.
    #   * height we could not answer   -> rival_heights_unresolved. We should
    #                                     have had it; the judge refuses to
    #                                     count such a sample as clean.
    #   * hash differs from ours there -> a rival.
    #
    # Rivals are summed twice on purpose. `disagreeing_peers` counts every
    # rival witness, so nothing is hidden. `contested_peers` counts only
    # rivals whose own cluster meets min_distinct_peers, and that is what a
    # judge grades: one peer is an anecdote in BOTH directions, so a single
    # remote host must be unable to mint agreement AND unable to hold the
    # verdict red by shouting one bad hash.
    local dp=0 cp=0 parts="" unresolved=0 above=0
    declare -A OUR_AT
    OUR_AT["$height"]="$our_hash"
    local hh oh
    while IFS= read -r hh; do
        [ -n "$hh" ] || continue
        [ "$hh" = "$height" ] && continue
        if [ -n "$our_height" ] && [ "$hh" -gt "$our_height" ]; then
            above=$((above + 1)); continue
        fi
        oh="$(our_hash_at "$hh")"
        if [ -z "$oh" ]; then unresolved=$((unresolved + 1)); continue; fi
        OUR_AT["$hh"]="$oh"
    done < <(printf '%s\n' "$rows" |
             awk -F"$SEP" 'NF && $1 ~ /^[0-9]+$/ {print $1}' | sort -rn -u)

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local h t n
        h="$(f1 "$line")"; t="$(f2 "$line")"; n="$(f3 "$line")"
        case "$h$n" in '' | *[!0-9]*) continue ;; esac
        [ -n "$t" ] || continue
        t="$(printf '%s' "$t" | tr 'A-F' 'a-f')"
        oh="${OUR_AT[$h]:-}"
        # No hash of ours at this height: already counted as above-tip or
        # unresolved. It must NOT fall through as "not a rival".
        [ -n "$oh" ] || continue
        [ "$t" != "$oh" ] || continue
        dp=$((dp + n))
        [ "$n" -ge "$MIN_DISTINCT_PEERS" ] && cp=$((cp + n))
        parts="$parts,{\"height\":$h,\"hash\":$(jstr "$t"),\"peers\":$n}"
    done <<<"$rows"
    disagree_peers="$dp"
    contested_peers="$cp"
    rival_unresolved="$unresolved"
    heights_above="$above"
    disagree_json="[${parts#,}]"

    if [ "$our_hash" = "$modal_hash" ]; then
        outcome="agrees"
        reason="our_hash_matches_${modal_peers}_distinct_remote_peers_at_${height}"
    else
        outcome="disagrees"
        reason="our_hash_differs_from_${modal_peers}_distinct_remote_peers_at_${height}"
    fi

    emit_sample "$name" "$ts" "$outcome" "$reason" "$detail" \
        "$our_height" "$height" "$our_hash" "$modal_hash" "$modal_peers" \
        "$modal_groups" "$disagree_peers" "$disagree_json" \
        "$peers_total" "$peers_with_height" "$peers_usable" "$clusters_seen" \
        "$contested_peers" "$rival_unresolved" "$heights_above"
}

emit_sample() {
    local name="$1" ts="$2" outcome="$3" reason="$4" detail="$5"
    local our_height="$6" height="$7" our_hash="$8" modal_hash="$9"
    local modal_peers="${10}" modal_groups="${11}" disagree_peers="${12}"
    local disagree_json="${13}" peers_total="${14}" peers_with_height="${15}"
    local peers_usable="${16}" clusters_seen="${17}"
    local contested_peers="${18}" rival_unresolved="${19}"
    local heights_above="${20}"

    # Structural guard, not decoration: the only paths that may print
    # "agrees" are the two that compared two real 64-hex hashes. If the
    # ladder above is ever refactored into letting a failure fall through
    # here, this turns it into a loud instrument failure instead of a
    # false green.
    if [ "$outcome" = "agrees" ] || [ "$outcome" = "disagrees" ]; then
        case "${our_hash}${modal_hash}" in
            *[!0-9a-fA-F]* | '') outcome="could-not-ask"
                                 reason="internal_invariant_hash_missing" ;;
            *) [ "${#our_hash}" -eq 64 ] && [ "${#modal_hash}" -eq 64 ] || {
                   outcome="could-not-ask"
                   reason="internal_invariant_hash_length"; } ;;
        esac
    fi
    case "$outcome" in
        agrees | disagrees | could-not-ask) ;;
        *) outcome="could-not-ask"; reason="internal_invariant_bad_outcome" ;;
    esac
    [ -n "$reason" ] || reason="unspecified"

    local line
    line="$(printf '{"ts":%s,"instance":%s,"rpcport":%s,"datadir":%s,"window_secs":%s,"min_distinct_peers":%s,"our_height":%s,"height":%s,"our_tip_hash":%s,"modal_remote_hash":%s,"modal_remote_peers":%s,"modal_remote_groups":%s,"disagreeing_peers":%s,"contested_peers":%s,"rival_heights_unresolved":%s,"heights_above_tip":%s,"disagreeing_hashes":%s,"peers_total":%s,"peers_with_height":%s,"peers_usable":%s,"clusters_seen":%s,"excluded_hosts":%s,"outcome":%s,"reason":%s,"error_detail":%s}' \
        "$ts" "$(jstr "$name")" "$SAMPLE_RPCPORT" "$(jstr "$SAMPLE_DATADIR")" \
        "$WINDOW_SECS" "$MIN_DISTINCT_PEERS" \
        "$(jnum "$our_height")" "$(jnum "$height")" \
        "$(jstr "$our_hash")" "$(jstr "$modal_hash")" \
        "$(jnum "$modal_peers")" "$(jnum "$modal_groups")" \
        "$(jnum "$disagree_peers")" "$(jnum "$contested_peers")" \
        "$(jnum "$rival_unresolved")" "$(jnum "$heights_above")" \
        "${disagree_json:-[]}" \
        "$(jnum "$peers_total")" "$(jnum "$peers_with_height")" \
        "$(jnum "$peers_usable")" "$(jnum "$clusters_seen")" \
        "$(jnum "$EXCLUDED_HOSTS")" \
        "$(jstr "$outcome")" "$(jstr "$reason")" "$(jstr "$detail")")"

    evidence_append_line "$LEDGER_FILE" "$line" "tip-agreement-probe" || return 1
    echo "$line"
    if [ "$outcome" = "disagrees" ]; then
        echo "tip-agreement-probe: DISAGREE instance=$name height=$height ours=$our_hash remote=$modal_hash peers=$modal_peers" >&2
    elif [ "$outcome" = "could-not-ask" ]; then
        echo "tip-agreement-probe: COULD-NOT-ASK instance=$name reason=$reason detail=${detail:-none}" >&2
    fi
    return 0
}

cmd_collect() {
    mkdir -p "$LEDGER_DIR" || {
        echo "tip-agreement-probe: FAIL cannot create $LEDGER_DIR" >&2; return 1; }
    rotate_ledger_if_needed
    local rc=0 row name port dir
    for row in "${INSTANCES[@]}"; do
        IFS='|' read -r name port dir <<<"$row"
        sample_instance "$name" "$port" "$dir" || rc=1
    done
    echo "tip-agreement-probe: collect done file=$LEDGER_FILE instances=${#INSTANCES[@]} min_distinct_peers=$MIN_DISTINCT_PEERS window_secs=$WINDOW_SECS"
    return "$rc"
}

case "${1:-collect}" in
    collect)    shift || true; cmd_collect "$@" ;;
    --selftest) exec bash "$SCRIPT_DIR/test_tip_agreement_evidence.sh" --only recorder ;;
    *)
        echo "usage: tip_agreement_probe.sh [collect] | --selftest" >&2
        exit 2
        ;;
esac
