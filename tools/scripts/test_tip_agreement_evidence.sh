#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# test_tip_agreement_evidence.sh — the hermetic proof for the off-host
# tip-hash agreement RECORDER (tools/scripts/tip_agreement_probe.sh). Its
# judge is C now: `z23 ops tip-agreement judge`, proved by the
# tip_agreement_judge test group (tests/harness/src/test_tip_agreement_judge.c).
#
# Hermetic: every node reader is stubbed with a fixture command, so this
# never dials a node, never reads a datadir, and never touches the live
# instance. It runs the REAL prober — the stubs replace
# only what the node would have answered.
#
# The three cases the whole design turns on are asserted SEPARATELY and by
# name, because conflating them is the defect this ledger exists to prevent:
#
#   agreement       recorded as outcome "agrees" with the witness count
#   disagreement    recorded as outcome "disagrees" with both hashes
#   could-not-ask   an unreachable or unusable source records
#                   "could-not-ask" — never a zero, never a blank, never a
#                   pass
#
# The could-not-ask family is tested in five distinct shapes, four of which
# were observed against the live node while this was being written:
# a source that refuses outright, a query INTERRUPTED by the command budget
# (which returns "rows":[] — an empty result that means "we did not ask",
# not "nobody answered"), an envelope whose pager DROPPED the rows key, a
# genuinely empty result, and a cluster below the distinct-peer control.
#
# Usage:
#   test_tip_agreement_evidence.sh                 # everything
#   test_tip_agreement_evidence.sh --only recorder
#
# Ends with "selftest: PASS" on success (the token every sibling harness in
# tools/scripts uses and the Makefile gates on) and exits non-zero on any
# failure.

set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
. "$SCRIPT_DIR/sh_str.sh"
PROBE="$SCRIPT_DIR/tip_agreement_probe.sh"

ONLY="all"
case "${1:-}" in
    --only) ONLY="${2:?--only needs recorder}" ;;
    '') ;;
    *) echo "usage: test_tip_agreement_evidence.sh [--only recorder]" >&2; exit 2 ;;
esac

FAILED=0
ok()   { echo "  ok: $*"; }
bad()  { echo "  FAIL: $*"; FAILED=1; }

for f in "$PROBE"; do
    if [ ! -r "$f" ]; then
        echo "selftest: FAIL missing $f" >&2
        echo "selftest: this harness proves the off-host tip-hash agreement ledger;" >&2
        echo "          on a tree without the recorder it must fail, and does." >&2
        exit 1
    fi
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-tip-agreement-selftest.XXXXXX")" || {
    echo "selftest: FAIL could not mktemp" >&2; exit 1; }
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT

NOW=2000000000
HASH_OURS="00000413d24a748e127ed332680da715e676b9a3d60c2f9d4b0dd592113a8a05"
HASH_THEM="000006b9193728f7b4cc399428202a38bde9c41220dd28a3164be7bee87a16c5"
HEIGHT=3197949

# ── fixture builders ───────────────────────────────────────────────────

# envelope <columns-json> <rows-json> <row_count> <interrupted>
envelope() {
    printf '{"schema":"zcl.result.v1","command":"core.storage.query","ok":true,"status":"passed","data_schema":"zcl.storage_query.v1","data":{"columns":%s,"rows":%s,"row_count":%s,"truncated":false,"interrupted":%s,"elapsed_ms":1,"_page":{"view":"normal","total_fields":7,"included":7,"truncated":false}}}' \
        "$1" "$2" "$3" "$4"
}

# sql_stub <file> <cluster-rows-json> <cluster-count> <interrupted>
# Dispatches on the statement the prober exported as ZCL_PARITY_SQL:
#   GROUP BY        -> the cluster aggregate (the case under test)
#   SELECT DISTINCT -> the winning cluster's hosts (address-group column)
#   otherwise       -> the peers_usable count
sql_stub() {
    local f="$1" rows="$2" n="$3" interrupted="$4"
    cat >"$f" <<STUB
#!/usr/bin/env bash
s="\${ZCL_PARITY_SQL:-}"
case "\$s" in
  *"GROUP BY"*)
    printf '%s' '$(envelope '["h","t","n"]' "$rows" "$n" "$interrupted")' ;;
  *"SELECT DISTINCT"*)
    printf '%s' '$(envelope '["host"]' '[["203.0.113.7"],["198.51.100.9"]]' 2 false)' ;;
  *)
    printf '%s' '$(envelope '["n"]' '[[9]]' 1 false)' ;;
esac
STUB
    chmod +x "$f"
}

# query_aware_cluster_stub <file> <source-tsv>
# The fixture returns rows in the production ORDER BY and applies the LIMIT
# parsed from the actual SQL statement, so a cap regression cannot be hidden
# by an arbitrary pre-truncated response.
query_aware_cluster_stub() {
    local f="$1" fixture="$2" malformed="${3:-none}"
    cat >"$f" <<STUB
#!/usr/bin/env bash
s="\${ZCL_PARITY_SQL:-}"
malformed='$malformed'
case "\$s" in
  *"GROUP BY"*)
    case "\$s" in
      *"ORDER BY n DESC, h DESC LIMIT "*) ;;
      *) echo "stub: production cluster ordering/limit missing: \$s" >&2; exit 1 ;;
    esac
    limit=\${s##*LIMIT }
    case "\$limit" in ''|*[!0-9]*) echo "stub: invalid LIMIT: \$limit" >&2; exit 1 ;; esac
    rows=\$(sort -t '|' -k3,3nr -k1,1nr "$fixture" | head -n "\$limit" |
      awk -F '|' 'BEGIN { printf "[" } { if (NR > 1) printf ","; printf "[%s,\"%s\",%s]", \$1, \$2, \$3 } END { printf "]" }')
    n=\$(sort -t '|' -k3,3nr -k1,1nr "$fixture" | head -n "\$limit" | wc -l | tr -d ' ')
    case "\$malformed" in
      missing-count) rows="\${rows%]},[1]]"; n=\$((n + 1)) ;;
      oversized-count) rows="\${rows%]},[$((HEIGHT - 13)),\"$HASH_THEM\",9223372036854775808]]"; n=\$((n + 1)) ;;
    esac
    printf '{"schema":"zcl.result.v1","command":"core.storage.query","ok":true,"data":{"columns":["h","t","n"],"rows":%s,"row_count":%s,"truncated":false,"interrupted":false}}' "\$rows" "\$n" ;;
  *"SELECT DISTINCT"*)
    printf '%s' '{"schema":"zcl.result.v1","ok":true,"data":{"columns":["host"],"rows":[["203.0.113.7"],["198.51.100.9"]],"row_count":2,"truncated":false,"interrupted":false}}' ;;
  *) printf '%s' '{"schema":"zcl.result.v1","ok":true,"data":{"columns":["n"],"rows":[[40]],"row_count":1,"truncated":false,"interrupted":false}}' ;;
esac
STUB
    chmod +x "$f"
}

# Twelve successively lower-ranked clusters match the local chain. The
# optional thirteenth row is a qualifying rival at/below our tip.
make_ranked_clusters() {
    local f="$1" include_rival="$2" i h hash
    : >"$f"
    for ((i = 1; i <= 12; i++)); do
        h=$((HEIGHT - i + 1))
        printf -v hash '%064x' "$i"
        printf '%s|%s|%s\n' "$h" "$hash" "$((16 - i))" >>"$f"
    done
    if [ "$include_rival" = yes ]; then
        printf '%s|%s|2\n' "$((HEIGHT - 1))" "$HASH_THEM" >>"$f"
    fi
}

# Twelve rows remain within the query cap. Rank 1 is the local-chain modal
# cluster; rank 12 is a qualifying conflicting cluster with four witnesses.
# The valid one-witness row at rank 13 is the below-threshold sentinel.
make_ranked_clusters_retained_rival() {
    local f="$1" i h hash
    : >"$f"
    for ((i = 1; i <= 12; i++)); do
        h=$((HEIGHT - i + 1))
        printf -v hash '%064x' "$i"
        if [ "$i" -eq 12 ]; then hash="$HASH_THEM"; fi
        printf '%s|%s|%s\n' "$h" "$hash" "$((16 - i))" >>"$f"
    done
    printf '%s|%s|1\n' "$((HEIGHT - 12))" "$HASH_THEM" >>"$f"
}

append_one_witness_tails() {
    local f="$1" tails="$2" i h hash
    for ((i = 1; i <= tails; i++)); do
        h=$((HEIGHT - i))
        printf -v hash '%064x' "$((100 + i))"
        printf '%s|%s|1\n' "$h" "$hash" >>"$f"
    done
}

state_stub() {
    printf '{"subsystem":"network_monitor","state":{"ready":true,"num_peers":21,"peers_with_height":20,"our_height":%s,"tip_clusters":[]}}' "$1"
}

# run_probe <ledger-dir> <sql-cmd> <hash-cmd> [ts] [extra env assignments...]
run_probe() {
    local dir="$1" sqlcmd="$2" hashcmd="$3" ts="${4:-$NOW}"
    if [ "$#" -ge 4 ]; then shift 4; else shift 3; fi
    env "ZCL_PARITY_LEDGER_DIR=$dir" \
        "ZCL_PARITY_NOW=$ts" \
        "ZCL_PARITY_CANON_DATADIR=/fixture/canonical" \
        "ZCL_PARITY_CANON_RPCPORT=18232" \
        "ZCL_PARITY_SQL_CMD=$sqlcmd" \
        "ZCL_PARITY_HASH_CMD=$hashcmd" \
        "ZCL_PARITY_STATE_CMD=printf '%s' '$(state_stub "$HEIGHT")'" \
        "ZCL_PARITY_NODE_BIN=" "ZCL_PARITY_RPC_BIN=" \
        "$@" \
        bash "$PROBE" collect >/dev/null 2>&1
}

ledger_of() { printf '%s/agreement-ledger.jsonl' "$1"; }

# ── recorder cases ─────────────────────────────────────────────────────

recorder_cases() {
    echo "tip-agreement: recorder cases"

    # R1 — AGREEMENT. Two distinct remote hosts report HASH_OURS at HEIGHT
    # and our node holds HASH_OURS there.
    local d="$TMP/r1"; sql_stub "$TMP/r1.sh" \
        "[[$HEIGHT,\"$HASH_OURS\",2],[$((HEIGHT - 1)),\"$HASH_THEM\",1]]" 2 false
    run_probe "$d" "$TMP/r1.sh" "printf '{\"result\":\"$HASH_OURS\",\"error\":null,\"id\":1}'"
    local L; L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" &&
       grep -q "\"height\":$HEIGHT," "$L" &&
       grep -q '"modal_remote_peers":2,' "$L" &&
       grep -q "\"our_tip_hash\":\"$HASH_OURS\"" "$L" &&
       grep -q '"clusters_seen":2,' "$L" &&
       grep -q '"min_distinct_peers":2,' "$L"; then
        ok "agreement recorded as outcome=agrees with 2 distinct remote peers"
    else
        cat "$L" >&2; bad "R1 agreement not recorded correctly"
    fi
    # The address-group column must be derived, not invented: two hosts in
    # different /16s must read as 2 groups.
    grep -q '"modal_remote_groups":2,' "$L" \
        || { cat "$L" >&2; bad "R1 modal_remote_groups not derived from distinct hosts"; }
    # The R1 fixture also carries a ONE-witness cluster holding a different
    # hash at HEIGHT-1. It must be recorded honestly (disagreeing_peers 1),
    # and it must NOT contest the sample: the distinct-peer control is
    # symmetric, so one remote host can neither mint agreement nor hold the
    # verdict red by shouting a hash nobody else reports.
    if grep -q '"disagreeing_peers":1,"contested_peers":0,' "$L" &&
       grep -q '"rival_heights_unresolved":0,"heights_above_tip":0,' "$L"; then
        ok "a one-witness rival is recorded but does not contest (control is symmetric)"
    else
        cat "$L" >&2; bad "R1 one-witness rival accounting wrong"
    fi

    # R2 — DISAGREEMENT. The same two remote hosts agree with each other on
    # HASH_THEM at HEIGHT; we hold HASH_OURS.
    d="$TMP/r2"; sql_stub "$TMP/r2.sh" "[[$HEIGHT,\"$HASH_THEM\",2]]" 1 false
    run_probe "$d" "$TMP/r2.sh" "printf '{\"result\":\"$HASH_OURS\",\"error\":null,\"id\":1}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"disagrees"' "$L" &&
       grep -q "\"our_tip_hash\":\"$HASH_OURS\",\"modal_remote_hash\":\"$HASH_THEM\"" "$L" &&
       grep -q '"disagreeing_peers":2,"contested_peers":2,' "$L" &&
       grep -q "\"disagreeing_hashes\":\[{\"height\":$HEIGHT,\"hash\":\"$HASH_THEM\",\"peers\":2}\]" "$L"; then
        ok "disagreement recorded as outcome=disagrees with both hashes and the rival count"
    else
        cat "$L" >&2; bad "R2 disagreement not recorded correctly"
    fi

    # R3 — UNREACHABLE SOURCE. The peer-observation read refuses outright.
    # This must be could-not-ask, and must NOT be a zero that reads like
    # "nobody disagreed".
    d="$TMP/r3"
    run_probe "$d" "exit 1" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"reason":"remote_observations_unavailable"' "$L" &&
       grep -q '"modal_remote_peers":null' "$L" &&
       grep -q '"height":null' "$L" &&
       ! grep -q '"outcome":"agrees"' "$L"; then
        ok "unreachable source recorded as could-not-ask with null (not zero) witness fields"
    else
        cat "$L" >&2; bad "R3 unreachable source not recorded as could-not-ask"
    fi

    # R4 — INTERRUPTED QUERY. Observed live: the command budget kills the
    # scan and the reply carries "rows":[] with interrupted:true. An empty
    # row set here means WE DID NOT ASK, not "no peer answered".
    d="$TMP/r4"; sql_stub "$TMP/r4.sh" '[]' 0 true
    run_probe "$d" "$TMP/r4.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"error_detail":"query_interrupted_budget_exceeded"' "$L"; then
        ok "an INTERRUPTED query recorded as could-not-ask, never as silence"
    else
        cat "$L" >&2; bad "R4 interrupted query not distinguished from an empty result"
    fi

    # R5 — PAGED ENVELOPE. Observed live: a large result comes back with
    # the rows key dropped entirely and only _page.truncated saying so.
    d="$TMP/r5"
    cat >"$TMP/r5.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s' '{"schema":"zcl.result.v1","ok":true,"data":{"columns":["h","t","n"],"_page":{"view":"normal","total_fields":7,"included":1,"truncated":true,"next_cursor":1}}}'
STUB
    chmod +x "$TMP/r5.sh"
    run_probe "$d" "$TMP/r5.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"error_detail":"envelope_paged_rows_key_absent"' "$L"; then
        ok "an envelope whose pager dropped the rows key recorded as could-not-ask"
    else
        cat "$L" >&2; bad "R5 paged envelope not recorded as could-not-ask"
    fi

    # R6 — GENUINELY EMPTY. The query ran and no peer reported any hash.
    # Still not agreement: zero peers is not consensus.
    d="$TMP/r6"; sql_stub "$TMP/r6.sh" '[]' 0 false
    run_probe "$d" "$TMP/r6.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"reason":"no_hash_with_min_distinct_peers_2"' "$L" &&
       grep -q '"clusters_seen":0,' "$L"; then
        ok "an empty-but-honest result recorded as could-not-ask, never as agreement"
    else
        cat "$L" >&2; bad "R6 empty result not recorded as could-not-ask"
    fi

    # R7 — THE CONTROL. ONE remote host reports exactly the hash we hold.
    # If a single peer could mint agreement this line would read "agrees";
    # it must not.
    d="$TMP/r7"; sql_stub "$TMP/r7.sh" "[[$HEIGHT,\"$HASH_OURS\",1]]" 1 false
    run_probe "$d" "$TMP/r7.sh" "printf '{\"result\":\"$HASH_OURS\",\"error\":null,\"id\":1}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"reason":"no_hash_with_min_distinct_peers_2"' "$L" &&
       ! grep -q '"outcome":"agrees"' "$L"; then
        ok "a SINGLE peer reporting our own hash cannot manufacture agreement"
    else
        cat "$L" >&2; bad "R7 the distinct-peer control did not hold"
    fi

    # R8 — OUR SIDE UNAVAILABLE. Remote evidence qualifies but our node
    # cannot answer for that height (we are behind, or the RPC is down).
    # Being behind is neither agreement nor disagreement.
    d="$TMP/r8"; sql_stub "$TMP/r8.sh" "[[$HEIGHT,\"$HASH_OURS\",3]]" 1 false
    run_probe "$d" "$TMP/r8.sh" "echo '{\"result\":null,\"error\":{\"code\":-8,\"message\":\"Block height out of range\"}}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q "\"reason\":\"our_hash_unavailable_at_height_$HEIGHT\"" "$L" &&
       grep -q '"our_tip_hash":""' "$L"; then
        ok "our own hash being unavailable recorded as could-not-ask, not as a match"
    else
        cat "$L" >&2; bad "R8 missing local hash not recorded as could-not-ask"
    fi

    # R10 — the operator-owned-peer filter. Measured live: the only remote
    # host surfacing tip hashes was the operator's own second server, on
    # three connections. Excluding it must (a) reach the SQL as a NOT IN
    # clause, (b) be recorded in the sample, and (c) be able to turn an
    # apparent agreement into could-not-ask — the filter narrows evidence,
    # it never manufactures it.
    d="$TMP/r10"
    cat >"$TMP/r10.sh" <<STUB
#!/usr/bin/env bash
s="\${ZCL_PARITY_SQL:-}"
case "\$s" in
  *"NOT IN ('198.51.100.9')"*) ;;
  *) echo "stub: exclusion clause missing from: \$s" >&2; exit 1 ;;
esac
case "\$s" in
  *"GROUP BY"*) printf '%s' '$(envelope '["h","t","n"]' '[]' 0 false)' ;;
  *)            printf '%s' '$(envelope '["n"]' '[[0]]' 1 false)' ;;
esac
STUB
    chmod +x "$TMP/r10.sh"
    run_probe "$d" "$TMP/r10.sh" "printf '{\"result\":\"$HASH_OURS\"}'" "$NOW" \
        "ZCL_PARITY_EXCLUDE_HOSTS=198.51.100.9"
    L="$(ledger_of "$d")"
    if grep -q '"excluded_hosts":1,' "$L" &&
       grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"reason":"no_hash_with_min_distinct_peers_2"' "$L"; then
        ok "an excluded operator-owned host is filtered in SQL and recorded"
    else
        cat "$L" >&2; bad "R10 excluded-host filter not applied/recorded"
    fi

    # R11 — the sanitiser: a host list carrying SQL punctuation must reach
    # the statement stripped, never as syntax.
    d="$TMP/r11"
    cat >"$TMP/r11.sh" <<STUB
#!/usr/bin/env bash
s="\${ZCL_PARITY_SQL:-}"
case "\$s" in
  *"');"*|*"DROP TABLE"*) echo "stub: unsanitised list reached SQL: \$s" >&2; exit 1 ;;
esac
case "\$s" in
  *"NOT IN ('1.2.3.4DROPTABLEblocks--')"*) ;;
  *) echo "stub: sanitised exclusion clause absent from: \$s" >&2; exit 1 ;;
esac
case "\$s" in
  *"GROUP BY"*) printf '%s' '$(envelope '["h","t","n"]' '[]' 0 false)' ;;
  *)            printf '%s' '$(envelope '["n"]' '[[0]]' 1 false)' ;;
esac
STUB
    chmod +x "$TMP/r11.sh"
    run_probe "$d" "$TMP/r11.sh" "printf '{\"result\":\"$HASH_OURS\"}'" "$NOW" \
        "ZCL_PARITY_EXCLUDE_HOSTS=1.2.3.4'); DROP TABLE blocks --"
    L="$(ledger_of "$d")"
    if [ -s "$L" ] && grep -q '"outcome":"could-not-ask"' "$L"; then
        ok "an excluded-host list is sanitised before it reaches SQL"
    else
        cat "$L" 2>/dev/null >&2; bad "R11 exclusion list sanitiser did not hold"
    fi

    # R12 — THE MASKED TIP FORK. This is the defect that shipped in the
    # first cut of the recorder and it is the reason contested_peers exists.
    # A 3-witness cluster sits at an already-settled height (we match it, of
    # course) while a 2-witness cluster holds a DIFFERENT block at our own
    # tip. The old rival loop skipped every cluster whose height was not the
    # winner's, so the line read
    #     "outcome":"agrees","disagreeing_peers":0,"disagreeing_hashes":[]
    # and a window of them graded PASS while we were on another chain.
    d="$TMP/r12"; sql_stub "$TMP/r12.sh" \
        "[[$((HEIGHT - 9)),\"$HASH_OURS\",3],[$HEIGHT,\"$HASH_THEM\",2]]" 2 false
    run_probe "$d" "$TMP/r12.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q "\"height\":$((HEIGHT - 9))," "$L" &&
       grep -q '"disagreeing_peers":2,"contested_peers":2,' "$L" &&
       grep -q "\"disagreeing_hashes\":\[{\"height\":$HEIGHT,\"hash\":\"$HASH_THEM\",\"peers\":2}\]" "$L"; then
        ok "a rival at a DIFFERENT height than the winner is counted, not skipped"
    else
        cat "$L" >&2; bad "R12 rival at another height was not recorded (masked tip fork)"
    fi

    # R13 — OUR HASH IN UPPER CASE. The extractor accepts [0-9a-fA-F] on
    # purpose, but the peer table is compared as lower(tip_hash) and the
    # comparison is a byte compare, so an upper-case RPC reply used to record
    # a FALSE "disagrees" — a fabricated fork alarm on a healthy node.
    d="$TMP/r13"; sql_stub "$TMP/r13.sh" "[[$HEIGHT,\"$HASH_OURS\",2]]" 1 false
    run_probe "$d" "$TMP/r13.sh" \
        "printf '{\"result\":\"$(printf '%s' "$HASH_OURS" | tr 'a-f' 'A-F')\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" && ! grep -q '"outcome":"disagrees"' "$L"; then
        ok "an upper-case hash from our own RPC does not fabricate a disagreement"
    else
        cat "$L" >&2; bad "R13 hash case sensitivity produced a false disagreement"
    fi

    # R14 — A HEIGHT ABOVE OUR TIP. Peers ahead of us is the normal state of
    # a syncing node. It is neither a rival nor an unresolved check: it is
    # recorded as heights_above_tip so the sample stays clean.
    # (the at-tip cluster carries more witnesses so IT is the winner; a tie
    # would break to the higher height and make the above-tip cluster the
    # thing being compared, which is a different case.)
    d="$TMP/r14"; sql_stub "$TMP/r14.sh" \
        "[[$HEIGHT,\"$HASH_OURS\",3],[$((HEIGHT + 3)),\"$HASH_THEM\",2]]" 2 false
    run_probe "$d" "$TMP/r14.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if grep -q '"contested_peers":0,"rival_heights_unresolved":0,"heights_above_tip":1,' "$L" &&
       grep -q '"outcome":"agrees"' "$L"; then
        ok "a cluster above our own tip is recorded as behind-ness, not as a rival"
    else
        cat "$L" >&2; bad "R14 above-tip cluster mis-classified"
    fi

    # R15 — A HEIGHT WE SHOULD HAVE AND CANNOT ANSWER. Below our tip, the
    # node will not produce a hash. That is UNKNOWN and must be recorded as
    # unresolved — never folded into "no rival at that height".
    d="$TMP/r15"; sql_stub "$TMP/r15.sh" \
        "[[$HEIGHT,\"$HASH_OURS\",2],[$((HEIGHT - 4)),\"$HASH_THEM\",2]]" 2 false
    run_probe "$d" "$TMP/r15.sh" \
        "if [ \"\$ZCL_PARITY_HEIGHT\" = \"$HEIGHT\" ]; then printf '{\"result\":\"$HASH_OURS\"}'; else printf '{\"result\":null,\"error\":{\"code\":-8}}'; fi"
    L="$(ledger_of "$d")"
    if grep -q '"disagreeing_peers":0,"contested_peers":0,"rival_heights_unresolved":1,' "$L"; then
        ok "an unanswerable height at or below our tip records as unresolved, not as zero rivals"
    else
        cat "$L" >&2; bad "R15 unresolved height was folded into 'no rivals'"
    fi

    # R16 — THE HOST KEY REACHES SQL IN THE GUARDED FORM. The distinctness
    # control is only as good as the expression that derives a host from an
    # addr, and the naive rtrim(rtrim(addr,'0-9'),':') splits ONE machine
    # into TWO witnesses twice over: it eats the last octet of a portless
    # "1.2.3.4", and it keys the bracketed IPv6 that -addnode produces
    # (net_service_to_string) differently from the unbracketed IPv6 that
    # addrman and every inbound peer produce (p2p_node_create's fallback).
    # Both were confirmed against the node's own SQLite. The port may only
    # be stripped when those trailing digits are actually preceded by a
    # colon, brackets must be removed, and the key must be lowercased.
    d="$TMP/r16"
    cat >"$TMP/r16.sh" <<'STUB'
#!/usr/bin/env bash
s="${ZCL_PARITY_SQL:-}"
case "$s" in
  *"rtrim(rtrim(addr,'0123456789'),':')"*)
      echo "stub: naive host key reached SQL (splits one host into two): $s" >&2; exit 1 ;;
esac
case "$s" in
  *"substr(rtrim(addr,'0123456789'),-1)=':'"*) ;;
  *) echo "stub: host key is not guarded on a preceding colon: $s" >&2; exit 1 ;;
esac
case "$s" in
  *"trim("*"'[]')"*) ;;
  *) echo "stub: host key does not unbracket: $s" >&2; exit 1 ;;
esac
case "$s" in
  *"lower("*) ;;
  *) echo "stub: host key is not lowercased: $s" >&2; exit 1 ;;
esac
printf '%s' '{"schema":"zcl.result.v1","ok":true,"data":{"columns":["h","t","n"],"rows":[],"row_count":0,"truncated":false,"interrupted":false}}'
STUB
    chmod +x "$TMP/r16.sh"
    run_probe "$d" "$TMP/r16.sh" "printf '{\"result\":\"$HASH_OURS\"}'"
    L="$(ledger_of "$d")"
    if [ -s "$L" ] && grep -q '"reason":"no_hash_with_min_distinct_peers_2"' "$L"; then
        ok "the distinct-host key reaches SQL guarded, unbracketed and lowercased"
    else
        cat "$L" 2>/dev/null >&2; bad "R16 host key shape wrong (one machine could count as two witnesses)"
    fi

    # R17 — the query-aware LIMIT+1 sentinel. The thirteenth qualifying
    # cluster is a rival below our tip, ordered after twelve higher-ranked
    # local-chain clusters. A sentinel row must make this observation unknown.
    d="$TMP/r17"
    make_ranked_clusters "$TMP/r17.tsv" yes
    query_aware_cluster_stub "$TMP/r17.sh" "$TMP/r17.tsv"
    local hash_by_height='printf -v h "%064x" "$((3197949 - ZCL_PARITY_HEIGHT + 1))"; printf "{\"result\":\"%s\"}" "$h"'
    run_probe "$d" "$TMP/r17.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"reason":"remote_observations_cluster_limit_reached"' "$L" &&
       grep -q '"clusters_seen":13,' "$L" &&
       grep -q '"cluster_census_complete":false,"qualifying_cluster_census_complete":false' "$L" &&
       grep -q '"disagreeing_peers":null' "$L" &&
       grep -q '"disagreeing_hashes":null' "$L" &&
       grep -q '"contested_peers":null,"rival_heights_unresolved":null,' "$L"; then
        ok "a thirteenth qualifying cluster makes the capped observation unknown"
    else
        cat "$L" >&2; bad "R17 capped cluster query was treated as complete"
    fi

    # R18 — exactly twelve clusters are still a complete census: the
    # sentinel query returns twelve rows, so the clean observation remains valid.
    d="$TMP/r18"
    make_ranked_clusters "$TMP/r18.tsv" no
    query_aware_cluster_stub "$TMP/r18.sh" "$TMP/r18.tsv"
    run_probe "$d" "$TMP/r18.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" &&
       grep -q '"clusters_seen":12,' "$L" &&
       grep -q '"contested_peers":0,"rival_heights_unresolved":0,' "$L"; then
        ok "an exactly-at-cap complete agreeing census remains valid"
    else
        cat "$L" >&2; bad "R18 exactly-at-cap census was not preserved"
    fi

    # R19 — a one-witness sentinel cannot contest the verdict. The reviewed
    # candidate incorrectly refuses solely because row 13 exists.
    d="$TMP/r19"
    make_ranked_clusters "$TMP/r19.tsv" no
    append_one_witness_tails "$TMP/r19.tsv" 1
    query_aware_cluster_stub "$TMP/r19.sh" "$TMP/r19.tsv"
    run_probe "$d" "$TMP/r19.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" &&
       grep -q '"contested_peers":0,"rival_heights_unresolved":0,' "$L" &&
       grep -q '"clusters_seen":13,"cluster_census_complete":false,"qualifying_cluster_census_complete":true' "$L" &&
       grep -q '"disagreeing_peers":null' "$L" &&
       grep -q '"disagreeing_hashes":null' "$L" &&
       grep -q '"heights_above_tip":null' "$L"; then
        ok "a one-witness sentinel preserves valid agreement"
    else
        cat "$L" >&2; bad "R19 one-witness sentinel changed the agreement policy"
    fi

    # R20 — two more one-witness rows beyond the returned sentinel must not
    # move the same cap regression to row 15.
    d="$TMP/r20"
    make_ranked_clusters "$TMP/r20.tsv" no
    append_one_witness_tails "$TMP/r20.tsv" 3
    query_aware_cluster_stub "$TMP/r20.sh" "$TMP/r20.tsv"
    run_probe "$d" "$TMP/r20.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" &&
       grep -q '"contested_peers":0,"rival_heights_unresolved":0,' "$L" &&
       grep -q '"clusters_seen":13,"cluster_census_complete":false,"qualifying_cluster_census_complete":true' "$L" &&
       grep -q '"disagreeing_peers":null' "$L" &&
       grep -q '"disagreeing_hashes":null' "$L" &&
       grep -q '"heights_above_tip":null' "$L"; then
        ok "additional below-threshold tail rows preserve valid agreement"
    else
        cat "$L" >&2; bad "R20 additional below-threshold tail changed agreement policy"
    fi

    # R21 — an actually malformed sentinel row with no count column must not
    # be accepted through cut's behavior for a missing delimiter.
    d="$TMP/r21"
    make_ranked_clusters "$TMP/r21.tsv" no
    query_aware_cluster_stub "$TMP/r21.sh" "$TMP/r21.tsv" missing-count
    run_probe "$d" "$TMP/r21.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"cluster_census_complete":false,"qualifying_cluster_census_complete":false' "$L" &&
       grep -q '"disagreeing_peers":null,"contested_peers":null,"rival_heights_unresolved":null' "$L"; then
        ok "a sentinel row missing its count field remains unknown"
    else
        cat "$L" >&2; bad "R21 missing sentinel count was trusted"
    fi

    # R22 — an integer outside Bash's signed arithmetic range must not turn
    # a failed numeric comparison into a complete qualifying census.
    d="$TMP/r22"
    make_ranked_clusters "$TMP/r22.tsv" no
    query_aware_cluster_stub "$TMP/r22.sh" "$TMP/r22.tsv" oversized-count
    run_probe "$d" "$TMP/r22.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"could-not-ask"' "$L" &&
       grep -q '"cluster_census_complete":false,"qualifying_cluster_census_complete":false' "$L" &&
       grep -q '"disagreeing_peers":null,"contested_peers":null,"rival_heights_unresolved":null' "$L"; then
        ok "an out-of-range sentinel count remains unknown"
    else
        cat "$L" >&2; bad "R22 out-of-range sentinel count was trusted"
    fi

    # R23 — a valid subthreshold sentinel completes the qualifying census,
    # but a qualifying conflicting cluster retained at rank 12 still counts.
    # The raw census remains incomplete because rank 13 is outside the cap.
    d="$TMP/r23"
    make_ranked_clusters_retained_rival "$TMP/r23.tsv"
    query_aware_cluster_stub "$TMP/r23.sh" "$TMP/r23.tsv"
    run_probe "$d" "$TMP/r23.sh" "$hash_by_height"
    L="$(ledger_of "$d")"
    if grep -q '"outcome":"agrees"' "$L" &&
       grep -q '"modal_remote_hash":"0000000000000000000000000000000000000000000000000000000000000001"' "$L" &&
       grep -q '"clusters_seen":13,"cluster_census_complete":false,"qualifying_cluster_census_complete":true' "$L" &&
       grep -q '"disagreeing_peers":null,"contested_peers":4,' "$L"; then
        ok "the matching modal remains agrees while the retained rival records four contested peers"
    else
        cat "$L" >&2; bad "R23 retained qualifying rival was not counted exactly"
    fi

    # R9 — the ledger is append-only across runs and every line is one
    # complete JSON object (the judge reads it line by line).
    d="$TMP/r9"; sql_stub "$TMP/r9.sh" "[[$HEIGHT,\"$HASH_OURS\",2]]" 1 false
    local i
    for i in 1 2 3; do
        run_probe "$d" "$TMP/r9.sh" \
            "printf '{\"result\":\"$HASH_OURS\"}'" "$((NOW - i * 600))"
    done
    L="$(ledger_of "$d")"
    if [ "$(wc -l < "$L")" -eq 3 ] &&
       [ "$(grep -c '^{.*}$' "$L")" -eq 3 ] &&
       [ "$(grep -c '"outcome":"agrees"' "$L")" -eq 3 ]; then
        ok "three runs append three complete, independently parseable lines"
    else
        cat "$L" >&2; bad "R9 ledger append shape wrong"
    fi
}

judge_recorded() {
    local d="$1" want="$2" rc="$3" out
    out="$(build/bin/z23-dev ops tip-agreement judge --ledger="$(ledger_of "$d")" --now="$NOW" 2>&1)" || {
        bad "native judge could not read the recorder ledger: $out"; return; }
    if [[ "$out" == *"\"verdict\":\"$want\""* && "$out" == *"\"judge_rc\":$rc"* ]]; then
        ok "recorder to native judge -> $want"
    else
        bad "recorder to native judge expected $want/$rc: $out"
    fi
}

recorder_judge_cases() {
    local d i hash_by_height
    d="$TMP/live-good"; sql_stub "$TMP/live-good.sh" "[[$HEIGHT,\"$HASH_OURS\",2]]" 1 false
    for i in 1 2 3 4 5 6 7 8; do
        run_probe "$d" "$TMP/live-good.sh" "printf '{\"result\":\"$HASH_OURS\"}'" "$((NOW - i * 600))"
    done
    judge_recorded "$d" PASS 0
    d="$TMP/live-unknown"
    for i in 1 2 3 4 5 6 7 8; do
        run_probe "$d" "exit 1" "printf '{\"result\":\"$HASH_OURS\"}'" "$((NOW - i * 600))"
    done
    judge_recorded "$d" NO_EVIDENCE 1
    d="$TMP/live-rival"
    make_ranked_clusters_retained_rival "$TMP/live-rival.tsv"
    query_aware_cluster_stub "$TMP/live-rival.sh" "$TMP/live-rival.tsv"
    hash_by_height='printf -v h "%064x" "$((3197949 - ZCL_PARITY_HEIGHT + 1))"; printf "{\"result\":\"%s\"}" "$h"'
    for i in 1 2 3 4 5 6 7 8; do
        run_probe "$d" "$TMP/live-rival.sh" "$hash_by_height" "$((NOW - i * 600))"
    done
    judge_recorded "$d" DISAGREE 1
}

case "$ONLY" in
    recorder) recorder_cases ;;
    all)      recorder_cases; recorder_judge_cases ;;
    *) echo "selftest: FAIL unknown --only '$ONLY'" >&2; exit 2 ;;
esac

if [ "$FAILED" -ne 0 ]; then
    echo "selftest: FAIL" >&2
    exit 1
fi
echo "selftest: PASS"
