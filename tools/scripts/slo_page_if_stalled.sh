#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# slo_page_if_stalled.sh — the EXTERNAL SLO PAGER (the pager half of the
# uptime-SLO loop). node_slo_probe.sh is the scoreboard (it dials each
# instance's RPC port and appends what it saw); `z23 ops slo` is the native
# read surface (it emits a windowed per-instance summary). Neither of those
# WAKES ANYONE UP. This script is the missing half: it reads the same ledger
# and, when a page-worthy condition is active, it (a) appends a durable page
# record, (b) best-effort broadcasts via wall(1), and (c) exits non-zero so a
# systemd unit wrapping it STAYS FAILED — the failed unit IS the page surface.
#
# WHY this exists at all: the live canonical node once made ZERO height
# progress for its ENTIRE 13-day uptime and nobody was paged — it was
# "reachable" the whole time, just not advancing. Worse, the external prober
# ledger itself went stale on 2026-07-20 and NOTHING noticed the prober had
# died. A pager that only fired on "unreachable" would have slept through
# both. So this pager treats four distinct failure shapes as page-worthy:
#
#   1. stale_ledger        — the prober itself stopped writing (self-watchdog:
#                            if the scoreboard dies, the pager must page; a
#                            silent prober is the worst failure of all).
#   2. probe_coverage       — the prober is still writing SOMETHING, but its
#                            sampling rate has dropped well below cadence
#                            (e.g. a flaky timer after a user-manager
#                            restart). Below-cadence coverage can starve the
#                            other conditions of the evidence they need, so
#                            this fires on RATE before staleness would.
#   3. canonical_unreachable — the canonical node stopped answering RPC.
#   4. canonical_no_advance  — the canonical node answers but its served
#                            height has not made a CONFIRMED climb (a strict
#                            increase corroborated by trailing samples) in
#                            over ZCL_SLO_PAGE_ADVANCE_SEC, measured as the
#                            age since that last confirmed climb over the
#                            WHOLE retained ledger — not a fixed trailing
#                            window (see the 2026-07-24 incident below).
#
# 2026-07-24 incident (the reason canonical_no_advance changed shape): the
# live canonical node's served_height had been flat at the SAME value for
# its entire 12-day retained ledger, and pages.jsonl had never been written
# once. The original canonical_no_advance check required >=2 reachable
# samples inside a trailing ZCL_SLO_PAGE_ADVANCE_SEC window whose first->last
# ts-span covered >= 3/4 of that window — a reasonable-looking heuristic that
# a concurrent PROBE OUTAGE defeated: the outage shrank the in-window sample
# count down to a short resumed cluster whose span fell under the 3/4
# threshold, so the check saw "not enough evidence" instead of "12 days
# flat" and stayed silent. The fix in this file measures the age since the
# last CONFIRMED climb over the full retained ledger instead of a windowed
# span, so a probe outage can shrink the window without hiding a real stall.
# probe_coverage exists so a probe outage of THAT shape pages on its own,
# independent of node health, rather than silently degrading other checks.
#
# Rotation bound: canonical_no_advance and probe_coverage both reason over
# whatever is in the CURRENT $ZCL_SLO_LEDGER_DIR/uptime-ledger.jsonl file
# only — they do not read rotated/archived generations. A stall whose last
# true climb predates the entire live unrotated ledger file (~121 days of
# retention at measured growth) is out of scope for the "age since last
# confirmed climb" calculation; such a case still pages (the fallback
# baseline is the OLDEST reachable sample in the file, a conservative LOWER
# BOUND on the true flat duration), it just cannot report the true climb
# age. Extend this to read rotated generations only if that boundary is
# ever actually hit in practice.
#
# Reads the prober ledger $ZCL_SLO_LEDGER_DIR/uptime-ledger.jsonl (schema in
# node_slo_probe.sh's header: one JSON object per probe per instance with
# fields ts, instance, reachable, served_height, oracle_height, gap_vs_oracle,
# error_detail, ...). Never TRUSTS a node self-report — everything here is a
# derivation over what an outside client actually observed and recorded.
#
# Page action per ACTIVE condition:
#   - append ONE JSON line to $ZCL_SLO_LEDGER_DIR/pages.jsonl:
#       {"ts":<now>,"condition":"<id>","detail":"<text>",
#        "served_height":<n|null>,"oracle_height":<n|null>,"gap_vs_oracle":<n|null>}
#   - DEDUP: a per-condition state file $ZCL_SLO_LEDGER_DIR/page-state/<id>.last
#     holds the epoch of the last announcement; a fresh page line + wall
#     broadcast is only emitted when the previous announcement is older than
#     ZCL_SLO_PAGE_RENOTIFY_SEC (a still-failing condition must not spam the
#     ledger every probe cycle, but must re-announce periodically so an
#     unacknowledged page stays visible).
#   - Whether or not deduped, an active condition means EXIT 1. The systemd
#     unit staying failed is the page — dedup only throttles the ledger/wall
#     noise, it never suppresses the failed-unit signal.
# No active condition => one OK summary line to stdout, exit 0.
#
# Blocker enrichment (best-effort, NEVER fatal): when a page is announced and
# ZCL_SLO_NODE_BIN is executable, the current typed blocker is folded into the
# detail so the pager record says WHY, not just THAT. Any failure/timeout of
# enrichment is swallowed — it can never change the verdict or the exit code.
#
# Usage:
#   slo_page_if_stalled.sh [evaluate]   # default: evaluate ledger, page/exit
#   slo_page_if_stalled.sh --selftest   # hermetic; tmp ledgers + fixed clock
#
# Env (test/operator injection seams):
#   ZCL_SLO_LEDGER_DIR        ledger dir (default ~/.local/state/zclassic23-slo)
#   ZCL_SLO_NOW               epoch override for "now" (staleness/window calc)
#   ZCL_SLO_PAGE_STALE_SEC    max age of the newest sample of ANY instance
#                             before stale_ledger fires (default 300)
#   ZCL_SLO_PAGE_UNREACH_SEC  canonical_unreachable window (default 600)
#   ZCL_SLO_PAGE_ADVANCE_SEC  canonical_no_advance: max age since the last
#                             CONFIRMED climb before it fires (default 7200)
#   ZCL_SLO_PAGE_ADVANCE_MIN_TRAILING
#                             reachable samples required, both to CONFIRM a
#                             climb (corroboration after it) and to let
#                             canonical_no_advance fire at all (evidence
#                             since the baseline) (default 2)
#   ZCL_SLO_PAGE_COVERAGE_WINDOW_SEC   probe_coverage trailing window
#                             (default 3600)
#   ZCL_SLO_PAGE_COVERAGE_MIN_RATIO    probe_coverage min (observed/expected)
#                             sample ratio before it fires (default 0.5)
#   ZCL_SLO_PAGE_COVERAGE_CADENCE_SEC  probe_coverage expected inter-sample
#                             interval (default 60, matching the standing
#                             probe timer's cadence)
#   ZCL_SLO_PAGE_RENOTIFY_SEC re-announce interval per condition (default 21600)
#   ZCL_SLO_PAGE_WALL         set 0 to skip the wall(1) broadcast (default 1)
#   ZCL_SLO_NODE_BIN          node binary for blocker enrichment
#                             (default <script-dir>/../../build/bin/zclassic23,
#                              skipped when not executable)
#
# No python (banned), no jq — bash + awk + flock only, same rule as
# node_slo_probe.sh.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The ONE reader per measurement — see tools/scripts/lib/evidence_sources.sh.
. "$SCRIPT_DIR/lib/evidence_sources.sh"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

LEDGER_DIR="${ZCL_SLO_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-slo}"
LEDGER_FILE="$LEDGER_DIR/uptime-ledger.jsonl"
PAGES_FILE="$LEDGER_DIR/pages.jsonl"
PAGE_STATE_DIR="$LEDGER_DIR/page-state"

STALE_SEC="${ZCL_SLO_PAGE_STALE_SEC:-300}"
UNREACH_SEC="${ZCL_SLO_PAGE_UNREACH_SEC:-600}"
ADVANCE_SEC="${ZCL_SLO_PAGE_ADVANCE_SEC:-7200}"
ADV_MIN_TRAILING="${ZCL_SLO_PAGE_ADVANCE_MIN_TRAILING:-2}"
COVERAGE_WINDOW_SEC="${ZCL_SLO_PAGE_COVERAGE_WINDOW_SEC:-3600}"
COVERAGE_MIN_RATIO="${ZCL_SLO_PAGE_COVERAGE_MIN_RATIO:-0.5}"
COVERAGE_CADENCE_SEC="${ZCL_SLO_PAGE_COVERAGE_CADENCE_SEC:-60}"
RENOTIFY_SEC="${ZCL_SLO_PAGE_RENOTIFY_SEC:-21600}"
WALL="${ZCL_SLO_PAGE_WALL:-1}"

# Which nodes exist on this host, asked of the prober rather than inferred
# from ledger history. Empty (prober missing/unreadable) falls back to
# ageing every instance in the ledger — noisier, never quieter, which is the
# right direction to fail for a pager.
LIVE_INSTANCES="${ZCL_SLO_PAGE_LIVE_INSTANCES-$(
    "$SCRIPT_DIR/node_slo_probe.sh" --list-instances 2>/dev/null | paste -sd, - || true
)}"

# Node binary for best-effort blocker enrichment. An explicit override always
# wins (even to empty, which disables enrichment); otherwise default to this
# checkout's build output. Never required — enrichment is decoration.
resolve_node_bin() {
    if [ -n "${ZCL_SLO_NODE_BIN+x}" ]; then printf '%s' "${ZCL_SLO_NODE_BIN}"; return 0; fi
    printf '%s' "$SCRIPT_DIR/../../build/bin/zclassic23"
}
NODE_BIN="$(resolve_node_bin)"

# ── helpers ────────────────────────────────────────────────────────────

# json_escape / jstr: emit a JSON string literal (escaped) — same pattern as
# node_slo_probe.sh so page detail text with quotes/backslashes stays valid.
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
jstr() { printf '"%s"' "$(json_escape "${1:-}")"; }

# jtok <value>: pass a bare integer through as a JSON number, everything else
# (empty, "null", non-numeric) becomes JSON null — a page record never carries
# a fabricated 0 or an unescaped token.
jtok() {
    local v="${1:-}"
    case "$v" in
        ''|null|-) printf 'null' ;;
        -*) case "${v#-}" in ''|*[!0-9]*) printf 'null' ;; *) printf '%s' "$v" ;; esac ;;
        *[!0-9]*) printf 'null' ;;
        *) printf '%s' "$v" ;;
    esac
}

# append_line <file> <json-line>: flock-serialized append (bounded -w 30,
# explicit failure) — copied from node_slo_probe.sh so a timer run and an
# ad-hoc operator run can never interleave a torn line into pages.jsonl.
append_line() { evidence_append_line "$1" "$2" "slo-page"; }

# enrich_blocker: best-effort typed blocker snapshot, single-line, <=400 bytes,
# NEVER fatal. Prints "" on any absence/timeout/failure. The 5 s timeout and
# the executable guard keep a wedged or missing node from ever stalling or
# aborting the pager.
enrich_blocker() {
    ZCL_EVIDENCE_TIMEOUT_SEC=5 \
        evidence_node_dumpstate "$NODE_BIN" blocker | head -c 400 || true
    return 0
}

# evaluate_ledger <now>: emit zero-or-more tab-separated PAGE rows plus one
# SUMMARY row. PAGE row is: PAGE<TAB>condition<TAB>detail<TAB>served<TAB>oracle
# <TAB>gap  (served/oracle/gap already normalized to an integer or the literal
# "null"). Only called when the ledger file is non-empty; the missing/empty
# case is handled by the caller as an unconditional stale_ledger.
evaluate_ledger() {
    local now="$1"
    awk -v now="$now" -v stale_sec="$STALE_SEC" -v unreach_sec="$UNREACH_SEC" \
        -v live_instances="${LIVE_INSTANCES:-}" \
        -v advance_sec="$ADVANCE_SEC" -v adv_min_trailing="$ADV_MIN_TRAILING" \
        -v cov_window_sec="$COVERAGE_WINDOW_SEC" -v cov_min_ratio="$COVERAGE_MIN_RATIO" \
        -v cov_cadence_sec="$COVERAGE_CADENCE_SEC" '
        function fld(line, key,   re, s) {
            re = "\"" key "\":(-?[0-9]+|null|true|false)"
            if (match(line, re) == 0) return ""
            s = substr(line, RSTART, RLENGTH)
            sub(/^"[^"]*":/, "", s)
            return s
        }
        function isnum(s) { return (s != "" && s != "null" && s != "true" && s != "false") }
        function ntok(s)  { return (isnum(s) ? s : "null") }
        function instof(line,   re, s) {
            re = "\"instance\":\"[a-zA-Z0-9_]+\""
            if (match(line, re) == 0) return ""
            s = substr(line, RSTART, RLENGTH)
            sub(/^"instance":"/, "", s)
            sub(/"$/, "", s)
            return s
        }
        {
            t = fld($0, "ts")
            if (t == "") next
            t = t + 0
            inst = instof($0)
            if (inst == "") next
            if (!(inst in imax) || t > imax[inst]) imax[inst] = t
            if (inst == "canonical") {
                nc++
                cts[nc]    = t
                creach[nc] = (index($0, "\"reachable\":true") > 0) ? 1 : 0
                cserved[nc] = fld($0, "served_height")
                coracle[nc] = fld($0, "oracle_height")
                cgap[nc]    = fld($0, "gap_vs_oracle")
            }
        }
        END {
            # chronological order = append order, but sort defensively by ts
            # (insertion sort is fine at this n).
            for (i = 2; i <= nc; i++) {
                tv=cts[i]; rv=creach[i]; sv=cserved[i]; ov=coracle[i]; gv=cgap[i]
                j = i - 1
                while (j >= 1 && cts[j] > tv) {
                    cts[j+1]=cts[j]; creach[j+1]=creach[j]; cserved[j+1]=cserved[j]
                    coracle[j+1]=coracle[j]; cgap[j+1]=cgap[j]
                    j--
                }
                cts[j+1]=tv; creach[j+1]=rv; cserved[j+1]=sv; coracle[j+1]=ov; cgap[j+1]=gv
            }

            last_served="null"; last_oracle="null"; last_gap="null"
            newest_c_reach=0; newest_c_ts=0
            if (nc > 0) {
                newest_c_ts    = cts[nc]
                newest_c_reach = creach[nc]
                last_served = ntok(cserved[nc])
                last_oracle = ntok(coracle[nc])
                last_gap    = ntok(cgap[nc])
            }

            # ── stale_ledger: the OLDEST newest-per-instance sample is too
            # old. If the prober died, every instance goes stale together;
            # deterministic tie-break on instance name keeps the detail stable.
            # Only instances the prober CURRENTLY probes can be stale. The
            # rows of a retired lane stay in the retained ledger forever, so
            # ageing every name ever seen would page "prober may be dead"
            # falsely and permanently the moment a lane is retired. The
            # instance table in the prober is the authority for who exists;
            # live_instances carries it in.
            nlive = split(live_instances, livearr, ",")
            for (i = 1; i <= nlive; i++) if (livearr[i] != "") live[livearr[i]] = 1

            stale=0; stale_detail=""
            worst_inst=""; worst_age=-1
            for (inst in imax) {
                if (nlive > 0 && !(inst in live)) continue
                age = now - imax[inst]
                if (age > worst_age || (age == worst_age && (worst_inst == "" || inst < worst_inst))) {
                    worst_age = age; worst_inst = inst
                }
            }
            if (worst_inst != "" && worst_age > stale_sec) {
                stale = 1
                stale_detail = "instance=" worst_inst " newest_sample_age=" worst_age \
                    "s exceeds stale threshold " stale_sec "s (prober may be dead)"
            }

            # ── probe_coverage: prober sampling density in a trailing window,
            # independent of node health. A stalled prober/timer (e.g. after
            # a user-manager restart) thins the sample rate well before the
            # newest sample goes fully stale, and a thin sample rate can also
            # shrink the evidence available to other conditions. Fires on
            # RATE, not staleness or reachability.
            cov_cutoff = now - cov_window_sec
            cov_n = 0
            for (i = 1; i <= nc; i++) if (cts[i] >= cov_cutoff) cov_n++
            overall_min_ts = (nc > 0 ? cts[1] : now)
            eff_window = cov_window_sec
            if (now - overall_min_ts < cov_window_sec) eff_window = now - overall_min_ts
            coverage = 0; coverage_detail = ""; ratio = 1
            if (eff_window >= cov_cadence_sec * 3) {
                expected = eff_window / cov_cadence_sec
                ratio = (expected > 0) ? cov_n / expected : 1
                if (ratio < cov_min_ratio) {
                    coverage = 1
                    coverage_detail = "probe coverage " int(ratio*100) "% (" cov_n "/" int(expected) \
                        " expected canonical samples in trailing " eff_window "s at " cov_cadence_sec \
                        "s cadence) -- prober/timer likely stalling (e.g. user-manager), independent of node health"
                }
            }

            # ── canonical_unreachable: >=3 canonical samples in the window,
            # ALL reachable:false, and the newest canonical sample unreachable.
            unreach=0; unreach_detail=""
            cutoff_u = now - unreach_sec
            win_n=0; win_reach_true=0
            for (i = 1; i <= nc; i++) if (cts[i] >= cutoff_u) {
                win_n++
                if (creach[i]) win_reach_true++
            }
            if (win_n >= 3 && win_reach_true == 0 && nc > 0 && newest_c_reach == 0) {
                unreach = 1
                unreach_detail = "canonical unreachable: " win_n " samples in last " \
                    unreach_sec "s all reachable=false (newest sample age=" (now - newest_c_ts) "s)"
            }

            # ── canonical_no_advance: age since the most recent CONFIRMED
            # climb (a strict served_height increase corroborated by
            # >= adv_min_trailing later reachable samples), measured over the
            # WHOLE retained ledger — not a fixed trailing window. A windowed
            # span check is fooled by a probe outage that shrinks the
            # in-window sample count (see the file header for the incident
            # this replaced). A height DECREASE is never an advance. A single
            # anomalous uptick as the newest sample cannot clear an active
            # stall by itself: the backward scan requires trailing
            # corroboration, so it skips an uncorroborated tip and falls
            # through to the older confirmed baseline.
            rn = 0
            for (i = 1; i <= nc; i++) {
                if (creach[i] && isnum(cserved[i])) { rn++; rts[rn] = cts[i]; rh[rn] = cserved[i] + 0 }
            }
            noadv = 0; noadv_detail = ""; noadv_served="null"; noadv_oracle="null"; noadv_gap="null"
            if (rn > 0) {
                adv_idx = 0
                for (i = rn; i >= 2; i--) {
                    if (rh[i] > rh[i-1] && (rn - i) >= adv_min_trailing) { adv_idx = i; break }
                }
                if (adv_idx == 0) adv_idx = 1   # no confirmed climb in retained ledger -> baseline = oldest reachable sample (conservative LOWER BOUND on flat duration)
                last_adv_ts = rts[adv_idx]
                trailing    = rn - adv_idx
                age         = now - last_adv_ts
                if (age > advance_sec && trailing >= adv_min_trailing) {
                    noadv = 1
                    noadv_detail = "canonical no net advance: served_height held at " rh[rn] " for " age "s since last confirmed climb (to " rh[adv_idx] ") at ts=" last_adv_ts " (advance_sec=" advance_sec "), " trailing " reachable samples observed since with zero climb"
                    noadv_served = ntok(cserved[nc]); noadv_oracle = ntok(coracle[nc]); noadv_gap = ntok(cgap[nc])
                }
            }

            # emit active conditions in a fixed order (self-watchdog first)
            if (stale)    printf "PAGE\tstale_ledger\t%s\t%s\t%s\t%s\n", stale_detail, last_served, last_oracle, last_gap
            if (coverage) printf "PAGE\tprobe_coverage\t%s\t%s\t%s\t%s\n", coverage_detail, last_served, last_oracle, last_gap
            if (unreach)  printf "PAGE\tcanonical_unreachable\t%s\t%s\t%s\t%s\n", unreach_detail, last_served, last_oracle, last_gap
            if (noadv)    printf "PAGE\tcanonical_no_advance\t%s\t%s\t%s\t%s\n", noadv_detail, noadv_served, noadv_oracle, noadv_gap

            printf "SUMMARY\tcanonical_samples=%d newest_canonical_age=%s stale=%d unreachable=%d no_advance=%d coverage_ratio=%.2f\n", \
                nc, (nc > 0 ? (now - newest_c_ts) "s" : "na"), stale, unreach, noadv, ratio
        }
    ' "$LEDGER_FILE"
}

# announce_or_dedup <now> <cond> <detail> <served> <oracle> <gap>: throttled
# announcement. Appends a page line + wall broadcast + WARN only when the last
# announcement of this condition is older than RENOTIFY_SEC (or never made);
# otherwise it is a silent no-op (the caller's exit 1 is the standing page).
announce_or_dedup() {
    local now="$1" cond="$2" detail="$3" served="$4" oracle="$5" gap="$6"
    local statefile="$PAGE_STATE_DIR/$cond.last"
    local last_epoch=0 since
    if [ -f "$statefile" ]; then
        last_epoch="$(<"$statefile")"
        case "$last_epoch" in ''|*[!0-9]*) last_epoch=0 ;; esac
    fi
    since=$(( now - last_epoch ))
    if [ -f "$statefile" ] && [ "$since" -lt "$RENOTIFY_SEC" ]; then
        echo "slo-page: WARN condition=$cond ACTIVE but deduped (last announced ${since}s ago < renotify ${RENOTIFY_SEC}s)" >&2
        return 0
    fi

    local detail_full="$detail" blk
    blk="$(enrich_blocker)"
    [ -n "$blk" ] && detail_full="$detail | blocker=$blk"

    local line
    line="$(printf '{"ts":%s,"condition":%s,"detail":%s,"served_height":%s,"oracle_height":%s,"gap_vs_oracle":%s}' \
        "$now" "$(jstr "$cond")" "$(jstr "$detail_full")" \
        "$(jtok "$served")" "$(jtok "$oracle")" "$(jtok "$gap")")"
    append_line "$PAGES_FILE" "$line" || true

    mkdir -p "$PAGE_STATE_DIR"
    printf '%s\n' "$now" > "$statefile"

    if [ "$WALL" != "0" ]; then
        printf 'zclassic23 SLO PAGE [%s]: %s\n' "$cond" "$detail_full" | wall 2>/dev/null || true
    fi
    echo "slo-page: WARN PAGE condition=$cond detail=$detail_full" >&2
    return 0
}

# ── evaluate ────────────────────────────────────────────────────────────

cmd_evaluate() {
    mkdir -p "$LEDGER_DIR"
    local now="${ZCL_SLO_NOW:-$(date +%s)}"

    local CONDS=()
    local -A DETAIL=() SERVED=() ORACLE=() GAP=()
    local SUMMARY_TEXT=""

    if [ ! -s "$LEDGER_FILE" ]; then
        # Self-watchdog top priority: no ledger at all means the prober never
        # wrote (dead or never started). That is itself the loudest page.
        CONDS+=("stale_ledger")
        DETAIL["stale_ledger"]="ledger file missing or empty at $LEDGER_FILE (prober has written no sample; it may be dead or never started)"
        SERVED["stale_ledger"]="null"; ORACLE["stale_ledger"]="null"; GAP["stale_ledger"]="null"
        SUMMARY_TEXT="canonical_samples=0 newest_canonical_age=na stale=1 unreachable=0 no_advance=0 reason=no_ledger_file"
    else
        local marker c1 c2 c3 c4 c5
        while IFS=$'\t' read -r marker c1 c2 c3 c4 c5; do
            case "$marker" in
                PAGE)
                    CONDS+=("$c1")
                    DETAIL["$c1"]="$c2"; SERVED["$c1"]="$c3"; ORACLE["$c1"]="$c4"; GAP["$c1"]="$c5"
                    ;;
                SUMMARY) SUMMARY_TEXT="$c1" ;;
            esac
        done < <(evaluate_ledger "$now")
    fi

    if [ "${#CONDS[@]}" -gt 0 ]; then
        local cond
        for cond in "${CONDS[@]}"; do
            announce_or_dedup "$now" "$cond" "${DETAIL[$cond]}" "${SERVED[$cond]}" "${ORACLE[$cond]}" "${GAP[$cond]}"
        done
        echo "slo-page: PAGE active=${CONDS[*]} | $SUMMARY_TEXT" >&2
        exit 1
    fi

    echo "slo-page: OK no active page conditions | $SUMMARY_TEXT"
    exit 0
}

# ── selftest (hermetic; tmp ledger dirs + fixed clock, no live nodes) ──

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

# st_line <file> <instance> <ts> <reachable 0|1> <served|null> <oracle|null> <gap|null>
st_line() {
    local f="$1" inst="$2" ts="$3" reach="$4" served="$5" oracle="$6" gap="$7"
    printf '{"ts":%d,"instance":"%s","rpcport":1,"datadir":"/x","reachable":%s,"served_height":%s,"header_height":%s,"latency_ms":1,"oracle_height":%s,"max_height":%s,"gap_vs_max":0,"gap_vs_oracle":%s,"error_detail":""}\n' \
        "$ts" "$inst" "$( [ "$reach" = 1 ] && echo true || echo false )" "$served" "$served" "$oracle" "$oracle" "$gap" >> "$f"
}

cmd_selftest() {
    local base f p p2 k ts served now now2 rc before
    # ST_TMP stays global (not local): the EXIT trap runs after this function
    # returns, where a local would be out of scope and trip set -u.
    ST_TMP="$(mktemp -d /tmp/zcl-slo-page-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT
    base=1700000000

    # Shared throttle knobs for the no-advance cluster (a/b/c/d): a big stale
    # threshold and a big advance window so pushing "now" forward past the
    # renotify interval re-announces the SAME condition rather than tripping
    # a different one. Coverage is disabled here (ratio can never be < 0) —
    # these fixtures sample at a 500s cadence that would otherwise spuriously
    # trip probe_coverage against its 60s default cadence; coverage gets its
    # own dedicated cases below.
    local ENV_NA="ZCL_SLO_PAGE_WALL=0 ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=10000 ZCL_SLO_PAGE_UNREACH_SEC=600 ZCL_SLO_PAGE_ADVANCE_SEC=4000 ZCL_SLO_PAGE_RENOTIFY_SEC=100 ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0"

    # (a) advancing canonical => rc 0, no pages.jsonl.
    mkdir -p "$ST_TMP/a"; f="$ST_TMP/a/uptime-ledger.jsonl"
    for k in 0 1 2 3 4 5 6 7; do
        ts=$((base + k * 500)); served=$((10 + k))
        st_line "$f" canonical "$ts" 1 "$served" 100 $((100 - served))
    done
    now=$((base + 7 * 500))
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/a" ZCL_SLO_NOW="$now" $ENV_NA \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || st_fail "case=advancing expected rc 0 got $rc"
    [ ! -f "$ST_TMP/a/pages.jsonl" ] || st_fail "case=advancing expected NO pages.jsonl"
    echo "selftest: ok case=advancing"

    # (b) no-advance => rc 1 + exactly one page line containing canonical_no_advance.
    # 9 flat samples ts=0,500,...,4000; now=4500 => age 4500 > ADVANCE_SEC=4000
    # (override), trailing=8 >= adv_min_trailing(2).
    mkdir -p "$ST_TMP/b"; f="$ST_TMP/b/uptime-ledger.jsonl"
    for k in 0 1 2 3 4 5 6 7 8; do
        ts=$((base + k * 500))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=$((base + 9 * 500))
    p="$ST_TMP/b/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/b" ZCL_SLO_NOW="$now" $ENV_NA \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=no-advance expected rc 1 got $rc"
    [ -f "$p" ] || st_fail "case=no-advance expected pages.jsonl"
    [ "$(wc -l < "$p")" -eq 1 ] || { cat "$p" >&2; st_fail "case=no-advance expected exactly 1 page line"; }
    grep -q 'canonical_no_advance' "$p" || { cat "$p" >&2; st_fail "case=no-advance missing condition id"; }
    echo "selftest: ok case=no-advance"

    # (c) immediate rerun => rc 1 and pages.jsonl UNCHANGED (dedup).
    before="$(<"$p")"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/b" ZCL_SLO_NOW="$now" $ENV_NA \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=dedup expected rc 1 got $rc"
    [ "$(wc -l < "$p")" -eq 1 ] || { cat "$p" >&2; st_fail "case=dedup pages.jsonl line count changed"; }
    [ "$(<"$p")" = "$before" ] || { cat "$p" >&2; st_fail "case=dedup pages.jsonl content changed"; }
    echo "selftest: ok case=dedup"

    # (d) rerun with now pushed past RENOTIFY => second page line appended.
    now2=$((now + 200))    # renotify=100
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/b" ZCL_SLO_NOW="$now2" $ENV_NA \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=renotify expected rc 1 got $rc"
    [ "$(wc -l < "$p")" -eq 2 ] || { cat "$p" >&2; st_fail "case=renotify expected 2 page lines"; }
    echo "selftest: ok case=renotify"

    # (e) stale ledger (present but newest sample far in the past) => rc 1 + stale_ledger.
    mkdir -p "$ST_TMP/e"; f="$ST_TMP/e/uptime-ledger.jsonl"
    st_line "$f" canonical "$base" 1 5 100 95
    now=$((base + 100000))
    p="$ST_TMP/e/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/e" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=stale expected rc 1 got $rc"
    grep -q 'stale_ledger' "$p" || { cat "$p" >&2; st_fail "case=stale missing stale_ledger"; }
    echo "selftest: ok case=stale-ledger"

    # (e2) a RETIRED instance must not page. Its rows sit in the retained
    # ledger forever and never get another sample, so ageing every name ever
    # seen pages "prober may be dead" falsely and permanently the moment a
    # lane is retired. Live rows fresh + retired rows ancient => rc 0.
    # The paired assertion below is the one that matters: the same ancient
    # rows DO page when the instance is still live, so this is a narrowing of
    # who can be stale, not a weakening of staleness itself.
    mkdir -p "$ST_TMP/e2"; f="$ST_TMP/e2/uptime-ledger.jsonl"
    : > "$f"
    st_line "$f" retired_lane "$base" 1 5 100 95
    now=$((base + 100000))
    st_line "$f" canonical "$now" 1 5 100 95
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/e2" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        ZCL_SLO_PAGE_LIVE_INSTANCES=canonical \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || { cat "$ST_TMP/e2/pages.jsonl" >&2 2>/dev/null || true
        st_fail "case=retired-not-stale a retired instance must not page (rc $rc)"; }
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/e2" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        ZCL_SLO_PAGE_LIVE_INSTANCES=canonical,retired_lane \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=retired-not-stale the SAME old rows must page while the instance is live (rc $rc)"
    echo "selftest: ok case=retired-not-stale"

    # (f) all-unreachable streak => rc 1 + canonical_unreachable.
    mkdir -p "$ST_TMP/f"; f="$ST_TMP/f/uptime-ledger.jsonl"
    for k in 0 1 2 3; do
        ts=$((base + k * 60))
        st_line "$f" canonical "$ts" 0 null null null
    done
    now=$((base + 3 * 60))
    p="$ST_TMP/f/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/f" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        ZCL_SLO_PAGE_UNREACH_SEC=600 ZCL_SLO_PAGE_ADVANCE_SEC=7200 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=unreachable expected rc 1 got $rc"
    grep -q 'canonical_unreachable' "$p" || { cat "$p" >&2; st_fail "case=unreachable missing condition id"; }
    echo "selftest: ok case=unreachable"

    # (g) missing ledger file entirely => rc 1 + stale_ledger.
    p="$ST_TMP/g/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/g" ZCL_SLO_NOW="$base" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=missing-ledger expected rc 1 got $rc"
    grep -q 'stale_ledger' "$p" || { cat "$p" >&2; st_fail "case=missing-ledger missing stale_ledger"; }
    echo "selftest: ok case=missing-ledger"

    # (h) gap-masks-long-stall: a probe OUTAGE shrinks the in-window sample
    # span and must NOT mask a real long-run stall. Uses PRODUCTION defaults
    # (no ADVANCE_SEC override) — this is the exact 2026-07-24 incident
    # shape: a canonical node flat for the ENTIRE retained ledger, plus a
    # probe gap sitting right before "now".
    mkdir -p "$ST_TMP/h"; f="$ST_TMP/h/uptime-ledger.jsonl"
    # Dense flat history: served_height=10 every 300s, ts=0..13800 (47 samples).
    for k in $(seq 0 46); do
        ts=$((k * 300))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    # Gap: no samples for 7200s (14000..21200), i.e. the outage window.
    # Resumed cluster: served_height still 10, every 100s, 21200..21800 (7 samples).
    for k in 0 1 2 3 4 5 6; do
        ts=$((21200 + k * 100))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=21800
    p="$ST_TMP/h/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/h" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=gap-masks-long-stall expected rc 1 got $rc"
    [ -f "$p" ] || st_fail "case=gap-masks-long-stall expected pages.jsonl"
    grep -q 'canonical_no_advance' "$p" || { cat "$p" >&2; st_fail "case=gap-masks-long-stall missing canonical_no_advance (probe gap masked a long-run stall)"; }
    echo "selftest: ok case=gap-masks-long-stall"

    # (i) probe-coverage-degraded: fresh + reachable + no real stall, but
    # sample density ~30% in the trailing window (200s spacing against a
    # 60s cadence) => pages probe_coverage AND NOTHING ELSE.
    mkdir -p "$ST_TMP/i"; f="$ST_TMP/i/uptime-ledger.jsonl"
    for k in $(seq 0 18); do
        ts=$((k * 200))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=3600
    p="$ST_TMP/i/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/i" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        ZCL_SLO_PAGE_UNREACH_SEC=600 ZCL_SLO_PAGE_ADVANCE_SEC=7200 \
        ZCL_SLO_PAGE_COVERAGE_WINDOW_SEC=3600 ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0.5 \
        ZCL_SLO_PAGE_COVERAGE_CADENCE_SEC=60 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=probe-coverage-degraded expected rc 1 got $rc"
    [ -f "$p" ] || st_fail "case=probe-coverage-degraded expected pages.jsonl"
    [ "$(wc -l < "$p")" -eq 1 ] || { cat "$p" >&2; st_fail "case=probe-coverage-degraded expected exactly 1 page line"; }
    grep -q 'probe_coverage' "$p" || { cat "$p" >&2; st_fail "case=probe-coverage-degraded missing condition id"; }
    if grep -qE 'stale_ledger|canonical_unreachable|canonical_no_advance' "$p"; then
        cat "$p" >&2; st_fail "case=probe-coverage-degraded unexpected extra condition"
    fi
    echo "selftest: ok case=probe-coverage-degraded"

    # (j) probe-coverage-nominal: ~100% density (60s spacing = 60s cadence)
    # => rc 0.
    mkdir -p "$ST_TMP/j"; f="$ST_TMP/j/uptime-ledger.jsonl"
    for k in $(seq 0 60); do
        ts=$((k * 60))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=3600
    p="$ST_TMP/j/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/j" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=300 \
        ZCL_SLO_PAGE_UNREACH_SEC=600 ZCL_SLO_PAGE_ADVANCE_SEC=7200 \
        ZCL_SLO_PAGE_COVERAGE_WINDOW_SEC=3600 ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0.5 \
        ZCL_SLO_PAGE_COVERAGE_CADENCE_SEC=60 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || st_fail "case=probe-coverage-nominal expected rc 0 got $rc"
    [ ! -f "$p" ] || st_fail "case=probe-coverage-nominal expected NO pages.jsonl"
    echo "selftest: ok case=probe-coverage-nominal"

    # (k) never-advanced-dense: dense flat samples spanning just OVER
    # ADVANCE_SEC => pages canonical_no_advance. Companion (k2) below: the
    # same shape but spanning just UNDER ADVANCE_SEC => rc 0.
    mkdir -p "$ST_TMP/k"; f="$ST_TMP/k/uptime-ledger.jsonl"
    for k in $(seq 0 37); do
        ts=$((k * 100))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=3700
    p="$ST_TMP/k/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/k" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_ADVANCE_SEC=3600 \
        ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=never-advanced-dense-over expected rc 1 got $rc"
    grep -q 'canonical_no_advance' "$p" || { cat "$p" >&2; st_fail "case=never-advanced-dense-over missing condition id"; }
    echo "selftest: ok case=never-advanced-dense-over"

    mkdir -p "$ST_TMP/k2"; f="$ST_TMP/k2/uptime-ledger.jsonl"
    for k in $(seq 0 35); do
        ts=$((k * 100))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    now=3500
    p2="$ST_TMP/k2/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/k2" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_ADVANCE_SEC=3600 \
        ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || st_fail "case=never-advanced-dense-under expected rc 0 got $rc"
    [ ! -f "$p2" ] || st_fail "case=never-advanced-dense-under expected NO pages.jsonl"
    echo "selftest: ok case=never-advanced-dense-under"

    # (l) spurious-uptick-does-not-clear-page: a long flat baseline past
    # ADVANCE_SEC plus ONE final higher-height sample must still page — the
    # uptick lacks trailing corroboration, so the backward scan skips it and
    # falls through to the older confirmed (flat) baseline.
    mkdir -p "$ST_TMP/l"; f="$ST_TMP/l/uptime-ledger.jsonl"
    for k in $(seq 0 36); do
        ts=$((k * 100))
        st_line "$f" canonical "$ts" 1 10 100 90
    done
    st_line "$f" canonical 3700 1 11 100 89
    now=3700
    p="$ST_TMP/l/pages.jsonl"
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/l" ZCL_SLO_NOW="$now" ZCL_SLO_PAGE_WALL=0 \
        ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_ADVANCE_SEC=3600 \
        ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0 \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=spurious-uptick expected rc 1 got $rc"
    grep -q 'canonical_no_advance' "$p" || { cat "$p" >&2; st_fail "case=spurious-uptick missing condition id (uptick incorrectly cleared the page)"; }
    echo "selftest: ok case=spurious-uptick-does-not-clear-page"

    # (m) confirmed-recent-advance: a confirmed mid-ledger climb (with
    # trailing corroboration) that is still recent => rc 0. The SAME static
    # ledger re-evaluated with "now" pushed past ADVANCE_SEC since that
    # climb => rc 1, and the reported served_height reflects the CURRENT
    # flat value (10), not the pre-climb baseline (5).
    mkdir -p "$ST_TMP/m"; f="$ST_TMP/m/uptime-ledger.jsonl"
    st_line "$f" canonical 0   1 5  100 95
    st_line "$f" canonical 100 1 5  100 95
    st_line "$f" canonical 200 1 10 100 90   # confirmed climb (5 -> 10)
    st_line "$f" canonical 300 1 10 100 90   # trailing corroboration #1
    st_line "$f" canonical 400 1 10 100 90   # trailing corroboration #2
    p="$ST_TMP/m/pages.jsonl"
    local ENV_M="ZCL_SLO_PAGE_WALL=0 ZCL_SLO_NODE_BIN=/nonexistent/zclassic23 ZCL_SLO_PAGE_STALE_SEC=100000 ZCL_SLO_PAGE_ADVANCE_SEC=1000 ZCL_SLO_PAGE_COVERAGE_MIN_RATIO=0"

    now=400
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/m" ZCL_SLO_NOW="$now" $ENV_M \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || st_fail "case=confirmed-recent-advance expected rc 0 (recent climb) got $rc"
    [ ! -f "$p" ] || st_fail "case=confirmed-recent-advance expected NO pages.jsonl before the window elapses"
    echo "selftest: ok case=confirmed-recent-advance (recent)"

    now2=1300
    rc=0
    env ZCL_SLO_LEDGER_DIR="$ST_TMP/m" ZCL_SLO_NOW="$now2" $ENV_M \
        bash "$SELF" evaluate >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || st_fail "case=confirmed-recent-advance expected rc 1 (aged past ADVANCE_SEC) got $rc"
    [ -f "$p" ] || st_fail "case=confirmed-recent-advance expected pages.jsonl once aged out"
    grep -q 'canonical_no_advance' "$p" || { cat "$p" >&2; st_fail "case=confirmed-recent-advance missing condition id"; }
    grep -q '"served_height":10' "$p" || { cat "$p" >&2; st_fail "case=confirmed-recent-advance served_height should reflect the current flat value (10)"; }
    echo "selftest: ok case=confirmed-recent-advance (aged out)"

    echo "selftest: PASS"
}

# ── dispatch ─────────────────────────────────────────────────────────

case "${1:-evaluate}" in
    evaluate)   shift || true; cmd_evaluate "$@" ;;
    --selftest) shift; cmd_selftest "$@" ;;
    *)
        echo "usage: slo_page_if_stalled.sh [evaluate] | --selftest" >&2
        exit 2
        ;;
esac
