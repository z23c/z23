#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# slo_hold_judge.sh — the 72h HOLD JUDGE: the certification instrument for
# "stable at tip". It reads the EXTERNAL uptime prober's ledger
# (tools/scripts/node_slo_probe.sh, ~/.local/state/zclassic23-slo/
# uptime-ledger.jsonl) plus the pager's page log (pages.jsonl in the same
# dir, written by slo_page_if_stalled.sh) and answers ONE question for a
# single instance: has instance X satisfied the HOLD BAR *continuously* for
# the trailing W hours?
#
# It never trusts a node self-report — it only reads what the outside prober
# actually recorded. A hole in the ledger is a hole in the proof, never a
# free pass: a window that is not densely covered by real samples cannot
# prove a hold, and a prober that stopped running is itself a violation.
#
# HOLD BAR — every criterion must hold over the trailing-W-hours window
# (window = [newest_sample_ts - W*3600, newest_sample_ts], matching the
# native SLO evidence reader's anchor-to-newest contract; staleness is a SEPARATE
# criterion so a long-dead prober can never look "covered"):
#
#   reachability    reachable:true on >= 99.5% of in-window samples AND no
#                   consecutive unreachable run longer than 10 minutes. (Both
#                   sub-checks: a 20-min outage in an otherwise-99.9%-up
#                   window is still a hold failure.)
#   gap_vs_oracle   gap_vs_oracle <= --gap-budget on EVERY sample where both
#                   this node and the oracle answered (gap_vs_oracle numeric,
#                   not null). One over-budget sample fails.
#   served_advance  served_height monotonically non-decreasing across
#                   reachable samples AND at least one advance per 15-minute
#                   bucket that carries samples (the chain moves ~4 blocks/
#                   10min; a populated 15-min bucket whose served max did not
#                   climb over the previous populated bucket is a stall).
#                   Sample DENSITY is coverage's job, not this criterion's —
#                   this fires only on a real forward-progress stall/regress.
#   pages           zero page lines in pages.jsonl within the window (a page
#                   for this instance is a recorded stall alarm — its mere
#                   existence disproves an unbroken hold).
#   coverage        in-window sample count >= 90% of the expected count
#                   (W hours / 60s cadence). This is the ledger-hole guard.
#   freshness       newest sample age (now - newest_sample_ts) <= 5 minutes,
#                   so a prober that silently stopped cannot certify a hold.
#
# Output: one summary line per criterion (met / VIOLATED with the worst
# offender ts + value) then a final
#   VERDICT=HOLD_PROVEN
# or
#   VERDICT=NOT_PROVEN reason=<first-violated-criterion>
# Criteria are evaluated (and the reason resolved) in the fixed order above.
# Exit code is 0 ONLY on HOLD_PROVEN; any violation / no-data exits non-zero.
#
# Usage:
#   slo_hold_judge.sh [--instance canonical] [--window-hours 72] [--gap-budget 3]
#   slo_hold_judge.sh --record          # judge, then append the verdict as one
#                                       # JSON line to $LEDGER_DIR/hold-ledger.jsonl
#                                       # and exit 0 (recorder, not a pager — the
#                                       # certifier timer must not sit failed for
#                                       # the whole 72h a hold takes to accrue)
#   slo_hold_judge.sh --selftest        # hermetic fixture ledgers, no live nodes
#
# Env (test seams / threshold overrides):
#   ZCL_SLO_LEDGER_DIR    ledger dir (default ~/.local/state/zclassic23-slo)
#   ZCL_SLO_PAGES_FILE    page log path (default $LEDGER_DIR/pages.jsonl)
#   ZCL_SLO_NOW           epoch override for "now" (freshness calc; test clock)
#   ZCL_SLO_GAP_BUDGET    default gap budget (default 3; --gap-budget wins)
#   ZCL_SLO_WINDOW_HOURS  default window hours (default 72; --window-hours wins)
#   ZCL_SLO_INSTANCE      default instance (default canonical; --instance wins)
#   ZCL_SLO_REACH_PCT     reachable-pct floor (default 99.5)
#   ZCL_SLO_MAX_UNREACH_SEC   longest tolerable unreachable run sec (default 600)
#   ZCL_SLO_COVERAGE_PCT  coverage floor pct (default 90)
#   ZCL_SLO_CADENCE_SEC   expected probe cadence sec (default 60)
#   ZCL_SLO_MAX_AGE_SEC   newest-sample staleness ceiling sec (default 300)
#   ZCL_SLO_BUCKET_SEC    advance bucket width sec (default 900 = 15 min)
#
# No python (banned), no jq — bash + awk only, same rule as
# node_slo_probe.sh.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

LEDGER_DIR="${ZCL_SLO_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-slo}"
LEDGER_FILE="$LEDGER_DIR/uptime-ledger.jsonl"
PAGES_FILE="${ZCL_SLO_PAGES_FILE:-$LEDGER_DIR/pages.jsonl}"

INSTANCES="canonical soak dev"

# thresholds (env-overridable)
REACH_PCT_MIN="${ZCL_SLO_REACH_PCT:-99.5}"
MAX_UNREACH_SEC="${ZCL_SLO_MAX_UNREACH_SEC:-600}"
COV_PCT_MIN="${ZCL_SLO_COVERAGE_PCT:-90}"
CADENCE_SEC="${ZCL_SLO_CADENCE_SEC:-60}"
MAX_AGE_SEC="${ZCL_SLO_MAX_AGE_SEC:-300}"
BUCKET_SEC="${ZCL_SLO_BUCKET_SEC:-900}"

# ── core judge ─────────────────────────────────────────────────────────
# judge <window_hours> <instance> <gap_budget> <ledger_file> <pages_file> <now>
# Prints the per-criterion lines + verdict; returns 0 only on HOLD_PROVEN.
judge() {
    local wh="$1" inst="$2" gap_budget="$3" ledger="$4" pages="$5" now="$6"

    if [ ! -s "$ledger" ]; then
        echo "slo-hold: instance=$inst window_hours=$wh file=$ledger file_samples=0"
        echo "slo-hold: instance=$inst window_hours=$wh VERDICT=NOT_PROVEN reason=no_ledger_file"
        return 4
    fi

    # Read pages FIRST (if present) so all page timestamps are in memory before
    # END computes the window; then the ledger. FILENAME distinguishes them.
    local files=() pf=""
    if [ -n "$pages" ] && [ -f "$pages" ]; then files+=("$pages"); pf="$pages"; fi
    files+=("$ledger")

    local out rc
    set +e
    out="$(awk \
        -v inst="$inst" -v wh="$wh" -v gap_budget="$gap_budget" \
        -v reach_pct_min="$REACH_PCT_MIN" -v max_unreach_sec="$MAX_UNREACH_SEC" \
        -v cov_pct_min="$COV_PCT_MIN" -v cadence_sec="$CADENCE_SEC" \
        -v max_age_sec="$MAX_AGE_SEC" -v bucket_sec="$BUCKET_SEC" \
        -v now="$now" -v pages_file="$pf" '
        function fld(line, key,    re, s) {
            re = "\"" key "\":(-?[0-9]+|null|true|false)"
            if (match(line, re) == 0) return ""
            s = substr(line, RSTART, RLENGTH)
            sub(/^"[^"]*":/, "", s)
            return s
        }
        function isnum(s) { return (s != "" && s != "null" && s != "true" && s != "false") }

        # page lines (read before the ledger): keep ts of pages that name this
        # instance or name no instance at all (a page without an instance
        # counts against every instance).
        pages_file != "" && FILENAME == pages_file {
            pt = fld($0, "ts"); if (pt == "") next
            if (index($0, "\"instance\":") > 0 && index($0, "\"instance\":\"" inst "\"") == 0) next
            pn++; pts[pn] = pt + 0
            next
        }
        # ledger: only this instance.
        index($0, "\"instance\":\"" inst "\"") == 0 { next }
        {
            t = fld($0, "ts"); if (t == "") next
            n++
            ts[n]     = t + 0
            reach[n]  = (index($0, "\"reachable\":true") > 0) ? 1 : 0
            served[n] = fld($0, "served_height")
            gapo[n]   = fld($0, "gap_vs_oracle")
        }
        END {
            if (n == 0) {
                printf "slo-hold: instance=%s window_hours=%d probe_count=0\n", inst, wh
                printf "slo-hold: instance=%s window_hours=%d VERDICT=NOT_PROVEN reason=no_samples\n", inst, wh
                exit 3
            }
            # sort by ts (defensive insertion sort; append order is ~chrono).
            for (i = 2; i <= n; i++) {
                tv = ts[i]; rv = reach[i]; sv = served[i]; gv = gapo[i]; j = i - 1
                while (j >= 1 && ts[j] > tv) {
                    ts[j+1]=ts[j]; reach[j+1]=reach[j]; served[j+1]=served[j]; gapo[j+1]=gapo[j]; j--
                }
                ts[j+1]=tv; reach[j+1]=rv; served[j+1]=sv; gapo[j+1]=gv
            }

            last = ts[n]
            cutoff = last - wh * 3600
            i0 = 1
            for (i = 1; i <= n; i++) { if (ts[i] < cutoff) i0 = i + 1; else break }
            if (i0 > n) i0 = n
            cnt = n - i0 + 1

            # ── reachability ──────────────────────────────────────────────
            reach_cnt = 0
            run_len = 0; run_start = ""; best_run_sec = 0; best_run_start = ""
            for (i = i0; i <= n; i++) {
                if (reach[i]) {
                    reach_cnt++
                    if (run_len > 0) {
                        rs = ts[i-1] - run_start
                        if (rs > best_run_sec) { best_run_sec = rs; best_run_start = run_start }
                    }
                    run_len = 0; run_start = ""
                } else {
                    if (run_len == 0) run_start = ts[i]
                    run_len++
                }
            }
            if (run_len > 0) {
                rs = ts[n] - run_start
                if (rs > best_run_sec) { best_run_sec = rs; best_run_start = run_start }
            }
            reach_pct = 100.0 * reach_cnt / cnt
            reach_ok = (reach_pct >= reach_pct_min + 0 && best_run_sec <= max_unreach_sec + 0)

            # ── gap_vs_oracle ─────────────────────────────────────────────
            max_gap = ""; gap_bad = 0; gap_bad_ts = ""; gap_bad_val = ""
            for (i = i0; i <= n; i++) {
                if (reach[i] && isnum(gapo[i])) {
                    g = gapo[i] + 0
                    if (max_gap == "" || g > max_gap + 0) max_gap = g
                    if (g > gap_budget + 0) {
                        if (gap_bad == 0 || g > gap_bad_val + 0) { gap_bad = 1; gap_bad_val = g; gap_bad_ts = ts[i] }
                    }
                }
            }
            gap_ok = (gap_bad == 0)

            # ── served_advance ────────────────────────────────────────────
            m = 0
            for (i = i0; i <= n; i++) {
                if (reach[i] && isnum(served[i])) { m++; svt[m] = ts[i]; svh[m] = served[i] + 0 }
            }
            adv_ok = 1; adv_kind = ""; adv_ts = ""; adv_val = ""; adv_prev = ""; nb = 0
            if (m == 0) {
                adv_ok = 0; adv_kind = "no_reachable_served_samples"
            } else {
                for (i = 2; i <= m; i++) {
                    if (svh[i] < svh[i-1]) { adv_ok = 0; adv_kind = "regressed"; adv_ts = svt[i]; adv_val = svh[i]; adv_prev = svh[i-1]; break }
                }
                if (adv_ok) {
                    last_b = ""
                    for (i = 1; i <= m; i++) {
                        b = int(svt[i] / bucket_sec)
                        if (nb == 0 || b != last_b) { nb++; bmax[nb] = svh[i]; bts[nb] = svt[i]; last_b = b }
                        else if (svh[i] > bmax[nb]) bmax[nb] = svh[i]
                    }
                    for (k = 2; k <= nb; k++) {
                        if (bmax[k] <= bmax[k-1]) { adv_ok = 0; adv_kind = "stall_no_advance_in_bucket"; adv_ts = bts[k]; adv_val = bmax[k]; adv_prev = bmax[k-1]; break }
                    }
                }
            }

            # ── pages ─────────────────────────────────────────────────────
            pages_in = 0; page_worst = ""
            for (i = 1; i <= pn; i++) {
                if (pts[i] >= cutoff && pts[i] <= last) {
                    pages_in++
                    if (page_worst == "" || pts[i] < page_worst) page_worst = pts[i]
                }
            }
            pages_ok = (pages_in == 0)

            # ── coverage ──────────────────────────────────────────────────
            expected = int(wh * 3600 / cadence_sec)
            cov_pct = (expected > 0) ? 100.0 * cnt / expected : 0
            cov_ok = (cov_pct >= cov_pct_min + 0)

            # ── freshness ─────────────────────────────────────────────────
            age = now - last
            fresh_ok = (age <= max_age_sec + 0)

            # ── first-violated resolution (fixed order) ───────────────────
            reason = ""
            if (!reach_ok)      reason = "reachability"
            else if (!gap_ok)   reason = "gap_vs_oracle"
            else if (!adv_ok)   reason = "served_advance"
            else if (!pages_ok) reason = "pages"
            else if (!cov_ok)   reason = "coverage"
            else if (!fresh_ok) reason = "freshness"

            # ── per-criterion summary lines ───────────────────────────────
            if (reach_ok)
                printf "slo-hold: criterion=reachability met reachable_pct=%.2f samples=%d reachable=%d longest_unreachable_run_sec=%d floor_pct=%s max_run_sec=%d\n", reach_pct, cnt, reach_cnt, best_run_sec, reach_pct_min, max_unreach_sec
            else
                printf "slo-hold: criterion=reachability VIOLATED reachable_pct=%.2f samples=%d reachable=%d longest_unreachable_run_sec=%d worst_run_start_ts=%s floor_pct=%s max_run_sec=%d\n", reach_pct, cnt, reach_cnt, best_run_sec, (best_run_start == "" ? "-" : best_run_start), reach_pct_min, max_unreach_sec

            if (gap_ok)
                printf "slo-hold: criterion=gap_vs_oracle met max_gap=%s budget=%d\n", (max_gap == "" ? "null" : max_gap ""), gap_budget
            else
                printf "slo-hold: criterion=gap_vs_oracle VIOLATED worst_ts=%s gap_vs_oracle=%d budget=%d\n", gap_bad_ts, gap_bad_val, gap_budget

            if (adv_ok)
                printf "slo-hold: criterion=served_advance met reachable_served_samples=%d buckets=%d span_advance=%d bucket_sec=%d\n", m, nb, (m > 0 ? svh[m] - svh[1] : 0), bucket_sec
            else
                printf "slo-hold: criterion=served_advance VIOLATED kind=%s worst_ts=%s served=%s prev=%s bucket_sec=%d\n", adv_kind, (adv_ts == "" ? "-" : adv_ts), (adv_val == "" ? "-" : adv_val ""), (adv_prev == "" ? "-" : adv_prev ""), bucket_sec

            if (pages_ok)
                printf "slo-hold: criterion=pages met pages_in_window=0\n"
            else
                printf "slo-hold: criterion=pages VIOLATED pages_in_window=%d worst_ts=%s\n", pages_in, page_worst

            printf "slo-hold: criterion=coverage %s samples=%d expected=%d coverage_pct=%.2f floor_pct=%s\n", (cov_ok ? "met" : "VIOLATED"), cnt, expected, cov_pct, cov_pct_min

            printf "slo-hold: criterion=freshness %s newest_ts=%d newest_age_sec=%d max_age_sec=%d\n", (fresh_ok ? "met" : "VIOLATED"), last, age, max_age_sec

            if (reason == "") {
                printf "slo-hold: instance=%s window_hours=%d VERDICT=HOLD_PROVEN\n", inst, wh
                exit 0
            } else {
                printf "slo-hold: instance=%s window_hours=%d VERDICT=NOT_PROVEN reason=%s\n", inst, wh, reason
                exit 1
            }
        }
    ' "${files[@]}")"
    rc=$?
    set -e
    printf '%s\n' "$out"
    return "$rc"
}

# ── selftest (hermetic; fixture ledgers + ZCL_SLO_NOW test clock) ───────

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

# emit_ledger <file> <inst> <base_ts> <n> <step> <sv0> <svstep> <gap>
#             [ur_lo ur_hi] [breach_idx breach_gap]
# Appends n JSON ledger lines. Samples in [ur_lo,ur_hi] are unreachable
# (null served/gap). Sample breach_idx gets gap_vs_oracle=breach_gap (served
# still advances). Defaults: no unreachable run, no breach.
emit_ledger() {
    local f="$1" inst="$2" base="$3" n="$4" step="$5" sv0="$6" svstep="$7" gap="$8"
    local ur_lo="${9:--1}" ur_hi="${10:--1}" bi="${11:--1}" bg="${12:-0}"
    awk -v inst="$inst" -v base="$base" -v n="$n" -v step="$step" \
        -v sv0="$sv0" -v svstep="$svstep" -v gap="$gap" \
        -v ur_lo="$ur_lo" -v ur_hi="$ur_hi" -v bi="$bi" -v bg="$bg" 'BEGIN {
        for (i = 0; i < n; i++) {
            ts = base + i * step
            if (ur_lo >= 0 && i >= ur_lo && i <= ur_hi) {
                printf "{\"ts\":%d,\"instance\":\"%s\",\"rpcport\":1,\"datadir\":\"/x\",\"reachable\":false,\"served_height\":null,\"header_height\":null,\"latency_ms\":1,\"oracle_height\":null,\"max_height\":null,\"gap_vs_max\":null,\"gap_vs_oracle\":null,\"error_detail\":\"down\"}\n", ts, inst
            } else {
                sv = sv0 + i * svstep
                g = (i == bi) ? bg : gap
                orc = sv + g
                printf "{\"ts\":%d,\"instance\":\"%s\",\"rpcport\":1,\"datadir\":\"/x\",\"reachable\":true,\"served_height\":%d,\"header_height\":%d,\"latency_ms\":1,\"oracle_height\":%d,\"max_height\":%d,\"gap_vs_max\":%d,\"gap_vs_oracle\":%d,\"error_detail\":\"\"}\n", ts, inst, sv, sv, orc, orc, g, g
            }
        }
    }' >> "$f"
}

cmd_selftest() {
    ST_TMP="$(mktemp -d /tmp/zcl-slo-hold-judge-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT

    local base=1700000000
    # a dense 72h ledger at 60s cadence = 4320 samples spanning ts
    # [base, base + 4319*60]; last = base + 259140.
    local N=4320 STEP=60 SV0=3000000 SVSTEP=1
    local last=$((base + (N - 1) * STEP))
    local fresh_now=$((last + 30))       # 30s stale -> fresh
    local out rc

    # A) clean 72h window PROVES.
    local d="$ST_TMP/a"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'VERDICT=HOLD_PROVEN' || { printf '%s\n' "$out" >&2; st_fail "case=clean expected HOLD_PROVEN"; }
    [ "$rc" -eq 0 ] || st_fail "case=clean expected rc=0 got $rc"
    echo "selftest: ok case=clean-proves"

    # B) one gap breach fails (sample 2000 has gap_vs_oracle=4, budget=3).
    d="$ST_TMP/b"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0 -1 -1 2000 4
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'criterion=gap_vs_oracle VIOLATED.*gap_vs_oracle=4 budget=3' || { printf '%s\n' "$out" >&2; st_fail "case=gap-breach wrong gap line"; }
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=gap_vs_oracle' || { printf '%s\n' "$out" >&2; st_fail "case=gap-breach expected reason=gap_vs_oracle"; }
    [ "$rc" -ne 0 ] || st_fail "case=gap-breach expected non-zero exit"
    echo "selftest: ok case=gap-breach"

    # C) one 20-min unreachable run fails (21 consecutive down = 1200s > 600s),
    # while reachable_pct stays >= 99.5% so ONLY the run-length sub-check fires.
    d="$ST_TMP/c"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0 2000 2020
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'criterion=reachability VIOLATED.*longest_unreachable_run_sec=1200' || { printf '%s\n' "$out" >&2; st_fail "case=unreachable-run wrong run math"; }
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=reachability' || { printf '%s\n' "$out" >&2; st_fail "case=unreachable-run expected reason=reachability"; }
    [ "$rc" -ne 0 ] || st_fail "case=unreachable-run expected non-zero exit"
    echo "selftest: ok case=unreachable-run"

    # D) a page line within the window fails (ledger otherwise clean).
    d="$ST_TMP/d"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0
    printf '{"ts":%d,"instance":"canonical","event":"page","reason":"stall"}\n' "$((base + 100000))" > "$d/pages.jsonl"
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q "criterion=pages VIOLATED pages_in_window=1 worst_ts=$((base + 100000))" || { printf '%s\n' "$out" >&2; st_fail "case=page-line wrong pages line"; }
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=pages' || { printf '%s\n' "$out" >&2; st_fail "case=page-line expected reason=pages"; }
    [ "$rc" -ne 0 ] || st_fail "case=page-line expected non-zero exit"
    echo "selftest: ok case=page-line"

    # E) sparse coverage fails: 72 hourly samples (each advancing) over 72h.
    # reachability/gap/served all pass; only coverage (72 of 4320 expected) fails.
    d="$ST_TMP/e"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" 72 3600 "$SV0" 240 0
    local sparse_last=$((base + 71 * 3600))
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$((sparse_last + 30))" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'criterion=coverage VIOLATED samples=72 expected=4320' || { printf '%s\n' "$out" >&2; st_fail "case=sparse-coverage wrong coverage line"; }
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=coverage' || { printf '%s\n' "$out" >&2; st_fail "case=sparse-coverage expected reason=coverage"; }
    [ "$rc" -ne 0 ] || st_fail "case=sparse-coverage expected non-zero exit"
    echo "selftest: ok case=sparse-coverage"

    # F) stale newest sample fails: dense clean ledger, but now is 1h past last.
    d="$ST_TMP/f"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$((last + 3600))" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'criterion=freshness VIOLATED.*newest_age_sec=3600' || { printf '%s\n' "$out" >&2; st_fail "case=stale wrong freshness line"; }
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=freshness' || { printf '%s\n' "$out" >&2; st_fail "case=stale expected reason=freshness"; }
    [ "$rc" -ne 0 ] || st_fail "case=stale expected non-zero exit"
    echo "selftest: ok case=stale-newest-sample"

    # G) missing ledger -> NOT_PROVEN reason=no_ledger_file, non-zero exit.
    d="$ST_TMP/g"; mkdir -p "$d"
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q 'VERDICT=NOT_PROVEN reason=no_ledger_file' || { printf '%s\n' "$out" >&2; st_fail "case=missing-ledger wrong output"; }
    [ "$rc" -ne 0 ] || st_fail "case=missing-ledger expected non-zero exit"
    echo "selftest: ok case=missing-ledger"

    # H) --record: exits 0 on BOTH verdicts and appends one JSON line per run
    #    to hold-ledger.jsonl (proven ledger from case A, missing ledger for
    #    the NOT_PROVEN leg).
    d="$ST_TMP/h"; mkdir -p "$d"
    emit_ledger "$d/uptime-ledger.jsonl" canonical "$base" "$N" "$STEP" "$SV0" "$SVSTEP" 0
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --window-hours 72 --gap-budget 3 --record)"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || st_fail "case=record-proven expected rc=0 got $rc"
    printf '%s\n' "$out" | grep -q 'slo-hold: recorded verdict=HOLD_PROVEN' || { printf '%s\n' "$out" >&2; st_fail "case=record-proven missing recorded line"; }
    grep -q "^{\"ts\":$fresh_now,\"instance\":\"canonical\",\"window_hours\":72,\"gap_budget\":3,\"verdict\":\"HOLD_PROVEN\",\"reason\":\"\",\"judge_rc\":0}$" "$d/hold-ledger.jsonl" \
        || { cat "$d/hold-ledger.jsonl" >&2; st_fail "case=record-proven wrong ledger line"; }
    d="$ST_TMP/h2"; mkdir -p "$d"
    set +e
    out="$(ZCL_SLO_LEDGER_DIR="$d" ZCL_SLO_NOW="$fresh_now" bash "$SELF" --instance canonical --record)"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || st_fail "case=record-notproven expected rc=0 got $rc"
    grep -q '"verdict":"NOT_PROVEN","reason":"no_ledger_file"' "$d/hold-ledger.jsonl" \
        || { cat "$d/hold-ledger.jsonl" >&2; st_fail "case=record-notproven wrong ledger line"; }
    echo "selftest: ok case=record-mode"

    echo "selftest: PASS"
}

# ── record mode ─────────────────────────────────────────────────────
# cmd_record: run the judge, echo its full per-criterion output (journal),
# then append ONE JSON verdict line to $LEDGER_DIR/hold-ledger.jsonl and exit
# 0 regardless of verdict. The certifier timer runs this every 15 min for the
# whole hold window: the ledger accretes an unfakeable verdict history, and
# the first VERDICT=HOLD_PROVEN line in it IS the 72h win-proof. Alarming on
# NOT_PROVEN is deliberately NOT this mode's job — the SLO pager already owns
# the failed-unit page surface, and NOT_PROVEN is the *expected* state for
# the first 72h of any hold.
cmd_record() {
    local now="${ZCL_SLO_NOW:-$(date +%s)}"
    local out rc verdict reason
    set +e
    out="$(judge "$WINDOW_HOURS" "$INSTANCE" "$GAP_BUDGET" "$LEDGER_FILE" "$PAGES_FILE" "$now")"
    rc=$?
    set -e
    printf '%s\n' "$out"
    verdict="$(printf '%s\n' "$out" | sed -n 's/.*VERDICT=\([A-Z_]*\).*/\1/p' | tail -n 1)"
    reason="$(printf '%s\n' "$out" | sed -n 's/.*VERDICT=[A-Z_]* reason=\([a-z_]*\).*/\1/p' | tail -n 1)"
    [ -n "$verdict" ] || verdict="JUDGE_ERROR"
    local line
    line="$(printf '{"ts":%s,"instance":"%s","window_hours":%s,"gap_budget":%s,"verdict":"%s","reason":"%s","judge_rc":%s}' \
        "$now" "$INSTANCE" "$WINDOW_HOURS" "$GAP_BUDGET" "$verdict" "$reason" "$rc")"
    local hold_file="$LEDGER_DIR/hold-ledger.jsonl"
    mkdir -p "$LEDGER_DIR"
    local append_rc=0
    (
        flock -x -w 30 9 || exit 9
        printf '%s\n' "$line" >&9
    ) 9>>"$hold_file" || append_rc=$?
    if [ "$append_rc" -ne 0 ]; then
        echo "slo-hold: FAIL could not append verdict to $hold_file (rc=$append_rc)" >&2
        return 1
    fi
    echo "slo-hold: recorded verdict=$verdict file=$hold_file"
    return 0
}

# ── dispatch ─────────────────────────────────────────────────────────

INSTANCE="${ZCL_SLO_INSTANCE:-canonical}"
WINDOW_HOURS="${ZCL_SLO_WINDOW_HOURS:-72}"
GAP_BUDGET="${ZCL_SLO_GAP_BUDGET:-3}"
RECORD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --instance)       shift; INSTANCE="${1:?--instance needs a value}" ;;
        --instance=*)     INSTANCE="${1#*=}" ;;
        --window-hours)   shift; WINDOW_HOURS="${1:?--window-hours needs a value}" ;;
        --window-hours=*) WINDOW_HOURS="${1#*=}" ;;
        --gap-budget)     shift; GAP_BUDGET="${1:?--gap-budget needs a value}" ;;
        --gap-budget=*)   GAP_BUDGET="${1#*=}" ;;
        --record)         RECORD=1 ;;
        --selftest)       cmd_selftest; exit 0 ;;
        *) echo "usage: slo_hold_judge.sh [--instance NAME] [--window-hours N] [--gap-budget N] [--record] | --selftest" >&2; exit 2 ;;
    esac
    shift
done

case "$WINDOW_HOURS" in ''|*[!0-9]*) echo "slo-hold: --window-hours must be a positive integer" >&2; exit 2 ;; esac
case "$GAP_BUDGET"   in ''|*[!0-9-]*) echo "slo-hold: --gap-budget must be an integer" >&2; exit 2 ;; esac
case " $INSTANCES " in
    *" $INSTANCE "*) ;;
    *) echo "slo-hold: unknown --instance '$INSTANCE' (known: $INSTANCES)" >&2; exit 2 ;;
esac

if [ "$RECORD" -eq 1 ]; then
    cmd_record
    exit $?
fi

judge "$WINDOW_HOURS" "$INSTANCE" "$GAP_BUDGET" "$LEDGER_FILE" "$PAGES_FILE" "${ZCL_SLO_NOW:-$(date +%s)}"
