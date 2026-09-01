#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# soak_evidence.sh — the MVP-C6 live-soak evidence harness.
#
# Makes the 168 h "7-day soak with zero operator intervention" window
# MEASURABLE and JUDGEABLE instead of anecdotal. Two halves:
#
#   collect : append ONE JSON line per invocation (hourly via the
#             platform/deploy/examples/zclassic23-soak-evidence.timer) to
#             ~/.local/state/zclassic23-soak-evidence/evidence.jsonl:
#               ts              epoch the sample was taken
#               soak_height     soak node getblockcount (RPC 18242) or null
#               zd_height       zclassicd getblockcount (RPC 8232) or null
#               gap             zd_height - soak_height, or null
#               nrestarts       systemd NRestarts of zclassic23-soak, or null
#               active_enter_ts epoch of ActiveEnterTimestamp, or null
#               rss_kb          VmRSS of MainPID from /proc/<pid>/status
#                               (NOT cgroup MemoryCurrent — that includes
#                               page cache and runs 3x high), or null
#               mainpid         systemd MainPID at sample time (forensic
#                               signal for restart-ambiguity analysis), or null
#               security_review_required
#                               operator snapshot security gate, or null when
#                               the target cannot prove its posture
#               security_posture_ok
#                               true only when review_required is explicitly
#                               false; unknown is fail-closed
#               window_eligible true iff RPC evidence and security posture
#                               are both eligible for soak accrual
#               ok              true iff BOTH RPCs answered
#             If a node is unreachable the line is STILL appended with
#             ok:false and nulls — a hole in the evidence is itself
#             evidence; collect never exits silently. Appends are
#             flock-serialized. READ-ONLY against all nodes.
#
#   judge   : parse the JSONL and print a verdict block over the trailing
#             --window-hours N (default 168) window anchored at the LAST
#             sample: coverage, sampling holes, NRestarts delta (with the
#             autonomous-recycle note), operator-intervention detection,
#             soak/oracle reachability, gap==0 rate, rss_first/rss_last,
#             evidence freshness. Verdict line:
#               soak-evidence: VERDICT=MET|NOT_MET|INSUFFICIENT reason=...
#             MET ONLY if ALL of:
#               - window_covered >= N hours, allowing the explicit
#                 WINDOW_SLACK_SEC start-boundary tolerance for hourly
#                 timer jitter;
#               - no sampling hole > HOLE_THRESHOLD (2h cadence-doubling
#                 + 15 min slack);
#               - no operator intervention detected;
#               - every sample has an explicitly review-free security
#                 posture; review_required breaks the window and missing
#                 posture evidence is INSUFFICIENT;
#               - the SOAK node answered in all but <= (100-GAP0_MIN_PCT)%
#                 of window samples — a node whose RPC is dead/wedged for
#                 the week (unit active, RPC unanswering, no restart: the
#                 exact MVP-C6 failure mode) is NOT_MET
#                 soak_unreachable_*, never MET; the few ok samples don't
#                 get to carry the verdict while the holes are ignored;
#               - the zclassicd ORACLE answered in >= 90% of window
#                 samples — thinner gap evidence cannot prove the gap==0
#                 claim => INSUFFICIENT oracle_coverage_thin_*;
#               - gap==0 in >= GAP0_MIN_PCT% of ok samples;
#               - the LAST sample is FRESH: now - last_ts <=
#                 HOLE_THRESHOLD. A green week whose collector then died
#                 (timer disabled, box rebuilt, script path broken — none
#                 of which trip OnFailure) must NOT stay evergreen MET; it
#                 caps at INSUFFICIENT stale_evidence_age_*. Pass
#                 --allow-stale to deliberately judge a historical window.
#             The verdict comes from PARSED DATA only — an empty or short
#             log is an explicit INSUFFICIENT, never a silent pass (never
#             exit-0-as-proof). Exit: 0=MET 1=NOT_MET 2=INSUFFICIENT.
#
# Restart semantics (reader-verified 2026-06-13):
#   - systemd NRestarts counts AUTOMATIC restarts only; a manual
#     `systemctl restart` RESETS it to 0 and bumps ActiveEnterTimestamp.
#     The judge therefore flags "NRestarts decreased" OR
#     "ActiveEnterTimestamp jumped without an NRestarts increment" as
#     OPERATOR INTERVENTION (NOT_MET).
#   - An NRestarts INCREMENT is the chain_tip_watchdog's bounded clean
#     self-recycle (chain_tip_watchdog.c "requesting shutdown" + systemd
#     Restart=always) — AUTONOMOUS recovery. The judge REPORTS the count
#     and lets the criterion text decide; it does not gate MET on it.
#     (Strict soak_harness.c math counts ANY observed downtime as
#     FAIL_CRASH — both numbers stay visible, neither bar is redefined.)
#   - SAMPLING-RESOLUTION LIMIT: with one sample per hour, a manual
#     `systemctl restart` (NRestarts resets to 0) followed by >= prev+1
#     autonomous recycles before the next sample lands ABOVE the previous
#     sample's NRestarts and is indistinguishable from pure autonomous
#     recycles. Every inter-sample interval where ActiveEnterTimestamp
#     jumped AND NRestarts climbed is therefore reported as
#     ambiguous_restarts (the restart count inside such intervals) —
#     reported, NOT gating, consistent with the criterion-text-decides
#     stance; the per-sample mainpid + the systemd journal are the
#     forensic tiebreakers.
#
# Usage:
#   soak_evidence.sh collect
#   soak_evidence.sh judge [--window-hours N] [--allow-stale]
#   soak_evidence.sh --selftest        # hermetic; fixture JSONL, no nodes
#
# Env (test injection seams — the selftest needs no live nodes):
#   ZCL_SOAK_EVIDENCE_DIR  evidence dir (default ~/.local/state/zclassic23-soak-evidence)
#   ZCL_SOAK_UNIT          systemd unit name (default zclassic23-soak)
#   ZCL_SOAK_RPC_CMD       command printing the soak node getblockcount JSON
#   ZCL_ZD_RPC_CMD         command printing the zclassicd getblockcount JSON
#   ZCL_SOAK_SHOW_CMD      command printing `systemctl show` key=value lines
#   ZCL_SOAK_RSS_CMD       command printing a "VmRSS: <n> kB" line
#   ZCL_SOAK_SECURITY_CMD  command printing operatorsnapshot JSON
#   ZCL_SOAK_NOW           epoch override for "now" in the judge staleness
#                          math (test seam — keeps the selftest hermetic)
#
# No python (banned), no jq (installed but unused by repo convention) —
# bash + sed + awk + flock only, same rule as replay_canary.sh.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The ONE reader per measurement (peers, RSS, disk bytes, systemd, node
# self-report). Sourced so this script and every evidence ledger measure
# the same host the same way — see tools/scripts/lib/evidence_sources.sh.
. "$SCRIPT_DIR/lib/evidence_sources.sh"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

EVIDENCE_DIR="${ZCL_SOAK_EVIDENCE_DIR:-${HOME:-/root}/.local/state/zclassic23-soak-evidence}"
EVIDENCE_FILE="$EVIDENCE_DIR/evidence.jsonl"
SOAK_UNIT="${ZCL_SOAK_UNIT:-zclassic23-soak}"

# Cadence contract: the timer fires hourly (RandomizedDelaySec=120). A
# sampling hole is judged against 2x cadence + 15 min slack so one missed
# tick (host suspend, timer jitter, catch-up run) is tolerated but a dead
# collector is not.
CADENCE_SEC=3600
HOLE_THRESHOLD_SEC=8100   # 2*3600 + 900
WINDOW_SLACK_SEC=900      # window-start tolerance for timer jitter
GAP0_MIN_PCT=99           # gap==0 required in >= this % of ok samples

# ── helpers ────────────────────────────────────────────────────────

# jnum <value>: print the value, or JSON null when empty.
jnum() { if [ -n "${1:-}" ]; then printf '%s' "$1"; else printf 'null'; fi; }

# rpc_height <cmd>: run the command, extract the numeric "result". Empty
# on any failure (unreachable, auth error, non-numeric) — the caller
# records null, never a fake 0.
rpc_height() {
    local out
    out="$(bash -c "$1" 2>/dev/null || true)"
    printf '%s' "$out" | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p' | head -n1
}

# rpc_security_review_required <cmd>: print true|false only when the target
# emits the exact operator-snapshot gate. Missing/invalid output is empty and
# therefore window-ineligible; an old target can never inherit a green soak.
rpc_security_review_required() {
    local out
    out="$(bash -c "$1" 2>/dev/null || true)"
    printf '%s' "$out" |
        grep -oE '"security_review_required"[[:space:]]*:[[:space:]]*(true|false)' |
        head -n1 | sed -E 's/.*:[[:space:]]*//' || true
}

# ── collect ────────────────────────────────────────────────────────

cmd_collect() {
    mkdir -p "$EVIDENCE_DIR"

    local ts soak_cmd zd_cmd security_cmd show_cmd
    ts="$(date +%s)"

    # The two reader-VERIFIED query commands (zcl-rpc is env-configured
    # ONLY — it has no -rpcport/-datadir flags; extra argv become the
    # JSON params string).
    soak_cmd="${ZCL_SOAK_RPC_CMD:-ZCL_DATADIR=\"\$HOME/.zclassic-c23-soak\" ZCL_RPCPORT=18242 \"$REPO_ROOT/build/bin/zcl-rpc\" getblockcount}"
    zd_cmd="${ZCL_ZD_RPC_CMD:-ZCL_DATADIR=\"\$HOME/.zclassic\" ZCL_RPCPORT=8232 \"$REPO_ROOT/build/bin/zcl-rpc\" getblockcount}"
    security_cmd="${ZCL_SOAK_SECURITY_CMD:-ZCL_DATADIR=\"\$HOME/.zclassic-c23-soak\" ZCL_RPCPORT=18242 \"$REPO_ROOT/build/bin/zcl-rpc\" operatorsnapshot}"
    show_cmd="${ZCL_SOAK_SHOW_CMD:-systemctl --user show $SOAK_UNIT -p NRestarts -p ActiveEnterTimestamp -p MainPID}"

    local soak_height zd_height
    soak_height="$(rpc_height "$soak_cmd")"
    zd_height="$(rpc_height "$zd_cmd")"

    local gap=""
    if [ -n "$soak_height" ] && [ -n "$zd_height" ]; then
        gap=$((zd_height - soak_height))
    fi

    local ok="false"
    [ -n "$soak_height" ] && [ -n "$zd_height" ] && ok="true"

    local security_review_required security_posture_ok="false"
    security_review_required="$(rpc_security_review_required "$security_cmd")"
    [ "$security_review_required" = "false" ] && security_posture_ok="true"
    local window_eligible="false"
    [ "$ok" = "true" ] && [ "$security_posture_ok" = "true" ] &&
        window_eligible="true"

    # systemd restart/uptime accounting. MainPID changes on every recycle
    # — re-read it every sample, never cache.
    local show_out nrestarts aet_str mainpid aet_epoch=""
    show_out="$(bash -c "$show_cmd" 2>/dev/null || true)"
    nrestarts="$(printf '%s\n' "$show_out" | sed -n 's/^NRestarts=\([0-9][0-9]*\)$/\1/p' | head -n1)"
    aet_str="$(printf '%s\n' "$show_out" | sed -n 's/^ActiveEnterTimestamp=\(..*\)$/\1/p' | head -n1)"
    mainpid="$(printf '%s\n' "$show_out" | sed -n 's/^MainPID=\([0-9][0-9]*\)$/\1/p' | head -n1)"
    if [ -n "$aet_str" ]; then
        aet_epoch="$(date -d "$aet_str" +%s 2>/dev/null || true)"
    fi

    # RSS: VmRSS from /proc/<MainPID>/status — the soak_harness-parity
    # source (tools/soak/main.c rss_bytes_for parses exactly this).
    # The injection seam still yields a raw VmRSS LINE (fixtures depend on
    # that shape); the live path now goes through the shared reader, which
    # parses the same /proc field the same way.
    local rss_line="" rss_kb=""
    if [ -n "${ZCL_SOAK_RSS_CMD:-}" ]; then
        rss_line="$(bash -c "$ZCL_SOAK_RSS_CMD" 2>/dev/null || true)"
        rss_kb="$(printf '%s' "$rss_line" | sed -n 's/.*VmRSS:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*kB.*/\1/p' | head -n1)"
    else
        rss_kb="$(evidence_rss_kb "$mainpid")"
    fi

    local line
    line="$(printf '{"ts":%s,"soak_height":%s,"zd_height":%s,"gap":%s,"nrestarts":%s,"active_enter_ts":%s,"rss_kb":%s,"mainpid":%s,"security_review_required":%s,"security_posture_ok":%s,"window_eligible":%s,"ok":%s}' \
        "$ts" "$(jnum "$soak_height")" "$(jnum "$zd_height")" "$(jnum "$gap")" \
        "$(jnum "$nrestarts")" "$(jnum "$aet_epoch")" "$(jnum "$rss_kb")" \
        "$(jnum "$mainpid")" "${security_review_required:-null}" \
        "$security_posture_ok" "$window_eligible" "$ok")"

    # flock-serialized append: timer run + ad-hoc operator run can never
    # interleave a torn line. The lock acquire is BOUNDED (-w 30) and its
    # failure is EXPLICIT (`|| exit 9`) — set -e is suppressed inside an
    # if/|| condition context, so without the explicit exit a missing or
    # failing `flock` would silently degrade to an UNLOCKED append, and
    # without -w a stuck lock holder would block until the unit's
    # TimeoutStartSec kills the run. Failure to LOCK or APPEND is the
    # only collect failure (exit 1 → unit OnFailure pages); an
    # unreachable node is NOT a failure — it is the ok:false record.
    local append_rc=0
    (
        flock -x -w 30 9 || exit 9
        printf '%s\n' "$line" >&9
    ) 9>>"$EVIDENCE_FILE" || append_rc=$?
    if [ "$append_rc" -ne 0 ]; then
        if [ "$append_rc" -eq 9 ]; then
            echo "soak-evidence: FAIL could not acquire append lock on $EVIDENCE_FILE within 30s" >&2
        else
            echo "soak-evidence: FAIL could not append to $EVIDENCE_FILE (rc=$append_rc)" >&2
        fi
        exit 1
    fi

    if [ "$ok" != "true" ]; then
        echo "soak-evidence: WARN node unreachable (soak_height=$(jnum "$soak_height") zd_height=$(jnum "$zd_height")) — ok:false recorded" >&2
    fi
    if [ "$security_posture_ok" != "true" ]; then
        echo "soak-evidence: WARN security posture is ${security_review_required:-unknown} — window_eligible:false recorded" >&2
    fi
    echo "soak-evidence: appended file=$EVIDENCE_FILE"
    echo "$line"
}

# ── judge ──────────────────────────────────────────────────────────

cmd_judge() {
    local window_hours=168 allow_stale=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --window-hours)   shift; window_hours="${1:?--window-hours needs a value}" ;;
            --window-hours=*) window_hours="${1#*=}" ;;
            --allow-stale)    allow_stale=1 ;;
            *) echo "soak-evidence: unknown judge arg '$1'" >&2; exit 2 ;;
        esac
        shift
    done
    case "$window_hours" in
        ''|*[!0-9]*) echo "soak-evidence: --window-hours must be a positive integer" >&2; exit 2 ;;
    esac

    # "now" feeds the staleness rung; ZCL_SOAK_NOW is the hermetic test
    # seam (same pattern as the i5 replay-canary staleness-guard fix).
    local now_ts
    now_ts="${ZCL_SOAK_NOW:-$(date +%s)}"
    case "$now_ts" in
        ''|*[!0-9]*) echo "soak-evidence: ZCL_SOAK_NOW must be a positive integer epoch" >&2; exit 2 ;;
    esac

    if [ ! -s "$EVIDENCE_FILE" ]; then
        echo "soak-evidence: judge window_hours=$window_hours file=$EVIDENCE_FILE file_samples=0"
        echo "soak-evidence: VERDICT=INSUFFICIENT reason=no_evidence_file"
        return 2
    fi

    local out
    out="$(awk -v wh="$window_hours" -v hole_thr="$HOLE_THRESHOLD_SEC" \
               -v slack="$WINDOW_SLACK_SEC" -v gap0_min="$GAP0_MIN_PCT" \
               -v now="$now_ts" -v allow_stale="$allow_stale" \
               -v file="$EVIDENCE_FILE" '
        # fld(line,key) -> "" (missing) | "null" | numeric string
        function fld(line, key,    re, s) {
            re = "\"" key "\":(-?[0-9]+|null)"
            if (match(line, re) == 0) return ""
            s = substr(line, RSTART, RLENGTH)
            sub(/^"[^"]*":/, "", s)
            return s
        }
        function isnum(s) { return (s != "" && s != "null") }
        {
            t = fld($0, "ts")
            if (!isnum(t)) { malformed++; next }
            n++
            ts[n]   = t + 0
            okv[n]  = ($0 ~ /"ok":true/) ? 1 : 0
            secok[n] = ($0 ~ /"security_posture_ok":true/) ? 1 : 0
            secrev[n] = ($0 ~ /"security_review_required":true/) ? 1 : 0
            secknown[n] = ($0 ~ /"security_review_required":(true|false)/ && $0 ~ /"security_posture_ok":(true|false)/) ? 1 : 0
            shv[n]  = fld($0, "soak_height")
            zdv[n]  = fld($0, "zd_height")
            gapv[n] = fld($0, "gap")
            nrv[n]  = fld($0, "nrestarts")
            aetv[n] = fld($0, "active_enter_ts")
            rssv[n] = fld($0, "rss_kb")
        }
        END {
            if (n == 0) {
                printf "soak-evidence: judge window_hours=%d file=%s file_samples=0 malformed=%d\n", wh, file, malformed
                printf "soak-evidence: VERDICT=INSUFFICIENT reason=empty_log\n"
                exit 0
            }
            last = ts[n]
            cutoff = last - wh * 3600 - slack
            i0 = 1
            for (i = 1; i <= n; i++) { if (ts[i] < cutoff) i0 = i + 1; else break }
            if (i0 > n) i0 = n
            cnt = n - i0 + 1
            covered_sec = last - ts[i0]
            covered = covered_sec / 3600.0

            hole_max = 0; op = 0; ambiguous = 0; ok_cnt = 0; gap0 = 0; gapgt0 = 0
            soak_null = 0; zd_null = 0
            security_review = 0; security_unknown = 0; security_gap = 0
            eligible_cnt = 0
            max_gap = ""; nr_first = ""; nr_last = ""
            rss_first = ""; rss_last = ""
            prev_t = ""; prev_nr = ""; prev_aet = ""
            for (i = i0; i <= n; i++) {
                if (prev_t != "") { d = ts[i] - prev_t; if (d > hole_max) hole_max = d }
                prev_t = ts[i]
                # Reachability accounting: a soak-null sample means the
                # SOAK node did not answer (RPC dead/hung — the exact
                # MVP-C6 failure mode); a zd-only-null sample means only
                # the ORACLE was missing (gap unprovable, soak alive).
                if (!isnum(shv[i]))      soak_null++
                else if (!isnum(zdv[i])) zd_null++
                if (secrev[i]) security_review++
                if (!secknown[i]) security_unknown++
                if (secknown[i] && !secok[i]) security_gap++
                if (okv[i] && secok[i]) eligible_cnt++
                if (okv[i] && isnum(gapv[i])) {
                    ok_cnt++
                    g = gapv[i] + 0
                    if (g == 0) gap0++
                    if (g > 0)  gapgt0++
                    if (max_gap == "" || g > max_gap + 0) max_gap = g
                }
                if (isnum(nrv[i])) {
                    r = nrv[i] + 0
                    a = isnum(aetv[i]) ? aetv[i] + 0 : ""
                    if (nr_first == "") nr_first = r
                    nr_last = r
                    if (prev_nr != "") {
                        jumped = (a != "" && prev_aet != "" && a > prev_aet + 5)
                        # NRestarts decreased => manual restart reset it;
                        # AET jumped with no NRestarts increment => manual
                        # restart while NRestarts was already 0. Either way:
                        # OPERATOR intervention.
                        if (r < prev_nr) op++
                        else if (jumped && r == prev_nr) op++
                        # AET jumped AND NRestarts climbed: at hourly
                        # sampling resolution this is indistinguishable
                        # from a manual reset-to-0 followed by >= prev+1
                        # autonomous recycles within the same interval.
                        # Count the restarts in such intervals as
                        # AMBIGUOUS — reported, not gated (see header).
                        else if (jumped && r > prev_nr) ambiguous += r - prev_nr
                    }
                    prev_nr = r
                    if (a != "") prev_aet = a
                }
                if (isnum(rssv[i])) {
                    if (rss_first == "") rss_first = rssv[i] + 0
                    rss_last = rssv[i] + 0
                }
            }
            restarts = (nr_first == "") ? "null" : sprintf("%d", nr_last - nr_first)
            gap0_pct = (ok_cnt > 0) ? (100.0 * gap0 / ok_cnt) : 0.0

            printf "soak-evidence: judge window_hours=%d file=%s file_samples=%d window_samples=%d malformed=%d\n", wh, file, n, cnt, malformed
            printf "soak-evidence: window_covered_hours=%.3f window_covered_sec=%d first_ts=%d last_ts=%d last_sample_age_sec=%d allow_stale=%d\n", covered, covered_sec, ts[i0], last, now - last, allow_stale
            printf "soak-evidence: max_sampling_hole_sec=%d hole_threshold_sec=%d\n", hole_max, hole_thr
            printf "soak-evidence: restarts_in_window=%s ambiguous_restarts=%d operator_interventions=%d (NRestarts delta; in-binary watchdog self-recycles count as AUTONOMOUS recovery — count reported, the criterion text decides; ambiguous = restarts in AET-jump intervals where a manual reset-then-climb is indistinguishable at hourly sampling resolution; strict soak_harness math counts ANY observed downtime as FAIL_CRASH)\n", restarts, ambiguous, op
            printf "soak-evidence: ok_samples=%d/%d soak_null_samples=%d zd_null_samples=%d samples_with_gap_gt0=%d max_gap=%s gap0_pct=%.2f\n", ok_cnt, cnt, soak_null, zd_null, gapgt0, (max_gap == "" ? "null" : max_gap ""), gap0_pct
            printf "soak-evidence: window_eligible_samples=%d/%d security_review_required_samples=%d security_posture_unknown_samples=%d security_posture_gap_samples=%d\n", eligible_cnt, cnt, security_review, security_unknown, security_gap
            printf "soak-evidence: rss_first_kb=%s rss_last_kb=%s\n", (rss_first == "" ? "null" : rss_first ""), (rss_last == "" ? "null" : rss_last "")

            # Verdict ladder — deterministic priority, parsed data only.
            # soak_unreachable gets the SAME 1% budget as the gap rate
            # ((100 - gap0_min)% of window samples): an unanswering soak
            # RPC is a liveness hole, and a hole in the evidence is
            # itself evidence — judged, not just collected.
            if (cnt < 2) {
                v = "INSUFFICIENT"; reason = "too_few_samples"
            } else if (covered_sec + slack < wh * 3600) {
                v = "INSUFFICIENT"; reason = sprintf("window_short_%ds_lt_%ds_slack%ds", covered_sec, wh * 3600, slack)
            } else if (op > 0) {
                v = "NOT_MET"; reason = sprintf("operator_intervention_detected_x%d", op)
            } else if (security_review > 0) {
                v = "NOT_MET"; reason = sprintf("security_review_required_in_%d_of_%d_samples", security_review, cnt)
            } else if (hole_max > hole_thr) {
                v = "NOT_MET"; reason = sprintf("sampling_hole_%ds_gt_%ds", hole_max, hole_thr)
            } else if (soak_null * 100 > cnt * (100 - gap0_min)) {
                v = "NOT_MET"; reason = sprintf("soak_unreachable_in_%d_of_%d_samples", soak_null, cnt)
            } else if (ok_cnt * 100 < cnt * 90) {
                # Soak node fine, but the zclassicd oracle answered too
                # rarely: the gap evidence is too thin to prove gap==0.
                v = "INSUFFICIENT"; reason = sprintf("oracle_coverage_thin_ok_%d_of_%d", ok_cnt, cnt)
            } else if (gap0_pct < gap0_min) {
                v = "NOT_MET"; reason = sprintf("gap_nonzero_in_%d_of_%d_ok_samples", ok_cnt - gap0, ok_cnt)
            } else if (security_unknown > 0) {
                v = "INSUFFICIENT"; reason = sprintf("security_posture_unknown_in_%d_of_%d_samples", security_unknown, cnt)
            } else if (security_gap > 0) {
                v = "NOT_MET"; reason = sprintf("security_posture_gap_in_%d_of_%d_samples", security_gap, cnt)
            } else {
                v = "MET"; reason = sprintf("covered_%.1fh_hole_max_%ds_gap0_%.2fpct", covered, hole_max, gap0_pct)
            }
            # Staleness cap (the anti-evergreen rung, same defect class as
            # the i5 replay-canary vaporware staleness guard f89a3b00c):
            # a window anchored at the LAST sample can be green forever
            # after the collector dies. MET requires the evidence to be
            # FRESH; --allow-stale deliberately judges a historical window.
            if (v == "MET" && !allow_stale && now - last > hole_thr) {
                v = "INSUFFICIENT"; reason = sprintf("stale_evidence_age_%ds", now - last)
            }
            printf "soak-evidence: VERDICT=%s reason=%s\n", v, reason
        }' "$EVIDENCE_FILE")"

    printf '%s\n' "$out"
    if printf '%s\n' "$out" | grep -q 'VERDICT=MET '; then
        return 0
    elif printf '%s\n' "$out" | grep -q 'VERDICT=NOT_MET '; then
        return 1
    else
        return 2
    fi
}

# ── selftest (hermetic; fixture JSONL in a mktemp dir, no nodes) ───

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

# st_judge <dir> <hours> <now> <want_verdict> <want_reason_substr> <want_rc> <case> [extra judge args...]
# <now> is injected via the ZCL_SOAK_NOW seam so the staleness rung stays
# hermetic (the fixtures live in 2023-epoch time, not wall-clock time).
st_judge() {
    local dir="$1" hours="$2" jnow="$3" want_v="$4" want_r="$5" want_rc="$6" name="$7"
    shift 7
    local out rc
    set +e
    out="$(ZCL_SOAK_EVIDENCE_DIR="$dir" ZCL_SOAK_NOW="$jnow" bash "$SELF" judge --window-hours "$hours" "$@" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out" | grep -q "VERDICT=$want_v " \
        || { printf '%s\n' "$out" >&2; st_fail "case=$name wanted VERDICT=$want_v"; }
    if [ -n "$want_r" ]; then
        printf '%s\n' "$out" | grep -q "reason=$want_r" \
            || { printf '%s\n' "$out" >&2; st_fail "case=$name wanted reason=$want_r*"; }
    fi
    [ "$rc" = "$want_rc" ] \
        || { printf '%s\n' "$out" >&2; st_fail "case=$name wanted rc=$want_rc got rc=$rc"; }
    echo "selftest: ok case=$name (VERDICT=$want_v rc=$rc)"
}

# st_line <file> <ts> <gap> <nr> <aet> <rss>  (ok:true, heights derived)
st_line() {
    printf '{"ts":%d,"soak_height":%d,"zd_height":%d,"gap":%d,"nrestarts":%d,"active_enter_ts":%d,"rss_kb":%d,"security_review_required":false,"security_posture_ok":true,"window_eligible":true,"ok":true}\n' \
        "$2" $((3000000 + ($2 % 100000))) $((3000000 + ($2 % 100000) + $3)) "$3" "$4" "$5" "$6" >> "$1"
}

cmd_selftest() {
    # NOT local: the EXIT trap fires after the function scope is gone.
    ST_TMP="$(mktemp -d /tmp/zcl-soak-evidence-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT
    local tmp="$ST_TMP"
    local base=1700000000 aet=$((1700000000 - 500)) i ts f
    # The fixtures end at base + 168 h; "fresh" is one minute after that
    # (injected via the ZCL_SOAK_NOW seam — the staleness rung must never
    # depend on the real wall clock inside the hermetic selftest).
    local last_ts=$((base + 168 * 3600)) fresh
    fresh=$((base + 168 * 3600 + 60))

    # A) full-green 169 hourly samples spanning exactly 168 h, including
    #    ONE autonomous watchdog recycle (NRestarts 1->2 + AET bump at
    #    i=80) — must still be MET (autonomous recovery is reported, not
    #    gated; the single-step climb is counted as ambiguous_restarts=1
    #    because hourly sampling cannot exclude a reset-then-climb).
    f="$tmp/green"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -lt 80 ]; then
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" $((1500000 + i % 7))
        else
            st_line "$f/evidence.jsonl" "$ts" 0 2 $((base + 80 * 3600 - 100)) $((1500000 + i % 7))
        fi
    done
    st_judge "$f" 168 "$fresh" MET "" 0 full-green-window
    soak_judge_out="$(ZCL_SOAK_EVIDENCE_DIR="$f" ZCL_SOAK_NOW="$fresh" bash "$SELF" judge --window-hours 168 2>&1)" \
        || st_fail "case=full-green-window judge itself exited non-zero"
    grep -q 'restarts_in_window=1 ambiguous_restarts=1 operator_interventions=0' <<<"$soak_judge_out" \
        || st_fail "case=full-green-window expected restarts_in_window=1 ambiguous_restarts=1 operator_interventions=0"

    # A2) Timer-jitter boundary: the first selected sample is 2 minutes
    #     after the nominal 168h start, so covered_sec is 604680 instead
    #     of 604800. That is within WINDOW_SLACK_SEC and must not hide a
    #     green week behind a bogus window_short verdict.
    f="$tmp/slack-ok"; mkdir -p "$f"
    st_line "$f/evidence.jsonl" $((base + 120)) 0 1 "$aet" 1500000
    for ((i = 1; i <= 168; i++)); do
        st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 1 "$aet" 1500000
    done
    st_judge "$f" 168 "$fresh" MET "" 0 window-slack-ok
    soak_judge_out="$(ZCL_SOAK_EVIDENCE_DIR="$f" ZCL_SOAK_NOW="$fresh" bash "$SELF" judge --window-hours 168 2>&1)" \
        || st_fail "case=window-slack-ok judge itself exited non-zero"
    grep -q 'window_covered_sec=604680' <<<"$soak_judge_out" \
        || st_fail "case=window-slack-ok expected exact covered seconds"

    # A3) Same boundary, but one second beyond the explicit 15-minute
    #     start slack: still INSUFFICIENT, and the reason names exact
    #     seconds instead of rounded hours.
    f="$tmp/slack-short"; mkdir -p "$f"
    st_line "$f/evidence.jsonl" $((base + WINDOW_SLACK_SEC + 1)) 0 1 "$aet" 1500000
    for ((i = 1; i <= 168; i++)); do
        st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 1 "$aet" 1500000
    done
    st_judge "$f" 168 "$fresh" INSUFFICIENT "window_short_603899s_lt_604800s_slack900s" 2 window-slack-short

    # B) short window: 12 hourly samples (11 h) => INSUFFICIENT.
    f="$tmp/short"; mkdir -p "$f"
    for ((i = 0; i <= 11; i++)); do
        st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 1 "$aet" 1500000
    done
    st_judge "$f" 168 $((base + 11 * 3600 + 60)) INSUFFICIENT "window_short_" 2 short-window

    # C) sampling hole: full 168 h coverage but samples 50..53 missing
    #    (5 h hole > 8100 s threshold) => NOT_MET.
    f="$tmp/hole"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        [ "$i" -ge 50 ] && [ "$i" -le 53 ] && continue
        st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 1 "$aet" 1500000
    done
    st_judge "$f" 168 "$fresh" NOT_MET "sampling_hole_" 1 sampling-hole

    # D) persistent gap: 10 of 169 ok samples lag zclassicd by 3 blocks
    #    (gap0 94.1% < 99%) => NOT_MET.
    f="$tmp/gap"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        if [ "$i" -ge 60 ] && [ "$i" -le 69 ]; then
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 3 1 "$aet" 1500000
        else
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 1 "$aet" 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" NOT_MET "gap_nonzero_in_10_of_169_ok_samples" 1 persistent-gap

    # E) operator intervention: NRestarts 2 -> 0 reset + AET bump at
    #    i=100 (the manual-restart signature) => NOT_MET.
    f="$tmp/operator"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        if [ "$i" -lt 100 ]; then
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 2 "$aet" 1500000
        else
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 0 $((base + 100 * 3600 - 30)) 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" NOT_MET "operator_intervention_detected" 1 operator-intervention

    # F) empty/missing log => explicit INSUFFICIENT (never silent pass).
    f="$tmp/empty"; mkdir -p "$f"
    st_judge "$f" 168 "$fresh" INSUFFICIENT "no_evidence_file" 2 empty-log

    # I) soak node unreachable for nearly the whole window: 165 of 169
    #    samples are ok:false with soak_height null (RPC dead/hung — the
    #    exact MVP-C6 failure mode), only 4 ok gap==0 samples. The 4
    #    green samples must NOT carry the verdict => NOT_MET. (This was
    #    the reviewer-proven false-MET fixture.)
    f="$tmp/soak-down"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -eq 0 ] || [ "$i" -eq 56 ] || [ "$i" -eq 112 ] || [ "$i" -eq 168 ]; then
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" 1500000
        else
            printf '{"ts":%d,"soak_height":null,"zd_height":%d,"gap":null,"nrestarts":1,"active_enter_ts":%d,"rss_kb":null,"mainpid":null,"ok":false}\n' \
                "$ts" $((3000000 + (ts % 100000))) "$aet" >> "$f/evidence.jsonl"
        fi
    done
    st_judge "$f" 168 "$fresh" NOT_MET "soak_unreachable_in_165_of_169_samples" 1 soak-unreachable

    # J) oracle coverage thin: soak node answers everywhere, but the
    #    zclassicd oracle is null in 30 of 169 samples (ok 139/169 <
    #    90%) — gap evidence too thin to prove gap==0 => INSUFFICIENT.
    f="$tmp/oracle-thin"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -ge 20 ] && [ "$i" -le 49 ]; then
            printf '{"ts":%d,"soak_height":%d,"zd_height":null,"gap":null,"nrestarts":1,"active_enter_ts":%d,"rss_kb":1500000,"mainpid":777,"ok":false}\n' \
                "$ts" $((3000000 + (ts % 100000))) "$aet" >> "$f/evidence.jsonl"
        else
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" INSUFFICIENT "oracle_coverage_thin_ok_139_of_169" 2 oracle-coverage-thin

    # K) staleness cap: the SAME fully-green fixture as A, judged with
    #    "now" 30 days after the last sample — a collector that died
    #    after one green week must not stay evergreen MET =>
    #    INSUFFICIENT stale_evidence_age_*; --allow-stale deliberately
    #    judges the historical window => MET again.
    st_judge "$tmp/green" 168 $((last_ts + 2592000)) INSUFFICIENT "stale_evidence_age_2592000s" 2 stale-green
    st_judge "$tmp/green" 168 $((last_ts + 2592000)) MET "" 0 stale-green-allow-stale --allow-stale

    # M) One explicit review-required sample breaks the clean window even
    #    though every height, gap, cadence, and restart fact is green.
    f="$tmp/security-review"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -eq 80 ]; then
            printf '{"ts":%d,"soak_height":3000000,"zd_height":3000000,"gap":0,"nrestarts":1,"active_enter_ts":%d,"rss_kb":1500000,"security_review_required":true,"security_posture_ok":false,"window_eligible":false,"ok":true}\n' \
                "$ts" "$aet" >> "$f/evidence.jsonl"
        else
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" NOT_MET \
        "security_review_required_in_1_of_169_samples" 1 \
        security-review-breaks-window

    # N) A legacy/unknown posture sample also cannot bridge a green window.
    #    Unknown evidence is not a demonstrated failure, so it is
    #    INSUFFICIENT rather than NOT_MET, but it can never earn MET.
    f="$tmp/security-unknown"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -eq 80 ]; then
            printf '{"ts":%d,"soak_height":3000000,"zd_height":3000000,"gap":0,"nrestarts":1,"active_enter_ts":%d,"rss_kb":1500000,"ok":true}\n' \
                "$ts" "$aet" >> "$f/evidence.jsonl"
        else
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" INSUFFICIENT \
        "security_posture_unknown_in_1_of_169_samples" 2 \
        security-unknown-breaks-window

    # P) A known but internally ineligible posture pair also breaks the
    #    window. This catches corrupt/inconsistent evidence independently of
    #    the explicit review-required spelling.
    f="$tmp/security-gap"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        ts=$((base + i * 3600))
        if [ "$i" -eq 80 ]; then
            printf '{"ts":%d,"soak_height":3000000,"zd_height":3000000,"gap":0,"nrestarts":1,"active_enter_ts":%d,"rss_kb":1500000,"security_review_required":false,"security_posture_ok":false,"window_eligible":false,"ok":true}\n' \
                "$ts" "$aet" >> "$f/evidence.jsonl"
        else
            st_line "$f/evidence.jsonl" "$ts" 0 1 "$aet" 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" NOT_MET \
        "security_posture_gap_in_1_of_169_samples" 1 \
        security-gap-breaks-window

    # L) reset-then-climb ambiguity: NRestarts 5 -> 7 with an AET jump at
    #    i=100 (could be 2 autonomous recycles OR a manual reset + 8
    #    recycles inside one cadence — indistinguishable at hourly
    #    resolution). Reported as ambiguous_restarts=2, NOT gated
    #    (criterion text + journal forensics decide) => still MET.
    f="$tmp/ambiguous"; mkdir -p "$f"
    for ((i = 0; i <= 168; i++)); do
        if [ "$i" -lt 100 ]; then
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 5 "$aet" 1500000
        else
            st_line "$f/evidence.jsonl" $((base + i * 3600)) 0 7 $((base + 100 * 3600 - 30)) 1500000
        fi
    done
    st_judge "$f" 168 "$fresh" MET "" 0 ambiguous-reset-climb
    soak_judge_out="$(ZCL_SOAK_EVIDENCE_DIR="$f" ZCL_SOAK_NOW="$fresh" bash "$SELF" judge --window-hours 168 2>&1)" \
        || st_fail "case=ambiguous-reset-climb judge itself exited non-zero"
    grep -q 'restarts_in_window=2 ambiguous_restarts=2 operator_interventions=0' <<<"$soak_judge_out" \
        || st_fail "case=ambiguous-reset-climb expected restarts_in_window=2 ambiguous_restarts=2 operator_interventions=0"

    # G) collect with INJECTED commands (no live nodes): both fake RPCs
    #    answer => ok:true line with the computed gap and systemd fields.
    f="$tmp/collect-up"; mkdir -p "$f"
    (
        export ZCL_SOAK_EVIDENCE_DIR="$f"
        export ZCL_SOAK_RPC_CMD="echo '{\"result\":105,\"error\":null,\"id\":1}'"
        export ZCL_ZD_RPC_CMD="echo '{\"result\":107,\"error\":null,\"id\":1}'"
        export ZCL_SOAK_SECURITY_CMD="echo '{\"result\":{\"security_review_required\":false}}'"
        export ZCL_SOAK_SHOW_CMD="printf 'MainPID=4242\nNRestarts=3\nActiveEnterTimestamp=Fri 2026-06-12 23:25:11 UTC\n'"
        export ZCL_SOAK_RSS_CMD="echo 'VmRSS:    123456 kB'"
        bash "$SELF" collect > /dev/null
    ) || st_fail "case=collect-up collect exited non-zero"
    grep -q '"soak_height":105,"zd_height":107,"gap":2,"nrestarts":3,' "$f/evidence.jsonl" \
        || { cat "$f/evidence.jsonl" >&2; st_fail "case=collect-up wrong fields"; }
    grep -q '"rss_kb":123456,"mainpid":4242,"security_review_required":false,"security_posture_ok":true,"window_eligible":true,"ok":true}' "$f/evidence.jsonl" \
        || { cat "$f/evidence.jsonl" >&2; st_fail "case=collect-up wrong rss/mainpid/ok"; }
    echo "selftest: ok case=collect-up"

    # H) collect with BOTH nodes down (commands fail): still appends an
    #    ok:false line with nulls, exits 0 (the hole IS the evidence).
    f="$tmp/collect-down"; mkdir -p "$f"
    (
        export ZCL_SOAK_EVIDENCE_DIR="$f"
        export ZCL_SOAK_RPC_CMD="false"
        export ZCL_ZD_RPC_CMD="false"
        export ZCL_SOAK_SECURITY_CMD="false"
        export ZCL_SOAK_SHOW_CMD="false"
        export ZCL_SOAK_RSS_CMD="false"
        bash "$SELF" collect > /dev/null 2>&1
    ) || st_fail "case=collect-down collect must exit 0 on unreachable nodes"
    grep -q '"soak_height":null,"zd_height":null,"gap":null,"nrestarts":null,"active_enter_ts":null,"rss_kb":null,"mainpid":null,"security_review_required":null,"security_posture_ok":false,"window_eligible":false,"ok":false}' \
        "$f/evidence.jsonl" \
        || { cat "$f/evidence.jsonl" >&2; st_fail "case=collect-down wrong null line"; }
    echo "selftest: ok case=collect-down"

    # O) A reachable, perfectly aligned node with review_required still
    #    records a non-accruing sample.
    f="$tmp/collect-review"; mkdir -p "$f"
    (
        export ZCL_SOAK_EVIDENCE_DIR="$f"
        export ZCL_SOAK_RPC_CMD="echo '{\"result\":105}'"
        export ZCL_ZD_RPC_CMD="echo '{\"result\":105}'"
        export ZCL_SOAK_SECURITY_CMD="echo '{\"result\":{\"security_review_required\":true}}'"
        export ZCL_SOAK_SHOW_CMD="printf 'MainPID=4242\nNRestarts=0\nActiveEnterTimestamp=Fri 2026-06-12 23:25:11 UTC\n'"
        export ZCL_SOAK_RSS_CMD="echo 'VmRSS: 123456 kB'"
        bash "$SELF" collect > /dev/null 2>&1
    ) || st_fail "case=collect-review collect exited non-zero"
    grep -q '"security_review_required":true,"security_posture_ok":false,"window_eligible":false,"ok":true}' \
        "$f/evidence.jsonl" \
        || { cat "$f/evidence.jsonl" >&2; st_fail "case=collect-review accrued"; }
    echo "selftest: ok case=collect-review"

    echo "selftest: PASS"
}

# ── dispatch ───────────────────────────────────────────────────────

case "${1:-}" in
    collect)    shift; cmd_collect "$@" ;;
    judge)      shift; cmd_judge "$@" ;;
    --selftest) shift; cmd_selftest "$@" ;;
    *)
        echo "usage: soak_evidence.sh collect | judge [--window-hours N] [--allow-stale] | --selftest" >&2
        exit 2
        ;;
esac
