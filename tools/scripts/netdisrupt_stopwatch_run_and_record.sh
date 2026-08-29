#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# netdisrupt_stopwatch_run_and_record.sh — the COLLECT half of PROOF B
# (network-disruption recovery). Runs
# tools/scripts/network_disruption_recovery_stopwatch.sh exactly once and
# appends ONE JSON line to the durable ledger at
# ~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl. Same
# collect/judge split as c3_stopwatch_run_and_record.sh and
# tools/scripts/soak_evidence.sh — this wrapper NEVER gates on the run's
# outcome; tools/scripts/stopwatch_evidence_judge.sh /
# `make netdisrupt-stopwatch-report` does.
#
# Ledger line: {ts, verdict, exit_code, wall_clock_seconds, budget_seconds,
#               cut_seconds, peer, node_bin, build_commit, artifact_dir}
#   "peer" here is the CLIENT's own loopback RPC endpoint
#   (127.0.0.1:<client-rpc>) — this harness has no P2P peer of its own to
#   dial (unlike the C3 stopwatch), so the field is repurposed to name the
#   node under test, keeping the ledger schema close enough to
#   c3_stopwatch_run_and_record.sh's for one shared judge script.
#   verdict is one of pass|fail|skip|seam|stalled-named|frontier-busy-timeout|
#   error, mapped from the underlying script's exit code (0/1/2/3/4/5/other).
#   ADDITIVE fields skip_reason, skip_class, skip_streak, no_pass_streak
#   mirror the C3 collector's: a skip used to be a dead end in the ledger,
#   indistinguishable from any other skip. PROOF B is the ONLY harness that
#   can produce a genuinely BENIGN skip (class not_configured — no
#   --client-rpc and no upstream pid means there was nothing to prove), which
#   is exactly why its reason has to be recorded: without it the benign class
#   could never be told apart from a dead fixture in production.
#   Two alarms are emitted after the append, both on stderr + syslog only and
#   neither touching the exit code: a consecutive-SKIP run of a class with a
#   non-zero threshold ("this proof could not run at all"), and a consecutive
#   NON-PASS run reaching STOPWATCH_NO_PASS_THRESHOLD ("this proof RAN and
#   never once passed"). A streak of purely benign not_configured skips
#   reaches neither.
#
# Env (forwarded straight through to network_disruption_recovery_stopwatch.sh):
#   ZCL_ND_NODE_BIN            client CLI binary (default $REPO_ROOT/build/bin/zclassic23)
#   ZCL_ND_UPSTREAM_PID_FILE   this wrapper's own source of --upstream-pid-file=
#   ZCL_ND_UPSTREAM_PID        bare upstream pid, used when no pid file is set
#   ZCL_ND_CLIENT_RPCPORT      client RPC port (required — no default; a
#                              missing target is an operator misconfig, not
#                              a silently-skippable default)
#   ZCL_ND_CLIENT_DATADIR      client datadir (required, same reasoning)
#   ZCL_ND_CUT_SECS            upstream outage duration (default 600)
#   ZCL_ND_BUDGET_SECS         recovery budget (default 600)
#   ZCL_ND_HISTORY_DIR         ledger dir override (default
#                              ~/.local/state/zclassic23-netdisrupt-stopwatch)
#
# Exit code: 0 once the ledger append succeeds, REGARDLESS of the
# underlying run's verdict — the only hard failure is an unlockable/
# unappendable ledger. Never fails the append silently.

set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STOPWATCH="$SCRIPT_DIR/network_disruption_recovery_stopwatch.sh"

# Shared skip classifier + streak arithmetic (see the C3 collector). Absence
# must never break the collect: the line is still appended, just without a
# class or an alarm.
SKIP_CLASS_LIB="$SCRIPT_DIR/stopwatch_skip_class.sh"
SKIP_CLASS_OK=0
# shellcheck source=tools/scripts/stopwatch_skip_class.sh
if [ -r "$SKIP_CLASS_LIB" ] && . "$SKIP_CLASS_LIB"; then
    SKIP_CLASS_OK=1
else
    echo "netdisrupt-stopwatch-run: WARN skip classifier $SKIP_CLASS_LIB unreadable — the ledger line will carry no skip_class and no skip-streak alarm will fire" >&2
fi

NODE_BIN="${ZCL_ND_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
UPSTREAM_PID_FILE="${ZCL_ND_UPSTREAM_PID_FILE:-}"
CLIENT_RPCPORT="${ZCL_ND_CLIENT_RPCPORT:-}"
CLIENT_DATADIR="${ZCL_ND_CLIENT_DATADIR:-}"
CUT_SECS="${ZCL_ND_CUT_SECS:-600}"
BUDGET="${ZCL_ND_BUDGET_SECS:-600}"

HISTORY_DIR="${ZCL_ND_HISTORY_DIR:-${HOME:-/root}/.local/state/zclassic23-netdisrupt-stopwatch}"
HISTORY_FILE="$HISTORY_DIR/history.jsonl"
mkdir -p "$HISTORY_DIR"

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr '\n' ' '; }
json_string() { printf '"%s"' "$(json_escape "$1")"; }
json_num_or_null() { case "${1:-}" in ''|*[!0-9-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

build_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
[ -z "$build_commit" ] && build_commit="unknown"

flag_args=("--bin=$NODE_BIN" "--cut-secs=$CUT_SECS" "--budget=$BUDGET")
[ -n "$UPSTREAM_PID_FILE" ] && flag_args+=("--upstream-pid-file=$UPSTREAM_PID_FILE")
[ -n "$CLIENT_RPCPORT" ] && flag_args+=("--client-rpc=$CLIENT_RPCPORT")
[ -n "$CLIENT_DATADIR" ] && flag_args+=("--client-datadir=$CLIENT_DATADIR")

echo "netdisrupt-stopwatch-run: bin=$NODE_BIN client_rpc=${CLIENT_RPCPORT:-<unset>} client_datadir=${CLIENT_DATADIR:-<unset>} cut=${CUT_SECS}s budget=${BUDGET}s build_commit=$build_commit"

set +e
out="$(ZCL_ND_UPSTREAM_PID="${ZCL_ND_UPSTREAM_PID:-}" bash "$STOPWATCH" "${flag_args[@]}" 2>&1)"
rc=$?
set -e
printf '%s\n' "$out"

verdict="error"
case "$rc" in
    0) verdict="pass" ;;
    1) verdict="fail" ;;
    2) verdict="skip" ;;
    3) verdict="seam" ;;
    4) verdict="stalled-named" ;;
    5) verdict="frontier-busy-timeout" ;;
esac

wall_clock="$(printf '%s\n' "$out" | sed -n 's/^WALL_CLOCK_SECONDS=\([0-9][0-9]*\)$/\1/p' | tail -1)"
artifact_dir="$(printf '%s\n' "$out" | sed -n 's/^netdisrupt-stopwatch: artifact=\(.*\)$/\1/p' | tail -1)"
peer_desc="127.0.0.1:${CLIENT_RPCPORT:-0}"

# Why this run skipped, and where that puts the trailing streak. Best-effort
# enrichment under `set +e` like the C3 collector's — a grep that finds
# nothing may never abort the append.
set +e
skip_reason=""
if [ "$verdict" = "skip" ] && [ -n "${artifact_dir:-}" ] &&
   [ -f "$artifact_dir/proof.json" ]; then
    skip_reason="$(grep -oE '"reason"[[:space:]]*:[[:space:]]*"[^"]*"' \
                   "$artifact_dir/proof.json" 2>/dev/null | head -n1 |
                   sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')"
fi
skip_streak=0
no_pass_streak=0
skip_class=""
skip_threshold=0
prior_last_pass="-"
if [ "$SKIP_CLASS_OK" = "1" ]; then
    read -r prior_skip prior_nopass _prior_verdict prior_last_pass _prior_rows \
        < <(stopwatch_skip_streaks "$HISTORY_FILE")
    if [ "$verdict" != "pass" ]; then
        no_pass_streak=$((prior_nopass + 1))
        [ "$verdict" = "skip" ] && skip_streak=$((prior_skip + 1))
    fi
    if [ "$skip_streak" -gt 0 ]; then
        has_artifact=0
        [ -n "${artifact_dir:-}" ] && has_artifact=1
        read -r skip_class skip_threshold \
            < <(stopwatch_skip_classify "$skip_reason" 1 "$has_artifact")
    fi
fi
set -e

ts="$(date +%s)"
line="$(printf '{"ts":%s,"verdict":%s,"exit_code":%s,"wall_clock_seconds":%s,"budget_seconds":%s,"cut_seconds":%s,"peer":%s,"node_bin":%s,"build_commit":%s,"artifact_dir":%s,"skip_reason":%s,"skip_class":%s,"skip_streak":%s,"no_pass_streak":%s}' \
    "$ts" "$(json_string "$verdict")" "$rc" "$(json_num_or_null "$wall_clock")" \
    "$(json_num_or_null "$BUDGET")" "$(json_num_or_null "$CUT_SECS")" "$(json_string "$peer_desc")" \
    "$(json_string "$NODE_BIN")" "$(json_string "$build_commit")" "$(json_string "${artifact_dir:-}")" \
    "$(json_string "$skip_reason")" "$(json_string "$skip_class")" \
    "$(json_num_or_null "$skip_streak")" "$(json_num_or_null "$no_pass_streak")")"

append_rc=0
(
    flock -x -w 30 9 || exit 9
    printf '%s\n' "$line" >&9
) 9>>"$HISTORY_FILE" || append_rc=$?
if [ "$append_rc" -ne 0 ]; then
    if [ "$append_rc" -eq 9 ]; then
        echo "netdisrupt-stopwatch-run: FAIL could not acquire append lock on $HISTORY_FILE within 30s" >&2
    else
        echo "netdisrupt-stopwatch-run: FAIL could not append to $HISTORY_FILE (rc=$append_rc)" >&2
    fi
    exit 1
fi

echo "netdisrupt-stopwatch-run: appended file=$HISTORY_FILE verdict=$verdict rc=$rc"
echo "$line"

# ── skip-streak alarm — stderr + syslog only, never stdout, never the exit
# code, never a VERDICT= token. See the C3 collector for the containment
# argument. PROOF B is the harness that can legitimately be UNCONFIGURED, so
# the benign branch below is not decoration: without it this alarm would fire
# on every host that simply never set up a network-disruption fixture, and an
# alarm that fires on nothing gets ignored.
if [ "$skip_streak" -gt 0 ] && [ "$SKIP_CLASS_OK" = "1" ]; then
    if [ "$prior_last_pass" = "-" ]; then
        last_pass_note="last_pass=never_in_ledger_tail"
    else
        last_pass_note="last_pass=$prior_last_pass"
    fi
    if [ "$skip_threshold" = "0" ]; then
        echo "netdisrupt-stopwatch-run: note class=$skip_class skip_streak=$skip_streak — benign (nothing configured, nothing to prove); no alarm" >&2
    elif [ "$skip_streak" -ge "$skip_threshold" ]; then
        alarm_msg="netdisrupt-stopwatch-run: ALARM class=$skip_class skip_streak=$skip_streak threshold=$skip_threshold no_pass_streak=$no_pass_streak $last_pass_note reason=\"$skip_reason\" — this proof could not run at all on the last $skip_streak consecutive scheduled attempts, so nothing has proven the claim; fix the named cause"
        echo "$alarm_msg" >&2
        command -v logger >/dev/null 2>&1 && \
            logger -t stopwatch-gate "$alarm_msg" 2>/dev/null || true
    else
        echo "netdisrupt-stopwatch-run: WARN class=$skip_class skip_streak=$skip_streak threshold=$skip_threshold reason=\"$skip_reason\" — one more skipped run raises an alarm" >&2
    fi
fi

# ── no-pass alarm (the SECOND rung) ─────────────────────────────────────
# Same containment as the block above: STDERR + syslog only, never stdout,
# never a VERDICT= token, never the exit code. This collector exits 0
# whatever it finds — the ledger append must never be lost to a failed
# escalation — so the loudness lives here and in the judge, not in $?.
#
# WHY THIS EXISTS. The block above only ever asks "could the proof RUN".
# Measured 2026-08-29 on the C3 ledger: 34 consecutive scheduled runs, none
# of them skipped, none of them passing (the last 17 `stalled-named` with the
# node under test at zero blocks synced) — skip_streak was 0 the whole time,
# so nothing above fired and the typed report called that state "quiet".
# A proof that runs and never succeeds is the more damning of the two
# conditions, and it was the silent one.
#
# The ONE carve-out is narrow on purpose: a streak made ENTIRELY of skips the
# class table calls benign (threshold 0 — nothing configured, nothing to
# prove) stays quiet. A single fail/seam/stalled-named/unclassified row in
# the streak ends it, so it can never mute a real fault. There is deliberately
# no env knob and no threshold of 0: a non-pass is never benign, the harness
# had something to prove and did not prove it.
if [ "$SKIP_CLASS_OK" = "1" ] && [ "$no_pass_streak" -gt 0 ]; then
    no_pass_threshold="$(stopwatch_no_pass_threshold)"
    no_pass_benign="$(stopwatch_no_pass_all_benign "$HISTORY_FILE")"
    # Same guard the C reader uses: a "-" (no pass in the tail) and a clock
    # that went backwards both report unknown rather than a negative age.
    if [ "$prior_last_pass" = "-" ] || [ "$ts" -lt "$prior_last_pass" ]; then
        no_pass_age_note="last_pass=never_in_ledger_tail"
    else
        no_pass_age_note="last_pass_age=$((ts - prior_last_pass))s-before-newest-row"
    fi
    if [ "$no_pass_benign" = "1" ]; then
        echo "netdisrupt-stopwatch-run: note no_pass_streak=$no_pass_streak — benign (every run in the streak had nothing configured to prove); no alarm" >&2
    elif [ "$no_pass_streak" -ge "$no_pass_threshold" ]; then
        no_pass_msg="netdisrupt-stopwatch-run: ALARM no_pass_streak=$no_pass_streak no_pass_threshold=$no_pass_threshold last_verdict=$verdict $no_pass_age_note — this proof RAN on every one of those consecutive scheduled attempts and never once passed, so the claim it exists to prove is unproven; fix the failing verdict, do not wait for the score to move"
        echo "$no_pass_msg" >&2
        command -v logger >/dev/null 2>&1 && \
            logger -t stopwatch-gate "$no_pass_msg" 2>/dev/null || true
    else
        echo "netdisrupt-stopwatch-run: WARN no_pass_streak=$no_pass_streak no_pass_threshold=$no_pass_threshold last_verdict=$verdict — this proof has run and not passed that many times in a row; $((no_pass_threshold - no_pass_streak)) more raises an alarm" >&2
    fi
fi

exit 0
