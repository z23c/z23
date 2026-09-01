#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# c3_stopwatch_run_and_record.sh — the COLLECT half of the C3 wall-clock
# stopwatch evidence ledger. Runs
# tools/scripts/cold_start_to_tip_stopwatch.sh exactly once and appends ONE
# JSON line to the durable ledger at
# ~/.local/state/zclassic23-c3-stopwatch/history.jsonl. The JUDGE half is
# tools/scripts/stopwatch_evidence_judge.sh / `make c3-stopwatch-report`
# (same collect/judge split as tools/scripts/soak_evidence.sh — collect
# NEVER gates on the run's outcome, judge does).
#
# Ledger line: {ts, verdict, exit_code, wall_clock_seconds, boots,
#               budget_seconds, peer, file_peer, node_bin, build_commit,
#               artifact_dir, final_network_tip, final_hstar, peer_datadir,
#               peer_block_index_rows, peer_tip_finalize_rows, peer_utxo_rows}
#   boots is the total node launches the run spanned (1 = no respawn; >1 = the
#   harness followed that many supervised self-respawns across the one wiped
#   datadir — how an install-on-next-boot run survives the respawn seam).
#   verdict is one of pass|fail|skip|seam|stalled-named|frontier-busy-timeout|
#   readback-failed|error, mapped from the underlying stopwatch's exit code
#   (0/1/2/3/4/5/6/other).
#   final_network_tip/final_hstar are lifted straight out of the run's
#   proof.json (the best peer-advertised height and the reducer's authoritative
#   tip at end-of-run) so the judge can refuse a "pass" against a below-
#   checkpoint / stale fixture peer WITHOUT re-reading the artifact directory —
#   the anti-thin-fixture gate keys on these two fields.
#   peer_datadir + peer_*_rows record the SHAPE of the serving fixture peer's
#   hot tables (block-index / tip_finalize_log / utxo row volumes) at collect
#   time, so a future judge can ratchet on fixture shape — a thin fixture that
#   never carried live row volumes once hid an O(delta^2) tip_finalize collapse
#   behind a green stopwatch. Best-effort (SELECT-only, read-only, bounded):
#   any count that is not cheaply available is recorded null, never fabricated
#   and never allowed to fail the collect. These are ADDITIVE fields — every
#   pre-existing field keeps its exact name/position/value, so older ledger
#   consumers (the shared judge, `make c3-stopwatch-report`) are unaffected.
#   skip_reason + peer_precheck + skip_class + skip_streak + no_pass_streak
#   are likewise additive, and they exist because a `skip` used to be a dead
#   end: the harness records WHY it skipped in its proof.json, but the ledger
#   line carried neither the reason nor the precheck, so no ledger-only
#   consumer could tell a week-dead fixture peer from a typo in a flag. Both
#   are recorded now, plus the class that reason maps to (the shared table in
#   engine/services/include/services/stopwatch_skip_classes.def) and the trailing
#   streaks. The streak fields are a CONVENIENCE for readers: every consumer
#   that acts on them recomputes them from the verdict values rather than
#   trusting the recorded number, so a forged field cannot silence anything.
#
# ALARM (stderr + syslog, never an exit code): after the append, a run of
# consecutive skips whose class has a non-zero threshold prints one ALARM
# line to stderr and to `logger -t stopwatch-gate`. This is the fix for the
# defect where the C3 gate skipped every scheduled run from 2026-07-28 06:02
# onward and nothing said so — the judge grades a skip as FAIL, but nothing
# ran the judge, and the architecture scorer reads `tail -n 5`, so one old
# pass held the number up for four consecutive skips (~30h). The alarm
# REPORTS: it never changes this script's exit code (still 0 on a successful
# append), it is never printed on stdout, and it carries no VERDICT= token,
# so no grader can consume it. Benign skips (class not_configured, threshold
# 0) never alarm — a detector that cries wolf on a benign skip gets ignored,
# which recreates the bug it was built to fix.
#
# SECOND ALARM (stderr + syslog, likewise never an exit code): a run of
# consecutive NON-PASSES — verdict != pass, whether or not any of them were
# skips — prints its own ALARM line once it reaches STOPWATCH_NO_PASS_THRESHOLD
# in the same shared table (4, ~24h at the 6h timer cadence). The first alarm
# only ever asked "could the proof RUN"; measured 2026-08-29 the C3 gate ran
# 34 consecutive scheduled times, skipped NONE of them and passed none of
# them, so skip_streak stayed 0 and every reader called that "quiet". The two
# alarms are worded so an operator can tell them apart without opening the
# ledger: "could not run at all" vs "RAN ... and never once passed". The only
# exemption is a streak made entirely of benign (threshold-0) skips.
#
# Env:
#   ZCL_BIN               node binary to time (default $REPO_ROOT/build/bin/zclassic23)
#   ZCL_PEER              peer H:P to dial (default 127.0.0.1:39070 — the
#                          dedicated zcl-stopwatch-peer.service fixture)
#   ZCL_CS_FILE_PEER      ROM file-service H:P (defaults to the dedicated
#                          fixture's 127.0.0.1:39072 only for the autonomous
#                          fetch path; copied-header/staged-bundle runs leave
#                          it empty unless explicitly supplied)
#   ZCL_CS_HEADER_SOURCE  optional copied legacy datadir for the board's
#                          headers-first proof move
#   ZCL_CS_BUNDLE_PATH    optional immutable checkpoint bundle to stage into
#                          the wiped proof datadir
#   ZCL_CS_BUDGET_SECS    stopwatch budget seconds, forwarded straight
#                          through to cold_start_to_tip_stopwatch.sh
#                          (its own default is 600 if unset here)
#   ZCL_C3_HISTORY_DIR    ledger dir override (default
#                          ~/.local/state/zclassic23-c3-stopwatch)
#   ZCL_CS_PEER_DATADIR   serving fixture peer's datadir, counted (read-only)
#                          for the fixture-shape fields. Default
#                          ~/.zclassic-c23-fixture-serve — the datadir of the
#                          canonical serving fixture that listens on the default
#                          ZCL_PEER (39070) / ZCL_CS_PEER_RPCPORT (39071). The
#                          RPC client authenticates with the cookie at
#                          <datadir>/.cookie, so this MUST match the peer being
#                          dialed or every count refuses with CONNECT_REFUSED and
#                          records null. Override for a differently-sited peer.
#   ZCL_CS_PEER_RPCPORT   that peer's RPC port used for the read-only row
#                          counts (default 39071, the fixture peer's rpcport).
#                          Counting goes through the RUNNING peer's own RPC via
#                          the SELECT-only `core storage query` primitive, so it
#                          never opens the live datadir out from under the node.
#
# Exit code: 0 once the ledger append succeeds, REGARDLESS of the
# underlying run's verdict (pass/fail/skip/seam/stalled-named are all
# recorded, not gated here — that is the judge's job). The ONLY thing that
# makes this wrapper itself fail is being unable to lock or append the
# ledger line — never fails the append silently, same discipline as
# soak_evidence.sh's collect command.

set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STOPWATCH="$SCRIPT_DIR/cold_start_to_tip_stopwatch.sh"

# Skip classification + streak arithmetic, shared with the judge and with the
# node's typed `ops state --subsystem=stopwatch_evidence` surface (all three
# read one class table). Absence must never break the collect: without it the
# line still gets appended, just without a class or an alarm.
SKIP_CLASS_LIB="$SCRIPT_DIR/stopwatch_skip_class.sh"
SKIP_CLASS_OK=0
# shellcheck source=tools/scripts/stopwatch_skip_class.sh
if [ -r "$SKIP_CLASS_LIB" ] && . "$SKIP_CLASS_LIB"; then
    SKIP_CLASS_OK=1
else
    echo "c3-stopwatch-run: WARN skip classifier $SKIP_CLASS_LIB unreadable — the ledger line will carry no skip_class and no skip-streak alarm will fire" >&2
fi

ZCL_BIN="${ZCL_BIN:-$REPO_ROOT/build/bin/zclassic23}"
ZCL_PEER="${ZCL_PEER:-127.0.0.1:39070}"
if [ -z "${ZCL_CS_FILE_PEER+x}" ]; then
    if [ -n "${ZCL_CS_HEADER_SOURCE:-}" ] || [ -n "${ZCL_CS_BUNDLE_PATH:-}" ]; then
        export ZCL_CS_FILE_PEER=""
    else
        export ZCL_CS_FILE_PEER="127.0.0.1:39072"
    fi
fi
export ZCL_CS_BUDGET_SECS="${ZCL_CS_BUDGET_SECS:-600}"

HISTORY_DIR="${ZCL_C3_HISTORY_DIR:-${HOME:-/root}/.local/state/zclassic23-c3-stopwatch}"
HISTORY_FILE="$HISTORY_DIR/history.jsonl"
mkdir -p "$HISTORY_DIR"

# Serving fixture peer whose hot-table row volumes we record (read-only) for
# the fixture-shape fields. Defaults match the dedicated zcl-stopwatch-peer
# .service (datadir ~/.local/state/zclassic23-stopwatch-peer, rpcport 39071).
PEER_DATADIR="${ZCL_CS_PEER_DATADIR:-${HOME:-/root}/.zclassic-c23-fixture-serve}"
PEER_RPCPORT="${ZCL_CS_PEER_RPCPORT:-39071}"

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr '\n' ' '; }
json_string() { printf '"%s"' "$(json_escape "$1")"; }
json_num_or_null() { case "${1:-}" in ''|*[!0-9-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

# proof_num <proof.json> <key> — first integer value of "key" in the run's
# proof.json (schema zcl.c3_stopwatch_artifact.v1). Echoes nothing if the file
# is absent or the field is null/non-numeric (json_num_or_null then records
# null). The proof.json writer emits `"key": <value>,` with a space after the
# colon, so the pattern tolerates optional whitespace.
proof_num() {
    [ -f "$1" ] || return 0
    grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+" "$1" 2>/dev/null |
        head -n1 | grep -oE -- '-?[0-9]+$'
}

# proof_str <proof.json> <key> — first string value of "key" in the run's
# proof.json. Echoes nothing when the file or field is absent. The whole
# reason a skip used to be undiagnosable from the ledger alone: the harness
# writes `"reason": "serving peer not reachable: 127.0.0.1:39070"` here and
# nothing ever copied it out.
proof_str() {
    [ -f "$1" ] || return 0
    grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null |
        head -n1 | sed -E "s/.*:[[:space:]]*\"([^\"]*)\"/\1/"
}

# count_peer_rows <table> — best-effort read-only COUNT(*) of one hot table in
# the serving fixture peer's datadir, via the RUNNING peer's own SELECT-only
# `core storage query` primitive (semicolon-rejected, auto-LIMIT, its own 2s
# budget + 100-row cap). Echoes the integer, or nothing on ANY hiccup (peer
# down, datadir gone, table absent, query interrupted by the node's budget) so
# a fat fixture that can't be cheaply counted records null rather than blocking
# the collect. A thin toy fixture — the exact cheat this guards against —
# counts near-instantly, which is precisely when we want the number recorded.
#
# Bounded retries with growing backoff (1,2,3s): under a heavy concurrent fold
# the serving peer misses the RPC/query deadline and answers empty exactly like
# the frontier read did — retrying across a longer window catches a load gap
# instead of recording a spurious null. When every retry still misses, null is
# the honest record (a genuinely-uncountable-under-load table), never fabricated.
# NEVER allowed to fail the collect: wrapped so a non-zero rc is swallowed.
count_peer_rows() {
    local table="$1" out cnt backoff
    [ -x "$ZCL_BIN" ] || return 0
    [ -d "$PEER_DATADIR" ] || return 0
    for backoff in 1 2 3 0; do
        out="$(timeout 12 "$ZCL_BIN" -rpcport="$PEER_RPCPORT" -datadir="$PEER_DATADIR" \
                core storage query --sql="SELECT COUNT(*) FROM $table" --format=json \
                2>/dev/null)" || out=""
        # dbquery renders result rows as a positional array: {"rows":[[<count>]],...}
        cnt="$(printf '%s' "$out" | tr -d ' \n' |
               grep -oE '"rows":\[\[-?[0-9]+' | grep -oE -- '-?[0-9]+$' | head -n1)"
        [ -n "$cnt" ] && { printf '%s' "$cnt"; return 0; }
        [ "$backoff" = 0 ] && break
        sleep "$backoff"
    done
    printf '%s' "$cnt"
}

build_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
[ -z "$build_commit" ] && build_commit="unknown"

echo "c3-stopwatch-run: bin=$ZCL_BIN peer=$ZCL_PEER file_peer=$ZCL_CS_FILE_PEER budget=${ZCL_CS_BUDGET_SECS}s build_commit=$build_commit"

set +e
out="$(bash "$STOPWATCH" --bin="$ZCL_BIN" --peer="$ZCL_PEER" 2>&1)"
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
    6) verdict="readback-failed" ;;
esac

wall_clock="$(printf '%s\n' "$out" | sed -n 's/^WALL_CLOCK_SECONDS=\([0-9][0-9]*\)$/\1/p' | tail -1)"
artifact_dir="$(printf '%s\n' "$out" | sed -n 's/^cold-start-wipe-stopwatch: artifact=\(.*\)$/\1/p' | tail -1)"
# boots = total node launches this run spanned (1 = no respawn; >1 = the
# harness followed N-1 supervised self-respawns across the one wiped datadir).
# Distinguishes an install-respawn run that SURVIVED the seam from a plain
# single-boot run in the durable ledger.
boots="$(printf '%s\n' "$out" | sed -n 's/^BOOTS=\([0-9][0-9]*\)$/\1/p' | tail -1)"

# All of the following extractions are BEST-EFFORT enrichment of the ledger
# line — none may ever fail the collect. Run them with set +e (same idiom as
# the stopwatch invocation above) so a grep-found-nothing / peer-unreachable
# non-zero can never abort the append; a missing value is simply recorded null.
set +e
# final_network_tip / final_hstar: lifted from the run's proof.json so the
# judge's anti-thin-fixture gate has them in the ledger line itself (it reads
# ONLY the last line, never the artifact dir). Absent/null on a run that never
# read a frontier — recorded null, gate then tolerates the line.
proof_json=""
[ -n "${artifact_dir:-}" ] && proof_json="$artifact_dir/proof.json"
final_network_tip="$(proof_num "$proof_json" final_network_tip)"
final_hstar="$(proof_num "$proof_json" final_hstar)"

# Fixture shape: row volumes of the serving peer's hot tables at collect time.
# Best-effort, read-only, null when not cheaply countable (see count_peer_rows).
peer_block_index_rows="$(count_peer_rows blocks)"
peer_tip_finalize_rows="$(count_peer_rows tip_finalize_log)"
peer_utxo_rows="$(count_peer_rows utxos)"

# Why this run skipped, straight out of the run's own proof.json. Empty for
# every non-skip verdict, and empty for a skip that never reached the
# harness's skip() at all (an argv error exits 2 without writing an artifact)
# — that emptiness is itself the signal the classifier keys on.
skip_reason=""
peer_precheck=""
if [ "$verdict" = "skip" ]; then
    skip_reason="$(proof_str "$proof_json" reason)"
fi
peer_precheck="$(proof_str "$proof_json" peer_precheck)"

# Trailing streaks, folded exactly the way every reader recomputes them: take
# the streaks the ledger already carries, then apply THIS row. Recorded for
# convenience only — the judge and the node both recompute from the verdict
# values rather than trust these fields.
skip_streak=0
no_pass_streak=0
skip_class=""
skip_threshold=0
prior_last_pass="-"
if [ "$SKIP_CLASS_OK" = "1" ]; then
    read -r prior_skip prior_nopass _prior_verdict prior_last_pass _prior_rows \
        < <(stopwatch_skip_streaks "$HISTORY_FILE")
    if [ "$verdict" = "pass" ]; then
        skip_streak=0
        no_pass_streak=0
    else
        no_pass_streak=$((prior_nopass + 1))
        if [ "$verdict" = "skip" ]; then
            skip_streak=$((prior_skip + 1))
        else
            skip_streak=0
        fi
    fi
    if [ "$skip_streak" -gt 0 ]; then
        reason_present=1
        has_artifact=0
        [ -n "${artifact_dir:-}" ] && has_artifact=1
        read -r skip_class skip_threshold \
            < <(stopwatch_skip_classify "$skip_reason" "$reason_present" \
                                        "$has_artifact")
    fi
fi
set -e

ts="$(date +%s)"
line="$(printf '{"ts":%s,"verdict":%s,"exit_code":%s,"wall_clock_seconds":%s,"boots":%s,"budget_seconds":%s,"peer":%s,"file_peer":%s,"node_bin":%s,"build_commit":%s,"artifact_dir":%s,"final_network_tip":%s,"final_hstar":%s,"peer_datadir":%s,"peer_block_index_rows":%s,"peer_tip_finalize_rows":%s,"peer_utxo_rows":%s,"skip_reason":%s,"peer_precheck":%s,"skip_class":%s,"skip_streak":%s,"no_pass_streak":%s}' \
    "$ts" "$(json_string "$verdict")" "$rc" "$(json_num_or_null "$wall_clock")" \
    "$(json_num_or_null "$boots")" \
    "$(json_num_or_null "$ZCL_CS_BUDGET_SECS")" "$(json_string "$ZCL_PEER")" \
    "$(json_string "$ZCL_CS_FILE_PEER")" "$(json_string "$ZCL_BIN")" \
    "$(json_string "$build_commit")" "$(json_string "${artifact_dir:-}")" \
    "$(json_num_or_null "$final_network_tip")" "$(json_num_or_null "$final_hstar")" \
    "$(json_string "$PEER_DATADIR")" \
    "$(json_num_or_null "$peer_block_index_rows")" \
    "$(json_num_or_null "$peer_tip_finalize_rows")" \
    "$(json_num_or_null "$peer_utxo_rows")" \
    "$(json_string "$skip_reason")" \
    "$(json_string "$peer_precheck")" \
    "$(json_string "$skip_class")" \
    "$(json_num_or_null "$skip_streak")" \
    "$(json_num_or_null "$no_pass_streak")")"

# flock-serialized append (same pattern as soak_evidence.sh cmd_collect):
# a bounded lock acquire (-w 30) whose failure is EXPLICIT, so a missing
# or stuck flock can never silently degrade to an unlocked/torn append,
# and can never hang past the unit's TimeoutStartSec.
append_rc=0
(
    flock -x -w 30 9 || exit 9
    printf '%s\n' "$line" >&9
) 9>>"$HISTORY_FILE" || append_rc=$?
if [ "$append_rc" -ne 0 ]; then
    if [ "$append_rc" -eq 9 ]; then
        echo "c3-stopwatch-run: FAIL could not acquire append lock on $HISTORY_FILE within 30s" >&2
    else
        echo "c3-stopwatch-run: FAIL could not append to $HISTORY_FILE (rc=$append_rc)" >&2
    fi
    exit 1
fi

echo "c3-stopwatch-run: appended file=$HISTORY_FILE verdict=$verdict rc=$rc"
echo "$line"

# ── skip-streak alarm ───────────────────────────────────────────────────
# STDERR + syslog only. Never stdout (the architecture scorer consumes the
# report's stdout), never a VERDICT= token, never an exit code. It can only
# ADD a line; there is no input under which it removes a FAIL, upgrades a
# verdict, or extends a window.
if [ "$skip_streak" -gt 0 ] && [ "$SKIP_CLASS_OK" = "1" ]; then
    # Plain if/then, not `[ … ] && …`: errexit is ON from here down, and a
    # false test in an && chain would take the whole collect with it.
    if [ "$prior_last_pass" = "-" ]; then
        last_pass_note="last_pass=never_in_ledger_tail"
    else
        last_pass_note="last_pass=$prior_last_pass"
    fi
    if [ "$skip_threshold" = "0" ]; then
        # Benign by construction: the harness had nothing configured, so it
        # had nothing to prove. Say so once, quietly, and do NOT alarm.
        echo "c3-stopwatch-run: note class=$skip_class skip_streak=$skip_streak — benign (nothing configured, nothing to prove); no alarm" >&2
    elif [ "$skip_streak" -ge "$skip_threshold" ]; then
        alarm_msg="c3-stopwatch-run: ALARM class=$skip_class skip_streak=$skip_streak threshold=$skip_threshold no_pass_streak=$no_pass_streak $last_pass_note reason=\"$skip_reason\" — this proof could not run at all on the last $skip_streak consecutive scheduled attempts, so nothing has proven the claim; fix the named cause, do not wait for the score to move"
        echo "$alarm_msg" >&2
        command -v logger >/dev/null 2>&1 && \
            logger -t stopwatch-gate "$alarm_msg" 2>/dev/null || true
    else
        echo "c3-stopwatch-run: WARN class=$skip_class skip_streak=$skip_streak threshold=$skip_threshold reason=\"$skip_reason\" — one more skipped run raises an alarm" >&2
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
        echo "c3-stopwatch-run: note no_pass_streak=$no_pass_streak — benign (every run in the streak had nothing configured to prove); no alarm" >&2
    elif [ "$no_pass_streak" -ge "$no_pass_threshold" ]; then
        no_pass_msg="c3-stopwatch-run: ALARM no_pass_streak=$no_pass_streak no_pass_threshold=$no_pass_threshold last_verdict=$verdict $no_pass_age_note — this proof RAN on every one of those consecutive scheduled attempts and never once passed, so the claim it exists to prove is unproven; fix the failing verdict, do not wait for the score to move"
        echo "$no_pass_msg" >&2
        command -v logger >/dev/null 2>&1 && \
            logger -t stopwatch-gate "$no_pass_msg" 2>/dev/null || true
    else
        echo "c3-stopwatch-run: WARN no_pass_streak=$no_pass_streak no_pass_threshold=$no_pass_threshold last_verdict=$verdict — this proof has run and not passed that many times in a row; $((no_pass_threshold - no_pass_streak)) more raises an alarm" >&2
    fi
fi

exit 0
