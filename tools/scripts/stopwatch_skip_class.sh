#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# stopwatch_skip_class.sh — the shell half of the stopwatch skip-streak
# detector. SOURCE it; it is not meant to be run as a command (running it
# directly only self-tests, see --selftest at the bottom).
#
# Three callers source this file:
#   tools/scripts/c3_stopwatch_run_and_record.sh   (collector — alarms at
#       collect time, on stderr + syslog, right after the ledger append)
#   tools/scripts/stopwatch_evidence_judge.sh      (judge — reports the
#       streak on stdout and alarms on stderr)
#   tools/scripts/netdisrupt_stopwatch_run_and_record.sh (PROOF B collector)
#
# It reads its class table from
# app/services/include/services/stopwatch_skip_classes.def — the SAME file
# app/services/src/stopwatch_skip_watch.c #includes for the typed
# `z23 ops state --subsystem=stopwatch_evidence` surface. One table,
# two consumers, no private copy to drift.
#
# ⛔ THIS FILE REPORTS. IT NEVER GRADES.
# Nothing here may change a verdict, a pass threshold, or an evidence window.
# The alarm it produces goes to STDERR and to syslog, never to stdout in a
# form any grader consumes, and it carries no "VERDICT=" token. The
# architecture scorer (tools/scripts/arch_score.sh) reads stdout of
# `make c3-stopwatch-report` and greps for VERDICT=PASS; a fact that cannot
# physically reach the grader cannot flatter it. That is the containment, not
# a promise to be careful.
#
# API (all functions echo, none exit):
#   stopwatch_skip_class_table            -> "class|threshold|match" per line
#   stopwatch_no_pass_threshold           -> the STOPWATCH_NO_PASS_THRESHOLD(n)
#                                            row, as a bare integer >= 1
#   stopwatch_no_pass_all_benign <ledger> -> 1 when the whole trailing
#                                            no-pass streak is benign skips
#   stopwatch_skip_classify R P A         -> "class threshold"
#       R = the recorded skip reason (may be empty)
#       P = 1 when the ledger row carried a skip_reason FIELD at all, else 0
#       A = 1 when the row named a non-empty artifact_dir, else 0
#   stopwatch_skip_streaks <ledger>       -> "skip_streak no_pass_streak
#                                            last_verdict last_pass_ts rows"
#   stopwatch_skip_row_field <line> <key> -> the string value, or empty
#   stopwatch_skip_row_has <line> <key>   -> rc 0 when the field EXISTS

# Resolve the class table relative to this file, so a worktree, a copied
# checkout, and the installed tree all find their own.
_SW_SKIP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_SW_SKIP_DEF="${ZCL_STOPWATCH_SKIP_CLASSES_DEF:-$_SW_SKIP_DIR/../../app/services/include/services/stopwatch_skip_classes.def}"

# Emit the table as class|threshold|match rows, in file order (order IS
# precedence — first substring match wins). Fallback rows carry an empty
# match field and are addressed by name, never matched.
stopwatch_skip_class_table() {
    [ -r "$_SW_SKIP_DEF" ] || return 0
    sed -n \
        -e 's/^STOPWATCH_SKIP_CLASS("\([^"]*\)",[ ]*\([0-9][0-9]*\),[ ]*"\(.*\)")[ ]*$/\1|\2|\3/p' \
        -e 's/^STOPWATCH_SKIP_FALLBACK("\([^"]*\)",[ ]*\([0-9][0-9]*\))[ ]*$/\1|\2|/p' \
        "$_SW_SKIP_DEF"
}

# ── the SECOND rung: consecutive NON-PASSES ────────────────────────────
# The class table above answers "the proof COULD NOT RUN, how loud is that".
# It is silent about the proof that RAN every scheduled time and never passed
# — measured 2026-08-29, 34 of those in a row on the C3 ledger with
# skip_streak 0 throughout, reported as "quiet". These two functions are the
# shell half of that second alarm; the C half is in
# app/services/src/stopwatch_skip_watch.c. Same one table, no private copy.

# stopwatch_no_pass_threshold — the STOPWATCH_NO_PASS_THRESHOLD(n) row, as a
# bare integer. Falls back LOUD (4, ~24h at the 6h C3 cadence) rather than to
# silence: an unreadable table must not be a supported way to mute this. 0 is
# not a legal value — unlike a skip class there is no benign non-pass, so a 0
# would mean "mute", and the C side refuses it at build time.
stopwatch_no_pass_threshold() {
    local v=""
    if [ -r "$_SW_SKIP_DEF" ]; then
        v="$(sed -n 's/^STOPWATCH_NO_PASS_THRESHOLD(\([0-9][0-9]*\))[ ]*$/\1/p' \
             "$_SW_SKIP_DEF" | head -n1)"
    fi
    case "$v" in
        ''|*[!0-9]*|0) printf '4\n'; return 0 ;;
    esac
    printf '%s\n' "$v"
}

# stopwatch_no_pass_all_benign <ledger> — echoes 1 when the ENTIRE trailing
# no-pass streak is skips the class table calls benign (threshold 0), else 0.
# This is the only carve-out on the no-pass alarm, and it is deliberately
# narrow: one fail/seam/stalled-named/unclassified row anywhere in the streak
# ends it, so it can never mute a real fault. An empty streak is NOT benign
# (there is nothing to excuse), it simply never reaches the threshold.
# Mirrors scan_row()/scan_finish() in the C module row for row.
stopwatch_no_pass_all_benign() {
    local f="${1:-}" line v reason present artifact cls thr any=0
    if [ -z "$f" ] || [ ! -s "$f" ]; then
        printf '0\n'
        return 0
    fi
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        v="$(stopwatch_skip_row_field "$line" verdict)"
        [ -n "$v" ] || continue
        [ "$v" = "pass" ] && break
        any=1
        if [ "$v" != "skip" ]; then
            printf '0\n'
            return 0
        fi
        reason="$(stopwatch_skip_row_field "$line" skip_reason)"
        present=0
        stopwatch_skip_row_has "$line" skip_reason && present=1
        artifact=0
        [ -n "$(stopwatch_skip_row_field "$line" artifact_dir)" ] && artifact=1
        read -r cls thr \
            < <(stopwatch_skip_classify "$reason" "$present" "$artifact")
        if [ "$thr" != "0" ]; then
            printf '0\n'
            return 0
        fi
    done < <(tail -n 200 "$f" |
             awk '{a[NR]=$0} END{for(i=NR;i>=1;i--) print a[i]}')
    printf '%s\n' "$any"
}

# stopwatch_skip_classify <reason> <reason_field_present 0|1> <has_artifact 0|1>
# Echoes "<class> <threshold>". Mirrors stopwatch_skip_classify() in
# app/services/src/stopwatch_skip_watch.c exactly, including the two
# structural fallbacks.
stopwatch_skip_classify() {
    local reason="${1:-}" present="${2:-0}" artifact="${3:-0}"
    local cls thr match line
    if [ -n "$reason" ]; then
        while IFS='|' read -r cls thr match; do
            [ -n "$match" ] || continue
            case "$reason" in
                *"$match"*) printf '%s %s\n' "$cls" "$thr"; return 0 ;;
            esac
        done <<EOF
$(stopwatch_skip_class_table)
EOF
    fi
    # No substring matched. A skip that wrote NO artifact never reached the
    # harness's skip(), so it died in argv parsing (harness_misuse).
    # Everything else — including every ledger row written before skip_reason
    # existed — is honestly unknown, never assumed benign.
    local want="unclassified"
    if [ "$present" = "1" ] && [ -z "$reason" ] && [ "$artifact" != "1" ]; then
        want="harness_misuse"
    fi
    while IFS='|' read -r cls thr match; do
        [ -z "$match" ] || continue
        if [ "$cls" = "$want" ]; then
            printf '%s %s\n' "$cls" "$thr"
            return 0
        fi
    done <<EOF
$(stopwatch_skip_class_table)
EOF
    # The table is missing its fallback rows — say so rather than inventing a
    # threshold. Threshold 2 keeps an unknown skip loud-ish, never silent.
    printf 'unclassified 2\n'
}

# stopwatch_skip_row_field <json_line> <key> — the string value of "key", or
# empty. Same one-line/flat-object assumption the judge's fld_str() makes.
stopwatch_skip_row_field() {
    printf '%s' "$1" | grep -oE "\"$2\":\"[^\"]*\"" | head -n1 |
        sed -E "s/\"$2\":\"([^\"]*)\"/\1/"
}

# stopwatch_skip_row_has <json_line> <key> — rc 0 when the FIELD exists at
# all (even as an empty string). "absent" and "present but empty" must read
# differently: absent means the row predates the field.
stopwatch_skip_row_has() {
    printf '%s' "$1" | grep -q "\"$2\":"
}

# stopwatch_skip_streaks <ledger> — recompute the trailing streaks from the
# `verdict` values in the ledger tail. Echoes
#   "<skip_streak> <no_pass_streak> <last_verdict> <last_pass_ts> <rows>"
# (last_verdict "-" and last_pass_ts "-" when unknown).
#
# Deliberately RECOMPUTED, never read from the skip_streak field the
# collector also records: a recorded number could be forged or simply absent
# on older rows, and a detector that trusts the thing it is detecting is not
# a detector. Bounded to the last 200 rows — the streak only ever lives at
# the tail.
stopwatch_skip_streaks() {
    local f="${1:-}"
    if [ -z "$f" ] || [ ! -s "$f" ]; then
        printf '0 0 - - 0\n'
        return 0
    fi
    tail -n 200 "$f" | awk '
        {
            if (match($0, /"verdict":"[^"]*"/) == 0) next
            v = substr($0, RSTART + 11, RLENGTH - 12)
            rows++
            last = v
            if (v == "pass") {
                skip = 0; nopass = 0
                lastpass = "-"
                if (match($0, /"ts":-?[0-9]+/) > 0)
                    lastpass = substr($0, RSTART + 5, RLENGTH - 5)
                next
            }
            nopass++
            if (v == "skip") skip++; else skip = 0
        }
        END {
            printf "%d %d %s %s %d\n", skip + 0, nopass + 0,
                   (rows ? last : "-"), (lastpass == "" ? "-" : lastpass),
                   rows + 0
        }'
}

# ── --selftest: hermetic checks against canned /tmp ledgers ─────────────
# Same idiom as the other tools/scripts selftests. Asserts the four
# contracts the C test group asserts, so a drift between the two
# implementations of ONE table shows up here rather than in production.
# Guarded on BASH_SOURCE==$0 so that sourcing this file from a script that
# happens to have been invoked with --selftest can never run these instead of
# the caller's own.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--selftest" ]; then
    set -uo pipefail
    export LC_ALL=C
    _st_fail=0
    _st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-skip-class-selftest.XXXXXX")" || {
        echo "selftest: FAIL could not mktemp" >&2; exit 1; }
    trap 'rm -rf "$_st_tmp" 2>/dev/null || true' EXIT

    _st_check() { # <name> <got> <want>
        if [ "$2" = "$3" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 -> got '$2', wanted '$3'"
            _st_fail=1
        fi
    }

    echo "stopwatch-skip-class: --selftest running hermetic checks"

    _st_check "class table parses" \
        "$(stopwatch_skip_class_table | grep -c '|')" \
        "$(grep -cE '^STOPWATCH_SKIP_(CLASS|FALLBACK)\(' "$_SW_SKIP_DEF")"

    _st_check "dead serving peer -> fixture_absent 2" \
        "$(stopwatch_skip_classify 'serving peer not reachable: 127.0.0.1:39070' 1 1)" \
        "fixture_absent 2"
    _st_check "absent binary -> config_error 1" \
        "$(stopwatch_skip_classify 'node binary absent/not executable: /nope' 1 1)" \
        "config_error 1"
    _st_check "unconfigured client rpc -> not_configured 0 (benign)" \
        "$(stopwatch_skip_classify 'no valid --client-rpc / ZCL_ND_CLIENT_RPCPORT given' 1 1)" \
        "not_configured 0"
    _st_check "no reason, no artifact -> harness_misuse 1" \
        "$(stopwatch_skip_classify '' 1 0)" "harness_misuse 1"
    _st_check "legacy row (no reason field) -> unclassified 2" \
        "$(stopwatch_skip_classify '' 0 1)" "unclassified 2"
    _st_check "unknown reason -> unclassified 2" \
        "$(stopwatch_skip_classify 'something nobody has classified yet' 1 1)" \
        "unclassified 2"

    _st_led="$_st_tmp/history.jsonl"
    _st_skip() {
        printf '{"ts":%s,"verdict":"skip","exit_code":2,"artifact_dir":"/a/x","skip_reason":"serving peer not reachable: 127.0.0.1:39070"}\n' \
            "$1" >>"$_st_led"
    }
    : >"$_st_led"
    _st_skip 1000
    _st_check "one skip: streak 1 (quiet at threshold 2)" \
        "$(stopwatch_skip_streaks "$_st_led")" "1 1 skip - 1"
    _st_skip 2000
    _st_check "two skips: streak 2 (alarm at threshold 2)" \
        "$(stopwatch_skip_streaks "$_st_led")" "2 2 skip - 2"
    printf '{"ts":3000,"verdict":"pass","exit_code":0,"artifact_dir":"/a/p"}\n' \
        >>"$_st_led"
    _st_check "a pass clears both streaks" \
        "$(stopwatch_skip_streaks "$_st_led")" "0 0 pass 3000 3"
    _st_skip 4000
    printf '{"ts":5000,"verdict":"seam","exit_code":3,"artifact_dir":"/a/s"}\n' \
        >>"$_st_led"
    _st_skip 6000
    _st_check "a seam breaks the skip streak but not no_pass" \
        "$(stopwatch_skip_streaks "$_st_led")" "1 3 skip 3000 6"
    _st_check "absent ledger reports zeros, never an error" \
        "$(stopwatch_skip_streaks "$_st_tmp/nope.jsonl")" "0 0 - - 0"

    _st_line='{"ts":1,"verdict":"skip","artifact_dir":"","skip_reason":""}'
    _st_check "row_has sees an empty-but-present field" \
        "$(stopwatch_skip_row_has "$_st_line" skip_reason && echo yes)" "yes"
    _st_check "row_has is false for an absent field" \
        "$(stopwatch_skip_row_has "$_st_line" peer_precheck || echo no)" "no"


    # ── the SECOND rung: the proof RAN and never passed ─────────────────
    _st_check "no-pass threshold parses from the shared table" \
        "$(stopwatch_no_pass_threshold)" \
        "$(sed -n 's/^STOPWATCH_NO_PASS_THRESHOLD(\([0-9][0-9]*\))[ ]*$/\1/p' "$_SW_SKIP_DEF" | head -n1)"
    _st_check "no-pass threshold is >= 1 (0 would mean mute, not benign)" \
        "$([ "$(stopwatch_no_pass_threshold)" -ge 1 ] && echo yes)" "yes"
    # An unreadable table falls back LOUD, never to silence.
    _st_check "unreadable table falls back to 4, not to 0" \
        "$(ZCL_STOPWATCH_SKIP_CLASSES_DEF=/nonexistent bash -c \
           '. tools/scripts/stopwatch_skip_class.sh; stopwatch_no_pass_threshold')" \
        "4"

    # A ledger of NON-SKIP failures — the live C3 shape: the proof ran every
    # time and never passed. Not benign, so the no-pass alarm is reachable.
    _st_led2="$_st_tmp/nopass.jsonl"
    : >"$_st_led2"
    for _st_i in 1 2 3 4; do
        printf '{"ts":%s000,"verdict":"stalled-named","exit_code":4,"artifact_dir":"/a/s","skip_reason":""}\n' \
            "$_st_i" >>"$_st_led2"
    done
    _st_check "4 stalled runs: skip_streak 0, no_pass_streak 4" \
        "$(stopwatch_skip_streaks "$_st_led2")" "0 4 stalled-named - 4"
    _st_check "a streak of stalled runs is NOT benign" \
        "$(stopwatch_no_pass_all_benign "$_st_led2")" "0"

    # A ledger of purely benign skips — the harness had nothing to prove on
    # every one of those runs, so the carve-out holds however long it runs.
    _st_led3="$_st_tmp/benign.jsonl"
    : >"$_st_led3"
    for _st_i in 1 2 3 4 5 6; do
        printf '{"ts":%s000,"verdict":"skip","exit_code":2,"artifact_dir":"/a/b","skip_reason":"no valid --client-rpc / ZCL_ND_CLIENT_RPCPORT given"}\n' \
            "$_st_i" >>"$_st_led3"
    done
    _st_check "a streak of purely benign skips IS benign" \
        "$(stopwatch_no_pass_all_benign "$_st_led3")" "1"
    # ONE non-benign row ends the carve-out — it must never mute a real fault.
    printf '{"ts":7000,"verdict":"fail","exit_code":1,"artifact_dir":"/a/f"}\n' \
        >>"$_st_led3"
    _st_check "one fail in the streak ends the benign carve-out" \
        "$(stopwatch_no_pass_all_benign "$_st_led3")" "0"
    # A pass ends the streak, so there is nothing left to excuse.
    printf '{"ts":8000,"verdict":"pass","exit_code":0,"artifact_dir":"/a/p"}\n' \
        >>"$_st_led3"
    _st_check "after a pass the streak is empty, so not benign either" \
        "$(stopwatch_no_pass_all_benign "$_st_led3")" "0"
    _st_check "an absent ledger has no benign streak" \
        "$(stopwatch_no_pass_all_benign "$_st_tmp/nope.jsonl")" "0"

    if [ "$_st_fail" = 0 ]; then
        echo "selftest: PASS"
        exit 0
    fi
    echo "selftest: FAIL" >&2
    exit 1
fi
