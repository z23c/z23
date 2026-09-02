#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# verdict.sh — `make verdict`. One screen of truth after a gate run.
#
# WHY THIS EXISTS. Several agents run `make lint` / `make t-fast` many times
# an hour, on several machines, and then re-derive "did it pass, and what
# broke" by scrolling a 170-second terminal log or re-running the gate just to
# see the tail again. Both cost more than the gate itself. This script reads
# ONLY the receipts the gate/test drivers already wrote — it builds nothing,
# runs no gate, and never re-executes a check — and prints at most 40 lines:
# tree identity, the last lint run, the last test run, and one VERDICT line.
#
# SOURCES (all machine-written, all gitignored, read-only):
#   .cache/lint-timing/last-run.json           tools/lint/run_lint.sh
#   .cache/lint-timing/gates/run.<pid>/<gate>.log   same driver, per-gate
#                                               captured output (kept for the
#                                               most recent run at least; see
#                                               the 120-minute prune in
#                                               run_lint.sh). The NEWEST
#                                               run.* directory by mtime is
#                                               assumed to belong to the
#                                               last-run.json this read; there
#                                               is no stronger link recorded
#                                               (see the honesty note below).
#   .cache/test-timing/last-run.json           tests/harness/src/test_parallel.c
#                                               write_test_timing_json()
#
# HONESTY, modeled on tools/scripts/timings.sh:
#   MISSING   a receipt file is absent. Exit 2, name exactly which one and the
#             command that produces it. Never a borrowed or invented number.
#   STALE     the receipt predates HEAD's own commit time — the code moved
#             after the measurement. Neither JSON artifact records a content
#             hash of the tree it scanned (lint's has no such field; the test
#             runner's "toolkey" is a compiler/tool digest, not a source id),
#             so staleness is read from mtime against HEAD, exactly as
#             `make timings` already does — not invented fresh here.
#   DIRTY     the working tree carries uncommitted changes right now. This is
#             independent of STALE: a receipt can be fresh against HEAD and
#             still describe a tree that has since been edited again.
#   TRUNCATED failed-item lists longer than the per-section cap are counted,
#             not silently dropped — the cap line says how many more.
#
# Exit codes: 0 green, 1 red or stale (see the VERDICT line for gate/group
# counts; a stale receipt is never reported green — the code moved after it),
# 2 a receipt is missing (see which, on stderr and in the VERDICT line).
#
# Read-only: writes nothing, runs no gate, never fails a build.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${ZCL_VERDICT_CACHE:-$ROOT/.cache}"
LINT_JSON="$CACHE/lint-timing/last-run.json"
TEST_JSON="$CACHE/test-timing/last-run.json"
LINT_GATES_ROOT="$CACHE/lint-timing/gates"

MAX_TOTAL_LINES=40
FAIL_CAP=15   # per section: at most this many named failures before "+N more"

# --- tiny JSON field readers (no external deps — grep/sed only; the writers
# are machine-made, fixed-format printf, so a narrow reader is sound) --------
jnum() { grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9]\+" "$1" 2>/dev/null | head -1 |
         grep -o '[0-9]\+$'; }
jstr() { grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 |
         sed 's/.*:[[:space:]]*"//; s/"$//'; }
# Names of entries whose "rc" field is present and non-zero. Works for both
# the lint gate array ({"name":...,"ms":...,"rc":...}) and the test group
# array ({"name":...,"ms":...,"rc":...,"signaled":...,"cached":...}) because
# both print one object per line and this only reads through the rc field.
jfailed_names() {
    grep -oE '"name":"[^"]*","ms":[0-9]+,"rc":-?[0-9]+' "$1" 2>/dev/null |
    while IFS= read -r row; do
        local name rc
        name="$(sed -E 's/^"name":"([^"]*)".*/\1/' <<<"$row")"
        rc="$(sed -E 's/.*"rc":(-?[0-9]+)$/\1/' <<<"$row")"
        [ "$rc" != "0" ] && printf '%s\n' "$name"
    done
}

rel() { printf '%s' "${1#"$ROOT"/}"; }

# --- git identity (read-only; GIT_OPTIONAL_LOCKS=0 so this never contends
# for the index lock a concurrent build/gate might hold) ---------------------
git_ro() { GIT_OPTIONAL_LOCKS=0 git -C "$ROOT" "$@" 2>/dev/null; }

head_epoch="$(git_ro log -1 --format=%ct || echo 0)"
head_sha="$(git_ro rev-parse --short=10 HEAD || echo unknown)"
branch="$(git_ro rev-parse --abbrev-ref HEAD || echo unknown)"
dirty_n="$(git_ro status --porcelain | grep -c . || true)"
[ -n "$dirty_n" ] || dirty_n=0

# Age/staleness for one receipt file: prints "STATE age=<human>" on stdout.
receipt_state() {
    local f="$1" mtime now age state age_h
    mtime="$(date -r "$f" +%s 2>/dev/null || echo 0)"
    now="$(date +%s)"
    age=$(( now - mtime ))
    [ "$age" -ge 0 ] || age=0
    if [ "$age" -ge 3600 ]; then age_h="$((age / 3600))h$(((age % 3600) / 60))m"
    elif [ "$age" -ge 60 ]; then age_h="$((age / 60))m$((age % 60))s"
    else age_h="${age}s"; fi
    if [ "$head_epoch" -gt 0 ] && [ "$mtime" -lt "$head_epoch" ]; then
        state=STALE
    else
        state=FRESH
    fi
    printf '%s age=%s' "$state" "$age_h"
}

# Newest lint gate-log directory — best-effort link from last-run.json to the
# per-gate .log files run_lint.sh wrote alongside it (no stronger link is
# recorded on disk; see the header note).
lint_gates_dir() {
    local d
    [ -d "$LINT_GATES_ROOT" ] || return 1
    d="$(ls -1dt "$LINT_GATES_ROOT"/run.* 2>/dev/null | head -1)"
    [ -n "$d" ] || return 1
    printf '%s\n' "$d"
}

# First non-empty line of a failed lint gate's captured output, or a concrete
# reproduction command when nothing was captured (a gate that fails silently
# is itself a defect — see run_lint.sh's own FAIL-log handling — but this
# reader still owes the caller something actionable).
lint_fix_hint() {
    local name="$1" gdir line script
    gdir="$(lint_gates_dir 2>/dev/null || true)"
    if [ -n "$gdir" ] && [ -s "$gdir/$name.log" ]; then
        # Many gates run their own --selftest first and log its "PASS" banner
        # ahead of the real failure detail. Skip PASS-bearing lines first, so
        # a red gate's own self-test success does not stand in as the hint;
        # fall back to the true first line if every line happens to say PASS.
        line="$(grep -v '^[[:space:]]*$' "$gdir/$name.log" 2>/dev/null |
                grep -vi 'PASS' | head -1)"
        [ -n "${line:-}" ] ||
            line="$(grep -v '^[[:space:]]*$' "$gdir/$name.log" 2>/dev/null | head -1)"
    fi
    if [ -z "${line:-}" ]; then
        script="tools/lint/check_${name#check-}"
        script="${script//-/_}"
        printf '(no captured output — reproduce: %s)' "$script.sh"
        return
    fi
    # Keep this a single terminal line.
    line="${line//$'\n'/ }"
    if [ "${#line}" -gt 140 ]; then line="${line:0:137}..."; fi
    printf '%s' "$line"
}

# --------------------------------------------------------------------------
run_selftest() {
    local self="${BASH_SOURCE[0]}" tmp out rc failures=0 tests=0
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-verdict.XXXXXX")"
    trap 'rm -rf "${tmp:-}"' EXIT HUP INT TERM

    check() {
        local label="$1" want_rc="$2" needle="$3"
        tests=$((tests + 1))
        if [ "$rc" -ne "$want_rc" ] || { [ -n "$needle" ] && [[ "$out" != *"$needle"* ]]; }; then
            printf 'verdict selftest: FAIL — %s (rc=%s, want %s; needle=%q)\n' \
                "$label" "$rc" "$want_rc" "$needle" >&2
            printf '%s\n' "$out" >&2
            failures=$((failures + 1))
        fi
    }

    # (1) Both receipts absent -> MISSING, exit 2, names both.
    mkdir -p "$tmp/empty"
    out="$(ZCL_VERDICT_CACHE="$tmp/empty" bash "$self" 2>&1)"; rc=$?
    check "absent receipts exit 2" 2 "MISSING RECEIPT"
    check "absent receipts name lint" 2 "lint,tests"

    # (2) Both green -> GREEN, exit 0.
    mkdir -p "$tmp/green/lint-timing" "$tmp/green/test-timing"
    cat > "$tmp/green/lint-timing/last-run.json" <<'JSON'
{"schema":"zcl.lint_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"gate_count":1,"failed_count":0,"gates":[{"name":"check-a","ms":1,"rc":0}]}
JSON
    cat > "$tmp/green/test-timing/last-run.json" <<'JSON'
{"schema":"zcl.test_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"group_count":1,"failed_count":0,"skipped_count":0,"mode":"cold","groups_ran":1,"groups_cached":0,"groups":[{"name":"g1","ms":1,"rc":0,"signaled":false,"cached":false}]}
JSON
    touch -d '2099-01-01' "$tmp/green/lint-timing/last-run.json" "$tmp/green/test-timing/last-run.json"
    out="$(ZCL_VERDICT_CACHE="$tmp/green" bash "$self" 2>&1)"; rc=$?
    check "all-pass exits 0" 0 "VERDICT: GREEN"

    # (3) A failed gate (with a captured log) and a signaled (negative rc)
    #     failed group -> RED, exit 1, names both, quotes the log's first line.
    mkdir -p "$tmp/red/lint-timing/gates/run.1" "$tmp/red/test-timing"
    cat > "$tmp/red/lint-timing/last-run.json" <<'JSON'
{"schema":"zcl.lint_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"gate_count":1,"failed_count":1,"gates":[{"name":"check-bad","ms":1,"rc":1}]}
JSON
    printf 'FAIL: planted fixture violation\n' > "$tmp/red/lint-timing/gates/run.1/check-bad.log"
    cat > "$tmp/red/test-timing/last-run.json" <<'JSON'
{"schema":"zcl.test_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"group_count":1,"failed_count":1,"skipped_count":0,"mode":"cold","groups_ran":1,"groups_cached":0,"groups":[{"name":"g_bad","ms":1,"rc":-11,"signaled":true,"cached":false}]}
JSON
    touch -d '2099-01-01' "$tmp/red/lint-timing/last-run.json" "$tmp/red/test-timing/last-run.json"
    out="$(ZCL_VERDICT_CACHE="$tmp/red" bash "$self" 2>&1)"; rc=$?
    check "a failure exits 1" 1 "VERDICT: RED"
    check "failed gate named with its log's first line" 1 "check-bad: FAIL: planted fixture violation"
    check "signaled (negative rc) group counted as failed" 1 "g_bad"

    # (4) A receipt older than HEAD's own commit reads STALE, not FRESH.
    mkdir -p "$tmp/stale/lint-timing" "$tmp/stale/test-timing"
    cat > "$tmp/stale/lint-timing/last-run.json" <<'JSON'
{"schema":"zcl.lint_timing.v1","generated_at_utc":"2000-01-01T00:00:00Z","wall_ms":1,"jobs":1,"gate_count":1,"failed_count":0,"gates":[{"name":"check-a","ms":1,"rc":0}]}
JSON
    cat > "$tmp/stale/test-timing/last-run.json" <<'JSON'
{"schema":"zcl.test_timing.v1","generated_at_utc":"2000-01-01T00:00:00Z","wall_ms":1,"jobs":1,"group_count":0,"failed_count":0,"skipped_count":0,"mode":"cold","groups_ran":0,"groups_cached":0,"groups":[]}
JSON
    touch -d '2000-01-01 00:00:00' "$tmp/stale/lint-timing/last-run.json" "$tmp/stale/test-timing/last-run.json"
    out="$(ZCL_VERDICT_CACHE="$tmp/stale" bash "$self" 2>&1)"; rc=$?
    check "pre-HEAD receipt reads STALE" 1 "STALE"

    # (5) More failed gates than FAIL_CAP -> truncated with a "more" count,
    #     and the whole report still fits the 40-line budget.
    mkdir -p "$tmp/many/lint-timing" "$tmp/many/test-timing"
    {
        printf '{"schema":"zcl.lint_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"gate_count":20,"failed_count":20,"gates":[\n'
        for i in $(seq 1 20); do
            [ "$i" -gt 1 ] && printf ',\n'
            printf '{"name":"check-many-%02d","ms":1,"rc":1}' "$i"
        done
        printf '\n]}\n'
    } > "$tmp/many/lint-timing/last-run.json"
    cat > "$tmp/many/test-timing/last-run.json" <<'JSON'
{"schema":"zcl.test_timing.v1","generated_at_utc":"2099-01-01T00:00:00Z","wall_ms":1,"jobs":1,"group_count":0,"failed_count":0,"skipped_count":0,"mode":"cold","groups_ran":0,"groups_cached":0,"groups":[]}
JSON
    touch -d '2099-01-01' "$tmp/many/lint-timing/last-run.json" "$tmp/many/test-timing/last-run.json"
    out="$(ZCL_VERDICT_CACHE="$tmp/many" bash "$self" 2>&1)"; rc=$?
    check "a long failure list is truncated with a count" 1 "more failed gate(s)"
    lc="$(printf '%s\n' "$out" | wc -l)"
    if [ "$lc" -gt "$MAX_TOTAL_LINES" ]; then
        printf 'verdict selftest: FAIL — 20-failure report printed %s lines, budget is %s\n' \
            "$lc" "$MAX_TOTAL_LINES" >&2
        failures=$((failures + 1))
    fi

    if [ "$failures" -ne 0 ]; then
        printf 'verdict: self-test FAIL (%s/%s)\n' "$failures" "$tests" >&2
        return 1
    fi
    printf 'verdict: self-test PASS (%s/%s)\n' "$tests" "$tests"
}

if [ "${1:-}" = "--self-test" ]; then
    run_selftest
    exit $?
fi

lines_used=0
emit() { printf '%s\n' "$1"; lines_used=$((lines_used + 1)); }

missing=()
lint_failed_n=0
test_failed_n=0

emit "══ verdict: $branch @ $head_sha (${dirty_n} dirty file(s)) ══"

# ---- lint section ----------------------------------------------------------
if [ ! -f "$LINT_JSON" ]; then
    emit "lint   MISSING RECEIPT — no $(rel "$LINT_JSON"). Run: make lint"
    missing+=("lint")
else
    lint_state="$(receipt_state "$LINT_JSON")"
    lint_wall="$(jnum "$LINT_JSON" wall_ms)"
    lint_n="$(jnum "$LINT_JSON" gate_count)"
    lint_failed_n="$(jnum "$LINT_JSON" failed_count)"
    lint_stamp="$(jstr "$LINT_JSON" generated_at_utc)"
    [ -n "${lint_failed_n:-}" ] || lint_failed_n=0
    emit "lint   $lint_state  ${lint_n:-?} gates, ${lint_failed_n} failed, wall ${lint_wall:-?} ms   [${lint_stamp:-no timestamp}]"
    if [ "$lint_failed_n" -gt 0 ]; then
        shown=0
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            shown=$((shown + 1))
            if [ "$shown" -gt "$FAIL_CAP" ]; then
                emit "  … and $((lint_failed_n - FAIL_CAP)) more failed gate(s) — full list: $(rel "$LINT_JSON")"
                break
            fi
            emit "  ✗ $name: $(lint_fix_hint "$name")"
        done < <(jfailed_names "$LINT_JSON")
    fi
fi

# ---- test section -----------------------------------------------------------
if [ ! -f "$TEST_JSON" ]; then
    emit "tests  MISSING RECEIPT — no $(rel "$TEST_JSON"). Run: make t-fast ONLY=<group>  (or make test-parallel)"
    missing+=("tests")
else
    test_state="$(receipt_state "$TEST_JSON")"
    test_wall="$(jnum "$TEST_JSON" wall_ms)"
    test_n="$(jnum "$TEST_JSON" group_count)"
    test_failed_n="$(jnum "$TEST_JSON" failed_count)"
    test_ran="$(jnum "$TEST_JSON" groups_ran)"
    test_cached="$(jnum "$TEST_JSON" groups_cached)"
    test_stamp="$(jstr "$TEST_JSON" generated_at_utc)"
    test_mode="$(jstr "$TEST_JSON" mode)"
    [ -n "${test_failed_n:-}" ] || test_failed_n=0
    emit "tests  $test_state  ${test_n:-?} group(s) (${test_ran:-?} ran, ${test_cached:-0} cached, mode=${test_mode:-?}), ${test_failed_n} failed, wall ${test_wall:-?} ms   [${test_stamp:-no timestamp}]"
    if [ "$test_failed_n" -gt 0 ]; then
        shown=0
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            shown=$((shown + 1))
            if [ "$shown" -gt "$FAIL_CAP" ]; then
                emit "  … and $((test_failed_n - FAIL_CAP)) more failed group(s) — full list: $(rel "$TEST_JSON")"
                break
            fi
            emit "  ✗ $name"
        done < <(jfailed_names "$TEST_JSON")
    fi
fi

# ---- final verdict line -----------------------------------------------------
if [ "${#missing[@]}" -gt 0 ]; then
    emit "VERDICT: MISSING RECEIPT(S): $(IFS=,; echo "${missing[*]}")"
    exit 2
fi
if [ "$lint_failed_n" -eq 0 ] && [ "$test_failed_n" -eq 0 ]; then
    if [[ "$lint_state" == STALE* || "$test_state" == STALE* ]]; then
        emit "VERDICT: STALE — the code moved after the last measurement; re-run make lint-fast and the mapped tests, then make verdict"
        exit 1
    fi
    emit "VERDICT: GREEN (${lint_n:-0} gates, ${test_n:-0} groups)"
    exit 0
fi
emit "VERDICT: RED ($lint_failed_n gates, $test_failed_n groups)"
exit 1
