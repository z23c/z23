#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# public_explorer_smoke.sh — external smoke checks for the public explorer,
# and the ONLY availability evidence on this host that is genuinely
# external.
#
# Purpose (unchanged): catch regressions where the public HODL page/API
# tells users to refresh, wait, or retry instead of serving the best
# available projection.
#
# WHY IT NOW WRITES A LEDGER
# --------------------------
# The uptime ledger's `reachable` column is a LOOPBACK RPC dial from the
# same host as the node (tools/scripts/node_slo_probe.sh). That measures
# "the process is answering", not "a user can reach the service". Every
# failure mode between the node and a user — the port forward, TLS, the
# certificate expiring, the machine's route to the internet, DNS — is
# invisible to it, and by construction always will be.
#
# This script already dialled the real public endpoint over the real
# internet path. It was wired to no timer and wrote no ledger, so its
# result existed only in whichever terminal happened to run it. It now
# appends one JSON line per run to
# ~/.local/state/zclassic23-public-smoke/availability-ledger.jsonl:
#   ts, base, reachable, unreachable_streak, api_ok, html_ok,
#   http_status_api, http_status_html, latency_ms_api, latency_ms_html,
#   served_height, older_than_1y_percent, fail_stage, error_detail
#
# Same doctrine as the uptime ledger, deliberately: a FAILED check is not a
# script failure, it IS the data point, so the ledger line is written on
# every path including every failure. The exit status is unchanged (0 pass,
# 1 fail) so existing callers keep working — but the record no longer
# depends on anybody watching the output.
#
# `unreachable_streak` lives in a separate streak/ directory rather than
# being derived from the ledger tail, for the same reason it does in the
# uptime ledger: a rotation must not reset a long outage to "just went
# down" at exactly the moment that distinction matters most.
#
# Usage:
#   public_explorer_smoke.sh              one check, appends one line
#   public_explorer_smoke.sh --selftest   hermetic; fixture fetches
#
# Env:
#   ZCL_PUBLIC_BASE              endpoint (default https://zclnet.net)
#   ZCL_PUBLIC_SMOKE_LEDGER_DIR  ledger dir
#   ZCL_PUBLIC_SMOKE_ROTATE_BYTES rotation threshold (default 50 MiB)
#   ZCL_PUBLIC_SMOKE_BLIND_STREAK consecutive misses at which the run
#                                reports BLIND (default 5)
#   ZCL_PUBLIC_SMOKE_FETCH_CMD   override the fetch; run with URL and OUT
#                                exported, must print the HTTP status on
#                                stdout (selftest injection seam)

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

EVIDENCE_LIB="$SCRIPT_DIR/lib/evidence_sources.sh"
if [ ! -r "$EVIDENCE_LIB" ]; then
    echo "public-explorer-smoke: FATAL missing reader library $EVIDENCE_LIB" >&2
    exit 3
fi
# shellcheck source=lib/evidence_sources.sh
. "$EVIDENCE_LIB"

base="${ZCL_PUBLIC_BASE:-https://zclnet.net}"
LEDGER_DIR="${ZCL_PUBLIC_SMOKE_LEDGER_DIR:-${HOME:-/root}/.local/state/zclassic23-public-smoke}"
LEDGER_FILE="$LEDGER_DIR/availability-ledger.jsonl"
STREAK_DIR="$LEDGER_DIR/streak"
ROTATE_BYTES="${ZCL_PUBLIC_SMOKE_ROTATE_BYTES:-52428800}"
BLIND_STREAK="${ZCL_PUBLIC_SMOKE_BLIND_STREAK:-5}"

# ── ledger plumbing (same shapes as node_slo_probe.sh) ─────────────────

rotate_ledger_if_needed() {
    [ -f "$LEDGER_FILE" ] || return 0
    local size
    size="$(stat -c %s "$LEDGER_FILE" 2>/dev/null || echo 0)"
    case "$size" in '' | *[!0-9]*) size=0 ;; esac
    if [ "$size" -ge "$ROTATE_BYTES" ]; then
        [ -f "$LEDGER_FILE.2" ] && rm -f "$LEDGER_FILE.2"
        [ -f "$LEDGER_FILE.1" ] && mv "$LEDGER_FILE.1" "$LEDGER_FILE.2"
        mv "$LEDGER_FILE" "$LEDGER_FILE.1"
        echo "public-explorer-smoke: rotated ledger (size=$size >= $ROTATE_BYTES)" >&2
    fi
}

streak_read() {
    local f="$STREAK_DIR/$1" v=""
    [ -f "$f" ] && v="$(cat "$f" 2>/dev/null || true)"
    case "$v" in '' | *[!0-9]*) v=0 ;; esac
    printf '%s' "$v"
}

streak_write() {
    mkdir -p "$STREAK_DIR" 2>/dev/null || return 0
    local f="$STREAK_DIR/$1"
    printf '%s\n' "$2" > "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f" 2>/dev/null
    return 0
}

# streak_key: one counter per endpoint, so pointing the script at a staging
# base cannot silently reset the production outage counter.
streak_key() { printf '%s' "$base" | tr -c 'a-zA-Z0-9' '_'; }

# ── fetch ──────────────────────────────────────────────────────────────

FAIL_STAGE=""
ERROR_DETAIL=""

# fetch <url> <out>: writes the body to <out>, prints
# "<http_status>\x1f<latency_ms>". Returns non-zero on transport failure.
# Never aborts the script — the caller decides, because a failed fetch must
# still produce a ledger line.
fetch() {
    local url="$1" out="$2" t0 t1 status rc=0
    t0="$(date +%s%N)"
    if [ -n "${ZCL_PUBLIC_SMOKE_FETCH_CMD:-}" ]; then
        status="$(URL="$url" OUT="$out" bash -c "$ZCL_PUBLIC_SMOKE_FETCH_CMD" 2>/dev/null)" || rc=$?
    else
        status="$(curl -kfsS --connect-timeout 8 --max-time 20 \
            -w '%{http_code}' "$url" -o "$out" 2>/dev/null)" || rc=$?
    fi
    t1="$(date +%s%N)"
    case "${status:-}" in '' | *[!0-9]*) status="" ;; esac
    printf '%s\x1f%s' "$status" "$(( (t1 - t0) / 1000000 ))"
    return "$rc"
}

f1() { printf '%s' "$1" | cut -d $'\x1f' -f1; }
f2() { printf '%s' "$1" | cut -d $'\x1f' -f2; }

note_fail() {
    [ -n "$FAIL_STAGE" ] && return 0   # keep the FIRST failure, the causal one
    FAIL_STAGE="$1"; ERROR_DETAIL="$2"
    return 0
}

# ── the check ──────────────────────────────────────────────────────────

cmd_check() {
    mkdir -p "$LEDGER_DIR"
    rotate_ledger_if_needed

    # Global, not `local`: an EXIT trap runs after the function's locals
    # are gone, and under `set -u` a trap referencing a dead local turns a
    # successful check into a non-zero exit at the very last instant.
    TMPDIR_SMOKE="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR_SMOKE"' EXIT
    local tmpdir="$TMPDIR_SMOKE"

    local ts; ts="$(date +%s)"
    local api="$tmpdir/hodl.json" html="$tmpdir/hodl.html"
    local api_ok="false" html_ok="false"
    local r_api r_html
    local status_api="" status_html="" lat_api="" lat_html=""

    r_api="$(fetch "$base/api/v1/hodl" "$api")" ||
        note_fail "fetch_api" "fetch failed: $base/api/v1/hodl"
    status_api="$(f1 "$r_api")"; lat_api="$(f2 "$r_api")"

    r_html="$(fetch "$base/explorer/hodl" "$html")" ||
        note_fail "fetch_html" "fetch failed: $base/explorer/hodl"
    status_html="$(f1 "$r_html")"; lat_html="$(f2 "$r_html")"

    # `reachable` is transport only: both documents came back. Whether the
    # CONTENT is acceptable is a separate axis, because "the site is up but
    # telling users to retry" and "the site is down" need different
    # responses and a single boolean conflates them.
    local reachable="false"
    [ -s "$api" ] && [ -s "$html" ] && reachable="true"

    if [ -s "$api" ]; then
        api_ok="true"
        grep -q '"schema":"zcl.hodl_wave.v1"' "$api" ||
            { api_ok="false"; note_fail "api_schema" "HODL API schema marker missing"; }
        grep -q '"status":"ok"' "$api" ||
            { api_ok="false"; note_fail "api_status" "HODL API status is not ok"; }
        grep -q '"blocker":"none"' "$api" ||
            { api_ok="false"; note_fail "api_blocker" "HODL API reports a blocker"; }
        grep -q '"fresh":true' "$api" ||
            { api_ok="false"; note_fail "api_stale" "HODL API is not fresh"; }
        if grep -Eiq 'refresh in a minute|not processed|please retry|try again|waiting|temporarily unavailable' "$api"; then
            api_ok="false"; note_fail "api_wait_marker" "HODL API contains a wait/retry marker"
        fi
    fi

    if [ -s "$html" ]; then
        html_ok="true"
        if grep -Eiq 'refresh in a minute|not processed|please retry|try again|waiting|temporarily unavailable' "$html"; then
            html_ok="false"; note_fail "html_wait_marker" "HODL page contains a wait/retry marker"
        fi
    fi

    # `|| true` is load-bearing, not defensive noise: when the fetch failed
    # there is no file, sed exits non-zero, and `set -e -o pipefail` would
    # abort the run one line before the ledger append — which is precisely
    # the old bug (an outage leaving no trace) reintroduced in a new place.
    local height="" percent=""
    if [ -s "$api" ]; then
        height="$(sed -n 's/.*"served_height":\([0-9][0-9]*\).*/\1/p' "$api" 2>/dev/null | head -n1 || true)"
        percent="$(sed -n 's/.*"older_than_1y":{"value":[0-9][0-9.]*,"percent":\([0-9][0-9.]*\)},"skipped_rows".*/\1/p' "$api" 2>/dev/null | head -n1 || true)"
    fi

    local key; key="$(streak_key)"
    local streak; streak="$(streak_read "$key")"
    if [ "$reachable" = "true" ]; then streak=0; else streak=$((streak + 1)); fi
    streak_write "$key" "$streak"

    # percent is a decimal, so it goes through jstr rather than jnum —
    # emitting it as a bare token would produce an invalid line the first
    # time the API returns something unexpected there.
    local line
    line="$(printf '{"ts":%s,"base":%s,"reachable":%s,"unreachable_streak":%s,"api_ok":%s,"html_ok":%s,"http_status_api":%s,"http_status_html":%s,"latency_ms_api":%s,"latency_ms_html":%s,"served_height":%s,"older_than_1y_percent":%s,"fail_stage":%s,"error_detail":%s}' \
        "$ts" "$(evidence_jstr "$base")" "$reachable" "$streak" \
        "$api_ok" "$html_ok" \
        "$(evidence_jnum "$status_api")" "$(evidence_jnum "$status_html")" \
        "$(evidence_jnum "$lat_api")" "$(evidence_jnum "$lat_html")" \
        "$(evidence_jnum "$height")" "$(evidence_jstr "$percent")" \
        "$(evidence_jstr "$FAIL_STAGE")" "$(evidence_jstr "$ERROR_DETAIL")")"
    evidence_append_line "$LEDGER_FILE" "$line" "public-explorer-smoke" || return 1
    echo "$line" >&2

    if [ -n "$FAIL_STAGE" ]; then
        if [ "$streak" -ge "$BLIND_STREAK" ]; then
            echo "public-explorer-smoke: BLIND base=$base unreachable for $streak consecutive checks (threshold $BLIND_STREAK)" >&2
        fi
        echo "public-explorer-smoke: FAIL: $ERROR_DETAIL (stage=$FAIL_STAGE)" >&2
        return 1
    fi

    echo "public-explorer-smoke: PASS base=$base served_height=${height:-unknown} older_than_1y_percent=${percent:-unknown}"
    return 0
}

# ── selftest ───────────────────────────────────────────────────────────

st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

cmd_selftest() {
    ST_TMP="$(mktemp -d /tmp/zcl-public-smoke-selftest.XXXXXX)"
    trap 'rm -rf "$ST_TMP"' EXIT

    local good='{"schema":"zcl.hodl_wave.v1","status":"ok","blocker":"none","fresh":true,"served_height":3197857,"older_than_1y":{"value":1.0,"percent":61.5},"skipped_rows":0}'

    # A) healthy endpoint: PASS, exit 0, and one ledger line carrying the
    #    height, the percent, and both latencies.
    printf '%s' "$good" > "$ST_TMP/good.json"
    printf '<html>fine</html>' > "$ST_TMP/good.html"
    (
        export ZCL_PUBLIC_SMOKE_LEDGER_DIR="$ST_TMP/a"
        export ZCL_PUBLIC_BASE="https://example.invalid"
        export ZCL_PUBLIC_SMOKE_FETCH_CMD="case \"\$URL\" in *api*) cp '$ST_TMP/good.json' \"\$OUT\";; *) cp '$ST_TMP/good.html' \"\$OUT\";; esac; echo 200"
        bash "$SELF" >/dev/null 2>&1
    ) || st_fail "case=healthy must exit 0"
    local f="$ST_TMP/a/availability-ledger.jsonl"
    [ "$(wc -l < "$f")" -eq 1 ] || { cat "$f" >&2; st_fail "case=healthy expected exactly 1 ledger line"; }
    grep -q '"reachable":true,"unreachable_streak":0,"api_ok":true,"html_ok":true' "$f" \
        || { cat "$f" >&2; st_fail "case=healthy wrong shape"; }
    grep -q '"http_status_api":200,"http_status_html":200' "$f" \
        || { cat "$f" >&2; st_fail "case=healthy http status not recorded"; }
    grep -q '"served_height":3197857,"older_than_1y_percent":"61.5"' "$f" \
        || { cat "$f" >&2; st_fail "case=healthy height/percent not recorded"; }
    grep -q '"fail_stage":"","error_detail":""' "$f" \
        || { cat "$f" >&2; st_fail "case=healthy must record no failure"; }
    echo "selftest: ok case=healthy"

    # B) THE point of the whole change: a FAILED external check still
    #    writes its line. The old script exited before recording anything,
    #    so an outage left no trace unless a human was watching stdout.
    (
        export ZCL_PUBLIC_SMOKE_LEDGER_DIR="$ST_TMP/b"
        export ZCL_PUBLIC_BASE="https://example.invalid"
        export ZCL_PUBLIC_SMOKE_FETCH_CMD="exit 7"
        bash "$SELF" >/dev/null 2>&1
    ) && st_fail "case=unreachable must exit non-zero"
    f="$ST_TMP/b/availability-ledger.jsonl"
    [ -s "$f" ] || st_fail "case=unreachable an outage MUST still be recorded"
    grep -q '"reachable":false,"unreachable_streak":1,"api_ok":false,"html_ok":false' "$f" \
        || { cat "$f" >&2; st_fail "case=unreachable wrong shape"; }
    grep -q '"fail_stage":"fetch_api"' "$f" \
        || { cat "$f" >&2; st_fail "case=unreachable must name the failing stage"; }
    grep -q '"served_height":null' "$f" \
        || { cat "$f" >&2; st_fail "case=unreachable must not fabricate a height"; }
    echo "selftest: ok case=outage-is-recorded"

    # C) reachable but SERVING A WAIT MARKER — the regression this script
    #    was written for. reachable:true, api_ok:false, named stage. One
    #    boolean could not express this, which is why there are three.
    printf '{"schema":"zcl.hodl_wave.v1","status":"ok","blocker":"none","fresh":true,"served_height":10,"note":"please retry"}' > "$ST_TMP/wait.json"
    (
        export ZCL_PUBLIC_SMOKE_LEDGER_DIR="$ST_TMP/c"
        export ZCL_PUBLIC_BASE="https://example.invalid"
        export ZCL_PUBLIC_SMOKE_FETCH_CMD="case \"\$URL\" in *api*) cp '$ST_TMP/wait.json' \"\$OUT\";; *) cp '$ST_TMP/good.html' \"\$OUT\";; esac; echo 200"
        bash "$SELF" >/dev/null 2>&1
    ) && st_fail "case=wait-marker must exit non-zero"
    f="$ST_TMP/c/availability-ledger.jsonl"
    grep -q '"reachable":true,"unreachable_streak":0,"api_ok":false,"html_ok":true' "$f" \
        || { cat "$f" >&2; st_fail "case=wait-marker up-but-degraded must be distinguishable from down"; }
    grep -q '"fail_stage":"api_wait_marker"' "$f" \
        || { cat "$f" >&2; st_fail "case=wait-marker stage not named"; }
    echo "selftest: ok case=up-but-degraded"

    # D) the streak climbs across runs and survives a ROTATION, then snaps
    #    back to 0 on recovery. Same guarantee the uptime ledger makes, for
    #    the same reason: the moment the file rolls is exactly when a long
    #    outage most needs to still look long.
    local envd=(
        "ZCL_PUBLIC_SMOKE_LEDGER_DIR=$ST_TMP/d"
        "ZCL_PUBLIC_BASE=https://example.invalid"
        "ZCL_PUBLIC_SMOKE_ROTATE_BYTES=200"
    )
    local i
    for i in 1 2 3; do
        env "${envd[@]}" ZCL_PUBLIC_SMOKE_FETCH_CMD="exit 7" bash "$SELF" >/dev/null 2>&1 || true
    done
    f="$ST_TMP/d/availability-ledger.jsonl"
    [ -f "$f.1" ] || st_fail "case=streak-survives-rotation expected a rotation to have happened"
    env "${envd[@]}" ZCL_PUBLIC_SMOKE_FETCH_CMD="exit 7" bash "$SELF" >/dev/null 2>&1 || true
    grep -q '"unreachable_streak":4' "$f" "$f.1" \
        || { cat "$f" "$f.1" >&2; st_fail "case=streak-survives-rotation streak must keep climbing across a rotation"; }
    (
        export ZCL_PUBLIC_SMOKE_LEDGER_DIR="$ST_TMP/d"
        export ZCL_PUBLIC_BASE="https://example.invalid"
        export ZCL_PUBLIC_SMOKE_FETCH_CMD="case \"\$URL\" in *api*) cp '$ST_TMP/good.json' \"\$OUT\";; *) cp '$ST_TMP/good.html' \"\$OUT\";; esac; echo 200"
        bash "$SELF" >/dev/null 2>&1
    ) || st_fail "case=streak-survives-rotation recovery must exit 0"
    grep -q '"unreachable_streak":0' <<<"$(tail -n1 "$f")" \
        || { tail -n1 "$f" >&2; st_fail "case=streak-survives-rotation recovery must reset the streak"; }
    echo "selftest: ok case=streak-survives-rotation"

    # E) a different base gets its OWN streak counter — pointing the script
    #    at staging must not launder a production outage.
    env "ZCL_PUBLIC_SMOKE_LEDGER_DIR=$ST_TMP/d" "ZCL_PUBLIC_BASE=https://other.invalid" \
        ZCL_PUBLIC_SMOKE_FETCH_CMD="exit 7" bash "$SELF" >/dev/null 2>&1 || true
    grep -q '"base":"https://other.invalid","reachable":false,"unreachable_streak":1' <<<"$(tail -n1 "$f")" \
        || { tail -n1 "$f" >&2; st_fail "case=per-base-streak a second endpoint must not inherit the first's streak"; }
    echo "selftest: ok case=per-base-streak"

    echo "selftest: PASS"
}

case "${1:-check}" in
    check)      cmd_check ;;
    --selftest) shift; cmd_selftest "$@" ;;
    *)
        echo "usage: public_explorer_smoke.sh [check] | --selftest" >&2
        exit 2
        ;;
esac
