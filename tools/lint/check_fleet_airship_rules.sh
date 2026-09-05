#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fleet_airship_rules.sh — no fleet node is ever paid for a fact it
# reported about itself (HARD).
#
# engine/composition/fleet_airship_rules.def maps a fact about a fleet node to
# the in-game assets it earns. `fleet.roster` derives its `airships` object
# from those rows. A row that pays out for a self-reported number pays whoever
# types the largest one, so the gate refuses it at the table rather than after
# a fleet has already been rewarded on it.
#
# Asserted: names are unique, bounded, lowercase; every verification is
# PEER_VERIFIED or SELF_REPORTED; every rule names a declared fact and asset;
# per_node is a decimal count under the ceiling; a rule that pays anything
# names a PEER_VERIFIED fact and is OBSERVED; a rule on a SELF_REPORTED fact
# pays zero and is DOCTRINE; every rule has a bounded why; no two rules repeat
# a fact/asset pair; no declared name goes unread; and at least one rule pays,
# so a table that stopped rewarding is noticed rather than read as clean. A
# row that mixes up quoted and bare fields is MALFORMED, never half-read.
#
# Usage: tools/lint/check_fleet_airship_rules.sh [--selftest]
# Env:   ZCL_AIRSHIP_ROOT, ZCL_AIRSHIP_DEF, ZCL_AIRSHIP_FLOOR (default 5)
# Exit:  0 clean, 1 on a false row, 2 on a hollow/missing table.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_AIRSHIP_ROOT:-$REPO_ROOT}"
DEF_REL="${ZCL_AIRSHIP_DEF:-engine/composition/fleet_airship_rules.def}"
DEF="$ROOT/$DEF_REL"
FLOOR="${ZCL_AIRSHIP_FLOOR:-5}"
GATE="check_fleet_airship_rules"
NAME_MAX=31
WHY_MAX=191
PER_NODE_MAX=8

# One reader for all three families: TAG<TAB>field... so a malformed row is
# reported rather than silently skipped. A row mixes quoted names with bare
# tokens (the counts and the two vocabularies the compiler pastes), so the
# quoted strings are lifted out FIRST and the commas they leave behind are
# what positions the bare fields — never a regex guessing at position.
parse_rows() {
    awk '
    /^AIRSHIP_(FACT|ASSET|RULE)\(/ {
        c = 1; buf = ""
        tag = substr($0, 9); sub(/\(.*/, "", tag)
        want = (tag == "RULE") ? 3 : 1
    }
    c { buf = buf $0 }
    c && /\)[[:space:]]*$/ {
        c = 0; n = 0; rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            p[++n] = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, 1, RSTART - 1) substr(rest, RSTART + RLENGTH)
        }
        sub(/^[^(]*\(/, "", rest); sub(/\)[ \t]*$/, "", rest)
        m = split(rest, f, ",")
        for (i = 1; i <= m; i++) gsub(/[ \t]/, "", f[i])
        if (n != want) { printf "MALFORMED\t%s\n", tag; next }
        if (tag == "ASSET" && rest !~ /[^ \t]/) { printf "ASSET\t%s\n", p[1]; next }
        if (tag == "FACT" && m == 2) { printf "FACT\t%s\t%s\n", p[1], f[2]; next }
        if (tag == "RULE" && m == 5) {
            printf "RULE\t%s\t%s\t%s\t%s\t%s\n", p[1], p[2], f[3], f[4], p[3]
            next
        }
        printf "MALFORMED\t%s\n", tag
    }' "$1"
}
rows_of() { printf '%s\n' "$1" | awk -F'\t' -v t="$2" '$1 == t'; }

scan() {
    local rows="$1" facts assets rules names name verification
    local fact_names asset_names
    facts="$(rows_of "$rows" FACT)"
    assets="$(rows_of "$rows" ASSET)"
    rules="$(rows_of "$rows" RULE)"
    names="$(printf '%s\n%s\n' "$facts" "$assets" | awk -F'\t' 'NF{print $2}')"
    fact_names="$(printf '%s\n' "$facts" | awk -F'\t' 'NF{print $2}')"
    asset_names="$(printf '%s\n' "$assets" | awk -F'\t' 'NF{print $2}')"

    grep -q '^MALFORMED' <<<"$rows" && echo "  a row does not carry the right number of strings"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        grep -qE "^[a-z][a-z0-9_]{0,$((NAME_MAX - 1))}$" <<<"$name" || \
            echo "  '$name' is not a bounded lowercase token"
    done <<<"$names"
    printf '%s\n' "$names" | LC_ALL=C sort | uniq -d | while IFS= read -r name; do
        [ -n "$name" ] && echo "  '$name' is declared twice"
    done
    while IFS=$'\t' read -r _ name verification; do
        [ -n "$name" ] || continue
        case "$verification" in
            PEER_VERIFIED|SELF_REPORTED) ;;
            *) echo "  fact '$name' claims verification '$verification', which is neither PEER_VERIFIED nor SELF_REPORTED" ;;
        esac
    done <<<"$facts"

    local fact asset per confidence why used_facts used_assets paying=0
    while IFS=$'\t' read -r _ fact asset per confidence why; do
        [ -n "$fact" ] || continue
        verification="$(rows_of "$rows" FACT | awk -F'\t' -v f="$fact" '$2 == f { print $3 }')"
        [ -n "$verification" ] || echo "  rule on '$fact' names a fact no row declares"
        grep -qxF "$asset" <<<"$asset_names" || \
            echo "  rule '$fact' awards '$asset', which no row declares"
        if ! grep -qE '^(0|[1-9][0-9]*)$' <<<"$per" || [ "$per" -gt "$PER_NODE_MAX" ]; then
            echo "  rule '$fact' -> '$asset' pays '$per', which is not a decimal count at or under $PER_NODE_MAX"
            continue
        fi
        [ "$per" -gt 0 ] && paying=$((paying + 1))
        case "$confidence" in OBSERVED|DOCTRINE) ;;
            *) echo "  rule '$fact' -> '$asset' carries confidence '$confidence', which is neither OBSERVED nor DOCTRINE" ;;
        esac
        if [ "$per" -gt 0 ] && [ "$verification" != "PEER_VERIFIED" ]; then
            echo "  rule '$fact' -> '$asset' pays $per for a fact the node reports about itself"
        fi
        [ "$per" -gt 0 ] && [ "$confidence" != "OBSERVED" ] && \
            echo "  rule '$fact' -> '$asset' pays $per but is not OBSERVED"
        [ "$per" -eq 0 ] && [ "$confidence" != "DOCTRINE" ] && \
            echo "  rule '$fact' -> '$asset' pays nothing, so it is this table's assertion and must be DOCTRINE"
        if [ -z "${why//[[:space:]]/}" ]; then
            echo "  rule '$fact' -> '$asset' has an empty why"
        elif [ "${#why}" -gt "$WHY_MAX" ]; then
            echo "  rule '$fact' -> '$asset': why is longer than $WHY_MAX bytes"
        fi
    done <<<"$rules"

    printf '%s\n' "$rules" | awk -F'\t' 'NF{print $2 "|" $3}' | LC_ALL=C sort | uniq -d \
        | while IFS= read -r name; do
              [ -n "$name" ] && echo "  a second rule repeats '$name'"
          done
    used_facts="$(printf '%s\n' "$rules" | awk -F'\t' 'NF{print $2}' | LC_ALL=C sort -u)"
    used_assets="$(printf '%s\n' "$rules" | awk -F'\t' 'NF{print $3}' | LC_ALL=C sort -u)"
    while IFS= read -r name; do
        [ -n "$name" ] && ! grep -qxF "$name" <<<"$used_facts" && \
            echo "  fact '$name' is declared but no rule reads it"
    done <<<"$fact_names"
    while IFS= read -r name; do
        [ -n "$name" ] && ! grep -qxF "$name" <<<"$used_assets" && \
            echo "  asset '$name' is declared but no rule awards it"
    done <<<"$asset_names"
    [ "$paying" -gt 0 ] || echo "  no rule pays anything, so the table rewards nothing at all"
}

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    fails=0
    SDEF="$tmp/rules.def"
    head_rows='AIRSHIP_FACT("reachable", PEER_VERIFIED)
AIRSHIP_FACT("cpus", SELF_REPORTED)
AIRSHIP_ASSET("airship")'
    expect() { # <label> <pass|fail> <rules>
        local got=pass
        printf '%s\n%s\n' "$head_rows" "$3" > "$SDEF"
        ZCL_AIRSHIP_ROOT="$tmp" ZCL_AIRSHIP_DEF="rules.def" ZCL_AIRSHIP_FLOOR=1 \
            bash "$REPO_ROOT/tools/lint/check_fleet_airship_rules.sh" >/dev/null 2>&1 || got=fail
        if [ "$got" = "$2" ]; then
            echo "  selftest ok: $1"
        else
            echo "$GATE: SELFTEST FAILED — $1 (got $got, wanted $2)" >&2
            fails=$((fails + 1))
        fi
    }
    good='AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "a dial connects or it does not")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "the node says so itself")'
    expect "a paying peer-verified rule beside a zero self-reported one" pass "$good"
    expect "a self-reported fact that pays" fail \
        'AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "w")
AIRSHIP_RULE("cpus", "airship", 2, OBSERVED, "the node says so itself")'
    expect "an asset no row declares" fail \
        'AIRSHIP_RULE("reachable", "zeppelin", 1, OBSERVED, "w")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "w")'
    expect "a fact no row declares" fail \
        'AIRSHIP_RULE("ram_total", "airship", 1, OBSERVED, "w")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "w")
AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "w")'
    expect "a zero rule claiming to be an observation" fail \
        'AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "w")
AIRSHIP_RULE("cpus", "airship", 0, OBSERVED, "w")'
    expect "a duplicated rule" fail "$good
AIRSHIP_RULE(\"reachable\", \"airship\", 1, OBSERVED, \"w\")"
    expect "a per_node and a confidence written as strings" fail \
        'AIRSHIP_RULE("reachable", "airship", "1", "OBSERVED", "w")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "w")'
    expect "an empty why" fail \
        'AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "w")'
    expect "a declared fact no rule reads" fail \
        'AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "w")'
    expect "a table where nothing pays" fail \
        'AIRSHIP_RULE("reachable", "airship", 0, DOCTRINE, "w")
AIRSHIP_RULE("cpus", "airship", 0, DOCTRINE, "w")'
    # A verification the table never declares, which needs its own head rows.
    printf '%s\n' 'AIRSHIP_FACT("reachable", TRUSTED)
AIRSHIP_ASSET("airship")
AIRSHIP_RULE("reachable", "airship", 1, OBSERVED, "w")' > "$SDEF"
    if ZCL_AIRSHIP_ROOT="$tmp" ZCL_AIRSHIP_DEF="rules.def" ZCL_AIRSHIP_FLOOR=1 \
        bash "$REPO_ROOT/tools/lint/check_fleet_airship_rules.sh" >/dev/null 2>&1; then
        echo "$GATE: SELFTEST FAILED — a third verification value passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a verification that is neither PEER_VERIFIED nor SELF_REPORTED"
    fi

    rc=0
    ZCL_AIRSHIP_ROOT="$tmp" ZCL_AIRSHIP_DEF="missing.def" ZCL_AIRSHIP_FLOOR=1 \
        bash "$REPO_ROOT/tools/lint/check_fleet_airship_rules.sh" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a missing table did not exit 2 (rc=$rc)" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a missing table exits 2"
    fi
    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (a paying self-reported fact, an undeclared fact or asset, a mislabelled zero row, a duplicate, an empty why, an unread fact and a table that pays nothing all fail; an honest table passes; a missing table exits 2)"
    exit 0
fi

[ -f "$DEF" ] || { echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2; exit 2; }
rows="$(parse_rows "$DEF")"
rule_count="$(rows_of "$rows" RULE | grep -c . || true)"
fact_count="$(rows_of "$rows" FACT | grep -c . || true)"
asset_count="$(rows_of "$rows" ASSET | grep -c . || true)"
if [ "$rule_count" -lt "$FLOOR" ] || [ "$fact_count" -lt 1 ] || [ "$asset_count" -lt 1 ]; then
    echo "[$GATE] FATAL — $rule_count rules over $fact_count facts and $asset_count assets is below the floor of $FLOOR rules and one of each vocabulary" >&2
    echo "        A table that stopped parsing must never read as clean." >&2
    exit 2
fi
faults="$(scan "$rows")"
if [ -n "${faults//[[:space:]]/}" ]; then
    echo "[$GATE] FAIL — the airship rule table would reward an unverified claim:"
    printf '%s\n' "$faults"
    exit 1
fi
verified="$(rows_of "$rows" FACT | awk -F'\t' '$3 == "PEER_VERIFIED"' | grep -c . || true)"
echo "[$GATE] OK — $rule_count rules over $fact_count facts ($verified peer-verified) and $asset_count assets; every paying rule names a fact a peer observed"
exit 0
