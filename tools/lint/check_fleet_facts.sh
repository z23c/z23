#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fleet_facts.sh — every fleet fact still says something checkable, and
# the executor routing table in the docs is this table's output (HARD).
#
# engine/composition/fleet_facts.def is the one place the fleet's doctrine is
# written down: which executor handles which unit kind, what a train and a
# proof require, which failure signature names which trap. `z23 dev know`
# answers from it. A row whose object is a typo, or whose path names no
# tracked file, is a false statement an agent will act on.
#
# Asserted:
#   A. Every FLEET_TERM is unique, non-empty, bounded, and lowercase-rooted.
#   B. Every term containing '/' is a tracked file.
#   C. Every fact subject and object is a declared term or a canonical root
#      (64 lowercase hex). There is no free text on either side of a relation.
#   D. Every relation and context is declared in this same file.
#   E. Every confidence is DOCTRINE or OBSERVED. UNKNOWN is what the query
#      synthesizes when it has no row; writing it here would be a lie.
#   F. Every row has a `why`, bounded by the module's field.
#   G. No two rows repeat one subject/relation/object/context.
#   H. Every declared term is used. Dead vocabulary rots into a second
#      spelling of a live term.
#   I. A lives_at object is a path, not a token.
#   J. docs/agent/EXECUTOR_HEURISTICS.md's routing block is this file's own
#      output, so the .md can never become a second source.
#   K. Row and vocabulary counts are at or above their floors (a hollow scan
#      is exit 2).
#
# Usage:
#   tools/lint/check_fleet_facts.sh
#   tools/lint/check_fleet_facts.sh --selftest
#   tools/lint/check_fleet_facts.sh --write-doc   # `make docs-executor-routing`
#
# Env:
#   ZCL_FLEET_FACTS_ROOT   repo root (default: this script's repo)
#   ZCL_FLEET_FACTS_DEF    table path relative to root
#   ZCL_FLEET_FACTS_FLOOR  minimum fact-row count (default: 20)
#
# Exit: 0 clean, 1 on a false row, 2 on a hollow/missing table.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_FLEET_FACTS_ROOT:-$REPO_ROOT}"
DEF_REL="${ZCL_FLEET_FACTS_DEF:-engine/composition/fleet_facts.def}"
DEF="$ROOT/$DEF_REL"
DOC_REL="docs/agent/EXECUTOR_HEURISTICS.md"
DOC="$ROOT/$DOC_REL"
FLOOR="${ZCL_FLEET_FACTS_FLOOR:-20}"
BEGIN_MARK="<!-- FLEET-FACTS-ROUTING-BEGIN -->"
END_MARK="<!-- FLEET-FACTS-ROUTING-END -->"
GATE="check_fleet_facts"
TOKEN_MAX=63
WHY_MAX=223

# One reader for all four X-macro families. Emits TAG<TAB>field<TAB>... so a
# malformed row is reported rather than silently skipped.
parse_rows() {
    awk '
    /^FLEET_(RELATION|CONTEXT|TERM|FACT)\(/ {
        collecting = 1; buf = ""
        tag = substr($0, 7); sub(/\(.*/, "", tag)
        want = (tag == "FACT") ? 6 : 1
    }
    collecting { buf = buf $0 }
    collecting && /\)[[:space:]]*$/ {
        collecting = 0
        n = 0; rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            parts[++n] = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
        }
        if (n != want) { printf "MALFORMED\t%s\n", tag; next }
        line = tag
        for (i = 1; i <= n; i++) line = line "\t" parts[i]
        print line
    }
    ' "$1"
}

rows_of() { printf '%s\n' "$1" | awk -F'\t' -v t="$2" '$1 == t'; }
col() { awk -F'\t' -v c="$1" '{ print $c }'; }

# The routing block docs/agent/EXECUTOR_HEURISTICS.md carries: every row about
# an executor, and nothing else. An executor is a subject some row says
# handles something, so the block follows the table rather than a second list
# of names kept here.
emit_doc() {
    local rows="$1" facts
    facts="$(rows_of "$rows" FACT)"
    echo "$BEGIN_MARK"
    echo
    echo "| Executor | Relation | Object | Why |"
    echo "| --- | --- | --- | --- |"
    printf '%s\n' "$facts" | awk -F'\t' '
        NR == FNR { if ($3 ~ /^handles_/) exec[$2] = 1; next }
        ($2 in exec) && ($3 ~ /^handles_/ || $3 == "requires") {
            printf "%s\t%s\t%s\t%s\n", $2, $3, $4, $7
        }' - <(printf '%s\n' "$facts") \
        | LC_ALL=C sort -t$'\t' -k1,1 -k2,2 -k3,3 \
        | awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4 }'
    echo
    echo "$END_MARK"
}

doc_block() { awk -v b="$BEGIN_MARK" -v e="$END_MARK" \
    'index($0,b){f=1} f{print} index($0,e){f=0}' "$DOC"; }

scan() {
    local rows="$1"
    local terms relations contexts facts
    local name

    terms="$(rows_of "$rows" TERM | col 2)"
    relations="$(rows_of "$rows" RELATION | col 2)"
    contexts="$(rows_of "$rows" CONTEXT | col 2)"
    facts="$(rows_of "$rows" FACT)"

    if grep -q '^MALFORMED' <<<"$rows"; then
        echo "  a row does not carry the right number of strings"
    fi
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if ! grep -qE '^[a-z0-9][A-Za-z0-9._/-]*$' <<<"$name"; then
            echo "  term '$name' is not a lowercase-rooted token or path"
            continue
        fi
        [ "${#name}" -le "$TOKEN_MAX" ] || \
            echo "  term '$name' is longer than $TOKEN_MAX bytes"
        case "$name" in
            */*) git -C "$ROOT" ls-files --error-unmatch -- "$name" \
                     >/dev/null 2>&1 || \
                     echo "  term '$name' looks like a path but is not tracked" ;;
        esac
    done <<<"$terms"
    printf '%s\n' "$terms" | LC_ALL=C sort | uniq -d \
        | while IFS= read -r name; do
              [ -n "$name" ] && echo "  term '$name' is declared twice"
          done
    printf '%s\n%s\n' "$relations" "$contexts" | LC_ALL=C sort | uniq -d \
        | while IFS= read -r name; do
              [ -n "$name" ] && echo "  relation or context '$name' is declared twice"
          done

    local subject relation object context confidence why tok
    while IFS=$'\t' read -r _ subject relation object context confidence why; do
        [ -n "$subject" ] || continue
        for tok in "$subject" "$object"; do
            if ! grep -qxF "$tok" <<<"$terms" && \
               ! grep -qE '^[0-9a-f]{64}$' <<<"$tok"; then
                echo "  '$tok' is neither a declared term nor a canonical root"
            fi
        done
        grep -qxF "$relation" <<<"$relations" || \
            echo "  $subject: relation '$relation' is not declared"
        grep -qxF "$context" <<<"$contexts" || \
            echo "  $subject: context '$context' is not declared"
        case "$confidence" in
            DOCTRINE|OBSERVED) ;;
            *) echo "  $subject $relation $object: confidence '$confidence' is not DOCTRINE or OBSERVED" ;;
        esac
        if [ -z "${why//[[:space:]]/}" ]; then
            echo "  $subject $relation $object: empty why"
        elif [ "${#why}" -gt "$WHY_MAX" ]; then
            echo "  $subject $relation $object: why is longer than $WHY_MAX bytes"
        fi
        if [ "$relation" = "lives_at" ]; then
            case "$object" in
                */*) ;;
                *) echo "  $subject lives_at '$object', which is not a path" ;;
            esac
        fi
    done <<<"$facts"

    printf '%s\n' "$facts" | awk -F'\t' '{ print $2 "|" $3 "|" $4 "|" $5 }' \
        | LC_ALL=C sort | uniq -d \
        | while IFS= read -r name; do
              [ -n "$name" ] && echo "  a second row repeats '$name'"
          done

    local used
    used="$(printf '%s\n' "$facts" | awk -F'\t' '{ print $2; print $4 }' \
            | LC_ALL=C sort -u)"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        grep -qxF "$name" <<<"$used" || \
            echo "  term '$name' is declared but no row uses it"
    done <<<"$terms"

    if [ -f "$DOC" ]; then
        if ! diff -q <(emit_doc "$rows") <(doc_block) >/dev/null 2>&1; then
            echo "  $DOC_REL's routing block is not this table's output"
            echo "    fix with: make docs-executor-routing"
        fi
    else
        echo "  $DOC_REL is missing, so the routing block cannot be checked"
    fi
}

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    fails=0
    stub="$tmp/repo"
    mkdir -p "$stub/docs/agent" "$stub/engine/composition"
    git -C "$stub" init -q
    printf '%s\n%s\n' "$BEGIN_MARK" "$END_MARK" > "$stub/docs/agent/EXECUTOR_HEURISTICS.md"
    git -C "$stub" add docs/agent/EXECUTOR_HEURISTICS.md
    git -C "$stub" -c user.email=t@t -c user.name=t commit -qm s
    SDEF="$stub/engine/composition/fleet_facts.def"
    head_rows='FLEET_RELATION("is_a")
FLEET_CONTEXT("doctrine")
FLEET_TERM("sonnet")
FLEET_TERM("executor")'

    write_stub() {
        printf '%s\n%s\n' "$head_rows" "$1" > "$SDEF"
        # The block is rewritten from whatever the table says, so the selftest
        # exercises the row rules and never the doc comparison.
        ZCL_FLEET_FACTS_ROOT="$stub" ZCL_FLEET_FACTS_FLOOR=1 \
            bash "$REPO_ROOT/tools/lint/check_fleet_facts.sh" --write-doc \
            >/dev/null 2>&1
        ZCL_FLEET_FACTS_ROOT="$stub" ZCL_FLEET_FACTS_FLOOR=1 \
            bash "$REPO_ROOT/tools/lint/check_fleet_facts.sh" >/dev/null 2>&1
    }
    expect() { # <label> <pass|fail> <row>
        local got=pass
        write_stub "$3" || got=fail
        if [ "$got" = "$2" ]; then
            echo "  selftest ok: $1"
        else
            echo "$GATE: SELFTEST FAILED — $1 (got $got, wanted $2)" >&2
            fails=$((fails + 1))
        fi
    }
    good='FLEET_FACT("sonnet", "is_a", "executor", "doctrine", "DOCTRINE", "a")'
    expect "a row whose term, relation and context are declared" pass "$good"
    expect "an object no term declares" fail \
        'FLEET_FACT("sonnet", "is_a", "wizard", "doctrine", "DOCTRINE", "a")
FLEET_FACT("sonnet", "is_a", "executor", "doctrine", "DOCTRINE", "a")'
    expect "a relation the table does not declare" fail \
        'FLEET_FACT("sonnet", "eats", "executor", "doctrine", "DOCTRINE", "a")'
    expect "a confidence of UNKNOWN" fail \
        'FLEET_FACT("sonnet", "is_a", "executor", "doctrine", "UNKNOWN", "a")'
    expect "a duplicated row" fail "$good
$good"
    expect "an empty why" fail \
        'FLEET_FACT("sonnet", "is_a", "executor", "doctrine", "DOCTRINE", "")'
    expect "a declared term no row uses" fail \
        'FLEET_FACT("sonnet", "is_a", "sonnet", "doctrine", "DOCTRINE", "a")'

    rc=0
    ZCL_FLEET_FACTS_ROOT="$stub" ZCL_FLEET_FACTS_DEF="missing.def" \
        ZCL_FLEET_FACTS_FLOOR=1 \
        bash "$REPO_ROOT/tools/lint/check_fleet_facts.sh" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a missing table did not exit 2 (rc=$rc)" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a missing table exits 2"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (undeclared object, undeclared relation, UNKNOWN confidence, duplicate row, empty why and unused term all fail; a resolving row passes; a missing table exits 2)"
    exit 0
fi

[ -f "$DEF" ] || {
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
}

rows="$(parse_rows "$DEF")"
fact_count="$(rows_of "$rows" FACT | grep -c . || true)"
term_count="$(rows_of "$rows" TERM | grep -c . || true)"
rel_count="$(rows_of "$rows" RELATION | grep -c . || true)"
ctx_count="$(rows_of "$rows" CONTEXT | grep -c . || true)"
if [ "$fact_count" -lt "$FLOOR" ] || [ "$term_count" -lt 1 ] || \
   [ "$rel_count" -lt 1 ] || [ "$ctx_count" -lt 1 ]; then
    echo "[$GATE] FATAL — $fact_count facts, $term_count terms, $rel_count relations, $ctx_count contexts is below the floor of $FLOOR facts and one of each vocabulary" >&2
    echo "        A table that stopped parsing must never read as clean." >&2
    exit 2
fi

if [ "${1:-}" = "--write-doc" ]; then
    [ -f "$DOC" ] || { echo "[$GATE] FATAL — $DOC is missing" >&2; exit 2; }
    block="$(mktemp)"; merged="$(mktemp)"
    emit_doc "$rows" > "$block"
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" -v f="$block" \
        'index($0,b) { skip=1; while ((getline l < f) > 0) print l; next }
         skip && index($0,e) { skip=0; next }
         skip { next }
         { print }' "$DOC" > "$merged"
    if ! grep -qF "$BEGIN_MARK" "$merged"; then
        rm -f "$block" "$merged"
        echo "[$GATE] FATAL — $DOC_REL carries no $BEGIN_MARK marker" >&2
        exit 2
    fi
    mv "$merged" "$DOC"; rm -f "$block"
    echo "[$GATE] wrote the routing block in $DOC_REL from $DEF_REL"
    exit 0
fi

faults="$(scan "$rows")"
if [ -n "${faults//[[:space:]]/}" ]; then
    echo "[$GATE] FAIL — the fleet fact table has false rows:"
    printf '%s\n' "$faults"
    exit 1
fi

echo "[$GATE] OK — $fact_count facts over $term_count terms, $rel_count relations and $ctx_count contexts; every term resolves and $DOC_REL renders this table"
exit 0
