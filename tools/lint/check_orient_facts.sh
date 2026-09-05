#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# purpose: every row in engine/composition/facts/ must still be TRUE — its
#          path must exist and its anchor must still be findable in it.
#
# WHY. The fact table exists so an agent stops re-deriving the same map from
# source. That only holds while the rows are true, and a stale row is worse
# than no row: it is confidently wrong and costs the reader the derivation
# anyway plus the time to notice. So the anchor — a literal substring of the
# file the claim was read from — is re-proved here on every commit. When the
# code moves, this gate fails and the row gets rewritten or deleted.
#
# NEVER weaken an anchor to make a row pass. There is no baseline file and no
# exemption list, deliberately: both are ways to keep a false row.
#
# SCAN FLOOR. A gate that passes because it scanned nothing is the trap this
# tree has been bitten by. Zero topic files, zero rows, or an unreadable
# index is a FAILURE here, not a pass.
#
#   ZCL_ORIENT_FACTS_DIR=<dir>   scan another facts dir (selftest only)
#   --selftest                   plant a broken row and prove the gate trips

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [ "${1:-}" = --selftest ]; then
    mkdir -p "${TMPDIR:-$ROOT/build/scratch}"
    tmp="$(mktemp -d "${TMPDIR:-$ROOT/build/scratch}/orientfacts.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/facts"
    printf 'ZCL_FACT_TOPIC("t.ok", "b")\n#include "t_ok.def"\n' > "$tmp/facts/index.def"
    printf 'ZCL_FACT("t.ok", "k",\n "c",\n "Makefile",\n "no-such-anchor-ZZQ9")\n' \
        > "$tmp/facts/t_ok.def"
    if ZCL_ORIENT_FACTS_DIR="$tmp/facts" "$0" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: a missing anchor did not trip the gate" >&2
        exit 1
    fi
    printf 'ZCL_FACT("t.ok", "k",\n "c",\n "Makefile",\n "LINT_GATES")\n' \
        > "$tmp/facts/t_ok.def"
    ZCL_ORIENT_FACTS_DIR="$tmp/facts" "$0" >/dev/null
    echo "selftest ok: a broken anchor fails, a true row passes"
    exit 0
fi

DIR="${ZCL_ORIENT_FACTS_DIR:-engine/composition/facts}"
INDEX="$DIR/index.def"
[ -r "$INDEX" ] || { echo "FAIL: no readable $INDEX" >&2; exit 1; }
FILES="$(/usr/bin/grep -a -o '^#include "[^"]*"' "$INDEX" | cut -d'"' -f2 || true)"
[ -n "$FILES" ] || { echo "FAIL: $INDEX includes no topic file" >&2; exit 1; }

TOPICS="$(/usr/bin/grep -a -o '^ZCL_FACT_TOPIC("[^"]*"' "$INDEX" | cut -d'"' -f2 | tr '\n' ' ')"
rc=0 rows=0
for rel in $FILES; do
    f="$DIR/$rel"
    [ -r "$f" ] || { echo "FAIL: $INDEX includes unreadable $rel" >&2; rc=1; continue; }
    awk '/\t/ { exit 1 }' "$f" || { echo "FAIL: $rel contains a tab" >&2; rc=1; }
    while IFS='|' read -r topic key claim path anchor; do
        rows=$((rows + 1))
        id="$topic.$key"
        [ "$topic" != MALFORMED ] ||
            { echo "$rel: a ZCL_FACT row is not exactly five plain string fields" >&2
              rc=1; continue; }
        case " $TOPICS " in *" $topic "*) ;;
            *) echo "$id: topic not declared in $INDEX" >&2; rc=1 ;; esac
        [ "${#key}" -le 48 ] || { echo "$id: key over 48 chars" >&2; rc=1; }
        [ "${#claim}" -le 160 ] || { echo "$id: claim over 160 chars" >&2; rc=1; }
        [ "${#anchor}" -le 80 ] || { echo "$id: anchor over 80 chars" >&2; rc=1; }
        [ -f "$path" ] || { echo "$id: $path missing" >&2; rc=1; continue; }
        /usr/bin/grep -a -F -q -e "$anchor" "$path" ||
            { echo "$id: anchor \"$anchor\" not found in $path" >&2; rc=1; }
    done < <(awk '/^ZCL_FACT\(/ {r=""} /^ZCL_FACT\(/,/\)[[:space:]]*$/ {
        r = r $0; if (/\)[[:space:]]*$/) { n = split(r, q, "\"");
        if (n != 11) { printf "MALFORMED||||\n"; next }
        printf "%s|%s|%s|%s|%s\n", q[2], q[4], q[6], q[8], q[10] } }' "$f")
    dup="$(awk '/^ZCL_FACT\(/ { n = split($0, q, "\""); if (n >= 5) print q[2] "." q[4] }' \
        "$f" | sort | uniq -d)"
    [ -z "$dup" ] || { echo "FAIL: duplicate keys in $rel: $dup" >&2; rc=1; }
done

[ "$rows" -gt 0 ] || { echo "FAIL: scan floor — zero fact rows scanned" >&2; exit 1; }
[ "$rc" -eq 0 ] || exit 1
echo "orient facts: $rows rows across $(echo "$TOPICS" | wc -w) topics, every path and anchor proved"
