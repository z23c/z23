#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fleet_vitals.sh — the fleet vitals catalog is closed, complete, and
# the same list the documentation shows (HARD).
#
# engine/composition/fleet_vitals.def is the ONE declaration of what a fleet
# metric is. `fleet ledger add --kind=vitals` refuses a subject that is not
# in it (`vital_unknown`), the module pastes it as an X-macro, and
# docs/FLEET_LEDGER.md renders it as a table. A row that is malformed, a
# duplicate id, a missing unit, or a doc table that has drifted are each a
# false statement about what this fleet measures — and a metric id is
# IDENTITY: rows already signed carry its position, so a silent edit
# re-points stored history at a different metric.
#
# Asserted:
#   A. Every FLEET_VITAL row carries four strings and one integer cadence.
#   B. Every id is non-empty and appears exactly once.
#   C. Every unit is non-empty — an integer with no unit is not a measurement.
#   D. Every agg is exactly "gauge" or "sum".
#   E. Every cadence is a non-negative integer (0 means "per event").
#   F. Every why is non-empty — a metric nobody can name a use for will be
#      collected and never read.
#   G. docs/FLEET_LEDGER.md's vitals table lists exactly these ids, in the
#      catalog's own order.
#   H. Row count is at least the floor; a catalog that stopped parsing must
#      never read as clean (exit 2).
#
# Usage:
#   tools/lint/check_fleet_vitals.sh
#   tools/lint/check_fleet_vitals.sh --selftest
#
# Env:
#   ZCL_FLEET_VITALS_ROOT   repo root (default: this script's repo)
#   ZCL_FLEET_VITALS_DEF    catalog path relative to root
#   ZCL_FLEET_VITALS_DOC    doc path relative to root
#   ZCL_FLEET_VITALS_FLOOR  minimum row count (default: 30)
#
# Exit: 0 clean, 1 on a false row or a drifted table, 2 on a hollow catalog.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_FLEET_VITALS_ROOT:-$REPO_ROOT}"
DEF_REL="${ZCL_FLEET_VITALS_DEF:-engine/composition/fleet_vitals.def}"
DOC_REL="${ZCL_FLEET_VITALS_DOC:-docs/FLEET_LEDGER.md}"
DEF="$ROOT/$DEF_REL"
DOC="$ROOT/$DOC_REL"
FLOOR="${ZCL_FLEET_VITALS_FLOOR:-30}"
GATE="check_fleet_vitals"

# id \t unit \t agg \t cadence \t why, one row per line. A row that does not
# carry exactly four string literals and one integer is emitted as MALFORMED
# rather than silently skipped: a row the parser cannot read is the failure
# this gate exists to catch, not a row that does not exist.
parse_rows() {
    awk '
    /^FLEET_VITAL\(/ { collecting = 1; buf = "" }
    collecting       { buf = buf $0 }
    collecting && /\)[[:space:]]*$/ {
        collecting = 0
        n = 0
        rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            parts[++n] = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
        }
        stripped = buf
        gsub(/"([^"\\]|\\.)*"/, "", stripped)
        cadence = ""
        if (match(stripped, /[0-9]+/))
            cadence = substr(stripped, RSTART, RLENGTH)
        if (n != 4 || cadence == "") {
            printf "MALFORMED\t%s\t\t\t\n", buf
            next
        }
        printf "%s\t%s\t%s\t%s\t%s\n", parts[1], parts[2], parts[3], cadence, parts[4]
    }
    ' "$1"
}

# The vitals table in the doc: every markdown row whose first cell is a
# catalog-shaped id. The doc is the rendered view; drift means one of the
# two is lying about what this fleet measures.
doc_ids() {
    awk -F'|' '
        /^\|[[:space:]]*`[a-z]+\.[a-z0-9_]+`[[:space:]]*\|/ {
            id = $2
            gsub(/[[:space:]`]/, "", id)
            print id
        }
    ' "$1"
}

scan() {
    local -A seen=()
    local id unit agg cadence why
    local faults=0
    while IFS=$'\t' read -r id unit agg cadence why; do
        [ -n "$id" ] || continue
        if [ "$id" = "MALFORMED" ]; then
            echo "  a FLEET_VITAL row does not carry four strings and a cadence"
            faults=$((faults + 1))
            continue
        fi
        if [ -n "${seen[$id]+x}" ]; then
            echo "  $id: a second row for an id that already has one"
            faults=$((faults + 1))
        fi
        seen["$id"]=1
        if [ -z "$unit" ]; then
            echo "  $id: empty unit — an integer with no unit is not a measurement"
            faults=$((faults + 1))
        fi
        if [ "$agg" != "gauge" ] && [ "$agg" != "sum" ]; then
            echo "  $id: agg '$agg' is neither gauge nor sum"
            faults=$((faults + 1))
        fi
        case "$cadence" in
            ''|*[!0-9]*) echo "  $id: cadence '$cadence' is not a non-negative integer"
                         faults=$((faults + 1)) ;;
        esac
        if [ -z "$why" ]; then
            echo "  $id: empty why — nobody can say what the number is for"
            faults=$((faults + 1))
        fi
    done
    [ "$faults" -eq 0 ]
}

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0
    mkdir -p "$tmp/engine/composition" "$tmp/docs"

    write_doc() {
        {
            echo '| id | unit | agg |'
            echo '| --- | --- | --- |'
            for one in "$@"; do printf '| `%s` | count | sum |\n' "$one"; done
        } > "$tmp/docs/FLEET_LEDGER.md"
    }

    run_stub() {
        ZCL_FLEET_VITALS_ROOT="$tmp" ZCL_FLEET_VITALS_FLOOR=1 \
            bash "$REPO_ROOT/tools/lint/check_fleet_vitals.sh" >/dev/null 2>&1
    }

    printf 'FLEET_VITAL("box.load1", "load", "gauge", 300, "room for a lane")\n' \
        > "$tmp/engine/composition/fleet_vitals.def"
    write_doc box.load1
    if run_stub; then
        echo "  selftest ok: a complete row with a matching doc table"
    else
        echo "$GATE: SELFTEST FAILED — a sound catalog did not pass" >&2
        fails=$((fails + 1))
    fi

    printf 'FLEET_VITAL("box.load1", "load", "gauge", 300, "a")\nFLEET_VITAL("box.load1", "load", "sum", 5, "b")\n' \
        > "$tmp/engine/composition/fleet_vitals.def"
    write_doc box.load1 box.load1
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — a duplicate id passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a duplicate id"
    fi

    printf 'FLEET_VITAL("box.load1", "", "gauge", 300, "a")\n' \
        > "$tmp/engine/composition/fleet_vitals.def"
    write_doc box.load1
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — an empty unit passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: an empty unit"
    fi

    printf 'FLEET_VITAL("box.load1", "load", "average", 300, "a")\n' \
        > "$tmp/engine/composition/fleet_vitals.def"
    write_doc box.load1
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — an agg outside the enum passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: an agg outside the enum"
    fi

    printf 'FLEET_VITAL("box.load1", "load", "gauge", 300, "a")\n' \
        > "$tmp/engine/composition/fleet_vitals.def"
    write_doc box.cores
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — a drifted doc table passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a doc table that names a different id"
    fi

    rc=0
    ZCL_FLEET_VITALS_ROOT="$tmp" ZCL_FLEET_VITALS_DEF="missing.def" \
        ZCL_FLEET_VITALS_FLOOR=1 \
        bash "$REPO_ROOT/tools/lint/check_fleet_vitals.sh" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a missing .def did not exit 2 (rc=$rc)" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a missing .def exits 2"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (duplicate id, empty unit, unknown agg and a drifted doc table all fail; a sound catalog passes; a missing .def exits 2)"
    exit 0
fi

[ -f "$DEF" ] || {
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
}
[ -f "$DOC" ] || {
    echo "[$GATE] FATAL — $DOC is missing; the rendered table cannot be checked" >&2
    exit 2
}

rows="$(parse_rows "$DEF")"
row_count="$(printf '%s\n' "$rows" | grep -c . || true)"
if [ "$row_count" -lt "$FLOOR" ]; then
    echo "[$GATE] FATAL — $row_count vitals rows is below the floor of $FLOOR" >&2
    echo "        A catalog that stopped parsing must never read as clean." >&2
    exit 2
fi

faults="$(printf '%s\n' "$rows" | scan)"
scan_rc=$?
if [ "$scan_rc" -ne 0 ] || [ -n "${faults//[[:space:]]/}" ]; then
    echo "[$GATE] FAIL — the vitals catalog has false rows:"
    printf '%s\n' "$faults"
    exit 1
fi

def_ids="$(printf '%s\n' "$rows" | cut -f1)"
rendered="$(doc_ids "$DOC")"
if [ "$def_ids" != "$rendered" ]; then
    echo "[$GATE] FAIL — $DOC_REL's vitals table is not $DEF_REL, in order:"
    diff <(printf '%s\n' "$def_ids") <(printf '%s\n' "$rendered") | head -40
    echo "        Regenerate the table from the catalog; never edit one alone."
    exit 1
fi

echo "[$GATE] OK — $row_count vitals; every id unique, every unit and why named, every agg in the enum, and $DOC_REL renders exactly this list"
exit 0
