#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_specialists.sh — every specialist row still points at real territory,
# real lint gates, and real registered test groups (HARD).
#
# engine/composition/specialists.def is the one place a specialist lane is
# written down. `code focus` ranks from that table. A row whose globs match
# nothing, or that names a deleted gate or test group, is a false statement
# about where a lane should work.
#
# Asserted:
#   A. Every SPECIALIST name is unique and non-empty.
#   B. Every territory token matches at least one tracked file.
#   C. Every named gate exists in Makefile LINT_GATES / LINT_FAST_GATES or as
#      a `check-*:` target.
#   D. Every named test group is a ZCL_TEST_GROUP / ZCL_SPEC_GROUP row in
#      tools/dev/test_group_catalog.def.
#   E. Row count is at least the floor (a hollow scan is exit 2).
#
# Usage:
#   tools/lint/check_specialists.sh
#   tools/lint/check_specialists.sh --selftest
#
# Env:
#   ZCL_SPECIALISTS_ROOT   repo root (default: this script's repo)
#   ZCL_SPECIALISTS_DEF    catalog path relative to root
#   ZCL_SPECIALISTS_FLOOR  minimum row count (default: 10)
#
# Exit: 0 clean, 1 on a false row, 2 on a hollow/missing catalog.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_SPECIALISTS_ROOT:-$REPO_ROOT}"
DEF_REL="${ZCL_SPECIALISTS_DEF:-engine/composition/specialists.def}"
DEF="$ROOT/$DEF_REL"
CATALOG="$ROOT/tools/dev/test_group_catalog.def"
MAKEFILE="$ROOT/Makefile"
FLOOR="${ZCL_SPECIALISTS_FLOOR:-10}"
GATE="check_specialists"

# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"

parse_rows() {
    awk '
    /^SPECIALIST\(/ { collecting = 1; buf = "" }
    collecting   { buf = buf $0 }
    collecting && /\)[[:space:]]*$/ {
        collecting = 0
        n = 0
        rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            lit = substr(rest, RSTART + 1, RLENGTH - 2)
            parts[++n] = lit
            rest = substr(rest, RSTART + RLENGTH)
        }
        if (n != 5) { printf "MALFORMED\t%s\t\t\t\n", buf; next }
        printf "%s\t%s\t%s\t%s\t%s\n", parts[1], parts[2], parts[3], parts[4], parts[5]
    }
    ' "$1"
}

extract_gate_list() {
    local makefile="$1" var="$2"
    awk -v v="$var" '
        $0 ~ "^" v "[[:space:]]*:=" { inb = 1 }
        inb { print; if ($0 !~ /\\[[:space:]]*$/) exit }
    ' "$makefile" | grep -oE 'check-[a-z0-9-]+' | sort -u || true
}

territory_hits() {
    local pat="$1"
    if [[ "$pat" == *[\*\?\[]* ]]; then
        git -C "$ROOT" ls-files -- "$pat"
    else
        git -C "$ROOT" ls-files -- "$pat" "$pat/*"
    fi
}

scan() {
    local def="$1"
    local -A seen=()
    local name terr gates groups facts
    local makefile_gates
    makefile_gates="$(extract_gate_list "$MAKEFILE" LINT_GATES)
$(extract_gate_list "$MAKEFILE" LINT_FAST_GATES)
$(grep -oE '^check-[a-z0-9-]+:' "$MAKEFILE" | sed 's/:$//' | sort -u || true)"
    # Territory tokens may contain '*' (git pathspecs). Do not let the
    # shell glob them against the worktree before git ls-files sees them.
    set -f

    while IFS=$'\t' read -r name terr gates groups facts; do
        [ -n "$name" ] || continue
        if [ "$name" = "MALFORMED" ]; then
            echo "  a SPECIALIST row does not carry five strings"
            continue
        fi
        if [ -n "${seen[$name]+x}" ]; then
            echo "  $name: a second row for a specialist that already has one"
        fi
        seen["$name"]=1
        if [ -z "$terr" ]; then
            echo "  $name: empty territory"
            continue
        fi
        local IFS='|'
        local tok
        for tok in $terr; do
            [ -n "$tok" ] || continue
            local hits
            hits="$(territory_hits "$tok")"
            if [ -z "${hits//[[:space:]]/}" ]; then
                echo "  $name: territory '$tok' matches no tracked file"
            fi
        done
        for tok in $gates; do
            [ -n "$tok" ] || continue
            if ! grep -qx "$tok" <<<"$makefile_gates"; then
                echo "  $name: gate '$tok' is not a Makefile lint gate"
            fi
        done
        IFS='|'
        for tok in $groups; do
            [ -n "$tok" ] || continue
            if ! grep -Eq "^ZCL_(TEST|SPEC)_GROUP\\($tok\\)" "$CATALOG"; then
                echo "  $name: test group '$tok' is not in test_group_catalog.def"
            fi
        done
        if [ -z "$facts" ]; then
            echo "  $name: empty fact_kinds"
        fi
    done < <(parse_rows "$def")
    set +f
}

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0
    stub_root="$tmp/repo"
    mkdir -p "$stub_root/core/consensus" "$stub_root/tools/dev" \
             "$stub_root/engine/composition"
    echo 'int x;' > "$stub_root/core/consensus/x.c"
    git -C "$stub_root" init -q
    git -C "$stub_root" add core/consensus/x.c
    git -C "$stub_root" -c user.email=t@t -c user.name=t commit -qm s
    printf 'LINT_GATES := \\\n    check-consensus-parity\n' > "$stub_root/Makefile"
    printf 'check-consensus-parity:\n\t@true\n' >> "$stub_root/Makefile"
    echo 'ZCL_TEST_GROUP(consensus)' > "$stub_root/tools/dev/test_group_catalog.def"

    run_stub() {
        ZCL_SPECIALISTS_ROOT="$stub_root" ZCL_SPECIALISTS_FLOOR=1 \
            bash "$REPO_ROOT/tools/lint/check_specialists.sh" \
            >/dev/null 2>&1
    }

    echo 'SPECIALIST("consensus","core/consensus","check-consensus-parity","consensus","consensus")' \
        > "$stub_root/engine/composition/specialists.def"
    if run_stub; then
        echo "  selftest ok: a row whose territory, gate and group exist"
    else
        echo "$GATE: SELFTEST FAILED — a resolving row did not pass" >&2
        fails=$((fails + 1))
    fi

    echo 'SPECIALIST("consensus","core/nope","check-consensus-parity","consensus","consensus")' \
        > "$stub_root/engine/composition/specialists.def"
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — a territory that matches nothing passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a territory that matches nothing"
    fi

    echo 'SPECIALIST("consensus","core/consensus","check-not-a-gate","consensus","consensus")' \
        > "$stub_root/engine/composition/specialists.def"
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — an unknown gate passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a gate the Makefile does not declare"
    fi

    echo 'SPECIALIST("consensus","core/consensus","check-consensus-parity","no_such_group","consensus")' \
        > "$stub_root/engine/composition/specialists.def"
    if run_stub; then
        echo "$GATE: SELFTEST FAILED — an unknown test group passed" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a test group the catalog does not declare"
    fi

    rc=0
    ZCL_SPECIALISTS_ROOT="$stub_root" ZCL_SPECIALISTS_DEF="missing.def" \
        ZCL_SPECIALISTS_FLOOR=1 \
        bash "$REPO_ROOT/tools/lint/check_specialists.sh" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a missing .def did not exit 2 (rc=$rc)" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a missing .def exits 2"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (unknown territory, unknown gate, unknown group fail; a resolving row passes; a missing .def exits 2)"
    exit 0
fi

[ -f "$DEF" ] || {
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
}
[ -f "$CATALOG" ] || {
    echo "[$GATE] FATAL — $CATALOG is missing" >&2
    exit 2
}
[ -f "$MAKEFILE" ] || {
    echo "[$GATE] FATAL — $MAKEFILE is missing" >&2
    exit 2
}

rows="$(parse_rows "$DEF")"
row_count="$(printf '%s\n' "$rows" | grep -c . || true)"
if [ "$row_count" -lt "$FLOOR" ]; then
    echo "[$GATE] FATAL — $row_count specialist rows is below the floor of $FLOOR" >&2
    echo "        A catalog that stopped parsing must never read as clean." >&2
    exit 2
fi

faults="$(scan "$DEF")"
if [ -n "${faults//[[:space:]]/}" ]; then
    echo "[$GATE] FAIL — specialist catalog has false rows:"
    printf '%s\n' "$faults"
    exit 1
fi

echo "[$GATE] OK — $row_count specialists; every territory, gate and test group resolves"
exit 0
