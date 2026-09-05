#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fleet_observations.sh — engine/composition/fleet_observations.def is
# GENERATED, never hand-typed. It reproduces byte-for-byte from
# tests/fixtures/fleet_observations/rows.tsv through
# build/bin/z23-fleet-observe --check; a hand edit is a false statement about
# what the fleet has measured, and this gate is what catches it.
#
# Usage:
#   tools/lint/check_fleet_observations.sh
#   tools/lint/check_fleet_observations.sh --selftest
#
# Env:
#   ZCL_FLEET_OBS_ROOT   repo root (default: this script's repo)
#   ZCL_FLEET_OBS_BIN    the generator binary
#                        (default: build/bin/z23-fleet-observe)
#   ZCL_FLEET_OBS_FIXTURE  the committed fixture ledger
#                        (default: tests/fixtures/fleet_observations/rows.tsv)
#   ZCL_FLEET_OBS_DEF    the committed generated file
#                        (default: engine/composition/fleet_observations.def)
#
# Exit: 0 clean, 1 if the committed .def does not reproduce, 2 if the
# generator binary or the fixture is missing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_FLEET_OBS_ROOT:-$REPO_ROOT}"
BIN="${ZCL_FLEET_OBS_BIN:-build/bin/z23-fleet-observe}"
FIXTURE="${ZCL_FLEET_OBS_FIXTURE:-tests/fixtures/fleet_observations/rows.tsv}"
DEF="${ZCL_FLEET_OBS_DEF:-engine/composition/fleet_observations.def}"
GATE="check_fleet_observations"
DOC_REL="docs/agent/EXECUTOR_HEURISTICS.md"
DOC="$ROOT/$DOC_REL"
BEGIN_MARK="<!-- FLEET-OBSERVATIONS-BEGIN -->"
END_MARK="<!-- FLEET-OBSERVATIONS-END -->"

# The generated header embeds the --ledger path verbatim, so this gate always
# runs from ROOT with the relative fixture path — the same invocation anyone
# reproduces by hand, and stable across every checkout location.
cd "$ROOT" || { echo "[$GATE] FATAL — cannot cd to $ROOT" >&2; exit 2; }

# The doc block is this .def file's own rows, sorted the same way the
# generator sorts them (subject, object, relation), never a second listing
# kept by hand.
emit_doc() {
    echo "$BEGIN_MARK"
    echo
    echo "| Executor | Relation | Task class | n | window (days) |"
    echo "| --- | --- | --- | --- | --- |"
    awk '
    /^FLEET_OBSERVED\(/ {
        collecting = 1; buf = ""
    }
    collecting { buf = buf $0 }
    collecting && /\)[[:space:]]*$/ {
        collecting = 0
        n = 0; rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            parts[++n] = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
        }
        gsub(/[()]/, "", rest)
        split(rest, nv, ",")
        num = nv[2] + 0; den = nv[3] + 0; window = nv[4] + 0
        printf "%s\t%s\t%s\t%s/%s\t%s\n", parts[1], parts[2], parts[3], num, den, window
    }
    ' "$1" | LC_ALL=C sort -t$'\t' -k1,1 -k3,3 -k2,2 \
        | awk -F'\t' '{ printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5 }'
    echo
    echo "$END_MARK"
}

doc_block() { awk -v b="$BEGIN_MARK" -v e="$END_MARK" \
    'index($0,b){f=1} f{print} index($0,e){f=0}' "$DOC"; }

if [ "${1:-}" = "--write-doc" ]; then
    [ -f "$DEF" ] || { echo "[$GATE] FATAL — $DEF is missing" >&2; exit 2; }
    [ -f "$DOC" ] || { echo "[$GATE] FATAL — $DOC is missing" >&2; exit 2; }
    block="$(mktemp)"; merged="$(mktemp)"
    emit_doc "$DEF" > "$block"
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
    echo "[$GATE] wrote the observed-routing block in $DOC_REL from $DEF"
    exit 0
fi

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    fails=0

    if [ ! -x "$BIN" ]; then
        echo "$GATE: SELFTEST FAILED — generator binary '$BIN' is missing or not executable" >&2
        exit 1
    fi
    if [ ! -f "$FIXTURE" ]; then
        echo "$GATE: SELFTEST FAILED — fixture ledger '$FIXTURE' is missing" >&2
        exit 1
    fi

    good="$tmp/good.def"
    "$BIN" --ledger="$FIXTURE" --days=7 --out="$good" >/dev/null 2>&1
    if [ ! -s "$good" ]; then
        echo "$GATE: SELFTEST FAILED — a clean regeneration from the fixture produced nothing" >&2
        exit 1
    fi
    if "$BIN" --ledger="$FIXTURE" --days=7 --out="$good" --check >/dev/null 2>&1; then
        echo "  selftest ok: a fresh regeneration matches itself"
    else
        echo "$GATE: SELFTEST FAILED — a regeneration did not --check clean against itself" >&2
        fails=$((fails + 1))
    fi

    # A hand-edited row (den_ changed from 3 to 30) must fail --check.
    bad="$tmp/bad.def"
    sed 's/, 3, 7, /, 30, 7, /' "$good" > "$bad"
    if ! diff -q "$good" "$bad" >/dev/null 2>&1; then
        if "$BIN" --ledger="$FIXTURE" --days=7 --out="$bad" --check >/dev/null 2>&1; then
            echo "$GATE: SELFTEST FAILED — a hand-edited row passed --check" >&2
            fails=$((fails + 1))
        else
            echo "  selftest ok: a hand-edited row fails --check"
        fi
    else
        echo "$GATE: SELFTEST FAILED — the sed edit did not change the fixture copy" >&2
        fails=$((fails + 1))
    fi

    # A missing committed file must also fail --check (never read as clean).
    missing="$tmp/missing.def"
    if "$BIN" --ledger="$FIXTURE" --days=7 --out="$missing" --check >/dev/null 2>&1; then
        echo "$GATE: SELFTEST FAILED — a missing committed file passed --check" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a missing committed file fails --check"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (a fresh regeneration checks clean; a hand-edited row and a missing file both fail --check)"
    exit 0
fi

if [ ! -x "$BIN" ]; then
    echo "[$GATE] FATAL — $BIN is missing; run 'make build-only' first" >&2
    exit 2
fi
if [ ! -f "$FIXTURE" ]; then
    echo "[$GATE] FATAL — fixture ledger $FIXTURE is missing" >&2
    exit 2
fi
if [ ! -f "$DEF" ]; then
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
fi

out="$("$BIN" --ledger="$FIXTURE" --days=7 --out="$DEF" --check 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "[$GATE] FAIL — $DEF does not reproduce from $FIXTURE:"
    echo "$out"
    echo "  fix with: build/bin/z23-fleet-observe --ledger=$FIXTURE --days=7 --out=$DEF"
    exit 1
fi

if [ -f "$DOC" ]; then
    if ! diff -q <(emit_doc "$DEF") <(doc_block) >/dev/null 2>&1; then
        echo "[$GATE] FAIL — $DOC_REL's observed-routing block is not this .def's own output"
        echo "  fix with: make docs-executor-routing"
        exit 1
    fi
else
    echo "[$GATE] FATAL — $DOC_REL is missing, so the observed-routing block cannot be checked" >&2
    exit 2
fi

echo "[$GATE] OK — $out; $DOC_REL renders this table"
exit 0
