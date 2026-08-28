#!/usr/bin/env bash
# check-api-reference-generated — docs/API_REFERENCE.md must be the exact output
# of tools/gen_api_reference.c over config/commands/*.def.
#
# Why this gate exists. The command reference used to say of itself that every
# row was "transcribed directly from the declarative .def files" — by hand. A
# hand transcription of a 290-entry table drifts the first time a leaf is added
# or promoted, and it did: the page claimed 106 leaves across 41 branches long
# after the catalog had grown past twice that. A doc that names a `ready`
# command that is actually `planned` costs an agent a whole loop.
#
# Mechanism: compile the generator, run it into a temp file, diff. No `make`
# is invoked (the umbrella already runs gates in parallel), and nothing here
# reads git, so the gate works the same inside the lint sandbox copy.
#
# To fix a failure: edit config/commands/*.def (the catalog) or
# docs/API_REFERENCE.md.in (the editorial template), then run
#   make docs-api-reference
# Never hand-edit docs/API_REFERENCE.md — it is generated output.
#
# --selftest plants a one-line hand edit in a sandbox copy of the doc and
# proves this gate FAILS on it, so the gate cannot rot into a no-op.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

GEN_SRC="tools/gen_api_reference.c"
TEMPLATE="docs/API_REFERENCE.md.in"
DOC="docs/API_REFERENCE.md"
DEF_DIR="config/commands"

# Floors: the generator's scan set is the .def catalog. If those files vanish
# or move, refuse to report clean off an empty catalog.
#
# DEF_FLOOR covers the whole catalog including the nested bundles. It was 8
# when every .def sat directly in config/commands/; the nested
# config/commands/telemetry/ bundles pushed the real set past 20, and a floor
# left at 8 would have gone on passing with all ten of them deleted.
DEF_FLOOR=20
ENTRY_FLOOR=200

# The generator's scan set is exactly what it #includes — derive the list from
# the generator itself rather than globbing $DEF_DIR.
#
# A glob of "$DEF_DIR"/*.def is wrong twice over: it misses the nested bundles
# under config/commands/telemetry/ (which is how the selftest sandbox came to
# be built without them, so the sandbox compile failed for a reason that had
# nothing to do with the edit it was planting), and it counts .def files the
# generator does not include at all. config/commands/store.def was exactly
# that — present, compiled into the real catalog, absent from this generator,
# and therefore missing from the published reference while a flat glob happily
# counted it as covered.
def_rel_list() {
    sed -nE 's|^[[:space:]]*#include[[:space:]]+"\.\./(config/commands/[A-Za-z0-9_/]+\.def)".*|\1|p' \
        "$GEN_SRC" | sort -u
}

run_selftest() {
    local tmp sandbox out rc
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-apiref-selftest.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT HUP INT TERM
    sandbox="$tmp/repo"
    mkdir -p "$sandbox"
    # Hardlink-free copy of just what the gate reads.
    mkdir -p "$sandbox/tools/lint" "$sandbox/docs" "$sandbox/$DEF_DIR" \
             "$sandbox/lib/kernel/include/kernel" "$sandbox/lib/json/include/json"
    cp "$GEN_SRC" "$sandbox/tools/"
    cp "$SCRIPT_DIR/check_api_reference_generated.sh" "$sandbox/tools/lint/"
    cp "$SCRIPT_DIR/gate_lib.sh" "$sandbox/tools/lint/"
    cp "$TEMPLATE" "$DOC" "$sandbox/docs/"
    # Every .def the generator includes, at its own relative path so the
    # nested bundles resolve. Copying a flat glob here silently produced a
    # sandbox the generator could not compile in.
    while IFS= read -r rel; do
        mkdir -p "$sandbox/$(dirname "$rel")"
        cp "$rel" "$sandbox/$rel"
    done < <(def_rel_list)
    cp lib/kernel/include/kernel/command_registry.h \
       "$sandbox/lib/kernel/include/kernel/"
    cp lib/json/include/json/json.h "$sandbox/lib/json/include/json/"

    out="$tmp/clean.log"
    if ! (cd "$sandbox" && bash tools/lint/check_api_reference_generated.sh) \
            > "$out" 2>&1; then
        echo "check_api_reference_generated selftest: FAIL — the gate did not" >&2
        echo "  pass on an unmodified copy of the tree:" >&2
        sed 's/^/    /' "$out" >&2
        exit 1
    fi

    # Plant a hand edit: flip one availability cell.
    if ! grep -q '| planned |' "$sandbox/$DOC"; then
        echo "check_api_reference_generated selftest: FAIL — no 'planned' row" >&2
        echo "  to tamper with; the fixture assumption broke." >&2
        exit 1
    fi
    # Flip the FIRST availability cell via an awk rewrite: GNU's
    # `sed -i '0,/re/s//.../'` does not exist on BSD sed, which would treat
    # the program string as an in-place backup suffix and mutate nothing
    # (the selftest then passed for the wrong reason — hollow).
    FROM='| planned |'
    TO='| ready |'
    awk -v from="$FROM" -v to="$TO" '
        BEGIN { done = 0 }
        !done && (i = index($0, from)) {
            print substr($0, 1, i - 1) to substr($0, i + length(from))
            done = 1
            next
        }
        { print }
    ' "$sandbox/$DOC" > "$sandbox/$DOC.next" \
        && mv "$sandbox/$DOC.next" "$sandbox/$DOC"

    out="$tmp/tampered.log"
    rc=0
    (cd "$sandbox" && bash tools/lint/check_api_reference_generated.sh) \
        > "$out" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "check_api_reference_generated selftest: FAIL — a hand edit to" >&2
        echo "  $DOC did NOT trip the gate. The gate is hollow." >&2
        exit 1
    fi
    if ! grep -q "$DOC" "$out"; then
        echo "check_api_reference_generated selftest: FAIL — the failure did" >&2
        echo "  not name $DOC:" >&2
        sed 's/^/    /' "$out" >&2
        exit 1
    fi
    echo "check_api_reference_generated selftest: PASS — clean tree passes," \
         "a planted hand edit fails and names $DOC"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

for required in "$GEN_SRC" "$TEMPLATE" "$DOC"; do
    if [ ! -f "$required" ]; then
        echo "check_api_reference_generated: FATAL — missing $required" >&2
        exit 2
    fi
done

# wc -l, not `grep -c .`: under `set -o pipefail` a grep that matches nothing
# exits 1 and takes the whole command substitution down, turning "the catalog
# is empty" into an unexplained gate crash instead of the floor message below.
def_count=$(def_rel_list | wc -l)
missing=0
while IFS= read -r rel; do
    if [ ! -f "$rel" ]; then
        echo "check_api_reference_generated: FATAL — $GEN_SRC includes $rel," \
             "which does not exist" >&2
        missing=1
    fi
done < <(def_rel_list)
[ "$missing" -eq 0 ] || exit 2

gate_require_scanned "$def_count" "$DEF_FLOOR" check_api_reference_generated \
    "no .def catalogs included by $GEN_SRC — the command catalog moved?"

# The generator must include every .def the real catalog does, or a whole
# bundle of live commands goes unpublished with nothing to notice: this gate
# diffs the generator's output against a page the same generator wrote, so a
# bundle absent from both sides matches perfectly. app.store.{catalog,order,
# pay,purchases,collect} shipped ready-and-undocumented that way.
CATALOG_SRC="config/src/command_catalog.c"
if [ -f "$CATALOG_SRC" ]; then
    unpublished=$(comm -23 \
        <(sed -nE 's|^[[:space:]]*#include[[:space:]]+"\.\./(commands/[A-Za-z0-9_/]+\.def)".*|config/\1|p' \
              "$CATALOG_SRC" | sort -u) \
        <(def_rel_list) || true)
    if [ -n "$unpublished" ]; then
        echo "check_api_reference_generated: FAIL — $CATALOG_SRC compiles these" \
             ".def bundles into the binary but $GEN_SRC does not include them," >&2
        echo "  so every command they declare is missing from $DOC:" >&2
        echo "$unpublished" | sed 's/^/    /' >&2
        echo "  Add a matching ZCL_DEF_FILE block to $GEN_SRC." >&2
        exit 1
    fi
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-apiref.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -std=c23 -O0 -Wall -Wextra -Werror \
        -Ilib/kernel/include -Ilib/json/include \
        -o "$TMP/gen_api_reference" "$GEN_SRC" 2> "$TMP/cc.log"; then
    echo "check_api_reference_generated: FATAL — $GEN_SRC does not compile:" >&2
    sed 's/^/    /' "$TMP/cc.log" >&2
    exit 2
fi

if ! "$TMP/gen_api_reference" "$TEMPLATE" "$TMP/expected.md" \
        2> "$TMP/gen.log"; then
    echo "check_api_reference_generated: FATAL — the generator failed:" >&2
    sed 's/^/    /' "$TMP/gen.log" >&2
    exit 2
fi

entries="$(sed -n 's/^gen_api_reference: \([0-9]\{1,\}\) catalog entries.*/\1/p' \
    "$TMP/gen.log" | head -1)"
gate_require_scanned "${entries:-0}" "$ENTRY_FLOOR" \
    check_api_reference_generated \
    "the generator emitted almost no catalog entries — the X-macro expansion broke"

if ! diff -u "$DOC" "$TMP/expected.md" > "$TMP/diff.txt" 2>&1; then
    echo "FAIL: $DOC is not what tools/gen_api_reference.c produces." >&2
    echo "" >&2
    echo "  $DOC is GENERATED output. Do not edit it by hand." >&2
    echo "  Change the catalog ($DEF_DIR/*.def) or the editorial template" >&2
    echo "  ($TEMPLATE), then regenerate:" >&2
    echo "" >&2
    echo "      make docs-api-reference" >&2
    echo "" >&2
    echo "  Drift (checked-in '-' vs generated '+'), first 60 lines:" >&2
    head -60 "$TMP/diff.txt" | sed 's/^/    /' >&2
    exit 1
fi

echo "check_api_reference_generated: clean — $DOC matches the generator over" \
     "$def_count .def catalog(s) / $entries entries"
exit 0
