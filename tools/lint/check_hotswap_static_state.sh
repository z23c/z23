#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_static_state.sh — every TU that can be recompiled into a
# hot-swap .so must define NO mutable file-scope statics. A generation/module
# .so recompiles the whole TU, so any mutable file-scope static becomes a fresh
# zero-initialized copy inside the .so — the live process state (registered
# routes, boot-populated main_state, atomic provider slots) is silently lost.
# No crash, just wrong answers. Resident state MUST live in a sibling
# non-eligible trampoline TU.
#
# SCAN SET = the UNION of the two manifests that can name a recompiled TU:
#   engine/composition/hotswap_eligible.def   HOTSWAP_ELIGIBLE("<tu>")   (generation .so)
#   engine/composition/hotswap_swappable.def  HOTSWAP_SWAPPABLE("<tu>",…) (module .so)
# Scanning only the eligible list was a silent hole: the two lists happened to
# name the same six files, so a swappable-only TU would have been swapped with
# zero-initialized module-level state and never tripped a gate.
#
# Heuristic (documented as acceptable): a file-scope line matching `^static`,
# NOT `const`, NOT a function declarator (no `(`), that either carries an
# initializer (`=`), declares an array (`[`), or opens an aggregate (ends `{`).
# A provably swap-safe static may carry a same-line escape comment:
#   hotswap-static-ok: <reason>
#
# Manifest paths are overridable via ZCL_HOTSWAP_MANIFEST /
# ZCL_HOTSWAP_SWAPPABLE_MANIFEST so the lint-gate self-test can point either at
# a seeded-violation manifest. Both are parsed with the same build-free,
# COLUMN-1, paren-depth walk used by
# tools/lint/check_privileged_transition_receipt.sh, so a multi-line macro
# invocation parses and a macro named in a header comment does not.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

MANIFEST="${ZCL_HOTSWAP_MANIFEST:-engine/composition/hotswap_eligible.def}"
SWAPPABLE="${ZCL_HOTSWAP_SWAPPABLE_MANIFEST:-engine/composition/hotswap_swappable.def}"
ISLANDS="${ZCL_HOTSWAP_ISLAND_MANIFEST:-engine/composition/hotswap_islands.def}"

echo "══ LINT: hot-swap recompiled TUs hold no mutable file-scope statics ══"

for m in "$MANIFEST" "$SWAPPABLE" "$ISLANDS"; do
    if [ ! -r "$m" ]; then
        echo "check_hotswap_static_state: FATAL — manifest '$m' missing/unreadable." >&2
        echo "  Refusing to report 'clean' with a manifest missing from the scan set." >&2
        exit 2
    fi
done

# Print the first string literal of every COLUMN-1 invocation of TOK.
FIRST_ARG_AWK='
{ buf = buf $0 "\n" }
END {
    n = length(buf); L = length(TOK)
    i = 1
    while (i <= n) {
        if (substr(buf, i, L) != TOK || (i > 1 && substr(buf, i - 1, 1) != "\n")) {
            i++; continue
        }
        j = i + L; depth = 1; in_str = 0; esc = 0; spec = ""
        while (j <= n && depth > 0) {
            c = substr(buf, j, 1)
            if (in_str) {
                if (esc) { esc = 0 }
                else if (c == "\\") { esc = 1 }
                else if (c == "\"") { in_str = 0 }
            } else {
                if (c == "\"") { in_str = 1 }
                else if (c == "(") { depth++ }
                else if (c == ")") { depth-- }
            }
            if (depth > 0) spec = spec c
            j++
        }
        if (match(spec, /"[^"]*"/)) print substr(spec, RSTART + 1, RLENGTH - 2)
        i = j
    }
}'

mapfile -t ELIGIBLE_PATHS < <(awk -v TOK='HOTSWAP_ELIGIBLE(' "$FIRST_ARG_AWK" "$MANIFEST")
mapfile -t SWAPPABLE_PATHS < <(awk -v TOK='HOTSWAP_SWAPPABLE(' "$FIRST_ARG_AWK" "$SWAPPABLE")

# The second string contains the space-separated implementation members.
SECOND_ARG_AWK="${FIRST_ARG_AWK/if (match(spec, \/\"[^\"]*\"\/)) print substr(spec, RSTART + 1, RLENGTH - 2)/if (match(spec, \/\"[^\"]*\"\/)) { spec = substr(spec, RSTART + RLENGTH); if (match(spec, \/\"[^\"]*\"\/)) print substr(spec, RSTART + 1, RLENGTH - 2) }}"
mapfile -t ISLAND_MEMBER_LISTS < <(awk -v TOK='HOTSWAP_ISLAND(' "$SECOND_ARG_AWK" "$ISLANDS")
ISLAND_PATHS=()
for members in "${ISLAND_MEMBER_LISTS[@]}"; do
    for p in $members; do ISLAND_PATHS+=("$p"); done
done

gate_require_scanned "${#ELIGIBLE_PATHS[@]}" 1 check_hotswap_static_state \
    "no HOTSWAP_ELIGIBLE(\"...\") entries parsed from $MANIFEST"
gate_require_scanned "${#SWAPPABLE_PATHS[@]}" 1 check_hotswap_static_state \
    "no HOTSWAP_SWAPPABLE(\"...\") entries parsed from $SWAPPABLE"
gate_require_scanned "${#ISLAND_PATHS[@]}" 1 check_hotswap_static_state \
    "no HOTSWAP_ISLAND implementation members parsed from $ISLANDS"

# Union, de-duplicated, deterministic order.
declare -A seen=()
PATHS=()
for p in "${ELIGIBLE_PATHS[@]}" "${SWAPPABLE_PATHS[@]}" "${ISLAND_PATHS[@]}"; do
    [ -n "$p" ] || continue
    [ -n "${seen[$p]:-}" ] && continue
    seen[$p]=1
    PATHS+=("$p")
done

gate_require_scanned "${#PATHS[@]}" 1 check_hotswap_static_state \
    "the union of $MANIFEST and $SWAPPABLE parsed to zero TUs"

# awk detector for one file: flag mutable file-scope statics per the heuristic.
detect_statics() {
    awk '
        /hotswap-static-ok:/ { next }         # explicit allowlist escape
        /^static[ \t]/ {
            line = $0
            if (line ~ /\<const\>/)   next     # immutable
            if (line ~ /\(/)          next     # function declarator/prototype
            if (line ~ /=/ || line ~ /\[/ || line ~ /\{[ \t]*$/)
                printf "%s:%d: %s\n", FILENAME, FNR, line
        }
    ' "$1"
}

violations=""
scanned=0
for p in "${PATHS[@]}"; do
    if [ ! -f "$p" ]; then
        echo "check_hotswap_static_state: FATAL — hot-swap TU '$p' does not exist." >&2
        echo "  A manifest drifted; refusing to pass off an unscannable file." >&2
        exit 2
    fi
    scanned=$((scanned + 1))
    hits="$(detect_statics "$p")"
    if [ -n "$hits" ]; then
        violations="${violations}${hits}"$'\n'
    fi
done

gate_require_scanned "$scanned" 1 check_hotswap_static_state "no hot-swap TU scanned"

if [ -n "${violations//[[:space:]]/}" ]; then
    printf '%s' "$violations"
    echo "FAIL: a hot-swap recompiled TU defines a mutable file-scope static."
    echo "  Move it to a sibling NON-eligible resident trampoline TU (a .so"
    echo "  gets its own zero copy), or, if provably swap-safe, annotate the"
    echo "  declaration line with a comment reading  hotswap-static-ok: <reason>."
    exit 1
fi

echo "  OK: $scanned hot-swap TU(s) free of mutable file-scope statics"
echo "      (${#ELIGIBLE_PATHS[@]} eligible + ${#SWAPPABLE_PATHS[@]} swappable + ${#ISLAND_PATHS[@]} island members, de-duplicated)"
exit 0
