#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Gate — command-availability truthfulness (HARD). Sibling of
# check_command_contract.sh, same scan shape, different predicate.
#
# The typed command surface is declared in engine/composition/commands/*.def and expanded
# by engine/composition/src/command_catalog.c into one immutable g_catalog_commands[].
# Every leaf carries an `availability` (READY / COMPAT / PLANNED, see
# engine/modules/kernel/include/kernel/command_registry.h) that the engine acts on: a
# READY leaf is dispatched to its handler, a PLANNED leaf is fail-closed with
# a typed BLOCKED reply that quotes its `availability_reason`.
#
# Two ways that declaration can LIE, both compile clean:
#
#   1. A READY leaf that binds no handler. `discover help` advertises it as
#      executable, the operator invokes it, and the engine has nothing to
#      call. READY with a NULL handler is a promise the binary cannot keep.
#
#   2. A PLANNED leaf with an empty availability_reason. The refusal is
#      honest about REFUSING but says nothing about WHY, so the operator
#      cannot tell "not built yet" from "your node is misconfigured" and has
#      no next move. This codebase forbids a stall that does not name its
#      blocker; an unexplained refusal is that same silent stall wearing a
#      typed error's clothes.
#
# The same rule extends to the two neighbouring shapes:
#   - COMPAT leaves refuse natively and redirect; a COMPAT leaf that names no
#     compat_target (and, for COMPAT_COMMAND, no reason) is the same dead end.
#   - DEV leaves are READY in a dev build (ZCL_DEV_BUILD) and COMPAT in a
#     release build, so their handler must be non-NULL for the same reason
#     as (1) and their release reason/target non-empty for the same reason
#     as (2).
#
# Anti-hollow: the leaf population is parsed, not grepped, and the realized
# per-shape counts are floor-gated (gate_require_scanned). The parser also
# asserts each macro's ARITY against the grammar in command_catalog.c — if a
# macro gains or loses an argument, this gate aborts LOUD (exit 2) rather
# than silently reading the wrong slot and reporting a clean scan.

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

# Scan root overridable so a self-test can point at a planted fixture;
# production scans the command catalog fragments.
DEF_DIR="${ZCL_COMMAND_AVAILABILITY_DIR:-engine/composition/commands}"

mapfile -t def_files < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null | sort)
gate_require_scanned "${#def_files[@]}" 1 check_command_availability_truthful \
    "no *.def under: $DEF_DIR"

MODE="${ZCL_LINT_MODE:-FAIL}"

# Floors. Production carries 224 leaves (139 READY_READ + 43 READY_COMMAND +
# 12 PLANNED_READ + 13 PLANNED_COMMAND + 10 DEV_READ + 6 DEV_COMMAND + 1
# COMPAT_READ). Floors sit below the live counts with headroom so an ordinary
# addition never trips them, but an emptied/renamed fragment does. A self-test
# fixture dir sets its own floors.
READY_FLOOR="${ZCL_COMMAND_AVAILABILITY_READY_FLOOR:-160}"
PLANNED_FLOOR="${ZCL_COMMAND_AVAILABILITY_PLANNED_FLOOR:-18}"

# The parser: one character-level pass per file, tracking C block comments and
# string literals so a macro name inside prose (or a comma inside a string
# literal, of which the catalog has many) is never mistaken for structure.
AWK_OUT=$(awk '
function trim(s) {
    gsub(/^[ \t\r\n]+/, "", s); gsub(/[ \t\r\n]+$/, "", s); return s
}
# Concatenated string literals with the quotes removed and all whitespace
# squeezed out: non-empty iff the argument says something.
function literal_body(s,   t) {
    t = s; gsub(/\\"/, "", t); gsub(/"/, "", t); gsub(/[ \t\r\n]/, "", t)
    return t
}
function pathof(   p) { p = args[1]; gsub(/"/, "", p); return trim(p) }
function violation(msg) {
    printf "V\t%s\t%d\t%s\t%s\t%s\n", startfile, startline, mtype, pathof(), msg
    nviol++
}
function fatal(msg) {
    printf "FATAL\t%s\t%d\t%s\t%s\n", startfile, startline, mtype, msg
    nfatal++
}
function want_arity(n) {
    if (nargs != n) {
        fatal(sprintf("macro grammar drift: expected %d arguments, parsed %d." \
              " Re-read the macro definition in engine/composition/src/command_catalog.c" \
              " and fix this gate before trusting it.", n, nargs))
        return 0
    }
    return 1
}
function check_handler(idx,   h) {
    h = trim(args[idx])
    if (h == "" || h == "NULL" || h == "0") {
        violation(sprintf("declares availability READY but binds no handler" \
                  " (handler argument is \"%s\"): the catalog advertises an" \
                  " executable command the engine cannot dispatch.", h))
    }
}
function check_reason(idx, what,   r) {
    if (literal_body(args[idx]) == "") {
        violation(sprintf("refuses without saying why: %s is empty. A typed" \
                  " refusal with no stated cause is a silent stall; name the" \
                  " exact missing code path.", what))
    }
}
function finish_leaf() {
    nleaf++
    if (mtype == "ZCL_COMMAND_READY_READ") {
        nready++;   if (want_arity(22)) check_handler(22)
    } else if (mtype == "ZCL_COMMAND_READY_COMMAND") {
        nready++;   if (want_arity(25)) check_handler(25)
    } else if (mtype == "ZCL_COMMAND_DEV_READ") {
        nready++
        if (want_arity(22)) { check_handler(20)
            check_reason(21, "the release-build availability_reason")
            check_reason(22, "the release-build compat_target") }
    } else if (mtype == "ZCL_COMMAND_DEV_COMMAND") {
        nready++
        if (want_arity(26)) { check_handler(24)
            check_reason(25, "the release-build availability_reason")
            check_reason(26, "the release-build compat_target") }
    } else if (mtype == "ZCL_COMMAND_PLANNED_READ") {
        nplanned++; if (want_arity(20)) check_reason(20, "availability_reason")
    } else if (mtype == "ZCL_COMMAND_PLANNED_COMMAND") {
        nplanned++; if (want_arity(25)) check_reason(25, "availability_reason")
    } else if (mtype == "ZCL_COMMAND_COMPAT_READ") {
        nplanned++; if (want_arity(21)) check_reason(21, "compat_target")
    } else if (mtype == "ZCL_COMMAND_COMPAT_COMMAND") {
        nplanned++
        if (want_arity(26)) { check_reason(25, "availability_reason")
                              check_reason(26, "compat_target") }
    }
}
BEGIN {
    MACRO["ZCL_COMMAND_READY_READ"] = 1
    MACRO["ZCL_COMMAND_READY_COMMAND"] = 1
    MACRO["ZCL_COMMAND_PLANNED_READ"] = 1
    MACRO["ZCL_COMMAND_PLANNED_COMMAND"] = 1
    MACRO["ZCL_COMMAND_COMPAT_READ"] = 1
    MACRO["ZCL_COMMAND_COMPAT_COMMAND"] = 1
    MACRO["ZCL_COMMAND_DEV_READ"] = 1
    MACRO["ZCL_COMMAND_DEV_COMMAND"] = 1
    in_comment = 0; in_str = 0; esc = 0; collecting = 0; tok = ""
    nleaf = 0; nready = 0; nplanned = 0; nviol = 0; nfatal = 0
}
FNR == 1 { in_comment = 0; in_str = 0; collecting = 0; tok = "" }
{
    line = $0 "\n"
    n = length(line)
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (in_comment) {
            if (c == "*" && substr(line, i + 1, 1) == "/") { in_comment = 0; i++ }
            continue
        }
        if (in_str) {
            if (collecting) cur = cur c
            if (esc) esc = 0
            else if (c == "\\") esc = 1
            else if (c == "\"") in_str = 0
            continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { in_comment = 1; i++; continue }
        if (c == "\"") { in_str = 1; esc = 0; if (collecting) cur = cur c; continue }
        if (collecting) {
            if (c == "(") { depth++; cur = cur c; continue }
            if (c == ")") {
                depth--
                if (depth == 0) {
                    args[++nargs] = cur; cur = ""; collecting = 0; finish_leaf()
                } else cur = cur c
                continue
            }
            if (c == "," && depth == 1) { args[++nargs] = cur; cur = ""; continue }
            cur = cur c
            continue
        }
        if (c ~ /[A-Za-z0-9_]/) { tok = tok c; continue }
        if (c == "(" && (tok in MACRO)) {
            mtype = tok; collecting = 1; depth = 1; nargs = 0; cur = ""
            delete args
            startfile = FILENAME; startline = FNR
            tok = ""
            continue
        }
        tok = ""
    }
}
END {
    if (collecting)
        printf "FATAL\t%s\t%d\t%s\t%s\n", startfile, startline, mtype, \
               "unterminated macro invocation: the parser reached EOF with an open argument list."
    printf "COUNTS\t%d\t%d\t%d\t%d\t%d\n", nleaf, nready, nplanned, nviol, nfatal
}
' "${def_files[@]}")

COUNTS_LINE=$(printf '%s\n' "$AWK_OUT" | grep '^COUNTS' || true)
if [ -z "$COUNTS_LINE" ]; then
    echo "check_command_availability_truthful: FATAL — the parser produced no" >&2
    echo "  COUNTS record; refusing to report PASS off a broken scan." >&2
    exit 2
fi
IFS=$'\t' read -r _ LEAF_COUNT READY_COUNT PLANNED_COUNT VIOL_COUNT FATAL_COUNT \
    <<< "$COUNTS_LINE"

FATALS=$(printf '%s\n' "$AWK_OUT" | grep '^FATAL' || true)
if [ "$FATAL_COUNT" -gt 0 ] || [ -n "${FATALS//[[:space:]]/}" ]; then
    printf '%s\n' "$FATALS" | awk -F'\t' 'NF>1 {printf "  %s:%s: %s — %s\n", $2, $3, $4, $5}' >&2
    echo "check_command_availability_truthful: FATAL — macro grammar drift." >&2
    echo "  This gate reads a fixed argument slot per macro shape. A changed" >&2
    echo "  arity means it would be reading the WRONG slot, so it refuses to" >&2
    echo "  report a verdict at all. Fix the arity table in this script" >&2
    echo "  against engine/composition/src/command_catalog.c." >&2
    exit 2
fi

gate_require_scanned "$READY_COUNT" "$READY_FLOOR" \
    check_command_availability_truthful \
    "READY/DEV leaf population collapsed under floor (parsed $READY_COUNT)"
gate_require_scanned "$PLANNED_COUNT" "$PLANNED_FLOOR" \
    check_command_availability_truthful \
    "PLANNED/COMPAT leaf population collapsed under floor (parsed $PLANNED_COUNT)"

VIOLATIONS=$(printf '%s\n' "$AWK_OUT" | grep '^V' || true)
if [ "$VIOL_COUNT" -gt 0 ]; then
    printf '%s\n' "$VIOLATIONS" \
        | awk -F'\t' 'NF>1 {printf "%s:%s: %s leaf %s\n    %s\n", $2, $3, $4, $5, $6}'
    echo "[check_command_availability_truthful] $VIOL_COUNT leaf(s) whose" \
         "declared availability does not match what the catalog binds" \
         "(mode: $MODE)"
    echo "  A READY leaf must bind a non-NULL handler; a PLANNED/COMPAT leaf"
    echo "  must state a non-empty availability_reason (and a COMPAT leaf its"
    echo "  compat_target). See engine/modules/kernel/include/kernel/command_registry.h"
    echo "  (enum zcl_command_availability) and engine/composition/commands/README.md."
    if [ "$MODE" = "FAIL" ]; then exit 1; fi
fi

echo "[check_command_availability_truthful] PASS ($LEAF_COUNT leaves:" \
     "$READY_COUNT executable — all bind a handler; $PLANNED_COUNT refusing —" \
     "all name a cause)"
