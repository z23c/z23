#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Gate — declared `input_keys` vs. the keys the handler actually READS.
#
# THE BUG THIS EXISTS TO CATCH (reproduced live, 2026-07-29):
#
#   $ z23 zcode package publish plan --input='{"release_hex":"00",
#       "manifest_hex":"00","dir":"/tmp","recipe_hex":"00"}'
#   -> {"code":"INVALID_INPUT","message":"unknown input key 'recipe_hex'"}
#
# The handler REQUIRED recipe_hex (a missing one is the named publication
# failure recipe-missing) but the leaf's `input_keys` CSV never listed it, and
# zcl_command_registry_input_validate() rejects any key not in that CSV. Pass
# it -> INVALID_INPUT. Omit it -> RECIPE_MISSING. The command was UNCALLABLE
# from the real CLI, in every build, for every operator — and nothing failed,
# because the tests called the handler function directly and so never crossed
# input_validate. Package publication, the entrance to the whole ZCODE
# library, had no door.
#
# WHY check_command_contract.sh DOES NOT COVER THIS — the two gates share a
# scan set and nothing else. check_command_contract asserts that one leaf
# field is non-empty (`semantics`, the OUTPUT-interpretation contract): a
# purely INTRA-declaration predicate, decided by reading the .def alone; it
# never opens a handler. This gate is a CROSS-artifact agreement — it reads
# the .def AND the C the .def binds, and asserts the INPUT contract the
# kernel enforces at runtime is a superset of what the code consumes. A leaf
# can pass check_command_contract with a flawless `semantics` paragraph and
# still be uninvokable; zcode.package.publish.plan did exactly that for its
# whole life. Neither gate subsumes the other; do not merge them.
#
# WHAT IS CHECKED, per READY/DEV leaf that binds a handler bound by exactly
# one leaf (see the dispatcher note below):
#
#   read-but-not-declared  -> FAIL. The key is unreachable: the kernel
#                             rejects it before the handler ever runs.
#   declared-but-not-read  -> WARN, never gated. The catalog advertises an
#                             input whose name appears nowhere in the
#                             handler's code. Warned rather than failed
#                             because the extraction below is deliberately
#                             conservative in the OTHER direction.
#
# HOW THE READ SET IS EXTRACTED (and the honest limits of a static scan):
#
#   1. Any call `f(<expr naming the input object>, "KEY"` — that covers every
#      accessor form in the tree: json_get / json_get_str_or /
#      json_get_bool_or / json_get_int_or plus the ~15 per-file `*_input_str`
#      / `*_input_int` / `*_require_*` helpers. The rule keys off the
#      ARGUMENT, not a hardcoded accessor list, so a sixteenth helper is
#      covered the day it is written. `const struct json_value *in =
#      request->input;` is followed: any local assigned from an expression
#      naming `input` counts as the input object too.
#   2. `static const char *const NAME[] = {"a","b"};` where NAME is handed,
#      in the same statement as an input expression, to a call — the vault's
#      forward-exactly-these-keys shape.
#   3. Transitive closure over callees defined in the scanned files, so a
#      handler that only reaches `datadir` through a shared
#      `zc_datadir(request)` helper still counts it.
#
#   NOT seen: a key named by a runtime variable (`json_get(in, key)` with a
#   computed key). Invisible to any static scan — and it can only cause a
#   MISSED violation, never a false one, which is why the FAILING direction
#   is the conservative one.
#
# SHARED DISPATCHERS. One handler bound by MANY leaves (zcl_native_bridge_-
# command is bound by ~40) reads the union of every bridged leaf's keys and
# routes on the invoked path. Nothing static can attribute one of those reads
# to one leaf, so those leaves are excluded from the failing direction and
# the excluded count is PRINTED — a known blind spot, stated, not hidden.
#
# One thing about them IS attributable, and is gated:
#
#   same handler + same input schema, different input_keys -> FAIL.
#
# Two leaves that bind one handler AND declare one input schema are a single
# contract under two names; routing on the invoked path cannot justify
# different inputs, because the schema states the inputs are the same. The
# leaf missing a key answers INVALID_INPUT for an input its twin accepts.
# LIVE: zcode.work.show and zcode.work.status both bind
# zcl_native_handle_zcode_work_status under zcl.zcode_work_status.input.v1,
# the handler reads `datadir`, and only `status` declared it — so
# `zcode work show --input='{"datadir":...}'` was uninvokable while the
# identical `zcode work status` worked. The exclusion above is what hid it.
#
# Grandfathered violations live in the baseline (shrink-only, the same
# ratchet as check_route_command_parity): a NEW read-but-not-declared key
# FAILS, and a baseline line whose violation is gone must be deleted in the
# same commit.
#
# Anti-hollow: leaf, handler-resolution and function-index populations are
# each floor-gated, and a macro-arity change aborts LOUD (exit 2) rather than
# reading the wrong argument slot off a changed grammar.
#
# Env: ZCL_COMMAND_INPUT_KEYS_VERBOSE=1 lists every declared-but-not-read key
# (the summary line always reports how many there are).

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

DEF_DIR="${ZCL_COMMAND_INPUT_KEYS_DEF_DIR:-engine/composition/commands}"
BASELINE="${ZCL_COMMAND_INPUT_KEYS_BASELINE:-tools/lint/command_input_keys_baseline.txt}"
MODE="${ZCL_LINT_MODE:-FAIL}"
VERBOSE="${ZCL_COMMAND_INPUT_KEYS_VERBOSE:-0}"

# Floors sit below the live populations with headroom: an ordinary addition
# never trips them, an emptied or renamed producer does.
LEAF_FLOOR="${ZCL_COMMAND_INPUT_KEYS_LEAF_FLOOR:-160}"
FN_FLOOR="${ZCL_COMMAND_INPUT_KEYS_FN_FLOOR:-400}"
BOUND_FLOOR="${ZCL_COMMAND_INPUT_KEYS_BOUND_FLOOR:-150}"
RESOLVED_FLOOR="${ZCL_COMMAND_INPUT_KEYS_RESOLVED_FLOOR:-100}"

mapfile -t def_files < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null | sort)
gate_require_scanned "${#def_files[@]}" 1 check_command_input_keys \
    "no *.def under: $DEF_DIR"

# ── Phase 1: parse the leaf macros ────────────────────────────────────────
# One LEAF record per handler-binding leaf:
#   LEAF <path> <file> <line> <macro> <input_keys> <positional_keys> <handler>
# `input_keys` is argument 10 and `positional_keys` argument 11 in EVERY leaf
# macro shape (engine/composition/src/command_catalog.c); the handler slot differs per
# shape, and each shape's arity is asserted before any slot is read.
DEF_OUT=$(awk '
function trim(s) { gsub(/^[ \t\r\n]+/, "", s); gsub(/[ \t\r\n]+$/, "", s); return s }
# A concatenated string-literal argument -> its body with quotes and all
# whitespace removed ("a," "b" -> a,b). Input keys never contain spaces.
function literal(s,   t) {
    t = s; gsub(/\\"/, "", t); gsub(/"/, "", t); gsub(/[ \t\r\n]/, "", t)
    return t
}
function fatal(msg) {
    printf "FATAL\t%s\t%d\t%s\t%s\n", startfile, startline, mtype, msg
}
function want_arity(n) {
    if (nargs != n) {
        fatal(sprintf("macro grammar drift: expected %d arguments, parsed %d." \
              " This gate reads fixed argument slots; re-read the macro in" \
              " engine/composition/src/command_catalog.c and fix the arity table here.", \
              n, nargs))
        return 0
    }
    return 1
}
function emit(handler_idx,   h) {
    h = trim(args[handler_idx])
    if (h == "" || h == "NULL" || h == "0") return
    nbound++
    printf "LEAF\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", literal(args[1]), \
           startfile, startline, mtype, literal(args[10]), literal(args[11]), \
           h, literal(args[8]), literal(args[9])
}
function finish_leaf(ok) {
    nleaf++
    if (mtype == "ZCL_COMMAND_READY_READ")          { if (want_arity(22)) emit(22) }
    else if (mtype == "ZCL_COMMAND_READY_COMMAND")  { if (want_arity(25)) emit(25) }
    else if (mtype == "ZCL_COMMAND_DEV_READ")       { if (want_arity(22)) emit(20) }
    else if (mtype == "ZCL_COMMAND_DEV_COMMAND")    { if (want_arity(26)) emit(24) }
    else if (mtype == "ZCL_COMMAND_PLANNED_READ")   { ok = want_arity(20) }
    else if (mtype == "ZCL_COMMAND_PLANNED_COMMAND"){ ok = want_arity(25) }
    else if (mtype == "ZCL_COMMAND_COMPAT_READ")    { ok = want_arity(21) }
    else if (mtype == "ZCL_COMMAND_COMPAT_COMMAND") { ok = want_arity(26) }
}
BEGIN {
    split("ZCL_COMMAND_READY_READ ZCL_COMMAND_READY_COMMAND " \
          "ZCL_COMMAND_PLANNED_READ ZCL_COMMAND_PLANNED_COMMAND " \
          "ZCL_COMMAND_COMPAT_READ ZCL_COMMAND_COMPAT_COMMAND " \
          "ZCL_COMMAND_DEV_READ ZCL_COMMAND_DEV_COMMAND", mm, " ")
    for (i in mm) MACRO[mm[i]] = 1
    in_comment = 0; in_str = 0; esc = 0; collecting = 0; tok = ""
    nleaf = 0; nbound = 0
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
                if (depth == 0) { args[++nargs] = cur; cur = ""; collecting = 0; finish_leaf() }
                else cur = cur c
                continue
            }
            if (c == "," && depth == 1) { args[++nargs] = cur; cur = ""; continue }
            cur = cur c
            continue
        }
        if (c ~ /[A-Za-z0-9_]/) { tok = tok c; continue }
        if (c == "(" && (tok in MACRO)) {
            mtype = tok; collecting = 1; depth = 1; nargs = 0; cur = ""
            delete args; startfile = FILENAME; startline = FNR; tok = ""
            continue
        }
        tok = ""
    }
}
END {
    if (collecting)
        printf "FATAL\t%s\t%d\t%s\t%s\n", startfile, startline, mtype, \
               "unterminated macro invocation: EOF with an open argument list."
    printf "COUNTS\t%d\t%d\n", nleaf, nbound
}
' "${def_files[@]}")

DEF_FATALS=$(printf '%s\n' "$DEF_OUT" | grep '^FATAL' || true)
if [ -n "${DEF_FATALS//[[:space:]]/}" ]; then
    printf '%s\n' "$DEF_FATALS" \
        | awk -F'\t' 'NF>1 {printf "  %s:%s: %s — %s\n", $2, $3, $4, $5}' >&2
    echo "check_command_input_keys: FATAL — command macro grammar drift." >&2
    exit 2
fi
DEF_COUNTS=$(printf '%s\n' "$DEF_OUT" | grep '^COUNTS' || true)
if [ -z "$DEF_COUNTS" ]; then
    echo "check_command_input_keys: FATAL — the .def parser produced no" >&2
    echo "  COUNTS record; refusing to report a verdict off a broken scan." >&2
    exit 2
fi
IFS=$'\t' read -r _ LEAF_COUNT BOUND_COUNT <<< "$DEF_COUNTS"
gate_require_scanned "$LEAF_COUNT" "$LEAF_FLOOR" check_command_input_keys \
    "leaf population collapsed under floor (parsed $LEAF_COUNT)"
gate_require_scanned "$BOUND_COUNT" "$BOUND_FLOOR" check_command_input_keys \
    "handler-binding leaf population collapsed under floor (parsed $BOUND_COUNT)"

LEAVES=$(printf '%s\n' "$DEF_OUT" | grep '^LEAF' || true)

# ── Phase 2: locate the C that defines those handlers ─────────────────────
HANDLER_PAT=$(mktemp)
SRC_LIST=$(mktemp)
trap 'rm -f "$HANDLER_PAT" "$SRC_LIST"' EXIT
printf '%s\n' "$LEAVES" | awk -F'\t' 'NF>1 {print $8 "("}' | sort -u > "$HANDLER_PAT"
gate_require_scanned "$(wc -l < "$HANDLER_PAT")" "$RESOLVED_FLOOR" \
    check_command_input_keys "no handler symbols parsed out of $DEF_DIR/*.def"

# Fixed-string, one pass. Files that merely CALL a handler come along too;
# indexing them is harmless (they contribute functions nobody's closure reaches).
set +e
git grep -lFf "$HANDLER_PAT" -- '*.c' > "$SRC_LIST"
grc=$?
set -e
if [ "$grc" -ge 2 ]; then
    echo "check_command_input_keys: FATAL — git grep for handler definitions" >&2
    echo "  failed (exit $grc); refusing to report a verdict." >&2
    exit 2
fi
mapfile -t src_files < "$SRC_LIST"
gate_require_scanned "${#src_files[@]}" 5 check_command_input_keys \
    "no .c file names any registered handler symbol — the handler naming or the source layout moved; re-point this gate."

# ── Phase 3: index every C function -> keys read, literals, callees ───────
# One character-level pass (comments stripped, string literals kept),
# brace-matched. A function body starts at a `{` at brace depth 0 whose
# previous non-space character is `)` — that distinguishes a definition from
# a file-scope aggregate initializer (`... = {`).
FN_OUT=$(awk '
function iskey(s) { return s ~ /^[a-z][a-z0-9_-]{0,63}$/ }
function flush_fn(   b, m, j, key, aliasre, pat, arrname, arrbody, i, ns, st) {
    if (fname == "") { body = ""; return }
    nfn++
    keys = ""; lits = ""; calls = ""
    # Locals assigned from an expression naming the input OBJECT. Two
    # restrictions keep this from over-reaching:
    #   - `input` must appear as a WHOLE token on the right-hand side, or
    #     `struct zr_score_inputs *in = zcl_malloc(sizeof(*in),
    #     "zr_score_inputs")` would register `in` as an input alias and every
    #     `f(*in, "literal")` in the function would be misread as a key;
    #   - the right-hand side must contain no string literal, or
    #     `const char *channel = json_get_str(json_get(request->input,
    #     "channel"))` would alias the VALUE, and the next
    #     `strcmp(channel, "onchain")` would be misread as reading a key
    #     named onchain.
    aliasre = "input"
    ns = split(code, stmts, ";")
    for (i = 1; i <= ns; i++) {
        st = stmts[i]
        if (index(st, "\"") > 0) continue
        if (st !~ /(^|[^A-Za-z_0-9])input([^A-Za-z_0-9]|$)/) continue
        if (!match(st, /[A-Za-z_][A-Za-z_0-9]*[ ]*=[^=]/)) continue
        m = substr(st, RSTART, RLENGTH); sub(/[ ]*=.*$/, "", m)
        if (m != "" && m != "input") aliasre = aliasre "|" m
    }
    # (1) accessor form: f(<expr naming the input object>, "KEY"
    pat = "[A-Za-z_][A-Za-z_0-9]*\\(([^,()\"]*[^A-Za-z_0-9])?(" aliasre \
          ")([^A-Za-z_0-9][^,()\"]*)?,[ ]*\"[^\"]*\""
    b = body
    while (match(b, pat)) {
        m = substr(b, RSTART, RLENGTH)
        b = substr(b, RSTART + RLENGTH)
        j = index(m, "\"")
        key = substr(m, j + 1, length(m) - j - 1)
        if (iskey(key)) keys = keys " " key
    }
    # (2) forward-exactly-these-keys array form
    b = body
    while (match(b, /const char \*const [A-Za-z_][A-Za-z_0-9]*\[\][ ]*=[ ]*\{[^}]*\}/)) {
        m = substr(b, RSTART, RLENGTH)
        b = substr(b, RSTART + RLENGTH)
        arrname = m; sub(/^const char \*const /, "", arrname); sub(/\[\].*$/, "", arrname)
        arrbody = m; sub(/^[^{]*\{/, "", arrbody); sub(/\}$/, "", arrbody)
        ns = split(code, stmts, ";")
        for (i = 1; i <= ns; i++) {
            st = stmts[i]
            if (index(st, "input") == 0 || index(st, "(") == 0) continue
            if (st !~ ("(^|[^A-Za-z_0-9])" arrname "([^A-Za-z_0-9]|$)")) continue
            while (match(arrbody, /"[^"]*"/)) {
                key = substr(arrbody, RSTART + 1, RLENGTH - 2)
                arrbody = substr(arrbody, RSTART + RLENGTH)
                if (iskey(key)) keys = keys " " key
            }
            break
        }
    }
    # every string literal in the body (the declared-but-not-read WARN uses
    # this weak signal: a declared key whose NAME appears nowhere in the
    # handler is the only kind this gate is willing to call out)
    b = body
    while (match(b, /"[^"]*"/)) {
        key = substr(b, RSTART + 1, RLENGTH - 2)
        b = substr(b, RSTART + RLENGTH)
        if (key != "") lits = lits " " key
    }
    # (3) callees — read from `code`, the body with every string literal
    # emptied. Over `body` this would read a function name mentioned INSIDE a
    # string as a call: native_vault_command.c ships the evidence string
    # "every custody leaf ends in vault_dispatch() or vault_rpc_settle()",
    # which made the read-only routes leaf inherit the spend router'"'"'s keys.
    b = code
    while (match(b, /[A-Za-z_][A-Za-z_0-9]*\(/)) {
        calls = calls " " substr(b, RSTART, RLENGTH - 1)
        b = substr(b, RSTART + RLENGTH)
    }
    printf "FN\t%s\t%s\t%s\t%s\t%s\n", curfile, fname, keys, lits, calls
    fname = ""; body = ""; code = ""
}
BEGIN {
    in_comment = 0; in_line_comment = 0; in_str = 0; in_chr = 0; esc = 0
    bdepth = 0; pdepth = 0; tok = ""; last_ident = ""; cand = ""
    last_ns = ""; fname = ""; body = ""; code = ""; nfn = 0
}
FNR == 1 {
    flush_fn()
    curfile = FILENAME
    in_comment = 0; in_line_comment = 0; in_str = 0; in_chr = 0
    bdepth = 0; pdepth = 0; tok = ""; last_ident = ""; cand = ""; last_ns = ""
    fname = ""; body = ""; code = ""
}
{
    line = $0 "\n"
    n = length(line)
    seg = ""; segc = ""
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (in_line_comment) { if (c == "\n") in_line_comment = 0; continue }
        if (in_comment) {
            if (c == "*" && substr(line, i + 1, 1) == "/") { in_comment = 0; i++ }
            continue
        }
        if (in_chr) {
            if (esc) esc = 0
            else if (c == "\\") esc = 1
            else if (c == "'"'"'") in_chr = 0
            continue
        }
        if (in_str) {
            if (bdepth > 0) seg = seg c
            if (esc) esc = 0
            else if (c == "\\") esc = 1
            else if (c == "\"") { in_str = 0; if (bdepth > 0) segc = segc c }
            continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { in_comment = 1; i++; continue }
        if (c == "/" && substr(line, i + 1, 1) == "/") { in_line_comment = 1; i++; continue }
        if (c == "'"'"'") { in_chr = 1; esc = 0; continue }
        if (c == "\"") {
            in_str = 1; esc = 0
            if (bdepth > 0) { seg = seg c; segc = segc c }
            last_ns = c
            continue
        }
        if (c ~ /[A-Za-z0-9_]/) { tok = tok c }
        else if (tok != "") { last_ident = tok; tok = "" }

        if (c == "(") { if (bdepth == 0 && pdepth == 0) cand = last_ident; pdepth++ }
        else if (c == ")") { if (pdepth > 0) pdepth-- }
        else if (c == "{") {
            if (bdepth == 0 && last_ns == ")" && cand != "") { fname = cand; body = ""; code = "" }
            bdepth++
        }
        else if (c == "}") {
            bdepth--
            if (bdepth <= 0) {
                bdepth = 0
                if (fname != "") { body = body seg; code = code segc }
                seg = ""; segc = ""
                flush_fn(); pdepth = 0; cand = ""
                continue
            }
        }
        if (bdepth > 0) { seg = seg (c == "\n" ? " " : c); segc = segc (c == "\n" ? " " : c) }
        if (c !~ /[ \t\r\n]/) last_ns = c
    }
    if (bdepth > 0 && fname != "") { body = body seg; code = code segc }
}
END { flush_fn(); printf "FNCOUNT\t%d\n", nfn }
' "${src_files[@]}")

FN_COUNT=$(printf '%s\n' "$FN_OUT" | awk -F'\t' '/^FNCOUNT/ {print $2}')
if [ -z "${FN_COUNT:-}" ]; then
    echo "check_command_input_keys: FATAL — the C function indexer produced" >&2
    echo "  no FNCOUNT record; refusing to report a verdict." >&2
    exit 2
fi
gate_require_scanned "$FN_COUNT" "$FN_FLOOR" check_command_input_keys \
    "C function index collapsed under floor (indexed $FN_COUNT)"

# ── Phase 4: transitive closure + per-leaf diff ───────────────────────────
[ -f "$BASELINE" ] || touch "$BASELINE"

REPORT=$(printf '%s\n%s\n' "$FN_OUT" "$LEAVES" | awk -F'\t' -v baseline="$BASELINE" '
function setadd(cur, add,   i, a, m, out) {
    out = cur
    m = split(add, a, " ")
    for (i = 1; i <= m; i++)
        if (a[i] != "" && index(out, " " a[i] " ") == 0) out = out a[i] " "
    return out
}
function has(set, k) { return index(set, " " k " ") > 0 }
# Canonical form of the declared key set on one leaf: unique, sorted, joined.
# Two leaves that declare the same keys in a different ORDER are the same
# contract, and a gate that called that a divergence would be noise.
function sortedkeys(csv,   i, j, n2, a, k, dup, cnt, arr, tmp, out) {
    cnt = 0
    n2 = split(csv, a, ",")
    for (i = 1; i <= n2; i++) {
        k = a[i]
        if (k == "") continue
        dup = 0
        for (j = 1; j <= cnt; j++) if (arr[j] == k) dup = 1
        if (!dup) arr[++cnt] = k
    }
    for (i = 2; i <= cnt; i++) {
        tmp = arr[i]; j = i - 1
        while (j >= 1 && arr[j] > tmp) { arr[j + 1] = arr[j]; j-- }
        arr[j + 1] = tmp
    }
    out = ""
    for (i = 1; i <= cnt; i++) out = out (i > 1 ? "," : "") arr[i]
    return out
}
BEGIN {
    while ((getline bl < baseline) > 0) {
        sub(/#.*$/, "", bl); gsub(/^[ \t]+|[ \t]+$/, "", bl)
        if (bl == "") continue
        split(bl, bp, /[ \t]+/)
        BASE[bp[1] SUBSEP bp[2]] = 1
        BASEN++
    }
    close(baseline)
}
$1 == "FN" {
    fn = $3
    if (!(fn in K)) { K[fn] = " "; L[fn] = " "; C[fn] = " "; FNS[++nfns] = fn }
    K[fn] = setadd(K[fn], $4)
    L[fn] = setadd(L[fn], $5)
    C[fn] = setadd(C[fn], $6)
    next
}
$1 == "LEAF" {
    nleaf++
    LPATH[nleaf] = $2; LFILE[nleaf] = $3; LLINE[nleaf] = $4
    LIN[nleaf] = $6; LPOS[nleaf] = $7; LH[nleaf] = $8
    LSCHEMA[nleaf] = $9; LOUT[nleaf] = $10
    BOUNDBY[$8]++
    next
}
END {
    changed = 1; rounds = 0
    while (changed && rounds < 64) {
        changed = 0; rounds++
        for (i = 1; i <= nfns; i++) {
            fn = FNS[i]
            m = split(C[fn], a, " ")
            for (j = 1; j <= m; j++) {
                cal = a[j]
                if (cal == "" || cal == fn || !(cal in K)) continue
                nk = setadd(K[fn], K[cal]); if (nk != K[fn]) { K[fn] = nk; changed = 1 }
                nl = setadd(L[fn], L[cal]); if (nl != L[fn]) { L[fn] = nl; changed = 1 }
            }
        }
    }
    if (rounds >= 64) { printf "FATAL\tclosure did not reach a fixpoint in 64 rounds\n"; exit 0 }
    for (n = 1; n <= nleaf; n++) {
        h = LH[n]
        if (!(h in K)) { unresolved++; UNRES = UNRES "\n    " LPATH[n] " -> " h; continue }
        resolved++
        delete DECL
        nd = split(LIN[n] "," LPOS[n], d, ",")
        for (i = 1; i <= nd; i++) if (d[i] != "") DECL[d[i]] = 1
        if (BOUNDBY[h] > 1) {
            shared++
            # Reads are not attributable per leaf here — but one thing still
            # is. Two leaves that bind the SAME handler and declare the SAME
            # input AND output schema are one contract wearing two names: the
            # handler cannot be routing on the path to justify different
            # inputs, because both schemas say the two calls are the same
            # call. Any divergence is a leaf that silently rejects a key its
            # twin accepts.
            #
            # The OUTPUT schema is part of the key on purpose. core.chain.-
            # transaction.get and core.wallet.transaction.get share an input
            # schema name and the bridge, but answer zcl.transaction.v1 and
            # zcl.wallet_tx.v1 — two different questions that happen to reuse
            # one input schema name, and the wallet one has no raw paging to
            # declare. Grouping on the input schema alone called that a
            # divergence; it is not one.
            #
            # LIVE BUG THIS CAUGHT: zcode.work.show and zcode.work.status both
            # bind zcl_native_handle_zcode_work_status and both declare
            # zcl.zcode_work_status.input.v1, but only `status` declared
            # `datadir`. The handler reads it; `show` answered
            # INVALID_INPUT: unknown input key 'datadir'. The shared-dispatcher
            # exclusion above is exactly what hid it.
            if (LSCHEMA[n] != "" && LOUT[n] != "") {
                grp = h SUBSEP LSCHEMA[n] SUBSEP LOUT[n]
                canon = sortedkeys(LIN[n] "," LPOS[n])
                if (!(grp in GRPKEYS)) {
                    GRPKEYS[grp] = canon; GRPLEAF[grp] = LPATH[n]
                } else if (GRPKEYS[grp] != canon) {
                    printf "DIVERGENT\t%s\t%s\t%s\t%s\t%s\t%s\n", LPATH[n], \
                           canon, GRPLEAF[grp], GRPKEYS[grp], h, LSCHEMA[n]
                    ndiv++
                }
            }
            continue
        }
        m = split(K[h], a, " ")
        for (i = 1; i <= m; i++) {
            key = a[i]
            if (key == "" || (key in DECL)) continue
            if ((LPATH[n] SUBSEP key) in BASE) { HITBASE[LPATH[n] SUBSEP key] = 1; grand++; continue }
            printf "MISSING\t%s\t%s\t%s\t%s\t%s\n", LPATH[n], key, h, LFILE[n], LLINE[n]
            nmiss++
        }
        for (key in DECL) {
            if (has(K[h], key) || has(L[h], key)) continue
            printf "UNREAD\t%s\t%s\t%s\n", LPATH[n], key, h
            nunread++
        }
    }
    for (b in BASE) if (!(b in HITBASE)) {
        split(b, bp, SUBSEP)
        printf "STALE\t%s\t%s\n", bp[1], bp[2]
        nstale++
    }
    printf "SUMMARY\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", resolved, unresolved, \
           nmiss, nunread, grand, nstale, BASEN, shared, ndiv
    if (unresolved > 0) printf "UNRESOLVED\t%s\n", UNRES
}
')

# Extract the FATAL records and decide on the STRING, not on a pipeline's exit
# status. Under `set -o pipefail` a `printf | grep -q '^FATAL'` that MATCHED
# exits at the first hit, printf takes SIGPIPE, and the pipeline reports 141
# instead of grep's 0 — so a found non-convergence reads as "converged fine".
# MEASURED 2026-07-30: on a clean tree $REPORT is 310 bytes / 5 lines, well
# inside the 64 KB pipe buffer, so the inversion is NOT reachable here today —
# this is a shape fix, not a live-bug fix, and it is worth making because the
# report is finding-proportional (a record per UNREAD/STALE/MISS key) and
# nothing bounds it, so the safety here is an accident of a clean tree.
# grep without -q drains stdin, so printf always completes; the regex is
# unchanged, and this also folds in the second grep that re-scanned the report.
FATAL_RECORDS=$(printf '%s\n' "$REPORT" | grep '^FATAL' || true)
if [ -n "$FATAL_RECORDS" ]; then
    printf '%s\n' "$FATAL_RECORDS" >&2
    echo "check_command_input_keys: FATAL — analysis did not converge." >&2
    exit 2
fi

SUMMARY=$(printf '%s\n' "$REPORT" | grep '^SUMMARY' || true)
if [ -z "$SUMMARY" ]; then
    echo "check_command_input_keys: FATAL — no SUMMARY record." >&2
    exit 2
fi
IFS=$'\t' read -r _ RESOLVED UNRESOLVED NMISS NUNREAD NGRAND NSTALE NBASE NSHARED \
    NDIV <<< "$SUMMARY"

gate_require_scanned "$RESOLVED" "$RESOLVED_FLOOR" check_command_input_keys \
    "only $RESOLVED of $BOUND_COUNT handler symbols resolved to C source — the handler-definition scan is hollow; re-point it before trusting a verdict."

fail=0
if [ "$NMISS" -gt 0 ]; then
    fail=1
    echo ""
    echo "check_command_input_keys: $NMISS input key(s) READ by a handler but" \
         "NOT declared in the leaf's input_keys:"
    printf '%s\n' "$REPORT" | grep '^MISSING' \
        | awk -F'\t' '{printf "  %s:%s: %s reads \"%s\" (handler %s)\n", $5, $6, $2, $3, $4}'
    echo ""
    echo "  zcl_command_registry_input_validate() rejects any key not in the"
    echo "  leaf's input_keys CSV, so passing one of these is INVALID_INPUT and"
    echo "  omitting it is whatever the handler does without it: the key is"
    echo "  unreachable from the real CLI and the command is partly or wholly"
    echo "  UNCALLABLE. Add the key to input_keys in $DEF_DIR/*.def and"
    echo "  regenerate the catalog doc (make docs-api-reference). If the read"
    echo "  is genuinely unreachable, add '<leaf> <key>' to $BASELINE with the"
    echo "  reason on the same line."
fi
if [ "${NDIV:-0}" -gt 0 ]; then
    fail=1
    echo ""
    echo "check_command_input_keys: $NDIV leaf pair(s) share a handler AND an" \
         "input schema but declare DIFFERENT input keys:"
    printf '%s\n' "$REPORT" | grep '^DIVERGENT' \
        | awk -F'\t' '{printf "  %s declares [%s]\n  %s declares [%s]\n    (handler %s, input schema %s)\n", $2, $3, $4, $5, $6, $7}'
    echo ""
    echo "  One contract under two names: the input schema says the inputs are"
    echo "  identical, so the handler cannot be routing on the path to justify"
    echo "  the difference. Whichever leaf is missing a key answers"
    echo "  INVALID_INPUT for an input its twin accepts. Make the input_keys"
    echo "  CSVs agree in $DEF_DIR/*.def and regenerate the catalog doc"
    echo "  (make docs-api-reference)."
fi
if [ "$NSTALE" -gt 0 ]; then
    fail=1
    echo ""
    echo "check_command_input_keys: $NSTALE STALE baseline entry(ies) — the" \
         "violation is gone:"
    printf '%s\n' "$REPORT" | grep '^STALE' | awk -F'\t' '{printf "  %s %s\n", $2, $3}'
    echo "  Good: the key got declared. Delete each line from $BASELINE in the"
    echo "  same commit so the ratchet can only shrink."
fi
if [ "$UNRESOLVED" -gt 0 ]; then
    echo "check_command_input_keys: note — $UNRESOLVED bound handler symbol(s)" \
         "were not found in the scanned C (not gated):"
    printf '%s\n' "$REPORT" | grep '^UNRESOLVED' | cut -f2-
fi
if [ "$NUNREAD" -gt 0 ] && [ "$VERBOSE" = "1" ]; then
    echo "check_command_input_keys: declared-but-not-read (WARN, not gated):"
    printf '%s\n' "$REPORT" | grep '^UNREAD' \
        | awk -F'\t' '{printf "    %s: %s (handler %s)\n", $2, $3, $4}'
fi

if [ "$fail" = "1" ] && [ "$MODE" = "FAIL" ]; then exit 1; fi

echo "[check_command_input_keys] PASS ($RESOLVED leaf handler(s) resolved over" \
     "$FN_COUNT function(s); every key they read is declared; $NSHARED leaf(s)" \
     "on a shared dispatcher not attributable; $NUNREAD declared-but-unread" \
     "(ZCL_COMMAND_INPUT_KEYS_VERBOSE=1 to list); $NGRAND grandfathered;" \
     "shared-handler input contracts agree)"
