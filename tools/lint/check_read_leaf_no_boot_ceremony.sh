#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Gate — a leaf declared READ may not reach the datadir BOOT CEREMONY.
#
# THE BUG THIS EXISTS TO CATCH (reproduced live, 2026-07-29):
#
#   $ z23 app service access --input='{"service":"reference"}'
#   [boot] sqlite.quick_check ...
#   db: applied 35 migration(s), now at version 36
#
# `app.service.access` is ZCL_COMMAND_READY_READ / AUTH_PUBLIC /
# TRAIT_IDEMPOTENT and its handler called node_db_open(). That is
# node_db_open_impl(boot_ceremony=true) (engine/models/src/database.c): it
# opens <datadir>/node.db READWRITE|CREATE, runs PRAGMA quick_check and on
# failure db_quarantine_files() rename()s node.db/-wal/-shm aside to
# node.db.corrupt-<ts>, then create_schema(), then node_db_migrate(), then
#   DELETE FROM snapshot_staging_utxos
#   DELETE FROM node_state WHERE key LIKE 'snapshot_staging_%'
# Since `datadir` falls back to zcl_native_command_datadir(), a bare
# invocation of a READ leaf did all of that to the operator's LIVE node.
# Six leaves were wrong the same way (app.service.access,
# zcode.release.prove, zcode.domain.list, zcode.domain.status,
# zcode.contributor.show, zcode.package.resolve) and the whole test suite
# was green throughout.
#
# WHY THE OBVIOUS NARROWER GATE MISSES IT. The first attempt refused the
# ceremony "from a service source" — a FILE-scoped rule. It caught the one
# leaf in native_service_command.c and none of the other five, which live in
# native_zcode_release_command.c and native_zcode_contributor_command.c.
# The property has nothing to do with which file the call sits in: it is
# reachability from a leaf whose DECLARED effect is read. So this gate keys
# off the declaration in engine/composition/commands and follows the call graph
# wherever it goes.
#
# It also refuses the REJECTED WEAKER FIX for free. Swapping node_db_open()
# for node_db_open_runtime() looks like a fix and is not: the runtime open
# is still READWRITE|CREATE and still calls create_schema() and
# node_db_migrate(). Because engine/models/src is inside the scanned corpus,
# the closure walks node_db_open_runtime -> create_schema and the leaf is
# still refused.
#
# WHAT IS CHECKED. For every leaf declared with a READ macro that binds a
# handler, the transitive callee closure of that handler must not contain
# any of:
#
#   node_db_open            READWRITE|CREATE + the whole ceremony
#   node_db_open_impl       the ceremony itself
#   create_schema           writes DDL into the caller's file
#   node_db_migrate         rewrites the caller's schema
#   db_quarantine_files     rename()s the operator's database aside
#   progress_store_open     the same shape for the consensus.db kernel
#                           store: CREATE, a rename migration, and
#                           quarantine-then-recreate
#
# The read-only primitive to use instead is
# zcl_native_node_db_open_readonly() (tools/command/native_node_db_ro.c):
# SQLITE_OPEN_READONLY plus PRAGMA query_only=ON, no CREATE, no migrate, no
# quarantine.
#
# SCANNED CORPUS — stated, not hidden. Every tracked .c that names a bound
# handler symbol, UNION every tracked .c under tools/command,
# engine/controllers/src, engine/services/src, engine/models/src and engine/modules/storage/src.
# The closure only walks through functions DEFINED in that corpus, so a read
# handler that reached the ceremony through a helper defined outside it
# (core/modules/net, contexts/wallet/modules/wallet, ...) would be missed. That is the honest limit; the
# corpus covers every layer a command handler has ever used to reach a
# database, and widening it is a one-line change to CORPUS_DIRS.
#
# Grandfathered violations live in the baseline, shrink-only (the same
# ratchet as check_command_input_keys): a NEW read leaf reaching the
# ceremony FAILS, and a baseline line whose violation is gone must be
# deleted in the same commit.
#
# ANTI-HOLLOW. Every population this verdict rests on is floor-gated with
# gate_require_scanned: .def files, parsed leaves, READ leaves that bind a
# handler, corpus files, indexed C functions, handlers resolved into the
# index, and — the one that matters most — the banned symbols themselves.
# If `node_db_open` stops appearing anywhere in the corpus, this gate does
# not quietly pass; it aborts, because a gate that refuses a call nobody
# makes is refusing nothing.

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

DEF_DIR="${ZCL_READ_LEAF_DEF_DIR:-engine/composition/commands}"
BASELINE="${ZCL_READ_LEAF_BASELINE:-tools/lint/read_leaf_boot_ceremony_baseline.txt}"
MODE="${ZCL_LINT_MODE:-FAIL}"

CORPUS_DIRS=(tools/command engine/controllers/src engine/services/src \
             engine/models/src engine/modules/storage/src)

# The boot-ceremony entry points. Every one of these either opens
# READWRITE|CREATE or mutates the file it was handed.
BANNED=(node_db_open node_db_open_impl create_schema node_db_migrate \
        db_quarantine_files progress_store_open)

# Floors sit below the live populations with headroom: an ordinary addition
# never trips them, an emptied or renamed producer does.
LEAF_FLOOR="${ZCL_READ_LEAF_LEAF_FLOOR:-160}"
READ_FLOOR="${ZCL_READ_LEAF_READ_FLOOR:-60}"
CORPUS_FLOOR="${ZCL_READ_LEAF_CORPUS_FLOOR:-300}"
FN_FLOOR="${ZCL_READ_LEAF_FN_FLOOR:-2000}"
RESOLVED_FLOOR="${ZCL_READ_LEAF_RESOLVED_FLOOR:-40}"

mapfile -t def_files < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null | sort)
gate_require_scanned "${#def_files[@]}" 1 check_read_leaf_no_boot_ceremony \
    "no *.def under: $DEF_DIR"

# ── Phase 1: parse the leaf macros ────────────────────────────────────────
# One READ record per READ leaf that binds a handler:
#   READ <path> <file> <line> <macro> <handler>
# The handler argument slot differs per macro shape (engine/composition/src/
# command_catalog.c); each shape's arity is asserted before a slot is read,
# so a macro grammar change aborts LOUD instead of reading the wrong slot.
DEF_OUT=$(awk '
function trim(s) { gsub(/^[ \t\r\n]+/, "", s); gsub(/[ \t\r\n]+$/, "", s); return s }
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
              " This gate reads a fixed handler slot; re-read the macro in" \
              " engine/composition/src/command_catalog.c and fix the arity table here.", \
              n, nargs))
        return 0
    }
    return 1
}
function emit(handler_idx,   h) {
    h = trim(args[handler_idx])
    if (h == "" || h == "NULL" || h == "0") return
    nread++
    printf "READ\t%s\t%s\t%d\t%s\t%s\n", literal(args[1]), startfile, \
           startline, mtype, h
}
function finish_leaf() {
    nleaf++
    # Only the READ shapes are gated. A COMMAND leaf declares itself a
    # writer; opening the database for write is what it is FOR.
    if (mtype == "ZCL_COMMAND_READY_READ")          { if (want_arity(22)) emit(22) }
    else if (mtype == "ZCL_COMMAND_DEV_READ")       { if (want_arity(22)) emit(20) }
    else if (mtype == "ZCL_COMMAND_COMPAT_READ")    { (void_ = want_arity(21)) }
    else if (mtype == "ZCL_COMMAND_PLANNED_READ")   { (void_ = want_arity(20)) }
    else if (mtype == "ZCL_COMMAND_READY_COMMAND")  { (void_ = want_arity(25)) }
    else if (mtype == "ZCL_COMMAND_DEV_COMMAND")    { (void_ = want_arity(26)) }
    else if (mtype == "ZCL_COMMAND_PLANNED_COMMAND"){ (void_ = want_arity(25)) }
    else if (mtype == "ZCL_COMMAND_COMPAT_COMMAND") { (void_ = want_arity(26)) }
}
BEGIN {
    split("ZCL_COMMAND_READY_READ ZCL_COMMAND_READY_COMMAND " \
          "ZCL_COMMAND_PLANNED_READ ZCL_COMMAND_PLANNED_COMMAND " \
          "ZCL_COMMAND_COMPAT_READ ZCL_COMMAND_COMPAT_COMMAND " \
          "ZCL_COMMAND_DEV_READ ZCL_COMMAND_DEV_COMMAND", mm, " ")
    for (i in mm) MACRO[mm[i]] = 1
    in_comment = 0; in_str = 0; esc = 0; collecting = 0; tok = ""
    nleaf = 0; nread = 0
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
    printf "COUNTS\t%d\t%d\n", nleaf, nread
}
' "${def_files[@]}")

DEF_FATALS=$(printf '%s\n' "$DEF_OUT" | grep '^FATAL' || true)
if [ -n "${DEF_FATALS//[[:space:]]/}" ]; then
    printf '%s\n' "$DEF_FATALS" \
        | awk -F'\t' 'NF>1 {printf "  %s:%s: %s — %s\n", $2, $3, $4, $5}' >&2
    echo "check_read_leaf_no_boot_ceremony: FATAL — command macro grammar drift." >&2
    exit 2
fi
DEF_COUNTS=$(printf '%s\n' "$DEF_OUT" | grep '^COUNTS' || true)
if [ -z "$DEF_COUNTS" ]; then
    echo "check_read_leaf_no_boot_ceremony: FATAL — the .def parser produced" >&2
    echo "  no COUNTS record; refusing a verdict off a broken scan." >&2
    exit 2
fi
IFS=$'\t' read -r _ LEAF_COUNT READ_COUNT <<< "$DEF_COUNTS"
gate_require_scanned "$LEAF_COUNT" "$LEAF_FLOOR" check_read_leaf_no_boot_ceremony \
    "leaf population collapsed under floor (parsed $LEAF_COUNT)"
gate_require_scanned "$READ_COUNT" "$READ_FLOOR" check_read_leaf_no_boot_ceremony \
    "handler-binding READ-leaf population collapsed under floor (parsed $READ_COUNT)"

READS=$(printf '%s\n' "$DEF_OUT" | grep '^READ' || true)

# ── Phase 2: the scanned corpus ───────────────────────────────────────────
HANDLER_PAT=$(mktemp)
SRC_LIST=$(mktemp)
trap 'rm -f "$HANDLER_PAT" "$SRC_LIST"' EXIT
printf '%s\n' "$READS" | awk -F'\t' 'NF>1 {print $6 "("}' | sort -u > "$HANDLER_PAT"
gate_require_scanned "$(wc -l < "$HANDLER_PAT")" 40 \
    check_read_leaf_no_boot_ceremony \
    "no READ handler symbols parsed out of $DEF_DIR/*.def"

set +e
git grep -lFf "$HANDLER_PAT" -- '*.c' > "$SRC_LIST"
grc=$?
set -e
if [ "$grc" -ge 2 ]; then
    echo "check_read_leaf_no_boot_ceremony: FATAL — git grep for handler" >&2
    echo "  definitions failed (exit $grc); refusing a verdict." >&2
    exit 2
fi
git ls-files -- "${CORPUS_DIRS[@]/%//*.c}" >> "$SRC_LIST"
mapfile -t src_files < <(sort -u "$SRC_LIST")
gate_require_scanned "${#src_files[@]}" "$CORPUS_FLOOR" \
    check_read_leaf_no_boot_ceremony \
    "the scanned corpus collapsed (${#src_files[@]} files); a CORPUS_DIRS entry was renamed or moved."

# The banned symbols must actually EXIST in the corpus. A gate that forbids
# a call nobody makes forbids nothing, and would pass forever after a
# rename.
missing_banned=""
for sym in "${BANNED[@]}"; do
    if ! git grep -qF -- "$sym(" -- "${CORPUS_DIRS[@]/%//*.c}"; then
        missing_banned="$missing_banned $sym"
    fi
done
if [ -n "$missing_banned" ]; then
    echo "check_read_leaf_no_boot_ceremony: FATAL — banned symbol(s) not found" >&2
    echo "  anywhere in the scanned corpus:$missing_banned" >&2
    echo "  Either they were renamed (re-point BANNED) or the corpus moved." >&2
    echo "  Refusing to report 'clean' while forbidding calls nobody makes." >&2
    exit 2
fi

# ── Phase 3: index every C function -> its callees ────────────────────────
# Line-based: comments and string/char literals are stripped first, then
# brace depth delimits bodies. A definition is a `{` reached at depth 0
# whose pending file-scope text ends in `)` — that distinguishes a function
# body from a file-scope aggregate initializer (`... = {`).
FN_OUT=$(awk '
function strip(s,   out, i, c, n2) {
    # block comments spanning lines are handled by the in_comment state
    out = ""
    n2 = length(s)
    for (i = 1; i <= n2; i++) {
        c = substr(s, i, 1)
        if (in_comment) {
            if (c == "*" && substr(s, i + 1, 1) == "/") { in_comment = 0; i++ }
            continue
        }
        if (in_str) {
            if (esc) { esc = 0; continue }
            if (c == "\\") { esc = 1; continue }
            if (c == "\"") in_str = 0
            continue
        }
        if (in_chr) {
            if (esc) { esc = 0; continue }
            if (c == "\\") { esc = 1; continue }
            if (c == "'"'"'") in_chr = 0
            continue
        }
        if (c == "/" && substr(s, i + 1, 1) == "*") { in_comment = 1; i++; continue }
        if (c == "/" && substr(s, i + 1, 1) == "/") { break }
        if (c == "\"") { in_str = 1; esc = 0; continue }
        if (c == "'"'"'") { in_chr = 1; esc = 0; continue }
        out = out c
    }
    return out
}
function iskw(w) {
    return (w == "if" || w == "for" || w == "while" || w == "switch" || \
            w == "return" || w == "sizeof" || w == "defined" || \
            w == "do" || w == "else" || w == "alignof" || w == "_Generic")
}
function fnname(s,   t, m, name, d, i, c, id) {
    # first IDENT( at paren depth 0 in the pending signature text
    d = 0; id = "";
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c ~ /[A-Za-z0-9_]/) { id = id c; continue }
        if (c == "(") {
            if (d == 0 && id != "" && !iskw(id)) return id
            d++
        } else if (c == ")") d--
        id = ""
    }
    return ""
}
function flush(   i, m, a, seen, out) {
    if (fname != "") {
        nfn++
        printf "FN\t%s\t%s\t%s\n", curfile, fname, callees
    }
    fname = ""; callees = ""; body = ""
}
BEGIN { in_comment = 0; in_str = 0; in_chr = 0; esc = 0; nfn = 0 }
FNR == 1 {
    flush()
    curfile = FILENAME
    in_comment = 0; in_str = 0; in_chr = 0; esc = 0
    depth = 0; pend = ""; fname = ""; callees = ""
}
{
    s = strip($0 " ")
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "{") {
            if (depth == 0) {
                sig = pend
                sub(/[ \t]+$/, "", sig)
                if (sig ~ /\)$/) {
                    nm = fnname(pend)
                    if (nm != "") { fname = nm; callees = "" }
                }
                pend = ""
            }
            depth++
            continue
        }
        if (c == "}") {
            depth--
            if (depth <= 0) { depth = 0; flush(); pend = "" }
            continue
        }
        if (depth == 0) {
            if (c == ";") { pend = "" } else { pend = pend c }
            continue
        }
        buf = buf c
    }
    if (depth > 0 && fname != "") {
        while (match(buf, /[A-Za-z_][A-Za-z_0-9]*\(/)) {
            cal = substr(buf, RSTART, RLENGTH - 1)
            buf = substr(buf, RSTART + RLENGTH)
            if (!iskw(cal) && index(callees, " " cal " ") == 0)
                callees = callees " " cal " "
        }
    }
    buf = ""
}
END { flush(); printf "FNCOUNT\t%d\n", nfn }
' "${src_files[@]}")

FN_COUNT=$(printf '%s\n' "$FN_OUT" | awk -F'\t' '/^FNCOUNT/ {print $2}')
if [ -z "${FN_COUNT:-}" ]; then
    echo "check_read_leaf_no_boot_ceremony: FATAL — the C function indexer" >&2
    echo "  produced no FNCOUNT record; refusing a verdict." >&2
    exit 2
fi
gate_require_scanned "$FN_COUNT" "$FN_FLOOR" check_read_leaf_no_boot_ceremony \
    "C function index collapsed under floor (indexed $FN_COUNT)"

# ── Phase 4: reverse reachability + per-leaf verdict ──────────────────────
[ -f "$BASELINE" ] || touch "$BASELINE"

REPORT=$(printf '%s\n%s\n' "$FN_OUT" "$READS" \
    | awk -F'\t' -v baseline="$BASELINE" -v banned="${BANNED[*]}" '
BEGIN {
    nb = split(banned, bb, " ")
    for (i = 1; i <= nb; i++) if (bb[i] != "") { BAN[bb[i]] = 1; TAINT[bb[i]] = bb[i] }
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
    if (!(fn in SEEN)) { SEEN[fn] = 1; FNS[++nfns] = fn; C[fn] = " " }
    C[fn] = C[fn] $4 " "
    next
}
$1 == "READ" {
    nread++
    LPATH[nread] = $2; LFILE[nread] = $3; LLINE[nread] = $4; LH[nread] = $6
    next
}
END {
    # A function is TAINTED if it calls a banned symbol or a tainted
    # function. TAINT[f] records the callee that tainted it, so the report
    # can print the whole path instead of just the verdict.
    changed = 1; rounds = 0
    while (changed && rounds < 128) {
        changed = 0; rounds++
        for (i = 1; i <= nfns; i++) {
            fn = FNS[i]
            if (fn in TAINT) continue
            m = split(C[fn], a, " ")
            for (j = 1; j <= m; j++) {
                cal = a[j]
                if (cal == "" || cal == fn) continue
                if (cal in TAINT) { TAINT[fn] = cal; changed = 1; break }
            }
        }
    }
    if (rounds >= 128) {
        printf "FATAL\ttaint closure did not reach a fixpoint in 128 rounds\n"
        exit 0
    }
    for (n = 1; n <= nread; n++) {
        h = LH[n]
        if (!(h in SEEN)) { unresolved++; UNRES = UNRES "\n    " LPATH[n] " -> " h; continue }
        resolved++
        if (!(h in TAINT)) continue
        # walk the taint chain to the banned symbol at its end
        path = h; cur = h; hops = 0
        while ((cur in TAINT) && TAINT[cur] != cur && hops < 64) {
            cur = TAINT[cur]; path = path " -> " cur; hops++
        }
        sym = cur
        if ((LPATH[n] SUBSEP sym) in BASE) {
            HITBASE[LPATH[n] SUBSEP sym] = 1; grand++; continue
        }
        printf "VIOLATION\t%s\t%s\t%s\t%s\t%s\n", LPATH[n], sym, path, \
               LFILE[n], LLINE[n]
        nviol++
    }
    for (b in BASE) if (!(b in HITBASE)) {
        split(b, bp, SUBSEP)
        printf "STALE\t%s\t%s\n", bp[1], bp[2]
        nstale++
    }
    printf "SUMMARY\t%d\t%d\t%d\t%d\t%d\t%d\n", resolved, unresolved, nviol, \
           grand, nstale, BASEN
    if (unresolved > 0) printf "UNRESOLVED\t%s\n", UNRES
}
')

# Decide on the extracted string, not on a pipeline's exit status: under
# pipefail a matching `grep -q '^FATAL'` can surface printf's SIGPIPE 141
# rather than grep's 0, which reads a real non-convergence as clean.
# MEASURED 2026-07-30: on a clean tree $REPORT is 21 bytes / 1 line, so the
# inversion is NOT reachable here today — a shape fix, not a live-bug fix. It
# is still worth making: the report grows one record per finding and nothing
# bounds it, so today's safety is an accident of a clean tree.
# Same regex, and the second grep that re-scanned the report is folded in.
FATAL_RECORDS=$(printf '%s\n' "$REPORT" | grep '^FATAL' || true)
if [ -n "$FATAL_RECORDS" ]; then
    printf '%s\n' "$FATAL_RECORDS" >&2
    echo "check_read_leaf_no_boot_ceremony: FATAL — analysis did not converge." >&2
    exit 2
fi
SUMMARY=$(printf '%s\n' "$REPORT" | grep '^SUMMARY' || true)
if [ -z "$SUMMARY" ]; then
    echo "check_read_leaf_no_boot_ceremony: FATAL — no SUMMARY record." >&2
    exit 2
fi
IFS=$'\t' read -r _ RESOLVED UNRESOLVED NVIOL NGRAND NSTALE NBASE <<< "$SUMMARY"

gate_require_scanned "$RESOLVED" "$RESOLVED_FLOOR" \
    check_read_leaf_no_boot_ceremony \
    "only $RESOLVED of $READ_COUNT READ handlers resolved into the function index — the scan is hollow; re-point it before trusting a verdict."

fail=0
if [ "$NVIOL" -gt 0 ]; then
    fail=1
    echo ""
    echo "check_read_leaf_no_boot_ceremony: $NVIOL leaf(s) declared READ reach" \
         "the datadir boot ceremony:"
    printf '%s\n' "$REPORT" | grep '^VIOLATION' \
        | awk -F'\t' '{printf "  %s:%s: %s reaches %s\n      %s\n", $5, $6, $2, $3, $4}'
    echo ""
    echo "  A READ leaf takes a caller-supplied datadir that DEFAULTS to the"
    echo "  operator's live one. The boot ceremony opens node.db"
    echo "  READWRITE|CREATE, quarantines it on a failed quick_check,"
    echo "  create_schema()s it, migrates it, and DELETEs the"
    echo "  snapshot_staging rows — to whatever datadir the leaf was pointed"
    echo "  at. Route the read through"
    echo "  zcl_native_node_db_open_readonly() / _require_readonly()"
    echo "  (tools/command/native_node_db_ro.c), which is SQLITE_OPEN_READONLY"
    echo "  plus PRAGMA query_only=ON. If the leaf genuinely needs to write,"
    echo "  it is not a READ leaf: redeclare it ZCL_COMMAND_READY_COMMAND."
    echo "  A known-open violation goes in $BASELINE as"
    echo "  '<leaf> <symbol>' with the reason on the same line."
fi
if [ "$NSTALE" -gt 0 ]; then
    fail=1
    echo ""
    echo "check_read_leaf_no_boot_ceremony: $NSTALE STALE baseline entry(ies)" \
         "— the violation is gone:"
    printf '%s\n' "$REPORT" | grep '^STALE' | awk -F'\t' '{printf "  %s %s\n", $2, $3}'
    echo "  Good: the leaf stopped reaching the ceremony. Delete each line"
    echo "  from $BASELINE in the same commit so the ratchet can only shrink."
fi
if [ "$UNRESOLVED" -gt 0 ]; then
    echo "check_read_leaf_no_boot_ceremony: note — $UNRESOLVED READ handler(s)" \
         "were not found in the scanned corpus (not gated):"
    printf '%s\n' "$REPORT" | grep '^UNRESOLVED' | cut -f2-
fi

if [ "$fail" = "1" ] && [ "$MODE" = "FAIL" ]; then exit 1; fi

echo "[check_read_leaf_no_boot_ceremony] PASS ($RESOLVED READ leaf handler(s)" \
     "resolved over $FN_COUNT function(s) in ${#src_files[@]} file(s); none" \
     "reaches ${#BANNED[@]} banned boot-ceremony symbol(s); $NGRAND" \
     "grandfathered of $NBASE baseline entry(ies))"
