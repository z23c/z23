#!/usr/bin/env bash
# check-outparam-init-before-return: a function that hands back a struct the
# caller will free MUST initialize that struct before the first thing that can
# fail.
#
# THE BUG CLASS THIS CLOSES (found live, 2026-08-26, commit bce343876).
# compact_block_reconstruct() took `struct block *out_block`, and its first
# failure return —
#
#     if (total == 0 || total > MAX_COMPACT_BLOCK_TXNS)
#         LOG_FAIL("compact", "invalid compact block tx count: %zu", total);
#
# — sat ABOVE block_init(out_block). Its caller process_cmpctblock() ran
# block_free(&out_block) on that outcome, so transaction_free() walked
# whatever pointer and count the caller's own stack happened to hold. Any
# connected peer could reach it with a valid header plus two zero bytes.
#
# TWO THINGS MADE IT INVISIBLE, and this gate is shaped around both:
#   1. LOG_FAIL and every other LOG_* macro in this tree EXPAND TO
#      `return false`. A line that reads like logging is a control-flow exit,
#      so a human scanning for `return` above the init sees nothing.
#   2. A freshly mapped stack reads back as zero, so a one-shot replay frees
#      nothing and exits clean. 140 stock replays and a 1.26M-exec fuzz
#      session missed it; it only fires in a long-lived process whose stack
#      slot has been dirtied. Rebuild with -ftrivial-auto-var-init=pattern to
#      make it deterministic.
#
# WHAT THIS GATE CHECKS. For every function in every tracked .c file it
# extracts the parameters of the form `struct T *name` (non-const, single
# pointer), finds the first `*_init(name)` / `memset(name, ...)` in the body,
# and reports the pair when a `return` or a `LOG_*(` precedes that line. It
# only reports when `T_free` exists somewhere in the tree — i.e. when the
# struct is the kind a caller frees — and only when the pre-init exit is
# reachable with well-formed arguments, not solely under a NULL/empty-pointer
# guard (a `if (!out) return false;` costs nothing and cannot be reached by a
# caller that then frees `out`).
#
# WHAT IT CANNOT CHECK. It is a line-order scanner over C text, not a compiler:
#   - It does not follow control flow. `if (x) { init(out); } ... return` reads
#     as initialized.
#   - It does not resolve macros. A wrapper macro that expands to `return` and
#     is not named LOG_* is invisible.
#   - It does not prove the CALLER frees. That leg is the reviewer's, recorded
#     per entry in the baseline.
#   - It only sees `T_init(out)` / `memset(out, ...)` shapes. An out-param
#     initialized field-by-field, or via `stream_init_from_data(&s, ...)`, does
#     not register as initialized (over-report) — and one initialized by a
#     helper this scanner cannot see is a miss.
#   - Multi-declarator declarations and `struct T **out` owner-outs are out of
#     scope entirely.
# It is therefore a RATCHET, not a prover: the baseline below is closed, every
# entry carries a reviewed verdict, and anything NOT in it fails the gate.
#
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL).
# Self-test: `bash tools/lint/check_outparam_init_before_return.sh --selftest`
# plants one clean function and one violating function in a scratch tree and
# asserts the analyzer's verdict on each.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="$SCRIPT_DIR/outparam_init_baseline.txt"
ANALYZER="$SCRIPT_DIR/outparam_init_scan.awk"

# ── the analyzer, emitted here so --selftest and the real run share one text ──
# Reads one .c file, prints one FINDING line per (function, out-param) whose
# first *_init/memset lands AFTER a return / LOG_* line, plus one STATS line.
write_analyzer() {
    cat > "$1" <<'AWK_EOF'
function emit(   i, p, np, parts, nm, ptype, firstinit, firstexit, j, line, tag, o, c, plist, inittag) {
    if (sig == "" || nbody == 0) return
    nfuncs++
    o = index(sig, "(")
    if (o == 0) return
    plist = substr(sig, o + 1)
    c = length(plist)
    while (c > 0 && substr(plist, c, 1) != ")") c--
    if (c == 0) return
    plist = substr(plist, 1, c - 1)
    np = split(plist, parts, ",")
    for (i = 1; i <= np; i++) {
        p = parts[i]
        gsub(/^[ \t]+|[ \t]+$/, "", p)
        if (p ~ /(^|[^A-Za-z0-9_])const([^A-Za-z0-9_]|$)/) continue
        if (p !~ /\*/) continue
        if (!match(p, /(^|[^A-Za-z0-9_])struct[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\*/)) continue
        ptype = substr(p, RSTART, RLENGTH)
        sub(/^[^A-Za-z_]*struct[ \t]+/, "", ptype)
        sub(/[ \t]*\*$/, "", ptype)
        if (p ~ /\*[ \t]*\*/) continue
        if (!match(p, /[A-Za-z_][A-Za-z0-9_]*[ \t]*(\[[^]]*\])?$/)) continue
        nm = substr(p, RSTART, RLENGTH)
        gsub(/[ \t]/, "", nm)
        sub(/\[.*\]$/, "", nm)
        if (nm == "") continue
        nparams++
        firstinit = 0; inittag = ""
        for (j = 1; j <= nbody; j++) {
            line = body[j]
            if (match(line, /[A-Za-z_][A-Za-z0-9_]*_init[ \t]*\([ \t]*&?[A-Za-z_][A-Za-z0-9_]*/)) {
                tag = substr(line, RSTART, RLENGTH)
                if (tag ~ ("_init[ \t]*\\([ \t]*" nm "$")) { firstinit = j; inittag = "init"; break }
            }
            if (line ~ ("memset[ \t]*\\([ \t]*" nm "[ \t]*,")) { firstinit = j; inittag = "memset"; break }
        }
        if (firstinit == 0) continue
        # Walk EVERY exit above the init, not just the first, and report the
        # first one reachable with well-formed (non-NULL) arguments. The first
        # exit in a function is very often `if (!a || !b) return false;`, which
        # a caller that then frees the out-param cannot reach — stopping there
        # would miss the data-dependent refusals underneath it, which is
        # exactly where the compact-block bug lived.
        firstexit = 0; kind = ""
        for (j = 1; j < firstinit; j++) {
            line = body[j]
            if (line !~ /(^|[^A-Za-z0-9_])return([^A-Za-z0-9_]|$)/ &&
                line !~ /(^|[^A-Za-z0-9_])LOG_[A-Z_0-9]+[ \t]*\(/) continue
            # Include continuation lines so a multi-line return payload does
            # not leak its operators into the next guard's region.
            k = j
            while (k < firstinit && body[k] !~ /;/) k++
            # Guard text = everything above, with every return/LOG_ statement
            # deleted. Then subtract what a pure pointer-nullness test is made
            # of; if anything survives — a numeric literal, a relational
            # operator, arithmetic, a comparison call — this exit is
            # DATA-dependent.
            # Drop each return/LOG_ statement (and its multi-line payload) by
            # walking lines, NOT by a gsub over the flattened text: a textual
            # /return[^;]*;/ also matches the "return" inside an identifier
            # like `op_return_len` and silently eats the guard behind it.
            region = ""
            m = 1
            while (m <= k) {
                line = body[m]
                if (match(line, /(^|[^A-Za-z0-9_])(return|LOG_[A-Z_0-9]+)([^A-Za-z0-9_]|$)/)) {
                    region = region " " substr(line, 1, RSTART)
                    while (m <= k && body[m] !~ /;/) m++
                    m++
                    continue
                }
                region = region " " line
                m++
            }
            gsub(/"[^"]*"/, "", region)
            gsub(/->/, ".", region)
            r = region
            gsub(/[ \t]+/, "", r)
            gsub(/\[0\]/, "", r)
            gsub(/[A-Za-z_][A-Za-z0-9_.]*/, "", r)
            gsub(/\|\||&&|==|!=|[()!{};,]/, "", r)
            if (r != "") { firstexit = j; kind = "DATA"; break }
            j = k
        }
        if (firstexit == 0) continue
        printf "FINDING\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
            FILENAME, fnname, ptype, nm, kind, bodyline[firstexit], bodyline[firstinit], inittag
    }
}
BEGIN { depth = 0; sig = ""; nbody = 0; nfuncs = 0; nparams = 0 }
{
    line = $0
    gsub(/"([^"\\]|\\.)*"/, "\"\"", line)
    gsub(/'([^'\\]|\\.)*'/, "CH", line)
    sub(/\/\/.*$/, "", line)
    if (incomment) { if (line ~ /\*\//) { sub(/^.*\*\//, "", line); incomment = 0 } else next }
    while (match(line, /\/\*/)) {
        pre = substr(line, 1, RSTART - 1)
        rest = substr(line, RSTART)
        if (match(rest, /\*\//)) { line = pre substr(rest, RSTART + 2) }
        else { line = pre; incomment = 1; break }
    }
    nb = gsub(/\{/, "{", line)
    ne = gsub(/\}/, "}", line)
    if (depth == 0) {
        if (nb == 0) {
            if (line ~ /[^ \t]/) { if (line ~ /;[ \t]*$/) sig = ""; else sig = sig " " line }
            next
        }
        sigfull = sig " " line
        gsub(/[ \t]+/, " ", sigfull); sub(/^ +/, "", sigfull)
        depth = nb - ne
        if (depth <= 0) { sig = ""; depth = 0; next }
        if (sigfull !~ /\(/ || sigfull ~ /^(typedef|struct |union |enum )/) { sig = ""; nbody = 0; next }
        if (match(sigfull, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
            fnname = substr(sigfull, RSTART, RLENGTH); sub(/[ \t]*\(/, "", fnname)
        } else fnname = "?"
        sig = sigfull; nbody = 0
        next
    }
    depth += nb - ne
    nbody++; body[nbody] = line; bodyline[nbody] = FNR
    if (depth > 0) next
    emit(); sig = ""; nbody = 0; depth = 0
}
END { printf "STATS\t%s\t%d\t%d\n", FILENAME, nfuncs, nparams }
AWK_EOF
}

# ── leg 2: the same class with a PUBLISHED GLOBAL as the out-parameter ────
#
# lib/sapling/src/params_init.c (fixed in 69518f2f3) published the three
# Groth16 verifying keys — sapling_set_spend_vk(&spend_vk) and friends store
# the pointer in a file-scope variable the verifiers read — and then a later
# Sprout failure path freed their ic[] arrays and comb tables WITHOUT storing
# NULL back into those variables. Every reader's fail-closed guard asks only
# "is the pointer NULL?", so the guard passed and groth16_verify() read freed
# heap, reachable from accept_to_mempool. Same class as leg 1: the thing a
# later reader will use is left in a state its guard cannot see. The
# out-parameter is just a module global instead of a stack slot.
#
# write_publisher_finder emits, for each function, whether it stores a
# caller-supplied pointer into a file-scope variable. That is DERIVED from the
# code, never from the name: a `*_set_*` that only writes through the pointer
# is not a publisher, and a publisher that is not spelled `set` still is one.
write_publisher_finder() {
    cat > "$1" <<'AWK_EOF'
function emit(   i, np, parts, p, nm, j, line, o, c, plist, sink) {
    if (sig == "" || nbody == 0) return
    o = index(sig, "(")
    if (o == 0) return
    plist = substr(sig, o + 1)
    c = length(plist)
    while (c > 0 && substr(plist, c, 1) != ")") c--
    if (c == 0) return
    plist = substr(plist, 1, c - 1)
    np = split(plist, parts, ",")
    for (i = 1; i <= np; i++) {
        p = parts[i]
        gsub(/^[ \t]+|[ \t]+$/, "", p)
        if (p !~ /\*/) continue
        if (!match(p, /[A-Za-z_][A-Za-z0-9_]*$/)) continue
        nm = substr(p, RSTART, RLENGTH)
        for (j = 1; j <= nbody; j++) {
            line = body[j]
            if (match(line, "(^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*" nm "[ \t]*;")) {
                sink = substr(line, RSTART, RLENGTH)
                sub(/^[^A-Za-z_]*/, "", sink); sub(/[ \t]*=.*$/, "", sink)
                # The sink must OUTLIVE the call: a file-scope object, never a
                # local. `struct worker *w = arg;` at the top of a pthread
                # entry point is not a publish.
                if (sink != nm && (sink in fileobj)) { print fnname; return }
            }
            if (line ~ ("atomic_store[ \t]*\\([ \t]*&[A-Za-z_][A-Za-z0-9_]*[ \t]*,[ \t]*" nm "[ \t]*\\)")) {
                print fnname; return
            }
        }
    }
}
BEGIN { depth = 0; nbody = 0 }
{
    line = $0
    gsub(/"([^"\\]|\\.)*"/, "\"\"", line)
    sub(/\/\/.*$/, "", line)
    if (incomment) { if (line ~ /\*\//) { sub(/^.*\*\//, "", line); incomment = 0 } else next }
    while (match(line, /\/\*/)) {
        pre = substr(line, 1, RSTART - 1); rest = substr(line, RSTART)
        if (match(rest, /\*\//)) line = pre substr(rest, RSTART + 2)
        else { line = pre; incomment = 1; break }
    }
    nb = gsub(/\{/, "{", line); ne = gsub(/\}/, "}", line)
    if (depth == 0 && nb == 0 && line ~ /;[ \t]*$/) {
        d = line
        sub(/[ \t]*=.*$/, "", d); sub(/[ \t]*;.*$/, "", d)
        if (match(d, /[A-Za-z_][A-Za-z0-9_]*[ \t]*(\[[^]]*\])?$/)) {
            g = substr(d, RSTART, RLENGTH); gsub(/[ \t]/, "", g); sub(/\[.*\]$/, "", g)
            if (g != "" && d ~ /\*/) fileobj[g] = 1
        }
    }
    if (depth == 0) {
        if (nb == 0) {
            if (line ~ /[^ \t]/) { if (line ~ /;[ \t]*$/) sig = ""; else sig = sig " " line }
            next
        }
        sigfull = sig " " line
        gsub(/[ \t]+/, " ", sigfull); sub(/^ +/, "", sigfull)
        depth = nb - ne
        if (sigfull !~ /\(/ || sigfull ~ /^(typedef|struct |union |enum )/) {
            sig = ""; nbody = 0; if (depth < 0) depth = 0; next
        }
        if (match(sigfull, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
            fnname = substr(sigfull, RSTART, RLENGTH); sub(/[ \t]*\(/, "", fnname)
        } else fnname = "?"
        sig = sigfull
        if (depth <= 0) {   # one-line definition: body is on this line
            nbody = 1; body[1] = line
            emit(); sig = ""; nbody = 0; depth = 0
            next
        }
        nbody = 0
        next
    }
    depth += nb - ne
    nbody++; body[nbody] = line
    if (depth > 0) next
    emit(); sig = ""; nbody = 0; depth = 0
}
AWK_EOF
}

# Reports a publish of &obj followed, in the SAME function body, by a free
# touching obj with no unpublish in between. Function-scoped and order-aware
# on purpose: a file-level check is not enough, because the pre-fix
# params_init.c had a CORRECT sapling_free_params() next to the broken
# sapling_init_params().
write_pubfree_analyzer() {
    cat > "$1" <<'AWK_EOF'
function base(v) { sub(/^&/, "", v); sub(/[.[].*$/, "", v); return v }
function flushfn(   j, line, call, setter, arg, v, obj, k, a, rest, td, mod) {
    if (nbody == 0) return
    nfuncs++
    delete pubat; delete clearedat; delete teardown
    for (j = 1; j <= nbody; j++) {
        line = body[j]
        rest = line
        while (match(rest, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\([ \t]*[^(),]*\)/)) {
            call = substr(rest, RSTART, RLENGTH)
            rest = substr(rest, RSTART + RLENGTH)
            setter = call; sub(/[ \t]*\(.*$/, "", setter)
            if (!(setter in PUB)) continue
            arg = call; sub(/^[^(]*\([ \t]*/, "", arg); sub(/[ \t]*\).*$/, "", arg)
            if (arg == "NULL" || arg == "0") clearedat[setter] = j
            else if (arg ~ /^&/) { obj = base(arg); pubat[setter SUBSEP obj] = j }
        }
        # A module teardown named for the same module is an unpublish too:
        # tip_finalize_stage_init(&ms) is undone by
        # tip_finalize_stage_shutdown(), not by passing NULL.
        if (match(line, /[A-Za-z_][A-Za-z0-9_]*_(shutdown|reset|clear|close|free)[ \t]*\(/)) {
            td = substr(line, RSTART, RLENGTH); sub(/[ \t]*\($/, "", td)
            sub(/_(shutdown|reset|clear|close|free)$/, "", td)
            teardown[td] = j
        }
        if (match(line, /(^|[^A-Za-z0-9_])([a-z0-9_]*_)?free[ \t]*\([ \t]*&?[A-Za-z_][A-Za-z0-9_.]*/)) {
            v = substr(line, RSTART, RLENGTH)
            sub(/^.*free[ \t]*\([ \t]*/, "", v)
            v = base(v)
            for (k in pubat) {
                split(k, a, SUBSEP)
                if (a[2] != v) continue
                if (pubat[k] >= j) continue
                if ((a[1] in clearedat) && clearedat[a[1]] > pubat[k] && clearedat[a[1]] < j) continue
                mod = a[1]; sub(/_(init|set_[A-Za-z0-9_]*)$/, "", mod)
                if ((mod in teardown) && teardown[mod] > pubat[k] && teardown[mod] < j) continue
                printf "PUBFREE\t%s\t%s\t%s\t%s\tpublish=L%d\tfree=L%d\n",
                    FILENAME, fnname, a[1], v, bodyline[pubat[k]], bodyline[j]
                nhit++
            }
        }
    }
}
BEGIN {
    depth = 0; nbody = 0; nfuncs = 0; nhit = 0
    if (PUBFILE != "") while ((getline pl < PUBFILE) > 0) if (pl != "") PUB[pl] = 1
}
{
    line = $0
    gsub(/"([^"\\]|\\.)*"/, "\"\"", line)
    sub(/\/\/.*$/, "", line)
    if (incomment) { if (line ~ /\*\//) { sub(/^.*\*\//, "", line); incomment = 0 } else next }
    while (match(line, /\/\*/)) {
        pre = substr(line, 1, RSTART - 1); rest = substr(line, RSTART)
        if (match(rest, /\*\//)) line = pre substr(rest, RSTART + 2)
        else { line = pre; incomment = 1; break }
    }
    nb = gsub(/\{/, "{", line); ne = gsub(/\}/, "}", line)
    if (depth == 0) {
        if (nb == 0) {
            if (line ~ /[^ \t]/) { if (line ~ /;[ \t]*$/) sig = ""; else sig = sig " " line }
            next
        }
        sigfull = sig " " line
        gsub(/[ \t]+/, " ", sigfull); sub(/^ +/, "", sigfull)
        depth = nb - ne
        if (depth <= 0) { sig = ""; depth = 0; next }
        if (sigfull !~ /\(/ || sigfull ~ /^(typedef|struct |union |enum )/) { sig = ""; nbody = 0; next }
        if (match(sigfull, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
            fnname = substr(sigfull, RSTART, RLENGTH); sub(/[ \t]*\(/, "", fnname)
        } else fnname = "?"
        sig = sigfull; nbody = 0
        next
    }
    depth += nb - ne
    nbody++; body[nbody] = line; bodyline[nbody] = FNR
    if (depth > 0) next
    flushfn(); sig = ""; nbody = 0; depth = 0
}
END { printf "PSTATS\t%s\t%d\t%d\n", FILENAME, nfuncs, nhit }
AWK_EOF
}

# ── selftest ──────────────────────────────────────────────────────────────
# Plants a CLEAN function (init above every exit) and a VIOLATING function
# (LOG_FAIL above the init, exactly the compact-block shape) and asserts the
# analyzer's verdict on each. A gate whose detector silently stops detecting
# is worse than no gate; this is the only thing that catches that.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/outparam-selftest.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    write_analyzer "$tmp/scan.awk"
    cat > "$tmp/case.c" <<'C_EOF'
#include <string.h>

/* CLEAN: out is initialized before the first thing that can fail. */
bool clean_reconstruct(const struct wire *w, struct block *out_block)
{
    block_init(out_block);
    size_t total = w->a + w->b;
    if (total == 0 || total > 100)
        LOG_FAIL("t", "bad count %zu", total);
    out_block->n = total;
    return true;
}

/* VIOLATING: LOG_FAIL expands to `return false` and sits above block_init. */
bool dirty_reconstruct(const struct wire *w, struct block *out_block)
{
    size_t total = w->a + w->b;
    if (total == 0 || total > 100)
        LOG_FAIL("t", "bad count %zu", total);
    block_init(out_block);
    out_block->n = total;
    return true;
}
C_EOF
    out="$(awk -f "$tmp/scan.awk" "$tmp/case.c")"
    # `printf ... | grep -q` inverts under pipefail (a MATCH reports 141), so
    # every assertion below is pipeline-free. See tools/scripts/sh_str.sh.
    # shellcheck source=tools/scripts/sh_str.sh
    source "$ROOT/tools/scripts/sh_str.sh"
    tab=$'\t'
    rc=0
    if str_contains "$out" "FINDING${tab}${tmp}/case.c${tab}dirty_reconstruct${tab}block${tab}out_block${tab}DATA"; then
        echo "  selftest: violating case DETECTED — ok"
    else
        echo "  selftest: FAIL — the violating case was NOT detected" >&2
        printf '%s\n' "$out" >&2
        rc=1
    fi
    if str_contains "$out" "clean_reconstruct"; then
        echo "  selftest: FAIL — the clean case was reported as a violation" >&2
        printf '%s\n' "$out" >&2
        rc=1
    else
        echo "  selftest: clean case NOT reported — ok"
    fi
    # The STATS line must show the scan actually walked both functions;
    # without this a broken parser passes both assertions by finding nothing.
    if str_contains "$out" "STATS${tab}${tmp}/case.c${tab}2${tab}2"; then
        echo "  selftest: parser saw 2 functions and 2 out-params — ok"
    else
        echo "  selftest: FAIL — parser did not see 2 functions / 2 out-params" >&2
        printf '%s\n' "$out" >&2
        rc=1
    fi
    # ── leg 2: published global freed without unpublishing ────────────────
    write_publisher_finder "$tmp/pub.awk"
    write_pubfree_analyzer "$tmp/pubfree.awk"
    cat > "$tmp/sink.c" <<'C_EOF'
static struct groth16_vk *sapling_spend_vk = NULL;
void sapling_set_spend_vk(struct groth16_vk *vk) { sapling_spend_vk = vk; }
void set_by_value(struct groth16_vk *vk) { vk->n = 0; }
C_EOF
    cat > "$tmp/loader.c" <<'C_EOF'
static struct groth16_vk spend_vk;

/* VIOLATING: publishes, then a later failure path frees the published
 * storage without ever storing NULL back into the sink. */
bool dirty_init(const char *dir)
{
    sapling_set_spend_vk(&spend_vk);
    if (!read_sprout(dir)) {
        free(spend_vk.ic);
        return false;
    }
    return true;
}

/* CLEAN: unpublishes before freeing. */
bool clean_init(const char *dir)
{
    sapling_set_spend_vk(&spend_vk);
    if (!read_sprout(dir)) {
        sapling_set_spend_vk(NULL);
        free(spend_vk.ic);
        return false;
    }
    return true;
}
C_EOF
    awk -f "$tmp/pub.awk" "$tmp/sink.c" | sort -u > "$tmp/pubnames.txt"
    pubout="$(awk -v PUBFILE="$tmp/pubnames.txt" -f "$tmp/pubfree.awk" "$tmp/loader.c")"
    if str_contains "$(cat "$tmp/pubnames.txt")" "sapling_set_spend_vk"; then
        echo "  selftest: publisher DERIVED from the store, not the name — ok"
    else
        echo "  selftest: FAIL — the publisher was not derived" >&2
        cat "$tmp/pubnames.txt" >&2
        rc=1
    fi
    if str_lacks "$(cat "$tmp/pubnames.txt")" "set_by_value"; then
        echo "  selftest: a set_* that only writes THROUGH the pointer is not a publisher — ok"
    else
        echo "  selftest: FAIL — set_by_value was misread as a publisher" >&2
        rc=1
    fi
    if str_contains "$pubout" "PUBFREE${tab}${tmp}/loader.c${tab}dirty_init"; then
        echo "  selftest: publish-then-free-without-unpublish DETECTED — ok"
    else
        echo "  selftest: FAIL — the published-global violation was NOT detected" >&2
        printf '%s\n' "$pubout" >&2
        rc=1
    fi
    if str_contains "$pubout" "clean_init"; then
        echo "  selftest: FAIL — the unpublish-first case was reported" >&2
        printf '%s\n' "$pubout" >&2
        rc=1
    else
        echo "  selftest: unpublish-first case NOT reported — ok"
    fi

    if [ "$rc" -eq 0 ]; then
        echo "check_outparam_init_before_return --selftest: PASS"
    else
        echo "check_outparam_init_before_return --selftest: FAIL" >&2
    fi
    exit "$rc"
fi

cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source "$ROOT/tools/lint/scan_exclusions.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/outparam-gate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
write_analyzer "$WORK/scan.awk"

# Scan set: every tracked .c file outside vendor/.
mapfile -t SRCS < <(git ls-files '*.c' | grep -v '^vendor/' || true)
gate_require_scanned "${#SRCS[@]}" 2000 check-outparam-init-before-return \
    "expected thousands of tracked .c files; the git ls-files producer is empty"

# The set of struct types that have a *_free: only those can be wild-freed by
# a caller, so only those are in scope. Derived, never hand-listed.
git ls-files '*.c' '*.h' | grep -v '^vendor/' \
    | xargs grep -hoE '\b[a-z0-9_]+_free\b' 2>/dev/null \
    | sort -u > "$WORK/frees.txt" || true
free_count=$(wc -l < "$WORK/frees.txt")
gate_require_scanned "$free_count" 100 check-outparam-init-before-return \
    "expected >=100 distinct *_free symbols; the derivation is empty"

printf '%s\0' "${SRCS[@]}" | xargs -0 awk -f "$WORK/scan.awk" > "$WORK/raw.txt" 2>/dev/null || true

scanned_funcs=$(awk -F'\t' '$1=="STATS"{n+=$3} END{print n+0}' "$WORK/raw.txt")
gate_require_scanned "$scanned_funcs" 10000 check-outparam-init-before-return \
    "the analyzer walked almost no function bodies — its C parser is broken"

# ── leg 2: published global freed without unpublishing ───────────────────
# Zero-tolerance, no allowlist: the tree has none today, so the first one to
# land fails here. Scoped to PRODUCTION sources. Test harnesses legitimately
# hand a stage module a &main_state and then free it at case teardown, which
# is the same textual shape and ~870 occurrences; baselining those would bury
# the one shape that actually shipped a use-after-free.
write_publisher_finder "$WORK/pub.awk"
write_pubfree_analyzer "$WORK/pubfree.awk"

printf '%s\0' "${SRCS[@]}" | xargs -0 awk -f "$WORK/pub.awk" 2>/dev/null \
    | sort -u > "$WORK/publishers.txt" || true
pub_count=$(wc -l < "$WORK/publishers.txt")
gate_require_scanned "$pub_count" 20 check-outparam-init-before-return \
    "expected >=20 publisher functions (a store of a caller pointer into a file-scope var); the derivation is empty"

mapfile -t PROD_SRCS < <(printf '%s\n' "${SRCS[@]}" \
    | grep -vE '^(lib/test/|tests/|tools/fuzz/|examples/|lib/vcs/tests/)' || true)
gate_require_scanned "${#PROD_SRCS[@]}" 1000 check-outparam-init-before-return \
    "expected >=1000 production .c files after excluding harnesses"

printf '%s\0' "${PROD_SRCS[@]}" | xargs -0 \
    awk -v PUBFILE="$WORK/publishers.txt" -f "$WORK/pubfree.awk" \
    > "$WORK/pubraw.txt" 2>/dev/null || true
pub_scanned=$(awk -F'\t' '$1=="PSTATS"{n+=$3} END{print n+0}' "$WORK/pubraw.txt")
gate_require_scanned "$pub_scanned" 5000 check-outparam-init-before-return \
    "the publish/free analyzer walked almost no function bodies"

pubfree_hits=$(grep -c '^PUBFREE' "$WORK/pubraw.txt" || true)
if [ "${pubfree_hits:-0}" -gt 0 ]; then
    {
        echo "check-outparam-init-before-return: ${pubfree_hits} PUBLISHED pointer(s) freed"
        echo "  without being unpublished first:"
        grep '^PUBFREE' "$WORK/pubraw.txt" \
            | awk -F'\t' '{printf "    %s: %s() published %s via %s at %s, freed at %s\n", $2, $3, $5, $4, $6, $7}'
        echo
        echo "  Every reader's fail-closed guard asks only whether the published"
        echo "  pointer is NULL. That reading is true only while every failure path"
        echo "  actually produces NULL. Publish BELOW every fallible step, and"
        echo "  unpublish BEFORE freeing — see the invariant comment in"
        echo "  lib/sapling/src/params_init.c."
    } >&2
    pubfree_failed=1
else
    pubfree_failed=0
fi

# Keep only in-scope findings: freeable type, data-dependent pre-init exit,
# and not the type's own <type>_init / <type>_free / <type>_reset (where the
# memset IS the teardown, not a missing init).
awk -F'\t' '
    NR==FNR { free[$0]=1; next }
    # FINDING <file> <fn> <type> <param> <kind> <exit-line> <init-line> <tag>
    $1=="FINDING" {
        fn=$3; ty=$4; nm=$5
        if (!((ty "_free") in free)) next
        if ($6 != "DATA") next
        if (fn == ty "_free" || fn == ty "_init" || fn == ty "_reset") next
        printf "%s|%s|%s\t%s\texit=L%s init=L%s(%s)\n", fn, nm, ty, $2, $7, $8, $9
    }
' "$WORK/frees.txt" "$WORK/raw.txt" > "$WORK/detail.txt"

cut -f1 "$WORK/detail.txt" | sort -u > "$WORK/keys.txt"
found=$(wc -l < "$WORK/keys.txt")
gate_require_scanned "$found" 1 check-outparam-init-before-return \
    "the in-scope filter matched nothing at all — the *_free derivation or the analyzer changed shape"

# Maintainer aid: print every in-scope finding with its file and line numbers,
# in baseline-key order, so a reviewer can work the list and paste the keys.
if [ "${1:-}" = "--print-findings" ]; then
    sort "$WORK/detail.txt"
    exit 0
fi

declare -A ALLOWED
gate_load_list_file "$BASELINE" ALLOWED baseline_count
gate_require_scanned "$baseline_count" 1 check-outparam-init-before-return \
    "$BASELINE is missing or empty"

new=()
while IFS= read -r key; do
    [ -z "$key" ] && continue
    [ -n "${ALLOWED[$key]:-}" ] || new+=("$key")
done < "$WORK/keys.txt"

# A baseline entry that no longer matches any code is a stale exception, and a
# stale exception is how an allowlist stops being closed: the next function
# that happens to reuse the name inherits a waiver nobody reviewed. Removing
# it is the whole point of having fixed the code.
stale=()
for key in "${!ALLOWED[@]}"; do
    grep -qxF "$key" "$WORK/keys.txt" || stale+=("$key")
done
failed="$pubfree_failed"

# NEW findings are reported FIRST and unconditionally: a stale-baseline
# complaint must never pre-empt the report of an actual new violation.
if [ "${#new[@]}" -gt 0 ]; then
    {
        echo "check-outparam-init-before-return: ${#new[@]} NEW out-parameter(s) whose"
        echo "  initialization sits BELOW a failure return:"
        for k in "${new[@]}"; do
            fn=${k%%|*}; rest=${k#*|}; pm=${rest%%|*}; ty=${rest##*|}
            echo "    $fn(): struct $ty *$pm"
            grep -F "$k	" "$WORK/detail.txt" | cut -f2- | sed 's/^/        at /' || true
        done
        echo
        echo "  Remember LOG_FAIL / LOG_ERR / LOG_RETURN EXPAND TO a return."
        echo "  Fix by moving the *_init()/memset() ABOVE the first thing that can"
        echo "  fail, and state the post-condition in the header so the next caller"
        echo "  can rely on it — see lib/net/include/net/compact_blocks.h."
        echo "  If the caller provably never frees on that path, add the key to"
        echo "  $BASELINE with a one-line reviewed reason:"
        for k in "${new[@]}"; do echo "    $k"; done
    } >&2
    if [ "$MODE" = "WARN" ]; then
        echo "check-outparam-init-before-return: WARN (${#new[@]} new)"
    else
        failed=1
    fi
fi

if [ "${#stale[@]}" -gt 0 ]; then
    {
        echo "check-outparam-init-before-return: ${#stale[@]} STALE baseline entr(ies)"
        echo "  in $BASELINE — the code they name no longer trips this gate."
        echo "  Delete them (and the reason comment above them):"
        for k in "${stale[@]}"; do echo "    $k"; done
    } >&2
    [ "$MODE" = "WARN" ] || failed=1
fi

[ "$failed" -eq 0 ] || exit 1

echo "check-outparam-init-before-return: clean — ${scanned_funcs} function bodies scanned, ${found} in-scope out-param(s), all ${baseline_count} reviewed; ${pub_scanned} bodies checked for publish-before-free over ${pub_count} publishers, 0 dangling"
