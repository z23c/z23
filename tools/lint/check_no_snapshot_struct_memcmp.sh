#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_snapshot_struct_memcmp.sh — refuse a raw `memcmp`/`bcmp` over a
# `struct platform_positioned_file_snapshot` object (Makefile
# `check-no-snapshot-struct-memcmp` gate).
#
# ── THE DEFECT CLASS ─────────────────────────────────────────────────────
# `struct platform_positioned_file_snapshot`
# (lib/platform/include/platform/positioned_file.h) is 64 bytes wide but
# holds only 56 bytes of fields: two `uint32_t` nanosecond members sit in
# front of wider `int64_t`/`uint64_t` members, so the compiler inserts 8
# bytes of alignment padding it is never required to initialize. A
# `memcmp(&before, &after, sizeof(before)) == 0` "did this file change under
# me?" check therefore reads those 8 indeterminate bytes and can report a
# change when nothing about the file changed.
#
# This exact bug landed THREE TIMES. Three call sites were fixed once; three
# more (lib/vcs/src/vcs_object.c, lib/vcs/src/zcode_dht_record_store.c,
# lib/vcs/src/package_swarm_receipt_session.c) turned up later in commit
# 44c45f255 and had taken twenty test groups red, mostly reporting nothing
# more specific than "object changed while read". The correct comparison
# already exists: platform_positioned_file_snapshot_equal()
# (lib/platform/include/platform/positioned_file.h:53), which compares
# field-by-field and never touches the padding.
#
# ── WHAT THIS GATE CATCHES ──────────────────────────────────────────────
# For every `.c`/`.h` file under app/ config/ lib/ src/ tools/ (excluding
# vendor/): find identifiers declared, on ONE physical line, as
#
#     struct platform_positioned_file_snapshot <name>[, <name>...];
#
# (a plain OBJECT declaration — no `*`, so a pointer parameter like
# `const struct platform_positioned_file_snapshot *a` is correctly not
# collected as a name to watch), then flag any `memcmp(` or `bcmp(` call
# ELSEWHERE IN THAT SAME FILE whose first or second argument — after
# stripping a leading `&` — is bare one of those names.
#
# ── WHAT THIS GATE CANNOT SEE (said plainly, not implied) ──────────────
# This is a text scan, not a type checker. It is deliberately narrow and
# every gap below is a known, accepted false-negative, not an oversight:
#
#   * A snapshot object declared across multiple physical lines, with an
#     initializer, or reached through a typedef alias is not collected as a
#     name to watch.
#   * A `memcmp`/`bcmp` call whose argument list spans multiple physical
#     lines is not parsed (the three real defects fixed in 44c45f255 were
#     all single-line calls; this scan only ever looked at one line at a
#     time).
#   * A pointer to a snapshot struct passed into a HELPER function that
#     does the `memcmp` internally is completely out of reach — this gate
#     never crosses a function call boundary, so
#     `bool stable(struct platform_positioned_file_snapshot *a, ...)`
#     comparing `*a` with `memcmp` in a different file, or even a different
#     function in the same file that never itself declares a snapshot
#     object, is invisible to it.
#   * `memcmp` reached only through a wrapping macro (`MY_MEMCMP_EQ(a, b)`)
#     is invisible: this gate looks for the literal tokens `memcmp(` /
#     `bcmp(`, not for macro expansions.
#   * A snapshot object copied into a differently-typed buffer (e.g. cast
#     to `unsigned char[64]`) before the `memcmp` breaks the name-based
#     match entirely.
#   * The identifier match is by NAME, not by type: if a file coincidentally
#     declares a snapshot object named `x` and separately has an unrelated
#     `memcmp(x, ...)` on a completely different variable also named `x` in
#     a different scope, this gate would flag it. Measured against the
#     real tree at introduction (2026-08-28): zero such collisions exist —
#     every file that declares a snapshot object and also calls memcmp/bcmp
#     was checked by hand, and none of the OTHER memcmp calls in those files
#     touch a name shared with a snapshot declaration.
#
# A narrow gate that is honest about these gaps beats a broad one that
# claims exhaustiveness it cannot deliver. If a case above is ever missed in
# production, THAT is the moment to widen the detector — not before.
#
# ── HONESTY CONTRACT ─────────────────────────────────────────────────────
# A scan that silently walks zero files, or whose declaration parse comes
# back empty, must never report "clean" — this repo has been bitten by
# exactly that shape of hollow gate before. Both floors below are asserted
# with gate_require_scanned (tools/lint/gate_lib.sh), which exits 2 (FATAL,
# never a quiet 0) when the realized count is under the floor.
#
# Usage:
#   tools/lint/check_no_snapshot_struct_memcmp.sh              # the gate
#   tools/lint/check_no_snapshot_struct_memcmp.sh --self-test   # prove it
#                                                                 # trips
#
# Exit: 0 clean; 1 on a real violation; 2 on a hollow/misconfigured scan.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
. tools/lint/scan_exclusions.sh

GATE="check-no-snapshot-struct-memcmp"
STRUCT_TYPE="platform_positioned_file_snapshot"
SCAN_DIRS=(app config lib src tools)

# A plain (non-pointer) object declaration, one or more names, on one
# physical line. Excluding any line that contains a `*` between the type
# name and the trailing `;` is what keeps pointer parameters
# (`const struct platform_positioned_file_snapshot *a,`) out of the
# collected name set — those are never the two operands of a same-object
# `memcmp`, they are the comparator function's own parameters.
DECL_RE='^[[:space:]]*(static[[:space:]]+|const[[:space:]]+)*struct[[:space:]]+platform_positioned_file_snapshot[[:space:]]+[^*]*;[[:space:]]*$'
DECL_PREFIX_RE='^[[:space:]]*(static[[:space:]]+|const[[:space:]]+)*struct[[:space:]]+platform_positioned_file_snapshot[[:space:]]+'
# NOTE the doubled backslash: this string travels through awk's `-v`
# assignment, which — like a string constant written in awk program text —
# interprets one level of backslash escaping. A single `\(` would collapse
# to a bare `(` before the regex engine ever sees it (observed: gawk warns
# "escape sequence `\(' treated as plain `('" and then a group), so
# `\\(` is what survives -v's unescaping as the literal `\(` the dynamic
# regexp needs to match a real parenthesis instead of opening a group.
USE_RE='(^|[^A-Za-z0-9_])(memcmp|bcmp)[[:space:]]*\\('

# Measured on the real tree at introduction (2026-08-28): 4356 in-scope
# .c/.h files, 107 matching declaration lines. Both floors sit well below
# that so a directory move or a regex that stops matching is a loud FATAL,
# never a silent "0 to check".
FILE_FLOOR=3000
DECL_FLOOR=40

# ── declaration extractor ────────────────────────────────────────────────
# Reads one file; for every DECL_RE line, prints one collected identifier
# per output line (array-suffix stripped, comma-separated names split out).
# A part that doesn't survive as a bare C identifier after trimming (an
# initializer, a stray token) is silently dropped, not guessed at.
read -r -d '' DECL_AWK <<'AWK_EOF'
{
  line = $0
  if (line ~ dre) {
    rest = line
    sub(pre, "", rest)
    sub(/;[ \t]*$/, "", rest)
    n = split(rest, parts, ",")
    for (i = 1; i <= n; i++) {
      p = parts[i]
      gsub(/^[ \t]+|[ \t]+$/, "", p)
      sub(/\[.*\]$/, "", p)
      if (p ~ /^[A-Za-z_][A-Za-z0-9_]*$/) print p
    }
  }
}
AWK_EOF

# ── memcmp/bcmp scanner ──────────────────────────────────────────────────
# Reads one file; `idlist` (-v, newline-separated) is the set of snapshot
# object names collected from that same file by DECL_AWK above. For every
# memcmp(/bcmp( call whose ARGUMENT LIST closes on the same physical line,
# split the top-level (paren/bracket/brace-depth 0) comma-separated
# arguments and check the first two (the two compared pointers — the third,
# `sizeof(...)`/length argument, is never checked, so `sizeof(before)` alone
# does not trip this) for a leading `&`-stripped bare identifier that is one
# of the watched names. A call whose parens are unbalanced on this line
# (the argument list spans multiple lines) is skipped — out of reach, see
# the header comment.
read -r -d '' SCAN_AWK <<'AWK_EOF'
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function base_ident(s) {
    if (match(s, /^[A-Za-z_][A-Za-z0-9_]*/)) return substr(s, RSTART, RLENGTH)
    return ""
}
function split_top(s, arr,    i, c, n, depth, cur, cnt) {
    depth = 0; cur = ""; cnt = 0; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "(" || c == "[" || c == "{") depth++
        else if (c == ")" || c == "]" || c == "}") depth--
        if (c == "," && depth == 0) { cnt++; arr[cnt] = cur; cur = "" }
        else cur = cur c
    }
    cnt++; arr[cnt] = cur
    return cnt
}
BEGIN {
    nids = split(idlist, idtmp, "\n")
    for (i = 1; i <= nids; i++) if (idtmp[i] != "") ids[idtmp[i]] = 1
}
{
    rest = $0
    while (match(rest, ure)) {
        mstart = RSTART; mlen = RLENGTH
        openpos = mstart + mlen - 1
        depth = 0; closepos = 0; rn = length(rest)
        for (i = openpos; i <= rn; i++) {
            c = substr(rest, i, 1)
            if (c == "(") depth++
            else if (c == ")") { depth--; if (depth == 0) { closepos = i; break } }
        }
        if (closepos == 0) { rest = substr(rest, openpos + 1); continue }
        args = substr(rest, openpos + 1, closepos - openpos - 1)
        delete argv
        na = split_top(args, argv)
        hit = ""
        for (k = 1; k <= 2 && k <= na; k++) {
            a = trim(argv[k])
            sub(/^&[ \t]*/, "", a)
            b = base_ident(a)
            if (b != "" && (b in ids)) { hit = b; break }
        }
        if (hit != "") {
            print FILENAME ":" FNR ": memcmp()/bcmp() compares a struct " \
                  "platform_positioned_file_snapshot object (`" hit "`) by " \
                  "raw bytes -- the struct has 8 bytes of never-initialized " \
                  "alignment padding, so this can report an unchanged file " \
                  "as CHANGED. Use platform_positioned_file_snapshot_equal() " \
                  "(lib/platform/include/platform/positioned_file.h) instead."
        }
        rest = substr(rest, closepos + 1)
    }
}
AWK_EOF

# ── core scan, parameterized on directories so --self-test can point it at
# a throwaway fixture tree instead of the real one ─────────────────────────
# Sets SCAN_FILE_COUNT, SCAN_DECL_COUNT, SCAN_VIOLATIONS (global — a bash
# function returning three values does it this way or via a temp file; this
# is the shorter honest option, documented here rather than left implicit).
run_scan() {
    local files decl_files f ids idlist hits n_ids
    SCAN_FILE_COUNT=0
    SCAN_DECL_COUNT=0
    SCAN_VIOLATIONS=""

    files="$(find "$@" -type f \( -name '*.c' -o -name '*.h' \) \
        "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)"
    [ -z "$files" ] && return 0
    SCAN_FILE_COUNT=$(printf '%s\n' "$files" | wc -l)

    decl_files="$(printf '%s\n' "$files" | xargs -r grep -lE "$DECL_RE" 2>/dev/null)"
    [ -z "$decl_files" ] && return 0

    while IFS= read -r f; do
        [ -z "$f" ] && continue
        ids="$(awk -v dre="$DECL_RE" -v pre="$DECL_PREFIX_RE" "$DECL_AWK" "$f" | sort -u)"
        [ -z "$ids" ] && continue
        n_ids=$(printf '%s\n' "$ids" | wc -l)
        SCAN_DECL_COUNT=$((SCAN_DECL_COUNT + n_ids))
        idlist="$ids"
        hits="$(awk -v ure="$USE_RE" -v idlist="$idlist" "$SCAN_AWK" "$f")"
        if [ -n "$hits" ]; then
            if [ -n "$SCAN_VIOLATIONS" ]; then
                SCAN_VIOLATIONS="${SCAN_VIOLATIONS}"$'\n'"${hits}"
            else
                SCAN_VIOLATIONS="$hits"
            fi
        fi
    done <<< "$decl_files"
    return 0
}

# ── --self-test ─────────────────────────────────────────────────────────
# (a) plants a violating fixture (a snapshot object compared with a raw
#     memcmp, exactly the shape fixed in 44c45f255) and asserts the gate
#     trips on it, at the right file and line; plants a clean fixture
#     (a snapshot object declared in the same file as an UNRELATED memcmp
#     of a different struct, by different names) and asserts it stays
#     silent — proving the name-based match does not just flag every file
#     that merely contains the word "memcmp".
# (b) runs the real scan (production directories) and asserts zero
#     violations, since the three known sites were fixed in 44c45f255.
if [ "${1:-}" = "--self-test" ]; then
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-snapshot-memcmp-selftest.XXXXXX")" || {
        echo "$GATE --self-test: FATAL — mktemp failed." >&2; exit 2; }
    trap 'rm -rf "$WORK"' EXIT

    mkdir -p "$WORK/fixture"
    cat > "$WORK/fixture/violating.c" <<'C_EOF'
#include "platform/positioned_file.h"
#include <string.h>

static bool probe_stable(struct platform_positioned_file *file)
{
    struct platform_positioned_file_snapshot before, after;
    (void)platform_positioned_file_snapshot(file, &before);
    (void)platform_positioned_file_snapshot(file, &after);
    return memcmp(&before, &after, sizeof(before)) == 0;
}
C_EOF

    cat > "$WORK/fixture/clean.c" <<'C_EOF'
#include "platform/positioned_file.h"
#include <string.h>

struct other_thing { int x; int y; };

static int cmp_other(const struct other_thing *a, const struct other_thing *b)
{
    /* Unrelated memcmp, unrelated struct, names 'a'/'b' -- must NOT trip
     * the gate just because the file also declares a snapshot pair below. */
    return memcmp(a, b, sizeof(*a));
}

struct platform_positioned_file_snapshot before, after;

static bool probe_stable_ok(void)
{
    /* The correct predicate -- field-wise, never memcmp. */
    return platform_positioned_file_snapshot_equal(&before, &after);
}
C_EOF

    run_scan "$WORK/fixture"
    fail=0

    expect_line=9
    case "$SCAN_VIOLATIONS" in
        *"violating.c:${expect_line}: memcmp()/bcmp() compares"*) : ;;
        *)
            echo "FAIL: --self-test — the violating fixture (raw memcmp of" >&2
            echo "  two struct platform_positioned_file_snapshot objects," >&2
            echo "  violating.c:${expect_line}) was NOT flagged. Gate is hollow." >&2
            echo "  SCAN_VIOLATIONS was:" >&2
            printf '%s\n' "$SCAN_VIOLATIONS" | sed 's/^/    /' >&2
            fail=1
            ;;
    esac
    case "$SCAN_VIOLATIONS" in
        *"clean.c:"*)
            echo "FAIL: --self-test — the clean fixture (an UNRELATED memcmp" >&2
            echo "  in a file that also happens to declare a snapshot pair)" >&2
            echo "  was flagged. The gate is not name-precise; it would false-" >&2
            echo "  positive on every file that declares a snapshot object and" >&2
            echo "  ALSO calls memcmp for anything else." >&2
            printf '%s\n' "$SCAN_VIOLATIONS" | sed 's/^/    /' >&2
            fail=1
            ;;
        *) : ;;
    esac
    if [ "$fail" = 0 ]; then
        echo "  ok: --self-test fixture — trips on the violating file/line," \
             "silent on the clean one"
    fi

    run_scan "${SCAN_DIRS[@]}"
    gate_require_scanned "$SCAN_FILE_COUNT" "$FILE_FLOOR" "$GATE --self-test" \
        "the real-tree leg of --self-test scanned too few files"
    gate_require_scanned "$SCAN_DECL_COUNT" "$DECL_FLOOR" "$GATE --self-test" \
        "the real-tree leg of --self-test parsed too few declarations"
    if [ -n "$SCAN_VIOLATIONS" ]; then
        echo "FAIL: --self-test — the REAL tree has a violation; the three" >&2
        echo "  known sites (fixed in 44c45f255) should be clean:" >&2
        printf '%s\n' "$SCAN_VIOLATIONS" | sed 's/^/    /' >&2
        fail=1
    else
        echo "  ok: --self-test real tree — $SCAN_FILE_COUNT file(s)," \
             "$SCAN_DECL_COUNT declaration(s), 0 violations"
    fi

    if [ "$fail" != 0 ]; then
        exit 1
    fi
    echo "  OK: $GATE --self-test"
    exit 0
fi

# ── the gate ─────────────────────────────────────────────────────────────
echo "══ LINT: no raw memcmp/bcmp over a struct platform_positioned_file_snapshot ══"

run_scan "${SCAN_DIRS[@]}"
gate_require_scanned "$SCAN_FILE_COUNT" "$FILE_FLOOR" "$GATE" \
    "scanned '${SCAN_DIRS[*]}' for *.c/*.h — a directory move or a broken find would show up here"
gate_require_scanned "$SCAN_DECL_COUNT" "$DECL_FLOOR" "$GATE" \
    "parsed 'struct $STRUCT_TYPE <name>[, <name>...];' declarations — if this legitimately drops to zero because every site moved to a different declaration shape, lower DECL_FLOOR by hand with a comment explaining why; do not let a silently-broken regex read as 'nothing to check'"

if [ -n "$SCAN_VIOLATIONS" ]; then
    echo "" >&2
    echo "FAIL: raw memcmp()/bcmp() over a struct $STRUCT_TYPE object." >&2
    echo "  The struct carries 8 bytes of never-initialized alignment" >&2
    echo "  padding (see lib/platform/include/platform/positioned_file.h)," >&2
    echo "  so comparing the whole object by raw bytes can report an" >&2
    echo "  UNCHANGED file as changed. Use" >&2
    echo "  platform_positioned_file_snapshot_equal() instead." >&2
    echo "" >&2
    printf '%s\n' "$SCAN_VIOLATIONS" | sed 's/^/  /' >&2
    exit 1
fi

echo "  OK: $SCAN_FILE_COUNT file(s) scanned, $SCAN_DECL_COUNT struct" \
     "$STRUCT_TYPE object declaration(s), 0 memcmp/bcmp comparisons of them"
exit 0
