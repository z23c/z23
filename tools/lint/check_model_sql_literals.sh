#!/usr/bin/env bash
# Gate — literal SQL in the models layer (ratchet, shrink-only file list).
#
# What it enforces
# ----------------
# A model file must not carry a hand-written SQL statement. Reads and writes
# go through the typed query builder,
# app/models/include/models/query_builder.h, whose identifiers come from the
# closed set in query_schema.def and whose values can only reach the
# statement as bound parameters. Every file still holding a literal is listed
# in model_sql_literal_baseline.txt. THAT LIST MAY ONLY SHRINK.
#
# Why
# ---
# An audit of the 87 model files found 70 carrying literal SQL and — the good
# news — no injection hole: nothing concatenated a caller value into
# statement text and every parameter was bound. But that safety was resting
# on 70 files' worth of authors each remembering, every time, forever, with
# no builder available to make the safe thing the easy thing. The two defects
# the conversion did surface are exactly the shape you get from hand-written
# SQL, and neither was an injection:
#
#   - app/models/src/peer.c wrote strftime('%%s','now') in a string that is
#     handed straight to sqlite3_prepare_v2 with no printf in the path. In
#     SQLite '%%' is an escaped percent, so that expression evaluated to the
#     TEXT "%s" and every db_peer_mark_tried() had been storing two literal
#     characters in peers.last_try instead of the epoch. Every other
#     strftime site in app/models uses a single '%s'.
#   - app/models/src/op_return_index.c built its prune DELETE with snprintf
#     ("... WHERE height<%d"). The value was a machine-derived int32_t so it
#     was never exploitable, but it was the one place in the layer where a
#     value reached SQL as text rather than as a parameter.
#
# Neither is the kind of bug a reviewer finds by reading; both are the kind a
# rail removes. This gate is that rail's ratchet.
#
# Unit of measurement
# -------------------
# Per FILE. A file "carries literal SQL" when a string literal in it OPENS a
# DML statement — the literal's first non-space token is SELECT, INSERT,
# UPDATE, DELETE, REPLACE or WITH, uppercase (every SQL keyword in this tree
# is written uppercase; a lowercase identifier like "update_foo: bad args" is
# not a statement and must not be flagged). Continuation fragments of a
# multi-line statement are not counted separately — one file, one row.
#
# DDL is counted the same as DML when it opens a statement string, because a
# migration file that also carries a data statement is still a file a model
# author will copy from. Migration and schema files are therefore ordinary
# baseline rows, not exemptions: a query builder cannot express CREATE TABLE,
# so those rows are expected to stay, and their presence costs nothing —
# the list only has to shrink over time, not empty.
#
# Excluded from the scan, with reasons:
#   app/models/src/query_builder.c        — it IS the SQL constructor. Every
#   app/models/include/models/query_builder.h  keyword it emits is a builder
#   app/models/include/models/query_schema.def token, not a hand-written
#                                              statement. Flagging the rail
#                                              itself would make the gate
#                                              unfixable.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#   UPDATE can only be run deliberately, and adding a row is not a fix.
#
# A baseline row whose file no longer carries literal SQL must be DELETED, or
# the ratchet rusts shut at a stale list. That is reported as a failure too,
# and it is what makes the count strictly monotonic: converting a model
# forces its row out, and the row cannot come back without failing the gate.
#
# --selftest plants each shape in a sandbox and requires the gate to FAIL on
# it, then plants innocent files and requires a PASS — so a gate whose regex
# quietly stopped matching cannot keep reporting PASS.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_model_sql_literals
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_MODEL_SQL_BASELINE:-tools/lint/model_sql_literal_baseline.txt}"
SCAN_ROOT="${ZCL_MODEL_SQL_SCAN_ROOT:-app/models}"
FILE_FLOOR="${ZCL_MODEL_SQL_FILE_FLOOR:-80}"

# A string literal whose first non-space token opens a SQL statement.
RE_SQL_LITERAL='"[[:space:]]*(SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH|CREATE|ALTER|DROP|PRAGMA)[[:space:]]'

# The builder itself, by basename — it emits these keywords by construction.
is_the_rail() {
    case "$1" in
        */query_builder.c|*/query_builder.h|*/query_schema.def) return 0 ;;
        *) return 1 ;;
    esac
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    self="$PWD/tools/lint/$GATE.sh"
    mkdir -p "$tmp/models/src" "$tmp/models/include/models"
    : > "$tmp/baseline.txt"

    # Filler so the scan-set floor is met without any of it being SQL.
    i=0
    while [ "$i" -lt 12 ]; do
        printf 'static int filler_%d(void) { return %d; }\n' "$i" "$i" \
            > "$tmp/models/src/filler_$i.c"
        i=$((i + 1))
    done

    plant() { printf '%s\n' "$2" > "$tmp/models/src/$1"; }

    run_sandbox() {
        ZCL_MODEL_SQL_SCAN_ROOT="$tmp/models" \
        ZCL_MODEL_SQL_BASELINE="$tmp/baseline.txt" \
        ZCL_MODEL_SQL_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" 2>&1
    }

    expect() { # $1 = fail|pass, $2 = message, $3 = needle ("" to skip)
        local want="$1" msg="$2" needle="$3" out rc=0
        out="$(run_sandbox)" || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg (expected a rejection)" >&2
            printf '%s\n' "$out" | sed 's/^/    /' >&2
            exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg (expected a PASS)" >&2
            printf '%s\n' "$out" | sed 's/^/    /' >&2
            exit 2
        fi
        # Here-string, not a pipeline: under `set -o pipefail` a MATCH in
        # `printf | grep -q` can surface printf's SIGPIPE 141 instead of
        # grep's 0 (see check_pipefail_status_pipe).
        if [ -n "$needle" ] && ! grep -qF "$needle" <<<"$out"; then
            echo "$GATE: SELFTEST FAILED — $msg (never named '$needle')" >&2
            printf '%s\n' "$out" | sed 's/^/    /' >&2
            exit 2
        fi
        echo "  selftest ok: $msg"
    }

    # ── negative controls: each planted statement must FAIL ──
    plant offender.c 'static const char *k = "SELECT id FROM peers WHERE ip=?";'
    expect fail "an unbaselined SELECT literal is caught" "offender.c"

    plant offender.c 'bool save(void) { return exec("INSERT INTO peers (ip) VALUES (?)"); }'
    expect fail "an INSERT literal is caught" "offender.c"

    plant offender.c 'bool bump(void) { return exec("UPDATE peers SET a=a+1 WHERE ip=?"); }'
    expect fail "an UPDATE literal is caught" "offender.c"

    plant offender.c 'bool reap(void) { return exec("DELETE FROM peers WHERE id<?"); }'
    expect fail "a DELETE literal is caught" "offender.c"

    plant offender.c 'static const char *k =
    "SELECT a,b,c"
    " FROM peers WHERE ip=?";'
    expect fail "a statement split across adjacent literals is caught" \
        "offender.c"

    # ── the ratchet: a baselined file is tolerated ──
    plant offender.c 'static const char *k = "SELECT id FROM peers";'
    printf '%s\n' "$tmp/models/src/offender.c" > "$tmp/baseline.txt"
    expect pass "a baselined file is tolerated (ratchet, not a hard ban)" ""

    # ── a stale row FAILS, so the list can only shrink ──
    plant offender.c 'static int clean(void) { return 0; }'
    expect fail "a baseline row whose file is now clean is caught as STALE" \
        "STALE"

    # ── a converted file that REGRESSES is caught ──
    # (same as the first case, but with a non-empty baseline that does NOT
    #  name it — the exact situation after a model is converted.)
    printf '%s\n' "$tmp/models/src/other.c" > "$tmp/baseline.txt"
    plant other.c 'static const char *k = "SELECT 1 FROM peers";'
    plant converted.c 'static const char *k = "SELECT id FROM peers WHERE ip=?";'
    expect fail "a converted file that regresses to literal SQL is caught" \
        "converted.c"
    rm -f "$tmp/models/src/converted.c"

    # ── positive controls: innocent code must PASS ──
    : > "$tmp/baseline.txt"
    rm -f "$tmp/models/src/offender.c" "$tmp/models/src/other.c"
    plant innocent.c 'bool f(void) { return log("update_tree: invalid args"); }'
    expect pass "a lowercase identifier that merely starts with a keyword" ""

    plant innocent.c 'static const char *k = " FROM peers WHERE ip=?";'
    expect pass "a continuation fragment with no opening keyword" ""

    plant innocent.c 'void f(struct qb *q) { qb_select(q, QB_T_peers); }'
    expect pass "a file that uses the query builder" ""

    # ── the rail itself is exempt, or the gate would be unfixable ──
    printf 'void e(struct qb *q){ qb_puts(q, "INSERT INTO "); }\n' \
        > "$tmp/models/src/query_builder.c"
    expect pass "the query builder itself is not flagged for its own keywords" ""
    rm -f "$tmp/models/src/query_builder.c"

    # ── hollow scan must be LOUD, never a quiet pass ──
    empty="$tmp/empty"
    mkdir -p "$empty"
    rc=0
    ZCL_MODEL_SQL_SCAN_ROOT="$empty" \
    ZCL_MODEL_SQL_BASELINE="$tmp/baseline.txt" \
    ZCL_LINT_MODE=FAIL bash "$self" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — an empty scan set did not exit 2" >&2
        exit 2
    fi
    echo "  selftest ok: an empty scan set fails LOUD (exit 2), never clean"

    echo "[$GATE] SELFTEST PASS (SELECT/INSERT/UPDATE/DELETE/split literals fail; baselined tolerated; stale row and regression fail; lowercase token, continuation fragment, builder caller and the builder itself pass; hollow scan exits 2)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
[ -d "$SCAN_ROOT" ] || {
    echo "$GATE: FATAL — scan root '$SCAN_ROOT' does not exist" >&2
    exit 2
}

mapfile -t scan_files < <(
    find "$SCAN_ROOT" \( -name '*.c' -o -name '*.h' -o -name '*.def' \) \
        -type f 2>/dev/null | sort
)
gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "no model .c/.h under: $SCAN_ROOT"

# Drop the builder itself before the grep, so its own keyword emission can
# never be reported (and can never be "fixed" by rewriting the rail).
keep=()
for f in "${scan_files[@]}"; do
    is_the_rail "$f" || keep+=("$f")
done
scan_files=("${keep[@]}")
gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "every scanned file was the builder itself — impossible"

# ── Detect ───────────────────────────────────────────────────────────────
mapfile -t FOUND < <(
    gate_grep -lE "$RE_SQL_LITERAL" -- "${scan_files[@]}" | sed '/^$/d' | sort -u
)

declare -A BASELINED=()
gate_load_list_file "$BASELINE" BASELINED baseline_count

declare -A HIT=()
violations=()
for path in "${FOUND[@]}"; do
    if [ -n "${BASELINED[$path]+x}" ]; then
        HIT["$path"]=1
    else
        violations+=("$path")
    fi
done

stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path")
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — model files that still carry a hand-written"
        echo "# SQL statement instead of building it with"
        echo "# app/models/include/models/query_builder.h."
        echo "#"
        echo "# One path per line. THE LIST MAY ONLY SHRINK. Adding a row is"
        echo "# not a fix; a row whose file no longer carries literal SQL must"
        echo "# be DELETED, and this gate fails until it is."
        echo "#"
        echo "# Fix a row by converting the model:"
        echo "#   1. add its table + columns to"
        echo "#      app/models/include/models/query_schema.def"
        echo "#   2. replace each statement with qb_select/qb_insert/"
        echo "#      qb_update/qb_delete + qb_where_*/qb_value_*/qb_set_*"
        echo "#   3. run its existing test group, then delete the line here."
        echo "#"
        echo "# Migration and schema files are ordinary rows: a query builder"
        echo "# cannot express CREATE TABLE, so those are expected to stay."
        echo "#"
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        printf '%s\n' "${FOUND[@]}" | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE (${#FOUND[@]} file(s))"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} model file(s) carry a hand-written SQL"
    echo "        statement and are not in the shrink-only baseline:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Build the statement instead — models/query_builder.h:"
    echo "    qb_select(&q, QB_T_<table>);  qb_select_columns(&q, cols, n);"
    echo "    qb_where_int/_text/_blob(&q, QB_C_<table>_<col>, QB_EQ, v);"
    echo "    qb_order_by(&q, col, QB_DESC);  qb_limit(&q, n);"
    echo "    QB_QUERY_LIST(ndb, &q, s, out, max, row_reader(s, &out[count]));"
    echo "  Identifiers come from app/models/include/models/query_schema.def"
    echo "  (add the table there first); values are bound, never pasted."
    echo "  Adding a row to $BASELINE is NOT a fix; the list may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer"
    echo "        carries literal SQL. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    echo ""
    echo "  Leaving a converted file listed would let it silently regress."
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} model files scanned, ${#FOUND[@]} still carrying literal SQL, all $baseline_count baselined)"
