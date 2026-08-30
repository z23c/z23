/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed query builder for the models layer. The contract, the reason it
 * exists, and the shape census that sized it are in
 * app/models/include/models/query_builder.h.
 *
 * The whole safety argument lives in two functions here:
 *
 *   qb_ident()  — the ONLY place an identifier reaches the SQL buffer, and
 *                 it copies from k_col[]/k_table[], never from a caller.
 *   qb_bind()   — the ONLY place a caller value is stored, and it goes into
 *                 the bind list while the SQL buffer receives a bare '?'.
 *
 * Nothing else writes caller-derived bytes into q->sql. Everything that can
 * go wrong — an out-of-range enum, a column from another table, an
 * over-long statement, too many binds, a call in the wrong statement
 * section — latches q->failed, and qb_prepare_db() refuses. There is no
 * "best effort" path: a builder that made a mistake produces no statement.
 *
 * ar-validate-skip:query-builder-infrastructure — this file is the SQL
 * construction rail itself, not a persisted model, so it has no record to
 * validate and registers no AR callbacks.
 */

#include "models/query_builder.h"
#include "base/log_macros.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ── Closed identifier tables (generated from query_schema.def) ──────── */

static const char *const k_table[QB_TABLE_COUNT] = {
#define QB_TABLE(t)      #t,
#define QB_COLUMN(t, c)
#include "models/query_schema.def"
#undef QB_TABLE
#undef QB_COLUMN
};

struct qb_col_meta {
    const char   *name;
    enum qb_table table;
};

static const struct qb_col_meta k_col[QB_COLUMN_COUNT] = {
#define QB_TABLE(t)
#define QB_COLUMN(t, c)  { #c, QB_T_##t },
#include "models/query_schema.def"
#undef QB_TABLE
#undef QB_COLUMN
};

/* ── Failure latch ───────────────────────────────────────────────────── */

static void qb_fail(struct qb *q, const char *fmt, ...)
{
    if (!q || q->failed)
        return;
    q->failed = true;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(q->error, sizeof(q->error), fmt, ap);
    va_end(ap);
    q->sql[0] = '\0';
    q->len = 0;
}

/* ── SQL text emission. Only ever called with builder-owned bytes. ──── */

static void qb_puts(struct qb *q, const char *s)
{
    if (q->failed)
        return;
    size_t n = strlen(s);
    if (q->len + n + 1 > sizeof(q->sql)) {
        qb_fail(q, "statement exceeds %zu bytes", sizeof(q->sql));
        return;
    }
    memcpy(q->sql + q->len, s, n);
    q->len += n;
    q->sql[q->len] = '\0';
}

static void qb_put_values(struct qb *q, const char *s)
{
    if (q->failed)
        return;
    size_t n = strlen(s);
    if (q->values_len + n + 1 > sizeof(q->values)) {
        qb_fail(q, "INSERT placeholder list exceeds %zu bytes",
                sizeof(q->values));
        return;
    }
    memcpy(q->values + q->values_len, s, n);
    q->values_len += n;
    q->values[q->values_len] = '\0';
}

static bool qb_table_valid(struct qb *q, enum qb_table t, const char *what)
{
    if ((int)t < 0 || (int)t >= QB_TABLE_COUNT) {
        qb_fail(q, "%s: table id %d is not in the closed schema set", what,
                (int)t);
        return false;
    }
    return true;
}

/* Emit one column identifier. Refuses an id outside the generated range and
 * an id belonging to a table this statement does not name — the two ways a
 * caller could otherwise steer the text. */
static bool qb_ident(struct qb *q, enum qb_column c)
{
    if (q->failed)
        return false;
    if ((int)c < 0 || (int)c >= QB_COLUMN_COUNT) {
        qb_fail(q, "column id %d is not in the closed schema set", (int)c);
        return false;
    }
    enum qb_table owner = k_col[c].table;
    if (owner != q->table && !(q->has_join && owner == q->join_table)) {
        qb_fail(q, "column %s.%s does not belong to this statement's table %s",
                k_table[owner], k_col[c].name, k_table[q->table]);
        return false;
    }
    if (q->has_join) {
        qb_puts(q, k_table[owner]);
        qb_puts(q, ".");
    }
    qb_puts(q, k_col[c].name);
    return !q->failed;
}

/* ── Bind collection. The ONLY store of a caller value. ─────────────── */

static void qb_bind(struct qb *q, struct qb_bind b)
{
    if (q->failed)
        return;
    if (q->nbinds >= QB_MAX_BINDS) {
        qb_fail(q, "more than %d bound parameters", QB_MAX_BINDS);
        return;
    }
    q->binds[q->nbinds++] = b;
    qb_puts(q, "?");
}

static void qb_bind_i(struct qb *q, int64_t v)
{
    qb_bind(q, (struct qb_bind){ .kind = QB_BIND_INT, .i = v });
}

static void qb_bind_d(struct qb *q, double v)
{
    qb_bind(q, (struct qb_bind){ .kind = QB_BIND_DOUBLE, .d = v });
}

static void qb_bind_t(struct qb *q, const char *v)
{
    if (!v) {
        qb_bind(q, (struct qb_bind){ .kind = QB_BIND_NULL });
        return;
    }
    qb_bind(q, (struct qb_bind){ .kind = QB_BIND_TEXT, .p = v,
                                 .n = strlen(v) });
}

static void qb_bind_b(struct qb *q, const void *p, size_t n)
{
    if (!p) {
        qb_bind(q, (struct qb_bind){ .kind = QB_BIND_NULL });
        return;
    }
    qb_bind(q, (struct qb_bind){ .kind = QB_BIND_BLOB, .p = p, .n = n });
}

static const char *qb_op_text(struct qb *q, enum qb_op op)
{
    switch (op) {
    case QB_EQ: return "=";
    case QB_NE: return "<>";
    case QB_LT: return "<";
    case QB_LE: return "<=";
    case QB_GT: return ">";
    case QB_GE: return ">=";
    }
    qb_fail(q, "comparison operator %d is not in the closed set", (int)op);
    return "";
}

/* ── Openers ─────────────────────────────────────────────────────────── */

static void qb_reset(struct qb *q, enum qb_verb verb, enum qb_table t)
{
    memset(q, 0, sizeof(*q));
    q->verb = verb;
    q->table = t;
    (void)qb_table_valid(q, t, "statement");
}

void qb_select(struct qb *q, enum qb_table t)
{
    qb_reset(q, QB_VERB_SELECT, t);
    q->stage = QB_STAGE_PROJECTION;
    qb_puts(q, "SELECT ");
}

void qb_insert(struct qb *q, enum qb_table t, enum qb_insert_mode mode)
{
    qb_reset(q, QB_VERB_INSERT, t);
    q->stage = QB_STAGE_VALUES;
    switch (mode) {
    case QB_INSERT_PLAIN:      qb_puts(q, "INSERT INTO ");            break;
    case QB_INSERT_OR_REPLACE: qb_puts(q, "INSERT OR REPLACE INTO "); break;
    case QB_INSERT_OR_IGNORE:  qb_puts(q, "INSERT OR IGNORE INTO ");  break;
    default:
        qb_fail(q, "insert mode %d is not in the closed set", (int)mode);
        return;
    }
    if (!q->failed) {
        qb_puts(q, k_table[t]);
        qb_puts(q, " (");
    }
}

void qb_update(struct qb *q, enum qb_table t)
{
    qb_reset(q, QB_VERB_UPDATE, t);
    q->stage = QB_STAGE_SET;
    if (!q->failed) {
        qb_puts(q, "UPDATE ");
        qb_puts(q, k_table[t]);
        qb_puts(q, " SET ");
    }
}

void qb_delete(struct qb *q, enum qb_table t)
{
    qb_reset(q, QB_VERB_DELETE, t);
    q->stage = QB_STAGE_WHERE;
    if (!q->failed) {
        qb_puts(q, "DELETE FROM ");
        qb_puts(q, k_table[t]);
    }
}

/* ── SELECT projection ───────────────────────────────────────────────── */

static bool qb_in_projection(struct qb *q, const char *what)
{
    if (q->failed)
        return false;
    if (q->verb != QB_VERB_SELECT || q->stage != QB_STAGE_PROJECTION) {
        qb_fail(q, "%s is only valid in a SELECT projection", what);
        return false;
    }
    return true;
}

static void qb_projection_sep(struct qb *q)
{
    if (q->n_projection > 0)
        qb_puts(q, ",");
    q->n_projection++;
}

void qb_select_column(struct qb *q, enum qb_column c)
{
    if (!qb_in_projection(q, "qb_select_column"))
        return;
    qb_projection_sep(q);
    (void)qb_ident(q, c);
}

void qb_select_columns(struct qb *q, const enum qb_column *cols, size_t n)
{
    if (!cols || n == 0) {
        qb_fail(q, "qb_select_columns needs a non-empty column list");
        return;
    }
    for (size_t i = 0; i < n; i++)
        qb_select_column(q, cols[i]);
}

void qb_select_one(struct qb *q)
{
    if (!qb_in_projection(q, "qb_select_one"))
        return;
    qb_projection_sep(q);
    qb_puts(q, "1");
}

void qb_select_agg(struct qb *q, enum qb_agg a, enum qb_column c,
                   bool coalesce_zero)
{
    if (!qb_in_projection(q, "qb_select_agg"))
        return;
    qb_projection_sep(q);
    if (coalesce_zero)
        qb_puts(q, "COALESCE(");
    switch (a) {
    case QB_COUNT_STAR:     qb_puts(q, "COUNT(*");         break;
    case QB_COUNT:          qb_puts(q, "COUNT(");          break;
    case QB_COUNT_DISTINCT: qb_puts(q, "COUNT(DISTINCT "); break;
    case QB_SUM:            qb_puts(q, "SUM(");            break;
    case QB_MIN:            qb_puts(q, "MIN(");            break;
    case QB_MAX:            qb_puts(q, "MAX(");            break;
    default:
        qb_fail(q, "aggregate %d is not in the closed set", (int)a);
        return;
    }
    if (a != QB_COUNT_STAR && !qb_ident(q, c))
        return;
    qb_puts(q, ")");
    if (coalesce_zero)
        qb_puts(q, ",0)");
}

void qb_select_count_star(struct qb *q)
{
    if (!qb_in_projection(q, "qb_select_count_star"))
        return;
    qb_projection_sep(q);
    qb_puts(q, "COUNT(*)");
}

void qb_join(struct qb *q, enum qb_table t2,
             enum qb_column left, enum qb_column right)
{
    if (!qb_in_projection(q, "qb_join"))
        return;
    if (q->n_projection != 0) {
        qb_fail(q, "qb_join must be called before any projection column, so "
                   "every identifier can be table-qualified");
        return;
    }
    if (!qb_table_valid(q, t2, "qb_join"))
        return;
    if (t2 == q->table) {
        qb_fail(q, "qb_join needs a second table, not %s again", k_table[t2]);
        return;
    }
    q->has_join = true;
    q->join_table = t2;
    /* Both endpoints are validated when the ON clause is emitted in
     * qb_close_projection(), after has_join makes qualification legal. */
    q->join_left = left;
    q->join_right = right;
}

static void qb_close_projection(struct qb *q)
{
    if (q->failed)
        return;
    if (q->n_projection == 0) {
        qb_fail(q, "SELECT with an empty projection");
        return;
    }
    qb_puts(q, " FROM ");
    qb_puts(q, k_table[q->table]);
    if (q->has_join) {
        qb_puts(q, " INNER JOIN ");
        qb_puts(q, k_table[q->join_table]);
        qb_puts(q, " ON ");
        if (!qb_ident(q, q->join_left))
            return;
        qb_puts(q, "=");
        if (!qb_ident(q, q->join_right))
            return;
    }
    q->stage = QB_STAGE_WHERE;
}

/* ── INSERT values ───────────────────────────────────────────────────── */

static bool qb_in_values(struct qb *q)
{
    if (q->failed)
        return false;
    if (q->verb != QB_VERB_INSERT || q->stage != QB_STAGE_VALUES) {
        qb_fail(q, "qb_value_* is only valid in an INSERT value list");
        return false;
    }
    return true;
}

/* Emit "col" into the column list and ",?" into the placeholder tail. The
 * placeholder is written to q->values, so qb_bind() (which appends '?' to
 * q->sql) must not be used here — the value list is spliced in later. */
static bool qb_value_slot(struct qb *q, enum qb_column c)
{
    if (!qb_in_values(q))
        return false;  // raw-return-ok:qb_fail already latched the reason
    if (q->n_values > 0) {
        qb_puts(q, ",");
        qb_put_values(q, ",?");
    } else {
        qb_put_values(q, "?");
    }
    q->n_values++;
    return qb_ident(q, c);
}

static void qb_value_push(struct qb *q, struct qb_bind b)
{
    if (q->failed)
        return;
    if (q->nbinds >= QB_MAX_BINDS) {
        qb_fail(q, "more than %d bound parameters", QB_MAX_BINDS);
        return;
    }
    q->binds[q->nbinds++] = b;
}

void qb_value_int(struct qb *q, enum qb_column c, int64_t v)
{
    if (qb_value_slot(q, c))
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_INT, .i = v });
}

void qb_value_double(struct qb *q, enum qb_column c, double v)
{
    if (qb_value_slot(q, c))
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_DOUBLE, .d = v });
}

void qb_value_text(struct qb *q, enum qb_column c, const char *v)
{
    if (!qb_value_slot(q, c))
        return;
    if (!v)
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_NULL });
    else
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_TEXT, .p = v,
                                           .n = strlen(v) });
}

void qb_value_blob(struct qb *q, enum qb_column c, const void *p, size_t n)
{
    if (!qb_value_slot(q, c))
        return;
    if (!p)
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_NULL });
    else
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_BLOB, .p = p,
                                           .n = n });
}

void qb_value_null(struct qb *q, enum qb_column c)
{
    if (qb_value_slot(q, c))
        qb_value_push(q, (struct qb_bind){ .kind = QB_BIND_NULL });
}

static void qb_close_values(struct qb *q)
{
    if (q->failed || q->stage != QB_STAGE_VALUES)
        return;
    if (q->n_values == 0) {
        qb_fail(q, "INSERT with no values");
        return;
    }
    qb_puts(q, ") VALUES (");
    qb_puts(q, q->values);
    qb_puts(q, ")");
    q->stage = QB_STAGE_CONFLICT;
}

static bool qb_conflict_target(struct qb *q, const enum qb_column *target,
                               size_t n)
{
    if (q->verb != QB_VERB_INSERT) {
        qb_fail(q, "ON CONFLICT is only valid on an INSERT");
        return false;
    }
    qb_close_values(q);
    if (q->failed)
        return false;
    if (q->stage != QB_STAGE_CONFLICT || q->conflict_opened) {
        qb_fail(q, "ON CONFLICT clause is already present");
        return false;
    }
    q->conflict_opened = true;
    if (!target || n == 0) {
        qb_fail(q, "ON CONFLICT needs a non-empty conflict target");
        return false;
    }
    qb_puts(q, " ON CONFLICT(");
    for (size_t i = 0; i < n; i++) {
        if (i > 0)
            qb_puts(q, ",");
        if (!qb_ident(q, target[i]))
            return false;  // raw-return-ok:qb_fail already latched the reason
    }
    qb_puts(q, ")");
    return !q->failed;
}

void qb_on_conflict_do_nothing(struct qb *q, const enum qb_column *target,
                               size_t n)
{
    if (!qb_conflict_target(q, target, n))
        return;
    qb_puts(q, " DO NOTHING");
    q->stage = QB_STAGE_TAIL;
}

void qb_on_conflict_do_update(struct qb *q, const enum qb_column *target,
                              size_t n)
{
    if (!qb_conflict_target(q, target, n))
        return;
    qb_puts(q, " DO UPDATE SET ");
    q->conflict_updates = true;
}

static bool qb_conflict_set_slot(struct qb *q, enum qb_column c)
{
    if (q->failed)
        return false;
    if (q->verb != QB_VERB_INSERT || q->stage != QB_STAGE_CONFLICT ||
        !q->conflict_updates) {
        qb_fail(q, "qb_conflict_set_* needs an open DO UPDATE SET");
        return false;
    }
    if (q->n_conflict_sets > 0)
        qb_puts(q, ",");
    q->n_conflict_sets++;
    if (!qb_ident(q, c))
        return false;  // raw-return-ok:qb_fail already latched the reason
    qb_puts(q, "=");
    return !q->failed;
}

void qb_conflict_set_excluded(struct qb *q, enum qb_column c)
{
    if (!qb_conflict_set_slot(q, c))
        return;
    qb_puts(q, "excluded.");
    qb_puts(q, k_col[c].name);
}

void qb_conflict_set_increment(struct qb *q, enum qb_column c, int64_t delta)
{
    if (!qb_conflict_set_slot(q, c))
        return;
    qb_puts(q, k_table[q->table]);
    qb_puts(q, ".");
    qb_puts(q, k_col[c].name);
    qb_puts(q, "+");
    qb_bind_i(q, delta);
}

/* ── UPDATE assignments ──────────────────────────────────────────────── */

static bool qb_set_slot(struct qb *q, enum qb_column c)
{
    if (q->failed)
        return false;
    if (q->verb != QB_VERB_UPDATE || q->stage != QB_STAGE_SET) {
        qb_fail(q, "qb_set_* is only valid in an UPDATE SET list");
        return false;
    }
    if (q->n_sets > 0)
        qb_puts(q, ",");
    q->n_sets++;
    if (!qb_ident(q, c))
        return false;  // raw-return-ok:qb_fail already latched the reason
    qb_puts(q, "=");
    return !q->failed;
}

void qb_set_int(struct qb *q, enum qb_column c, int64_t v)
{
    if (qb_set_slot(q, c))
        qb_bind_i(q, v);
}

void qb_set_double(struct qb *q, enum qb_column c, double v)
{
    if (qb_set_slot(q, c))
        qb_bind_d(q, v);
}

void qb_set_text(struct qb *q, enum qb_column c, const char *v)
{
    if (qb_set_slot(q, c))
        qb_bind_t(q, v);
}

void qb_set_blob(struct qb *q, enum qb_column c, const void *p, size_t n)
{
    if (qb_set_slot(q, c))
        qb_bind_b(q, p, n);
}

void qb_set_null(struct qb *q, enum qb_column c)
{
    if (qb_set_slot(q, c))
        qb_puts(q, "NULL");
}

void qb_set_increment(struct qb *q, enum qb_column c, int64_t delta)
{
    if (!qb_set_slot(q, c))
        return;
    qb_puts(q, k_col[c].name);
    qb_puts(q, "+");
    qb_bind_i(q, delta);
}

void qb_set_unix_now(struct qb *q, enum qb_column c)
{
    if (qb_set_slot(q, c))
        qb_puts(q, "strftime('%s','now')");
}

/* ── WHERE ───────────────────────────────────────────────────────────── */

/* Move the statement into its WHERE section, closing whatever came before,
 * then emit the connector for the next predicate. */
static bool qb_where_lead(struct qb *q)
{
    if (q->failed)
        return false;
    switch (q->verb) {
    case QB_VERB_SELECT:
        if (q->stage == QB_STAGE_PROJECTION)
            qb_close_projection(q);
        break;
    case QB_VERB_UPDATE:
        if (q->stage == QB_STAGE_SET) {
            if (q->n_sets == 0) {
                qb_fail(q, "UPDATE with no SET assignments");
                return false;
            }
            q->stage = QB_STAGE_WHERE;
        }
        break;
    case QB_VERB_DELETE:
        break;
    case QB_VERB_INSERT:
        qb_fail(q, "INSERT has no WHERE clause");
        return false;
    default:
        qb_fail(q, "predicate before any statement verb");
        return false;
    }
    if (q->failed)
        return false;
    if (q->stage != QB_STAGE_WHERE) {
        qb_fail(q, "WHERE predicate after the statement tail was opened");
        return false;
    }

    if (q->group_open) {
        if (q->group_terms == 0) {
            qb_puts(q, q->n_where++ == 0 ? " WHERE (" : " AND (");
        } else {
            qb_puts(q, q->group_conj == QB_OR ? " OR " : " AND ");
        }
        q->group_terms++;
    } else {
        qb_puts(q, q->n_where++ == 0 ? " WHERE " : " AND ");
    }
    return !q->failed;
}

static bool qb_where_col_op(struct qb *q, enum qb_column c, enum qb_op op)
{
    if (!qb_where_lead(q))
        return false;  // raw-return-ok:qb_fail already latched the reason
    if (!qb_ident(q, c))
        return false;  // raw-return-ok:qb_fail already latched the reason
    qb_puts(q, qb_op_text(q, op));
    return !q->failed;
}

void qb_where_int(struct qb *q, enum qb_column c, enum qb_op op, int64_t v)
{
    if (qb_where_col_op(q, c, op))
        qb_bind_i(q, v);
}

void qb_where_double(struct qb *q, enum qb_column c, enum qb_op op, double v)
{
    if (qb_where_col_op(q, c, op))
        qb_bind_d(q, v);
}

void qb_where_text(struct qb *q, enum qb_column c, enum qb_op op,
                   const char *v)
{
    if (qb_where_col_op(q, c, op))
        qb_bind_t(q, v);
}

void qb_where_blob(struct qb *q, enum qb_column c, enum qb_op op,
                   const void *p, size_t n)
{
    if (qb_where_col_op(q, c, op))
        qb_bind_b(q, p, n);
}

void qb_where_null(struct qb *q, enum qb_column c, bool is_null)
{
    if (!qb_where_lead(q) || !qb_ident(q, c))
        return;
    qb_puts(q, is_null ? " IS NULL" : " IS NOT NULL");
}

void qb_where_between_int(struct qb *q, enum qb_column c,
                          int64_t lo, int64_t hi)
{
    if (!qb_where_lead(q) || !qb_ident(q, c))
        return;
    qb_puts(q, " BETWEEN ");
    qb_bind_i(q, lo);
    qb_puts(q, " AND ");
    qb_bind_i(q, hi);
}

void qb_where_in_int(struct qb *q, enum qb_column c,
                     const int64_t *vals, size_t n)
{
    if (!vals || n == 0) {
        qb_fail(q, "IN () is not a query — pass at least one value");
        return;
    }
    if (!qb_where_lead(q) || !qb_ident(q, c))
        return;
    qb_puts(q, " IN (");
    for (size_t i = 0; i < n; i++) {
        if (i > 0)
            qb_puts(q, ",");
        qb_bind_i(q, vals[i]);
    }
    qb_puts(q, ")");
}

void qb_where_in_text(struct qb *q, enum qb_column c,
                      const char *const *vals, size_t n)
{
    if (!vals || n == 0) {
        qb_fail(q, "IN () is not a query — pass at least one value");
        return;
    }
    if (!qb_where_lead(q) || !qb_ident(q, c))
        return;
    qb_puts(q, " IN (");
    for (size_t i = 0; i < n; i++) {
        if (i > 0)
            qb_puts(q, ",");
        qb_bind_t(q, vals[i]);
    }
    qb_puts(q, ")");
}

void qb_where_in_select(struct qb *q, enum qb_column c, bool negated,
                        struct qb *sub)
{
    if (!sub) {
        qb_fail(q, "IN (subselect) needs a built subquery");
        return;
    }
    /* Settle the subquery first: a still-open projection has no FROM yet.
     * A subquery that failed for any reason poisons the parent — there is
     * no partial splice. */
    (void)qb_sql(sub);
    if (sub->failed || sub->verb != QB_VERB_SELECT || sub->len == 0) {
        qb_fail(q, "IN (subselect): subquery is not a completed SELECT (%s)",
                sub->failed ? sub->error : "not settled");
        return;
    }
    if (!qb_where_lead(q) || !qb_ident(q, c))
        return;
    qb_puts(q, negated ? " NOT IN (" : " IN (");
    qb_puts(q, sub->sql);
    qb_puts(q, ")");
    for (int i = 0; i < sub->nbinds; i++) {
        if (q->nbinds >= QB_MAX_BINDS) {
            qb_fail(q, "more than %d bound parameters", QB_MAX_BINDS);
            return;
        }
        q->binds[q->nbinds++] = sub->binds[i];
    }
}

void qb_group_begin(struct qb *q, enum qb_conj conj)
{
    if (q->failed)
        return;
    if (q->group_open) {
        qb_fail(q, "predicate groups do not nest");
        return;
    }
    if (conj != QB_AND && conj != QB_OR) {
        qb_fail(q, "conjunction %d is not in the closed set", (int)conj);
        return;
    }
    q->group_open = true;
    q->group_conj = conj;
    q->group_terms = 0;
}

void qb_group_end(struct qb *q)
{
    if (q->failed)
        return;
    if (!q->group_open) {
        qb_fail(q, "qb_group_end without qb_group_begin");
        return;
    }
    if (q->group_terms == 0) {
        qb_fail(q, "empty predicate group");
        return;
    }
    qb_puts(q, ")");
    q->group_open = false;
    q->group_terms = 0;
}

/* ── Tail ────────────────────────────────────────────────────────────── */

/* Close every still-open section so a tail clause (or the finished text)
 * can be emitted. */
static void qb_settle(struct qb *q)
{
    if (q->failed)
        return;
    if (q->group_open) {
        qb_fail(q, "predicate group left open");
        return;
    }
    switch (q->verb) {
    case QB_VERB_SELECT:
        if (q->stage == QB_STAGE_PROJECTION)
            qb_close_projection(q);
        break;
    case QB_VERB_INSERT:
        if (q->stage == QB_STAGE_VALUES)
            qb_close_values(q);
        if (q->conflict_updates && q->n_conflict_sets == 0)
            qb_fail(q, "ON CONFLICT DO UPDATE with no assignments");
        break;
    case QB_VERB_UPDATE:
        if (q->stage == QB_STAGE_SET) {
            if (q->n_sets == 0)
                qb_fail(q, "UPDATE with no SET assignments");
            else
                q->stage = QB_STAGE_WHERE;
        }
        break;
    case QB_VERB_DELETE:
        break;
    default:
        qb_fail(q, "no statement was started");
        break;
    }
}

void qb_order_by(struct qb *q, enum qb_column c, enum qb_dir d)
{
    qb_settle(q);
    if (q->failed)
        return;
    if (q->verb != QB_VERB_SELECT) {
        qb_fail(q, "ORDER BY is only supported on SELECT");
        return;
    }
    if (q->has_limit || q->has_offset) {
        qb_fail(q, "ORDER BY must precede LIMIT/OFFSET");
        return;
    }
    qb_puts(q, q->n_order++ == 0 ? " ORDER BY " : ",");
    if (!qb_ident(q, c))
        return;
    switch (d) {
    case QB_ASC:  qb_puts(q, " ASC");  break;
    case QB_DESC: qb_puts(q, " DESC"); break;
    default:      qb_fail(q, "sort direction %d is not in the closed set",
                          (int)d); break;
    }
    q->stage = QB_STAGE_ORDER;
}

void qb_limit(struct qb *q, int64_t n)
{
    qb_settle(q);
    if (q->failed)
        return;
    if (q->has_limit) {
        qb_fail(q, "LIMIT set twice");
        return;
    }
    if (n < 0) {
        qb_fail(q, "LIMIT must not be negative");
        return;
    }
    q->has_limit = true;
    qb_puts(q, " LIMIT ");
    qb_bind_i(q, n);
    q->stage = QB_STAGE_TAIL;
}

void qb_offset(struct qb *q, int64_t n)
{
    if (q->failed)
        return;
    if (!q->has_limit) {
        qb_fail(q, "OFFSET without LIMIT");
        return;
    }
    if (q->has_offset) {
        qb_fail(q, "OFFSET set twice");
        return;
    }
    if (n < 0) {
        qb_fail(q, "OFFSET must not be negative");
        return;
    }
    q->has_offset = true;
    qb_puts(q, " OFFSET ");
    qb_bind_i(q, n);
}

static void qb_returning_lead(struct qb *q)
{
    qb_settle(q);
    if (q->failed)
        return;
    if (q->verb == QB_VERB_SELECT) {
        qb_fail(q, "RETURNING is not a SELECT clause");
        return;
    }
    qb_puts(q, " RETURNING ");
    q->stage = QB_STAGE_TAIL;
}

void qb_returning(struct qb *q, enum qb_column c)
{
    qb_returning_lead(q);
    if (!q->failed)
        (void)qb_ident(q, c);
}

void qb_returning_one(struct qb *q)
{
    qb_returning_lead(q);
    if (!q->failed)
        qb_puts(q, "1");
}

/* ── Terminals ───────────────────────────────────────────────────────── */

const char *qb_sql(struct qb *q)
{
    if (!q)
        return "";
    qb_settle(q);
    return q->failed ? "" : q->sql;
}

bool qb_ok(const struct qb *q)
{
    return q && !q->failed;
}

const char *qb_error(const struct qb *q)
{
    if (!q)
        return "null builder";
    return q->failed ? q->error : "";
}

int qb_bind_count(const struct qb *q)
{
    return q ? q->nbinds : 0;
}

bool qb_prepare_db(sqlite3 *db, struct qb *q, sqlite3_stmt **out)
{
    if (out)
        *out = NULL;
    if (!db || !q || !out)
        LOG_FAIL("models", "qb_prepare: null argument");

    const char *sql = qb_sql(q);
    if (q->failed)
        LOG_FAIL("models", "query builder refused the statement: %s",
                 q->error);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        if (s)
            sqlite3_finalize(s);
        LOG_FAIL("models", "prepare failed: %s | sql=%s",
                 sqlite3_errmsg(db), sql);
    }

    /* The emitted text and the collected values must agree exactly. A
     * mismatch means the builder produced placeholders it cannot fill (or
     * values with nowhere to go), so refuse rather than run a statement with
     * an implicit NULL in it. */
    int want = sqlite3_bind_parameter_count(s);
    if (want != q->nbinds) {
        sqlite3_finalize(s);
        LOG_FAIL("models",
                 "bind arity mismatch: sql has %d parameter(s), builder "
                 "collected %d | sql=%s", want, q->nbinds, sql);
    }

    for (int i = 0; i < q->nbinds; i++) {
        const struct qb_bind *b = &q->binds[i];
        int pos = i + 1;
        int rc = SQLITE_OK;
        switch (b->kind) {
        case QB_BIND_INT:
            rc = sqlite3_bind_int64(s, pos, b->i);
            break;
        case QB_BIND_DOUBLE:
            rc = sqlite3_bind_double(s, pos, b->d);
            break;
        case QB_BIND_TEXT:
            rc = sqlite3_bind_text(s, pos, (const char *)b->p, (int)b->n,
                                   SQLITE_TRANSIENT);
            break;
        case QB_BIND_BLOB:
            rc = sqlite3_bind_blob(s, pos, b->p, (int)b->n, SQLITE_TRANSIENT);
            break;
        case QB_BIND_NULL:
            rc = sqlite3_bind_null(s, pos);
            break;
        default:
            rc = SQLITE_MISUSE;
            break;
        }
        if (rc != SQLITE_OK) {
            sqlite3_finalize(s);
            LOG_FAIL("models", "bind %d failed rc=%d: %s | sql=%s", pos, rc,
                     sqlite3_errmsg(db), sql);
        }
    }

    *out = s;
    return true;
}
