/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed query builder for the models layer — the safe way to write a model
 * read or write, so nobody has to hand-write SQL correctly forever.
 *
 * ── WHY ─────────────────────────────────────────────────────────────────
 * 70 of 87 model files carried literal SQL strings. Audited, none of them
 * concatenated a caller value into statement text — every one bound its
 * parameters. That is a good outcome resting on a bad foundation: it holds
 * only while 70 files' worth of authors each remember, every time, forever.
 * There was no builder, so hand-written SQL was the ONLY option a model
 * author had. This is the missing rail.
 *
 * ── THE INVARIANT ───────────────────────────────────────────────────────
 * A caller-supplied VALUE can only reach the statement as a bound
 * parameter. There is no entry point on this API that takes SQL text, and
 * no entry point that accepts an identifier as a string. Values arrive
 * through qb_value_* / qb_set_* / qb_where_* / qb_limit, each of which
 * emits a `?` into the text and pushes the value onto a bind list; the
 * value bytes never touch the SQL buffer.
 *
 * Identifiers are the exception that breaks every design like this, so they
 * come from a CLOSED set fixed at compile time:
 * models/query_schema.def. Every table/column parameter is an enum
 * generated from that file. An out-of-range value (an int cast in from
 * elsewhere) or a column belonging to a table this statement does not name
 * fails the statement CLOSED — the builder latches an error, refuses to
 * emit anything further, and qb_prepare() returns false.
 *
 * ── SHAPES ──────────────────────────────────────────────────────────────
 * Built for the census of what the 79 non-migration model files actually
 * do (588 statements): upsert-save 17%, filtered list 21%, single-row read
 * 14%, aggregate 15%, delete 10%, update 9%, join/subquery 3%.
 *
 * ── LIFETIME ────────────────────────────────────────────────────────────
 * Text and blob values are bound with SQLITE_TRANSIENT: SQLite copies them
 * at prepare time. A caller therefore does NOT have to keep its buffers
 * alive past qb_prepare(), which removes the dangling-SQLITE_STATIC class
 * of bug the raw AR_BIND_* macros can still produce.
 *
 * ── USE ─────────────────────────────────────────────────────────────────
 *   struct qb q;
 *   qb_select(&q, QB_T_peers);
 *   qb_select_columns(&q, k_peer_cols, PEER_NCOLS);
 *   qb_where_blob(&q, QB_C_peers_ip, QB_EQ, ip, 16);
 *   qb_where_int(&q, QB_C_peers_port, QB_EQ, port);
 *   QB_QUERY_ONE_BOOL(ndb, &q, s, row_to_peer(s, out, 0));
 */

#ifndef ZCL_MODELS_QUERY_BUILDER_H
#define ZCL_MODELS_QUERY_BUILDER_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Closed identifier set (generated from query_schema.def) ─────────── */

enum qb_table {
#define QB_TABLE(t)       QB_T_##t,
#define QB_COLUMN(t, c)
#include "models/query_schema.def"
#undef QB_TABLE
#undef QB_COLUMN
    QB_TABLE_COUNT
};

enum qb_column {
#define QB_TABLE(t)
#define QB_COLUMN(t, c)   QB_C_##t##_##c,
#include "models/query_schema.def"
#undef QB_TABLE
#undef QB_COLUMN
    QB_COLUMN_COUNT
};

/* ── Small closed vocabularies ──────────────────────────────────────── */

enum qb_op   { QB_EQ, QB_NE, QB_LT, QB_LE, QB_GT, QB_GE };
enum qb_dir  { QB_ASC, QB_DESC };
enum qb_agg  { QB_COUNT_STAR, QB_COUNT, QB_COUNT_DISTINCT, QB_SUM, QB_MIN, QB_MAX };
enum qb_conj { QB_AND, QB_OR };

/* INSERT conflict policy — the three the census actually uses. */
enum qb_insert_mode {
    QB_INSERT_PLAIN,      /* INSERT INTO             */
    QB_INSERT_OR_REPLACE, /* INSERT OR REPLACE INTO  */
    QB_INSERT_OR_IGNORE   /* INSERT OR IGNORE INTO   */
};

/* ── Capacities. Exceeding any of them fails the statement closed. ──── */

#define QB_SQL_MAX     3072
#define QB_VALUES_MAX   192   /* the "(?,?,?...)" tail of an INSERT      */
#define QB_MAX_BINDS     48
#define QB_ERROR_MAX    160

enum qb_bind_kind { QB_BIND_INT, QB_BIND_DOUBLE, QB_BIND_TEXT, QB_BIND_BLOB,
                    QB_BIND_NULL };

struct qb_bind {
    enum qb_bind_kind kind;
    int64_t     i;
    double      d;
    const void *p;
    size_t      n;
};

enum qb_verb { QB_VERB_NONE, QB_VERB_SELECT, QB_VERB_INSERT,
               QB_VERB_UPDATE, QB_VERB_DELETE };

/* Which section of the statement is currently open. The order is the SQL
 * order; a call that belongs to an earlier stage than the current one is
 * refused, because emitting it would produce syntactically wrong SQL. */
enum qb_stage { QB_STAGE_NONE, QB_STAGE_PROJECTION, QB_STAGE_VALUES,
                QB_STAGE_SET, QB_STAGE_CONFLICT, QB_STAGE_WHERE,
                QB_STAGE_ORDER, QB_STAGE_TAIL };

struct qb {
    char   sql[QB_SQL_MAX];
    size_t len;
    char   values[QB_VALUES_MAX];  /* INSERT placeholder list, closed lazily */
    size_t values_len;

    struct qb_bind binds[QB_MAX_BINDS];
    int    nbinds;

    enum qb_verb  verb;
    enum qb_stage stage;
    enum qb_table table;
    enum qb_table join_table;
    enum qb_column join_left;
    enum qb_column join_right;
    bool   has_join;
    bool   conflict_opened;
    bool   conflict_updates;

    int    n_projection;
    int    n_values;
    int    n_sets;
    int    n_where;
    int    n_order;
    int    n_conflict_sets;

    bool   group_open;
    enum qb_conj group_conj;
    int    group_terms;

    bool   has_limit;
    bool   has_offset;

    bool   failed;
    char   error[QB_ERROR_MAX];
};

/* ── Statement openers. Each resets the builder. ─────────────────────── */

void qb_select(struct qb *q, enum qb_table t);
void qb_insert(struct qb *q, enum qb_table t, enum qb_insert_mode mode);
void qb_update(struct qb *q, enum qb_table t);
void qb_delete(struct qb *q, enum qb_table t);

/* ── SELECT projection (before any WHERE) ────────────────────────────── */

void qb_select_column(struct qb *q, enum qb_column c);
void qb_select_columns(struct qb *q, const enum qb_column *cols, size_t n);
/* SELECT 1 FROM t — the existence probe. */
void qb_select_one(struct qb *q);
/* COUNT(*) / COUNT(c) / COUNT(DISTINCT c) / SUM|MIN|MAX(c).
 * When `coalesce_zero` is true the aggregate is wrapped COALESCE(...,0),
 * which is what nearly every SUM/MAX site in the tree wants. */
void qb_select_agg(struct qb *q, enum qb_agg a, enum qb_column c,
                   bool coalesce_zero);
/* COUNT(*) — the aggregate with no column operand. */
void qb_select_count_star(struct qb *q);

/* INNER JOIN t2 ON <left> = <right>. Both columns must belong to the two
 * tables named by this statement. After a join every identifier is
 * table-qualified. */
void qb_join(struct qb *q, enum qb_table t2,
             enum qb_column left, enum qb_column right);

/* ── INSERT values ───────────────────────────────────────────────────── */

void qb_value_int(struct qb *q, enum qb_column c, int64_t v);
void qb_value_double(struct qb *q, enum qb_column c, double v);
void qb_value_text(struct qb *q, enum qb_column c, const char *v);
void qb_value_blob(struct qb *q, enum qb_column c, const void *p, size_t n);
void qb_value_null(struct qb *q, enum qb_column c);

/* ON CONFLICT (cols) DO NOTHING / DO UPDATE SET ... */
void qb_on_conflict_do_nothing(struct qb *q, const enum qb_column *target,
                               size_t n);
void qb_on_conflict_do_update(struct qb *q, const enum qb_column *target,
                              size_t n);
/* c = excluded.c — only inside a DO UPDATE. */
void qb_conflict_set_excluded(struct qb *q, enum qb_column c);
/* c = <table>.c + ? — the "bump a counter on re-insert" shape. */
void qb_conflict_set_increment(struct qb *q, enum qb_column c, int64_t delta);

/* ── UPDATE assignments ──────────────────────────────────────────────── */

void qb_set_int(struct qb *q, enum qb_column c, int64_t v);
void qb_set_double(struct qb *q, enum qb_column c, double v);
void qb_set_text(struct qb *q, enum qb_column c, const char *v);
void qb_set_blob(struct qb *q, enum qb_column c, const void *p, size_t n);
void qb_set_null(struct qb *q, enum qb_column c);
/* c = c + ? — the delta is BOUND, not pasted. */
void qb_set_increment(struct qb *q, enum qb_column c, int64_t delta);
/* c = strftime('%s','now') — a fixed SQL function, no caller input. */
void qb_set_unix_now(struct qb *q, enum qb_column c);

/* ── WHERE ───────────────────────────────────────────────────────────── */

void qb_where_int(struct qb *q, enum qb_column c, enum qb_op op, int64_t v);
void qb_where_double(struct qb *q, enum qb_column c, enum qb_op op, double v);
void qb_where_text(struct qb *q, enum qb_column c, enum qb_op op,
                   const char *v);
void qb_where_blob(struct qb *q, enum qb_column c, enum qb_op op,
                   const void *p, size_t n);
void qb_where_null(struct qb *q, enum qb_column c, bool is_null);
void qb_where_between_int(struct qb *q, enum qb_column c,
                          int64_t lo, int64_t hi);
/* IN (?,?,...) — every element bound. n == 0 is refused: `IN ()` is not
 * valid SQL and silently matching nothing would be a worse answer. */
void qb_where_in_int(struct qb *q, enum qb_column c,
                     const int64_t *vals, size_t n);
void qb_where_in_text(struct qb *q, enum qb_column c,
                      const char *const *vals, size_t n);
/* <c> [NOT] IN (<sub>) where <sub> is another builder-built SELECT. Its
 * text is spliced and its binds appended in order — so a subquery is
 * subject to exactly the same no-concatenation rule as its parent. */
void qb_where_in_select(struct qb *q, enum qb_column c, bool negated,
                        struct qb *sub);

/* One level of OR/AND grouping: qb_group_begin(q, QB_OR); ...; qb_group_end(q)
 * emits "(a OR b OR c)" as one AND-term of the enclosing WHERE. */
void qb_group_begin(struct qb *q, enum qb_conj conj);
void qb_group_end(struct qb *q);

/* ── Tail ────────────────────────────────────────────────────────────── */

void qb_order_by(struct qb *q, enum qb_column c, enum qb_dir d);
void qb_limit(struct qb *q, int64_t n);
void qb_offset(struct qb *q, int64_t n);
void qb_returning(struct qb *q, enum qb_column c);
void qb_returning_one(struct qb *q);

/* ── Terminals ───────────────────────────────────────────────────────── */

/* Finished SQL text, or "" when the statement is failed. Never contains a
 * caller-supplied value; the tests assert exactly that. */
const char *qb_sql(struct qb *q);
bool        qb_ok(const struct qb *q);
const char *qb_error(const struct qb *q);
int         qb_bind_count(const struct qb *q);

/* Prepare against a raw handle and bind every collected value. On failure
 * *out is NULL and the reason is logged. */
bool qb_prepare_db(sqlite3 *db, struct qb *q, sqlite3_stmt **out);

/* Prepare against any struct exposing a `sqlite3 *db` member — the same
 * handle-genericity contract the AR_* macros document. */
#define QB_PREPARE(ndb, q, stmt) qb_prepare_db((ndb)->db, (q), &(stmt))

/* ── ActiveRecord integration ────────────────────────────────────────── *
 * These mirror the AR_QUERY_* / AR_EXEC_* family in activerecord.h one for
 * one, with (sql, bind_code) replaced by a built `struct qb *`. The
 * validate → before_save → SQL → after_save lifecycle is unchanged.       */

/* Returns false when no row matched; otherwise runs row_code, returns true. */
#define QB_QUERY_ONE_BOOL(ndb, q, stmt, row_code) do { \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    if (sqlite3_step(stmt) != SQLITE_ROW) { \
        sqlite3_finalize(stmt); \
        return false; \
    } \
    row_code; \
    sqlite3_finalize(stmt); \
    return true; \
} while (0)

/* True when the statement yields at least one row. */
#define QB_QUERY_EXISTS(ndb, q, stmt) do { \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    bool _qb_found = sqlite3_step(stmt) == SQLITE_ROW; \
    sqlite3_finalize(stmt); \
    return _qb_found; \
} while (0)

/* Fills out[0..max) via row_code, returns the row count. */
#define QB_QUERY_LIST(ndb, q, stmt, out, max, row_code) do { \
    sqlite3_stmt *stmt = NULL; \
    int count = 0; \
    if (!QB_PREPARE((ndb), (q), stmt)) return 0; \
    while (sqlite3_step(stmt) == SQLITE_ROW && (size_t)count < (max)) { \
        memset(&(out)[count], 0, sizeof((out)[count])); \
        row_code; \
        count++; \
    } \
    sqlite3_finalize(stmt); \
    return count; \
} while (0)

/* First column of the first row as int / int64, 0 when there is no row. */
#define QB_QUERY_COUNT(ndb, q, stmt) do { \
    sqlite3_stmt *stmt = NULL; \
    int _qb_c = 0; \
    if (!QB_PREPARE((ndb), (q), stmt)) return 0; \
    if (sqlite3_step(stmt) == SQLITE_ROW) \
        _qb_c = (int)sqlite3_column_int64(stmt, 0); \
    sqlite3_finalize(stmt); \
    return _qb_c; \
} while (0)

#define QB_QUERY_INT64(ndb, q, stmt) do { \
    sqlite3_stmt *stmt = NULL; \
    int64_t _qb_v = 0; \
    if (!QB_PREPARE((ndb), (q), stmt)) return 0; \
    if (sqlite3_step(stmt) == SQLITE_ROW) \
        _qb_v = sqlite3_column_int64(stmt, 0); \
    sqlite3_finalize(stmt); \
    return _qb_v; \
} while (0)

/* UPDATE/DELETE/INSERT where SQLITE_DONE is the whole answer. */
#define QB_EXEC_BOOL(ndb, q, stmt) do { \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    bool _qb_ok = sqlite3_step(stmt) == SQLITE_DONE; \
    sqlite3_finalize(stmt); \
    return _qb_ok; \
} while (0)

/* As QB_EXEC_BOOL, but also requires the statement to have changed a row. */
#define QB_EXEC_CHANGED_BOOL(ndb, q, stmt) do { \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    bool _qb_ok = sqlite3_step(stmt) == SQLITE_DONE; \
    sqlite3_finalize(stmt); \
    return _qb_ok && sqlite3_changes((ndb)->db) > 0; \
} while (0)

/* Save through the full AR lifecycle with a built INSERT. */
#define QB_ADHOC_SAVE(ndb, q, stmt, cbs, model_name, record, validate_fn) do { \
    AR_BEGIN_SAVE((cbs), (model_name), (record), (validate_fn)); \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    bool _qb_ok = sqlite3_step(stmt) == SQLITE_DONE; \
    sqlite3_finalize(stmt); \
    AR_FINISH_SAVE((cbs), (record), _qb_ok); \
} while (0)

/* Destroy through the full AR lifecycle with a built DELETE. */
#define QB_ADHOC_DESTROY(ndb, q, stmt, cbs, record) do { \
    AR_BEGIN_DESTROY((cbs), (record)); \
    sqlite3_stmt *stmt = NULL; \
    if (!QB_PREPARE((ndb), (q), stmt)) return false; \
    bool _qb_ok = sqlite3_step(stmt) == SQLITE_DONE; \
    sqlite3_finalize(stmt); \
    AR_FINISH_DESTROY((cbs), (record), _qb_ok); \
} while (0)

#endif /* ZCL_MODELS_QUERY_BUILDER_H */
