/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Bounded per-height digest history of the zslp_ledger and op_return_index
 * catalogs. See models/catalog_digest_history.h for why it exists and the
 * invariants. node.db ONLY; never consulted by consensus. */

#include "models/catalog_digest_history.h"

#include "models/activerecord.h"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define CATALOG_FOLD_SAVEPOINT "catalog_fold_unit"

DEFINE_MODEL_CALLBACKS(catalog_digest_history)

struct catalog_history_row {
    int32_t kind;
    int32_t height;
    uint8_t digest[32];
    bool tainted;
};

static bool catalog_history_validate(const struct catalog_history_row *r,
                                     struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_non_negative(errors, r, height);
    validates_custom(errors,
                     r->kind == CATALOG_HISTORY_ZSLP_LEDGER ||
                         r->kind == CATALOG_HISTORY_OP_RETURN_INDEX,
                     "kind", "is not a known catalog");
    return !ar_errors_any(errors);
}

/* ── The fold unit ─────────────────────────────────────────────────── */

bool catalog_fold_unit_begin(struct node_db *ndb)
{
    if (!ndb || !ndb->open || !ndb->db)
        LOG_FAIL("catalog_history", "fold unit: db not open");
    /* The node.db connection is shared by every thread. Holding its
     * (recursive) mutex from here to end() keeps another thread's statement
     * from landing between ours, so a rollback to the savepoint can only
     * undo this unit's own writes. The mutex is NULL on a single-threaded
     * SQLite build; enter/leave of NULL are no-ops. */
    sqlite3_mutex_enter(sqlite3_db_mutex(ndb->db));
    if (!node_db_exec(ndb, "SAVEPOINT " CATALOG_FOLD_SAVEPOINT)) {
        sqlite3_mutex_leave(sqlite3_db_mutex(ndb->db));
        LOG_FAIL("catalog_history", "fold unit: SAVEPOINT failed");
    }
    return true;
}

bool catalog_fold_unit_end(struct node_db *ndb, bool ok)
{
    if (!ndb || !ndb->open || !ndb->db)
        LOG_FAIL("catalog_history", "fold unit end: db not open");
    bool done;
    if (ok) {
        done = node_db_exec(ndb, "RELEASE " CATALOG_FOLD_SAVEPOINT);
        if (!done) {
            LOG_ERROR("catalog_history", "fold unit: RELEASE failed; "
                      "rolling the step back");
            (void)node_db_exec(ndb, "ROLLBACK TO " CATALOG_FOLD_SAVEPOINT);
            (void)node_db_exec(ndb, "RELEASE " CATALOG_FOLD_SAVEPOINT);
        }
    } else {
        done = node_db_exec(ndb, "ROLLBACK TO " CATALOG_FOLD_SAVEPOINT);
        if (!node_db_exec(ndb, "RELEASE " CATALOG_FOLD_SAVEPOINT))
            done = false;
        if (!done)
            LOG_ERROR("catalog_history", "fold unit: rollback failed");
    }
    sqlite3_mutex_leave(sqlite3_db_mutex(ndb->db));
    return ok && done;
}

/* ── Rows ──────────────────────────────────────────────────────────── */

static bool history_put(struct node_db *ndb, enum catalog_history_kind kind,
                        int32_t height, const uint8_t digest[32],
                        bool tainted, enum qb_insert_mode mode)
{
    struct catalog_history_row row;
    memset(&row, 0, sizeof(row));
    row.kind = (int32_t)kind;
    row.height = height;
    memcpy(row.digest, digest, 32);
    row.tainted = tainted;

    struct ar_callbacks *cbs = db_catalog_digest_history_callbacks();
    struct qb q;
    qb_insert(&q, QB_T_catalog_digest_history, mode);
    qb_value_int(&q, QB_C_catalog_digest_history_catalog, row.kind);
    qb_value_int(&q, QB_C_catalog_digest_history_height, row.height);
    qb_value_blob(&q, QB_C_catalog_digest_history_digest, row.digest, 32);
    qb_value_int(&q, QB_C_catalog_digest_history_tainted, row.tainted ? 1 : 0);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "catalog_digest_history", &row,
                  catalog_history_validate);
}

static bool history_delete(struct node_db *ndb, enum catalog_history_kind kind,
                           bool bounded, enum qb_op op, int32_t height)
{
    struct qb q;
    qb_delete(&q, QB_T_catalog_digest_history);
    qb_where_int(&q, QB_C_catalog_digest_history_catalog, QB_EQ, (int64_t)kind);
    if (bounded)
        qb_where_int(&q, QB_C_catalog_digest_history_height, op, height);
    QB_EXEC_BOOL(ndb, &q, s);
}

bool catalog_history_record_step(struct node_db *ndb,
                                 enum catalog_history_kind kind,
                                 int32_t prev_height,
                                 const uint8_t prev_digest[32],
                                 int32_t height, const uint8_t digest[32],
                                 bool tainted)
{
    if (!ndb || !ndb->open || !digest || height < 0)
        LOG_FAIL("catalog_history", "record_step: invalid arguments");
    if (prev_height >= 0 && prev_digest) {
        /* The entry the step starts from must be the cursor's own digest. It
         * differs only when something that does not write this history moved
         * the catalog in between (a binary without it that truncated and
         * refolded across a reorg): the entries then describe a chain the
         * catalog no longer folds, and a later rewind would restore a loser
         * digest over winner rows. Start the history again. */
        uint8_t held[32];
        if (catalog_history_lookup(ndb, kind, prev_height, held, NULL) &&
            memcmp(held, prev_digest, 32) != 0) {
            LOG_WARN("catalog_history", "record_step: catalog %d history at "
                     "h=%d disagrees with the cursor it folds from; clearing "
                     "it (the catalog was refolded without it)", (int)kind,
                     prev_height);
            if (!catalog_history_clear(ndb, kind))
                LOG_FAIL("catalog_history", "record_step: clear failed");
        }
        if (!history_put(ndb, kind, prev_height, prev_digest, false,
                         QB_INSERT_OR_IGNORE))
            LOG_FAIL("catalog_history", "record_step: previous entry h=%d "
                     "failed", prev_height);
    }
    if (!history_put(ndb, kind, height, digest, tainted, QB_INSERT_OR_REPLACE))
        LOG_FAIL("catalog_history", "record_step: entry h=%d failed", height);
    if (height > CATALOG_HISTORY_DEPTH &&
        !history_delete(ndb, kind, true, QB_LT, height - CATALOG_HISTORY_DEPTH))
        LOG_FAIL("catalog_history", "record_step: prune below h=%d failed",
                 height - CATALOG_HISTORY_DEPTH);
    return true;
}

bool catalog_history_lookup(struct node_db *ndb,
                            enum catalog_history_kind kind, int32_t height,
                            uint8_t digest_out[32], bool *tainted_out)
{
    if (!ndb || !ndb->open)
        return false;
    static const enum qb_column k_cols[] = {
        QB_C_catalog_digest_history_digest,
        QB_C_catalog_digest_history_tainted,
    };
    struct qb q;
    qb_select(&q, QB_T_catalog_digest_history);
    qb_select_columns(&q, k_cols, sizeof(k_cols) / sizeof(k_cols[0]));
    qb_where_int(&q, QB_C_catalog_digest_history_catalog, QB_EQ, (int64_t)kind);
    qb_where_int(&q, QB_C_catalog_digest_history_height, QB_EQ, height);
    QB_QUERY_ONE_BOOL(ndb, &q, s, {
        if (sqlite3_column_bytes(s, 0) != 32) {
            sqlite3_finalize(s);
            return false;
        }
        if (digest_out)
            memcpy(digest_out, sqlite3_column_blob(s, 0), 32);
        if (tainted_out)
            *tainted_out = sqlite3_column_int(s, 1) != 0;
    });
}

int64_t catalog_history_count(struct node_db *ndb,
                              enum catalog_history_kind kind)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_catalog_digest_history);
    qb_select_count_star(&q);
    qb_where_int(&q, QB_C_catalog_digest_history_catalog, QB_EQ, (int64_t)kind);
    QB_QUERY_INT64(ndb, &q, s);
}

bool catalog_history_drop_above(struct node_db *ndb,
                                enum catalog_history_kind kind, int32_t height)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("catalog_history", "drop_above: db not open");
    if (!history_delete(ndb, kind, true, QB_GT, height))
        LOG_FAIL("catalog_history", "drop_above: DELETE above h=%d failed",
                 height);
    return true;
}

bool catalog_history_clear(struct node_db *ndb, enum catalog_history_kind kind)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("catalog_history", "clear: db not open");
    if (!history_delete(ndb, kind, false, QB_EQ, 0))
        LOG_FAIL("catalog_history", "clear: DELETE failed");
    return true;
}

bool catalog_history_tainted_between(struct node_db *ndb,
                                     enum catalog_history_kind kind,
                                     int32_t fork_height,
                                     int32_t cursor_height)
{
    if (!ndb || !ndb->open)
        return true;
    struct qb q;
    qb_select(&q, QB_T_catalog_digest_history);
    qb_select_count_star(&q);
    qb_where_int(&q, QB_C_catalog_digest_history_catalog, QB_EQ, (int64_t)kind);
    qb_where_int(&q, QB_C_catalog_digest_history_height, QB_GT, fork_height);
    qb_where_int(&q, QB_C_catalog_digest_history_height, QB_LE, cursor_height);
    qb_where_int(&q, QB_C_catalog_digest_history_tainted, QB_EQ, 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        return true;
    enum zcl_step rc = ar_step_checked(s, "catalog history taint probe", NULL);
    bool tainted = rc != ZCL_STEP_ROW || sqlite3_column_int64(s, 0) > 0;
    sqlite3_finalize(s);
    return tainted;
}


#define WHY(...) \
    do { if (why && why_size) snprintf(why, why_size, __VA_ARGS__); } while (0)

bool catalog_history_can_rewind(struct node_db *ndb,
                                enum catalog_history_kind kind,
                                int32_t fork_height, int32_t cursor_height,
                                const uint8_t cursor_digest[32],
                                uint8_t fork_digest[32], char *why,
                                size_t why_size)
{
    uint8_t at_cursor[32];
    if (fork_height < 0) {
        WHY("the fork is below genesis: the whole catalog (cursor %d) is "
            "above it", cursor_height);
        return false;
    }
    if (fork_height >= cursor_height) {
        WHY("fork %d is not below cursor %d", fork_height, cursor_height);
        return false;
    }
    if (cursor_height - fork_height > CATALOG_HISTORY_DEPTH) {
        WHY("fork is %d heights below the cursor, past the %d-height "
            "history window", cursor_height - fork_height,
            CATALOG_HISTORY_DEPTH);
        return false;
    }
    if (!catalog_history_lookup(ndb, kind, cursor_height, at_cursor, NULL)) {
        WHY("no digest history at the cursor %d (catalog predates the "
            "history, or it was cleared)", cursor_height);
        return false;
    }
    if (!cursor_digest || memcmp(at_cursor, cursor_digest, 32) != 0) {
        WHY("digest history at cursor %d disagrees with the cursor digest",
            cursor_height);
        return false;
    }
    if (!catalog_history_lookup(ndb, kind, fork_height, fork_digest, NULL)) {
        WHY("no digest history at fork height %d (cursor %d)", fork_height,
            cursor_height);
        return false;
    }
    if (catalog_history_tainted_between(ndb, kind, fork_height,
                                        cursor_height)) {
        WHY("a fold between %d and %d rewrote state at an earlier height",
            fork_height, cursor_height);
        return false;
    }
    return true;
}
