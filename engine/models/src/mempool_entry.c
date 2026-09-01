/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: MempoolEntry
 *
 * validates :txid, presence: true
 * validates :size, positive: true, max: 2_000_000
 * validates :fee, numericality: { >= 0 }
 * validates :time_added, positive: true
 * validates :height_added, numericality: { >= 0 } */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/mempool_entry.h"
#include "storage/mempool_projection.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "util/safe_alloc.h"

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(mempool)

/* before_save: validate txid present and fee non-negative */
static bool mempool_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_mempool_entry *e = record;
    static const uint8_t zero[32] = {0};
    if (memcmp(e->txid, zero, 32) == 0) {
        LOG_FAIL("mempool", "before_save REJECTED: null txid");
    }
    if (e->fee < 0) {
        LOG_FAIL("mempool", "before_save REJECTED: negative fee %lld",
                (long long)e->fee);
    }
    return true;
}

static void mempool_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_mempool_callbacks();
    ar_register_before_save(cbs, mempool_before_save);
    done = true;
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_mempool_validate(const struct db_mempool_entry *e,
                         struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, e, txid);
    validates_positive(errors, e, size);
    validates_max(errors, e, size, 2000000);
    validates_custom(errors,
        !(e->raw_tx && e->raw_tx_len == 0),
        "raw_tx_len", "must be positive when raw_tx present");
    validates_custom(errors,
        e->raw_tx_len <= (size_t)INT32_MAX,
        "raw_tx_len", "exceeds max size");
    validates_non_negative(errors, e, fee);
    validates_positive(errors, e, time_added);
    validates_non_negative(errors, e, height_added);
    return !ar_errors_any(errors);
}

/* ── Save ─────────────────────────────────────────────────────── */

bool db_mempool_save(struct node_db *ndb, const struct db_mempool_entry *e)
{
    if (!ndb->open) return false;
    if (e->time_added == 0)
        ((struct db_mempool_entry *)e)->time_added = (int64_t)platform_time_wall_time_t();

    mempool_init_hooks();
    struct ar_callbacks *cbs = db_mempool_callbacks();
    AR_BEGIN_SAVE(cbs, "mempool_entry", e, db_mempool_validate);

    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO mempool"
        "(txid,raw_tx,fee,size,time_added,height_added,spends_coinbase)"
        " VALUES(?,?,?,?,?,?,?)",
        -1, &s, NULL);
    if (!s) LOG_FAIL("mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, e->txid, 32);
    AR_BIND_BLOB(s, 2, e->raw_tx, (int)e->raw_tx_len);
    AR_BIND_INT(s, 3, e->fee);
    AR_BIND_INT(s, 4, e->size);
    AR_BIND_INT(s, 5, e->time_added);
    AR_BIND_INT(s, 6, e->height_added);
    AR_BIND_INT(s, 7, e->spends_coinbase ? 1 : 0);
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    if (ok && mempool_projection_event_log() &&
        !mempool_projection_emit_admit(e->txid, e->fee, (uint32_t)e->size,
                                       (uint32_t)e->size, e->time_added,
                                       e->raw_tx, e->raw_tx_len)) {
        LOG_WARN("model", "mempool projection emit failed for save");
    }
    AR_FINISH_SAVE(cbs, e, ok);
}

/* ── Delete ───────────────────────────────────────────────────── */

bool db_mempool_delete(struct node_db *ndb, const uint8_t txid[32])
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_mempool_callbacks();
    struct db_mempool_entry e;
    memset(&e, 0, sizeof(e));
    memcpy(e.txid, txid, 32);

    AR_BEGIN_DESTROY(cbs, &e);
    db_mempool_remove_spends(ndb, txid);
    sqlite3_stmt *s = NULL;
    bool ok = false;
    sqlite3_prepare_v2(ndb->db, "DELETE FROM mempool WHERE txid=?",
                       -1, &s, NULL);
    if (!s) LOG_FAIL("mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    if (ok && mempool_projection_event_log() &&
        !mempool_projection_emit_remove(txid, 4)) {
        LOG_WARN("model", "mempool projection emit failed for delete");
    }
    AR_FINISH_DESTROY(cbs, &e, ok);
}

/* ── Count / Aggregate ────────────────────────────────────────── */

int db_mempool_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM mempool");
}

int64_t db_mempool_total_fee(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_INT64_SQL(ndb, "SELECT COALESCE(SUM(fee),0) FROM mempool");
}

struct clear_txid_buf {
    uint8_t *txids;
    int cap;
    int count;
};

static void emit_clear_remove(const struct db_mempool_entry *e, void *ctx)
{
    struct clear_txid_buf *buf = ctx;
    if (!e || !buf || buf->count >= buf->cap) return;
    memcpy(buf->txids + (size_t)buf->count * 32u, e->txid, 32);
    buf->count++;
}

static void emit_clear_removes(uint8_t *txids, int count)
{
    if (!mempool_projection_event_log()) return;
    for (int i = 0; i < count; i++) {
        const uint8_t *txid = txids + (size_t)i * 32u;
        if (!mempool_projection_emit_remove(txid, 3)) {
            LOG_WARN("model", "mempool projection emit failed for clear");
        }
    }
}

bool db_mempool_clear(struct node_db *ndb)
{
    if (!ndb->open) return false;
    bool projection_wired = mempool_projection_event_log() != NULL;
    int count = projection_wired ? db_mempool_count(ndb) : 0;
    uint8_t *txids = NULL;
    struct clear_txid_buf buf = {0};
    if (count > 0) {
        txids = zcl_malloc((size_t)count * 32u, "mempool clear txids");
        if (!txids) return false;
        buf.txids = txids;
        buf.cap = count;
        int seen = db_mempool_each(ndb, emit_clear_remove, &buf);
        if (seen != count || buf.count != count) {
            free(txids);
            return false;
        }
    }
    bool ok = node_db_exec(ndb, "DELETE FROM mempool_spends") &&
              node_db_exec(ndb, "DELETE FROM mempool");
    if (ok && txids)
        emit_clear_removes(txids, buf.count);
    free(txids);
    return ok;
}

/* ── Spend Tracking ───────────────────────────────────────────── */

bool db_mempool_is_spent(struct node_db *ndb,
                         const uint8_t txid[32], uint32_t vout)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT 1 FROM mempool_spends WHERE spent_txid=? AND spent_vout=?",
        -1, &s, NULL);
    if (!s) LOG_FAIL("mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vout);
    bool found = AR_STEP_ROW(s);
    AR_FINALIZE(s);
    return found;
}

bool db_mempool_add_spend(struct node_db *ndb,
                          const uint8_t spending_txid[32],
                          const uint8_t spent_txid[32], uint32_t spent_vout)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO mempool_spends(txid,spent_txid,spent_vout)"
        " VALUES(?,?,?)",
        -1, &s, NULL);
    if (!s) LOG_FAIL("mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, spending_txid, 32);
    AR_BIND_BLOB(s, 2, spent_txid, 32);
    AR_BIND_INT(s, 3, (int)spent_vout);
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    return ok;
}

bool db_mempool_remove_spends(struct node_db *ndb, const uint8_t txid[32])
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "DELETE FROM mempool_spends WHERE txid=?", -1, &s, NULL);
    if (!s) LOG_FAIL("mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    return ok;
}

/* ── Each (iteration) ─────────────────────────────────────────── */

int db_mempool_each(struct node_db *ndb, mempool_entry_cb cb, void *ctx)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,raw_tx,fee,size,time_added,height_added,spends_coinbase"
        " FROM mempool ORDER BY fee DESC",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "mempool", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    int count = 0;
    while (AR_STEP_ROW(s)) {
        struct db_mempool_entry e;
        memset(&e, 0, sizeof(e));
        AR_READ_BLOB(s, 0, e.txid, 32);
        e.raw_tx_len = (size_t)AR_COL_BYTES(s, 1);
        const void *rt = sqlite3_column_blob(s, 1);
        if (rt && e.raw_tx_len > 0) {
            e.raw_tx = zcl_malloc(e.raw_tx_len, "mempool_entry raw_tx each");
            if (e.raw_tx)
                memcpy(e.raw_tx, rt, e.raw_tx_len);
        }
        e.fee = AR_COL_INT(s, 2);
        e.size = (int)AR_COL_INT(s, 3);
        e.time_added = AR_COL_INT(s, 4);
        e.height_added = (int)AR_COL_INT(s, 5);
        e.spends_coinbase = AR_COL_INT(s, 6) != 0;
        cb(&e, ctx);
        free(e.raw_tx);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}
