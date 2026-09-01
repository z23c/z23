/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_kv — implementation. See storage/coins_kv.h for the contract and the
 * durability rationale (docs/work/tip-durability-collapse.md).
 *
 * Raw sqlite3_step calls carry // raw-sql-ok:progress-kv-kernel-store, the
 * sanctioned hatch for the kernel store (same convention as progress_store.c).
 * The coins set sits BELOW the AR lifecycle — it is reducer state, not an AR
 * model.
 *
 * Statement lifetime: every helper prepares/finalizes per call ON PURPOSE —
 * do NOT cache statements here. These run cross-thread on the ONE shared
 * progress.kv handle (the same-txn atomicity design forbids per-thread
 * connections): the staged-sync job thread (utxo_apply_stage.c apply_coins_kv
 * + script_validate prevout reads), the self-heal/condition-engine thread
 * (stage_repair_coin_backfill.c), the reorg unwind, and chain_state_validator
 * reads via coins_view_kv. FULLMUTEX serializes individual sqlite3_* calls,
 * NOT a reset/bind/step sequence, so a shared cached statement is a
 * cross-thread race class. Per-block batching belongs at the hot-loop
 * call sites (created_outputs_index_put_block's prepare-once idiom). Within a
 * call, txid/script bind with SQLITE_STATIC: every caller's buffers outlive
 * the statement, which never escapes the call.
 */
#include "storage/coins_kv.h"

#include "chain/checkpoints.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* UAF guard (the phashBlock-into-bucket class): the coins_ram overlay is a
 * process-global lock-free map mutated in place by the reducer writer (free +
 * repoint / grow). The READ shims below route to coins_ram_* whenever
 * coins_ram_active(), but those shims are called from OTHER threads (bg-
 * validation worker pthreads, the RPC pool's gettxoutsetinfo, the seal_service
 * background thread). A reader loading s->script or holding a slot pointer
 * races the writer. The guard: route to the overlay ONLY on a thread where the
 * map is not concurrently mutated; every other thread takes the FULLMUTEX SQLite
 * path (no UAF). The WRITE shims (coins_kv_add / _spend / _many) are NOT gated:
 * they run inside the writer bracket (or the progress_store_tx_lock-serialized
 * backfill).
 *
 * Two thread classes read safely:
 *   (1) the reducer fold thread inside the utxo_apply writer bracket — the only
 *       place the overlay mutates (the live/steady-state case);
 *   (2) the offline -mint-anchor drive thread: that fold runs all eight stages
 *       serially on ONE thread, so script_validate's prevout read and utxo_apply
 *       share it. The writer bracket only spans utxo_apply, so without (2)
 *       script_validate would miss a recent coin still resident in the
 *       un-flushed overlay (prevout_unresolved -> wedge). The mint-drive marker
 *       is entered ONLY by that single-threaded driver, so no other thread
 *       mutates the overlay while it holds the drive (asserted in
 *       coins_ram_writer_enter). */
static bool coins_kv_overlay_safe(void)
{
    return coins_ram_active() &&
           (coins_ram_writer_thread() || coins_ram_mint_drive_thread());
}

static _Thread_local uint64_t g_prepare_count;

uint64_t coins_kv_prepare_count_thread(void)
{
    return g_prepare_count;
}

/* Reducer-batch physical-row meter. Thread-local matches the single reducer
 * writer and cannot leak into maintenance work on another thread. Each
 * mutation records SQLite's affected-row result: INSERT OR IGNORE distinguishes
 * a new row from a collision, while DELETE distinguishes an existing row from
 * an absent no-op. This is exact without a read-before-write point query. */
static _Thread_local struct {
    bool active;
    int64_t delta;
    sqlite3 *db;
    sqlite3_stmt *add_many;
    sqlite3_stmt *spend_many;
} t_delta;

void coins_kv_delta_begin(void)
{
    coins_kv_delta_cancel();
    t_delta.active = true;
    t_delta.delta = 0;
}

void coins_kv_delta_cancel(void)
{
    if (t_delta.add_many)
        sqlite3_finalize(t_delta.add_many);
    if (t_delta.spend_many)
        sqlite3_finalize(t_delta.spend_many);
    memset(&t_delta, 0, sizeof(t_delta));
}

bool coins_kv_delta_finish(int64_t *delta_out)
{
    if (!t_delta.active || !delta_out)
        return false;
    *delta_out = t_delta.delta;
    coins_kv_delta_cancel();
    return true;
}

/* Complete the value replacement after INSERT OR IGNORE reports a primary-key
 * collision. This preserves the former INSERT OR REPLACE final-row semantics,
 * while keeping the physical row present (net delta zero) and avoiding a
 * SELECT probe on every normal insertion. Collisions are rejected by the
 * reducer's delta builder; this path primarily serves restore/reorg utilities
 * and makes the low-level store total under adversarial tests. */
static bool ckv_update_existing(sqlite3 *db, const uint8_t txid[32],
                                uint32_t vout, int64_t value, int32_t height,
                                bool is_coinbase, const uint8_t *script,
                                size_t script_len)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE coins SET value=?,height=?,is_coinbase=?,script=? "
            "WHERE txid=? AND vout=?", -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("coins_kv", "collision update prepare failed: %s (ext=%d)",
                 sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)value);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)height);
    sqlite3_bind_int(s, 3, is_coinbase ? 1 : 0);
    if (script && script_len > 0)
        sqlite3_bind_blob(s, 4, script, (int)script_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_blob(s, 4, "", 0, SQLITE_STATIC);
    sqlite3_bind_blob(s, 5, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, (int)vout);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc != SQLITE_DONE)
        LOG_WARN("coins_kv", "collision update failed rc=%d: %s (ext=%d)",
                 rc, sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

bool coins_kv_ensure_schema(sqlite3 *db)
{
    if (!db) return false;
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS coins ("
        "  txid        BLOB    NOT NULL,"
        "  vout        INTEGER NOT NULL,"
        "  value       INTEGER NOT NULL,"
        "  height      INTEGER NOT NULL,"
        "  is_coinbase INTEGER NOT NULL,"
        "  script      BLOB    NOT NULL,"
        "  PRIMARY KEY (txid, vout)"
        ") WITHOUT ROWID",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("coins_kv", "ensure_schema CREATE TABLE failed rc=%d: %s",
                 rc, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool coins_kv_add(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                  int64_t value, int32_t height, bool is_coinbase,
                  const uint8_t *script, size_t script_len)
{
    if (!db || !txid) return false;
    /* Bulk-fold hot store (flag-gated). With the flag off this is a single
     * bool load that is false, so the original SQLite path below runs
     * byte-for-byte unchanged. */
    if (coins_ram_active())
        return coins_ram_add(txid, vout, value, height, is_coinbase,
                             script, script_len);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO coins"
        "(txid,vout,value,height,is_coinbase,script) VALUES(?,?,?,?,?,?)",
        -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("coins_kv", "add prepare failed: %s (ext=%d)",
                 sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    sqlite3_bind_blob (s, 1, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 2, (int)vout);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)value);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)height);
    sqlite3_bind_int  (s, 5, is_coinbase ? 1 : 0);
    if (script && script_len > 0)
        sqlite3_bind_blob(s, 6, script, (int)script_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_blob(s, 6, "", 0, SQLITE_STATIC);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    /* The sole live UTXO author: a swallowed write would tear the coin set
     * silently. Capture the db error before finalize (which can reset it). */
    if (rc != SQLITE_DONE)
        LOG_WARN("coins_kv", "add step failed rc=%d: %s (ext=%d)",
                 rc, sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    bool inserted = rc == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(s);
    if (rc == SQLITE_DONE && !inserted &&
        !ckv_update_existing(db, txid, vout, value, height, is_coinbase,
                             script, script_len))
        return false;
    if (inserted && t_delta.active)
        t_delta.delta++;
    return rc == SQLITE_DONE;
}

bool coins_kv_spend(sqlite3 *db, const uint8_t txid[32], uint32_t vout)
{
    if (!db || !txid) return false;
    if (coins_ram_active())
        return coins_ram_spend(txid, vout);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM coins WHERE txid=? AND vout=?",
        -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("coins_kv", "spend prepare failed: %s (ext=%d)",
                 sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int (s, 2, (int)vout);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    /* DELETE of an absent row returns SQLITE_DONE (a no-op, not an error) —
     * intra-block double-spend safety relies on that; only a real engine
     * error (rc!=DONE) is logged here. */
    if (rc != SQLITE_DONE)
        LOG_WARN("coins_kv", "spend step failed rc=%d: %s (ext=%d)",
                 rc, sqlite3_errmsg(db), sqlite3_extended_errcode(db));
    int changed = rc == SQLITE_DONE ? sqlite3_changes(db) : 0;
    sqlite3_finalize(s);
    if (t_delta.active)
        t_delta.delta -= changed;
    return rc == SQLITE_DONE;
}

bool coins_kv_add_many_sqlite(sqlite3 *db, const struct coins_kv_add_row *rows,
                              size_t count)
{
    if (!db) return false;
    if (count == 0) return true;
    if (!rows) return false;

    /* ONE stack-local prepared statement, reset+bind+step per row. Byte-
     * identical SQL to coins_kv_add — only the prepare/finalize is hoisted out
     * of the row loop. Stack-local (never module-static): no cross-thread
     * cached-statement hazard (see the coins_kv.c header note). */
    sqlite3_stmt *local = NULL;
    bool cache = t_delta.active &&
                 (t_delta.db == NULL || t_delta.db == db);
    if (cache && !t_delta.db)
        t_delta.db = db;
    sqlite3_stmt **slot = cache ? &t_delta.add_many : &local;
    if (!*slot && sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO coins"
        "(txid,vout,value,height,is_coinbase,script) VALUES(?,?,?,?,?,?)",
        -1, slot, NULL) != SQLITE_OK) {
        LOG_FAIL("coins_kv", "add_many prepare failed: %s (ext=%d)",
                 sqlite3_errmsg(db), sqlite3_extended_errcode(db));
        return false;
    }
    sqlite3_stmt *s = *slot;

    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        const struct coins_kv_add_row *r = &rows[i];
        if (!r->txid) { ok = false;
            LOG_WARN("coins_kv", "add_many row %zu has NULL txid", i);
            break; }
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        sqlite3_bind_blob (s, 1, r->txid, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int  (s, 2, (int)r->vout);
        sqlite3_bind_int64(s, 3, (sqlite3_int64)r->value);
        sqlite3_bind_int64(s, 4, (sqlite3_int64)r->height);
        sqlite3_bind_int  (s, 5, r->is_coinbase ? 1 : 0);
        if (r->script && r->script_len > 0)
            sqlite3_bind_blob(s, 6, r->script, (int)r->script_len,
                              SQLITE_TRANSIENT);
        else
            sqlite3_bind_blob(s, 6, "", 0, SQLITE_STATIC);
        int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_DONE) {
            LOG_WARN("coins_kv",
                     "add_many row %zu step failed rc=%d: %s (ext=%d)",
                     i, rc, sqlite3_errmsg(db), sqlite3_extended_errcode(db));
            ok = false;
            break;
        }
        bool inserted = sqlite3_changes(db) == 1;
        if (!inserted && !ckv_update_existing(
                db, r->txid, r->vout, r->value, r->height, r->is_coinbase,
                r->script, r->script_len)) {
            ok = false;
            break;
        }
        if (t_delta.active && inserted)
            t_delta.delta++;
    }
    if (cache) {
        /* Cached statements outlive the caller's row buffers. Release the
         * final SQLITE_TRANSIENT copies now; the next call will rebind. */
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
    } else {
        sqlite3_finalize(s);
    }
    return ok;
}

bool coins_kv_add_many(sqlite3 *db, const struct coins_kv_add_row *rows,
                       size_t count)
{
    if (coins_ram_active()) {
        if (count == 0) return true;
        if (!rows) return false;
        for (size_t i = 0; i < count; i++) {
            const struct coins_kv_add_row *r = &rows[i];
            if (!r->txid) {
                LOG_WARN("coins_kv", "add_many row %zu has NULL txid", i);
                return false;
            }
            if (!coins_ram_add(r->txid, r->vout, r->value, r->height,
                               r->is_coinbase, r->script, r->script_len))
                return false;
        }
        return true;
    }
    return coins_kv_add_many_sqlite(db, rows, count);
}

bool coins_kv_spend_many_sqlite(sqlite3 *db, const struct coins_kv_spend_row *rows,
                                size_t count)
{
    if (!db) return false;
    if (count == 0) return true;
    if (!rows) return false;

    sqlite3_stmt *local = NULL;
    bool cache = t_delta.active &&
                 (t_delta.db == NULL || t_delta.db == db);
    if (cache && !t_delta.db)
        t_delta.db = db;
    sqlite3_stmt **slot = cache ? &t_delta.spend_many : &local;
    if (!*slot && sqlite3_prepare_v2(db,
        "DELETE FROM coins WHERE txid=? AND vout=?",
        -1, slot, NULL) != SQLITE_OK) {
        LOG_FAIL("coins_kv", "spend_many prepare failed: %s (ext=%d)",
                 sqlite3_errmsg(db), sqlite3_extended_errcode(db));
        return false;
    }
    sqlite3_stmt *s = *slot;

    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        const struct coins_kv_spend_row *r = &rows[i];
        if (!r->txid) { ok = false;
            LOG_WARN("coins_kv", "spend_many row %zu has NULL txid", i);
            break; }
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        sqlite3_bind_blob(s, 1, r->txid, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int (s, 2, (int)r->vout);
        int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
        /* DELETE of an absent row returns SQLITE_DONE (a no-op, not an error) —
         * intra-block double-spend safety relies on that, identical to
         * coins_kv_spend; only a real engine error is fatal. */
        if (rc != SQLITE_DONE) {
            LOG_WARN("coins_kv",
                     "spend_many row %zu step failed rc=%d: %s (ext=%d)",
                     i, rc, sqlite3_errmsg(db), sqlite3_extended_errcode(db));
            ok = false;
            break;
        }
        if (t_delta.active)
            t_delta.delta -= sqlite3_changes(db);
    }
    if (cache) {
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
    } else {
        sqlite3_finalize(s);
    }
    return ok;
}

bool coins_kv_spend_many(sqlite3 *db, const struct coins_kv_spend_row *rows,
                         size_t count)
{
    if (coins_ram_active()) {
        if (count == 0) return true;
        if (!rows) return false;
        for (size_t i = 0; i < count; i++) {
            const struct coins_kv_spend_row *r = &rows[i];
            if (!r->txid) {
                LOG_WARN("coins_kv", "spend_many row %zu has NULL txid", i);
                return false;
            }
            if (!coins_ram_spend(r->txid, r->vout))
                return false;
        }
        return true;
    }
    return coins_kv_spend_many_sqlite(db, rows, count);
}

/* ── shared point-read SQL + a lazy prepare-or-reuse helper ───────────────
 * The fresh (_sqlite) and cached (_sqlite_cached) variants share ONE SQL text
 * and ONE column-extraction path per query, so the two prepare strategies are
 * provably byte-identical (same statement, same binds, same column reads). */
static const char CKV_SQL_EXISTS[] =
    "SELECT 1 FROM coins WHERE txid=? AND vout=?";
static const char CKV_SQL_GET[] =
    "SELECT value, script FROM coins WHERE txid=? AND vout=?";
static const char CKV_SQL_GET_PREVOUT[] =
    "SELECT value, script, height, is_coinbase FROM coins WHERE txid=? AND vout=?";

/* Return a ready-to-bind statement: either a fresh prepare (fresh==true, the
 * caller finalizes) or the caller's cached statement (*cache; prepared lazily
 * once, then reset+clear for reuse). Returns NULL on prepare failure (leaving
 * *cache NULL). */
static sqlite3_stmt *ckv_point_stmt(sqlite3 *db, const char *sql, bool fresh,
                                    sqlite3_stmt **cache)
{
    if (fresh) {
        sqlite3_stmt *s = NULL;
        if (g_prepare_count != UINT64_MAX)
            g_prepare_count++;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
            return NULL;
        return s;
    }
    if (*cache) {
        sqlite3_reset(*cache);          /* release any prior row lock */
        sqlite3_clear_bindings(*cache);
        return *cache;
    }
    if (g_prepare_count != UINT64_MAX)
        g_prepare_count++;
    if (sqlite3_prepare_v2(db, sql, -1, cache, NULL) != SQLITE_OK) {
        *cache = NULL;
        return NULL;
    }
    return *cache;
}

/* Bind (txid,vout) and step for an EXISTS probe; reset when reuse==true so a
 * cached statement releases its lock for the next call. */
static bool ckv_exists_step(sqlite3_stmt *s, const uint8_t txid[32],
                            uint32_t vout, bool reuse)
{
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int (s, 2, (int)vout);
    bool found = sqlite3_step(s) == SQLITE_ROW;  // raw-sql-ok:progress-kv-kernel-store
    if (reuse) sqlite3_reset(s);
    return found;
}

bool coins_kv_exists_sqlite(sqlite3 *db, const uint8_t txid[32], uint32_t vout)
{
    if (!db || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_EXISTS, true, NULL);
    if (!s) return false;
    bool found = ckv_exists_step(s, txid, vout, false);
    sqlite3_finalize(s);
    return found;
}

bool coins_kv_exists_sqlite_cached(sqlite3 *db, sqlite3_stmt **cache,
                                   const uint8_t txid[32], uint32_t vout)
{
    if (!db || !cache || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_EXISTS, false, cache);
    if (!s) return false;
    return ckv_exists_step(s, txid, vout, true);
}

bool coins_kv_exists(sqlite3 *db, const uint8_t txid[32], uint32_t vout)
{
    if (coins_kv_overlay_safe())
        return coins_ram_exists(txid, vout);
    return coins_kv_exists_sqlite(db, txid, vout);
}

/* Bind (txid,vout), step, and extract the (value,script) column set; reset
 * when reuse==true (cached statement). */
static bool ckv_get_step(sqlite3_stmt *s, const uint8_t txid[32], uint32_t vout,
                         int64_t *value_out, uint8_t *script_out,
                         size_t script_cap, size_t *script_len_out, bool reuse)
{
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int (s, 2, (int)vout);
    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        /* A row exists iff the output is live (spend = DELETE). */
        found = true;
        if (value_out) *value_out = sqlite3_column_int64(s, 0);
        int slen = sqlite3_column_bytes(s, 1);
        const void *sblob = sqlite3_column_blob(s, 1);
        if (script_len_out) *script_len_out = (size_t)slen;
        if (script_out && script_cap > 0 && sblob && slen > 0) {
            size_t copy = (size_t)slen < script_cap
                        ? (size_t)slen : script_cap;
            memcpy(script_out, sblob, copy);
        }
    }
    if (reuse) sqlite3_reset(s);
    return found;
}

bool coins_kv_get_sqlite(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                  int64_t *value_out, uint8_t *script_out, size_t script_cap,
                  size_t *script_len_out)
{
    if (!db || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_GET, true, NULL);
    if (!s) return false;
    bool found = ckv_get_step(s, txid, vout, value_out, script_out, script_cap,
                              script_len_out, false);
    sqlite3_finalize(s);
    return found;
}

bool coins_kv_get_sqlite_cached(sqlite3 *db, sqlite3_stmt **cache,
                                const uint8_t txid[32], uint32_t vout,
                                int64_t *value_out, uint8_t *script_out,
                                size_t script_cap, size_t *script_len_out)
{
    if (!db || !cache || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_GET, false, cache);
    if (!s) return false;
    return ckv_get_step(s, txid, vout, value_out, script_out, script_cap,
                        script_len_out, true);
}

/* Bind (txid,vout), step, and extract the (value,script,height,is_coinbase)
 * prevout column set; reset when reuse==true (cached statement). */
static bool ckv_prevout_step(sqlite3_stmt *s, const uint8_t txid[32],
                             uint32_t vout, int64_t *value_out,
                             uint8_t *script_out, size_t script_cap,
                             size_t *script_len_out, int32_t *height_out,
                             bool *is_coinbase_out, bool reuse)
{
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int (s, 2, (int)vout);
    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        found = true;
        if (value_out) *value_out = sqlite3_column_int64(s, 0);
        int slen = sqlite3_column_bytes(s, 1);
        const void *sblob = sqlite3_column_blob(s, 1);
        if (script_len_out) *script_len_out = (size_t)slen;
        if (height_out) *height_out = sqlite3_column_int(s, 2);
        if (is_coinbase_out) *is_coinbase_out = sqlite3_column_int(s, 3) != 0;
        if (script_out && script_cap > 0 && sblob && slen > 0) {
            size_t copy = (size_t)slen < script_cap
                        ? (size_t)slen : script_cap;
            memcpy(script_out, sblob, copy);
        }
    }
    if (reuse) sqlite3_reset(s);
    return found;
}

bool coins_kv_get_prevout_sqlite(sqlite3 *db, const uint8_t txid[32],
                                 uint32_t vout, int64_t *value_out,
                                 uint8_t *script_out, size_t script_cap,
                                 size_t *script_len_out,
                                 int32_t *height_out,
                                 bool *is_coinbase_out)
{
    if (!db || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_GET_PREVOUT, true, NULL);
    if (!s) return false;
    bool found = ckv_prevout_step(s, txid, vout, value_out, script_out,
                                  script_cap, script_len_out, height_out,
                                  is_coinbase_out, false);
    sqlite3_finalize(s);
    return found;
}

bool coins_kv_get_prevout_sqlite_cached(sqlite3 *db, sqlite3_stmt **cache,
                                        const uint8_t txid[32], uint32_t vout,
                                        int64_t *value_out, uint8_t *script_out,
                                        size_t script_cap,
                                        size_t *script_len_out,
                                        int32_t *height_out,
                                        bool *is_coinbase_out)
{
    if (!db || !cache || !txid) return false;
    sqlite3_stmt *s = ckv_point_stmt(db, CKV_SQL_GET_PREVOUT, false, cache);
    if (!s) return false;
    return ckv_prevout_step(s, txid, vout, value_out, script_out, script_cap,
                            script_len_out, height_out, is_coinbase_out, true);
}

bool coins_kv_get(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                  int64_t *value_out, uint8_t *script_out, size_t script_cap,
                  size_t *script_len_out)
{
    if (coins_kv_overlay_safe())
        return coins_ram_get(txid, vout, value_out, script_out, script_cap,
                             script_len_out);
    return coins_kv_get_sqlite(db, txid, vout, value_out, script_out,
                               script_cap, script_len_out);
}

bool coins_kv_get_prevout(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                          int64_t *value_out, uint8_t *script_out,
                          size_t script_cap, size_t *script_len_out,
                          int32_t *height_out, bool *is_coinbase_out)
{
    if (coins_kv_overlay_safe())
        return coins_ram_get_prevout(txid, vout, value_out, script_out,
                                     script_cap, script_len_out, height_out,
                                     is_coinbase_out);
    return coins_kv_get_prevout_sqlite(db, txid, vout, value_out, script_out,
                                       script_cap, script_len_out, height_out,
                                       is_coinbase_out);
}

bool coins_kv_get_prevout_cached(sqlite3 *db, sqlite3_stmt **cache,
                                 const uint8_t txid[32], uint32_t vout,
                                 int64_t *value_out, uint8_t *script_out,
                                 size_t script_cap, size_t *script_len_out,
                                 int32_t *height_out, bool *is_coinbase_out)
{
    /* Same overlay dispatch as coins_kv_get_prevout; the *cache statement is
     * threaded only to the durable-SQLite path (the overlay never prepares). */
    if (coins_kv_overlay_safe())
        return coins_ram_get_prevout(txid, vout, value_out, script_out,
                                     script_cap, script_len_out, height_out,
                                     is_coinbase_out);
    return coins_kv_get_prevout_sqlite_cached(db, cache, txid, vout, value_out,
                                              script_out, script_cap,
                                              script_len_out, height_out,
                                              is_coinbase_out);
}

int64_t coins_kv_count_sqlite(sqlite3 *db)
{
    if (!db) return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM coins",
                           -1, &s, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

int64_t coins_kv_count(sqlite3 *db)
{
    if (coins_kv_overlay_safe())
        return coins_ram_count();
    return coins_kv_count_sqlite(db);
}

bool coins_kv_get_coins_sqlite(sqlite3 *db, const uint8_t txid[32],
                               struct coins *out)
{
    if (!out) return false;
    coins_init(out);
    if (!db || !txid) return false;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT vout, value, script, height, is_coinbase "
        "FROM coins WHERE txid=?",
        -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);

    uint32_t max_vout = 0;
    int nrows = 0, height = 0, is_coinbase = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        uint32_t vi = (uint32_t)sqlite3_column_int(s, 0);
        if (nrows == 0) {
            height      = sqlite3_column_int(s, 3);
            is_coinbase = sqlite3_column_int(s, 4);
        }
        if (vi > max_vout) max_vout = vi;
        nrows++;
    }
    if (nrows == 0) {
        sqlite3_finalize(s);
        return false;
    }

    if (!coins_alloc(out, (size_t)(max_vout + 1))) {
        sqlite3_finalize(s);
        return false;
    }
    out->version     = 1;
    out->height      = height;
    out->is_coinbase = (is_coinbase != 0);

    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        uint32_t vi = (uint32_t)sqlite3_column_int(s, 0);
        if (vi >= out->num_vout) continue;
        out->vout[vi].value = sqlite3_column_int64(s, 1);
        const void *script = sqlite3_column_blob(s, 2);
        int script_len = sqlite3_column_bytes(s, 2);
        if (script && script_len > 0) {
            size_t slen = (size_t)script_len;
            if (slen > MAX_SCRIPT_SIZE) slen = MAX_SCRIPT_SIZE;
            memcpy(out->vout[vi].script_pub_key.data, script, slen);
            out->vout[vi].script_pub_key.size = slen;
        }
    }
    coins_cleanup(out);
    sqlite3_finalize(s);
    return true;
}

bool coins_kv_get_coins(sqlite3 *db, const uint8_t txid[32], struct coins *out)
{
    if (coins_kv_overlay_safe())
        return coins_ram_get_coins(txid, out);
    return coins_kv_get_coins_sqlite(db, txid, out);
}

bool coins_kv_setinfo_sqlite(sqlite3 *db, int64_t *num_txs, int64_t *num_txouts,
                             int64_t *total_amount)
{
    if (!db) return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(DISTINCT txid), COUNT(*), COALESCE(SUM(value),0) "
            "FROM coins", -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        if (num_txs)      *num_txs      = sqlite3_column_int64(s, 0);
        if (num_txouts)   *num_txouts   = sqlite3_column_int64(s, 1);
        if (total_amount) *total_amount = sqlite3_column_int64(s, 2);
        ok = true;
    }
    sqlite3_finalize(s);
    return ok;
}

bool coins_kv_setinfo(sqlite3 *db, int64_t *num_txs, int64_t *num_txouts,
                      int64_t *total_amount)
{
    if (coins_kv_overlay_safe())
        return coins_ram_setinfo(num_txs, num_txouts, total_amount);
    return coins_kv_setinfo_sqlite(db, num_txs, num_txouts, total_amount);
}

int coins_kv_commitment(sqlite3 *db, uint8_t out[32])
{
    if (coins_kv_overlay_safe())
        return coins_ram_commitment(out);
    if (!db || !out) return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid, vout, value, script, height, is_coinbase "
            "FROM coins ORDER BY txid, vout", -1, &s, NULL) != SQLITE_OK)
        return -1;

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const uint8_t *txid = (const uint8_t *)sqlite3_column_blob(s, 0);
        int txid_len = sqlite3_column_bytes(s, 0);
        if (!txid || txid_len < 32) continue;

        uint32_t vout   = (uint32_t)sqlite3_column_int(s, 1);
        int64_t  value  = sqlite3_column_int64(s, 2);
        const uint8_t *script = (const uint8_t *)sqlite3_column_blob(s, 3);
        int script_len = sqlite3_column_bytes(s, 3);
        int32_t  height = sqlite3_column_int(s, 4);
        int cb_int = sqlite3_column_int(s, 5);

        /* Canonical must-never-fork record — see utxo_commitment.h. This is
         * BYTE-IDENTICAL to the legacy `utxos` commitment because both share
         * this single encoder (utxo_commitment_sha3_write_record). */
        utxo_commitment_sha3_write_record(&ctx, txid, vout, value,
                                          (script_len > 0) ? script : NULL,
                                          (uint32_t)(script_len > 0 ? script_len : 0),
                                          (uint32_t)height,
                                          (uint8_t)(cb_int ? 1 : 0));
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return -1;

    sha3_256_finalize(&ctx, out);
    return 0;
}

static void coins_kv_hex32(char out[65], const uint8_t in[32])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", in[i]);
}

bool coins_kv_verify_against_checkpoint(sqlite3 *db,
                                        const struct sha3_utxo_checkpoint *cp,
                                        uint8_t out_got_root[32],
                                        int64_t *out_got_count,
                                        char *reason, size_t reason_cap)
{
    if (out_got_root)
        memset(out_got_root, 0, 32);
    if (out_got_count)
        *out_got_count = -1;

    if (!db || !cp) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "null args db=%p cp=%p",
                     (void *)db, (const void *)cp);
        LOG_FAIL("coins_kv", "verify_against_checkpoint: null args");
    }

    /* ONE digest: re-derive via coins_kv_commitment — the exact canonical-order
     * SHA3 the ratify verb and the refold hard-assert use. No second fold. */
    uint8_t got_root[32] = {0};
    if (coins_kv_commitment(db, got_root) != 0) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap,
                     "coins_kv sha3 commitment computation failed");
        LOG_FAIL("coins_kv", "verify_against_checkpoint: commitment failed");
    }
    int64_t got_count = coins_kv_count(db);
    if (got_count < 0) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "coins_kv count read failed");
        LOG_FAIL("coins_kv", "verify_against_checkpoint: count read failed");
    }
    if (out_got_root)
        memcpy(out_got_root, got_root, 32);
    if (out_got_count)
        *out_got_count = got_count;

    bool sha3_ok = memcmp(got_root, cp->sha3_hash, 32) == 0;
    bool count_ok = (uint64_t)got_count == cp->utxo_count;
    if (sha3_ok && count_ok) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap,
                     "coins_kv reproduces the compiled checkpoint at h=%d",
                     (int)cp->height);
        return true;
    }

    if (reason && reason_cap) {
        /* Lead with the short count fields (the cheap discriminator) so both the
         * "count" and "sha3" tokens survive even a small/truncated buffer; the
         * long hex digests trail. */
        char got_hex[65], want_hex[65];
        coins_kv_hex32(got_hex, got_root);
        coins_kv_hex32(want_hex, cp->sha3_hash);
        snprintf(reason, reason_cap,
                 "coins_kv does not reproduce the compiled checkpoint "
                 "(count got=%lld want=%llu; sha3 got=%s want=%s)",
                 (long long)got_count, (unsigned long long)cp->utxo_count,
                 got_hex, want_hex);
    }
    return false;
}

/* ── Per-boundary UTXO root table (keystone reproducibility anchor) ──────
 *
 * Stored under a per-height key "mmb_utxo_root:<height>" as a raw 32-byte
 * blob. progress_meta is the right home: it is the same handle every leaf
 * builder already reaches (progress_store_db()), so catch-up and rebuild can
 * read the boundary root the live connect path stamped without re-folding the
 * historical UTXO set. The blob is the literal coins_kv_commitment output —
 * no integer encoding to drift across hosts. */

static void coins_kv_boundary_root_key(int32_t height, char *buf, size_t cap)
{
    snprintf(buf, cap, "mmb_utxo_root:%d", (int)height);
}

bool coins_kv_boundary_root_set(sqlite3 *db, int32_t height,
                                const uint8_t utxo_root[32])
{
    if (!db || !utxo_root || height < 0) return false;
    char key[40];
    coins_kv_boundary_root_key(height, key, sizeof(key));
    return progress_meta_set(db, key, utxo_root, 32);
}

/* In-tx variant: run the INSERT inside the caller's ALREADY-OPEN transaction.
 * The tip_finalize reducer step calls this from inside the stage's batch
 * BEGIN IMMEDIATE + per-step SAVEPOINT, so the own-BEGIN _set above would fail
 * with "cannot start a transaction within a transaction". progress_meta_set_in_tx
 * issues no inner BEGIN/COMMIT, so the boundary root commits atomically with the
 * finalize log row in the same step transaction. */
bool coins_kv_boundary_root_set_in_tx(sqlite3 *db, int32_t height,
                                      const uint8_t utxo_root[32])
{
    if (!db || !utxo_root || height < 0) return false;
    char key[40];
    coins_kv_boundary_root_key(height, key, sizeof(key));
    return progress_meta_set_in_tx(db, key, utxo_root, 32);
}

bool coins_kv_boundary_root_get(sqlite3 *db, int32_t height,
                                uint8_t out_utxo_root[32], bool *found)
{
    if (found) *found = false;
    if (!db || !out_utxo_root || height < 0) return false;
    char key[40];
    coins_kv_boundary_root_key(height, key, sizeof(key));
    uint8_t blob[32] = {0};
    size_t n = 0;
    bool f = false;
    if (!progress_meta_get(db, key, blob, sizeof(blob), &n, &f))
        return false;
    if (f && n == 32) {
        memcpy(out_utxo_root, blob, 32);
        if (found) *found = true;
    }
    return true;
}

/* ── coins_applied_height — contiguous applied-frontier counter ──────────
 *
 * Stored as a stable 8-byte little-endian int64 blob under
 * COINS_APPLIED_HEIGHT_KEY in progress_meta. LE so a value written on one
 * machine reads back identically on any host (the blob is opaque to the
 * progress_meta layer, which owns no integer encoding). */

static int64_t le64_get(const uint8_t b[8])
{
    uint64_t u = 0;
    for (int i = 0; i < 8; i++)
        u |= (uint64_t)b[i] << (8 * i);
    return (int64_t)u;
}

bool coins_kv_get_applied_height(sqlite3 *db, int32_t *out, bool *found)
{
    if (found) *found = false;
    if (!db) return false;
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool f = false;
    if (!progress_meta_get(db, COINS_APPLIED_HEIGHT_KEY,
                           blob, sizeof(blob), &n, &f))
        return false;
    if (!f) {
        /* Absent → clean "unknown"; a fresh datadir is NOT 0-as-applied. */
        return true;
    }
    if (n != sizeof(blob)) {
        /* A row exists but the blob is the wrong width — malformed; treat as a
         * hard read error rather than silently mis-decode a frontier. */
        LOG_WARN("coins_kv",
                 "[coins_kv] applied_height blob malformed (len=%zu)", n);
        return false;
    }
    /* The stored width is int64 (le64_put/le64_get) but the setter only ever
     * writes an int32_t-domain height and every reader below treats the
     * result as int32_t. A bit-flip or torn write on this 8-byte blob can
     * decode to a value outside int32_t range; narrowing that silently
     * (the old `(int32_t)le64_get(blob)` cast) would hand callers an
     * arbitrary in-range-looking height instead of the real corrupt one —
     * unbound trust in a persisted verdict. Bound-check before narrowing and
     * fail the same way the length check above does. */
    int64_t v = le64_get(blob);
    if (v < INT32_MIN || v > INT32_MAX) {
        LOG_WARN("coins_kv",
                 "[coins_kv] applied_height out of int32 range (%lld) — "
                 "treating as malformed", (long long)v);
        return false;
    }
    if (out) *out = (int32_t)v;
    if (found) *found = true;
    return true;
}

bool coins_kv_is_proven_authority(sqlite3 *db, int32_t *out_applied)
{
    if (out_applied) *out_applied = -1;
    if (!db)
        return false;

    /* (1) durable applied frontier present. */
    int32_t applied = 0;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found) || !found)
        return false;

    /* (2) migration stamp: the store provably holds the live set. A
     * cursor-backfilled frontier on a pre-migration datadir is NOT proof —
     * without this rung the derived gates would pass datadirs whose
     * coins still live only in the node.db mirror. */
    uint8_t mig = 0;
    size_t mlen = 0;
    bool mfound = false;
    if (!progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                           &mig, sizeof(mig), &mlen, &mfound))
        return false;  /* read error → the stricter legacy gates */
    if (!mfound || mlen != 1 || mig != 1)
        return false;

    /* (3) the set is non-empty. */
    if (coins_kv_count(db) <= 0)
        return false;

    if (out_applied) *out_applied = applied;
    return true;
}

/* ── Migration-complete stamp (coins_kv.h COINS_KV_MIGRATION_COMPLETE_KEY) ──── */

bool coins_kv_mark_migration_complete(sqlite3 *db)
{
    if (!db) {
        LOG_WARN("coins_kv", "[coins_kv] mark_migration_complete: NULL db");
        return false;
    }
    if (!progress_meta_table_ensure(db)) {
        LOG_WARN("coins_kv",
                 "[coins_kv] mark_migration_complete: meta table ensure failed");
        return false;
    }
    const uint8_t one = 0x01;
    progress_store_tx_lock();
    bool ok = progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                &one, sizeof(one));
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN("coins_kv",
                 "[coins_kv] mark_migration_complete: progress_meta_set failed");
        return false;
    }
    LOG_INFO("coins_kv",
             "[coins_kv] stamped migration-complete marker — coins_kv provably "
             "holds the live coin set");
    return true;
}

/* ── Self-folded provenance marker (coins_kv.h G-SOV part 3) ───────────────── */

bool coins_kv_mark_self_folded(sqlite3 *db)
{
    if (!db) {
        LOG_WARN("coins_kv", "[coins_kv] mark_self_folded: NULL db");
        return false;
    }
    if (!progress_meta_table_ensure(db)) {
        LOG_WARN("coins_kv", "[coins_kv] mark_self_folded: meta table ensure failed");
        return false;
    }
    const uint8_t one = 0x01;
    progress_store_tx_lock();
    bool ok = progress_meta_set(db, COINS_KV_SELF_FOLDED_KEY, &one, sizeof(one));
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN("coins_kv", "[coins_kv] mark_self_folded: progress_meta_set failed");
        return false;
    }
    LOG_INFO("coins_kv",
             "[coins_kv] stamped self-folded marker — the coin set is "
             "self-derived (not the borrowed node.db copy)");
    return true;
}

bool coins_kv_clear_self_folded(sqlite3 *db)
{
    if (!db) {
        LOG_WARN("coins_kv", "[coins_kv] clear_self_folded: NULL db");
        return false;
    }
    if (!progress_meta_table_ensure(db)) {
        LOG_WARN("coins_kv", "[coins_kv] clear_self_folded: meta table ensure failed");
        return false;
    }
    progress_store_tx_lock();
    bool ok = progress_meta_delete(db, COINS_KV_SELF_FOLDED_KEY);
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN("coins_kv", "[coins_kv] clear_self_folded: progress_meta_delete failed");
        return false;
    }
    return true;
}

bool coins_kv_contains_refold_marker(sqlite3 *db)
{
    if (!db)
        return false;
    uint8_t v = 0;
    size_t n = 0;
    bool found = false;
    progress_store_tx_lock();
    bool ok = progress_meta_get(db, COINS_KV_SELF_FOLDED_KEY,
                                &v, sizeof(v), &n, &found);
    progress_store_tx_unlock();
    if (!ok)
        return false;  /* read error → conservatively NOT proven self-folded */
    return found && n == 1 && v == 0x01;
}

bool coins_kv_tip_is_self_derived(sqlite3 *db, int32_t hstar,
                                  char *reason, size_t reason_cap)
{
    if (reason && reason_cap)
        reason[0] = '\0';
    if (!db) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "null_db");
        return false;
    }

    /* ONE consistent durable snapshot across all reads (recursive lock — safe
     * whether or not the caller already holds it). */
    progress_store_tx_lock();

    /* Part 2: coins_applied_height present AND == hstar + 1. */
    int32_t applied = 0;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found)) {
        progress_store_tx_unlock();
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "applied_height_read_error");
        return false;
    }
    if (!found) {
        progress_store_tx_unlock();
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "applied_height_absent");
        return false;
    }
    if (applied != hstar + 1) {
        progress_store_tx_unlock();
        if (reason && reason_cap)
            snprintf(reason, reason_cap,
                     "applied_height=%d!=hstar+1=%d", (int)applied, (int)hstar + 1);
        return false;
    }

    /* Part 3: NOT borrowed-and-stamped, OR self-folded marker present. */
    bool borrowed_stamped = coins_kv_is_proven_authority(db, NULL);
    uint8_t v = 0;
    size_t n = 0;
    bool mfound = false;
    bool self_folded = progress_meta_get(db, COINS_KV_SELF_FOLDED_KEY,
                                         &v, sizeof(v), &n, &mfound) &&
                       mfound && n == 1 && v == 0x01;
    progress_store_tx_unlock();

    if (borrowed_stamped && !self_folded) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "borrowed_seed_no_refold_marker");
        return false;
    }
    return true;
}

/* Read the durably committed utxo_apply stage cursor straight off the
 * stage_cursor table on the progress.kv handle. Kept in the storage layer (a
 * raw kernel-store read, same hatch as coins_kv_count) so the backfill below
 * does not pull in the app/jobs stage_helpers inline. Returns false with
 * *found=false when the row is absent (a brand-new datadir). */
static bool utxo_apply_cursor_persisted(sqlite3 *db, int64_t *out, bool *found)
{
    if (found) *found = false;
    if (!db || !out) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = 'utxo_apply'",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(st, 0);
        if (found) *found = true;
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

bool coins_kv_backfill_applied_height_if_absent(
    sqlite3 *db, coins_kv_frontier_writer_fn writer)
{
    if (!db) return true;  /* store not open yet → no-op, retried later */
    if (!writer)
        LOG_FAIL("coins_kv", "applied_height backfill: NULL frontier writer");

    bool present = false;
    int32_t cur = 0;
    if (!coins_kv_get_applied_height(db, &cur, &present))
        return false;
    if (present)
        return true;  /* already seeded — never re-seed (allows later rewind) */

    /* Derive the seed from the already-trusted utxo_apply cursor — NEVER from
     * MAX(coins.height) (which cannot see an interior hole). A brand-new
     * (virgin) datadir has no cursor row yet: leave the key ABSENT so the
     * first forward apply writes it in lockstep with the cursor. */
    int64_t cursor = 0;
    bool have_cursor = false;
    progress_store_tx_lock();
    if (!utxo_apply_cursor_persisted(db, &cursor, &have_cursor)) {
        progress_store_tx_unlock();
        LOG_WARN("coins_kv", "[coins_kv] applied_height backfill: cursor read failed");
        return false;
    }
    if (!have_cursor) {
        progress_store_tx_unlock();
        return true;  /* virgin datadir — nothing durable to seed from yet */
    }

    /* The ONE allowed standalone txn: a pure backfill of a derived value that
     * already equals the durable cursor, with NO coin mutation. */
    char *err = NULL;
    bool ok = true;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (ok && !writer(db, (int32_t)cursor))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (!ok) {
        if (err) LOG_WARN("coins_kv",
                          "[coins_kv] applied_height backfill failed: %s", err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();

    if (ok)
        LOG_INFO("coins_kv",
                 "[coins_kv] backfilled applied_height=%lld from utxo_apply cursor",
                 (long long)cursor);
    return ok;
}

bool coins_kv_seed_genesis_applied_height(
    sqlite3 *db, coins_kv_frontier_writer_fn writer)
{
    if (!db) return true;  /* store not open yet → no-op, retried later */
    if (!writer)
        LOG_FAIL("coins_kv", "genesis applied_height seed: NULL frontier writer");

    /* (1) Already seeded? Never re-seed (a later legitimate rewind must be free
     * to move it — same contract as the cursor backfill above). */
    bool present = false;
    int32_t cur = 0;
    if (!coins_kv_get_applied_height(db, &cur, &present))
        return false;
    if (present)
        return true;

    /* (2) A borrowed / snapshot seed is proven-authority: the sovereignty gate's
     * part 3 (borrowed_seed_no_refold_marker) refuses those; they must never be
     * minted on, and they already carry coins_applied_height (so this is doubly
     * inert). Skip — never manufacture a self-derived claim over a borrow. */
    if (coins_kv_is_proven_authority(db, NULL))
        return true;

    /* (3) Any coins already present means a fold/seed has begun — not a pristine
     * from-genesis store. Leave the frontier to the forward fold / cursor
     * backfill so we never claim coverage the store does not have. */
    if (coins_kv_count(db) > 0)
        return true;

    /* (4) A stamped utxo_apply cursor row likewise means the store is past
     * pristine genesis (the cursor backfill above already handled it). */
    int64_t cursor = 0;
    bool have_cursor = false;
    progress_store_tx_lock();
    if (!utxo_apply_cursor_persisted(db, &cursor, &have_cursor)) {
        progress_store_tx_unlock();
        LOG_WARN("coins_kv", "[coins_kv] genesis applied_height seed: cursor read failed");
        return false;
    }
    if (have_cursor) {
        progress_store_tx_unlock();
        return true;  /* fold already started — not pristine genesis */
    }

    /* Pristine from-genesis store: seed coins_applied_height = 1 (genesis applied,
     * empty coin delta). The ONE allowed standalone txn — a pure derived-frontier
     * write with NO coin mutation, mirroring coins_kv_backfill_applied_height_if_
     * absent. This equals the value the forward fold co-commits the instant it
     * applies genesis (cursor_in 0 → next_cursor 1), and equals hstar+1 at the
     * genesis tip (hstar==0), so the frontier tear/reconcile diagnostics stay
     * quiet (coins_applied 1 is NOT above the empty-log contiguity anchor+1). */
    char *err = NULL;
    bool ok = true;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (ok && !writer(db, (int32_t)1))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (!ok) {
        if (err) LOG_WARN("coins_kv",
                          "[coins_kv] genesis applied_height seed failed: %s", err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();

    if (ok)
        LOG_INFO("coins_kv",
                 "[coins_kv] seeded coins_applied_height=1 for a pristine "
                 "from-genesis regtest store (on-demand mint bootstrap)");
    return ok;
}

bool coins_kv_reset_for_reseed(sqlite3 *db)
{
    if (!db) return false;
    /* Ensure a brand-new store resets as a clean no-op. */
    if (!coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return false;

    /* The single legal standalone txn for a reindex epilogue: the replayed
     * `utxos` mirror is the authority and coins_kv is rebuilt from it in the
     * same single-writer boot. Truncate the coins set, then clear the
     * migration stamp, self-folded provenance bit, and applied frontier so
     * coins_kv_seed_from_node_db does a FRESH copy (it short-circuits when the
     * stamp is already set) and a borrowed reseed can never inherit a stale
     * sovereignty claim. */
    char *err = NULL;
    bool ok = true;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (ok && sqlite3_exec(db, "DELETE FROM coins", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (ok && !progress_meta_delete_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY))
        ok = false;
    if (ok && !progress_meta_delete_in_tx(db, COINS_KV_SELF_FOLDED_KEY))
        ok = false;
    if (ok && !progress_meta_delete_in_tx(db, COINS_APPLIED_HEIGHT_KEY))
        ok = false;
    if (ok && !coins_kv_bump_authority_generation_in_tx(db))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (!ok) {
        if (err) LOG_WARN("coins_kv",
                          "[coins_kv] reset_for_reseed failed: %s", err);
        else LOG_WARN("coins_kv", "[coins_kv] reset_for_reseed failed");
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (err) sqlite3_free(err);
    return ok;
}
