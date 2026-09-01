/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * txindex_projection — transaction-location projection. See
 * jobs/txindex_projection.h for the design rationale. Raw SQLite over the
 * shared progress.kv kernel store, mirroring address_index.c's prepare / bind /
 * step / finalize idiom (loud on error). The caller owns
 * progress_store_tx_lock serialization. */

#include "jobs/txindex_projection.h"

#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"
#include "util/util.h"

#include <sqlite3.h>
#include <string.h>

/* ── little-endian scalar writers for the deterministic digest ────── */
static void ti_put_u32le(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}
static void ti_put_u64le(uint8_t b[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

/* Cached -txindex decision (file-scope so a test can reset it). -1 = unknown. */
static int g_tx_enabled_cache = -1;

bool txindex_projection_enabled(void)
{
    /* Args are parsed once at startup; cache the decision.
     * OMNISCIENCE default (owner directive: "the node obsesses about knowing
     * everything about the ZClassic network"): ON by default so a plain boot
     * builds the tx-location catalog (getrawtransaction-class lookups without a
     * full-chain scan). Opt OUT with -txindex=0. The backfill is a bounded,
     * supervised, disk-pre-checked, tip-yielding background job — it never
     * wedges tip-follow (txindex_projection_service.c). */
    if (g_tx_enabled_cache < 0)
        g_tx_enabled_cache = GetBoolArg("-txindex", true) ? 1 : 0;
    return g_tx_enabled_cache == 1;
}

void txindex_projection_enabled_reset_for_test(void)
{
    g_tx_enabled_cache = -1;
}

bool txindex_projection_ensure_schema(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("txindex", "ensure_schema: NULL db");
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS txindex ("
        "  txid       BLOB    NOT NULL,"
        "  height     INTEGER NOT NULL,"
        "  block_hash BLOB    NOT NULL,"
        "  tx_n       INTEGER NOT NULL,"
        "  PRIMARY KEY (txid)"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS txindex_height ON txindex(height);"
        "CREATE TABLE IF NOT EXISTS txindex_state ("
        "  k TEXT PRIMARY KEY,"
        "  v BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("txindex", "[txindex] schema ensure failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool txindex_projection_drop(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("txindex", "drop: NULL db");
    static const char *const sql =
        "DROP TABLE IF EXISTS txindex;"
        "DROP TABLE IF EXISTS txindex_state;";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("txindex", "[txindex] drop failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool txindex_projection_put_block(sqlite3 *db, const struct block *blk,
                                  int height, const uint8_t block_hash[32],
                                  uint8_t digest[32], int *rows_added_out)
{
    if (rows_added_out) *rows_added_out = 0;
    if (!db || !blk || !block_hash || !digest)
        LOG_FAIL("txindex", "put_block: NULL db/blk/block_hash/digest");

    /* One digest pass, chained from the prior running value: the fold is
     * ascending and single-pass, so a full rebuild reproduces this exact
     * chain — the projection's self-integrity anchor. Bind the block identity
     * (height + block_hash) before folding its transactions. */
    struct sha3_256_ctx dctx;
    sha3_256_init(&dctx);
    sha3_256_write(&dctx, digest, 32);
    uint8_t hb[4];
    ti_put_u32le(hb, (uint32_t)height);
    sha3_256_write(&dctx, hb, 4);
    sha3_256_write(&dctx, block_hash, 32);

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO txindex "
        "(txid, height, block_hash, tx_n) VALUES (?,?,?,?)",
        -1, &ins, NULL) != SQLITE_OK) {
        LOG_WARN("txindex", "[txindex] insert prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }

    bool ok = true;
    int added = 0;

    for (size_t ti = 0; ok && ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];

        /* digest tuple: txid(32) tx_n(4) */
        uint8_t nb[4];
        ti_put_u32le(nb, (uint32_t)ti);
        sha3_256_write(&dctx, tx->hash.data, 32);
        sha3_256_write(&dctx, nb, 4);

        sqlite3_reset(ins);
        sqlite3_bind_blob (ins, 1, tx->hash.data, 32, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 2, (sqlite3_int64)height);
        sqlite3_bind_blob (ins, 3, block_hash, 32, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 4, (sqlite3_int64)ti);
        int rc = sqlite3_step(ins);  // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_DONE) {
            LOG_WARN("txindex", "[txindex] insert h=%d tx=%zu rc=%d",
                     height, ti, rc);
            ok = false;
            break;
        }
        added += sqlite3_changes(db);
    }

    sqlite3_finalize(ins);
    if (!ok)
        return false;

    sha3_256_finalize(&dctx, digest);
    if (rows_added_out) *rows_added_out = added;
    return true;
}

bool txindex_projection_get_cursor(sqlite3 *db, int64_t *cursor_out)
{
    if (cursor_out) *cursor_out = -1;
    if (!db || !cursor_out)
        LOG_FAIL("txindex", "get_cursor: NULL db/out");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT v FROM txindex_state WHERE k='cursor'",
        -1, &st, NULL) != SQLITE_OK) {
        /* table may not exist yet — clean cursor=-1, not an error. */
        return true;
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n == 8) {
            int64_t v = 0;
            const uint8_t *p = b;
            for (int i = 0; i < 8; i++)
                v |= (int64_t)p[i] << (8 * i);
            *cursor_out = v;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("txindex", "[txindex] get_cursor step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

bool txindex_projection_set_cursor(sqlite3 *db, int64_t cursor,
                                   const uint8_t digest[32])
{
    if (!db || !digest)
        LOG_FAIL("txindex", "set_cursor: NULL db/digest");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO txindex_state(k,v) VALUES(?,?)",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("txindex", "[txindex] set_cursor prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    uint8_t cb[8];
    ti_put_u64le(cb, (uint64_t)cursor);
    bool ok = true;
    /* cursor row */
    sqlite3_reset(st);
    sqlite3_bind_text(st, 1, "cursor", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, cb, 8, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:progress-kv-kernel-store
        LOG_WARN("txindex", "[txindex] set cursor rc: %s",
                 sqlite3_errmsg(db));
        ok = false;
    }
    /* digest row */
    if (ok) {
        sqlite3_reset(st);
        sqlite3_bind_text(st, 1, "digest", -1, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, digest, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:progress-kv-kernel-store
            LOG_WARN("txindex", "[txindex] set digest rc: %s",
                     sqlite3_errmsg(db));
            ok = false;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

bool txindex_projection_get_digest(sqlite3 *db, uint8_t digest[32], bool *found)
{
    if (found) *found = false;
    if (digest) memset(digest, 0, 32);
    if (!db || !digest || !found)
        LOG_FAIL("txindex", "get_digest: NULL arg");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT v FROM txindex_state WHERE k='digest'",
        -1, &st, NULL) != SQLITE_OK) {
        return true; /* no table yet */
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n == 32) {
            memcpy(digest, b, 32);
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("txindex", "[txindex] get_digest step rc=%d", rc);
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

int64_t txindex_projection_row_count(sqlite3 *db)
{
    if (!db)
        LOG_RETURN(-1, "txindex", "row_count: NULL db");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM txindex",
                           -1, &st, NULL) != SQLITE_OK) {
        return 0; /* no table yet — not an error */
    }
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int txindex_projection_lookup(sqlite3 *db, const uint8_t txid[32],
                              int64_t *height_out, uint8_t block_hash_out[32],
                              int64_t *tx_n_out)
{
    if (height_out) *height_out = -1;
    if (tx_n_out) *tx_n_out = -1;
    if (block_hash_out) memset(block_hash_out, 0, 32);
    if (!db || !txid)
        LOG_RETURN(-1, "txindex", "lookup: NULL db/txid");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT height, block_hash, tx_n FROM txindex WHERE txid=?",
        -1, &st, NULL) != SQLITE_OK) {
        return 0; /* no table yet — a benign miss, not an error */
    }
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    int result;
    if (rc == SQLITE_ROW) {
        if (height_out) *height_out = sqlite3_column_int64(st, 0);
        const void *bh = sqlite3_column_blob(st, 1);
        int bh_n = sqlite3_column_bytes(st, 1);
        if (block_hash_out && bh && bh_n == 32)
            memcpy(block_hash_out, bh, 32);
        if (tx_n_out) *tx_n_out = sqlite3_column_int64(st, 2);
        result = 1;
    } else if (rc == SQLITE_DONE) {
        result = 0;
    } else {
        LOG_WARN("txindex", "[txindex] lookup step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        result = -1;
    }
    sqlite3_finalize(st);
    return result;
}
