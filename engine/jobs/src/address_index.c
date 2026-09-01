/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * address_index — script-appearance projection. See jobs/address_index.h for
 * the design rationale. Raw SQLite over the shared progress.kv kernel store,
 * mirroring created_outputs_index.c's prepare / bind / step / finalize idiom
 * (loud on error). The caller owns progress_store_tx_lock serialization. */

#include "jobs/address_index.h"

#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "util/util.h"

#include <sqlite3.h>
#include <string.h>

/* ── little-endian scalar writers for the deterministic digest ────── */
static void ai_put_u32le(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}
static void ai_put_u64le(uint8_t b[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

/* Cached -addressindex decision (file-scope so a test can reset it). -1 =
 * unknown. */
static int g_ai_enabled_cache = -1;

bool address_index_enabled(void)
{
    /* Args are parsed once at startup; cache the decision.
     * OMNISCIENCE default (owner directive: "the node obsesses about knowing
     * everything about the ZClassic network"): ON by default so a plain boot
     * builds the script-appearance catalog. Opt OUT with -addressindex=0. The
     * backfill is a bounded, supervised, disk-pre-checked, tip-yielding
     * background job (address_index_service.c) — it never wedges tip-follow. */
    if (g_ai_enabled_cache < 0)
        g_ai_enabled_cache = GetBoolArg("-addressindex", true) ? 1 : 0;
    return g_ai_enabled_cache == 1;
}

void address_index_enabled_reset_for_test(void)
{
    g_ai_enabled_cache = -1;
}

void address_index_scripthash(const uint8_t *script, size_t len,
                              uint8_t out[32])
{
    /* Total function: a NULL/empty script hashes the empty string, so every
     * output — including a zero-length scriptPubKey — maps to one key. */
    sha3_256(script ? script : (const uint8_t *)"", script ? len : 0, out);
}

bool address_index_ensure_schema(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("address_index", "ensure_schema: NULL db");
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS address_index ("
        "  scripthash    BLOB    NOT NULL,"
        "  txid          BLOB    NOT NULL,"
        "  vout          INTEGER NOT NULL,"
        "  height        INTEGER NOT NULL,"
        "  value         INTEGER NOT NULL,"
        "  script_type   INTEGER NOT NULL,"
        "  spent_by_txid BLOB,"
        "  spent_height  INTEGER,"
        "  PRIMARY KEY (scripthash, txid, vout)"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS address_index_outpoint "
        "  ON address_index(txid, vout);"
        "CREATE INDEX IF NOT EXISTS address_index_sh_height "
        "  ON address_index(scripthash, height);"
        "CREATE TABLE IF NOT EXISTS address_index_state ("
        "  k TEXT PRIMARY KEY,"
        "  v BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] schema ensure failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool address_index_drop(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("address_index", "drop: NULL db");
    static const char *const sql =
        "DROP TABLE IF EXISTS address_index;"
        "DROP TABLE IF EXISTS address_index_state;";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] drop failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool address_index_put_block(sqlite3 *db, const struct block *blk, int height,
                             uint8_t digest[32], int *rows_added_out)
{
    if (rows_added_out) *rows_added_out = 0;
    if (!db || !blk || !digest)
        LOG_FAIL("address_index", "put_block: NULL db/blk/digest");

    /* One digest pass, chained from the prior running value: the fold is
     * ascending and single-pass, so a full rebuild reproduces this exact
     * chain — the projection's self-integrity anchor. */
    struct sha3_256_ctx dctx;
    sha3_256_init(&dctx);
    sha3_256_write(&dctx, digest, 32);
    uint8_t hb[4];
    ai_put_u32le(hb, (uint32_t)height);
    sha3_256_write(&dctx, hb, 4);

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO address_index "
        "(scripthash, txid, vout, height, value, script_type) "
        "VALUES (?,?,?,?,?,?)",
        -1, &ins, NULL) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] insert prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_stmt *spend = NULL;
    if (sqlite3_prepare_v2(db,
        "UPDATE address_index SET spent_by_txid=?, spent_height=? "
        "WHERE txid=? AND vout=?",
        -1, &spend, NULL) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] spend prepare failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(ins);
        return false;
    }

    bool ok = true;
    int added = 0;

    /* Pass 1: create a row per output + fold it into the digest. */
    for (size_t ti = 0; ok && ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        for (size_t vo = 0; vo < tx->num_vout; vo++) {
            const struct tx_out *o = &tx->vout[vo];
            uint8_t sh[32];
            address_index_scripthash(o->script_pub_key.data,
                                     o->script_pub_key.size, sh);
            bool has_addr = false;
            uint8_t addr_hash[20];
            enum script_type stype = utxo_classify_script(
                o->script_pub_key.data, o->script_pub_key.size,
                addr_hash, &has_addr);

            /* digest tuple: sh(32) txid(32) vout(4) value(8) */
            uint8_t vb[4], valb[8];
            ai_put_u32le(vb, (uint32_t)vo);
            ai_put_u64le(valb, (uint64_t)o->value);
            sha3_256_write(&dctx, sh, 32);
            sha3_256_write(&dctx, tx->hash.data, 32);
            sha3_256_write(&dctx, vb, 4);
            sha3_256_write(&dctx, valb, 8);

            sqlite3_reset(ins);
            sqlite3_bind_blob (ins, 1, sh, 32, SQLITE_STATIC);
            sqlite3_bind_blob (ins, 2, tx->hash.data, 32, SQLITE_STATIC);
            sqlite3_bind_int64(ins, 3, (sqlite3_int64)vo);
            sqlite3_bind_int64(ins, 4, (sqlite3_int64)height);
            sqlite3_bind_int64(ins, 5, (sqlite3_int64)o->value);
            sqlite3_bind_int  (ins, 6, (int)stype);
            int rc = sqlite3_step(ins);  // raw-sql-ok:progress-kv-kernel-store
            if (rc != SQLITE_DONE) {
                LOG_WARN("address_index",
                         "[address_index] insert h=%d tx=%zu vout=%zu rc=%d",
                         height, ti, vo, rc);
                ok = false;
                break;
            }
            added += sqlite3_changes(db);
        }
    }

    /* Pass 2: mark spends. Coinbase inputs carry a null prevout — skip them.
     * A spend of a pre-index (below-cursor) output no-ops; that output simply
     * was never indexed, which is a coverage-floor truth, not an error. */
    for (size_t ti = 0; ok && ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        if (transaction_is_coinbase(tx))
            continue;
        for (size_t vi = 0; vi < tx->num_vin; vi++) {
            const struct outpoint *op = &tx->vin[vi].prevout;
            if (outpoint_is_null(op))
                continue;
            sqlite3_reset(spend);
            sqlite3_bind_blob (spend, 1, tx->hash.data, 32, SQLITE_STATIC);
            sqlite3_bind_int64(spend, 2, (sqlite3_int64)height);
            sqlite3_bind_blob (spend, 3, op->hash.data, 32, SQLITE_STATIC);
            sqlite3_bind_int64(spend, 4, (sqlite3_int64)op->n);
            int rc = sqlite3_step(spend);  // raw-sql-ok:progress-kv-kernel-store
            if (rc != SQLITE_DONE) {
                LOG_WARN("address_index",
                         "[address_index] spend h=%d tx=%zu vin=%zu rc=%d",
                         height, ti, vi, rc);
                ok = false;
                break;
            }
        }
    }

    sqlite3_finalize(ins);
    sqlite3_finalize(spend);
    if (!ok)
        return false;

    sha3_256_finalize(&dctx, digest);
    if (rows_added_out) *rows_added_out = added;
    return true;
}

bool address_index_get_cursor(sqlite3 *db, int64_t *cursor_out)
{
    if (cursor_out) *cursor_out = -1;
    if (!db || !cursor_out)
        LOG_FAIL("address_index", "get_cursor: NULL db/out");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT v FROM address_index_state WHERE k='cursor'",
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
        LOG_WARN("address_index", "[address_index] get_cursor step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

bool address_index_set_cursor(sqlite3 *db, int64_t cursor,
                              const uint8_t digest[32])
{
    if (!db || !digest)
        LOG_FAIL("address_index", "set_cursor: NULL db/digest");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO address_index_state(k,v) VALUES(?,?)",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] set_cursor prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    uint8_t cb[8];
    ai_put_u64le(cb, (uint64_t)cursor);
    bool ok = true;
    /* cursor row */
    sqlite3_reset(st);
    sqlite3_bind_text(st, 1, "cursor", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, cb, 8, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:progress-kv-kernel-store
        LOG_WARN("address_index", "[address_index] set cursor rc: %s",
                 sqlite3_errmsg(db));
        ok = false;
    }
    /* digest row */
    if (ok) {
        sqlite3_reset(st);
        sqlite3_bind_text(st, 1, "digest", -1, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, digest, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:progress-kv-kernel-store
            LOG_WARN("address_index", "[address_index] set digest rc: %s",
                     sqlite3_errmsg(db));
            ok = false;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

bool address_index_get_digest(sqlite3 *db, uint8_t digest[32], bool *found)
{
    if (found) *found = false;
    if (digest) memset(digest, 0, 32);
    if (!db || !digest || !found)
        LOG_FAIL("address_index", "get_digest: NULL arg");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT v FROM address_index_state WHERE k='digest'",
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
        LOG_WARN("address_index", "[address_index] get_digest step rc=%d", rc);
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

int64_t address_index_row_count(sqlite3 *db)
{
    if (!db)
        LOG_RETURN(-1, "address_index", "row_count: NULL db");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM address_index",
                           -1, &st, NULL) != SQLITE_OK) {
        return 0; /* no table yet — not an error */
    }
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int address_index_query_appearances(sqlite3 *db, const uint8_t scripthash[32],
                                    int64_t from_height, int limit,
                                    struct json_value *out_arr,
                                    int64_t *balance_out)
{
    if (balance_out) *balance_out = 0;
    if (!db || !scripthash || !out_arr)
        LOG_RETURN(-1, "address_index", "query_appearances: NULL arg");
    if (limit <= 0 || limit > ADDRESS_INDEX_QUERY_MAX_ROWS)
        limit = ADDRESS_INDEX_QUERY_MAX_ROWS;

    /* Confirmed unspent balance across ALL appearances (not just this page). */
    if (balance_out) {
        sqlite3_stmt *bs = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(SUM(value),0) FROM address_index "
            "WHERE scripthash=? AND spent_by_txid IS NULL",
            -1, &bs, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(bs, 1, scripthash, 32, SQLITE_STATIC);
            if (sqlite3_step(bs) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
                *balance_out = sqlite3_column_int64(bs, 0);
            sqlite3_finalize(bs);
        }
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT txid, vout, height, value, script_type, "
        "       spent_by_txid, spent_height "
        "FROM address_index "
        "WHERE scripthash=? AND height>=? "
        "ORDER BY height, txid, vout LIMIT ?",
        -1, &st, NULL) != SQLITE_OK) {
        return -1; // raw-return-ok:no-address-index-table-is-a-benign-empty-query
    }
    sqlite3_bind_blob (st, 1, scripthash, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)from_height);
    sqlite3_bind_int  (st, 3, limit);

    int appended = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const void *txid = sqlite3_column_blob(st, 0);
        int txid_n = sqlite3_column_bytes(st, 0);
        int64_t vout = sqlite3_column_int64(st, 1);
        int64_t h = sqlite3_column_int64(st, 2);
        int64_t val = sqlite3_column_int64(st, 3);
        int64_t stype = sqlite3_column_int64(st, 4);
        const void *sby = sqlite3_column_blob(st, 5);
        int sby_n = sqlite3_column_bytes(st, 5);
        bool spent = sby && sby_n == 32;

        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        char hex[65];
        if (txid && txid_n == 32) {
            HexStr(txid, 32, false, hex, sizeof(hex));
            json_push_kv_str(&row, "txid", hex);
        }
        json_push_kv_int(&row, "vout", vout);
        json_push_kv_int(&row, "height", h);
        json_push_kv_int(&row, "value", val);
        json_push_kv_int(&row, "script_type", stype);
        json_push_kv_bool(&row, "spent", spent);
        if (spent) {
            HexStr(sby, 32, false, hex, sizeof(hex));
            json_push_kv_str(&row, "spent_by_txid", hex);
            json_push_kv_int(&row, "spent_height",
                             sqlite3_column_int64(st, 6));
        }
        json_push_back(out_arr, &row);
        json_free(&row);
        appended++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        LOG_RETURN(-1, "address_index", "query step rc=%d: %s",
                   rc, sqlite3_errmsg(db));
    return appended;
}
