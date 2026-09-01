/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: UTXO
 *
 * validates :txid, presence: true
 * validates :value, money_range: [0, MAX_MONEY]
 * validates :height, numericality: { >= 0 }
 * validates :script_type, inclusion: [P2PKH, P2SH, OP_RETURN, MULTISIG, OTHER]
 * validates :script_len, maximum: 10000
 *
 * belongs_to :transaction
 *
 * after_save -> emit EV_MODEL_SAVED */

#include "models/utxo.h"
#include "models/tx_index.h"
#include "util/log_macros.h"
#include "event/event.h"
#include "crypto/sha3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(utxo)

/* before_save: validate money range + script coherence */
static bool utxo_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_utxo *u = record;
    if (u->value < 0 || u->value > 2100000000000000LL) {
        LOG_FAIL("utxo", "before_save REJECTED: value %lld out of money range",
                 (long long)u->value);
    }
    if (u->height < 0) {
        LOG_FAIL("utxo", "before_save REJECTED: negative height %d", u->height);
    }
    if (u->script_len > 0 && !u->script) {
        LOG_FAIL("utxo", "before_save REJECTED: script_len=%zu but script is NULL",
                 u->script_len);
    }
    return true;
}

/* after_save: emit model-specific event */
static void utxo_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_utxo *u = record;
    event_emitf(EV_UTXO_SAVED, 0, "height=%d value=%lld",
                u->height, (long long)u->value);
}

static void utxo_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_utxo_callbacks();
    ar_register_before_save(cbs, utxo_before_save);
    ar_register_after_save(cbs, utxo_after_save);
    done = true;
}

/* SQLite interprets a NULL pointer passed to sqlite3_bind_blob() as SQL NULL,
 * even when the declared byte length is zero. Empty scriptPubKeys are valid
 * consensus data and the mirror schema correctly requires a BLOB, so preserve
 * that distinction at the model boundary for both lifecycle and bulk writes. */
static int utxo_bind_script(sqlite3_stmt *stmt, int pos,
                            const struct db_utxo *u)
{
    if (u->script_len == 0)
        return sqlite3_bind_zeroblob(stmt, pos, 0);
    return AR_BIND_BLOB(stmt, pos, u->script, u->script_len);
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_utxo_validate(const struct db_utxo *u, struct ar_errors *errors)
{
    ar_errors_clear(errors);

    validates_presence_of(errors, u, txid);
    validates_money_range(errors, u, value, 2100000000000000LL);
    validates_non_negative(errors, u, height);
    validates_max(errors, u, script_len, 10000);
    validates_custom(errors,
        !(u->script_len > 0 && !u->script),
        "script", "null pointer with nonzero length");

    static const enum script_type valid_types[] = {
        SCRIPT_P2PKH, SCRIPT_P2SH, SCRIPT_OP_RETURN,
        SCRIPT_MULTISIG, SCRIPT_OTHER
    };
    validates_inclusion_of(errors, u, script_type, valid_types, 5);

    /* Note: all-zeros address_hash with has_address=true is valid.
     * It represents coins sent to the Hash160(0x00...) burn address.
     * Rare (~7 UTXOs on mainnet) but must be accepted for SHA3 match. */

    return !ar_errors_any(errors);
}

/* ── Save ──────────────────────────────────────────────────────── */

bool db_utxo_save(struct node_db *ndb, const struct db_utxo *u)
{
    if (!ndb->open) return false;

    utxo_init_hooks();
    struct ar_callbacks *cbs = db_utxo_callbacks();
    AR_BEGIN_SAVE(cbs, "utxo", u, db_utxo_validate);

    sqlite3_stmt *s = ndb->stmt_utxo_insert;
    sqlite3_reset(s);
    AR_BIND_BLOB(s, 1, u->txid, 32);
    AR_BIND_INT(s, 2, (int)u->vout);
    AR_BIND_INT(s, 3, u->value);
    utxo_bind_script(s, 4, u);
    AR_BIND_INT(s, 5, (int)u->script_type);
    if (u->has_address)
        AR_BIND_BLOB(s, 6, u->address_hash, 20);
    else
        AR_BIND_NULL(s, 6);
    AR_BIND_INT(s, 7, u->height);
    AR_BIND_INT(s, 8, u->is_coinbase ? 1 : 0);

    bool ok = AR_STEP_DONE(s);
    /* Don't emit per-UTXO events during bulk import — db_utxo_insert_raw()
     * deliberately bypasses this model lifecycle. */
    AR_FINISH_SAVE(cbs, u, ok);
}

/* ── Bulk Import (fast path) ───────────────────────────────────── */

bool db_utxo_insert_raw(struct node_db *ndb, const struct db_utxo *u)
{
    sqlite3_stmt *s = ndb->stmt_utxo_insert;
    sqlite3_reset(s);
    AR_BIND_BLOB(s, 1, u->txid, 32);
    AR_BIND_INT(s, 2, (int)u->vout);
    AR_BIND_INT(s, 3, u->value);
    utxo_bind_script(s, 4, u);
    AR_BIND_INT(s, 5, (int)u->script_type);
    if (u->has_address)
        AR_BIND_BLOB(s, 6, u->address_hash, 20);
    else
        AR_BIND_NULL(s, 6);
    AR_BIND_INT(s, 7, u->height);
    AR_BIND_INT(s, 8, u->is_coinbase ? 1 : 0);
    return AR_STEP_DONE(s);
}

/* ── Find ──────────────────────────────────────────────────────── */

bool db_utxo_find(struct node_db *ndb, const uint8_t txid[32], uint32_t vout,
                  struct db_utxo *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = ndb->stmt_utxo_find;
    sqlite3_reset(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vout);
    if (!AR_STEP_ROW(s)) return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, txid, 32);
    out->vout = vout;
    out->value = AR_COL_INT(s, 0);
    out->script_len = (size_t)AR_COL_BYTES(s, 1);
    const void *sc = sqlite3_column_blob(s, 1);
    if (sc && out->script_len > 0) {
        out->script = zcl_malloc(out->script_len, "utxo find script");
        if (out->script)
            memcpy(out->script, sc, out->script_len);
    } else {
        out->script = NULL;
    }
    out->script_type = (enum script_type)AR_COL_INT(s, 2);
    const void *ah = sqlite3_column_blob(s, 3);
    if (ah && AR_COL_BYTES(s, 3) >= 20) {
        memcpy(out->address_hash, ah, 20);
        out->has_address = true;
    }
    out->height = (int)AR_COL_INT(s, 4);
    out->is_coinbase = AR_COL_INT(s, 5) != 0;
    return true;
}

bool db_utxo_exists(struct node_db *ndb, const uint8_t txid[32], uint32_t vout)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = ndb->stmt_utxo_find;
    sqlite3_reset(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vout);
    bool found = AR_STEP_ROW(s);
    sqlite3_reset(s);
    return found;
}

/* ── Delete ────────────────────────────────────────────────────── */

bool db_utxo_delete(struct node_db *ndb, const uint8_t txid[32], uint32_t vout)
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_utxo_callbacks();
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid, 32);
    u.vout = vout;
    sqlite3_stmt *s = ndb->stmt_utxo_delete;
    AR_CACHED_DESTROY(s, cbs, &u,
        AR_BIND_BLOB(s, 1, txid, 32);
        AR_BIND_INT(s, 2, (int)vout));
}

/* ── Queries ───────────────────────────────────────────────────── */

int64_t db_utxo_balance_for_address(struct node_db *ndb,
                                     const uint8_t address_hash[20])
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM utxos WHERE address_hash=?",
        AR_BIND_BLOB(s, 1, address_hash, 20));
}

int db_utxo_list_for_address(struct node_db *ndb,
                             const uint8_t address_hash[20],
                             struct db_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,vout,value,script_type,height,is_coinbase"
        " FROM utxos WHERE address_hash=? ORDER BY height",
        out, max,
        AR_BIND_BLOB(s, 1, address_hash, 20),
        AR_READ_BLOB(s, 0, out[count].txid, 32);
        out[count].vout = (uint32_t)AR_COL_INT(s, 1);
        out[count].value = AR_COL_INT(s, 2);
        out[count].script_type = (enum script_type)AR_COL_INT(s, 3);
        memcpy(out[count].address_hash, address_hash, 20);
        out[count].has_address = true;
        out[count].height = (int)AR_COL_INT(s, 4);
        out[count].is_coinbase = AR_COL_INT(s, 5) != 0);
}

/* Two probes, cheapest first. Contract (and the "false means not found
 * here" warning) is on the declaration in models/utxo.h. A missing or
 * unprepared table makes AR_QUERY_INT64_BOUND yield 0, i.e. "no history" —
 * the safe direction: the gap scan's floor still derives the standard
 * lookahead, it just cannot extend past it. */
static int64_t utxo_addr_probe(struct node_db *ndb, const char *sql,
                               const uint8_t address_hash[20])
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, sql,
        AR_BIND_BLOB(s, 1, address_hash, 20));
}

bool db_address_has_chain_history(struct node_db *ndb,
                                  const uint8_t address_hash[20])
{
    if (!ndb || !ndb->open || !address_hash)
        return false;
    if (utxo_addr_probe(ndb,
            "SELECT 1 FROM utxos WHERE address_hash=? LIMIT 1",
            address_hash) != 0)
        return true;
    return utxo_addr_probe(ndb,
            "SELECT 1 FROM tx_outputs WHERE address_hash=? LIMIT 1",
            address_hash) != 0;
}

static int64_t utxo_any_row(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, sql, (void)0);
}

bool db_address_index_populated(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return false;
    if (utxo_any_row(ndb,
            "SELECT 1 FROM utxos WHERE address_hash IS NOT NULL LIMIT 1") != 0)
        return true;
    return utxo_any_row(ndb,
            "SELECT 1 FROM tx_outputs WHERE address_hash IS NOT NULL LIMIT 1")
           != 0;
}

int64_t db_utxo_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, "SELECT COUNT(*) FROM utxos", (void)0);
}

/* Highest height present in the UTXO set, or -1 if the db is closed.
 * Mirrors db_block_max_height() (block model): MAX(height) yields NULL on an
 * empty table, which AR_COL_INT reads as 0 — the "no utxos written yet" floor.
 * The utxos table has no status column, so there is no status>=3 filter.
 * Single source of truth for "SELECT MAX(height) FROM utxos" (Law 8). */
int db_utxo_max_height(struct node_db *ndb)
{
    if (!ndb->open) return -1;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT MAX(height) FROM utxos",
        -1);
    int h = -1;
    if (AR_STEP_ROW(s))
        h = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return h;
}

int64_t db_utxo_total_value(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "utxo", "total_value: db unavailable");
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM utxos",
        (void)0);
}

bool db_utxo_count_rows_and_distinct_txids(struct node_db *ndb,
                                           int64_t *rows_out,
                                           int64_t *distinct_txids_out)
{
    if (!ndb || !ndb->open || !rows_out || !distinct_txids_out)
        LOG_FAIL("utxo", "count_rows_and_distinct_txids: invalid args");

    sqlite3_stmt *s = NULL;
    AR_PREPARE_OR(ndb, s,
        "SELECT COUNT(DISTINCT txid), COUNT(*) FROM utxos",
        LOG_FAIL("utxo", "count_rows_and_distinct_txids: prepare failed: %s",
                 sqlite3_errmsg(ndb->db)));

    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        LOG_FAIL("utxo", "count_rows_and_distinct_txids: query returned no row");
    }

    *distinct_txids_out = AR_COL_INT(s, 0);
    *rows_out = AR_COL_INT(s, 1);
    AR_FINALIZE(s);
    return true;
}

int64_t db_utxo_count_missing_heights(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "utxo", "count_missing_heights: db unavailable");
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM utxos WHERE height = 0 AND value > 0",
        (void)0);
}

int db_utxo_repair_missing_heights_from_tx_index(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_ERR("utxo", "repair_missing_heights: db unavailable");
    if (!node_db_exec(ndb,
            "UPDATE utxos SET height = ("
            "  SELECT t.block_height FROM transactions t"
            "  WHERE t.txid = utxos.txid"
            ") WHERE height = 0 AND EXISTS ("
            "  SELECT 1 FROM transactions t"
            "  WHERE t.txid = utxos.txid AND t.block_height IS NOT NULL"
            ")")) {
        LOG_ERR("utxo", "repair_missing_heights: update failed");
    }
    return sqlite3_changes(ndb->db);
}

bool db_utxo_rebuild_wallet_and_address_caches_in_txn(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("utxo", "rebuild_wallet_and_address_caches: db unavailable");

    bool ok = true;
    ok = ok && node_db_exec(ndb, "DELETE FROM wallet_utxos");
    ok = ok && node_db_exec(ndb,
        "INSERT INTO wallet_utxos "
        "(txid, vout, value, address_hash, script, height, is_coinbase) "
        "SELECT u.txid, u.vout, u.value, u.address_hash, u.script, "
        "u.height, u.is_coinbase "
        "FROM utxos u INNER JOIN wallet_keys wk "
        "ON u.address_hash = wk.pubkey_hash");
    ok = ok && node_db_exec(ndb, "DELETE FROM addresses");
    ok = ok && node_db_exec(ndb,
        "INSERT OR REPLACE INTO addresses "
        "(address_hash, script_type, balance, utxo_count, "
        "first_seen_height, last_seen_height) "
        "SELECT address_hash, MAX(script_type), SUM(value), count(*), "
        "MIN(height), MAX(height) "
        "FROM utxos WHERE address_hash IS NOT NULL "
        "GROUP BY address_hash");

    if (!ok)
        LOG_FAIL("utxo",
                 "rebuild_wallet_and_address_caches: refresh statements failed");

    return true;
}

bool db_utxo_rebuild_wallet_and_address_caches(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("utxo", "rebuild_wallet_and_address_caches: db unavailable");

    if (!node_db_begin(ndb))
        LOG_FAIL("utxo", "rebuild_wallet_and_address_caches: begin failed");

    if (!db_utxo_rebuild_wallet_and_address_caches_in_txn(ndb)) {
        (void)node_db_rollback(ndb);
        return false;
    }

    if (!node_db_commit(ndb))
        LOG_FAIL("utxo", "rebuild_wallet_and_address_caches: commit failed");

    return true;
}

/* Run one address-parameterized DML statement (a single 20-byte address_hash
 * bound at position 1), inside the caller's already-open transaction. Prepared
 * ad hoc: the delta path touches only a handful of addresses per pass, so the
 * prepare cost is negligible and no cached statement is warranted. */
static bool addr_refresh_exec(struct node_db *ndb, const char *sql,
                              const uint8_t address_hash[20])
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s, sql);   /* fprintf + return false on prepare fail */
    AR_BIND_BLOB(s, 1, address_hash, 20);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_FAIL("utxo", "refresh_caches_for_address: step failed: %s",
                 sqlite3_errmsg(ndb->db));
    return true;
}

bool db_utxo_refresh_caches_for_address(struct node_db *ndb,
                                        const uint8_t address_hash[20])
{
    if (!ndb || !ndb->open)
        LOG_FAIL("utxo", "refresh_caches_for_address: db unavailable");
    if (!address_hash)
        LOG_FAIL("utxo", "refresh_caches_for_address: null address_hash");

    /* Re-derive BOTH read models for this one address from the authoritative
     * `utxos` table. Delete-then-insert keeps them exactly consistent with the
     * source set: an address whose last UTXO was just spent ends with no row,
     * and there is no +/- arithmetic to drift. The addresses aggregate mirrors
     * db_utxo_rebuild_wallet_and_address_caches exactly (MAX(script_type),
     * SUM(value), COUNT(*), MIN/MAX(height)); wallet_utxos is filtered to the
     * operator's own keys. Caller holds the node.db write transaction. */
    if (!addr_refresh_exec(ndb,
            "DELETE FROM addresses WHERE address_hash=?1", address_hash))
        return false;
    if (!addr_refresh_exec(ndb,
            "INSERT INTO addresses"
            " (address_hash,script_type,balance,utxo_count,"
            "  first_seen_height,last_seen_height)"
            " SELECT address_hash, MAX(script_type), SUM(value), COUNT(*),"
            "        MIN(height), MAX(height)"
            " FROM utxos WHERE address_hash=?1 GROUP BY address_hash",
            address_hash))
        return false;
    if (!addr_refresh_exec(ndb,
            "DELETE FROM wallet_utxos WHERE address_hash=?1", address_hash))
        return false;
    if (!addr_refresh_exec(ndb,
            "INSERT INTO wallet_utxos"
            " (txid,vout,value,address_hash,script,height,is_coinbase)"
            " SELECT u.txid,u.vout,u.value,u.address_hash,u.script,"
            "        u.height,u.is_coinbase"
            " FROM utxos u JOIN wallet_keys wk"
            "   ON u.address_hash=wk.pubkey_hash"
            " WHERE u.address_hash=?1",
            address_hash))
        return false;
    return true;
}

void db_utxo_free(struct db_utxo *u)
{
    if (!u) return;
    free(u->script);
    u->script = NULL;
    u->script_len = 0;
}

/* ── Iteration ─────────────────────────────────────────────────── */

int64_t db_utxo_each(struct node_db *ndb, db_utxo_each_fn fn, void *ctx)
{
    if (!ndb || !ndb->open || !fn) return 0;

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT txid, vout, value, script, height, is_coinbase, "
        "script_type, address_hash FROM utxos ORDER BY txid, vout",
        0);

    int64_t count = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
        struct db_utxo u;
        memset(&u, 0, sizeof(u));

        const void *txid = sqlite3_column_blob(s, 0);
        if (!txid || sqlite3_column_bytes(s, 0) < 32) continue;
        memcpy(u.txid, txid, 32);

        u.vout = (uint32_t)sqlite3_column_int(s, 1);
        u.value = sqlite3_column_int64(s, 2);

        u.script = (uint8_t *)sqlite3_column_blob(s, 3);
        u.script_len = (size_t)sqlite3_column_bytes(s, 3);

        u.height = sqlite3_column_int(s, 4);
        u.is_coinbase = sqlite3_column_int(s, 5) != 0;
        u.script_type = (enum script_type)sqlite3_column_int(s, 6);

        const void *ah = sqlite3_column_blob(s, 7);
        if (ah && sqlite3_column_bytes(s, 7) >= 20) {
            memcpy(u.address_hash, ah, 20);
            u.has_address = true;
        }

        count++;
        if (!fn(&u, ctx)) break;
    }
    AR_FINALIZE(s);
    return count;
}

/* ── Snapshot Serialization ────────────────────────────────────── */

struct snapshot_writer {
    FILE *fp;
    uint32_t chunk_size;
    uint32_t entries_in_chunk;
    long chunk_start_pos;      /* file offset of current chunk's entry_count */
    int64_t total_written;
    struct sha3_256_ctx *sha3; /* optional SHA3 context for commitment */
};

static void snap_flush_chunk_header(struct snapshot_writer *w)
{
    if (w->entries_in_chunk == 0) return;
    /* Seek back and patch the entry count at chunk start */
    long cur = ftell(w->fp);
    fseek(w->fp, w->chunk_start_pos, SEEK_SET);
    uint8_t hdr[4] = {
        (uint8_t)(w->entries_in_chunk & 0xFF),
        (uint8_t)((w->entries_in_chunk >> 8) & 0xFF),
        (uint8_t)((w->entries_in_chunk >> 16) & 0xFF),
        (uint8_t)((w->entries_in_chunk >> 24) & 0xFF)
    };
    fwrite(hdr, 1, 4, w->fp);
    fseek(w->fp, cur, SEEK_SET);
}

static void snap_begin_chunk(struct snapshot_writer *w)
{
    w->chunk_start_pos = ftell(w->fp);
    uint8_t placeholder[4] = {0};
    fwrite(placeholder, 1, 4, w->fp);
    w->entries_in_chunk = 0;
}

static bool snap_write_utxo(const struct db_utxo *u, void *ctx)
{
    struct snapshot_writer *w = ctx;

    /* Start a new chunk if needed */
    if (w->entries_in_chunk == 0 && w->chunk_start_pos < 0) {
        snap_begin_chunk(w);
    }

    /* Feed to SHA3 commitment (must match utxo_commitment_sha3_compute format):
     * txid(32) || vout_le(4) || value_le(8) || script_len_le(4) || script ||
     * height_le(4) || is_coinbase(1) */
    if (w->sha3) {
        sha3_256_write(w->sha3, u->txid, 32);
        uint8_t le4[4];
        le4[0] = (uint8_t)(u->vout); le4[1] = (uint8_t)(u->vout >> 8);
        le4[2] = (uint8_t)(u->vout >> 16); le4[3] = (uint8_t)(u->vout >> 24);
        sha3_256_write(w->sha3, le4, 4);
        uint8_t le8[8];
        uint64_t v = (uint64_t)u->value;
        for (int i = 0; i < 8; i++) le8[i] = (uint8_t)(v >> (8 * i));
        sha3_256_write(w->sha3, le8, 8);
        uint32_t slen32 = (uint32_t)u->script_len;
        le4[0] = (uint8_t)(slen32); le4[1] = (uint8_t)(slen32 >> 8);
        le4[2] = (uint8_t)(slen32 >> 16); le4[3] = (uint8_t)(slen32 >> 24);
        sha3_256_write(w->sha3, le4, 4);
        if (u->script && u->script_len > 0)
            sha3_256_write(w->sha3, u->script, u->script_len);
        uint32_t ht = (uint32_t)u->height;
        le4[0] = (uint8_t)(ht); le4[1] = (uint8_t)(ht >> 8);
        le4[2] = (uint8_t)(ht >> 16); le4[3] = (uint8_t)(ht >> 24);
        sha3_256_write(w->sha3, le4, 4);
        uint8_t cb = u->is_coinbase ? 1 : 0;
        sha3_256_write(w->sha3, &cb, 1);
    }

    /* Write entry: txid(32) + vout(4) + value(8) + height(4) + compact + script */
    fwrite(u->txid, 1, 32, w->fp);

    uint8_t buf[16];
    buf[0] = (uint8_t)(u->vout & 0xFF);
    buf[1] = (uint8_t)((u->vout >> 8) & 0xFF);
    buf[2] = (uint8_t)((u->vout >> 16) & 0xFF);
    buf[3] = (uint8_t)((u->vout >> 24) & 0xFF);
    fwrite(buf, 1, 4, w->fp);

    uint64_t v = (uint64_t)u->value;
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
    fwrite(buf, 1, 8, w->fp);

    uint32_t h = (uint32_t)u->height;
    buf[0] = (uint8_t)(h & 0xFF);
    buf[1] = (uint8_t)((h >> 8) & 0xFF);
    buf[2] = (uint8_t)((h >> 16) & 0xFF);
    buf[3] = (uint8_t)((h >> 24) & 0xFF);
    fwrite(buf, 1, 4, w->fp);

    /* is_coinbase (1 byte) — needed for SHA3 match */
    uint8_t cb = u->is_coinbase ? 1 : 0;
    fwrite(&cb, 1, 1, w->fp);

    /* Compact size for script length */
    size_t slen = u->script_len;
    if (slen > 520) slen = 520;
    if (slen < 253) {
        uint8_t b = (uint8_t)slen;
        fwrite(&b, 1, 1, w->fp);
    } else {
        uint8_t b = 253;
        fwrite(&b, 1, 1, w->fp);
        buf[0] = (uint8_t)(slen & 0xFF);
        buf[1] = (uint8_t)((slen >> 8) & 0xFF);
        fwrite(buf, 1, 2, w->fp);
    }
    if (u->script && slen > 0)
        fwrite(u->script, 1, slen, w->fp);

    w->entries_in_chunk++;
    w->total_written++;

    if (w->entries_in_chunk >= w->chunk_size) {
        snap_flush_chunk_header(w);
        snap_begin_chunk(w);
    }
    return true;
}

int64_t db_utxo_serialize_snapshot(struct node_db *ndb,
                                    const char *path, uint32_t chunk_size,
                                    uint8_t sha3_out[32])
{
    if (!ndb || !ndb->open || !path) return -1;
    if (chunk_size == 0) chunk_size = 500;

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    struct sha3_256_ctx sha3_ctx;
    struct sha3_256_ctx *sha3_ptr = NULL;
    if (sha3_out) {
        sha3_256_init(&sha3_ctx);
        sha3_ptr = &sha3_ctx;
    }

    struct snapshot_writer w = {
        .fp = fp,
        .chunk_size = chunk_size,
        .entries_in_chunk = 0,
        .chunk_start_pos = -1,
        .total_written = 0,
        .sha3 = sha3_ptr
    };

    snap_begin_chunk(&w);
    db_utxo_each(ndb, snap_write_utxo, &w);

    /* Flush final partial chunk */
    if (w.entries_in_chunk > 0)
        snap_flush_chunk_header(&w);

    fclose(fp);

    if (sha3_out)
        sha3_256_finalize(&sha3_ctx, sha3_out);

    return w.total_written;
}

/* ── Relationships ─────────────────────────────────────────────── */

/* belongs_to :transaction */
bool db_utxo_transaction(struct node_db *ndb, const struct db_utxo *u,
                         struct db_tx_index *out)
{
    return db_tx_find(ndb, u->txid, out);
}
