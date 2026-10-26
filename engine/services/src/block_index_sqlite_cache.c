/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_cache (SQLite) save/load — split out of block_index_loader.c
 * for the E1 file-size ceiling. Owns save_block_index_recent() and
 * load_block_index_sqlite(), both declared in services/block_index_loader.h;
 * the flat-file and LevelDB loaders stay in block_index_loader.c.
 *
 * Integrity envelope: see services/block_index_cache_envelope.h. */

#include "services/block_index_loader.h"
#include "services/block_index_cache_envelope.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "core/uint256.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <string.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

/* ── save_block_index_recent ─────────────────────────────── */

/* Bind one row's columns (1-14) in INSERT order, then step the statement.
 * Returns SQLITE_DONE when the row was written, else the first failing
 * SQLite code; the caller logs and aborts the save. */
static int bind_and_step_block_index_cache_row(sqlite3_stmt *ins,
                                               const struct block_index *p,
                                               const unsigned char *prev)
{
    struct bind_col { int col; bool is_blob; int val; const void *blob; };
    const struct bind_col cols[] = {
        {1,  true,  0,                       p->phashBlock->data},
        {2,  true,  0,                       prev},
        {3,  false, p->nHeight,              NULL},
        {4,  false, (int)p->nBits,           NULL},
        {5,  false, (int)p->nTime,           NULL},
        {6,  false, p->nVersion,             NULL},
        {7,  false, (int)p->nStatus,         NULL},
        {8,  false, p->nFile,                NULL},
        {9,  false, (int)p->nDataPos,        NULL},
        {10, false, (int)p->nUndoPos,        NULL},
        {11, false, (int)p->nTx,             NULL},
        {12, true,  0,                       p->nChainWork.pn},
        {13, false, (int)p->nCachedBranchId, NULL},
        {14, false, (int)p->nChainTx,        NULL},
    };
    for (size_t i = 0; i < sizeof cols / sizeof cols[0]; i++) {
        const struct bind_col *c = &cols[i];
        int rc = c->is_blob
            ? sqlite3_bind_blob(ins, c->col, c->blob, 32, SQLITE_STATIC)
            : sqlite3_bind_int(ins, c->col, c->val);
        if (rc != SQLITE_OK)
            return rc;
    }
    return AR_STEP_WRITE(ins);
}

/* Single O(rows) pass: write every map_block_index entry through the
 * prepared INSERT, folding the integrity digest and rotating the
 * transaction every 50000 rows. Returns SQLITE_OK or the failing SQLite
 * code; *tx_open tracks the open transaction for the caller's rollback. */
static int write_block_index_cache_rows(struct node_db *ndb, struct main_state *ms,
                                        sqlite3_stmt *ins, size_t *count,
                                        uint8_t envelope_acc[32], bool *tx_open)
{
    static const unsigned char zero32[32] = {0};
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p || !p->phashBlock) continue;

        sqlite3_reset(ins);
        const unsigned char *prev = (p->pprev && p->pprev->phashBlock)
            ? p->pprev->phashBlock->data : zero32;
        int rc = bind_and_step_block_index_cache_row(ins, p, prev);
        if (rc != SQLITE_DONE)
            return rc;
        bic_row_digest_xor(envelope_acc, p, prev);  /* same O(rows) pass */
        (*count)++;

        if (*count % 50000 == 0) {
            rc = sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL);
            if (rc != SQLITE_OK)
                return rc;
            *tx_open = false;
            rc = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL);
            if (rc != SQLITE_OK)
                return rc;
            *tx_open = true;
        }
    }
    return SQLITE_OK;
}

/* Fail-path cleanup for save_block_index_recent(). */
static void abort_block_index_cache_save(sqlite3_stmt *ins, struct node_db *ndb,
                                         bool tx_open)
{
    if (ins)
        sqlite3_finalize(ins);
    if (tx_open)
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
}

void save_block_index_recent(struct node_db *ndb, struct main_state *ms)
{
    if (!ndb || !ndb->open) return;

    size_t total = ms->map_block_index.size;
    if (total == 0) return;

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    bool tx_open = false;
    int exec_rc = ar_exec_write_sql(ndb->db, "DELETE FROM block_index_cache");
    if (exec_rc != SQLITE_OK) {
        LOG_WARN("boot_index",
                 "boot-index: failed to clear block_index_cache: %s",
                 sqlite3_errmsg(ndb->db));
        return;
    }
    exec_rc = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL);
    if (exec_rc != SQLITE_OK) {
        LOG_WARN("boot_index",
                 "boot-index: failed to begin block_index_cache save: %s",
                 sqlite3_errmsg(ndb->db));
        return;
    }
    tx_open = true;

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO block_index_cache "
        "(hash,prev_hash,height,n_bits,n_time,n_version,n_status,"
        "n_file,n_data_pos,n_undo_pos,n_tx,chain_work,"
        "n_cached_branch_id,n_chain_tx) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1, &ins, NULL) != SQLITE_OK || !ins) {
        LOG_WARN("boot_index",
                 "boot-index: failed to prepare block_index_cache insert: %s",
                 sqlite3_errmsg(ndb->db));
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
        return;
    }

    uint8_t envelope_acc[32] = {0};
    size_t count = 0;
    if (write_block_index_cache_rows(ndb, ms, ins, &count, envelope_acc,
                                     &tx_open) != SQLITE_OK)
        goto fail;
    sqlite3_finalize(ins);
    ins = NULL;
    if (sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN("boot_index",
                 "boot-index: failed to commit block_index_cache save: %s",
                 sqlite3_errmsg(ndb->db));
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
        return;
    }

    bic_write_envelope(ndb, (int64_t)count, envelope_acc);  /* best-effort */
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("boot_index",
             "Block index: cached %zu/%zu entries in SQLite (%llds)",
             count, total, (long long)elapsed);
    return;

fail:
    LOG_WARN("chain", "boot-index: block_index_cache save aborted: %s", sqlite3_errmsg(ndb->db));
    abort_block_index_cache_save(ins, ndb, tx_open);
}

/* ── load_block_index_sqlite ─────────────────────────────── */

/* Cached row count used for the too-small refusal in load_block_index_sqlite. */
static int64_t read_block_index_cache_count(sqlite3 *db)
{
    int64_t cached_count = 0;
    sqlite3_stmt *cnt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM block_index_cache", -1, &cnt, NULL) == SQLITE_OK && cnt) {
        if (AR_STEP_ROW_READONLY(cnt) == SQLITE_ROW)
            cached_count = sqlite3_column_int64(cnt, 0);
        sqlite3_finalize(cnt);
    }
    return cached_count;
}

/* Fill one loaded entry's fields from the SELECT row and fold the row into
 * the computed digest. */
static void populate_block_index_from_cache_row(sqlite3_stmt *sel,
                                                struct block_index *pindex,
                                                uint8_t computed_acc[32])
{
    static const unsigned char zero32[32] = {0};

    pindex->nHeight         = sqlite3_column_int(sel, 2);
    pindex->nBits           = (uint32_t)sqlite3_column_int(sel, 3);
    pindex->nTime           = (uint32_t)sqlite3_column_int(sel, 4);
    pindex->nVersion        = sqlite3_column_int(sel, 5);
    pindex->nStatus         = (uint32_t)sqlite3_column_int(sel, 6);
    pindex->nFile           = sqlite3_column_int(sel, 7);
    pindex->nDataPos        = (uint32_t)sqlite3_column_int(sel, 8);
    pindex->nUndoPos        = (uint32_t)sqlite3_column_int(sel, 9);
    pindex->nTx             = (uint32_t)sqlite3_column_int(sel, 10);

    const void *cw = sqlite3_column_blob(sel, 11);
    if (cw && sqlite3_column_bytes(sel, 11) >= 32)
        memcpy(pindex->nChainWork.pn, cw, 32);

    pindex->nCachedBranchId = (uint32_t)sqlite3_column_int(sel, 12);
    pindex->nChainTx        = (uint32_t)sqlite3_column_int(sel, 13);
    const void *pvb = sqlite3_column_blob(sel, 1);  /* fold, same O(rows) pass */
    bic_row_digest_xor(computed_acc, pindex, (pvb && sqlite3_column_bytes(sel, 1) >= 32)
                       ? (const unsigned char *)pvb : zero32);
}

/* Single O(rows) load pass: insert each cached entry, fold the digest,
 * then run the persisted-FAILED trust reconcile. */
static void load_block_index_cache_rows(sqlite3_stmt *sel, struct main_state *ms,
                                        int32_t ckpt_h, uint8_t computed_acc[32],
                                        size_t *loaded, int64_t *stripped_failed,
                                        int64_t *demoted_failed)
{
    while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
        const void *hash_blob = sqlite3_column_blob(sel, 0);
        if (!hash_blob || sqlite3_column_bytes(sel, 0) < 32) continue;

        struct uint256 hash;
        memcpy(hash.data, hash_blob, 32);
        struct block_index *pindex = chainstate_insert_block_index(
            (struct chainstate *)ms, &hash);
        if (!pindex) continue;

        populate_block_index_from_cache_row(sel, pindex, computed_acc);

        /* Same persisted-FAILED trust reconcile as the flat loader: strip
         * below the ROM checkpoint, demote to a revalidation candidate above
         * it (a stale FAILED bit can no longer wedge the tip). Runs AFTER the
         * digest fold above so the envelope validates the bytes actually
         * stored on disk, not this load's post-reconcile in-memory state. */
        switch (block_index_apply_persisted_failure_trust(pindex, ckpt_h)) {
            case BLOCK_FAILURE_TRUST_STRIPPED: (*stripped_failed)++; break;
            case BLOCK_FAILURE_TRUST_DEMOTED:  (*demoted_failed)++;  break;
            case BLOCK_FAILURE_TRUST_NONE:     break;
        }
        (*loaded)++;
    }
}

/* Second pass over the cache: set each entry's pprev from prev_hash. */
static void link_block_index_pprev_from_cache(sqlite3 *db, struct main_state *ms)
{
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hash,prev_hash FROM block_index_cache "
            "WHERE prev_hash != X'0000000000000000000000000000000000000000000000000000000000000000'",
            -1, &sel, NULL) == SQLITE_OK && sel) {
        while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
            const void *h = sqlite3_column_blob(sel, 0);
            const void *ph = sqlite3_column_blob(sel, 1);
            if (!h || !ph) continue;
            if (sqlite3_column_bytes(sel, 0) < 32 ||
                sqlite3_column_bytes(sel, 1) < 32) continue;

            struct uint256 hash, prev;
            memcpy(hash.data, h, 32);
            memcpy(prev.data, ph, 32);

            struct block_index *pindex = block_map_find(&ms->map_block_index, &hash);
            struct block_index *pprev = block_map_find(&ms->map_block_index, &prev);
            if (pindex && pprev)
                pindex->pprev = pprev;
        }
        sqlite3_finalize(sel);
    }
}

struct zcl_result load_block_index_sqlite(struct node_db *ndb, struct main_state *ms)
{
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "load_block_index_sqlite: called with null or closed db");

    int64_t cached_count = read_block_index_cache_count(ndb->db);
    if (cached_count < 1000)
        return ZCL_ERR(-2, "load_block_index_sqlite: SQLite "
                       "block_index_cache too small: %lld entries",
                       (long long)cached_count);

    bool envelope_present = false; int64_t envelope_row_count = 0; uint8_t envelope_digest[32];
    bic_read_envelope(ndb, &envelope_present, &envelope_row_count, envelope_digest);
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    LOG_INFO("block_index",
             "Loading block index from SQLite (%lld entries)...",
             (long long)cached_count);

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT hash,prev_hash,height,n_bits,n_time,n_version,n_status,"
            "n_file,n_data_pos,n_undo_pos,n_tx,chain_work,"
            "n_cached_branch_id,n_chain_tx "
            "FROM block_index_cache ORDER BY height",
            -1, &sel, NULL) != SQLITE_OK || !sel)
        return ZCL_ERR(-3, "load_block_index_sqlite: failed to prepare SQLite SELECT for block_index_cache");

    /* Persisted-FAILED trust boundary: the baked ROM checkpoint height. */
    int32_t ckpt_h = get_rom_state_checkpoint()->height;
    int64_t stripped_failed = 0, demoted_failed = 0;
    uint8_t computed_acc[32] = {0};
    size_t loaded = 0;
    load_block_index_cache_rows(sel, ms, ckpt_h, computed_acc, &loaded,
                                &stripped_failed, &demoted_failed);
    sqlite3_finalize(sel);
    if (stripped_failed || demoted_failed)
        LOG_INFO("block_index",
                 "load_block_index_sqlite: persisted-FAILED trust reconcile: "
                 "%lld stripped (<=ckpt h=%d), %lld demoted to revalidation "
                 "candidates (>ckpt)",
                 (long long)stripped_failed, ckpt_h, (long long)demoted_failed);
    if (!bic_verify_or_demote(ndb, ms, envelope_present, envelope_row_count,
                              envelope_digest, (int64_t)loaded, computed_acc))
        return ZCL_ERR(-5, "load_block_index_sqlite: integrity envelope "
                       "mismatch — cache demoted, %lld rows discarded",
                       (long long)cached_count);

    /* Link pprev pointers after every cached index entry is loaded. */
    link_block_index_pprev_from_cache(ndb->db, ms);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index",
             "Block index SQLite: loaded %zu entries in %llds",
             loaded, (long long)elapsed);

    if (loaded == 0)
        return ZCL_ERR(-4, "load_block_index_sqlite: 0 rows loaded from "
                       "%lld cached entries", (long long)cached_count);
    return ZCL_OK;
}
