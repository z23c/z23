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

    static const unsigned char zero32[32] = {0};
    uint8_t envelope_acc[32] = {0};
    size_t iter = 0, count = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p || !p->phashBlock) continue;

        sqlite3_reset(ins);
        if (sqlite3_bind_blob(ins, 1, p->phashBlock->data, 32, SQLITE_STATIC) != SQLITE_OK)
            goto fail;
        const unsigned char *prev = (p->pprev && p->pprev->phashBlock)
            ? p->pprev->phashBlock->data : zero32;
        if (sqlite3_bind_blob(ins, 2, prev, 32, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int(ins, 3, p->nHeight) != SQLITE_OK ||
            sqlite3_bind_int(ins, 4, (int)p->nBits) != SQLITE_OK ||
            sqlite3_bind_int(ins, 5, (int)p->nTime) != SQLITE_OK ||
            sqlite3_bind_int(ins, 6, p->nVersion) != SQLITE_OK ||
            sqlite3_bind_int(ins, 7, (int)p->nStatus) != SQLITE_OK ||
            sqlite3_bind_int(ins, 8, p->nFile) != SQLITE_OK ||
            sqlite3_bind_int(ins, 9, (int)p->nDataPos) != SQLITE_OK ||
            sqlite3_bind_int(ins, 10, (int)p->nUndoPos) != SQLITE_OK ||
            sqlite3_bind_int(ins, 11, (int)p->nTx) != SQLITE_OK ||
            sqlite3_bind_blob(ins, 12, p->nChainWork.pn, 32, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int(ins, 13, (int)p->nCachedBranchId) != SQLITE_OK ||
            sqlite3_bind_int(ins, 14, (int)p->nChainTx) != SQLITE_OK ||
            AR_STEP_WRITE(ins) != SQLITE_DONE)
            goto fail;
        bic_row_digest_xor(envelope_acc, p, prev);  /* same O(rows) pass */
        count++;

        if (count % 50000 == 0) {
            if (sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
                goto fail;
            tx_open = false;
            if (sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
                goto fail;
            tx_open = true;
        }
    }
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
    if (ins)
        sqlite3_finalize(ins);
    if (tx_open)
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
}

/* ── load_block_index_sqlite ─────────────────────────────── */

struct zcl_result load_block_index_sqlite(struct node_db *ndb, struct main_state *ms)
{
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "load_block_index_sqlite: called with null or closed db");

    int64_t cached_count = 0;
    sqlite3_stmt *cnt = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM block_index_cache", -1, &cnt, NULL) == SQLITE_OK && cnt) {
        if (AR_STEP_ROW_READONLY(cnt) == SQLITE_ROW)
            cached_count = sqlite3_column_int64(cnt, 0);
        sqlite3_finalize(cnt);
    }
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
    static const unsigned char zero32[32] = {0}; uint8_t computed_acc[32] = {0};
    size_t loaded = 0;
    while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
        const void *hash_blob = sqlite3_column_blob(sel, 0);
        if (!hash_blob || sqlite3_column_bytes(sel, 0) < 32) continue;

        struct uint256 hash;
        memcpy(hash.data, hash_blob, 32);
        struct block_index *pindex = chainstate_insert_block_index(
            (struct chainstate *)ms, &hash);
        if (!pindex) continue;

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

        /* Same persisted-FAILED trust reconcile as the flat loader: strip
         * below the ROM checkpoint, demote to a revalidation candidate above
         * it (a stale FAILED bit can no longer wedge the tip). Runs AFTER the
         * digest fold above so the envelope validates the bytes actually
         * stored on disk, not this load's post-reconcile in-memory state. */
        switch (block_index_apply_persisted_failure_trust(pindex, ckpt_h)) {
            case BLOCK_FAILURE_TRUST_STRIPPED: stripped_failed++; break;
            case BLOCK_FAILURE_TRUST_DEMOTED:  demoted_failed++;  break;
            case BLOCK_FAILURE_TRUST_NONE:     break;
        }
        loaded++;
    }
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
    sel = NULL;
    if (sqlite3_prepare_v2(ndb->db,
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

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index",
             "Block index SQLite: loaded %zu entries in %llds",
             loaded, (long long)elapsed);

    if (loaded == 0)
        return ZCL_ERR(-4, "load_block_index_sqlite: 0 rows loaded from "
                       "%lld cached entries", (long long)cached_count);
    return ZCL_OK;
}
