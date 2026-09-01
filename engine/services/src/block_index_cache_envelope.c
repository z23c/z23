// one-result-type-ok:pure-policy-helpers-no-error-to-propagate
/* Every failure here (prepare/step/decode) is ALREADY handled in place — a
 * write failure falls back to "no envelope next boot" (logged, not fatal);
 * a read failure is treated as "absent" (falls back to the pre-existing
 * COUNT-only trust); a verify mismatch calls bic_demote(), which itself
 * raises the typed blocker. There is no caller-actionable error left to
 * carry in a struct zcl_result — same rationale as sapling_checkpoint_hook.c
 * and anchor_selfmint. */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_cache integrity envelope — implementation.
 * See services/block_index_cache_envelope.h for the contract. */

#include "services/block_index_cache_envelope.h"

#include "crypto/sha3.h"
#include "models/database.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Canonical, fixed-width, no-padding layout the digest is computed over. */
struct __attribute__((packed)) bic_row_canon {
    uint8_t  hash[32];
    uint8_t  prev_hash[32];
    int32_t  height;
    uint32_t n_bits;
    uint32_t n_time;
    int32_t  n_version;
    uint32_t n_status;
    int32_t  n_file;
    uint32_t n_data_pos;
    uint32_t n_undo_pos;
    uint32_t n_tx;
    uint8_t  chain_work[32];
    uint32_t n_cached_branch_id;
    uint32_t n_chain_tx;
};
_Static_assert(sizeof(struct bic_row_canon) == 140,
               "bic_row_canon must stay a packed, fixed-width layout — "
               "changing it changes every future envelope digest");

void bic_row_digest_xor(uint8_t acc[32], const struct block_index *p,
                        const uint8_t prev_hash[32])
{
    struct bic_row_canon row;
    memset(&row, 0, sizeof(row));
    memcpy(row.hash, p->phashBlock->data, 32);
    memcpy(row.prev_hash, prev_hash, 32);
    row.height = p->nHeight;
    row.n_bits = p->nBits;
    row.n_time = p->nTime;
    row.n_version = p->nVersion;
    row.n_status = p->nStatus;
    row.n_file = p->nFile;
    row.n_data_pos = p->nDataPos;
    row.n_undo_pos = p->nUndoPos;
    row.n_tx = p->nTx;
    memcpy(row.chain_work, p->nChainWork.pn, 32);
    row.n_cached_branch_id = (uint32_t)p->nCachedBranchId;
    row.n_chain_tx = p->nChainTx;

    uint8_t digest[32];
    sha3_256((const unsigned char *)&row, sizeof(row), digest);
    for (int i = 0; i < 32; i++)
        acc[i] ^= digest[i];
}

void bic_write_envelope(struct node_db *ndb, int64_t row_count,
                        const uint8_t digest[32])
{
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO block_index_cache_envelope "
            "(envelope_id,row_count,content_sha3,written_at) "
            "VALUES (1,?,?,strftime('%s','now'))",
            -1, &ins, NULL) != SQLITE_OK || !ins) {
        LOG_WARN("boot_index",
                 "boot-index: envelope insert prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
        return;
    }
    if (sqlite3_bind_int64(ins, 1, row_count) != SQLITE_OK ||
        sqlite3_bind_blob(ins, 2, digest, 32, SQLITE_STATIC) != SQLITE_OK ||
        AR_STEP_WRITE(ins) != SQLITE_DONE)
        LOG_WARN("boot_index",
                 "boot-index: envelope insert failed: %s",
                 sqlite3_errmsg(ndb->db));
    sqlite3_finalize(ins);
}

void bic_read_envelope(struct node_db *ndb, bool *present,
                       int64_t *row_count, uint8_t digest[32])
{
    *present = false;
    *row_count = 0;
    memset(digest, 0, 32);
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT row_count,content_sha3 FROM block_index_cache_envelope "
            "WHERE envelope_id=1", -1, &sel, NULL) != SQLITE_OK || !sel)
        return;
    if (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
        int64_t rc = sqlite3_column_int64(sel, 0);
        const void *d = sqlite3_column_blob(sel, 1);
        if (d && sqlite3_column_bytes(sel, 1) == 32) {
            *row_count = rc;
            memcpy(digest, d, 32);
            *present = true;
        }
    }
    sqlite3_finalize(sel);
}

static _Atomic uint64_t g_bic_envelope_demotions = 0;

void bic_demote(struct node_db *ndb, int64_t row_count,
                int64_t computed_count, const uint8_t stored[32],
                const uint8_t computed[32])
{
    atomic_fetch_add(&g_bic_envelope_demotions, 1);
    char stored_hex[65], computed_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(stored_hex + 2 * i, 3, "%02x", stored[i]);
        snprintf(computed_hex + 2 * i, 3, "%02x", computed[i]);
    }
    LOG_WARN("boot_index",
             "block_index_cache: integrity envelope MISMATCH "
             "(row_count stored=%lld computed=%lld, digest stored=%s "
             "computed=%s) — demoting: discarding the SQLite cache so the "
             "next loader rung re-derives it",
             (long long)row_count, (long long)computed_count,
             stored_hex, computed_hex);

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "block_index_cache integrity envelope mismatch "
             "(row_count stored=%lld computed=%lld) — cache discarded, "
             "re-derived from the next loader rung; self-clears on the "
             "next clean save",
             (long long)row_count, (long long)computed_count);
    struct blocker_record rec;
    if (blocker_init(&rec, "block_index_cache.integrity_demoted",
                     "block_index_loader", BLOCKER_TRANSIENT, reason))
        blocker_set(&rec);

    if (ndb && ndb->open) {
        if (ar_exec_write_sql(ndb->db, "DELETE FROM block_index_cache") !=
            SQLITE_OK)
            LOG_WARN("boot_index",
                     "block_index_cache: demotion DELETE failed: %s",
                     sqlite3_errmsg(ndb->db));
        if (ar_exec_write_sql(ndb->db,
                "DELETE FROM block_index_cache_envelope") != SQLITE_OK)
            LOG_WARN("boot_index",
                     "block_index_cache_envelope: demotion DELETE failed: %s",
                     sqlite3_errmsg(ndb->db));
    }
}

uint64_t block_index_cache_envelope_demotions_for_testing(void)
{
    return atomic_load(&g_bic_envelope_demotions);
}

bool bic_verify_or_demote(struct node_db *ndb, struct main_state *ms,
                          bool envelope_present, int64_t envelope_row_count,
                          const uint8_t envelope_digest[32],
                          int64_t computed_row_count,
                          const uint8_t computed_digest[32])
{
    if (!envelope_present ||
        (envelope_row_count == computed_row_count &&
         memcmp(envelope_digest, computed_digest, 32) == 0)) {
        /* A clean (or not-yet-enveloped) load clears any earlier demotion —
         * self-terminating, same discipline as every typed blocker here. */
        blocker_clear("block_index_cache.integrity_demoted");
        return true;
    }

    bic_demote(ndb, envelope_row_count, computed_row_count, envelope_digest,
              computed_digest);
    if (ms) {
        block_map_free(&ms->map_block_index);
        block_map_init(&ms->map_block_index);
    }
    return false;
}
