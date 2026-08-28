/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Header-corpus digest for the producer receipt: recompute the genesis..H*
 * header chain digest from the producer's own progress.kv rows. Split from
 * consensus_state_producer_receipt.c along the file-size ceiling seam. */

#include "consensus_state_producer_receipt_internal.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <string.h>

static void proof_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t le[8];
    for (size_t i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, le, sizeof(le));
}

/* See the contract note in consensus_state_producer_receipt_internal.h: this
 * MUST stay byte-identical to prove_header_chain() in
 * consensus_state_snapshot_export_proof.c. */
bool producer_receipt_header_corpus_digest(sqlite3 *db, int32_t height,
                                           const uint8_t expected_hash[32],
                                           uint8_t out[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height,hash,parent_hash FROM header_admit_log "
            "WHERE height BETWEEN 0 AND ? ORDER BY height", -1, &st,
            NULL) != SQLITE_OK) {
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS, "header corpus prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char domain[] =
        "zcl.consensus_state_bundle.v1/source-header-chain";
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));

    uint8_t prior[32] = {0};
    int64_t expected_height = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int height_type = sqlite3_column_type(st, 0);
        int hash_type = sqlite3_column_type(st, 1);
        int parent_type = sqlite3_column_type(st, 2);
        const void *hash = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        const void *parent = parent_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 2) : NULL;
        int parent_len = parent ? sqlite3_column_bytes(st, 2) : 0;
        int64_t row_height = height_type == SQLITE_INTEGER
            ? sqlite3_column_int64(st, 0) : -1;
        bool genesis_parent = row_height == 0 && parent_type == SQLITE_NULL;
        bool linked_parent = row_height > 0 && parent_type == SQLITE_BLOB &&
                             parent && parent_len == 32 &&
                             memcmp(parent, prior, 32) == 0;
        if (height_type != SQLITE_INTEGER || hash_type != SQLITE_BLOB || !hash ||
            sqlite3_column_bytes(st, 1) != 32 ||
            row_height != expected_height ||
            (!genesis_parent && !linked_parent)) {
            ok = false;
            break;
        }
        proof_u64(&ctx, (uint64_t)row_height);
        sha3_256_write(&ctx, hash, 32);
        if (row_height > 0) {
            sha3_256_write(&ctx, parent, 32);
        } else {
            uint8_t no_parent[32] = {0};
            sha3_256_write(&ctx, no_parent, sizeof(no_parent));
        }
        memcpy(prior, hash, sizeof(prior));
        expected_height++;
    }
    if (rc != SQLITE_DONE || expected_height != (int64_t)height + 1 ||
        memcmp(prior, expected_hash, 32) != 0)
        ok = false;
    sqlite3_finalize(st);
    if (ok)
        sha3_256_finalize(&ctx, out);
    else
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS,
                 "genesis..h=%d header corpus incomplete or wrong tip", height);
    return ok;
}
