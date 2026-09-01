/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_header_solution — header-solution backfill (save / load /
 * availability). A header's Equihash nSolution can be recovered from the block
 * index even when the reducer logged a solutionless validate failure; this TU
 * owns the durable side-table (header_solution_repair) and the verified
 * round-trip used by the validate_headers stage and the stale-validate Condition
 * to re-supply a solution. Pure read/write of the backfill table — no rewinds,
 * no cursor mutation. */

#include "jobs/stage_repair.h"

#include "core/uint256.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool ensure_header_solution_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS header_solution_repair ("
        "  height INTEGER PRIMARY KEY,"
        "  hash BLOB NOT NULL,"
        "  version INTEGER NOT NULL,"
        "  prev_hash BLOB NOT NULL,"
        "  merkle_root BLOB NOT NULL,"
        "  final_sapling_root BLOB NOT NULL,"
        "  n_time INTEGER NOT NULL,"
        "  n_bits INTEGER NOT NULL,"
        "  nonce BLOB NOT NULL,"
        "  solution BLOB NOT NULL,"
        "  solution_len INTEGER NOT NULL,"
        "  saved_at INTEGER NOT NULL"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repair-header schema failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool stage_repair_header_solution_save(sqlite3 *db, int height,
                                       const struct uint256 *hash,
                                       const struct block_header *header)
{
    if (!db || height < 0 || !hash || !header ||
        header->nSolutionSize == 0 ||
        header->nSolutionSize > sizeof(header->nSolution))
        LOG_FAIL("stage_repair", "header solution save invalid args");

    struct uint256 computed;
    block_header_get_hash(header, &computed);
    if (!uint256_eq(&computed, hash)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repair-header hash mismatch h=%d", height);
        return false;
    }

    progress_store_tx_lock();
    if (!ensure_header_solution_schema(db)) {
        progress_store_tx_unlock();
        return false;
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_solution_repair "
            "(height,hash,version,prev_hash,merkle_root,final_sapling_root,"
            "n_time,n_bits,nonce,solution,solution_len,saved_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repair-header prepare failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, header->nVersion);
    sqlite3_bind_blob(st, 4, header->hashPrevBlock.data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 5, header->hashMerkleRoot.data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 6, header->hashFinalSaplingRoot.data, 32,
                      SQLITE_STATIC);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)header->nTime);
    sqlite3_bind_int64(st, 8, (sqlite3_int64)header->nBits);
    sqlite3_bind_blob(st, 9, header->nNonce.data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 10, header->nSolution,
                      (int)header->nSolutionSize, SQLITE_STATIC);
    sqlite3_bind_int64(st, 11, (sqlite3_int64)header->nSolutionSize);
    sqlite3_bind_int64(st, 12,
                       (sqlite3_int64)platform_time_wall_unix());
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repair-header step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

bool stage_repair_header_solution_load(sqlite3 *db, int height,
                                       const struct uint256 *expected_hash,
                                       struct block_header *out)
{
    if (!db || height < 0 || !out)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hash,version,prev_hash,merkle_root,final_sapling_root,"
            "n_time,n_bits,nonce,solution,solution_len "
            "FROM header_solution_repair WHERE height=?",
            -1, &st, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return false;
    }
    if (rc != SQLITE_ROW) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repair-header load step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }

    const void *hash_blob = sqlite3_column_blob(st, 0);
    const void *prev_blob = sqlite3_column_blob(st, 2);
    const void *merkle_blob = sqlite3_column_blob(st, 3);
    const void *sapling_blob = sqlite3_column_blob(st, 4);
    const void *nonce_blob = sqlite3_column_blob(st, 7);
    const void *solution_blob = sqlite3_column_blob(st, 8);
    int solution_bytes = sqlite3_column_bytes(st, 8);
    int64_t solution_len = sqlite3_column_int64(st, 9);
    if (!hash_blob || !prev_blob || !merkle_blob || !sapling_blob ||
        !nonce_blob || !solution_blob ||
        sqlite3_column_bytes(st, 0) != 32 ||
        sqlite3_column_bytes(st, 2) != 32 ||
        sqlite3_column_bytes(st, 3) != 32 ||
        sqlite3_column_bytes(st, 4) != 32 ||
        sqlite3_column_bytes(st, 7) != 32 ||
        solution_len <= 0 || solution_len > MAX_SOLUTION_SIZE ||
        solution_bytes != (int)solution_len) {
        sqlite3_finalize(st);
        return false;
    }

    struct uint256 stored_hash;
    memcpy(stored_hash.data, hash_blob, 32);
    if (expected_hash && !uint256_eq(&stored_hash, expected_hash)) {
        sqlite3_finalize(st);
        return false;
    }

    block_header_init(out);
    out->nVersion = sqlite3_column_int(st, 1);
    memcpy(out->hashPrevBlock.data, prev_blob, 32);
    memcpy(out->hashMerkleRoot.data, merkle_blob, 32);
    memcpy(out->hashFinalSaplingRoot.data, sapling_blob, 32);
    out->nTime = (uint32_t)sqlite3_column_int64(st, 5);
    out->nBits = (uint32_t)sqlite3_column_int64(st, 6);
    memcpy(out->nNonce.data, nonce_blob, 32);
    memcpy(out->nSolution, solution_blob, (size_t)solution_len);
    out->nSolutionSize = (size_t)solution_len;
    sqlite3_finalize(st);

    struct uint256 computed;
    block_header_get_hash(out, &computed);
    return uint256_eq(&computed, &stored_hash);
}

bool stage_repair_header_solution_available(sqlite3 *db, int height,
                                            const struct uint256 *expected_hash)
{
    if (!db || height < 0)
        return false;
    progress_store_tx_lock();
    bool ok = ensure_header_solution_schema(db) &&
              stage_repair_header_solution_load(db, height, expected_hash,
                                                &(struct block_header){0});
    progress_store_tx_unlock();
    return ok;
}
