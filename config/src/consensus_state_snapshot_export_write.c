/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Strict SQLite bundle writer for the full-history exporter. */

#include "consensus_state_snapshot_export_internal.h"

#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "script/script.h"
#include "storage/anchor_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

#define EXPORT_WRITE_SUBSYS "consensus_bundle_export"

static const char k_bundle_schema_sql[] =
    "CREATE TABLE bundle_meta("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "schema TEXT NOT NULL,height INTEGER NOT NULL,block_hash BLOB NOT NULL,"
    "history_complete INTEGER NOT NULL,source_clean INTEGER NOT NULL,"
    "validation_profile INTEGER NOT NULL,"
    "activation_boundary INTEGER NOT NULL,"
    "utxo_root BLOB NOT NULL,utxo_count INTEGER NOT NULL,"
    "total_supply INTEGER NOT NULL,anchor_digest BLOB NOT NULL,"
    "anchor_count INTEGER NOT NULL,sprout_frontier_root BLOB NOT NULL,"
    "sprout_frontier_height INTEGER NOT NULL,"
    "sapling_frontier_root BLOB NOT NULL,"
    "sapling_frontier_height INTEGER NOT NULL,"
    "nullifier_digest BLOB NOT NULL,nullifier_count INTEGER NOT NULL,"
    "sprout_source_cursor INTEGER NOT NULL,"
    "sapling_source_cursor INTEGER NOT NULL,"
    "nullifier_source_cursor INTEGER NOT NULL,"
    "source_fold_cursor INTEGER NOT NULL,"
    "proof_manifest_digest BLOB NOT NULL,source_digest BLOB NOT NULL,"
    "artifact_digest BLOB NOT NULL);"
    "CREATE TABLE source_receipt("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,"
    "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
    "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
    "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
    "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
    "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
    "receipt_digest BLOB NOT NULL);"
    "CREATE TABLE bundle_proof("
    "ordinal INTEGER PRIMARY KEY,component TEXT NOT NULL UNIQUE,"
    "cursor INTEGER NOT NULL,first_height INTEGER NOT NULL,"
    "last_height INTEGER NOT NULL,row_count INTEGER NOT NULL,"
    "hash_bound_count INTEGER NOT NULL,component_digest BLOB NOT NULL);"
    "CREATE TABLE coins("
    "txid BLOB NOT NULL,vout INTEGER NOT NULL,value INTEGER NOT NULL,"
    "script BLOB NOT NULL,height INTEGER NOT NULL,is_coinbase INTEGER NOT NULL,"
    "PRIMARY KEY(txid,vout)) WITHOUT ROWID;"
    "CREATE TABLE anchors("
    "pool INTEGER NOT NULL CHECK(pool IN(0,1)),anchor BLOB NOT NULL,"
    "height INTEGER NOT NULL,tree BLOB NOT NULL,"
    "PRIMARY KEY(pool,anchor),UNIQUE(pool,height)) WITHOUT ROWID;"
    "CREATE TABLE nullifiers("
    "pool INTEGER NOT NULL CHECK(pool IN(0,1)),nf BLOB NOT NULL,"
    "height INTEGER NOT NULL,PRIMARY KEY(pool,nf)) WITHOUT ROWID;";

static const char k_proof_parent_schema_sql[] =
    "CREATE TABLE proof_parent("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "base_height INTEGER NOT NULL CHECK(base_height>=0),"
    "base_block_hash BLOB NOT NULL CHECK(length(base_block_hash)=32),"
    "validation_profile INTEGER NOT NULL CHECK(validation_profile IN(1,2)),"
    "proof_manifest_digest BLOB NOT NULL "
        "CHECK(length(proof_manifest_digest)=32),"
    "source_digest BLOB NOT NULL CHECK(length(source_digest)=32),"
    "artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32));"
    "CREATE TABLE proof_parent_component("
    "ordinal INTEGER PRIMARY KEY CHECK(ordinal>=0 AND ordinal<8),"
    "component TEXT NOT NULL UNIQUE,cursor INTEGER NOT NULL,"
    "first_height INTEGER NOT NULL,last_height INTEGER NOT NULL,"
    "row_count INTEGER NOT NULL,hash_bound_count INTEGER NOT NULL,"
    "component_digest BLOB NOT NULL CHECK(length(component_digest)=32),"
    "suffix_digest BLOB NOT NULL CHECK(length(suffix_digest)=32));";

static bool prepare_pair(sqlite3 *source, const char *select_sql,
                         sqlite3 *destination, const char *insert_sql,
                         sqlite3_stmt **read, sqlite3_stmt **write)
{
    *read = NULL;
    *write = NULL;
    if (sqlite3_prepare_v2(source, select_sql, -1, read, NULL) != SQLITE_OK) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "source prepare failed: %s",
                 sqlite3_errmsg(source));
        return false;
    }
    if (sqlite3_prepare_v2(destination, insert_sql, -1, write, NULL) !=
        SQLITE_OK) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "destination prepare failed: %s",
                 sqlite3_errmsg(destination));
        sqlite3_finalize(*read);
        *read = NULL;
        return false;
    }
    return true;
}

static bool bind_blob(sqlite3_stmt *st, int column, const void *blob, int len)
{
    if (len == 0)
        return sqlite3_bind_zeroblob(st, column, 0) == SQLITE_OK;
    return blob && sqlite3_bind_blob(st, column, blob, len,
                                     SQLITE_TRANSIENT) == SQLITE_OK;
}

static bool step_insert(sqlite3_stmt *st)
{
    int rc = sqlite3_step(st); // raw-sql-ok:consensus-bundle-artifact
    bool ok = rc == SQLITE_DONE;
    if (ok)
        ok = sqlite3_reset(st) == SQLITE_OK &&
             sqlite3_clear_bindings(st) == SQLITE_OK;
    return ok;
}

static bool column_int64_exact(sqlite3_stmt *st, int column, int64_t *out)
{
    if (sqlite3_column_type(st, column) != SQLITE_INTEGER)
        return false;
    *out = sqlite3_column_int64(st, column);
    return true;
}

static bool copy_coins(sqlite3 *source, sqlite3 *destination,
                       struct consensus_state_bundle_manifest *manifest)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit("copy_coins start height=%d",
                                   manifest->height);
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    if (!prepare_pair(source,
            "SELECT txid,vout,value,script,height,is_coinbase "
            "FROM coins ORDER BY txid,vout", destination,
            "INSERT INTO coins(txid,vout,value,script,height,is_coinbase) "
            "VALUES(?,?,?,?,?,?)", &read, &write))
        return false;
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int txid_type = sqlite3_column_type(read, 0);
        int script_type = sqlite3_column_type(read, 3);
        const void *txid = txid_type == SQLITE_BLOB
            ? sqlite3_column_blob(read, 0) : NULL;
        const void *script = script_type == SQLITE_BLOB
            ? sqlite3_column_blob(read, 3) : NULL;
        int script_len = script ? sqlite3_column_bytes(read, 3) : 0;
        int64_t vout = -1, value = -1, height = -1, coinbase = -1;
        bool numeric = column_int64_exact(read, 1, &vout) &&
                       column_int64_exact(read, 2, &value) &&
                       column_int64_exact(read, 4, &height) &&
                       column_int64_exact(read, 5, &coinbase);
        if (txid_type != SQLITE_BLOB || !txid ||
            sqlite3_column_bytes(read, 0) != 32 ||
            !numeric || vout < 0 || vout > UINT32_MAX ||
            !MoneyRange(value) || supply > MAX_MONEY - value ||
            script_type != SQLITE_BLOB || script_len < 0 ||
            script_len > MAX_SCRIPT_SIZE ||
            height < 0 || height > manifest->height ||
            (coinbase != 0 && coinbase != 1) || count == UINT64_MAX) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(
            &digest, txid, (uint32_t)vout, value,
            script_len ? script : NULL, (uint32_t)script_len,
            (uint32_t)height, (uint8_t)coinbase);
        supply += value;
        count++;
        ok = sqlite3_bind_blob(write, 1, txid, 32, SQLITE_TRANSIENT) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(write, 2, vout) == SQLITE_OK &&
             sqlite3_bind_int64(write, 3, value) == SQLITE_OK &&
             bind_blob(write, 4, script, script_len) &&
             sqlite3_bind_int64(write, 5, height) == SQLITE_OK &&
             sqlite3_bind_int(write, 6, coinbase) == SQLITE_OK &&
             step_insert(write);
        if (!ok)
            break;
        if (count % 500000 == 0)
            consensus_export_progress_emit(
                "copy_coins: %llu rows, %llds elapsed",
                (unsigned long long)count,
                (long long)((consensus_export_clock_ms() - t0) / 1000));
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(read);
    sqlite3_finalize(write);
    consensus_export_progress_emit(
        "copy_coins done rows=%llu ok=%d elapsed=%lldms",
        (unsigned long long)count, (ok && count != 0) ? 1 : 0,
        (long long)(consensus_export_clock_ms() - t0));
    if (!ok || count == 0)
        return false;
    sha3_256_finalize(&digest, manifest->utxo_root);
    manifest->utxo_count = count;
    manifest->total_supply = supply;
    return true;
}

static bool copy_anchors(sqlite3 *source, sqlite3 *destination,
                         struct consensus_state_bundle_manifest *manifest)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit("copy_anchors start height=%d",
                                   manifest->height);
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    if (!prepare_pair(source,
            "SELECT pool,anchor,height,tree FROM ("
            "SELECT 0 AS pool,anchor,height,tree FROM sprout_anchors "
            "UNION ALL "
            "SELECT 1 AS pool,anchor,height,tree FROM sapling_anchors) "
            "ORDER BY pool,anchor", destination,
            "INSERT INTO anchors(pool,anchor,height,tree) VALUES(?,?,?,?)",
            &read, &write))
        return false;
    struct sha3_256_ctx digest;
    consensus_state_bundle_anchor_digest_begin(&digest);
    int64_t frontier_height[2] = {-1, -1};
    uint8_t frontier_root[2][32] = {{0}, {0}};
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int root_type = sqlite3_column_type(read, 1);
        int tree_type = sqlite3_column_type(read, 3);
        const void *root = root_type == SQLITE_BLOB
            ? sqlite3_column_blob(read, 1) : NULL;
        int64_t pool = -1, height = -1;
        bool numeric = column_int64_exact(read, 0, &pool) &&
                       column_int64_exact(read, 2, &height);
        const void *tree = tree_type == SQLITE_BLOB
            ? sqlite3_column_blob(read, 3) : NULL;
        int tree_len = tree ? sqlite3_column_bytes(read, 3) : 0;
        if (!numeric ||
            (pool != ANCHOR_POOL_SPROUT && pool != ANCHOR_POOL_SAPLING) ||
            root_type != SQLITE_BLOB || !root ||
            sqlite3_column_bytes(read, 1) != 32 ||
            height < 0 || height > manifest->height ||
            tree_type != SQLITE_BLOB || !tree ||
            tree_len <= 0 || count == UINT64_MAX) {
            ok = false;
            break;
        }
        int pool_index = (int)pool;
        if (height == frontier_height[pool_index]) {
            ok = false;
            break;
        }
        if (height > frontier_height[pool_index]) {
            frontier_height[pool_index] = height;
            memcpy(frontier_root[pool_index], root, 32);
        }
        consensus_state_bundle_anchor_digest_row(
            &digest, (uint8_t)pool, root, (uint64_t)height, tree,
            (uint32_t)tree_len);
        count++;
        ok = sqlite3_bind_int(write, 1, pool) == SQLITE_OK &&
             sqlite3_bind_blob(write, 2, root, 32, SQLITE_TRANSIENT) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(write, 3, height) == SQLITE_OK &&
             sqlite3_bind_blob(write, 4, tree, tree_len, SQLITE_TRANSIENT) ==
                 SQLITE_OK &&
             step_insert(write);
        if (!ok)
            break;
        if (count % 500000 == 0)
            consensus_export_progress_emit(
                "copy_anchors: %llu rows, %llds elapsed",
                (unsigned long long)count,
                (long long)((consensus_export_clock_ms() - t0) / 1000));
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(read);
    sqlite3_finalize(write);
    bool anchors_ok = ok && frontier_height[ANCHOR_POOL_SPROUT] >= 0 &&
                      frontier_height[ANCHOR_POOL_SAPLING] >= 0;
    consensus_export_progress_emit(
        "copy_anchors done rows=%llu ok=%d elapsed=%lldms",
        (unsigned long long)count, anchors_ok ? 1 : 0,
        (long long)(consensus_export_clock_ms() - t0));
    if (!anchors_ok)
        return false;
    sha3_256_finalize(&digest, manifest->anchor_digest);
    manifest->anchor_count = count;
    manifest->sprout_frontier_height =
        frontier_height[ANCHOR_POOL_SPROUT];
    manifest->sapling_frontier_height =
        frontier_height[ANCHOR_POOL_SAPLING];
    memcpy(manifest->sprout_frontier_root,
           frontier_root[ANCHOR_POOL_SPROUT], 32);
    memcpy(manifest->sapling_frontier_root,
           frontier_root[ANCHOR_POOL_SAPLING], 32);
    return true;
}

static bool copy_nullifiers(sqlite3 *source, sqlite3 *destination,
                            struct consensus_state_bundle_manifest *manifest)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit("copy_nullifiers start height=%d",
                                   manifest->height);
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    if (!prepare_pair(source,
            "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf",
            destination,
            "INSERT INTO nullifiers(pool,nf,height) VALUES(?,?,?)",
            &read, &write))
        return false;
    struct sha3_256_ctx digest;
    consensus_state_bundle_nullifier_digest_begin(&digest);
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int nf_type = sqlite3_column_type(read, 1);
        const void *nf = nf_type == SQLITE_BLOB
            ? sqlite3_column_blob(read, 1) : NULL;
        int64_t pool = -1, height = -1;
        bool numeric = column_int64_exact(read, 0, &pool) &&
                       column_int64_exact(read, 2, &height);
        if (!numeric ||
            (pool != 0 && pool != 1) ||
            nf_type != SQLITE_BLOB || !nf ||
            sqlite3_column_bytes(read, 1) != 32 ||
            height < 0 || height > manifest->height || count == UINT64_MAX) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(
            &digest, (uint8_t)pool, nf, (uint64_t)height);
        count++;
        ok = sqlite3_bind_int(write, 1, pool) == SQLITE_OK &&
             sqlite3_bind_blob(write, 2, nf, 32, SQLITE_TRANSIENT) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(write, 3, height) == SQLITE_OK &&
             step_insert(write);
        if (!ok)
            break;
        if (count % 500000 == 0)
            consensus_export_progress_emit(
                "copy_nullifiers: %llu rows, %llds elapsed",
                (unsigned long long)count,
                (long long)((consensus_export_clock_ms() - t0) / 1000));
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(read);
    sqlite3_finalize(write);
    consensus_export_progress_emit(
        "copy_nullifiers done rows=%llu ok=%d elapsed=%lldms",
        (unsigned long long)count, ok ? 1 : 0,
        (long long)(consensus_export_clock_ms() - t0));
    if (!ok)
        return false;
    sha3_256_finalize(&digest, manifest->nullifier_digest);
    manifest->nullifier_count = count;
    return true;
}

static bool write_manifest(sqlite3 *db,
                           struct consensus_state_bundle_manifest *m)
{
    consensus_state_bundle_artifact_digest(m, m->artifact_digest);
    static const char sql[] =
        "INSERT INTO bundle_meta("
        "singleton,schema,height,block_hash,history_complete,source_clean,"
        "validation_profile,"
        "activation_boundary,utxo_root,utxo_count,total_supply,anchor_digest,"
        "anchor_count,sprout_frontier_root,sprout_frontier_height,"
        "sapling_frontier_root,sapling_frontier_height,nullifier_digest,"
        "nullifier_count,sprout_source_cursor,sapling_source_cursor,"
        "nullifier_source_cursor,source_fold_cursor,proof_manifest_digest,"
        "source_digest,artifact_digest) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
        "?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int i = 1;
    bool ok = sqlite3_bind_text(st, i++, CONSENSUS_STATE_BUNDLE_SCHEMA, -1,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, m->height) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->block_hash, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, m->history_complete ? 1 : 0) ==
                  SQLITE_OK &&
              sqlite3_bind_int(st, i++, m->source_clean ? 1 : 0) ==
                  SQLITE_OK &&
              sqlite3_bind_int(st, i++, m->validation_profile) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->activation_boundary) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->utxo_root, 32, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, (sqlite3_int64)m->utxo_count) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->total_supply) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->anchor_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, (sqlite3_int64)m->anchor_count) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->sprout_frontier_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->sprout_frontier_height) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->sapling_frontier_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->sapling_frontier_height) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->nullifier_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, (sqlite3_int64)m->nullifier_count) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->sprout_source_cursor) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->sapling_source_cursor) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->nullifier_source_cursor) ==
                  SQLITE_OK &&
              sqlite3_bind_int64(st, i++, m->source_fold_cursor) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->proof_manifest_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->source_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, m->artifact_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK;
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:consensus-bundle-artifact
    sqlite3_finalize(st);
    return ok;
}

static bool write_source_receipt(
    sqlite3 *db, const struct consensus_state_source_receipt *receipt)
{
    const char *schema =
        consensus_state_source_receipt_schema(receipt->schema_version);
    size_t commit_len = strnlen(receipt->producer_commit,
                                sizeof(receipt->producer_commit));
    if (!schema ||
        !consensus_state_source_receipt_commit_valid(
            receipt->schema_version, receipt->producer_commit, commit_len))
        return false;
    static const char sql[] =
        "INSERT INTO source_receipt("
        "singleton,schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int i = 1;
    bool ok = sqlite3_bind_text(st, i++, schema, -1, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->source_epoch_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->source_tree_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->running_binary_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->toolchain_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->build_inputs_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->chain_corpus_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, receipt->source_clean ? 1 : 0) ==
                  SQLITE_OK &&
              sqlite3_bind_int(st, i++, receipt->validation_profile) ==
                  SQLITE_OK &&
              sqlite3_bind_text(st, i++, receipt->producer_commit,
                                (int)commit_len,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, receipt->fold_cursor) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt->receipt_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:consensus-bundle-artifact
    sqlite3_finalize(st);
    return ok;
}

static bool write_proof_summaries(
    sqlite3 *db,
    const struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT])
{
    static const char sql[] =
        "INSERT INTO bundle_proof(ordinal,component,cursor,first_height,"
        "last_height,row_count,hash_bound_count,component_digest) "
        "VALUES(?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t row = 0; row < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; row++) {
        ok = sqlite3_bind_int(st, 1, (int)row) == SQLITE_OK &&
             sqlite3_bind_text(st, 2, proofs[row].component, -1,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_int64(st, 3, (sqlite3_int64)proofs[row].cursor) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 4, proofs[row].first_height) == SQLITE_OK &&
             sqlite3_bind_int64(st, 5, proofs[row].last_height) == SQLITE_OK &&
             sqlite3_bind_int64(st, 6,
                                (sqlite3_int64)proofs[row].row_count) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 7,
                                (sqlite3_int64)proofs[row].hash_bound_count) ==
                 SQLITE_OK &&
             sqlite3_bind_blob(st, 8, proofs[row].component_digest, 32,
                               SQLITE_STATIC) == SQLITE_OK &&
             step_insert(st);
        if (!ok)
            break;
    }
    sqlite3_finalize(st);
    return ok;
}

static bool write_proof_parent(
    sqlite3 *db, const struct consensus_state_bundle_proof_parent *parent)
{
    if (!parent || !parent->present)
        return true;
    if (sqlite3_exec(db, k_proof_parent_schema_sql, NULL, NULL, NULL) !=
        SQLITE_OK)
        return false;
    static const char base_sql[] =
        "INSERT INTO proof_parent("
        "singleton,base_height,base_block_hash,validation_profile,"
        "proof_manifest_digest,source_digest,artifact_digest) "
        "VALUES(1,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, base_sql, -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_int(st, 1, parent->base_height) == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, parent->base_block_hash, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, 3, parent->validation_profile) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, 4, parent->proof_manifest_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, 5, parent->source_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, 6, parent->artifact_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:consensus-bundle-artifact
    if (st)
        sqlite3_finalize(st);

    static const char component_sql[] =
        "INSERT INTO proof_parent_component("
        "ordinal,component,cursor,first_height,last_height,row_count,"
        "hash_bound_count,component_digest,suffix_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?)";
    st = NULL;
    if (ok)
        ok = sqlite3_prepare_v2(db, component_sql, -1, &st, NULL) ==
             SQLITE_OK;
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        const struct consensus_state_bundle_proof_summary *component =
            &parent->components[i];
        ok = sqlite3_bind_int(st, 1, (int)i) == SQLITE_OK &&
             sqlite3_bind_text(st, 2, component->component, -1,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_int64(st, 3, (sqlite3_int64)component->cursor) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 4, component->first_height) == SQLITE_OK &&
             sqlite3_bind_int64(st, 5, component->last_height) == SQLITE_OK &&
             sqlite3_bind_int64(st, 6,
                                (sqlite3_int64)component->row_count) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(
                 st, 7, (sqlite3_int64)component->hash_bound_count) ==
                 SQLITE_OK &&
             sqlite3_bind_blob(st, 8, component->component_digest, 32,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_blob(st, 9, parent->suffix_digest[i], 32,
                               SQLITE_STATIC) == SQLITE_OK &&
             step_insert(st);
    }
    if (st)
        sqlite3_finalize(st);
    return ok;
}

static bool compiled_checkpoint_matches(
    const struct consensus_state_bundle_manifest *manifest)
{
    const struct sha3_utxo_checkpoint *checkpoint =
        get_sha3_utxo_checkpoint();
    if (!checkpoint || checkpoint->height != manifest->height)
        return true;
    return memcmp(checkpoint->block_hash, manifest->block_hash, 32) == 0 &&
           memcmp(checkpoint->sha3_hash, manifest->utxo_root, 32) == 0 &&
           checkpoint->utxo_count == manifest->utxo_count &&
           checkpoint->total_supply == manifest->total_supply;
}

bool consensus_export_write_bundle(
    sqlite3 *source, sqlite3 *destination,
    struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt,
    const struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    const struct consensus_state_bundle_proof_parent *parent,
    struct consensus_state_export_result *result)
{
    char *error = NULL;
    if (sqlite3_exec(destination, "BEGIN IMMEDIATE", NULL, NULL, &error) !=
        SQLITE_OK) {
        if (error)
            sqlite3_free(error);
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle transaction begin failed");
    }
    bool ok = sqlite3_exec(destination, k_bundle_schema_sql, NULL, NULL,
                           &error) == SQLITE_OK;
    if (error) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "bundle schema error: %s", error);
        sqlite3_free(error);
        error = NULL;
    }
    if (ok)
        ok = copy_coins(source, destination, manifest);
    if (ok)
        ok = copy_anchors(source, destination, manifest);
    if (ok)
        ok = copy_nullifiers(source, destination, manifest);
    bool checkpoint_ok = ok && compiled_checkpoint_matches(manifest);
    if (ok && !checkpoint_ok) {
        (void)consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "frozen UTXO state does not match compiled checkpoint");
        ok = false;
    }
    if (ok)
        ok = write_source_receipt(destination, receipt);
    if (ok)
        ok = write_proof_summaries(destination, proofs);
    if (ok)
        ok = write_proof_parent(destination, parent);
    if (ok)
        ok = write_manifest(destination, manifest);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(destination, finish, NULL, NULL, &error) != SQLITE_OK)
        ok = false;
    if (error) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "bundle %s error: %s", finish, error);
        sqlite3_free(error);
    }
    if (!ok) {
        sqlite3_exec(destination, "ROLLBACK", NULL, NULL, NULL);
        if (!checkpoint_ok && result &&
            result->status == CONSENSUS_EXPORT_MISSING_PROOF)
            return false;
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_OUTPUT_ERROR,
            "strict consensus-state rows could not be copied atomically");
    }
    return true;
}
