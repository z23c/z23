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

struct coin_row {
    const void *txid;
    const void *script;
    int script_len;
    int64_t vout, value, height, coinbase;
};

/* Reads the current coins row and checks its column types and sizes. */
static bool coin_row_load(sqlite3_stmt *read, struct coin_row *row)
{
    int txid_type = sqlite3_column_type(read, 0);
    int script_type = sqlite3_column_type(read, 3);
    row->txid = txid_type == SQLITE_BLOB ? sqlite3_column_blob(read, 0) : NULL;
    row->script = script_type == SQLITE_BLOB
        ? sqlite3_column_blob(read, 3) : NULL;
    row->script_len = row->script ? sqlite3_column_bytes(read, 3) : 0;
    row->vout = -1;
    row->value = -1;
    row->height = -1;
    row->coinbase = -1;
    bool numeric = column_int64_exact(read, 1, &row->vout) &&
                   column_int64_exact(read, 2, &row->value) &&
                   column_int64_exact(read, 4, &row->height) &&
                   column_int64_exact(read, 5, &row->coinbase);
    return txid_type == SQLITE_BLOB && row->txid &&
           sqlite3_column_bytes(read, 0) == 32 && numeric &&
           script_type == SQLITE_BLOB && row->script_len >= 0 &&
           row->script_len <= MAX_SCRIPT_SIZE;
}

/* Value, height, flag and supply bounds for a loaded coins row. */
static bool coin_row_in_range(const struct coin_row *row, int64_t supply,
                              uint64_t count, int max_height)
{
    return !(row->vout < 0 || row->vout > UINT32_MAX ||
             !MoneyRange(row->value) || supply > MAX_MONEY - row->value ||
             row->height < 0 || row->height > max_height ||
             (row->coinbase != 0 && row->coinbase != 1) ||
             count == UINT64_MAX);
}

static bool coin_row_insert(sqlite3_stmt *write, const struct coin_row *row)
{
    return sqlite3_bind_blob(write, 1, row->txid, 32, SQLITE_TRANSIENT) ==
               SQLITE_OK &&
           sqlite3_bind_int64(write, 2, row->vout) == SQLITE_OK &&
           sqlite3_bind_int64(write, 3, row->value) == SQLITE_OK &&
           bind_blob(write, 4, row->script, row->script_len) &&
           sqlite3_bind_int64(write, 5, row->height) == SQLITE_OK &&
           sqlite3_bind_int(write, 6, row->coinbase) == SQLITE_OK &&
           step_insert(write);
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
        struct coin_row row;
        if (!coin_row_load(read, &row) ||
            !coin_row_in_range(&row, supply, count, manifest->height)) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(
            &digest, row.txid, (uint32_t)row.vout, row.value,
            row.script_len ? row.script : NULL, (uint32_t)row.script_len,
            (uint32_t)row.height, (uint8_t)row.coinbase);
        supply += row.value;
        count++;
        ok = coin_row_insert(write, &row);
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

struct anchor_row {
    const void *root;
    const void *tree;
    int tree_len;
    int64_t pool, height;
};

/* Reads the current anchors row and checks its column types and sizes. */
static bool anchor_row_load(sqlite3_stmt *read, struct anchor_row *row)
{
    int root_type = sqlite3_column_type(read, 1);
    int tree_type = sqlite3_column_type(read, 3);
    row->root = root_type == SQLITE_BLOB ? sqlite3_column_blob(read, 1) : NULL;
    row->pool = -1;
    row->height = -1;
    bool numeric = column_int64_exact(read, 0, &row->pool) &&
                   column_int64_exact(read, 2, &row->height);
    row->tree = tree_type == SQLITE_BLOB ? sqlite3_column_blob(read, 3) : NULL;
    row->tree_len = row->tree ? sqlite3_column_bytes(read, 3) : 0;
    return numeric && root_type == SQLITE_BLOB && row->root &&
           sqlite3_column_bytes(read, 1) == 32 &&
           tree_type == SQLITE_BLOB && row->tree && row->tree_len > 0;
}

static bool anchor_row_in_range(const struct anchor_row *row, uint64_t count,
                                int max_height)
{
    return (row->pool == ANCHOR_POOL_SPROUT ||
            row->pool == ANCHOR_POOL_SAPLING) &&
           row->height >= 0 && row->height <= max_height &&
           count != UINT64_MAX;
}

/* Tracks the newest anchor per pool; false on a duplicate pool height. */
static bool anchor_frontier_update(int64_t frontier_height[2],
                                   uint8_t frontier_root[2][32],
                                   const struct anchor_row *row)
{
    int pool_index = (int)row->pool;
    if (row->height == frontier_height[pool_index])
        return false;
    if (row->height > frontier_height[pool_index]) {
        frontier_height[pool_index] = row->height;
        memcpy(frontier_root[pool_index], row->root, 32);
    }
    return true;
}

static bool anchor_row_insert(sqlite3_stmt *write, const struct anchor_row *row)
{
    return sqlite3_bind_int(write, 1, row->pool) == SQLITE_OK &&
           sqlite3_bind_blob(write, 2, row->root, 32, SQLITE_TRANSIENT) ==
               SQLITE_OK &&
           sqlite3_bind_int64(write, 3, row->height) == SQLITE_OK &&
           sqlite3_bind_blob(write, 4, row->tree, row->tree_len,
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           step_insert(write);
}

static void anchors_publish(struct consensus_state_bundle_manifest *manifest,
                            struct sha3_256_ctx *digest, uint64_t count,
                            const int64_t frontier_height[2],
                            uint8_t frontier_root[2][32])
{
    sha3_256_finalize(digest, manifest->anchor_digest);
    manifest->anchor_count = count;
    manifest->sprout_frontier_height =
        frontier_height[ANCHOR_POOL_SPROUT];
    manifest->sapling_frontier_height =
        frontier_height[ANCHOR_POOL_SAPLING];
    memcpy(manifest->sprout_frontier_root,
           frontier_root[ANCHOR_POOL_SPROUT], 32);
    memcpy(manifest->sapling_frontier_root,
           frontier_root[ANCHOR_POOL_SAPLING], 32);
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
        struct anchor_row row;
        if (!anchor_row_load(read, &row) ||
            !anchor_row_in_range(&row, count, manifest->height)) {
            ok = false;
            break;
        }
        if (!anchor_frontier_update(frontier_height, frontier_root, &row)) {
            ok = false;
            break;
        }
        consensus_state_bundle_anchor_digest_row(
            &digest, (uint8_t)row.pool, row.root, (uint64_t)row.height,
            row.tree, (uint32_t)row.tree_len);
        count++;
        ok = anchor_row_insert(write, &row);
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
    anchors_publish(manifest, &digest, count, frontier_height, frontier_root);
    return true;
}

struct nullifier_row {
    const void *nf;
    int64_t pool, height;
};

/* Reads and range-checks the current nullifiers row. */
static bool nullifier_row_load(sqlite3_stmt *read, struct nullifier_row *row,
                               uint64_t count, int max_height)
{
    int nf_type = sqlite3_column_type(read, 1);
    row->nf = nf_type == SQLITE_BLOB ? sqlite3_column_blob(read, 1) : NULL;
    row->pool = -1;
    row->height = -1;
    bool numeric = column_int64_exact(read, 0, &row->pool) &&
                   column_int64_exact(read, 2, &row->height);
    return numeric && (row->pool == 0 || row->pool == 1) &&
           nf_type == SQLITE_BLOB && row->nf &&
           sqlite3_column_bytes(read, 1) == 32 &&
           row->height >= 0 && row->height <= max_height &&
           count != UINT64_MAX;
}

static bool nullifier_row_insert(sqlite3_stmt *write,
                                 const struct nullifier_row *row)
{
    return sqlite3_bind_int(write, 1, row->pool) == SQLITE_OK &&
           sqlite3_bind_blob(write, 2, row->nf, 32, SQLITE_TRANSIENT) ==
               SQLITE_OK &&
           sqlite3_bind_int64(write, 3, row->height) == SQLITE_OK &&
           step_insert(write);
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
        struct nullifier_row row;
        if (!nullifier_row_load(read, &row, count, manifest->height)) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(
            &digest, (uint8_t)row.pool, row.nf, (uint64_t)row.height);
        count++;
        ok = nullifier_row_insert(write, &row);
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

static bool bind_manifest_identity(
    sqlite3_stmt *st, int *i, const struct consensus_state_bundle_manifest *m)
{
    return sqlite3_bind_text(st, (*i)++, CONSENSUS_STATE_BUNDLE_SCHEMA, -1,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int(st, (*i)++, m->height) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->block_hash, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int(st, (*i)++, m->history_complete ? 1 : 0) ==
               SQLITE_OK &&
           sqlite3_bind_int(st, (*i)++, m->source_clean ? 1 : 0) ==
               SQLITE_OK &&
           sqlite3_bind_int(st, (*i)++, m->validation_profile) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->activation_boundary) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->utxo_root, 32, SQLITE_STATIC) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, (sqlite3_int64)m->utxo_count) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->total_supply) == SQLITE_OK;
}

static bool bind_manifest_shielded(
    sqlite3_stmt *st, int *i, const struct consensus_state_bundle_manifest *m)
{
    return sqlite3_bind_blob(st, (*i)++, m->anchor_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, (sqlite3_int64)m->anchor_count) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->sprout_frontier_root, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->sprout_frontier_height) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->sapling_frontier_root, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->sapling_frontier_height) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->nullifier_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, (sqlite3_int64)m->nullifier_count) ==
               SQLITE_OK;
}

static bool bind_manifest_cursors(
    sqlite3_stmt *st, int *i, const struct consensus_state_bundle_manifest *m)
{
    return sqlite3_bind_int64(st, (*i)++, m->sprout_source_cursor) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->sapling_source_cursor) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->nullifier_source_cursor) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, m->source_fold_cursor) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->proof_manifest_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->source_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, m->artifact_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK;
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
    bool ok = bind_manifest_identity(st, &i, m) &&
              bind_manifest_shielded(st, &i, m) &&
              bind_manifest_cursors(st, &i, m);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:consensus-bundle-artifact
    sqlite3_finalize(st);
    return ok;
}

static bool bind_receipt_digests(
    sqlite3_stmt *st, int *i, const char *schema,
    const struct consensus_state_source_receipt *receipt)
{
    return sqlite3_bind_text(st, (*i)++, schema, -1, SQLITE_STATIC) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->source_epoch_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->source_tree_root, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->running_binary_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->toolchain_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->build_inputs_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->chain_corpus_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK;
}

static bool bind_receipt_producer(
    sqlite3_stmt *st, int *i, size_t commit_len,
    const struct consensus_state_source_receipt *receipt)
{
    return sqlite3_bind_int(st, (*i)++, receipt->source_clean ? 1 : 0) ==
               SQLITE_OK &&
           sqlite3_bind_int(st, (*i)++, receipt->validation_profile) ==
               SQLITE_OK &&
           sqlite3_bind_text(st, (*i)++, receipt->producer_commit,
                             (int)commit_len,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, (*i)++, receipt->fold_cursor) == SQLITE_OK &&
           sqlite3_bind_blob(st, (*i)++, receipt->receipt_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK;
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
    bool ok = bind_receipt_digests(st, &i, schema, receipt) &&
              bind_receipt_producer(st, &i, commit_len, receipt) &&
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

/* Creates the proof_parent row; always finalizes its statement. */
static bool proof_parent_insert_base(
    sqlite3 *db, const struct consensus_state_bundle_proof_parent *parent)
{
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
    return ok;
}

static bool proof_parent_insert_component(
    sqlite3_stmt *st, const struct consensus_state_bundle_proof_parent *parent,
    size_t i)
{
    const struct consensus_state_bundle_proof_summary *component =
        &parent->components[i];
    return sqlite3_bind_int(st, 1, (int)i) == SQLITE_OK &&
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

static bool proof_parent_insert_components(
    sqlite3 *db, const struct consensus_state_bundle_proof_parent *parent)
{
    static const char component_sql[] =
        "INSERT INTO proof_parent_component("
        "ordinal,component,cursor,first_height,last_height,row_count,"
        "hash_bound_count,component_digest,suffix_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, component_sql, -1, &st, NULL) ==
              SQLITE_OK;
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++)
        ok = proof_parent_insert_component(st, parent, i);
    if (st)
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
    bool ok = proof_parent_insert_base(db, parent);
    if (ok)
        ok = proof_parent_insert_components(db, parent);
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

static bool export_begin_transaction(sqlite3 *destination)
{
    char *error = NULL;
    if (sqlite3_exec(destination, "BEGIN IMMEDIATE", NULL, NULL, &error) !=
        SQLITE_OK) {
        if (error)
            sqlite3_free(error);
        return false;
    }
    return true;
}

static bool export_copy_tables(
    sqlite3 *source, sqlite3 *destination,
    struct consensus_state_bundle_manifest *manifest)
{
    return copy_coins(source, destination, manifest) &&
           copy_anchors(source, destination, manifest) &&
           copy_nullifiers(source, destination, manifest);
}

static bool export_write_metadata(
    sqlite3 *destination, struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt,
    const struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    const struct consensus_state_bundle_proof_parent *parent)
{
    return write_source_receipt(destination, receipt) &&
           write_proof_summaries(destination, proofs) &&
           write_proof_parent(destination, parent) &&
           write_manifest(destination, manifest);
}

/* True when the failure is the already-reported checkpoint mismatch. */
static bool export_checkpoint_refused(
    bool checkpoint_ok, const struct consensus_state_export_result *result)
{
    return !checkpoint_ok && result &&
           result->status == CONSENSUS_EXPORT_MISSING_PROOF;
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
    if (!export_begin_transaction(destination))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle transaction begin failed");
    bool ok = sqlite3_exec(destination, k_bundle_schema_sql, NULL, NULL,
                           &error) == SQLITE_OK;
    if (error) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "bundle schema error: %s", error);
        sqlite3_free(error);
        error = NULL;
    }
    if (ok)
        ok = export_copy_tables(source, destination, manifest);
    bool checkpoint_ok = ok && compiled_checkpoint_matches(manifest);
    if (ok && !checkpoint_ok) {
        (void)consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "frozen UTXO state does not match compiled checkpoint");
        ok = false;
    }
    if (ok)
        ok = export_write_metadata(destination, manifest, receipt, proofs,
                                   parent);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(destination, finish, NULL, NULL, &error) != SQLITE_OK)
        ok = false;
    if (error) {
        LOG_WARN(EXPORT_WRITE_SUBSYS, "bundle %s error: %s", finish, error);
        sqlite3_free(error);
    }
    if (!ok) {
        sqlite3_exec(destination, "ROLLBACK", NULL, NULL, NULL);
        if (export_checkpoint_refused(checkpoint_ok, result))
            return false;
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_OUTPUT_ERROR,
            "strict consensus-state rows could not be copied atomically");
    }
    return true;
}
