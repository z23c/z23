/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Independent read-only validation of a closed consensus-state
 * candidate after its writable SQLite handle has been strictly closed. */

#include "consensus_state_snapshot_install_internal.h"
#include "consensus_state_sqlite_text.h"

#include "base/serialize_le.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "sapling/incremental_merkle_tree.h"
#include "script/script.h"
#include "services/nullifier_backfill_service.h"
#include "storage/anchor_kv.h"
#include "storage/consensus_state_bundle_codec.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static bool candidate_invalid(struct consensus_state_candidate_result *result,
                              const char *reason)
{
    return consensus_state_candidate_fail(
        result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
        "candidate reopen validation: %s", reason);
}

static bool blob32_equal(sqlite3_stmt *stmt, int column,
                         const uint8_t expected[32])
{
    if (sqlite3_column_type(stmt, column) != SQLITE_BLOB)
        return false;
    const void *blob = sqlite3_column_blob(stmt, column);
    return blob &&
           sqlite3_column_bytes(stmt, column) == 32 &&
           memcmp(blob, expected, 32) == 0;
}

static bool blob32_copy(sqlite3_stmt *stmt, int column, uint8_t out[32])
{
    if (sqlite3_column_type(stmt, column) != SQLITE_BLOB)
        return false;
    const void *blob = sqlite3_column_blob(stmt, column);
    if (!blob || sqlite3_column_bytes(stmt, column) != 32)
        return false;
    memcpy(out, blob, 32);
    return true;
}

static bool candidate_integrity(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL) !=
        SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              consensus_state_sqlite_text_equal(stmt, 0, "ok") &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

struct schema_object {
    const char *type;
    const char *name;
    int column_count;
};

static bool schema_column_count(sqlite3 *db, const char *name, int expected)
{
    if (expected < 0)
        return true;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT count(*) FROM pragma_table_xinfo(?) WHERE hidden=0",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    bool ok = sqlite3_step(stmt) == SQLITE_ROW && // raw-sql-ok:read-only-introspection
              sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(stmt, 0) == expected &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_closed_schema(sqlite3 *db)
{
    static const struct schema_object expected[] = {
        {"index", "idx_nullifiers_height", -1},
        {"index", "idx_sapling_anchors_height", -1},
        {"index", "idx_sprout_anchors_height", -1},
        {"table", "anchor_state", 2},
        {"table", "coins", 6},
        {"table", "consensus_state_bundle_proof", 8},
        {"table", "consensus_state_candidate_meta", 27},
        {"table", "consensus_state_source_receipt", 13},
        {"table", "nullifiers", 3},
        {"table", "progress_meta", 2},
        {"table", "sapling_anchors", 3},
        {"table", "sprout_anchors", 3},
        {"table", "stage_cursor", 3},
        {"table", "tip_finalize_log", 9},
        {"table", "utxo_apply_log", 9},
    };
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT type,name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(expected) / sizeof(expected[0]); i++) {
        int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
        int sql_type = rc == SQLITE_ROW ? sqlite3_column_type(stmt, 2)
                                        : SQLITE_NULL;
        const char *sql = sql_type == SQLITE_TEXT
            ? (const char *)sqlite3_column_text(stmt, 2) : NULL;
        ok = rc == SQLITE_ROW &&
             consensus_state_sqlite_text_equal(stmt, 0, expected[i].type) &&
             consensus_state_sqlite_text_equal(stmt, 1, expected[i].name) &&
             sql && sqlite3_column_bytes(stmt, 2) == (int)strlen(sql) &&
             schema_column_count(db, expected[i].name,
                                 expected[i].column_count);
    }
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_meta_matches(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m,
    const uint8_t admission_receipt[32])
{
    static const char sql[] =
        "SELECT schema,height,block_hash,history_complete,source_clean,"
        "validation_profile,activation_boundary,"
        "utxo_root,utxo_count,total_supply,anchor_digest,anchor_count,"
        "sprout_frontier_root,sprout_frontier_height,sapling_frontier_root,"
        "sapling_frontier_height,nullifier_digest,nullifier_count,"
        "sprout_source_cursor,sapling_source_cursor,nullifier_source_cursor,"
        "source_fold_cursor,proof_manifest_digest,source_digest,artifact_digest,"
        "admission_receipt_digest FROM consensus_state_candidate_meta "
        "WHERE singleton=1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
        consensus_state_sqlite_text_equal(
            stmt, 0, CONSENSUS_STATE_CANDIDATE_SCHEMA) &&
        sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 1) == m->height &&
        blob32_equal(stmt, 2, m->block_hash) &&
        sqlite3_column_type(stmt, 3) == SQLITE_INTEGER &&
        sqlite3_column_int(stmt, 3) == 1 &&
        sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
        sqlite3_column_int(stmt, 4) == (m->source_clean ? 1 : 0) &&
        sqlite3_column_type(stmt, 5) == SQLITE_INTEGER &&
        sqlite3_column_int(stmt, 5) == m->validation_profile &&
        sqlite3_column_type(stmt, 6) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 6) == 0 &&
        blob32_equal(stmt, 7, m->utxo_root) &&
        sqlite3_column_type(stmt, 8) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 8) == (sqlite3_int64)m->utxo_count &&
        sqlite3_column_type(stmt, 9) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 9) == m->total_supply &&
        blob32_equal(stmt, 10, m->anchor_digest) &&
        sqlite3_column_type(stmt, 11) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 11) == (sqlite3_int64)m->anchor_count &&
        blob32_equal(stmt, 12, m->sprout_frontier_root) &&
        sqlite3_column_type(stmt, 13) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 13) == m->sprout_frontier_height &&
        blob32_equal(stmt, 14, m->sapling_frontier_root) &&
        sqlite3_column_type(stmt, 15) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 15) == m->sapling_frontier_height &&
        blob32_equal(stmt, 16, m->nullifier_digest) &&
        sqlite3_column_type(stmt, 17) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 17) == (sqlite3_int64)m->nullifier_count &&
        sqlite3_column_type(stmt, 18) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 18) == 0 &&
        sqlite3_column_type(stmt, 19) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 19) == 0 &&
        sqlite3_column_type(stmt, 20) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 20) == 0 &&
        sqlite3_column_type(stmt, 21) == SQLITE_INTEGER &&
        sqlite3_column_int64(stmt, 21) == m->source_fold_cursor &&
        blob32_equal(stmt, 22, m->proof_manifest_digest) &&
        blob32_equal(stmt, 23, m->source_digest) &&
        blob32_equal(stmt, 24, m->artifact_digest) &&
        blob32_equal(stmt, 25, admission_receipt) &&
        sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_source_receipt(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m,
    struct consensus_state_source_receipt *receipt)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT schema,source_epoch_digest,source_tree_root,"
            "running_binary_digest,toolchain_digest,build_inputs_digest,"
            "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
            "fold_cursor,receipt_digest FROM consensus_state_source_receipt "
            "WHERE singleton=1",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    memset(receipt, 0, sizeof(*receipt));
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    int commit_type = rc == SQLITE_ROW ? sqlite3_column_type(stmt, 9)
                                       : SQLITE_NULL;
    const char *commit = commit_type == SQLITE_TEXT
        ? (const char *)sqlite3_column_text(stmt, 9) : NULL;
    int commit_len = commit ? sqlite3_column_bytes(stmt, 9) : -1;
    const char *schema =
        rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_TEXT
            ? (const char *)sqlite3_column_text(stmt, 0) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(stmt, 0) : -1;
    uint8_t receipt_version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    bool schema_ok = schema && schema_len >= 0 &&
        consensus_state_source_receipt_schema_version(
            schema, (size_t)schema_len, &receipt_version);
    bool ok = rc == SQLITE_ROW && commit &&
        schema_ok &&
        commit_type == SQLITE_TEXT &&
        commit_len >= 0 &&
        consensus_state_source_receipt_commit_valid(
            receipt_version, commit, (size_t)commit_len) &&
        blob32_copy(stmt, 1, receipt->source_epoch_digest) &&
        blob32_copy(stmt, 2, receipt->source_tree_root) &&
        blob32_copy(stmt, 3, receipt->running_binary_digest) &&
        blob32_copy(stmt, 4, receipt->toolchain_digest) &&
        blob32_copy(stmt, 5, receipt->build_inputs_digest) &&
        blob32_copy(stmt, 6, receipt->chain_corpus_digest) &&
        sqlite3_column_type(stmt, 7) == SQLITE_INTEGER &&
        (sqlite3_column_int(stmt, 7) == 0 ||
         sqlite3_column_int(stmt, 7) == 1) &&
        sqlite3_column_type(stmt, 8) == SQLITE_INTEGER &&
        (sqlite3_column_int(stmt, 8) == CONSENSUS_STATE_VALIDATION_FULL ||
         sqlite3_column_int(stmt, 8) ==
             CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
        blob32_copy(stmt, 11, receipt->receipt_digest) &&
        sqlite3_column_type(stmt, 10) == SQLITE_INTEGER;
    if (ok) {
        receipt->schema_version = receipt_version;
        memcpy(receipt->producer_commit, commit, (size_t)commit_len);
        receipt->producer_commit[commit_len] = '\0';
        receipt->source_clean = sqlite3_column_int(stmt, 7) == 1;
        receipt->validation_profile = (uint8_t)sqlite3_column_int(stmt, 8);
        receipt->fold_cursor = sqlite3_column_int64(stmt, 10);
        uint8_t digest[32], source_epoch[32];
        consensus_state_source_epoch_digest(receipt, source_epoch);
        consensus_state_source_receipt_digest(receipt, digest);
        ok = receipt->fold_cursor == m->source_fold_cursor &&
             receipt->source_clean == m->source_clean &&
             receipt->validation_profile == m->validation_profile &&
             memcmp(source_epoch, receipt->source_epoch_digest, 32) == 0 &&
             memcmp(digest, receipt->receipt_digest, 32) == 0 &&
             memcmp(digest, m->source_digest, 32) == 0 &&
             sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    }
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_proofs(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m,
    const struct consensus_state_source_receipt *receipt)
{
    static const char *const names[CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    static const bool hash_bound[CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
        true, true, true, false, true, true, true, false,
    };
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ordinal,component,cursor,first_height,last_height,row_count,"
            "hash_bound_count,component_digest "
            "FROM consensus_state_bundle_proof ORDER BY ordinal",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    memset(proofs, 0, sizeof(proofs));
    uint64_t rows = (uint64_t)m->height + 1;
    bool ok = true;
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
        if (rc != SQLITE_ROW) {
            ok = false;
            break;
        }
        bool types_ok = sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 1) == SQLITE_TEXT &&
            sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 3) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 5) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 6) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 7) == SQLITE_BLOB;
        if (!types_ok) {
            ok = false;
            break;
        }
        int64_t cursor = sqlite3_column_int64(stmt, 2);
        uint64_t minimum = i == 7 ? (uint64_t)m->height : rows;
        ok = sqlite3_column_int64(stmt, 0) == (sqlite3_int64)i &&
             consensus_state_sqlite_text_equal(stmt, 1, names[i]) &&
             cursor >= 0 &&
             (uint64_t)cursor >= minimum &&
             (i != 6 || (uint64_t)cursor == rows) &&
             (i != 7 || (uint64_t)cursor <= minimum + 1) &&
             sqlite3_column_int64(stmt, 3) == 0 &&
             sqlite3_column_int64(stmt, 4) == m->height &&
             sqlite3_column_int64(stmt, 5) == (sqlite3_int64)rows &&
             sqlite3_column_int64(stmt, 6) ==
                 (sqlite3_int64)(hash_bound[i] ? rows : 0) &&
             blob32_copy(stmt, 7, proofs[i].component_digest);
        if (ok) {
            snprintf(proofs[i].component, sizeof(proofs[i].component), "%s",
                     names[i]);
            proofs[i].cursor = (uint64_t)cursor;
            proofs[i].first_height = 0;
            proofs[i].last_height = m->height;
            proofs[i].row_count = rows;
            proofs[i].hash_bound_count = hash_bound[i] ? rows : 0;
        }
    }
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    uint8_t digest[32];
    if (ok) {
        consensus_state_bundle_proof_manifest_digest(
            proofs, CONSENSUS_STATE_BUNDLE_PROOF_COUNT, digest);
        ok = memcmp(digest, m->proof_manifest_digest, 32) == 0 &&
             memcmp(proofs[0].component_digest,
                    receipt->chain_corpus_digest, 32) == 0;
    }
    return ok;
}

static bool candidate_coins(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid,vout,value,script,height,is_coinbase "
            "FROM coins ORDER BY txid,vout",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx context;
    sha3_256_init(&context);
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        bool types_ok = sqlite3_column_type(stmt, 0) == SQLITE_BLOB &&
            sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 3) == SQLITE_BLOB &&
            sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 5) == SQLITE_INTEGER;
        if (!types_ok) {
            ok = false;
            break;
        }
        const uint8_t *txid = sqlite3_column_blob(stmt, 0);
        const uint8_t *script = sqlite3_column_blob(stmt, 3);
        int64_t vout = sqlite3_column_int64(stmt, 1);
        int64_t value = sqlite3_column_int64(stmt, 2);
        int script_size = sqlite3_column_bytes(stmt, 3);
        int64_t height = sqlite3_column_int64(stmt, 4);
        int coinbase = sqlite3_column_int(stmt, 5);
        if (!txid || sqlite3_column_bytes(stmt, 0) != 32 || vout < 0 ||
            vout > UINT32_MAX || !MoneyRange(value) ||
            supply > MAX_MONEY - value ||
            script_size < 0 ||
            script_size > MAX_SCRIPT_SIZE || height < 0 || height > m->height ||
            (coinbase != 0 && coinbase != 1) || count == UINT64_MAX) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(
            &context, txid, (uint32_t)vout, value,
            script_size ? script : NULL, (uint32_t)script_size,
            (uint32_t)height, (uint8_t)coinbase);
        supply += value;
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(stmt);
    uint8_t root[32];
    sha3_256_finalize(&context, root);
    return ok && count == m->utxo_count && supply == m->total_supply &&
           memcmp(root, m->utxo_root, 32) == 0;
}

bool consensus_state_snapshot_destination_anchors_valid(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    /* Tip-frontier-only Pedersen: pre-identify the per-pool MAX(height) anchor
     * so the full O(anchors x Pedersen-hash) recompute collapses to O(pools).
     * Only the tip rows carry consensus-load-bearing tree contents; historical
     * rows get the byte-integrity floor. Same boundary as the bulk import path
     * (chainstate_legacy_reader.c:376-378) and the source-bundle validator. */
    int64_t tip_height[2] = {-1, -1};
    {
        sqlite3_stmt *tq = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT pool,MAX(height) FROM ("
                "SELECT 0 AS pool,height FROM sprout_anchors UNION ALL "
                "SELECT 1 AS pool,height FROM sapling_anchors) GROUP BY pool",
                -1, &tq, NULL) != SQLITE_OK)
            return false;
        bool tq_ok = true;
        int trc;
        while ((trc = sqlite3_step(tq)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
            if (sqlite3_column_type(tq, 0) != SQLITE_INTEGER ||
                sqlite3_column_type(tq, 1) != SQLITE_INTEGER) {
                tq_ok = false;
                break;
            }
            int pool = sqlite3_column_int(tq, 0);
            int64_t h = sqlite3_column_int64(tq, 1);
            if (pool != 0 && pool != 1) {
                tq_ok = false;
                break;
            }
            tip_height[pool] = h;
        }
        if (trc != SQLITE_DONE)
            tq_ok = false;
        sqlite3_finalize(tq);
        if (!tq_ok)
            return false;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,anchor,height,tree FROM ("
            "SELECT 0 AS pool,anchor,height,tree FROM sprout_anchors UNION ALL "
            "SELECT 1 AS pool,anchor,height,tree FROM sapling_anchors) "
            "ORDER BY pool,anchor",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx context;
    consensus_state_bundle_anchor_digest_begin(&context);
    int64_t frontier_height[2] = {-1, -1};
    uint8_t frontier_root[2][32] = {{0}, {0}};
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        bool types_ok = sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 1) == SQLITE_BLOB &&
            sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 3) == SQLITE_BLOB;
        if (!types_ok) {
            ok = false;
            break;
        }
        int pool = sqlite3_column_int(stmt, 0);
        const uint8_t *root = sqlite3_column_blob(stmt, 1);
        int64_t height = sqlite3_column_int64(stmt, 2);
        const uint8_t *tree_blob = sqlite3_column_blob(stmt, 3);
        int tree_size = tree_blob ? sqlite3_column_bytes(stmt, 3) : 0;
        if ((pool != 0 && pool != 1) || !root ||
            sqlite3_column_bytes(stmt, 1) != 32 || !tree_blob ||
            tree_size <= 0 || height < 0 || height > m->height ||
            count == UINT64_MAX) {
            ok = false;
            break;
        }
        struct incremental_merkle_tree tree;
        if (pool == ANCHOR_POOL_SPROUT)
            sprout_tree_init(&tree);
        else
            sapling_tree_init(&tree);
        struct byte_stream stream;
        stream_init_from_data(&stream, tree_blob, (size_t)tree_size);
        /* Byte-integrity floor for EVERY row (torn/truncated/garbled/trailing
         * bytes are refused regardless of position). */
        if (!incremental_tree_deserialize(&tree, &stream) ||
            stream_remaining(&stream) != 0) {
            ok = false;
            break;
        }
        /* Tip-frontier Pedersen: recompute + bind the stored key ONLY for the
         * per-pool MAX(height) anchor. Historical rows delegate root/key
         * agreement to the whole-file digest + this tip bind. */
        if (height == tip_height[pool]) {
            struct uint256 computed;
            incremental_tree_root(&tree, &computed);
            if (memcmp(computed.data, root, 32) != 0) {
                ok = false;
                break;
            }
        }
        consensus_state_bundle_anchor_digest_row(
            &context, (uint8_t)pool, root, (uint64_t)height, tree_blob,
            (uint32_t)tree_size);
        if (height > frontier_height[pool]) {
            frontier_height[pool] = height;
            memcpy(frontier_root[pool], root, 32);
        }
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(stmt);
    uint8_t digest[32];
    sha3_256_finalize(&context, digest);
    return ok && count == m->anchor_count &&
        frontier_height[0] == m->sprout_frontier_height &&
        frontier_height[1] == m->sapling_frontier_height &&
        memcmp(frontier_root[0], m->sprout_frontier_root, 32) == 0 &&
        memcmp(frontier_root[1], m->sapling_frontier_root, 32) == 0 &&
        memcmp(digest, m->anchor_digest, 32) == 0;
}

bool consensus_state_snapshot_destination_nullifiers_valid(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx context;
    consensus_state_bundle_nullifier_digest_begin(&context);
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        bool types_ok = sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
            sqlite3_column_type(stmt, 1) == SQLITE_BLOB &&
            sqlite3_column_type(stmt, 2) == SQLITE_INTEGER;
        if (!types_ok) {
            ok = false;
            break;
        }
        int pool = sqlite3_column_int(stmt, 0);
        const uint8_t *nf = sqlite3_column_blob(stmt, 1);
        int64_t height = sqlite3_column_int64(stmt, 2);
        if ((pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(stmt, 1) != 32 || height < 0 ||
            height > m->height || count == UINT64_MAX) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(
            &context, (uint8_t)pool, nf, (uint64_t)height);
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(stmt);
    uint8_t digest[32];
    sha3_256_finalize(&context, digest);
    return ok && count == m->nullifier_count &&
           memcmp(digest, m->nullifier_digest, 32) == 0;
}

static bool candidate_meta_value(sqlite3 *db, const char *key,
                                 uint8_t *value, size_t capacity,
                                 size_t *size_out)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM progress_meta WHERE key=?",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    int type = rc == SQLITE_ROW ? sqlite3_column_type(stmt, 0) : SQLITE_NULL;
    const void *blob = type == SQLITE_BLOB
        ? sqlite3_column_blob(stmt, 0) : NULL;
    int size = blob ? sqlite3_column_bytes(stmt, 0) : 0;
    bool ok = rc == SQLITE_ROW && type == SQLITE_BLOB && size >= 0 &&
              (size_t)size <= capacity &&
              (size == 0 || blob);
    if (ok && size > 0)
        memcpy(value, blob, (size_t)size);
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    if (ok)
        *size_out = (size_t)size;
    return ok;
}

static bool candidate_reducer_state(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT pool,activation_cursor FROM anchor_state ORDER BY pool",
        -1, &stmt, NULL) == SQLITE_OK;
    for (int pool = 0; ok && pool < 2; pool++) {
        int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
        ok = rc == SQLITE_ROW &&
             sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
             sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
             sqlite3_column_int(stmt, 0) == pool &&
             sqlite3_column_int64(stmt, 1) == 0;
    }
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    if (stmt)
        sqlite3_finalize(stmt);
    if (!ok)
        return false;
    uint8_t value[32];
    size_t size = 0;
#define META_EQ(key, length, expression) \
    (candidate_meta_value(db, (key), value, sizeof(value), &size) && \
     size == (length) && (expression))
    ok = META_EQ("coins_applied_height", 8,
                 zcl_read_i64_le(value) == (int64_t)m->height + 1) &&
         META_EQ("coins_kv_migration_complete", 1, value[0] == 1) &&
         META_EQ("coins_kv_self_folded", 1, value[0] == 1) &&
         META_EQ(NULLIFIER_BACKFILL_ACTIVATION_KEY, 1, value[0] == '0') &&
         META_EQ(REDUCER_TRUSTED_BASE_HEIGHT_KEY, 8,
                 zcl_read_i64_le(value) == m->height) &&
         META_EQ(REDUCER_TRUSTED_BASE_HASH_KEY, 32,
                 memcmp(value, m->block_hash, 32) == 0);
#undef META_EQ
    if (!ok)
        return false;
    if (sqlite3_prepare_v2(db,
            "SELECT count(*) FROM progress_meta", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    ok = sqlite3_step(stmt) == SQLITE_ROW && // raw-sql-ok:read-only-introspection
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == 6;
    sqlite3_finalize(stmt);
    if (!ok)
        return false;

    static const char *const stages[] = {
        "body_fetch", "body_persist", "header_admit", "proof_validate",
        "script_validate", "tip_finalize", "utxo_apply", "validate_headers",
    };
    if (sqlite3_prepare_v2(db,
            "SELECT name,cursor,updated_at FROM stage_cursor ORDER BY name",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    for (size_t i = 0; ok && i < sizeof(stages) / sizeof(stages[0]); i++) {
        int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
        int64_t want = strcmp(stages[i], "tip_finalize") == 0
                           ? m->height : (int64_t)m->height + 1;
        ok = rc == SQLITE_ROW &&
             consensus_state_sqlite_text_equal(stmt, 0, stages[i]) &&
             sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
             sqlite3_column_int64(stmt, 1) == want &&
             sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
             sqlite3_column_int64(stmt, 2) == 0;
    }
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    if (!ok)
        return false;

    if (sqlite3_prepare_v2(db,
            "SELECT height,status,ok,spent_count,added_count,total_value_delta,"
            "first_failure_kind,first_failure_detail,applied_at "
            "FROM utxo_apply_log", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    ok = rc == SQLITE_ROW &&
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         consensus_state_sqlite_text_equal(stmt, 1, "anchor") &&
         sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == m->height &&
         sqlite3_column_int(stmt, 2) == 1 &&
         sqlite3_column_type(stmt, 3) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 3) == 0 &&
         sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 4) == 0 &&
         sqlite3_column_type(stmt, 5) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 5) == 0 &&
         sqlite3_column_type(stmt, 6) == SQLITE_NULL &&
         sqlite3_column_type(stmt, 7) == SQLITE_NULL &&
         sqlite3_column_type(stmt, 8) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 8) == 0 &&
         sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    if (!ok)
        return false;
    if (sqlite3_prepare_v2(db,
            "SELECT height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,tip_hash "
            "FROM tip_finalize_log", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    ok = rc == SQLITE_ROW &&
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         consensus_state_sqlite_text_equal(stmt, 1, "anchor") &&
         sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == m->height &&
         sqlite3_column_int(stmt, 2) == 1 &&
         sqlite3_column_type(stmt, 3) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 3) == 0 &&
         sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 4) == 0 &&
         sqlite3_column_type(stmt, 5) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 5) == (sqlite3_int64)m->utxo_count &&
         sqlite3_column_type(stmt, 6) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 6) == 0 &&
         sqlite3_column_type(stmt, 7) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 7) == 0 &&
         blob32_equal(stmt, 8, m->block_hash) &&
         sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

bool consensus_state_candidate_validate_reopened(
    sqlite3 *candidate,
    const struct consensus_state_bundle_manifest *expected,
    const uint8_t expected_admission_receipt[32],
    struct consensus_state_candidate_result *result)
{
    if (!candidate || !expected || !expected_admission_receipt)
        return candidate_invalid(result, "null validation input");
    struct consensus_state_source_receipt receipt;
    if (!candidate_integrity(candidate))
        return candidate_invalid(result, "integrity check failed");
    if (!candidate_closed_schema(candidate))
        return candidate_invalid(result, "schema is not the closed set");
    if (!candidate_meta_matches(candidate, expected,
                                expected_admission_receipt))
        return candidate_invalid(result, "manifest/admission receipt mismatch");
    if (!candidate_source_receipt(candidate, expected, &receipt) ||
        !candidate_proofs(candidate, expected, &receipt))
        return candidate_invalid(result, "source proof provenance mismatch");
    if (!candidate_coins(candidate, expected))
        return candidate_invalid(result, "UTXO root/count/supply mismatch");
    if (!consensus_state_snapshot_destination_anchors_valid(candidate,
                                                            expected))
        return candidate_invalid(result, "anchor digest/frontier mismatch");
    if (!consensus_state_snapshot_destination_nullifiers_valid(candidate,
                                                               expected))
        return candidate_invalid(result, "nullifier digest/count mismatch");
    if (!candidate_reducer_state(candidate, expected))
        return candidate_invalid(result, "reducer cursor/log/base mismatch");
    return true;
}
