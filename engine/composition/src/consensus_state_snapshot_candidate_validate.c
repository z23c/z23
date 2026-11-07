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
#include "util/ar_step_readonly.h"

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

static bool candidate_closed_schema(sqlite3 *db, uint8_t version)
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
                                 expected[i].column_count +
                                 (version == CONSENSUS_STATE_BUNDLE_V2 &&
                                  strcmp(expected[i].name, "consensus_state_candidate_meta") == 0 ? 3 : 0));
    }
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(stmt);
    return ok;
}

static bool int_col_is(sqlite3_stmt *stmt, int column, int expected)
{
    return sqlite3_column_type(stmt, column) == SQLITE_INTEGER &&
           sqlite3_column_int(stmt, column) == expected;
}

static bool int64_col_is(sqlite3_stmt *stmt, int column, int64_t expected)
{
    return sqlite3_column_type(stmt, column) == SQLITE_INTEGER &&
           sqlite3_column_int64(stmt, column) == expected;
}

static bool step_done(sqlite3_stmt *stmt)
{
    return sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
}

static bool meta_head_matches(sqlite3_stmt *stmt,
                              const struct consensus_state_bundle_manifest *m)
{
    return consensus_state_sqlite_text_equal(
               stmt, 0, CONSENSUS_STATE_CANDIDATE_SCHEMA) &&
           int64_col_is(stmt, 1, m->height) &&
           blob32_equal(stmt, 2, m->block_hash) &&
           int_col_is(stmt, 3, 1) &&
           int_col_is(stmt, 4, m->source_clean ? 1 : 0) &&
           int_col_is(stmt, 5, m->validation_profile) &&
           int64_col_is(stmt, 6, 0);
}

static bool meta_state_matches(sqlite3_stmt *stmt,
                               const struct consensus_state_bundle_manifest *m)
{
    return blob32_equal(stmt, 7, m->utxo_root) &&
           int64_col_is(stmt, 8, (sqlite3_int64)m->utxo_count) &&
           int64_col_is(stmt, 9, m->total_supply) &&
           blob32_equal(stmt, 10, m->anchor_digest) &&
           int64_col_is(stmt, 11, (sqlite3_int64)m->anchor_count) &&
           blob32_equal(stmt, 12, m->sprout_frontier_root) &&
           int64_col_is(stmt, 13, m->sprout_frontier_height) &&
           blob32_equal(stmt, 14, m->sapling_frontier_root) &&
           int64_col_is(stmt, 15, m->sapling_frontier_height) &&
           blob32_equal(stmt, 16, m->nullifier_digest) &&
           int64_col_is(stmt, 17, (sqlite3_int64)m->nullifier_count);
}

static bool meta_provenance_matches(
    sqlite3_stmt *stmt, const struct consensus_state_bundle_manifest *m,
    const uint8_t admission_receipt[32])
{
    return int64_col_is(stmt, 18, 0) && int64_col_is(stmt, 19, 0) &&
           int64_col_is(stmt, 20, 0) &&
           int64_col_is(stmt, 21, m->source_fold_cursor) &&
           blob32_equal(stmt, 22, m->proof_manifest_digest) &&
           blob32_equal(stmt, 23, m->source_digest) &&
           blob32_equal(stmt, 24, m->artifact_digest) &&
           blob32_equal(stmt, 25, admission_receipt);
}

static bool candidate_v2_pools_match(sqlite3 *db,
                                    const struct consensus_state_bundle_manifest *m)
{
    if (m->format_version == CONSENSUS_STATE_BUNDLE_V1)
        return true;
    if (m->format_version != CONSENSUS_STATE_BUNDLE_V2 ||
        m->sprout_pool_total < 0 || m->sapling_pool_total < 0)
        return false;
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT bundle_format_version,sprout_pool_total,sapling_pool_total "
                      "FROM consensus_state_candidate_meta WHERE singleton=1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = ar_step_checked(st, "candidate v2 pool row", NULL) == ZCL_STEP_ROW &&
              int64_col_is(st, 0, CONSENSUS_STATE_BUNDLE_V2) &&
              int64_col_is(st, 1, m->sprout_pool_total) &&
              int64_col_is(st, 2, m->sapling_pool_total) && step_done(st);
    int rc = sqlite3_finalize(st);
    return ok && rc == SQLITE_OK;
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
    bool ok = rc == SQLITE_ROW && meta_head_matches(stmt, m) &&
              meta_state_matches(stmt, m) &&
              meta_provenance_matches(stmt, m, admission_receipt) &&
              step_done(stmt);
    sqlite3_finalize(stmt);
    return ok;
}

/* The candidate source_receipt row's text columns and the schema version they
 * name. */
struct cand_receipt_head {
    int commit_type;
    const char *commit;
    int commit_len;
    uint8_t version;
    bool schema_ok;
};

static void cand_receipt_head_read(sqlite3_stmt *stmt, int rc,
                                   struct cand_receipt_head *h)
{
    h->commit_type = rc == SQLITE_ROW ? sqlite3_column_type(stmt, 9)
                                      : SQLITE_NULL;
    h->commit = h->commit_type == SQLITE_TEXT
        ? (const char *)sqlite3_column_text(stmt, 9) : NULL;
    h->commit_len = h->commit ? sqlite3_column_bytes(stmt, 9) : -1;
    const char *schema =
        rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_TEXT
            ? (const char *)sqlite3_column_text(stmt, 0) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(stmt, 0) : -1;
    h->version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    h->schema_ok = schema && schema_len >= 0 &&
        consensus_state_source_receipt_schema_version(
            schema, (size_t)schema_len, &h->version);
}

static bool cand_receipt_blobs_copy(
    sqlite3_stmt *stmt, struct consensus_state_source_receipt *receipt)
{
    return blob32_copy(stmt, 1, receipt->source_epoch_digest) &&
           blob32_copy(stmt, 2, receipt->source_tree_root) &&
           blob32_copy(stmt, 3, receipt->running_binary_digest) &&
           blob32_copy(stmt, 4, receipt->toolchain_digest) &&
           blob32_copy(stmt, 5, receipt->build_inputs_digest) &&
           blob32_copy(stmt, 6, receipt->chain_corpus_digest);
}

static bool cand_receipt_scalars_typed(sqlite3_stmt *stmt)
{
    return sqlite3_column_type(stmt, 7) == SQLITE_INTEGER &&
           (sqlite3_column_int(stmt, 7) == 0 ||
            sqlite3_column_int(stmt, 7) == 1) &&
           sqlite3_column_type(stmt, 8) == SQLITE_INTEGER &&
           (sqlite3_column_int(stmt, 8) == CONSENSUS_STATE_VALIDATION_FULL ||
            sqlite3_column_int(stmt, 8) ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD);
}

static bool cand_receipt_bound(
    const struct consensus_state_source_receipt *receipt,
    const struct consensus_state_bundle_manifest *m)
{
    uint8_t digest[32], source_epoch[32];
    consensus_state_source_epoch_digest(receipt, source_epoch);
    consensus_state_source_receipt_digest(receipt, digest);
    return receipt->fold_cursor == m->source_fold_cursor &&
           receipt->source_clean == m->source_clean &&
           receipt->validation_profile == m->validation_profile &&
           memcmp(source_epoch, receipt->source_epoch_digest, 32) == 0 &&
           memcmp(digest, receipt->receipt_digest, 32) == 0 &&
           memcmp(digest, m->source_digest, 32) == 0;
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
    struct cand_receipt_head head;
    cand_receipt_head_read(stmt, rc, &head);
    bool ok = rc == SQLITE_ROW && head.commit && head.schema_ok &&
        head.commit_type == SQLITE_TEXT && head.commit_len >= 0 &&
        consensus_state_source_receipt_commit_valid(
            head.version, head.commit, (size_t)head.commit_len) &&
        cand_receipt_blobs_copy(stmt, receipt) &&
        cand_receipt_scalars_typed(stmt) &&
        blob32_copy(stmt, 11, receipt->receipt_digest) &&
        sqlite3_column_type(stmt, 10) == SQLITE_INTEGER;
    if (ok) {
        receipt->schema_version = head.version;
        memcpy(receipt->producer_commit, head.commit, (size_t)head.commit_len);
        receipt->producer_commit[head.commit_len] = '\0';
        receipt->source_clean = sqlite3_column_int(stmt, 7) == 1;
        receipt->validation_profile = (uint8_t)sqlite3_column_int(stmt, 8);
        receipt->fold_cursor = sqlite3_column_int64(stmt, 10);
        ok = cand_receipt_bound(receipt, m) && step_done(stmt);
    }
    sqlite3_finalize(stmt);
    return ok;
}

static const char *const k_cand_proof_names[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    "header_admit", "validate_headers", "body_fetch", "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
};

static const bool k_cand_proof_hash_bound[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    true, true, true, false, true, true, true, false,
};

static bool cand_proof_types_ok(sqlite3_stmt *stmt)
{
    return sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 1) == SQLITE_TEXT &&
           sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 3) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 5) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 6) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 7) == SQLITE_BLOB;
}

static bool cand_proof_cursor_ok(size_t i, int64_t cursor, uint64_t minimum,
                                 uint64_t rows)
{
    return cursor >= 0 && (uint64_t)cursor >= minimum &&
           (i != 6 || (uint64_t)cursor == rows) &&
           (i != 7 || (uint64_t)cursor <= minimum + 1);
}

/* Reads proof row i and, when it matches the manifest, fills *proof. */
static bool cand_proof_row(sqlite3_stmt *stmt, size_t i,
                           const struct consensus_state_bundle_manifest *m,
                           uint64_t rows,
                           struct consensus_state_bundle_proof_summary *proof)
{
    if (sqlite3_step(stmt) != SQLITE_ROW) // raw-sql-ok:read-only-introspection
        return false;
    if (!cand_proof_types_ok(stmt))
        return false;
    int64_t cursor = sqlite3_column_int64(stmt, 2);
    uint64_t minimum = i == 7 ? (uint64_t)m->height : rows;
    if (!(sqlite3_column_int64(stmt, 0) == (sqlite3_int64)i &&
          consensus_state_sqlite_text_equal(stmt, 1, k_cand_proof_names[i]) &&
          cand_proof_cursor_ok(i, cursor, minimum, rows) &&
          sqlite3_column_int64(stmt, 3) == 0 &&
          sqlite3_column_int64(stmt, 4) == m->height &&
          sqlite3_column_int64(stmt, 5) == (sqlite3_int64)rows &&
          sqlite3_column_int64(stmt, 6) ==
              (sqlite3_int64)(k_cand_proof_hash_bound[i] ? rows : 0) &&
          blob32_copy(stmt, 7, proof->component_digest)))
        return false;
    snprintf(proof->component, sizeof(proof->component), "%s",
             k_cand_proof_names[i]);
    proof->cursor = (uint64_t)cursor;
    proof->first_height = 0;
    proof->last_height = m->height;
    proof->row_count = rows;
    proof->hash_bound_count = k_cand_proof_hash_bound[i] ? rows : 0;
    return true;
}

static bool candidate_proofs(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m,
    const struct consensus_state_source_receipt *receipt)
{
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
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++)
        ok = cand_proof_row(stmt, i, m, rows, &proofs[i]);
    if (ok)
        ok = step_done(stmt);
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

/* One coins row as stored, after the column types were checked. */
struct cand_coin {
    const uint8_t *txid, *script;
    int64_t vout, value, height;
    int script_size, txid_size, coinbase;
};

static bool cand_coin_types_ok(sqlite3_stmt *stmt)
{
    return sqlite3_column_type(stmt, 0) == SQLITE_BLOB &&
           sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 3) == SQLITE_BLOB &&
           sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 5) == SQLITE_INTEGER;
}

static void cand_coin_load(sqlite3_stmt *stmt, struct cand_coin *coin)
{
    coin->txid = sqlite3_column_blob(stmt, 0);
    coin->script = sqlite3_column_blob(stmt, 3);
    coin->vout = sqlite3_column_int64(stmt, 1);
    coin->value = sqlite3_column_int64(stmt, 2);
    coin->script_size = sqlite3_column_bytes(stmt, 3);
    coin->height = sqlite3_column_int64(stmt, 4);
    coin->coinbase = sqlite3_column_int(stmt, 5);
    coin->txid_size = sqlite3_column_bytes(stmt, 0);
}

static bool cand_coin_bad(const struct cand_coin *coin, int64_t supply,
                          uint64_t count, int32_t max_height)
{
    return !coin->txid || coin->txid_size != 32 || coin->vout < 0 ||
           coin->vout > UINT32_MAX || !MoneyRange(coin->value) ||
           supply > MAX_MONEY - coin->value || coin->script_size < 0 ||
           coin->script_size > MAX_SCRIPT_SIZE || coin->height < 0 ||
           coin->height > max_height ||
           (coin->coinbase != 0 && coin->coinbase != 1) ||
           count == UINT64_MAX;
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
        struct cand_coin coin;
        if (!cand_coin_types_ok(stmt)) {
            ok = false;
            break;
        }
        cand_coin_load(stmt, &coin);
        if (cand_coin_bad(&coin, supply, count, m->height)) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(
            &context, coin.txid, (uint32_t)coin.vout, coin.value,
            coin.script_size ? coin.script : NULL, (uint32_t)coin.script_size,
            (uint32_t)coin.height, (uint8_t)coin.coinbase);
        supply += coin.value;
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

/* Pre-identifies the per-pool MAX(height) anchor so the full
 * O(anchors x Pedersen-hash) recompute collapses to O(pools). Only the tip
 * rows carry consensus-load-bearing tree contents; historical rows get the
 * byte-integrity floor. Same boundary as the bulk import path
 * (chainstate_legacy_reader.c:376-378) and the source-bundle validator. */
static bool dest_anchor_tip_heights(sqlite3 *db, int64_t tip_height[2])
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
    return tq_ok;
}

/* One anchors row as stored, after the column types were checked. */
struct dest_anchor {
    int pool, tree_size, root_size;
    const uint8_t *root, *tree_blob;
    int64_t height;
};

static bool dest_anchor_types_ok(sqlite3_stmt *stmt)
{
    return sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 1) == SQLITE_BLOB &&
           sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 3) == SQLITE_BLOB;
}

static void dest_anchor_load(sqlite3_stmt *stmt, struct dest_anchor *a)
{
    a->pool = sqlite3_column_int(stmt, 0);
    a->root = sqlite3_column_blob(stmt, 1);
    a->height = sqlite3_column_int64(stmt, 2);
    a->tree_blob = sqlite3_column_blob(stmt, 3);
    a->tree_size = a->tree_blob ? sqlite3_column_bytes(stmt, 3) : 0;
    a->root_size = sqlite3_column_bytes(stmt, 1);
}

static bool dest_anchor_bad(const struct dest_anchor *a, uint64_t count,
                            int32_t max_height)
{
    return (a->pool != 0 && a->pool != 1) || !a->root ||
           a->root_size != 32 || !a->tree_blob || a->tree_size <= 0 ||
           a->height < 0 || a->height > max_height || count == UINT64_MAX;
}

/* Byte-integrity floor for EVERY row (torn/truncated/garbled/trailing bytes
 * are refused regardless of position). Recompute + bind the stored key ONLY
 * for the per-pool MAX(height) anchor; historical rows delegate root/key
 * agreement to the whole-file digest + this tip bind. */
static bool dest_anchor_tree_valid(const struct dest_anchor *a,
                                   const int64_t tip_height[2])
{
    struct incremental_merkle_tree tree;
    if (a->pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(&tree);
    else
        sapling_tree_init(&tree);
    struct byte_stream stream;
    stream_init_from_data(&stream, a->tree_blob, (size_t)a->tree_size);
    if (!incremental_tree_deserialize(&tree, &stream) ||
        stream_remaining(&stream) != 0)
        return false;
    if (a->height == tip_height[a->pool]) {
        struct uint256 computed;
        incremental_tree_root(&tree, &computed);
        if (memcmp(computed.data, a->root, 32) != 0)
            return false;
    }
    return true;
}

bool consensus_state_snapshot_destination_anchors_valid(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    int64_t tip_height[2] = {-1, -1};
    if (!dest_anchor_tip_heights(db, tip_height))
        return false;

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
        struct dest_anchor a;
        if (!dest_anchor_types_ok(stmt)) {
            ok = false;
            break;
        }
        dest_anchor_load(stmt, &a);
        if (dest_anchor_bad(&a, count, m->height) ||
            !dest_anchor_tree_valid(&a, tip_height)) {
            ok = false;
            break;
        }
        consensus_state_bundle_anchor_digest_row(
            &context, (uint8_t)a.pool, a.root, (uint64_t)a.height,
            a.tree_blob, (uint32_t)a.tree_size);
        if (a.height > frontier_height[a.pool]) {
            frontier_height[a.pool] = a.height;
            memcpy(frontier_root[a.pool], a.root, 32);
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

static bool dest_nullifier_types_ok(sqlite3_stmt *stmt)
{
    return sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
           sqlite3_column_type(stmt, 1) == SQLITE_BLOB &&
           sqlite3_column_type(stmt, 2) == SQLITE_INTEGER;
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
        if (!dest_nullifier_types_ok(stmt)) {
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

static bool cand_anchor_state(sqlite3 *db)
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
        ok = step_done(stmt);
    if (stmt)
        sqlite3_finalize(stmt);
    return ok;
}

static bool cand_progress_meta(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    uint8_t value[32];
    size_t size = 0;
#define META_EQ(key, length, expression) \
    (candidate_meta_value(db, (key), value, sizeof(value), &size) && \
     size == (length) && (expression))
    bool ok = META_EQ("coins_applied_height", 8,
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
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT count(*) FROM progress_meta", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    ok = sqlite3_step(stmt) == SQLITE_ROW && // raw-sql-ok:read-only-introspection
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == 6;
    sqlite3_finalize(stmt);
    return ok;
}

static bool cand_stage_cursors(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    static const char *const stages[] = {
        "body_fetch", "body_persist", "header_admit", "proof_validate",
        "script_validate", "tip_finalize", "utxo_apply", "validate_headers",
    };
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name,cursor,updated_at FROM stage_cursor ORDER BY name",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(stages) / sizeof(stages[0]); i++) {
        int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
        int64_t want = strcmp(stages[i], "tip_finalize") == 0
                           ? m->height : (int64_t)m->height + 1;
        ok = rc == SQLITE_ROW &&
             consensus_state_sqlite_text_equal(stmt, 0, stages[i]) &&
             int64_col_is(stmt, 1, want) && int64_col_is(stmt, 2, 0);
    }
    if (ok)
        ok = step_done(stmt);
    sqlite3_finalize(stmt);
    return ok;
}

static bool cand_utxo_apply_log(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height,status,ok,spent_count,added_count,total_value_delta,"
            "first_failure_kind,first_failure_detail,applied_at "
            "FROM utxo_apply_log", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         consensus_state_sqlite_text_equal(stmt, 1, "anchor") &&
         sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == m->height &&
         sqlite3_column_int(stmt, 2) == 1 &&
         int64_col_is(stmt, 3, 0) && int64_col_is(stmt, 4, 0) &&
         int64_col_is(stmt, 5, 0) &&
         sqlite3_column_type(stmt, 6) == SQLITE_NULL &&
         sqlite3_column_type(stmt, 7) == SQLITE_NULL &&
         int64_col_is(stmt, 8, 0) && step_done(stmt);
    sqlite3_finalize(stmt);
    return ok;
}

static bool cand_tip_finalize_log(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,tip_hash "
            "FROM tip_finalize_log", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
         sqlite3_column_type(stmt, 0) == SQLITE_INTEGER &&
         consensus_state_sqlite_text_equal(stmt, 1, "anchor") &&
         sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
         sqlite3_column_int64(stmt, 0) == m->height &&
         sqlite3_column_int(stmt, 2) == 1 &&
         int64_col_is(stmt, 3, 0) && int64_col_is(stmt, 4, 0) &&
         int64_col_is(stmt, 5, (sqlite3_int64)m->utxo_count) &&
         int64_col_is(stmt, 6, 0) && int64_col_is(stmt, 7, 0) &&
         blob32_equal(stmt, 8, m->block_hash) && step_done(stmt);
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_reducer_state(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m)
{
    return cand_anchor_state(db) && cand_progress_meta(db, m) &&
           cand_stage_cursors(db, m) && cand_utxo_apply_log(db, m) &&
           cand_tip_finalize_log(db, m);
}

static bool candidate_validate_header(
    sqlite3 *candidate, const struct consensus_state_bundle_manifest *expected,
    const uint8_t expected_admission_receipt[32],
    struct consensus_state_candidate_result *result)
{
    if (expected->format_version != CONSENSUS_STATE_BUNDLE_V1 &&
        expected->format_version != CONSENSUS_STATE_BUNDLE_V2)
        return candidate_invalid(result, "invalid bundle version");
    if (!candidate_integrity(candidate))
        return candidate_invalid(result, "integrity check failed");
    if (!candidate_closed_schema(candidate, expected->format_version))
        return candidate_invalid(result, "schema is not the closed set");
    if (!candidate_meta_matches(candidate, expected,
                                expected_admission_receipt) ||
        !candidate_v2_pools_match(candidate, expected))
        return candidate_invalid(result, "manifest/admission receipt mismatch");
    return true;
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
    if (!candidate_validate_header(candidate, expected, expected_admission_receipt, result))
        return false; // raw-return-ok:logged-by-callee
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
