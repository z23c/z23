/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Build a contained, immutable progress-store candidate from one
 * already-admitted complete consensus-state bundle.  This unit cannot select
 * or replace the active progress.kv generation. */

#define _GNU_SOURCE

#include "config/consensus_state_snapshot_install.h"

#include "base/serialize_le.h"

#include "consensus_state_snapshot_install_internal.h"
#include "jobs/reducer_frontier.h"
#include "services/nullifier_backfill_service.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANDIDATE_SUBSYS "consensus_state_candidate"

bool consensus_state_candidate_fail(
    struct consensus_state_candidate_result *result,
    enum consensus_state_candidate_status status,
    const char *fmt, ...)
{
    char reason[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = status;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    LOG_WARN(CANDIDATE_SUBSYS, "%s", reason);
    return false;
}

static bool candidate_failpoint_valid(
    enum consensus_state_candidate_failpoint failpoint)
{
    return failpoint >= CONSENSUS_CANDIDATE_FAIL_NONE &&
           failpoint <= CONSENSUS_CANDIDATE_FAIL_AFTER_REOPEN;
}

static bool candidate_exec(sqlite3 *db, const char *sql, const char *label)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK)
        LOG_WARN(CANDIDATE_SUBSYS, "%s failed: %s", label,
                 error ? error : sqlite3_errmsg(db));
    if (error)
        sqlite3_free(error);
    return rc == SQLITE_OK;
}

static bool candidate_create_schema(sqlite3 *db)
{
    static const char schema[] =
        "CREATE TABLE consensus_state_candidate_meta("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        "schema TEXT NOT NULL,height INTEGER NOT NULL,block_hash BLOB NOT NULL,"
        "history_complete INTEGER NOT NULL CHECK(history_complete=1),"
        "source_clean INTEGER NOT NULL CHECK(source_clean IN(0,1)),"
        "validation_profile INTEGER NOT NULL CHECK(validation_profile IN(1,2)),"
        "activation_boundary INTEGER NOT NULL CHECK(activation_boundary=0),"
        "utxo_root BLOB NOT NULL,utxo_count INTEGER NOT NULL,"
        "total_supply INTEGER NOT NULL,anchor_digest BLOB NOT NULL,"
        "anchor_count INTEGER NOT NULL,sprout_frontier_root BLOB NOT NULL,"
        "sprout_frontier_height INTEGER NOT NULL,"
        "sapling_frontier_root BLOB NOT NULL,"
        "sapling_frontier_height INTEGER NOT NULL,"
        "nullifier_digest BLOB NOT NULL,nullifier_count INTEGER NOT NULL,"
        "sprout_source_cursor INTEGER NOT NULL CHECK(sprout_source_cursor=0),"
        "sapling_source_cursor INTEGER NOT NULL CHECK(sapling_source_cursor=0),"
        "nullifier_source_cursor INTEGER NOT NULL CHECK(nullifier_source_cursor=0),"
        "source_fold_cursor INTEGER NOT NULL,proof_manifest_digest BLOB NOT NULL,"
        "source_digest BLOB NOT NULL,artifact_digest BLOB NOT NULL,"
        "admission_receipt_digest BLOB NOT NULL);"
        "CREATE TABLE consensus_state_source_receipt("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,"
        "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
        "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
        "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
        "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
        "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
        "receipt_digest BLOB NOT NULL);"
        "CREATE TABLE consensus_state_bundle_proof("
        "ordinal INTEGER PRIMARY KEY,component TEXT NOT NULL UNIQUE,"
        "cursor INTEGER NOT NULL,first_height INTEGER NOT NULL,"
        "last_height INTEGER NOT NULL,row_count INTEGER NOT NULL,"
        "hash_bound_count INTEGER NOT NULL,component_digest BLOB NOT NULL);"
        "CREATE TABLE coins("
        "txid BLOB NOT NULL,vout INTEGER NOT NULL,value INTEGER NOT NULL,"
        "height INTEGER NOT NULL,is_coinbase INTEGER NOT NULL,script BLOB NOT NULL,"
        "PRIMARY KEY(txid,vout)) WITHOUT ROWID;"
        "CREATE TABLE sprout_anchors("
        "anchor BLOB PRIMARY KEY NOT NULL,height INTEGER NOT NULL,"
        "tree BLOB NOT NULL) WITHOUT ROWID;"
        "CREATE INDEX idx_sprout_anchors_height ON sprout_anchors(height);"
        "CREATE TABLE sapling_anchors("
        "anchor BLOB PRIMARY KEY NOT NULL,height INTEGER NOT NULL,"
        "tree BLOB NOT NULL) WITHOUT ROWID;"
        "CREATE INDEX idx_sapling_anchors_height ON sapling_anchors(height);"
        "CREATE TABLE anchor_state("
        "pool INTEGER PRIMARY KEY NOT NULL,activation_cursor INTEGER NOT NULL,"
        "CHECK(typeof(pool)='integer' AND pool IN(0,1)),"
        "CHECK(typeof(activation_cursor)='integer' AND activation_cursor>=0))"
        " WITHOUT ROWID;"
        "CREATE TABLE nullifiers("
        "nf BLOB NOT NULL,pool INTEGER NOT NULL,height INTEGER NOT NULL,"
        "PRIMARY KEY(nf,pool)) WITHOUT ROWID;"
        "CREATE INDEX idx_nullifiers_height ON nullifiers(height);"
        "CREATE TABLE progress_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);"
        "CREATE TABLE stage_cursor("
        "name TEXT PRIMARY KEY,cursor INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE TABLE utxo_apply_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "spent_count INTEGER NOT NULL,added_count INTEGER NOT NULL,"
        "total_value_delta INTEGER NOT NULL,first_failure_kind TEXT,"
        "first_failure_detail BLOB,applied_at INTEGER NOT NULL);"
        "CREATE TABLE tip_finalize_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "work_delta_high INTEGER NOT NULL,work_delta_low INTEGER NOT NULL,"
        "utxo_size_after INTEGER NOT NULL,reorg_depth INTEGER NOT NULL,"
        "finalized_at INTEGER NOT NULL,tip_hash BLOB);";
    return candidate_exec(db, schema, "candidate closed schema");
}

static bool bind_source_column(sqlite3_stmt *destination, int destination_col,
                               sqlite3_stmt *source, int source_col)
{
    switch (sqlite3_column_type(source, source_col)) {
    case SQLITE_INTEGER:
        return sqlite3_bind_int64(destination, destination_col,
                                  sqlite3_column_int64(source, source_col)) ==
               SQLITE_OK;
    case SQLITE_TEXT:
        return sqlite3_bind_text(destination, destination_col,
                                 (const char *)sqlite3_column_text(
                                     source, source_col),
                                 sqlite3_column_bytes(source, source_col),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(source, source_col);
        /* sqlite3_column_blob() may return NULL for a zero-length BLOB.  A
         * NULL pointer passed to sqlite3_bind_blob() binds SQL NULL, which
         * changes the value's type and violates NOT NULL script columns. */
        if (bytes == 0)
            return sqlite3_bind_zeroblob(destination, destination_col, 0) ==
                   SQLITE_OK;
        const void *blob = sqlite3_column_blob(source, source_col);
        return blob &&
               sqlite3_bind_blob(destination, destination_col, blob, bytes,
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    }
    case SQLITE_NULL:
        return sqlite3_bind_null(destination, destination_col) == SQLITE_OK;
    default:
        return false;
    }
}

static bool stream_copy(sqlite3 *source, sqlite3 *destination,
                        const char *select_sql, const char *insert_sql,
                        int columns, uint64_t *rows_out)
{
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    bool ok = sqlite3_prepare_v2(source, select_sql, -1, &read, NULL) ==
                  SQLITE_OK &&
              sqlite3_prepare_v2(destination, insert_sql, -1, &write, NULL) ==
                  SQLITE_OK;
    uint64_t rows = 0;
    int rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        ok = sqlite3_reset(write) == SQLITE_OK &&
             sqlite3_clear_bindings(write) == SQLITE_OK;
        for (int i = 0; ok && i < columns; i++)
            ok = bind_source_column(write, i + 1, read, i);
        if (ok)
            ok = sqlite3_step(write) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
        if (ok && rows == UINT64_MAX)
            ok = false;
        if (ok)
            rows++;
    }
    if (ok)
        ok = rc == SQLITE_DONE;
    if (!ok)
        LOG_WARN(CANDIDATE_SUBSYS, "candidate row stream failed: source=%s destination=%s",
                 sqlite3_errmsg(source), sqlite3_errmsg(destination));
    if (read)
        sqlite3_finalize(read);
    if (write)
        sqlite3_finalize(write);
    if (rows_out)
        *rows_out = rows;
    return ok;
}

static bool candidate_copy_components(
    sqlite3 *source, sqlite3 *destination,
    const struct consensus_state_bundle_manifest *manifest,
    enum consensus_state_candidate_failpoint failpoint,
    struct consensus_state_candidate_result *result)
{
    uint64_t rows = 0;
    if (!stream_copy(source, destination,
            "SELECT txid,vout,value,height,is_coinbase,script "
            "FROM coins ORDER BY txid,vout",
            "INSERT INTO coins VALUES(?,?,?,?,?,?)", 6, &rows) ||
        rows != manifest->utxo_count)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate coin stream count mismatch");
    if (failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_COINS)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate coins");

    uint64_t sprout = 0, sapling = 0;
    if (!stream_copy(source, destination,
            "SELECT anchor,height,tree FROM anchors WHERE pool=0 ORDER BY anchor",
            "INSERT INTO sprout_anchors VALUES(?,?,?)", 3, &sprout) ||
        !stream_copy(source, destination,
            "SELECT anchor,height,tree FROM anchors WHERE pool=1 ORDER BY anchor",
            "INSERT INTO sapling_anchors VALUES(?,?,?)", 3, &sapling) ||
        sprout > UINT64_MAX - sapling ||
        sprout + sapling != manifest->anchor_count)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate anchor stream count mismatch");
    if (failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_ANCHORS)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate anchors");

    if (!stream_copy(source, destination,
            "SELECT nf,pool,height FROM nullifiers ORDER BY pool,nf",
            "INSERT INTO nullifiers VALUES(?,?,?)", 3, &rows) ||
        rows != manifest->nullifier_count)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate nullifier stream count mismatch");
    if (failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_NULLIFIERS)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate nullifiers");

    if (!stream_copy(source, destination,
            "SELECT singleton,schema,source_epoch_digest,source_tree_root,"
            "running_binary_digest,toolchain_digest,build_inputs_digest,"
            "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
            "fold_cursor,receipt_digest FROM source_receipt ORDER BY singleton",
            "INSERT INTO consensus_state_source_receipt VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            13, &rows) || rows != 1 ||
        !stream_copy(source, destination,
            "SELECT ordinal,component,cursor,first_height,last_height,row_count,"
            "hash_bound_count,component_digest FROM bundle_proof ORDER BY ordinal",
            "INSERT INTO consensus_state_bundle_proof VALUES(?,?,?,?,?,?,?,?)",
            8, &rows) || rows != CONSENSUS_STATE_BUNDLE_PROOF_COUNT)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate provenance stream mismatch");
    return true;
}

static bool insert_meta_blob(sqlite3 *db, const char *key,
                             const void *value, size_t value_size)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = value_size <= INT_MAX &&
        sqlite3_prepare_v2(db,
            "INSERT INTO progress_meta(key,value) VALUES(?,?)",
            -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(stmt, 2, value, (int)value_size,
                          SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (stmt)
        sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_write_control(
    sqlite3 *db, const struct consensus_state_bundle_manifest *manifest,
    const uint8_t admission_receipt[32])
{
    sqlite3_stmt *stmt = NULL;
    static const char meta_sql[] =
        "INSERT INTO consensus_state_candidate_meta VALUES(1,"
        "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    bool ok = sqlite3_prepare_v2(db, meta_sql, -1, &stmt, NULL) == SQLITE_OK;
    int i = 1;
#define CANDIDATE_BIND(call) do { if (ok) ok = (call) == SQLITE_OK; } while (0)
    CANDIDATE_BIND(sqlite3_bind_text(stmt, i++,
        CONSENSUS_STATE_CANDIDATE_SCHEMA, -1, SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int(stmt, i++, manifest->height));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->block_hash, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int(stmt, i++, 1));
    CANDIDATE_BIND(sqlite3_bind_int(stmt, i++, manifest->source_clean ? 1 : 0));
    CANDIDATE_BIND(sqlite3_bind_int(stmt, i++, manifest->validation_profile));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++, 0));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->utxo_root, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
                                      (sqlite3_int64)manifest->utxo_count));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++, manifest->total_supply));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->anchor_digest, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
                                      (sqlite3_int64)manifest->anchor_count));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++,
        manifest->sprout_frontier_root, 32, SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
        manifest->sprout_frontier_height));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++,
        manifest->sapling_frontier_root, 32, SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
        manifest->sapling_frontier_height));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->nullifier_digest, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
                                      (sqlite3_int64)manifest->nullifier_count));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++, 0));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++, 0));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++, 0));
    CANDIDATE_BIND(sqlite3_bind_int64(stmt, i++,
                                      manifest->source_fold_cursor));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++,
        manifest->proof_manifest_digest, 32, SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->source_digest, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, manifest->artifact_digest, 32,
                                     SQLITE_STATIC));
    CANDIDATE_BIND(sqlite3_bind_blob(stmt, i++, admission_receipt, 32,
                                     SQLITE_STATIC));
    if (ok)
        ok = sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (stmt)
        sqlite3_finalize(stmt);
#undef CANDIDATE_BIND

    uint8_t applied_height[8], trusted_height[8];
    uint8_t one = 1;
    uint8_t zero_text = '0';
    zcl_write_i64_le(applied_height, (int64_t)manifest->height + 1);
    zcl_write_i64_le(trusted_height, manifest->height);
    ok = ok && candidate_exec(db,
        "INSERT INTO anchor_state VALUES(0,0),(1,0)",
        "candidate anchor completeness") &&
        insert_meta_blob(db, COINS_APPLIED_HEIGHT_KEY,
                         applied_height, sizeof(applied_height)) &&
        insert_meta_blob(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) &&
        insert_meta_blob(db, COINS_KV_SELF_FOLDED_KEY, &one, 1) &&
        insert_meta_blob(db, NULLIFIER_BACKFILL_ACTIVATION_KEY,
                         &zero_text, 1) &&
        insert_meta_blob(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                         trusted_height, sizeof(trusted_height)) &&
        insert_meta_blob(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                         manifest->block_hash, 32);
    if (!ok)
        return false;

    static const char *const stages[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0)",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    for (size_t stage = 0; ok && stage < sizeof(stages) / sizeof(stages[0]);
         stage++) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_int64 cursor = stage == 7 ? manifest->height
                                          : (sqlite3_int64)manifest->height + 1;
        ok = sqlite3_bind_text(stmt, 1, stages[stage], -1, SQLITE_STATIC) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(stmt, 2, cursor) == SQLITE_OK &&
             sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (!ok || manifest->utxo_count > INT64_MAX)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_log VALUES(?,'anchor',1,0,0,0,NULL,NULL,0)",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    ok = sqlite3_bind_int(stmt, 1, manifest->height) == SQLITE_OK &&
         sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (ok)
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO tip_finalize_log VALUES(?,'anchor',1,0,0,?,0,0,?)",
            -1, &stmt, NULL) == SQLITE_OK &&
             sqlite3_bind_int(stmt, 1, manifest->height) == SQLITE_OK &&
             sqlite3_bind_int64(stmt, 2,
                                (sqlite3_int64)manifest->utxo_count) == SQLITE_OK &&
             sqlite3_bind_blob(stmt, 3, manifest->block_hash, 32,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (stmt)
        sqlite3_finalize(stmt);
    return ok;
}

bool consensus_state_snapshot_candidate_build(
    const struct consensus_state_artifact_evidence *evidence,
    const struct consensus_state_candidate_request *request,
    struct consensus_state_candidate_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
    if (!evidence || !request || !result ||
        !candidate_failpoint_valid(request->failpoint))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate build arguments/failpoint are invalid");
    struct consensus_state_bundle_manifest manifest;
    uint8_t admission_receipt[32];
    sqlite3 *source = NULL;
    if (!consensus_state_artifact_evidence_candidate_lease_begin(
            evidence, &manifest, admission_receipt, &source))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate artifact evidence is stale");
    if (!manifest.history_complete || manifest.activation_boundary != 0 ||
        manifest.sprout_source_cursor != 0 ||
        manifest.sapling_source_cursor != 0 ||
        manifest.nullifier_source_cursor != 0 ||
        manifest.source_fold_cursor != (int64_t)manifest.height + 1) {
        bool refused = consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate requires complete genesis-derived shielded history");
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return refused;
    }

    struct consensus_state_candidate_output *output = zcl_calloc(
        1, sizeof(*output), "consensus_state_candidate_output");
    if (!output) {
        bool failed = consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate output binding allocation failed");
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return failed;
    }
    if (!consensus_state_candidate_output_open(request, output, result)) {
        free(output);
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return false; // raw-return-ok:logged-by-callee
    }
    bool ok = true;
    sqlite3 *destination = NULL;
    bool transaction = false;
    if (!consensus_state_candidate_output_sqlite_open(output, &destination)) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate SQLite staging open failed");
        ok = false;
    }
    if (ok && request->failpoint ==
                  CONSENSUS_CANDIDATE_FAIL_AFTER_STAGING_OPEN) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate staging open");
        ok = false;
    }
    if (ok && !candidate_exec(destination, "BEGIN IMMEDIATE",
                              "candidate transaction begin")) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate transaction begin failed");
        ok = false;
    } else if (ok) {
        transaction = true;
    }
    if (ok && !candidate_create_schema(destination)) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate closed schema creation failed");
        ok = false;
    }
    if (ok && request->failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_SCHEMA) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate schema");
        ok = false;
    }
    if (ok)
        ok = candidate_copy_components(source, destination, &manifest,
                                       request->failpoint, result);
    if (ok && !candidate_write_control(destination, &manifest,
                                       admission_receipt)) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate control/provenance write failed");
        ok = false;
    }
    if (ok && request->failpoint ==
                  CONSENSUS_CANDIDATE_FAIL_AFTER_PROVENANCE) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate provenance");
        ok = false;
    }
    if (transaction) {
        if (!candidate_exec(destination, ok ? "COMMIT" : "ROLLBACK",
                            ok ? "candidate commit" : "candidate rollback")) {
            if (ok)
                (void)consensus_state_candidate_fail(
                    result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
                    "candidate transaction close failed");
            ok = false;
            (void)candidate_exec(destination, "ROLLBACK",
                                 "candidate rollback retry");
        }
        transaction = false;
    }
    if (ok && request->failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_COMMIT) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate commit");
        ok = false;
    }
    if (!consensus_state_candidate_sqlite_close_strict(output,
                                                        &destination)) {
        if (ok)
            (void)consensus_state_candidate_fail(
                result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
                "candidate strict close failed");
        ok = false;
    }
    if (ok && !consensus_state_artifact_evidence_revalidate(evidence)) {
        (void)consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate source evidence changed during stream");
        ok = false;
    }
    if (ok)
        ok = consensus_state_candidate_output_finalize(
            output, &manifest, admission_receipt, request->failpoint, result);
    if (!ok) {
        consensus_state_candidate_output_cleanup(output);
        if (!output->binding.abandon_on_close)
            free(output);
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return false;
    }

    result->status = CONSENSUS_CANDIDATE_VERIFIED_CONTAINED;
    result->source_clean = manifest.source_clean;
    result->validation_profile = manifest.validation_profile;
    result->height = manifest.height;
    result->utxo_count = manifest.utxo_count;
    result->anchor_count = manifest.anchor_count;
    result->nullifier_count = manifest.nullifier_count;
    memcpy(result->artifact_digest, manifest.artifact_digest, 32);
    snprintf(result->reason, sizeof(result->reason),
             "built immutable contained %s height=%d source=%s profile=%s; "
             "active generation unchanged",
             CONSENSUS_STATE_CANDIDATE_SCHEMA, manifest.height,
             manifest.source_clean ? "clean" : "dirty",
             manifest.validation_profile == CONSENSUS_STATE_VALIDATION_FULL
                 ? "full" : "checkpoint_fold");
    consensus_state_candidate_output_cleanup(output);
    if (!output->binding.abandon_on_close)
        free(output);
    consensus_state_artifact_evidence_candidate_lease_end(evidence);
    return true;
}
