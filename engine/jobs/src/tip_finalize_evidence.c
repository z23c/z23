/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Prove that tip-finalization authority comes from exact full
 * validation receipts or the exact durable trusted anchor. */

#include "tip_finalize_evidence.h"

#include "jobs/reducer_frontier.h"
#include "script_validate_log_store.h"
#include "platform/time_compat.h"
#include "tip_finalize_log_store.h"
#include "utxo_apply_log_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define TF_EVIDENCE_BLOCKER_ID "tip_finalize.validation_evidence"

static int tip_finalize_chain_utxo_evidence_at(
    sqlite3 *db, int height, const struct uint256 *block_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT h.hash,v.ok,v.hash,u.ok,u.status,d.branch_hash "
            "FROM header_admit_log h "
            "JOIN validate_headers_log v ON v.height=h.height "
            "JOIN utxo_apply_log u ON u.height=h.height "
            "JOIN utxo_apply_delta d ON d.height=h.height "
            "WHERE h.height=?", -1, &st, NULL) != SQLITE_OK) {
        LOG_ERR("tip_finalize", "chain/UTXO evidence prepare failed: %s",
                sqlite3_errmsg(db));
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    int exact = 0;
    if (rc == SQLITE_ROW) {
        const void *admit = sqlite3_column_type(st, 0) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        const void *validated = sqlite3_column_type(st, 2) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 2) : NULL;
        const void *status = sqlite3_column_type(st, 4) == SQLITE_TEXT
            ? sqlite3_column_text(st, 4) : NULL;
        const void *delta = sqlite3_column_type(st, 5) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 5) : NULL;
        bool verified = status && mint_validation_evidence_parse(
            status, (size_t)sqlite3_column_bytes(st, 4)) ==
            MINT_VALIDATION_EVIDENCE_VERIFIED;
        exact = block_hash && admit && validated && delta &&
            sqlite3_column_bytes(st, 0) == 32 &&
            sqlite3_column_type(st, 1) == SQLITE_INTEGER &&
            sqlite3_column_int(st, 1) == 1 &&
            sqlite3_column_bytes(st, 2) == 32 &&
            sqlite3_column_type(st, 3) == SQLITE_INTEGER &&
            sqlite3_column_int(st, 3) == 1 && verified &&
            sqlite3_column_bytes(st, 5) == 32 &&
            memcmp(admit, block_hash->data, 32) == 0 &&
            memcmp(validated, block_hash->data, 32) == 0 &&
            memcmp(delta, block_hash->data, 32) == 0;
        rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_DONE)
            exact = -1;
    } else if (rc != SQLITE_DONE) {
        exact = -1;
    }
    sqlite3_finalize(st);
    return exact;
}

int tip_finalize_full_evidence_at(sqlite3 *db, int height,
                                  const struct uint256 *block_hash)
{
    struct script_validate_verdict_row script;
    struct proof_validate_row proof;
    int sr = script_validate_log_verdict_at(db, height, &script);
    int pr = utxo_apply_proof_validate_log_at(db, height, &proof);
    int cr = tip_finalize_chain_utxo_evidence_at(db, height, block_hash);
    if (sr < 0 || pr < 0 || cr < 0)
        LOG_ERR("tip_finalize",
                "validation evidence read failed h=%d script=%d proof=%d "
                "chain_utxo=%d", height, sr, pr, cr);
    if (sr != 1 || pr != 1 || cr != 1 || !block_hash)
        return 0;
    return script.ok == 1 && proof.ok == 1 &&
           script.evidence == MINT_VALIDATION_EVIDENCE_VERIFIED &&
           proof.evidence == MINT_VALIDATION_EVIDENCE_VERIFIED &&
           script.has_block_hash && proof.has_block_hash &&
           uint256_eq(&script.block_hash, block_hash) &&
           uint256_eq(&proof.block_hash, block_hash);
}

/* The in-memory BLOCK_VALID_SCRIPTS bit can drift clear after restore. The
 * durable row is authoritative only when it is exact full-validation evidence
 * bound to the selected block hash. */
int tip_finalize_script_evidence_at(sqlite3 *db, int height,
                                    const struct uint256 *block_hash)
{
    if (!db || !block_hash)
        return 0;
    struct script_validate_verdict_row row;
    if (script_validate_log_verdict_at(db, height, &row) != 1)
        return 0;
    return row.ok == 1 &&
           row.evidence == MINT_VALIDATION_EVIDENCE_VERIFIED &&
           row.has_block_hash && uint256_eq(&row.block_hash, block_hash);
}

int tip_finalize_trusted_anchor_at(sqlite3 *db, int height,
                                   const struct uint256 *block_hash)
{
    if (!db || height < 0 || !block_hash)
        return 0;
    struct finalized_tip_row row;
    if (!finalized_tip_row_at(db, height, &row))
        LOG_ERR("tip_finalize", "trusted anchor row read failed h=%d", height);
    bool row_hash_match = row.has_tip_hash &&
                          uint256_eq(&row.tip_hash, block_hash);
    /* This predicate is intentionally attempted for every successor before
     * the full-validation path.  A missing/non-anchor row is therefore the
     * normal case, not an anomaly: logging it once per distinct height turns
     * a fast fold into an O(delta) warning storm.  Keep diagnostics for the
     * only surprising case below — a row that claims to be the anchor but
     * disagrees with the trusted-base metadata. */
    if (!row.found || !row.ok || !row.is_anchor || !row.has_tip_hash ||
        !row_hash_match)
        return 0;
    uint8_t hash_blob[32] = {0};
    int32_t trusted_height = -1;
    bool trusted_found = false;
    if (!reducer_frontier_trusted_base_read(
            db, &trusted_height, hash_blob, &trusted_found))
        LOG_ERR("tip_finalize", "trusted base metadata read failed h=%d",
                height);
    bool height_match = trusted_found && trusted_height == height;
    bool hash_match = trusted_found &&
                      memcmp(hash_blob, block_hash->data,
                             sizeof(hash_blob)) == 0;
    if (!height_match || !hash_match) {
        static struct log_throttle meta_throttle = LOG_THROTTLE_INIT;
        uint64_t repeats = 0;
        if (log_throttle_should_emit(&meta_throttle,
                                     (uint64_t)(uint32_t)height,
                                     platform_time_wall_unix(), 300,
                                     &repeats))
            LOG_WARN("tip_finalize",
                     "trusted anchor metadata mismatch h=%d "
                     "trusted_found=%d trusted_height=%d hash_match=%d "
                     "repeats=%llu",
                     height, trusted_found ? 1 : 0, trusted_height,
                     hash_match ? 1 : 0,
                     (unsigned long long)repeats);
    }
    return height_match && hash_match;
}

job_result_t tip_finalize_evidence_refuse(
    struct stage_step_ctx *ctx, int height,
    enum mint_validation_evidence utxo_evidence)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d cannot finalize: utxo evidence=%s and exact verified "
             "script/proof receipts for the selected block are required; "
             "checkpoint, missing, legacy, or foreign evidence stays contained",
             height, mint_validation_evidence_status(utxo_evidence));
    if (!ctx || !blocker_init(&ctx->blocker, TF_EVIDENCE_BLOCKER_ID,
                              "tip_finalize", BLOCKER_DEPENDENCY, reason))
        return JOB_FATAL;
    snprintf(ctx->blocker.escape_action, sizeof(ctx->blocker.escape_action),
             "replay script/proof/utxo validation for the selected block");
    ctx->blocker.retry_budget = -1;
    return JOB_BLOCKED;
}

void tip_finalize_evidence_clear(void)
{
    blocker_clear(TF_EVIDENCE_BLOCKER_ID);
}
