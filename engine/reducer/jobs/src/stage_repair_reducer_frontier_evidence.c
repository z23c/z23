/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Read hash- and profile-bound reducer evidence for safe repairs. */
// repair-rung-ok:test_reducer_frontier

#include "stage_repair_reducer_frontier_evidence.h"

#include "jobs/mint_skip_crypto.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

void rf_evidence_stmts_finalize(struct rf_evidence_stmts *es)
{
    sqlite3_finalize(es->validate_hash);
    sqlite3_finalize(es->script_hash);
    sqlite3_finalize(es->body_ok);
    sqlite3_finalize(es->proof_ok);
    sqlite3_finalize(es->utxo_ok);
    memset(es, 0, sizeof(*es));
}

bool rf_evidence_stmts_prepare(sqlite3 *db, struct rf_evidence_stmts *es)
{
    memset(es, 0, sizeof(*es));
    if (sqlite3_prepare_v2(db,
            "SELECT ok, hash FROM validate_headers_log WHERE height = ?",
            -1, &es->validate_hash, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT ok, block_hash, status FROM script_validate_log "
            "WHERE height = ?", -1, &es->script_hash, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT ok FROM body_persist_log WHERE height = ?",
            -1, &es->body_ok, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT ok, block_hash, status FROM proof_validate_log "
            "WHERE height = ?",
            -1, &es->proof_ok, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT u.ok,d.branch_hash,u.status FROM utxo_apply_log u "
            "LEFT JOIN utxo_apply_delta d ON d.height=u.height "
            "WHERE u.height = ?",
            -1, &es->utxo_ok, NULL) == SQLITE_OK)
        return true;

    LOG_WARN("stage_repair", "[stage_repair] evidence stmt prepare failed: %s",
             sqlite3_errmsg(db));
    rf_evidence_stmts_finalize(es);
    return false;
}

static bool log_ok_unlocked(sqlite3_stmt *st, const char *table, int height,
                            bool *found, bool *ok)
{
    *found = false;
    *ok = false;
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, height);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *found = true;
        *ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1;
        if (*ok && (strcmp(table, "proof_validate_log") == 0 ||
                    strcmp(table, "utxo_apply_log") == 0)) {
            int status_type = sqlite3_column_type(st, 1);
            const void *status = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 1) : NULL;
            *ok = status &&
                mint_validation_evidence_parse(
                    status, (size_t)sqlite3_column_bytes(st, 1)) ==
                    MINT_VALIDATION_EVIDENCE_VERIFIED;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] log_ok step failed table=%s h=%d rc=%d: %s",
                 table, height, rc, sqlite3_errmsg(sqlite3_db_handle(st)));
        return false;
    }
    return true;
}

static bool hash_log_ok_matches_unlocked(sqlite3_stmt *st, const char *table,
                                         int height,
                                         const struct uint256 *want,
                                         bool *matches)
{
    *matches = false;
    if (!want)
        return true;
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, height);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int row_ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER
            ? sqlite3_column_int(st, 0) : -1;
        int hash_type = sqlite3_column_type(st, 1);
        const void *blob = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int blen = blob ? sqlite3_column_bytes(st, 1) : 0;
        bool profile_ok = true;
        if (strcmp(table, "script_validate_log") == 0 ||
            strcmp(table, "proof_validate_log") == 0 ||
            strcmp(table, "utxo_apply_log") == 0) {
            int status_type = sqlite3_column_type(st, 2);
            const void *status = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 2) : NULL;
            profile_ok = status &&
                mint_validation_evidence_parse(
                    status, (size_t)sqlite3_column_bytes(st, 2)) ==
                    MINT_VALIDATION_EVIDENCE_VERIFIED;
        }
        if (row_ok == 1 && profile_ok && blob && blen == 32 &&
            memcmp(blob, want->data, 32) == 0)
            *matches = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] hash_log step failed table=%s h=%d rc=%d: %s",
                 table, height, rc, sqlite3_errmsg(sqlite3_db_handle(st)));
        return false;
    }
    return true;
}

bool rf_evidence_for_block_unlocked(struct rf_evidence_stmts *es,
                                    const struct block_index *bi,
                                    struct rf_log_evidence *ev)
{
    memset(ev, 0, sizeof(*ev));
    if (!bi || !bi->phashBlock)
        return true;
    if (!hash_log_ok_matches_unlocked(es->validate_hash,
                                      "validate_headers_log", bi->nHeight,
                                      bi->phashBlock, &ev->validate_ok_hash) ||
        !hash_log_ok_matches_unlocked(es->script_hash,
                                      "script_validate_log", bi->nHeight,
                                      bi->phashBlock, &ev->script_ok_hash))
        return false;

    bool found = false;
    if (!log_ok_unlocked(es->body_ok, "body_persist_log", bi->nHeight,
                         &found, &ev->body_ok))
        return false;
    ev->body_ok = found && ev->body_ok;
    if (!hash_log_ok_matches_unlocked(es->proof_ok,
                                      "proof_validate_log", bi->nHeight,
                                      bi->phashBlock, &ev->proof_ok_hash))
        return false;
    if (!hash_log_ok_matches_unlocked(es->utxo_ok,
                                      "utxo_apply_log", bi->nHeight,
                                      bi->phashBlock, &ev->utxo_ok_hash))
        return false;
    return true;
}

bool rf_utxo_branch_evidence_at(sqlite3 *db, int height,
                                const struct uint256 *want,
                                bool *row_present, bool *matches)
{
    if (!db || !want || !row_present || !matches)
        LOG_FAIL("stage_repair", "UTXO branch evidence: invalid argument");
    *row_present = false;
    *matches = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT d.branch_hash FROM utxo_apply_log u "
            "LEFT JOIN utxo_apply_delta d ON d.height=u.height "
            "WHERE u.height=?", -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair", "UTXO branch evidence prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    bool ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *row_present = true;
        int type = sqlite3_column_type(st, 0);
        const void *blob = type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        *matches = blob && sqlite3_column_bytes(st, 0) == 32 &&
                   memcmp(blob, want->data, 32) == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair", "UTXO branch evidence step failed h=%d: %s",
                 height, sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}
