/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only, node-free status projection for a consensus-state producer. */

#include "config/consensus_state_producer_receipt.h"

#include "base/bytes.h"
#include "storage/consensus_db.h"    /* consensus_db_kernel_store_path */
#include "storage/consensus_state_bundle_codec.h"
#include "storage/cure_progress_read.h"
#include "base/text_fit.h"

#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool status_set_err(char *err, size_t err_size, const char *msg)
{
    if (err && err_size)
        (void)zcl_text_fit(err, err_size, msg, "producer_status", "error");
    return false; /* raw-return-ok:bounded status reason returned to caller */
}

static bool status_set_sqlite_err(char *err, size_t err_size,
                                  sqlite3 *db, const char *operation)
{
    char why[256];
    snprintf(why, sizeof(why), "producer status: %s: %s", operation,
             db ? sqlite3_errmsg(db) : "sqlite handle unavailable");
    return status_set_err(err, err_size, why);
}

/* Every projection in one status response must describe the same durable
 * producer generation.  In WAL mode, an explicit read transaction pins the
 * snapshot established by the first SELECT while the producer keeps writing. */
static bool pkv_read_transaction(sqlite3 *db, const char *sql,
                                 const char *operation,
                                 char *err, size_t err_size)
{
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL); // raw-sql-ok:read-only-introspection
    if (rc != SQLITE_OK)
        return status_set_sqlite_err(err, err_size, db, operation);
    return true;
}

#ifdef ZCL_TESTING
static void (*g_status_after_first_cursor_hook)(void *ctx);
static void *g_status_after_first_cursor_ctx;

void consensus_state_producer_status_test_set_after_first_cursor_hook(
    void (*hook)(void *), void *ctx);

void consensus_state_producer_status_test_set_after_first_cursor_hook(
    void (*hook)(void *), void *ctx)
{
    g_status_after_first_cursor_hook = hook;
    g_status_after_first_cursor_ctx = ctx;
}
#endif

enum pkv_read_result {
    PKV_READ_ERROR = -1,
    PKV_READ_ABSENT = 0,
    PKV_READ_PRESENT = 1,
};

/* An old/empty progress.kv may legitimately predate a projection table. Once
 * a table exists, however, every read is strict: SQL errors and malformed
 * values are corruption/unreadability, never silently projected as absence. */
static bool pkv_table_exists(sqlite3 *db, const char *table, bool *exists,
                             char *err, size_t err_size)
{
    static const char sql[] =
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema "
        "WHERE type='table' AND name=?1)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema prepare");
    if (sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema bind");
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_INTEGER;
    int64_t value = ok ? sqlite3_column_int64(st, 0) : -1;
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (!ok || finalize_rc != SQLITE_OK || (value != 0 && value != 1))
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema result");
    *exists = value == 1;
    return true;
}

static enum pkv_read_result pkv_query_i64(sqlite3 *db, const char *table,
                                          const char *sql, int64_t *out,
                                          char *err, size_t err_size)
{
    bool table_present = false;
    if (!pkv_table_exists(db, table, &table_present, err, err_size))
        return PKV_READ_ERROR;
    if (!table_present)
        return PKV_READ_ABSENT;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db, "integer query prepare");
        return PKV_READ_ERROR;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        int finalize_rc = sqlite3_finalize(st);
        if (finalize_rc != SQLITE_OK) {
            status_set_sqlite_err(err, err_size, db,
                                  "integer query finalize");
            return PKV_READ_ERROR;
        }
        return PKV_READ_ABSENT;
    }
    if (rc != SQLITE_ROW || sqlite3_column_type(st, 0) != SQLITE_INTEGER) {
        sqlite3_finalize(st);
        status_set_err(err, err_size,
                       "producer status: integer projection is malformed");
        return PKV_READ_ERROR;
    }
    int64_t value = sqlite3_column_int64(st, 0);
    rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db, "integer query result");
        return PKV_READ_ERROR;
    }
    *out = value;
    return PKV_READ_PRESENT;
}

static void status_hex32(const uint8_t bytes[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[64] = '\0';
}

static bool pkv_rate_window_is_current(
    const struct producer_status_read *status,
    const struct cure_progress_sample *older,
    const struct cure_progress_sample *newer)
{
    if (!status || !older || !newer)
        return false;
    int64_t applied_height = status->receipt_finalized
        ? status->fold_cursor - 1
        : status->utxo_apply_cursor > 0
            ? status->utxo_apply_cursor - 1 : -1;
    if (newer->height != applied_height)
        return false;
    if (status->session_open) {
        /* Session start is microseconds while apply rows are whole seconds.
         * Flooring admits the first row written in the same wall-clock second
         * but rejects residual timing evidence from an earlier generation. */
        int64_t start_seconds = status->start_time_us / INT64_C(1000000);
        if (status->start_time_us <= 0 || older->time_unix < start_seconds ||
            newer->time_unix < start_seconds)
            return false;
    }
    return true;
}

#ifdef ZCL_TESTING
bool consensus_state_producer_status_rate_window_current_for_test(
    const struct producer_status_read *status,
    int64_t older_time_unix, int64_t newer_height,
    int64_t newer_time_unix);

bool consensus_state_producer_status_rate_window_current_for_test(
    const struct producer_status_read *status,
    int64_t older_time_unix, int64_t newer_height,
    int64_t newer_time_unix)
{
    const struct cure_progress_sample older = {
        .height = newer_height > 0 ? newer_height - 1 : 0,
        .time_unix = older_time_unix,
    };
    const struct cure_progress_sample newer = {
        .height = newer_height,
        .time_unix = newer_time_unix,
    };
    return pkv_rate_window_is_current(status, &older, &newer);
}
#endif

static bool status_schema_version(const char *schema, bool receipt,
                                  uint8_t *out_version)
{
    if (!schema || !out_version)
        return false;
    if (receipt)
        return consensus_state_source_receipt_schema_version(
            schema, strlen(schema), out_version);
    if (strcmp(schema, "zcl.consensus_state_producer_session.v1") == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
        return true;
    }
    if (strcmp(schema, "zcl.consensus_state_producer_session.v2") == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
        return true;
    }
    return false;
}

static bool status_copy_blob32(sqlite3_stmt *st, int column, uint8_t out[32])
{
    if (sqlite3_column_type(st, column) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, column) != 32)
        return false;
    const void *blob = sqlite3_column_blob(st, column);
    if (!blob)
        return false;
    memcpy(out, blob, 32);
    return true;
}

/* A receipt row is not a finalized receipt merely because `fold_cursor`
 * exists. Parse every authority-bearing field, require the cryptographic
 * claims to be nonzero, and reproduce both the source epoch and complete
 * receipt digest before exposing `receipt_finalized=true`. */
static enum pkv_read_result pkv_read_final_receipt(
    sqlite3 *db, struct producer_status_read *out,
    char *err, size_t err_size)
{
    static const char table[] = "consensus_state_source_receipt";
    static const char sql[] =
        "SELECT schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest FROM consensus_state_source_receipt "
        "WHERE singleton=1";
    bool table_present = false;
    if (!pkv_table_exists(db, table, &table_present, err, err_size))
        return PKV_READ_ERROR;
    if (!table_present)
        return PKV_READ_ABSENT;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db,
                              "finalized receipt prepare");
        return PKV_READ_ERROR;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        int finalize_rc = sqlite3_finalize(st);
        if (finalize_rc != SQLITE_OK) {
            status_set_sqlite_err(err, err_size, db,
                                  "finalized receipt finalize");
            return PKV_READ_ERROR;
        }
        return PKV_READ_ABSENT;
    }

    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    const unsigned char *schema = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_TEXT
        ? sqlite3_column_text(st, 0) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(st, 0) : -1;
    bool schema_ok = schema && schema_len > 0 &&
        (size_t)schema_len < sizeof(out->receipt_schema) &&
        memchr(schema, '\0', (size_t)schema_len) == NULL &&
        consensus_state_source_receipt_schema_version(
            (const char *)schema, (size_t)schema_len,
            &receipt.schema_version);
    char schema_copy[sizeof(out->receipt_schema)] = {0};
    if (schema_ok) {
        memcpy(schema_copy, schema, (size_t)schema_len);
        schema_copy[schema_len] = '\0';
    }
    const unsigned char *commit = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 9) == SQLITE_TEXT
        ? sqlite3_column_text(st, 9) : NULL;
    int commit_len = commit ? sqlite3_column_bytes(st, 9) : -1;
    bool commit_ok = commit && commit_len >= 0 &&
        (size_t)commit_len < sizeof(receipt.producer_commit) &&
        memchr(commit, '\0', (size_t)commit_len) == NULL &&
        consensus_state_source_receipt_commit_valid(
            receipt.schema_version, (const char *)commit,
            (size_t)commit_len);
    bool clean_ok = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
        (sqlite3_column_int(st, 7) == 0 ||
         sqlite3_column_int(st, 7) == 1);
    bool profile_ok = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
        (sqlite3_column_int(st, 8) == CONSENSUS_STATE_VALIDATION_FULL ||
         sqlite3_column_int(st, 8) ==
             CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD);
    bool cursor_ok = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 10) == SQLITE_INTEGER &&
        sqlite3_column_int64(st, 10) > 0 &&
        sqlite3_column_int64(st, 10) <= INT32_MAX;
    bool fields_ok = schema_ok && commit_ok && clean_ok && profile_ok &&
        cursor_ok && status_copy_blob32(st, 1,
                                        receipt.source_epoch_digest) &&
        status_copy_blob32(st, 2, receipt.source_tree_root) &&
        status_copy_blob32(st, 3, receipt.running_binary_digest) &&
        status_copy_blob32(st, 4, receipt.toolchain_digest) &&
        status_copy_blob32(st, 5, receipt.build_inputs_digest) &&
        status_copy_blob32(st, 6, receipt.chain_corpus_digest) &&
        status_copy_blob32(st, 11, receipt.receipt_digest);
    if (fields_ok) {
        receipt.source_clean = sqlite3_column_int(st, 7) == 1;
        receipt.validation_profile = (uint8_t)sqlite3_column_int(st, 8);
        memcpy(receipt.producer_commit, commit, (size_t)commit_len);
        receipt.producer_commit[commit_len] = '\0';
        receipt.fold_cursor = sqlite3_column_int64(st, 10);
        fields_ok = zcl_bytes_any_set(receipt.source_epoch_digest, 32) &&
            zcl_bytes_any_set(receipt.source_tree_root, 32) &&
            zcl_bytes_any_set(receipt.running_binary_digest, 32) &&
            zcl_bytes_any_set(receipt.toolchain_digest, 32) &&
            zcl_bytes_any_set(receipt.build_inputs_digest, 32) &&
            zcl_bytes_any_set(receipt.chain_corpus_digest, 32) &&
            zcl_bytes_any_set(receipt.receipt_digest, 32) &&
            (out->validation_profile < 0 ||
             out->validation_profile == receipt.validation_profile);
    }
    uint8_t recomputed_epoch[32] = {0};
    uint8_t recomputed_receipt[32] = {0};
    if (fields_ok) {
        consensus_state_source_epoch_digest(&receipt, recomputed_epoch);
        consensus_state_source_receipt_digest(&receipt, recomputed_receipt);
        fields_ok = memcmp(recomputed_epoch,
                           receipt.source_epoch_digest, 32) == 0 &&
                    memcmp(recomputed_receipt,
                           receipt.receipt_digest, 32) == 0;
    }
    rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db,
                              "finalized receipt result");
        return PKV_READ_ERROR;
    }
    if (!fields_ok) {
        status_set_err(err, err_size,
                       "producer status: finalized receipt is malformed or "
                       "fails digest verification");
        return PKV_READ_ERROR;
    }

    memcpy(out->receipt_schema, schema_copy, (size_t)schema_len + 1u);
    status_hex32(receipt.source_tree_root, out->source_tree_root);
    status_hex32(receipt.source_epoch_digest, out->source_epoch_digest);
    memcpy(out->producer_commit, receipt.producer_commit,
           (size_t)commit_len + 1u);
    out->validation_profile = receipt.validation_profile;
    out->fold_cursor = receipt.fold_cursor;
    out->receipt_finalized = true;
    return PKV_READ_PRESENT;
}

/* When no finalized receipt exists, expose the open session's bounded source
 * claim. This is progress telemetry only and never sets receipt_finalized. */
static bool pkv_read_session_identity(sqlite3 *db,
                                      struct producer_status_read *out,
                                      char *err, size_t err_size)
{
    static const struct {
        const char *table;
        const char *sql;
        bool receipt;
    } projections[] = {
        {
            "consensus_state_producer_session",
            "SELECT schema,source_tree_root,source_epoch_digest,producer_commit,"
            "toolchain_digest,build_inputs_digest,source_clean,validation_profile "
            "FROM consensus_state_producer_session WHERE singleton=1",
            false,
        },
    };
    for (size_t i = 0; i < sizeof(projections) / sizeof(projections[0]); i++) {
        bool table_present = false;
        if (!pkv_table_exists(db, projections[i].table, &table_present,
                              err, err_size))
            return false;
        if (!table_present)
            continue;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, projections[i].sql, -1, &st, NULL) !=
            SQLITE_OK)
            return status_set_sqlite_err(err, err_size, db,
                                         "source identity prepare");
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        if (rc == SQLITE_DONE) {
            int finalize_rc = sqlite3_finalize(st);
            if (finalize_rc != SQLITE_OK)
                return status_set_sqlite_err(err, err_size, db,
                                             "source identity finalize");
            continue;
        }
        const unsigned char *schema = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 0) == SQLITE_TEXT
            ? sqlite3_column_text(st, 0) : NULL;
        int schema_len = schema ? sqlite3_column_bytes(st, 0) : -1;
        const uint8_t *root = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 1) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 1) == 32
            ? sqlite3_column_blob(st, 1) : NULL;
        const uint8_t *epoch = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 2) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 2) == 32
            ? sqlite3_column_blob(st, 2) : NULL;
        const unsigned char *commit = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 3) == SQLITE_TEXT
            ? sqlite3_column_text(st, 3) : NULL;
        int commit_len = commit ? sqlite3_column_bytes(st, 3) : -1;
        const uint8_t *toolchain = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 4) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 4) == 32
            ? sqlite3_column_blob(st, 4) : NULL;
        const uint8_t *build_inputs = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 5) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 5) == 32
            ? sqlite3_column_blob(st, 5) : NULL;
        bool clean_ok = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 6) == SQLITE_INTEGER &&
            (sqlite3_column_int(st, 6) == 0 ||
             sqlite3_column_int(st, 6) == 1);
        bool profile_ok = rc == SQLITE_ROW &&
            sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
            (sqlite3_column_int(st, 7) == CONSENSUS_STATE_VALIDATION_FULL ||
             sqlite3_column_int(st, 7) ==
                 CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD);
        bool schema_ok = schema && schema_len > 0 &&
            (size_t)schema_len < sizeof(out->receipt_schema) &&
            memchr(schema, '\0', (size_t)schema_len) == NULL;
        uint8_t version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
        char schema_copy[sizeof(out->receipt_schema)];
        if (schema_ok) {
            memcpy(schema_copy, schema, (size_t)schema_len);
            schema_copy[schema_len] = '\0';
            schema_ok = status_schema_version(schema_copy,
                                              projections[i].receipt,
                                              &version);
        }
        bool commit_ok = commit && commit_len >= 0 &&
            (size_t)commit_len < sizeof(out->producer_commit) &&
            memchr(commit, '\0', (size_t)commit_len) == NULL &&
            consensus_state_source_receipt_commit_valid(
                version, (const char *)commit, (size_t)commit_len);
        struct consensus_state_source_receipt claim;
        memset(&claim, 0, sizeof(claim));
        bool claim_ok = schema_ok && root && epoch && toolchain &&
                        build_inputs && clean_ok && profile_ok &&
                        commit_ok && zcl_bytes_any_set(root, 32) &&
                        zcl_bytes_any_set(epoch, 32) &&
                        zcl_bytes_any_set(toolchain, 32) &&
                        zcl_bytes_any_set(build_inputs, 32);
        if (claim_ok) {
            claim.schema_version = version;
            memcpy(claim.source_tree_root, root, 32);
            memcpy(claim.source_epoch_digest, epoch, 32);
            memcpy(claim.toolchain_digest, toolchain, 32);
            memcpy(claim.build_inputs_digest, build_inputs, 32);
            memcpy(claim.producer_commit, commit, (size_t)commit_len);
            claim.producer_commit[commit_len] = '\0';
            claim.source_clean = sqlite3_column_int(st, 6) == 1;
            claim.validation_profile =
                (uint8_t)sqlite3_column_int(st, 7);
            uint8_t recomputed_epoch[32];
            consensus_state_source_epoch_digest(&claim, recomputed_epoch);
            claim_ok = memcmp(recomputed_epoch, epoch, 32) == 0 &&
                       (out->validation_profile < 0 ||
                        out->validation_profile == claim.validation_profile);
        }
        if (claim_ok) {
            memcpy(out->receipt_schema, schema, (size_t)schema_len);
            out->receipt_schema[schema_len] = '\0';
            status_hex32(root, out->source_tree_root);
            status_hex32(epoch, out->source_epoch_digest);
            memcpy(out->producer_commit, commit, (size_t)commit_len);
            out->producer_commit[commit_len] = '\0';
            out->validation_profile = claim.validation_profile;
            rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
            int finalize_rc = sqlite3_finalize(st);
            if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK)
                return status_set_sqlite_err(err, err_size, db,
                                             "source identity result");
            return true;
        }
        sqlite3_finalize(st);
        return status_set_err(err, err_size,
                              "producer status: source identity is malformed");
    }
    return true;
}

bool consensus_state_producer_status_read(const char *datadir,
                                          struct producer_status_read *out,
                                          char *err, size_t err_size)
{
    if (!out)
        return status_set_err(err, err_size, "producer status: null out");
    memset(out, 0, sizeof(*out));
    out->utxo_apply_cursor = -1;
    out->tip_finalize_cursor = -1;
    out->fold_cursor = -1;
    out->rate_older_height = -1;
    out->rate_older_time_unix = -1;
    out->rate_newer_height = -1;
    out->rate_newer_time_unix = -1;
    out->validation_profile = -1;
    if (!datadir || !datadir[0])
        return status_set_err(err, err_size, "producer status: empty datadir");
    if (strlen(datadir) >= CONSENSUS_STATE_PRODUCER_DATADIR_MAX)
        return status_set_err(err, err_size,
                              "producer status: datadir exceeds 1023 bytes");

    /* A4: read the kernel store — consensus.db post-flip, or the legacy
     * progress.kv on a pre-flip producer datadir. */
    char path[CONSENSUS_STATE_PRODUCER_DATADIR_MAX +
              sizeof("/consensus.db")];
    if (!consensus_db_kernel_store_path(datadir, path, sizeof(path)))
        return status_set_err(err, err_size,
                              "producer status: kernel store path overflow");
    struct stat stbuf;
    if (stat(path, &stbuf) != 0) {
        if (errno != ENOENT) {
            char why[1400];
            snprintf(why, sizeof(why), "producer status: stat %s: %s", path,
                     strerror(errno));
            return status_set_err(err, err_size, why);
        }
        out->progress_kv_present = false;
        return true;
    }
    if (!S_ISREG(stbuf.st_mode))
        return status_set_err(err, err_size,
                              "producer status: kernel store is not regular");

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        const char *message = db ? sqlite3_errmsg(db) : "open failed";
        char why[1400];
        snprintf(why, sizeof(why), "producer status: open %s: %s", path,
                 message);
        if (db)
            sqlite3_close(db);
        return status_set_err(err, err_size, why);
    }
    out->progress_kv_present = true;
    bool read_tx_open = false;
    if (!pkv_read_transaction(db, "BEGIN DEFERRED",
                              "begin read snapshot", err, err_size))
        goto fail;
    read_tx_open = true;

    int64_t value = 0;
    enum pkv_read_result read_result = pkv_query_i64(
            db, "stage_cursor",
            "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
            &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        goto fail;
    if (read_result == PKV_READ_PRESENT) {
        if (value < 0 || value > INT32_MAX) {
            status_set_err(err, err_size,
                           "producer status: utxo_apply cursor is malformed");
            goto fail;
        }
        out->utxo_apply_cursor = value;
    }
#ifdef ZCL_TESTING
    if (g_status_after_first_cursor_hook)
        g_status_after_first_cursor_hook(g_status_after_first_cursor_ctx);
#endif
    read_result = pkv_query_i64(
            db, "stage_cursor",
            "SELECT cursor FROM stage_cursor WHERE name='tip_finalize'",
            &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        goto fail;
    if (read_result == PKV_READ_PRESENT) {
        if (value < 0 || value > INT32_MAX) {
            status_set_err(err, err_size,
                           "producer status: tip_finalize cursor is malformed");
            goto fail;
        }
        out->tip_finalize_cursor = value;
    }
    read_result = pkv_query_i64(
            db, "consensus_state_producer_session",
            "SELECT start_time_us FROM consensus_state_producer_session "
                "WHERE singleton=1", &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        goto fail;
    if (read_result == PKV_READ_PRESENT) {
        if (value <= 0) {
            status_set_err(err, err_size,
                           "producer status: session start time is malformed");
            goto fail;
        }
        out->session_open = true;
        out->start_time_us = value;
    }
    read_result = pkv_query_i64(
            db, "consensus_state_producer_session",
            "SELECT validation_profile "
                "FROM consensus_state_producer_session WHERE singleton=1",
            &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        goto fail;
    if (read_result == PKV_READ_PRESENT) {
        if (value != CONSENSUS_STATE_VALIDATION_FULL &&
            value != CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) {
            status_set_err(err, err_size,
                           "producer status: validation profile is malformed");
            goto fail;
        }
        out->validation_profile = (int)value;
    }
    read_result = pkv_read_final_receipt(db, out, err, err_size);
    if (read_result == PKV_READ_ERROR)
        goto fail;
    if (read_result == PKV_READ_ABSENT &&
        !pkv_read_session_identity(db, out, err, err_size))
        goto fail;

    bool apply_log_present = false;
    if (!pkv_table_exists(db, "utxo_apply_log", &apply_log_present,
                          err, err_size))
        goto fail;
    if (apply_log_present) {
        struct cure_progress_sample older, newer;
        int samples = cure_progress_read_eta_samples(db, 60, &older, &newer);
        if (samples < 0) {
            status_set_sqlite_err(err, err_size, db,
                                  "read durable rate samples");
            goto fail;
        }
        if (samples == 1) {
            int64_t blocks = newer.height - older.height;
            int64_t seconds = newer.time_unix - older.time_unix;
            if (blocks <= 0 || seconds < 60 ||
                blocks > INT64_MAX / 1000) {
                status_set_err(
                    err, err_size,
                    "producer status: durable rate samples are malformed");
                goto fail;
            }
            /* Residual rows above/below the current durable frontier are not
             * evidence of the active producer's rate.  Rows predating the
             * open producer session are likewise from a prior generation.
             * Preserve status, but never expose an ETA from either. */
            if (pkv_rate_window_is_current(out, &older, &newer)) {
                out->durable_rate_available = true;
                out->rate_older_height = older.height;
                out->rate_older_time_unix = older.time_unix;
                out->rate_newer_height = newer.height;
                out->rate_newer_time_unix = newer.time_unix;
                out->rate_blocks_per_second_milli = blocks * 1000 / seconds;
                if (out->rate_blocks_per_second_milli <= 0) {
                    status_set_err(
                        err, err_size,
                        "producer status: durable rate rounds to zero");
                    goto fail;
                }
            }
        }
    }
    if (!pkv_read_transaction(db, "COMMIT", "commit read snapshot",
                              err, err_size))
        goto fail;
    read_tx_open = false;
    if (sqlite3_close(db) != SQLITE_OK)
        return status_set_err(err, err_size,
                              "producer status: close progress.kv failed");
    return true;

fail:
    if (read_tx_open) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); // raw-sql-ok:read-only-introspection
    }
    sqlite3_close(db);
    return false;
}
