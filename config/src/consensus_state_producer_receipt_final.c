/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the COMMITTED final receipt row of the producer-owned source
 * receipt — read its fold_cursor, write it, and decide whether an existing
 * row is the exact one this finalize would write (safe retry) or different
 * durable evidence (a named refusal).
 *
 * Split out of config/src/consensus_state_producer_receipt.c when that file
 * passed its shape ceiling. Pure move: the bodies below are byte-identical to
 * the ones that file carried; only the linkage of the three entry points
 * changed (static -> external) so finalize() can still reach them across the
 * TU boundary. Contract:
 * config/src/consensus_state_producer_receipt_final_internal.h.
 */

#include "consensus_state_producer_receipt_final_internal.h"

#include "storage/consensus_state_bundle_codec.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Read the EXISTING committed receipt's fold_cursor (H*+1 of the last finalize).
 * *present reports whether a receipt row exists; returns false only on a store
 * error. Used by the monotonic re-finalize guard: the standing live exporter
 * (config/src/bundle_exporter.c) re-finalizes each export cycle at the current
 * durable tip, and the committed generation must only ever roll FORWARD. */
bool read_existing_receipt_fold_cursor(sqlite3 *db, int64_t *out,
                                       bool *present)
{
    *present = false;
    *out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT fold_cursor FROM consensus_state_source_receipt "
            "WHERE singleton=1", -1, &st, NULL) != SQLITE_OK) {
        /* Table may not exist yet: a legitimate "no prior receipt". */
        return true;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_INTEGER) {
            *out = sqlite3_column_int64(st, 0);
            *present = true;
        } else {
            ok = false;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

bool write_final_receipt(
    sqlite3 *db, const struct consensus_state_source_receipt *r)
{
    const char *schema =
        consensus_state_source_receipt_schema(r->schema_version);
    size_t commit_len = strnlen(r->producer_commit,
                                sizeof(r->producer_commit));
    if (r->schema_version != CONSENSUS_STATE_SOURCE_RECEIPT_V2 || !schema ||
        !consensus_state_source_receipt_commit_valid(
            r->schema_version, r->producer_commit, commit_len))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO consensus_state_source_receipt("
            "singleton,schema,source_epoch_digest,source_tree_root,"
            "running_binary_digest,toolchain_digest,build_inputs_digest,"
            "chain_corpus_digest,source_clean,validation_profile,"
            "producer_commit,fold_cursor,receipt_digest) "
            "VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    int i = 1;
    bool ok = sqlite3_bind_text(st, i++, schema, -1, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->source_epoch_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->source_tree_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->running_binary_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->toolchain_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->build_inputs_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->chain_corpus_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, r->source_clean ? 1 : 0) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, r->validation_profile) == SQLITE_OK &&
              sqlite3_bind_text(st, i++, r->producer_commit, (int)commit_len,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, r->fold_cursor) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->receipt_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    return ok;
}

static bool receipt_blob_equal(sqlite3_stmt *st, int column,
                               const uint8_t expected[32])
{
    const void *blob = sqlite3_column_type(st, column) == SQLITE_BLOB
                           ? sqlite3_column_blob(st, column) : NULL;
    return blob && sqlite3_column_bytes(st, column) == 32 &&
           memcmp(blob, expected, 32) == 0;
}

static bool receipt_text_equal(sqlite3_stmt *st, int column,
                               const char *expected, size_t expected_len)
{
    const unsigned char *text =
        sqlite3_column_type(st, column) == SQLITE_TEXT
            ? sqlite3_column_text(st, column) : NULL;
    return text && sqlite3_column_bytes(st, column) == (int)expected_len &&
           memcmp(text, expected, expected_len) == 0;
}

/* A finalized receipt is an append-only ownership record. A retry may observe
 * the exact row it already committed, but must never heal, replace, or silently
 * adopt a malformed/different row. That distinction matters after a crash:
 * exact retry is safe; conflicting durable evidence is a named refusal. */
enum final_receipt_state final_receipt_state(
    sqlite3 *db, const struct consensus_state_source_receipt *expected)
{
    static const char sql[] =
        "SELECT schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest FROM consensus_state_source_receipt "
        "WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return FINAL_RECEIPT_READ_ERROR;
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return FINAL_RECEIPT_ABSENT;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return FINAL_RECEIPT_READ_ERROR;
    }
    const char *schema =
        consensus_state_source_receipt_schema(expected->schema_version);
    size_t commit_len = strnlen(expected->producer_commit,
                                sizeof(expected->producer_commit));
    bool identical =
        expected->schema_version == CONSENSUS_STATE_SOURCE_RECEIPT_V2 &&
        schema &&
        consensus_state_source_receipt_commit_valid(
            expected->schema_version, expected->producer_commit, commit_len) &&
        receipt_text_equal(st, 0, schema, strlen(schema)) &&
        receipt_blob_equal(st, 1, expected->source_epoch_digest) &&
        receipt_blob_equal(st, 2, expected->source_tree_root) &&
        receipt_blob_equal(st, 3, expected->running_binary_digest) &&
        receipt_blob_equal(st, 4, expected->toolchain_digest) &&
        receipt_blob_equal(st, 5, expected->build_inputs_digest) &&
        receipt_blob_equal(st, 6, expected->chain_corpus_digest) &&
        sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
        sqlite3_column_int(st, 7) == (expected->source_clean ? 1 : 0) &&
        sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
        sqlite3_column_int(st, 8) == expected->validation_profile &&
        receipt_text_equal(st, 9, expected->producer_commit, commit_len) &&
        sqlite3_column_type(st, 10) == SQLITE_INTEGER &&
        sqlite3_column_int64(st, 10) == expected->fold_cursor &&
        receipt_blob_equal(st, 11, expected->receipt_digest);
    rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return FINAL_RECEIPT_READ_ERROR;
    return identical ? FINAL_RECEIPT_IDENTICAL : FINAL_RECEIPT_CONFLICT;
}
