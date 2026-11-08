/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read the source receipt from a leased consensus bundle. */
#include "consensus_state_install_source_receipt.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/ar_step_readonly.h"
#include <sqlite3.h>
#include <string.h>

static bool icb_source_receipt_copy_blobs(sqlite3_stmt *st,
                                          struct consensus_state_source_receipt *out)
{
    const struct { int col; uint8_t *dst; } blobs[] = {
        {1, out->source_epoch_digest}, {2, out->source_tree_root},
        {3, out->running_binary_digest}, {4, out->toolchain_digest},
        {5, out->build_inputs_digest}, {6, out->chain_corpus_digest},
        {11, out->receipt_digest},
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(blobs) / sizeof(blobs[0]); i++) {
        ok = sqlite3_column_type(st, blobs[i].col) == SQLITE_BLOB &&
             sqlite3_column_bytes(st, blobs[i].col) == 32;
        if (ok)
            memcpy(blobs[i].dst, sqlite3_column_blob(st, blobs[i].col), 32);
    }
    return ok;
}

static bool icb_source_receipt_texts_accepted(
    uint8_t *receipt_version, const unsigned char *schema, int schema_len,
    const unsigned char *commit, int commit_len)
{
    return schema && schema_len >= 0 &&
           consensus_state_source_receipt_schema_version(
               (const char *)schema, (size_t)schema_len,
               receipt_version) &&
           commit && commit_len >= 0 &&
           consensus_state_source_receipt_commit_valid(
               *receipt_version, (const char *)commit,
               (size_t)commit_len);
}

static bool icb_source_receipt_integers_accepted(sqlite3_stmt *st)
{
    return sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 7) == 0 ||
            sqlite3_column_int(st, 7) == 1) &&
           sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 8) == CONSENSUS_STATE_VALIDATION_FULL ||
            sqlite3_column_int(st, 8) ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
           sqlite3_column_type(st, 10) == SQLITE_INTEGER;
}

/* Read the producer source receipt from the pinned, already-validated bundle
 * handle. The CAS re-checks the receipt's self-consistency and its binding to
 * the manifest source digest, so a misread fails closed there. */
bool icb_read_source_receipt(sqlite3 *bundle_db,
                                    struct consensus_state_source_receipt *out)
{
    static const char sql[] =
        "SELECT schema,source_epoch_digest,source_tree_root,running_binary_digest,"
        "toolchain_digest,build_inputs_digest,chain_corpus_digest,source_clean,"
        "validation_profile,producer_commit,fold_cursor,receipt_digest "
        "FROM source_receipt WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(bundle_db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    memset(out, 0, sizeof(*out));
    bool ok = ar_step_checked(st, "install source receipt", NULL) == ZCL_STEP_ROW;
    if (ok)
        ok = icb_source_receipt_copy_blobs(st, out);
    if (ok) {
        const unsigned char *schema =
            sqlite3_column_type(st, 0) == SQLITE_TEXT
                ? sqlite3_column_text(st, 0) : NULL;
        int schema_len = schema ? sqlite3_column_bytes(st, 0) : -1;
        const unsigned char *commit =
            sqlite3_column_type(st, 9) == SQLITE_TEXT
                ? sqlite3_column_text(st, 9) : NULL;
        int commit_len = commit ? sqlite3_column_bytes(st, 9) : -1;
        uint8_t receipt_version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
        ok = icb_source_receipt_texts_accepted(
                 &receipt_version, schema, schema_len, commit, commit_len) &&
             icb_source_receipt_integers_accepted(st);
        if (ok) {
            out->schema_version = receipt_version;
            memcpy(out->producer_commit, commit, (size_t)commit_len);
            out->producer_commit[commit_len] = '\0';
            out->source_clean = sqlite3_column_int(st, 7) == 1;
            out->validation_profile = (uint8_t)sqlite3_column_int(st, 8);
            out->fold_cursor = sqlite3_column_int64(st, 10);
        }
    }
    sqlite3_finalize(st);
    return ok;
}
