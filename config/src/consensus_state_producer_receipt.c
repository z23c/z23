/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Producer-owned durable source receipt for the full-history exporter. */
#include "config/consensus_state_producer_receipt.h"
#include "consensus_state_producer_receipt_internal.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "crypto/sha3.h"
#include "core/utiltime.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* Singleton start-of-fold ownership marker in the producer's progress.kv.
 * Distinct from the exporter-read consensus_state_source_receipt: this records
 * WHO started the fold; the receipt is written only when the fold completes. */
static const char k_receipt_schema_sql[] =
    "CREATE TABLE IF NOT EXISTS consensus_state_source_receipt("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,"
    "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
    "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
    "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
    "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
    "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
    "receipt_digest BLOB NOT NULL)";
#ifdef ZCL_TESTING
static bool g_override_active;
static char g_override_source_id[65];
static bool g_override_clean;
void consensus_state_producer_receipt_test_set_identity(const char *source_id,
                                                        bool source_clean)
{
    if (!source_id) {
        g_override_active = false;
        g_override_source_id[0] = '\0';
        return;
    }
    g_override_active = true;
    if (strnlen(source_id, sizeof(g_override_source_id) + 1u) != 64u) {
        g_override_source_id[0] = '\0';
    } else {
        memcpy(g_override_source_id, source_id, 65u);
    }
    g_override_clean = source_clean;
}
#endif
static bool set_err(char *err, size_t err_size, const char *msg)
{
    if (err && err_size)
        snprintf(err, err_size, "%s", msg);
    return false; /* raw-return-ok:bounded policy reason returned to caller */
}
static int lowercase_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}
static bool decode_sha256_identity(const char *hex, uint8_t out[32])
{
    if (!hex || strnlen(hex, 65) != 64)
        return false;
    for (size_t i = 0; i < 32; i++) {
        int high = lowercase_hex_nibble(hex[i * 2]);
        int low = lowercase_hex_nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}
static bool producer_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}
/* SHA3-256 of the executable image opened through the platform process seam.
 * All bytes and both identity snapshots come from one no-reparse handle, so a
 * pathname replacement cannot splice two image generations into one claim. */
bool producer_running_binary_digest(uint8_t out[32])
{
    if (!out)
        return false;
    char executable[4096];
    if (!os_proc_exe_path(executable, sizeof(executable))) {
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS,
                 "running executable path resolution failed");
        return false;
    }
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, executable)) {
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS,
                 "running executable handle open failed");
        return false;
    }
    struct platform_positioned_file_snapshot before;
    if (!platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buffer[32768];
    bool ok = true;
    uint64_t offset = 0;
    while (offset < before.size) {
        size_t wanted = before.size - offset < sizeof(buffer)
            ? (size_t)(before.size - offset) : sizeof(buffer);
        int64_t n = platform_positioned_file_read(&file, buffer, wanted,
                                                   offset);
        if (n > 0) {
            sha3_256_write(&ctx, buffer, (size_t)n);
            offset += (uint64_t)n;
            continue;
        }
        ok = false;
        break;
    }
    struct platform_positioned_file_snapshot after;
    ok = ok && offset == before.size &&
         platform_positioned_file_snapshot(&file, &after) &&
         producer_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok)
        sha3_256_finalize(&ctx, out);
    else
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS, "running executable digest failed");
    return ok;
}
#ifdef ZCL_TESTING
bool consensus_state_producer_receipt_test_running_binary_digest(
    uint8_t out[32])
{
    return producer_running_binary_digest(out);
}
#endif
static void claim_digest(const char *domain, const uint8_t *extra,
                         size_t extra_len, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, strlen(domain) + 1);
    sha3_256_write(&ctx, extra, extra_len);
    sha3_256_finalize(&ctx, out);
}
/* Fill a v2 source-identity claim. source_tree_root is the exact 32-byte value
 * baked from tools/dev/source-identity.sh; no Git object ID participates in
 * durable authority. producer_commit remains empty; GitHub trace metadata
 * lives outside the v2 receipt. */
static bool fill_source_identity_claim(struct consensus_state_source_receipt *r)
{
    const char *source_id = zcl_build_source_id_sha256();
    /* V2's legacy-named source_clean column means the exact current inventory
     * was captured successfully. It is deliberately not Git cleanliness:
     * HEAD/gitlink comparisons would make SHA-1 object ids receipt authority.
     * Dirty source is already bound exactly by source_tree_root. */
    bool clean = true;
#ifdef ZCL_TESTING
    if (g_override_active) {
        source_id = g_override_source_id;
        clean = g_override_clean;
    }
#endif
    if (!decode_sha256_identity(source_id, r->source_tree_root))
        return false; /* raw-return-ok:unstamped build cannot earn a receipt */
    r->schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
    r->producer_commit[0] = '\0';
    r->source_clean = clean;
    const char *toolchain =
#ifdef __VERSION__
        __VERSION__;
#else
        "unknown-toolchain";
#endif
    claim_digest("zcl.producer_toolchain.v2", (const uint8_t *)toolchain,
                 strlen(toolchain), r->toolchain_digest);
    uint8_t build_inputs_preimage[36];
    uint32_t version = (uint32_t)CLIENT_VERSION;
    for (size_t i = 0; i < 4; i++)
        build_inputs_preimage[i] = (uint8_t)(version >> (8u * i));
    memcpy(build_inputs_preimage + 4, r->source_tree_root, 32);
    claim_digest("zcl.producer_build_inputs.v2", build_inputs_preimage,
                 sizeof(build_inputs_preimage), r->build_inputs_digest);
    return true;
}
static bool read_session_blob(sqlite3_stmt *st, int col, uint8_t out[32])
{
    if (sqlite3_column_type(st, col) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, col) != 32)
        return false;
    memcpy(out, sqlite3_column_blob(st, col), 32);
    return true;
}
static const char *producer_session_schema(uint8_t receipt_version)
{
    /* V1 sessions remain parseable below for historical status/diagnostics,
     * but no producer may create new v1 authority. */
    if (receipt_version == CONSENSUS_STATE_SOURCE_RECEIPT_V2)
        return PRODUCER_SESSION_SCHEMA_V2;
    return NULL;
}
static bool producer_session_schema_version(sqlite3_stmt *st, int column,
                                            uint8_t *out_version)
{
    if (!out_version || sqlite3_column_type(st, column) != SQLITE_TEXT)
        return false;
    const unsigned char *schema = sqlite3_column_text(st, column);
    int schema_len = sqlite3_column_bytes(st, column);
    if (!schema || schema_len < 0)
        return false;
    if ((size_t)schema_len == strlen(PRODUCER_SESSION_SCHEMA_V1) &&
        memcmp(schema, PRODUCER_SESSION_SCHEMA_V1, (size_t)schema_len) == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
        return true;
    }
    if ((size_t)schema_len == strlen(PRODUCER_SESSION_SCHEMA_V2) &&
        memcmp(schema, PRODUCER_SESSION_SCHEMA_V2, (size_t)schema_len) == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
        return true;
    }
    return false;
}
/* Resume authority is derived from this running build, never from the row it
 * is deciding whether to trust. In particular, recomputing an epoch from a
 * stored claim would admit a preseeded/tampered claim whose attacker updated
 * source_epoch_digest consistently. */
bool producer_current_v2_claim(
    uint8_t validation_profile,
    struct consensus_state_source_receipt *out,
    uint8_t source_epoch[32])
{
    memset(out, 0, sizeof(*out));
    out->validation_profile = validation_profile;
    if (!fill_source_identity_claim(out))
        return false;
    consensus_state_source_epoch_digest(out, source_epoch);
    memcpy(out->source_epoch_digest, source_epoch, 32);
    return true;
}
bool consensus_state_producer_receipt_current_binary_epoch(uint8_t out[32])
{
    if (!out)
        return false;
    struct consensus_state_source_receipt claim;
    uint8_t epoch[32];
    /* validation_profile is not an input to the epoch digest (see
     * consensus_state_source_epoch_digest()); CONSENSUS_STATE_VALIDATION_FULL
     * is an arbitrary valid placeholder. */
    if (!producer_current_v2_claim(CONSENSUS_STATE_VALIDATION_FULL, &claim, epoch))
        return false;
    memcpy(out, epoch, 32);
    return true;
}
bool producer_session_matches_current(
    const struct producer_session *stored,
    const struct consensus_state_source_receipt *current,
    const uint8_t current_epoch[32],
    const uint8_t running_binary[32])
{
    return stored && current && stored->present &&
           stored->claim.schema_version == CONSENSUS_STATE_SOURCE_RECEIPT_V2 &&
           current->schema_version == CONSENSUS_STATE_SOURCE_RECEIPT_V2 &&
           memcmp(stored->running_binary_digest, running_binary, 32) == 0 &&
           memcmp(stored->claim.source_tree_root,
                  current->source_tree_root, 32) == 0 &&
           memcmp(stored->claim.toolchain_digest,
                  current->toolchain_digest, 32) == 0 &&
           memcmp(stored->claim.build_inputs_digest,
                  current->build_inputs_digest, 32) == 0 &&
           memcmp(stored->source_epoch_digest, current_epoch, 32) == 0 &&
           stored->claim.source_clean == current->source_clean &&
           stored->claim.validation_profile == current->validation_profile &&
           strcmp(stored->claim.producer_commit,
                  current->producer_commit) == 0;
}
/* Load the singleton start session. Returns false only on a store error;
 * `out->present` reports whether a row exists. */
bool producer_session_load(sqlite3 *db, struct producer_session *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT schema,running_binary_digest,source_tree_root,toolchain_digest,"
            "build_inputs_digest,source_epoch_digest,source_clean,"
            "validation_profile,producer_commit,start_time_us "
            "FROM consensus_state_producer_session WHERE singleton=1", -1,
            &st, NULL) != SQLITE_OK) {
        /* Table may not exist yet: that is a legitimate "no session". */
        return true;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    bool ok = true;
    if (rc == SQLITE_ROW) {
        uint8_t version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
        const unsigned char *commit = sqlite3_column_type(st, 8) == SQLITE_TEXT
            ? sqlite3_column_text(st, 8) : NULL;
        int commit_len = commit ? sqlite3_column_bytes(st, 8) : -1;
        ok = producer_session_schema_version(st, 0, &version) &&
             read_session_blob(st, 1, out->running_binary_digest) &&
             read_session_blob(st, 2, out->claim.source_tree_root) &&
             read_session_blob(st, 3, out->claim.toolchain_digest) &&
             read_session_blob(st, 4, out->claim.build_inputs_digest) &&
             read_session_blob(st, 5, out->source_epoch_digest) &&
             sqlite3_column_type(st, 6) == SQLITE_INTEGER &&
             (sqlite3_column_int(st, 6) == 0 ||
              sqlite3_column_int(st, 6) == 1) &&
             sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
             (sqlite3_column_int(st, 7) == CONSENSUS_STATE_VALIDATION_FULL ||
              sqlite3_column_int(st, 7) ==
                  CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
             commit && commit_len >= 0 &&
             consensus_state_source_receipt_commit_valid(
                 version, (const char *)commit, (size_t)commit_len) &&
             sqlite3_column_type(st, 9) == SQLITE_INTEGER;
        if (ok) {
            out->claim.schema_version = version;
            out->claim.source_clean = sqlite3_column_int(st, 6) == 1;
            out->claim.validation_profile =
                (uint8_t)sqlite3_column_int(st, 7);
            memcpy(out->claim.producer_commit, commit, (size_t)commit_len);
            out->claim.producer_commit[commit_len] = '\0';
            out->started_us = sqlite3_column_int64(st, 9);
            out->present = true;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}
static bool insert_session(sqlite3 *db,
                           const struct consensus_state_source_receipt *r,
                           const uint8_t running_binary[32],
                           const char *datadir, int64_t start_us)
{
    const char *schema = producer_session_schema(r->schema_version);
    size_t commit_len = strnlen(r->producer_commit,
                                sizeof(r->producer_commit));
    if (r->schema_version != CONSENSUS_STATE_SOURCE_RECEIPT_V2 || !schema ||
        !consensus_state_source_receipt_commit_valid(
            r->schema_version, r->producer_commit, commit_len))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO consensus_state_producer_session("
            "singleton,schema,running_binary_digest,source_tree_root,"
            "toolchain_digest,build_inputs_digest,source_epoch_digest,"
            "source_clean,validation_profile,producer_commit,datadir,"
            "start_time_us) VALUES(1,?,?,?,?,?,?,?,?,?,?,?)", -1, &st,
            NULL) != SQLITE_OK)
        return false;
    int i = 1;
    bool ok = sqlite3_bind_text(st, i++, schema, -1, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, running_binary, 32, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->source_tree_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->toolchain_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->build_inputs_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, r->source_epoch_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, r->source_clean ? 1 : 0) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, r->validation_profile) == SQLITE_OK &&
              sqlite3_bind_text(st, i++, r->producer_commit, (int)commit_len,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_text(st, i++, datadir ? datadir : "", -1,
                                SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, start_us) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    return ok;
}
/* Read the EXISTING committed receipt's fold_cursor (H*+1 of the last finalize).
 * *present reports whether a receipt row exists; returns false only on a store
 * error. Used by the monotonic re-finalize guard: the standing live exporter
 * (config/src/bundle_exporter.c) re-finalizes each export cycle at the current
 * durable tip, and the committed generation must only ever roll FORWARD. */
static bool read_existing_receipt_fold_cursor(sqlite3 *db, int64_t *out,
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
static bool write_final_receipt(
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
enum final_receipt_state {
    FINAL_RECEIPT_READ_ERROR = 0, FINAL_RECEIPT_ABSENT,
    FINAL_RECEIPT_IDENTICAL, FINAL_RECEIPT_CONFLICT,
};
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
static enum final_receipt_state final_receipt_state(
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
static bool exec_checked(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    if (error) {
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS, "exec failed: %s", error);
        sqlite3_free(error);
    }
    return ok;
}
bool consensus_state_producer_receipt_begin(sqlite3 *pdb,
                                            uint8_t validation_profile,
                                            char *err, size_t err_size)
{
    if (err && err_size)
        err[0] = '\0';
    if (!pdb)
        return set_err(err, err_size, "producer receipt begin: NULL store");
    if (validation_profile != CONSENSUS_STATE_VALIDATION_FULL &&
        validation_profile != CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD)
        return set_err(err, err_size,
                       "producer receipt begin: invalid validation profile");
    uint8_t running_binary[32];
    if (!producer_running_binary_digest(running_binary))
        return set_err(err, err_size,
                       "producer receipt begin: running executable digest "
                       "failed");
    /* Compute every current-build authority input before consulting durable
     * session state. A stored row is evidence to compare, never an input to
     * the claim/epoch we expect from this executable. */
    struct consensus_state_source_receipt claim;
    uint8_t source_epoch[32];
    if (!producer_current_v2_claim(validation_profile, &claim, source_epoch))
        return set_err(
            err, err_size,
            "producer receipt begin: build has no exact 64-hex SHA-256 "
            "source identity; an unstamped build cannot earn a receipt");
    char datadir[576] = {0};
    (void)progress_store_path(datadir, sizeof(datadir));
    int64_t start_us = GetTimeMicros();
    bool committed = false;
    progress_store_tx_lock();
    if (!exec_checked(pdb, "BEGIN IMMEDIATE")) {
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt begin: cannot open transaction");
    }
    bool ok = progress_meta_table_ensure(pdb) &&
              exec_checked(pdb, PRODUCER_SESSION_SCHEMA_SQL);
    struct producer_session existing;
    if (ok)
        ok = producer_session_load(pdb, &existing);
    if (ok && existing.present) {
        /* V1 remains parseable for historical inspection, but cannot be
         * resumed into current producer authority. */
        if (existing.claim.schema_version !=
            CONSENSUS_STATE_SOURCE_RECEIPT_V2) {
            (void)exec_checked(pdb, "ROLLBACK");
            progress_store_tx_unlock();
            return set_err(err, err_size,
                           "producer receipt begin: legacy v1 session is "
                           "inspection-only and cannot resume");
        }
        /* Exact equality with the independently derived current claim is the
         * only resume capability. A self-consistent foreign stored
         * claim+epoch is still foreign and must never be adopted. */
        if (!producer_session_matches_current(&existing, &claim, source_epoch,
                                     running_binary)) {
            (void)exec_checked(pdb, "ROLLBACK");
            progress_store_tx_unlock();
            return set_err(err, err_size,
                           "producer receipt begin: datadir session does not "
                           "exactly match current running binary / source "
                           "claim / source epoch / profile");
        }
    } else if (ok) {
        ok = insert_session(pdb, &claim, running_binary, datadir, start_us);
    }
    /* Publish the source-epoch authority so fold stages stamp their rows. */
    if (ok)
        ok = progress_meta_set_in_tx(pdb, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                                     source_epoch, 32);
    if (ok)
        ok = exec_checked(pdb, "COMMIT");
    if (ok)
        committed = true;
    else
        (void)exec_checked(pdb, "ROLLBACK");
    progress_store_tx_unlock();
    if (!committed)
        return set_err(err, err_size,
                       "producer receipt begin: durable session write failed");
    return true;
}
bool consensus_state_producer_receipt_finalize(sqlite3 *pdb, int32_t height,
                                               const uint8_t block_hash[32],
                                               char *err, size_t err_size)
{
    if (err && err_size)
        err[0] = '\0';
    if (!pdb || !block_hash)
        return set_err(err, err_size, "producer receipt finalize: NULL arg");
    if (height < 0 || height == INT32_MAX)
        return set_err(err, err_size,
                       "producer receipt finalize: height out of range");
    uint8_t running_binary[32];
    if (!producer_running_binary_digest(running_binary))
        return set_err(err, err_size,
                       "producer receipt finalize: running executable digest "
                       "failed");
    bool committed = false;
    progress_store_tx_lock();
    if (!exec_checked(pdb, "BEGIN IMMEDIATE")) {
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: cannot open transaction");
    }
    struct producer_session session;
    bool ok = producer_session_load(pdb, &session);
    if (ok && !session.present) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: no start session — this "
                       "producer was not begun by a receipt-owning binary");
    }
    if (ok && session.claim.schema_version !=
                  CONSENSUS_STATE_SOURCE_RECEIPT_V2) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: legacy v1 session is "
                       "inspection-only and cannot finalize");
    }
    struct consensus_state_source_receipt current_claim;
    uint8_t current_epoch[32];
    if (ok && !producer_current_v2_claim(session.claim.validation_profile,
                                &current_claim, current_epoch)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(
            err, err_size,
            "producer receipt finalize: build has no exact 64-hex SHA-256 "
            "source identity; an unstamped build cannot finalize a receipt");
    }
    if (ok && !producer_session_matches_current(&session, &current_claim,
                                       current_epoch, running_binary)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: running executable/current "
                       "build does not own the start session");
    }
    /* Build the receipt from the independently derived current claim after
     * exact session equality, never from durable fields under evaluation.
     * Then bind chain corpus + fold cursor to the completed fold. */
    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    if (ok) {
        receipt = current_claim;
        memcpy(receipt.running_binary_digest, running_binary, 32);
    }
    if (ok &&
        !producer_receipt_header_corpus_digest(pdb, height, block_hash,
                                               receipt.chain_corpus_digest)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: genesis..H* header corpus "
                       "does not resolve the completed tip");
    }
    /* Monotonic re-finalize guard: the committed generation may only roll
     * FORWARD. A first finalize (no prior receipt) always passes; a re-finalize
     * at an equal height is an idempotent re-emit; a re-finalize at a LOWER
     * height is refused (fail closed). The running-binary + session-epoch checks
     * above already forbid a FOREIGN binary from re-finalizing at all. */
    if (ok) {
        int64_t existing_cursor = 0;
        bool existing_present = false;
        if (!read_existing_receipt_fold_cursor(pdb, &existing_cursor,
                                                &existing_present)) {
            (void)exec_checked(pdb, "ROLLBACK");
            progress_store_tx_unlock();
            return set_err(err, err_size,
                           "producer receipt finalize: existing receipt fold "
                           "cursor read failed");
        }
        if (existing_present && (int64_t)height + 1 < existing_cursor) {
            (void)exec_checked(pdb, "ROLLBACK");
            progress_store_tx_unlock();
            char why[192];
            snprintf(why, sizeof(why),
                     "producer receipt finalize: monotonic re-finalize cannot "
                     "move the committed fold cursor backward (have=%lld "
                     "want=%lld)", (long long)existing_cursor,
                     (long long)((int64_t)height + 1));
            return set_err(err, err_size, why);
        }
    }
    if (ok) {
        receipt.fold_cursor = (int64_t)height + 1;
        consensus_state_source_receipt_digest(&receipt, receipt.receipt_digest);
        ok = exec_checked(pdb, k_receipt_schema_sql);
    }
    enum final_receipt_state prior = FINAL_RECEIPT_READ_ERROR;
    if (ok)
        prior = final_receipt_state(pdb, &receipt);
    if (ok && prior == FINAL_RECEIPT_CONFLICT) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: conflicting finalized "
                       "receipt already exists");
    }
    if (ok && prior == FINAL_RECEIPT_READ_ERROR) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return set_err(err, err_size,
                       "producer receipt finalize: existing receipt read "
                       "failed");
    }
    if (ok)
        ok = progress_meta_set_in_tx(
                 pdb, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                 receipt.source_epoch_digest, 32) &&
             (prior == FINAL_RECEIPT_IDENTICAL ||
              write_final_receipt(pdb, &receipt));
    if (ok)
        ok = exec_checked(pdb, "COMMIT");
    if (ok)
        committed = true;
    else
        (void)exec_checked(pdb, "ROLLBACK");
    progress_store_tx_unlock();
    if (!committed)
        return set_err(err, err_size,
                       "producer receipt finalize: durable receipt write "
                       "failed");
    return true;
}
