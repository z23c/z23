/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Strict validation for external zcl.consensus_state_bundle.v1 files. */

#include "config/consensus_state_bundle_validate.h"
#include "base/bytes.h"
#include "consensus_state_bundle_validate_schema.h"
#include "consensus_state_sqlite_text.h"

#include "chain/checkpoints.h"   /* get_rom_state_checkpoint — the shielded keystone */
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "sapling/incremental_merkle_tree.h"
#include "script/script.h"
#include "storage/anchor_kv.h"
#include "util/log_macros.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define VALIDATE_SUBSYS "consensus_bundle_validate"

#include "consensus_state_bundle_validate_heartbeat.h"

#ifdef ZCL_TESTING
static _Atomic uint64_t g_deep_scan_calls;
uint64_t consensus_state_bundle_validate_deep_scan_calls_for_test(void)
{ return atomic_load_explicit(&g_deep_scan_calls, memory_order_relaxed); }
void consensus_state_bundle_validate_deep_scan_calls_reset_for_test(void)
{ atomic_store_explicit(&g_deep_scan_calls, 0, memory_order_relaxed); }
#endif

static bool validation_fail(struct consensus_state_install_result *result,
                            enum consensus_state_install_status status,
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
    LOG_WARN(VALIDATE_SUBSYS, "%s", reason);
    return false;
}

static bool integrity_check(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check",
                           -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(VALIDATE_SUBSYS, "integrity_check prepare: %s",
                 sqlite3_errmsg(db));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              consensus_state_sqlite_text_equal(st, 0, "ok");
    sqlite3_finalize(st);
    if (!ok)
        LOG_WARN(VALIDATE_SUBSYS, "integrity_check failed");
    return ok;
}

static bool copy_blob32(sqlite3_stmt *st, int column, uint8_t out[32])
{
    if (sqlite3_column_type(st, column) != SQLITE_BLOB)
        return false;
    const void *blob = sqlite3_column_blob(st, column);
    if (!blob || sqlite3_column_bytes(st, column) != 32)
        return false;
    memcpy(out, blob, 32);
    return true;
}

static bool copy_int64_exact(sqlite3_stmt *st, int column, int64_t *out)
{
    if (sqlite3_column_type(st, column) != SQLITE_INTEGER)
        return false;
    *out = sqlite3_column_int64(st, column);
    return true;
}

static const char *const k_proof_names[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    "header_admit", "validate_headers", "body_fetch", "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
};

static const bool k_proof_hash_bound[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    true, true, true, false, true, true, true, false,
};

/* bundle_meta INTEGER columns; every one must be stored as an integer. */
static const int k_manifest_int_columns[] = {
    1, 3, 4, 5, 6, 8, 9, 11, 13, 15, 17, 18, 19, 20, 21,
};

static bool manifest_int_columns_typed(sqlite3_stmt *st)
{
    for (size_t i = 0; i < sizeof(k_manifest_int_columns) /
                               sizeof(k_manifest_int_columns[0]); i++)
        if (sqlite3_column_type(st, k_manifest_int_columns[i]) !=
            SQLITE_INTEGER)
            return false;
    return true;
}

static bool manifest_blobs_read(sqlite3_stmt *st,
                                struct consensus_state_bundle_manifest *m)
{
    return copy_blob32(st, 2, m->block_hash) &&
           copy_blob32(st, 7, m->utxo_root) &&
           copy_blob32(st, 10, m->anchor_digest) &&
           copy_blob32(st, 12, m->sprout_frontier_root) &&
           copy_blob32(st, 14, m->sapling_frontier_root) &&
           copy_blob32(st, 16, m->nullifier_digest) &&
           copy_blob32(st, 22, m->proof_manifest_digest) &&
           copy_blob32(st, 23, m->source_digest) &&
           copy_blob32(st, 24, m->artifact_digest);
}

/* The scalar bundle_meta columns, read before any bound is applied. */
struct manifest_cols {
    int64_t height;
    int history;
    int source_clean;
    int validation_profile;
    int64_t counts[3];
    int64_t supply;
    int64_t sprout_frontier_height;
    int64_t sapling_frontier_height;
};

static void manifest_cols_read(sqlite3_stmt *st, struct manifest_cols *c)
{
    c->height = sqlite3_column_int64(st, 1);
    c->history = sqlite3_column_int(st, 3);
    c->source_clean = sqlite3_column_int(st, 4);
    c->validation_profile = sqlite3_column_int(st, 5);
    c->counts[0] = sqlite3_column_int64(st, 8);
    c->counts[1] = sqlite3_column_int64(st, 11);
    c->counts[2] = sqlite3_column_int64(st, 17);
    c->supply = sqlite3_column_int64(st, 9);
    c->sprout_frontier_height = sqlite3_column_int64(st, 13);
    c->sapling_frontier_height = sqlite3_column_int64(st, 15);
}

static bool manifest_scalars_valid(const struct manifest_cols *c)
{
    return c->height >= 0 && c->height < INT32_MAX && MoneyRange(c->supply) &&
           (c->history == 0 || c->history == 1) &&
           (c->source_clean == 0 || c->source_clean == 1) &&
           (c->validation_profile == CONSENSUS_STATE_VALIDATION_FULL ||
            c->validation_profile ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
           c->counts[0] > 0 && c->counts[1] >= 0 && c->counts[2] >= 0;
}

static bool manifest_frontiers_valid(
    const struct manifest_cols *c,
    const struct consensus_state_bundle_manifest *m)
{
    return c->sprout_frontier_height >= 0 &&
           c->sprout_frontier_height <= c->height &&
           c->sapling_frontier_height >= 0 &&
           c->sapling_frontier_height <= c->height &&
           zcl_bytes_any_set(m->sprout_frontier_root, 32) &&
           zcl_bytes_any_set(m->sapling_frontier_root, 32);
}

static void manifest_fill(sqlite3_stmt *st, const struct manifest_cols *c,
                          struct consensus_state_bundle_manifest *m)
{
    m->height = (int32_t)c->height;
    m->history_complete = c->history == 1;
    m->source_clean = c->source_clean == 1;
    m->validation_profile = (uint8_t)c->validation_profile;
    m->activation_boundary = sqlite3_column_int64(st, 6);
    m->utxo_count = (uint64_t)c->counts[0];
    m->total_supply = c->supply;
    m->anchor_count = (uint64_t)c->counts[1];
    m->nullifier_count = (uint64_t)c->counts[2];
    m->sprout_frontier_height = c->sprout_frontier_height;
    m->sapling_frontier_height = c->sapling_frontier_height;
    m->sprout_source_cursor = sqlite3_column_int64(st, 18);
    m->sapling_source_cursor = sqlite3_column_int64(st, 19);
    m->nullifier_source_cursor = sqlite3_column_int64(st, 20);
    m->source_fold_cursor = sqlite3_column_int64(st, 21);
}

static bool manifest_complete_history_ok(
    const struct consensus_state_bundle_manifest *m)
{
    return m->activation_boundary == 0 && m->sprout_source_cursor == 0 &&
           m->sapling_source_cursor == 0 && m->nullifier_source_cursor == 0 &&
           m->source_fold_cursor == (int64_t)m->height + 1 &&
           zcl_bytes_any_set(m->proof_manifest_digest, 32) &&
           zcl_bytes_any_set(m->source_digest, 32) &&
           zcl_bytes_any_set(m->artifact_digest, 32);
}

static bool manifest_current_only_ok(
    const struct consensus_state_bundle_manifest *m)
{
    return m->activation_boundary > 0 && m->activation_boundary <= m->height &&
           m->sprout_source_cursor >= 0 && m->sapling_source_cursor >= 0 &&
           m->nullifier_source_cursor >= 0 && m->source_fold_cursor >= 0 &&
           m->source_fold_cursor <= (int64_t)m->height + 1;
}

/* Decodes and bounds-checks the bundle_meta row that sqlite3_step positioned
 * on; the manifest is only filled when every check passes. */
static bool manifest_row_read(sqlite3_stmt *st,
                              struct consensus_state_bundle_manifest *m)
{
    if (!(consensus_state_sqlite_text_equal(
              st, 0, CONSENSUS_STATE_BUNDLE_SCHEMA) &&
          manifest_int_columns_typed(st) && manifest_blobs_read(st, m)))
        return false;
    struct manifest_cols cols;
    manifest_cols_read(st, &cols);
    if (!manifest_scalars_valid(&cols) || !manifest_frontiers_valid(&cols, m))
        return false;
    manifest_fill(st, &cols, m);
    return true;
}

static bool read_manifest(sqlite3 *db,
                          struct consensus_state_bundle_manifest *m,
                          struct consensus_state_install_result *r)
{
    static const char *const sql =
        "SELECT schema,height,block_hash,history_complete,source_clean,"
        "validation_profile,activation_boundary,"
        "utxo_root,utxo_count,total_supply,anchor_digest,anchor_count,"
        "sprout_frontier_root,sprout_frontier_height,"
        "sapling_frontier_root,sapling_frontier_height,"
        "nullifier_digest,nullifier_count,sprout_source_cursor,"
        "sapling_source_cursor,nullifier_source_cursor,source_fold_cursor,"
        "proof_manifest_digest,source_digest,artifact_digest "
        "FROM bundle_meta WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle_meta missing or malformed");
    memset(m, 0, sizeof(*m));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW && manifest_row_read(st, m);
    sqlite3_finalize(st);
    if (!ok || !zcl_bytes_any_set(m->block_hash, 32))
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle_meta has invalid schema/types/bounds");
    if (m->history_complete) {
        if (!manifest_complete_history_ok(m))
            return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                                   "complete history lacks genesis cursors/provenance");
    } else if (!manifest_current_only_ok(m)) {
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "current-only history lacks positive boundary");
    }
    return true;
}

/* The source_receipt row's text columns and the schema version they name. */
struct receipt_row_head {
    int commit_type;
    const unsigned char *commit;
    int commit_len;
    uint8_t version;
    bool schema_ok;
};

static void receipt_row_head_read(sqlite3_stmt *st, int rc,
                                  struct receipt_row_head *h)
{
    h->commit_type = rc == SQLITE_ROW ? sqlite3_column_type(st, 10)
                                      : SQLITE_NULL;
    h->commit = h->commit_type == SQLITE_TEXT
                    ? sqlite3_column_text(st, 10) : NULL;
    h->commit_len = h->commit ? sqlite3_column_bytes(st, 10) : -1;
    const unsigned char *schema =
        rc == SQLITE_ROW && sqlite3_column_type(st, 1) == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(st, 1) : -1;
    h->version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    h->schema_ok = schema && schema_len >= 0 &&
        consensus_state_source_receipt_schema_version(
            (const char *)schema, (size_t)schema_len, &h->version);
}

static bool receipt_blobs_read(sqlite3_stmt *st,
                               struct consensus_state_source_receipt *r)
{
    return copy_blob32(st, 2, r->source_epoch_digest) &&
           copy_blob32(st, 3, r->source_tree_root) &&
           copy_blob32(st, 4, r->running_binary_digest) &&
           copy_blob32(st, 5, r->toolchain_digest) &&
           copy_blob32(st, 6, r->build_inputs_digest) &&
           copy_blob32(st, 7, r->chain_corpus_digest);
}

static bool receipt_scalars_typed(sqlite3_stmt *st,
                                  const struct receipt_row_head *h)
{
    return sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 8) == 0 ||
            sqlite3_column_int(st, 8) == 1) &&
           sqlite3_column_type(st, 9) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 9) == CONSENSUS_STATE_VALIDATION_FULL ||
            sqlite3_column_int(st, 9) ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
           h->commit_type == SQLITE_TEXT && h->commit_len >= 0 &&
           consensus_state_source_receipt_commit_valid(
               h->version, (const char *)h->commit, (size_t)h->commit_len) &&
           sqlite3_column_type(st, 11) == SQLITE_INTEGER;
}

/* Decodes the single source_receipt row into *receipt and requires that no
 * second row follows. */
static bool receipt_row_read(sqlite3_stmt *st, int rc,
                             const struct receipt_row_head *h,
                             struct consensus_state_source_receipt *receipt)
{
    bool ok = rc == SQLITE_ROW && h->commit &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1 && h->schema_ok &&
              receipt_blobs_read(st, receipt) &&
              receipt_scalars_typed(st, h) &&
              copy_blob32(st, 12, receipt->receipt_digest);
    if (!ok)
        return false;
    receipt->schema_version = h->version;
    memcpy(receipt->producer_commit, h->commit, (size_t)h->commit_len);
    receipt->producer_commit[h->commit_len] = '\0';
    receipt->source_clean = sqlite3_column_int(st, 8) == 1;
    receipt->validation_profile = (uint8_t)sqlite3_column_int(st, 9);
    receipt->fold_cursor = sqlite3_column_int64(st, 11);
    return sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
}

static bool receipt_bound_to_manifest(
    const struct consensus_state_source_receipt *receipt,
    const struct consensus_state_bundle_manifest *manifest)
{
    uint8_t recomputed[32];
    uint8_t source_epoch[32];
    consensus_state_source_epoch_digest(receipt, source_epoch);
    consensus_state_source_receipt_digest(receipt, recomputed);
    return zcl_bytes_any_set(receipt->source_epoch_digest, 32) &&
           zcl_bytes_any_set(receipt->source_tree_root, 32) &&
           zcl_bytes_any_set(receipt->running_binary_digest, 32) &&
           zcl_bytes_any_set(receipt->toolchain_digest, 32) &&
           zcl_bytes_any_set(receipt->build_inputs_digest, 32) &&
           zcl_bytes_any_set(receipt->chain_corpus_digest, 32) &&
           consensus_state_source_receipt_commit_valid(
               receipt->schema_version, receipt->producer_commit,
               strnlen(receipt->producer_commit,
                       sizeof(receipt->producer_commit))) &&
           receipt->fold_cursor == manifest->source_fold_cursor &&
           receipt->source_clean == manifest->source_clean &&
           receipt->validation_profile == manifest->validation_profile &&
           memcmp(source_epoch, receipt->source_epoch_digest, 32) == 0 &&
           memcmp(recomputed, receipt->receipt_digest, 32) == 0 &&
           memcmp(recomputed, manifest->source_digest, 32) == 0;
}

static bool validate_source_receipt(
    sqlite3 *db, const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_source_receipt *receipt_out,
    struct consensus_state_install_result *result)
{
    static const char sql[] =
        "SELECT singleton,schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest FROM source_receipt ORDER BY singleton";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "source_receipt missing or malformed");
    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    struct receipt_row_head head;
    receipt_row_head_read(st, rc, &head);
    bool legacy_v1 = head.schema_ok &&
        head.version == CONSENSUS_STATE_SOURCE_RECEIPT_V1;
    bool ok = receipt_row_read(st, rc, &head, &receipt);
    sqlite3_finalize(st);
    /* The v1 codec remains readable for historical tooling, but its Git-SHA-1-
     * derived source claim is never sufficient authority for installation. */
    if (legacy_v1)
        return validation_fail(
            result, CONSENSUS_INSTALL_REFUSED,
            "legacy v1 source receipt is inspection-only and cannot install");
    if (ok)
        ok = receipt_bound_to_manifest(&receipt, manifest);
    if (!ok)
        return validation_fail(
            result, CONSENSUS_INSTALL_REFUSED,
            "source receipt types/digest/fold binding mismatch");
    /* The source-tree and toolchain values are producer claims bound to this
     * receipt and its known executable digest. They are not, by themselves,
     * proof that an independent builder reproduced the source epoch. */
    if (receipt_out)
        *receipt_out = receipt;
    return true;
}

/* One proof component row: identity columns (ordinal, name, cursor). */
static bool proof_row_head(sqlite3_stmt *st, int rc, size_t i,
                           int64_t *cursor)
{
    int64_t ordinal = -1;
    *cursor = -1;
    return rc == SQLITE_ROW && copy_int64_exact(st, 0, &ordinal) &&
           ordinal == (int64_t)i &&
           consensus_state_sqlite_text_equal(st, 1, k_proof_names[i]) &&
           copy_int64_exact(st, 2, cursor) && *cursor >= 0;
}

/* One proof component row: extent columns (first, last, rows, hashes) for a
 * summary spanning [0, last_height] over rows_expected rows. */
static bool proof_row_extent(sqlite3_stmt *st, size_t i, int64_t last_height,
                             uint64_t rows_expected, int64_t *hashes)
{
    int64_t first = -1, last = -1, rows = -1;
    *hashes = -1;
    return copy_int64_exact(st, 3, &first) && first == 0 &&
           copy_int64_exact(st, 4, &last) && last == last_height &&
           copy_int64_exact(st, 5, &rows) && rows >= 0 &&
           (uint64_t)rows == rows_expected &&
           copy_int64_exact(st, 6, hashes) && *hashes >= 0 &&
           (uint64_t)*hashes ==
               (k_proof_hash_bound[i] ? rows_expected : 0u);
}

struct proof_row {
    int64_t cursor;
    int64_t hashes;
};

static bool proof_row_read(sqlite3_stmt *st, int rc, size_t i,
                           int64_t last_height, uint64_t rows_expected,
                           struct proof_row *row, uint8_t digest[32])
{
    return proof_row_head(st, rc, i, &row->cursor) &&
           proof_row_extent(st, i, last_height, rows_expected,
                            &row->hashes) &&
           copy_blob32(st, 7, digest);
}

static bool proof_cursor_ok(size_t i, int64_t cursor, int64_t last_height,
                            uint64_t rows)
{
    uint64_t minimum = i == CONSENSUS_STATE_BUNDLE_PROOF_COUNT - 1u
                           ? (uint64_t)last_height : rows;
    return (uint64_t)cursor >= minimum &&
           (i != 6u || (uint64_t)cursor == rows) &&
           (i != 7u || (uint64_t)cursor <= minimum + 1u);
}

static void proof_summary_fill(
    struct consensus_state_bundle_proof_summary *s, size_t i,
    const struct proof_row *row, int64_t last_height, uint64_t rows)
{
    snprintf(s->component, sizeof(s->component), "%s", k_proof_names[i]);
    s->cursor = (uint64_t)row->cursor;
    s->first_height = 0;
    s->last_height = last_height;
    s->row_count = rows;
    s->hash_bound_count = (uint64_t)row->hashes;
}

static bool parent_digests_present(
    const struct consensus_state_bundle_proof_parent *parent)
{
    return zcl_bytes_any_set(parent->base_block_hash, 32) &&
           zcl_bytes_any_set(parent->proof_manifest_digest, 32) &&
           zcl_bytes_any_set(parent->source_digest, 32) &&
           zcl_bytes_any_set(parent->artifact_digest, 32);
}

static bool parent_header_read(
    sqlite3_stmt *st, int rc,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_bundle_proof_parent *parent,
    int64_t *base_height, int64_t *profile)
{
    *base_height = -1;
    *profile = -1;
    return rc == SQLITE_ROW && copy_int64_exact(st, 0, base_height) &&
           *base_height >= 0 && *base_height < manifest->height &&
           copy_blob32(st, 1, parent->base_block_hash) &&
           copy_int64_exact(st, 2, profile) &&
           *profile == manifest->validation_profile &&
           copy_blob32(st, 3, parent->proof_manifest_digest) &&
           copy_blob32(st, 4, parent->source_digest) &&
           copy_blob32(st, 5, parent->artifact_digest) &&
           parent_digests_present(parent);
}

static bool parent_components_read(
    sqlite3_stmt *st, struct consensus_state_bundle_proof_parent *parent)
{
    uint64_t parent_rows = (uint64_t)parent->base_height + 1u;
    for (size_t i = 0; i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        struct proof_row row;
        struct consensus_state_bundle_proof_summary *comp =
            &parent->components[i];
        if (!(proof_row_read(st, rc, i, parent->base_height, parent_rows,
                             &row, comp->component_digest) &&
              copy_blob32(st, 8, parent->suffix_digest[i]) &&
              zcl_bytes_any_set(comp->component_digest, 32) &&
              zcl_bytes_any_set(parent->suffix_digest[i], 32) &&
              proof_cursor_ok(i, row.cursor, parent->base_height,
                              parent_rows)))
            return false;
        proof_summary_fill(comp, i, &row, parent->base_height, parent_rows);
    }
    return true;
}

static bool bundle_parent_components(
    sqlite3 *db, struct consensus_state_bundle_proof_parent *parent,
    struct consensus_state_install_result *result)
{
    static const char component_sql[] =
        "SELECT ordinal,component,cursor,first_height,last_height,"
        "row_count,hash_bound_count,component_digest,suffix_digest "
        "FROM proof_parent_component ORDER BY ordinal";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, component_sql, -1, &st, NULL) != SQLITE_OK)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "proof parent components are unavailable");
    bool ok = parent_components_read(st, parent);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    uint8_t parent_manifest[32];
    if (ok) {
        consensus_state_bundle_proof_manifest_digest(
            parent->components, CONSENSUS_STATE_BUNDLE_PROOF_COUNT,
            parent_manifest);
        ok = memcmp(parent_manifest, parent->proof_manifest_digest, 32) == 0;
    }
    if (!ok)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "proof parent component lineage malformed");
    return true;
}

/* Loads the optional proof_parent lineage. A bundle without the proof_parent
 * table has no parent and validates as a genesis-rescan summary. */
static bool bundle_parent_load(
    sqlite3 *db, const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_bundle_proof_parent *parent,
    struct consensus_state_install_result *result)
{
    static const char parent_sql[] =
        "SELECT base_height,base_block_hash,validation_profile,"
        "proof_manifest_digest,source_digest,artifact_digest "
        "FROM proof_parent WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, parent_sql, -1, &st, NULL) != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(db);
        if (!msg || strstr(msg, "no such table") == NULL)
            return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                                   "proof parent query failed");
        return true;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    int64_t base_height = -1;
    int64_t profile = -1;
    bool parent_ok = parent_header_read(st, rc, manifest, parent,
                                        &base_height, &profile);
    if (parent_ok)
        parent_ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    if (!parent_ok)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "proof parent base is malformed");
    parent->present = true;
    parent->base_height = (int32_t)base_height;
    parent->validation_profile = (uint8_t)profile;
    return bundle_parent_components(db, parent, result);
}

static bool bundle_proof_rows(
    sqlite3_stmt *st, const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_bundle_proof_summary *proofs)
{
    uint64_t expected_rows = (uint64_t)manifest->height + 1;
    for (size_t i = 0; i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        struct proof_row row;
        if (!proof_row_read(st, rc, i, manifest->height, expected_rows, &row,
                            proofs[i].component_digest) ||
            !proof_cursor_ok(i, row.cursor, manifest->height,
                             expected_rows) ||
            !zcl_bytes_any_set(proofs[i].component_digest, 32))
            return false;
        proof_summary_fill(&proofs[i], i, &row, manifest->height,
                           expected_rows);
    }
    return true;
}

static bool bundle_proofs_verified(
    const struct consensus_state_bundle_proof_parent *parent,
    const struct consensus_state_bundle_proof_summary *proofs,
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt)
{
    if (parent->present) {
        for (size_t i = 0; i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
            uint8_t extended[32];
            if (!consensus_state_bundle_proof_extension_digest(
                    parent, i, extended) ||
                memcmp(extended, proofs[i].component_digest, 32) != 0)
                return false;
        }
    }
    uint8_t recomputed[32];
    consensus_state_bundle_proof_manifest_digest(
        proofs, CONSENSUS_STATE_BUNDLE_PROOF_COUNT, recomputed);
    return memcmp(recomputed, manifest->proof_manifest_digest, 32) == 0 &&
           memcmp(proofs[0].component_digest,
                  receipt->chain_corpus_digest, 32) == 0;
}

static bool validate_bundle_proof(
    sqlite3 *db, const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt,
    struct consensus_state_install_result *result)
{
    struct consensus_state_bundle_proof_parent parent;
    memset(&parent, 0, sizeof(parent));
    if (!bundle_parent_load(db, manifest, &parent, result))
        return false;
    static const char sql[] =
        "SELECT ordinal,component,cursor,first_height,last_height,row_count,"
        "hash_bound_count,component_digest FROM bundle_proof ORDER BY ordinal";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "bundle_proof missing or malformed");
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    memset(proofs, 0, sizeof(proofs));
    bool ok = bundle_proof_rows(st, manifest, proofs);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    if (ok)
        ok = bundle_proofs_verified(&parent, proofs, manifest, receipt);
    if (!ok)
        return validation_fail(
            result, CONSENSUS_INSTALL_REFUSED,
            "bundle proof order/range/cursor/hash/digest mismatch");
    /* These summaries are producer evidence bound by source_receipt's known
     * executable. ZClassic headers do not commit these reducer state rows. */
    return true;
}

/* One coins row as stored, before any bound is applied. */
struct coin_row {
    int txid_type, script_type;
    const uint8_t *txid, *script;
    int txid_len, script_len;
    int64_t vout, value, height, coinbase;
    bool numeric;
};

static void coin_row_load(sqlite3_stmt *st, struct coin_row *row)
{
    row->txid_type = sqlite3_column_type(st, 0);
    row->script_type = sqlite3_column_type(st, 3);
    row->txid = row->txid_type == SQLITE_BLOB
        ? sqlite3_column_blob(st, 0) : NULL;
    row->script = row->script_type == SQLITE_BLOB
        ? sqlite3_column_blob(st, 3) : NULL;
    row->vout = row->value = row->height = row->coinbase = -1;
    row->numeric = copy_int64_exact(st, 1, &row->vout) &&
                   copy_int64_exact(st, 2, &row->value) &&
                   copy_int64_exact(st, 4, &row->height) &&
                   copy_int64_exact(st, 5, &row->coinbase);
    row->script_len = sqlite3_column_bytes(st, 3);
    row->txid_len = sqlite3_column_bytes(st, 0);
}

static bool coin_row_shape_bad(const struct coin_row *row)
{
    return row->txid_type != SQLITE_BLOB || row->script_type != SQLITE_BLOB ||
           !row->numeric || !row->txid || row->txid_len != 32 ||
           row->script_len < 0 || row->vout < 0 ||
           row->script_len > MAX_SCRIPT_SIZE || row->vout > UINT32_MAX ||
           !MoneyRange(row->value);
}

static bool coin_row_bounds_bad(const struct coin_row *row, int64_t supply,
                                uint64_t count, int32_t max_height)
{
    return supply > MAX_MONEY - row->value || row->height < 0 ||
           row->height > max_height ||
           (row->coinbase != 0 && row->coinbase != 1) ||
           count == UINT64_MAX;
}

/* Rows must be strictly ascending by (txid, vout). */
static bool coin_row_order_bad(const struct coin_row *row, bool have_prior,
                               const uint8_t prior_txid[32],
                               uint32_t prior_vout)
{
    int order = (have_prior && row->txid && row->txid_len == 32)
                    ? memcmp(prior_txid, row->txid, 32)
                    : -1;
    return have_prior && (order > 0 ||
                          (order == 0 && prior_vout >= (uint32_t)row->vout));
}

static bool validate_coins(sqlite3 *db,
                           const struct consensus_state_bundle_manifest *m,
                           struct consensus_state_install_result *r)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid,vout,value,script,height,is_coinbase "
            "FROM coins ORDER BY txid,vout", -1, &st, NULL) != SQLITE_OK)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle coins table missing/malformed");
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = true;
    uint8_t prior_txid[32] = {0};
    uint32_t prior_vout = 0;
    bool have_prior = false;
    struct validate_heartbeat hb;
    heartbeat_begin(&hb, "validate_coins", m->utxo_count);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        heartbeat_tick(&hb, count);
        struct coin_row row;
        coin_row_load(st, &row);
        if (coin_row_shape_bad(&row) ||
            coin_row_bounds_bad(&row, supply, count, m->height) ||
            coin_row_order_bad(&row, have_prior, prior_txid, prior_vout)) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(
            &ctx, row.txid, (uint32_t)row.vout, row.value,
            row.script_len ? row.script : NULL, (uint32_t)row.script_len,
            (uint32_t)row.height, (uint8_t)row.coinbase);
        supply += row.value;
        memcpy(prior_txid, row.txid, sizeof(prior_txid));
        prior_vout = (uint32_t)row.vout;
        have_prior = true;
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    uint8_t root[32];
    sha3_256_finalize(&ctx, root);
    if (!ok || count != m->utxo_count || supply != m->total_supply ||
        memcmp(root, m->utxo_root, 32) != 0)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "UTXO root/count/supply mismatch");
    return true;
}

/* Reads the per-pool MAX(height) anchor. Only those tip rows carry
 * consensus-load-bearing tree contents (their frontier root is
 * Pedersen-bound to the header-committed root); every other row gets the
 * byte-integrity floor. This collapses the O(anchors x Pedersen-hash) full
 * recompute to O(pools). See chainstate_legacy_reader.c:376-378 for the same
 * trust boundary the bulk import path proved. */
static bool anchor_tip_heights(sqlite3 *db, int64_t tip_height[2],
                               struct consensus_state_install_result *r)
{
    sqlite3_stmt *tq = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,MAX(height) FROM anchors GROUP BY pool",
            -1, &tq, NULL) != SQLITE_OK)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle anchors tip pre-query failed");
    bool tq_ok = true;
    int trc;
    while ((trc = sqlite3_step(tq)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        int64_t pool = -1, h = -1;
        if (!copy_int64_exact(tq, 0, &pool) ||
            !copy_int64_exact(tq, 1, &h) || (pool != 0 && pool != 1)) {
            tq_ok = false;
            break;
        }
        tip_height[pool] = h;
    }
    if (trc != SQLITE_DONE)
        tq_ok = false;
    sqlite3_finalize(tq);
    if (!tq_ok)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle anchors tip pre-query malformed");
    return true;
}

/* One anchors row as stored, before any bound is applied. */
struct anchor_row {
    int root_type, tree_type;
    const uint8_t *root, *tree_blob;
    int root_len, tree_len;
    int64_t pool, height;
    bool numeric;
};

static void anchor_row_load(sqlite3_stmt *st, struct anchor_row *row)
{
    row->root_type = sqlite3_column_type(st, 1);
    row->tree_type = sqlite3_column_type(st, 3);
    row->root = row->root_type == SQLITE_BLOB
        ? sqlite3_column_blob(st, 1) : NULL;
    row->pool = row->height = -1;
    row->numeric = copy_int64_exact(st, 0, &row->pool) &&
                   copy_int64_exact(st, 2, &row->height);
    row->tree_blob = row->tree_type == SQLITE_BLOB
        ? sqlite3_column_blob(st, 3) : NULL;
    row->tree_len = row->tree_blob ? sqlite3_column_bytes(st, 3) : 0;
    row->root_len = sqlite3_column_bytes(st, 1);
}

static bool anchor_row_shape_bad(const struct anchor_row *row, uint64_t count,
                                 int32_t max_height, int prior_pool,
                                 const uint8_t prior_root[32])
{
    return !row->numeric || row->root_type != SQLITE_BLOB ||
           row->tree_type != SQLITE_BLOB ||
           (row->pool != 0 && row->pool != 1) || !row->root ||
           row->root_len != 32 || !row->tree_blob || row->tree_len <= 0 ||
           row->height < 0 || row->height > max_height ||
           count == UINT64_MAX ||
           (prior_pool == row->pool && memcmp(prior_root, row->root, 32) >= 0);
}

/* Byte-integrity floor for EVERY row: a torn/truncated/garbled tree or
 * trailing bytes are refused regardless of the row's position. The root is
 * recomputed and bound to the stored key ONLY for the per-pool MAX(height)
 * anchor; historical rows delegate root/key agreement to the whole-file
 * digest plus this tip bind. */
static bool anchor_tree_valid(const struct anchor_row *row,
                              const int64_t tip_height[2])
{
    struct incremental_merkle_tree tree;
    if (row->pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(&tree);
    else
        sapling_tree_init(&tree);
    struct byte_stream stream;
    stream_init_from_data(&stream, row->tree_blob, (size_t)row->tree_len);
    if (!incremental_tree_deserialize(&tree, &stream) ||
        stream_remaining(&stream) != 0)
        return false;
    if (row->height == tip_height[(int)row->pool]) {
        struct uint256 computed;
        incremental_tree_root(&tree, &computed);
        if (memcmp(computed.data, row->root, 32) != 0)
            return false;
    }
    return true;
}

/* Running per-pool frontier and digest state of the anchors scan. */
struct anchor_scan {
    bool have_pool[2];
    int64_t frontier_height[2];
    uint8_t frontier_root[2][32];
    uint8_t prior_root[32];
    int prior_pool;
    uint64_t count;
};

static bool anchors_summary_ok(const struct anchor_scan *scan,
                               const struct consensus_state_bundle_manifest *m,
                               const uint8_t digest[32])
{
    return scan->count == m->anchor_count && scan->have_pool[0] &&
           scan->have_pool[1] &&
           scan->frontier_height[ANCHOR_POOL_SPROUT] ==
               m->sprout_frontier_height &&
           scan->frontier_height[ANCHOR_POOL_SAPLING] ==
               m->sapling_frontier_height &&
           memcmp(scan->frontier_root[ANCHOR_POOL_SPROUT],
                  m->sprout_frontier_root, 32) == 0 &&
           memcmp(scan->frontier_root[ANCHOR_POOL_SAPLING],
                  m->sapling_frontier_root, 32) == 0 &&
           memcmp(digest, m->anchor_digest, 32) == 0;
}

/* Folds one valid row into the digest and the per-pool frontier; false when
 * a second row repeats the pool's frontier height. */
static bool anchor_scan_fold(struct anchor_scan *scan, struct sha3_256_ctx *ctx,
                             const struct anchor_row *row)
{
    int pool_index = (int)row->pool;
    consensus_state_bundle_anchor_digest_row(
        ctx, (uint8_t)row->pool, row->root, (uint64_t)row->height,
        row->tree_blob, (uint32_t)row->tree_len);
    scan->have_pool[pool_index] = true;
    if (row->height == scan->frontier_height[pool_index])
        return false;
    if (row->height > scan->frontier_height[pool_index]) {
        scan->frontier_height[pool_index] = row->height;
        memcpy(scan->frontier_root[pool_index], row->root, 32);
    }
    scan->prior_pool = (int)row->pool;
    memcpy(scan->prior_root, row->root, sizeof(scan->prior_root));
    scan->count++;
    return true;
}

static bool validate_anchors(sqlite3 *db,
                             const struct consensus_state_bundle_manifest *m,
                             struct consensus_state_install_result *r)
{
    int64_t tip_height[2] = {-1, -1};
    if (!anchor_tip_heights(db, tip_height, r))
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,anchor,height,tree "
            "FROM anchors ORDER BY pool,anchor", -1, &st, NULL) != SQLITE_OK)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle anchors table missing/malformed");
    struct sha3_256_ctx ctx;
    consensus_state_bundle_anchor_digest_begin(&ctx);
    struct anchor_scan scan = {
        .frontier_height = {-1, -1}, .prior_pool = -1,
    };
    bool ok = true;
    struct validate_heartbeat hb;
    heartbeat_begin(&hb, "validate_anchors", m->anchor_count);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        heartbeat_tick(&hb, scan.count);
        struct anchor_row row;
        anchor_row_load(st, &row);
        if (anchor_row_shape_bad(&row, scan.count, m->height,
                                 scan.prior_pool, scan.prior_root) ||
            !anchor_tree_valid(&row, tip_height) ||
            !anchor_scan_fold(&scan, &ctx, &row)) {
            ok = false;
            break;
        }
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    uint8_t digest[32];
    sha3_256_finalize(&ctx, digest);
    if (!ok || !anchors_summary_ok(&scan, m, digest))
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "anchor structure/root/digest mismatch");
    return true;
}

static bool validate_nullifiers(
    sqlite3 *db, const struct consensus_state_bundle_manifest *m,
    struct consensus_state_install_result *r)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf",
            -1, &st, NULL) != SQLITE_OK)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "bundle nullifiers table missing/malformed");
    struct sha3_256_ctx ctx;
    consensus_state_bundle_nullifier_digest_begin(&ctx);
    uint64_t count = 0;
    bool ok = true;
    uint8_t prior_nf[32] = {0};
    int prior_pool = -1;
    struct validate_heartbeat hb;
    heartbeat_begin(&hb, "validate_nullifiers", m->nullifier_count);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        heartbeat_tick(&hb, count);
        int nf_type = sqlite3_column_type(st, 1);
        const uint8_t *nf = nf_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int64_t pool = -1, height = -1;
        bool numeric = copy_int64_exact(st, 0, &pool) &&
                       copy_int64_exact(st, 2, &height);
        if (!numeric || nf_type != SQLITE_BLOB ||
            (pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0 ||
            height > m->height || count == UINT64_MAX ||
            (prior_pool == pool && memcmp(prior_nf, nf, 32) >= 0)) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(
            &ctx, (uint8_t)pool, nf, (uint64_t)height);
        prior_pool = pool;
        memcpy(prior_nf, nf, sizeof(prior_nf));
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    uint8_t digest[32];
    sha3_256_finalize(&ctx, digest);
    if (!ok || count != m->nullifier_count ||
        memcmp(digest, m->nullifier_digest, 32) != 0)
        return validation_fail(r, CONSENSUS_INSTALL_REFUSED,
                               "nullifier structure/digest mismatch");
    return true;
}

/* A compiled ROM keystone with any all-zero shielded field is unbaked (a
 * placeholder) and is not a trust root — a dev build that has not yet baked the
 * shielded fold must REFUSE at the checkpoint height, never admit unbound state. */
static bool rom_keystone_is_placeholder(const struct rom_state_checkpoint *rom)
{
    return !zcl_bytes_any_set(rom->anchor_digest, 32) ||
           !zcl_bytes_any_set(rom->nullifier_digest, 32) ||
           !zcl_bytes_any_set(rom->sprout_frontier_root, 32) ||
           !zcl_bytes_any_set(rom->sapling_frontier_root, 32) ||
           !zcl_bytes_any_set(rom->utxo_root, 32) ||
           !zcl_bytes_any_set(rom->rom_state_root, 32);
}

/* Shielded-ROM keystone binding — the complete-state extension of the
 * transparent SHA3 UTXO checkpoint. ZClassic headers commit neither the UTXO set
 * nor the Sapling/Sprout anchor+nullifier state, so a bundle installed AT the
 * compiled checkpoint height must reproduce the compiled keystone's transparent
 * AND shielded digests byte-for-byte. The manifest digests are validated against
 * the bundle's own rows by validate_anchors/validate_nullifiers (or honored via
 * an install-verify receipt for these exact bytes), so binding them to the
 * compiled constant transitively binds the installed shielded state to the
 * sovereign keystone. LOCAL trust anchoring only: this tightens what THIS binary
 * accepts as an install source — no block/tx/header validity rule changes, and a
 * bundle at any OTHER height is untouched. Fires only at the exact checkpoint (or
 * baked ladder rung, get_baked_rom_state_checkpoint_at_height)
 * height; same refusal shape as the other validators (loud CONSENSUS_INSTALL_REFUSED). */
static bool validate_rom_keystone_binding(
    const struct consensus_state_bundle_manifest *m,
    struct consensus_state_install_result *r)
{
    /* The keystone height OR any baked ladder rung height binds; the lookup
     * returns NULL for every other height. */
    const struct rom_state_checkpoint *rom =
        get_baked_rom_state_checkpoint_at_height(m->height);
    if (!rom)
        return true; /* not a baked-height bundle: nothing to bind */

    if (rom_keystone_is_placeholder(rom))
        return validation_fail(
            r, CONSENSUS_INSTALL_REFUSED,
            "REFUSED: bundle sits at the compiled checkpoint height %d but the "
            "compiled ROM shielded keystone is a placeholder (unbaked shielded "
            "fold) — refusing to admit checkpoint-height state that cannot be "
            "bound to a sovereign shielded commitment",
            rom->height);

    /* Transparent block anchor (same bytes the SHA3 checkpoint carries). */
    if (memcmp(m->block_hash, rom->block_hash, 32) != 0 ||
        memcmp(m->utxo_root, rom->utxo_root, 32) != 0 ||
        m->utxo_count != rom->utxo_count ||
        m->total_supply != rom->total_supply)
        return validation_fail(
            r, CONSENSUS_INSTALL_REFUSED,
            "REFUSED: bundle at checkpoint height %d does not reproduce the "
            "compiled transparent keystone (block_hash/utxo_root/count/supply)",
            rom->height);

    /* Sprout+Sapling anchor history + both commitment-tree frontier roots. */
    if (memcmp(m->anchor_digest, rom->anchor_digest, 32) != 0 ||
        m->anchor_count != rom->anchor_count ||
        memcmp(m->sprout_frontier_root, rom->sprout_frontier_root, 32) != 0 ||
        m->sprout_frontier_height != rom->sprout_frontier_height ||
        memcmp(m->sapling_frontier_root, rom->sapling_frontier_root, 32) != 0 ||
        m->sapling_frontier_height != rom->sapling_frontier_height)
        return validation_fail(
            r, CONSENSUS_INSTALL_REFUSED,
            "REFUSED: bundle at checkpoint height %d does not reproduce the "
            "compiled shielded anchor keystone (anchor_digest/count or "
            "Sprout/Sapling frontier root/height mismatch)",
            rom->height);

    /* Combined nullifier history. */
    if (memcmp(m->nullifier_digest, rom->nullifier_digest, 32) != 0 ||
        m->nullifier_count != rom->nullifier_count)
        return validation_fail(
            r, CONSENSUS_INSTALL_REFUSED,
            "REFUSED: bundle at checkpoint height %d does not reproduce the "
            "compiled shielded nullifier keystone (nullifier_digest/count "
            "mismatch)",
            rom->height);

    LOG_INFO(VALIDATE_SUBSYS,
             "shielded-ROM keystone bound: bundle at checkpoint height %d "
             "reproduces the compiled transparent + shielded keystone "
             "byte-for-byte (anchors=%llu, nullifiers=%llu)",
             rom->height, (unsigned long long)rom->anchor_count,
             (unsigned long long)rom->nullifier_count);
    return true;
}

bool consensus_state_bundle_validate_ex(
    sqlite3 *db, struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_install_result *result, bool skip_deep_scan)
{
    if (!db || !manifest)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "NULL db/manifest");
    if ((!skip_deep_scan && !integrity_check(db)) ||
        !consensus_state_bundle_validate_canonical_schema(db, result) ||
        !read_manifest(db, manifest, result))
        return false; // raw-return-ok:logged-by-callee
    uint8_t computed[32];
    consensus_state_bundle_artifact_digest(manifest, computed);
    if (memcmp(computed, manifest->artifact_digest, 32) != 0)
        return validation_fail(result, CONSENSUS_INSTALL_REFUSED,
                               "artifact digest mismatch");
    struct consensus_state_source_receipt receipt;
    if (!validate_source_receipt(db, manifest, &receipt, result) ||
        !validate_bundle_proof(db, manifest, &receipt, result))
        return false; // raw-return-ok:logged-by-callee
    /* Shielded-ROM keystone binding — fires at the compiled checkpoint height on
     * BOTH the deep-scan and receipt-honored paths. See below. */
    if (!validate_rom_keystone_binding(manifest, result))
        return false; // raw-return-ok:logged-by-callee
    if (skip_deep_scan) {
        LOG_INFO(VALIDATE_SUBSYS,
                 "deep content scan (coins/anchors/nullifiers, whole-file "
                 "integrity_check) skipped: install-verify receipt honored "
                 "for this exact bundle bytes + verifying binary");
        return true;
    }
#ifdef ZCL_TESTING
    atomic_fetch_add_explicit(&g_deep_scan_calls, 1, memory_order_relaxed);
#endif
    return validate_coins(db, manifest, result) &&
           validate_anchors(db, manifest, result) &&
           validate_nullifiers(db, manifest, result);
}

bool consensus_state_bundle_validate(
    sqlite3 *db, struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_install_result *result)
{
    return consensus_state_bundle_validate_ex(db, manifest, result, false);
}
