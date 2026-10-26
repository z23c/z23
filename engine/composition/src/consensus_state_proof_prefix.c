/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable installed-bundle proof-prefix evidence.  Contract:
 * consensus_state_proof_prefix.h. */

#include "consensus_state_proof_prefix.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define PREFIX_SUBSYS "consensus_bundle_prefix"

static const char *const k_component_names[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    "header_admit", "validate_headers", "body_fetch", "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
};

static const bool k_component_hash_bound[
    CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
    true, true, true, false, true, true, true, false,
};

static const char k_prefix_schema_sql[] =
    "CREATE TABLE IF NOT EXISTS consensus_state_proof_prefix_base("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "height INTEGER NOT NULL CHECK(height>=0),"
    "block_hash BLOB NOT NULL CHECK(length(block_hash)=32),"
    "validation_profile INTEGER NOT NULL CHECK(validation_profile IN(1,2)),"
    "proof_manifest_digest BLOB NOT NULL "
        "CHECK(length(proof_manifest_digest)=32),"
    "source_digest BLOB NOT NULL CHECK(length(source_digest)=32),"
    "artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32),"
    "authority_generation BLOB CHECK(authority_generation IS NULL OR "
        "(typeof(authority_generation)='blob' AND length(authority_generation)=8)));"
    "CREATE TABLE IF NOT EXISTS consensus_state_proof_prefix_component("
    "ordinal INTEGER PRIMARY KEY CHECK(ordinal>=0 AND ordinal<8),"
    "component TEXT NOT NULL UNIQUE,cursor INTEGER NOT NULL CHECK(cursor>=0),"
    "first_height INTEGER NOT NULL CHECK(first_height=0),"
    "last_height INTEGER NOT NULL CHECK(last_height>=0),"
    "row_count INTEGER NOT NULL CHECK(row_count>0),"
    "hash_bound_count INTEGER NOT NULL CHECK(hash_bound_count>=0),"
    "component_digest BLOB NOT NULL CHECK(length(component_digest)=32));";

static bool prefix_fail(const char *reason)
{
    LOG_WARN(PREFIX_SUBSYS, "%s", reason);
    return false; /* raw-return-ok:logged fail-closed evidence refusal */
}

static void proof_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(ctx, le, sizeof(le));
}

static bool copy_blob32(sqlite3_stmt *st, int column, uint8_t out[32])
{
    const void *blob = sqlite3_column_type(st, column) == SQLITE_BLOB
                           ? sqlite3_column_blob(st, column) : NULL;
    if (!blob || sqlite3_column_bytes(st, column) != 32)
        return false;
    memcpy(out, blob, 32);
    return true;
}

static bool text_equal(sqlite3_stmt *st, int column, const char *expected)
{
    const unsigned char *text =
        sqlite3_column_type(st, column) == SQLITE_TEXT
            ? sqlite3_column_text(st, column) : NULL;
    size_t len = strlen(expected);
    return text && sqlite3_column_bytes(st, column) == (int)len &&
           memcmp(text, expected, len) == 0;
}

static int64_t column_int_if_row(int rc, sqlite3_stmt *st, int column)
{
    return rc == SQLITE_ROW &&
                   sqlite3_column_type(st, column) == SQLITE_INTEGER
               ? sqlite3_column_int64(st, column) : -1;
}

/* Reports whether the stepped row's raw columns violate the shape
 * contract: ordinal, name, height window and non-negative counters. */
static bool component_row_values_bad(int rc, size_t i, int64_t ordinal,
                                     int64_t cursor, int64_t first,
                                     int64_t last, int64_t row_count,
                                     int64_t hash_count, int32_t height,
                                     uint64_t rows, sqlite3_stmt *st)
{
    return rc != SQLITE_ROW || ordinal != (int64_t)i ||
           !text_equal(st, 1, k_component_names[i]) || cursor < 0 ||
           first != 0 || last != height || row_count < 0 ||
           (uint64_t)row_count != rows || hash_count < 0;
}

/* Reports whether the cross-field invariants fail: hash-bound count,
 * cursor progress bounds and a non-zero component digest. */
static bool component_row_invariants_bad(size_t i, int64_t cursor,
                                         int64_t hash_count, uint64_t rows,
                                         uint64_t minimum, sqlite3_stmt *st,
                                         uint8_t digest[32])
{
    return (uint64_t)hash_count !=
               (k_component_hash_bound[i] ? rows : 0u) ||
           (uint64_t)cursor < minimum ||
           (i == 6u && (uint64_t)cursor != rows) ||
           (i == 7u && (uint64_t)cursor > minimum + 1u) ||
           !copy_blob32(st, 7, digest) ||
           !zcl_bytes_any_set(digest, 32);
}

static bool read_components(
    sqlite3 *db, const char *table,
    struct consensus_state_bundle_proof_summary
        out[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    int32_t height)
{
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT ordinal,component,cursor,first_height,"
                     "last_height,row_count,hash_bound_count,component_digest "
                     "FROM %s ORDER BY ordinal", table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    memset(out, 0, sizeof(*out) * CONSENSUS_STATE_BUNDLE_PROOF_COUNT);
    bool ok = true;
    uint64_t rows = (uint64_t)height + 1u;
    for (size_t i = 0; i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        int64_t ordinal = column_int_if_row(rc, st, 0);
        int64_t cursor = column_int_if_row(rc, st, 2);
        int64_t first = column_int_if_row(rc, st, 3);
        int64_t last = column_int_if_row(rc, st, 4);
        int64_t row_count = column_int_if_row(rc, st, 5);
        int64_t hash_count = column_int_if_row(rc, st, 6);
        uint64_t minimum = i == CONSENSUS_STATE_BUNDLE_PROOF_COUNT - 1u
                               ? (uint64_t)height : rows;
        if (component_row_values_bad(rc, i, ordinal, cursor, first, last,
                                     row_count, hash_count, height, rows,
                                     st) ||
            component_row_invariants_bad(i, cursor, hash_count, rows,
                                         minimum, st,
                                         out[i].component_digest)) {
            ok = false;
            break;
        }
        snprintf(out[i].component, sizeof(out[i].component), "%s",
                 k_component_names[i]);
        out[i].cursor = (uint64_t)cursor;
        out[i].first_height = first;
        out[i].last_height = last;
        out[i].row_count = (uint64_t)row_count;
        out[i].hash_bound_count = (uint64_t)hash_count;
    }
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    sqlite3_finalize(st);
    return ok;
}

static bool generation_column_present(sqlite3 *db, bool *present)
{
    *present = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "PRAGMA table_info(consensus_state_proof_prefix_base)",
            -1, &st, NULL) != SQLITE_OK)
        return prefix_fail("prefix generation: schema introspection failed");
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (text_equal(st, 1, "authority_generation"))
            *present = true;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ||
           prefix_fail("prefix generation: schema introspection read failed");
}

static bool ensure_schema(sqlite3 *db)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, k_prefix_schema_sql, NULL, NULL, &err) ==
              SQLITE_OK;
    if (!ok)
        LOG_WARN(PREFIX_SUBSYS, "prefix schema ensure failed: %s",
                 err ? err : sqlite3_errmsg(db));
    if (err)
        sqlite3_free(err);
    if (!ok)
        return false; /* raw-return-ok:schema error logged above */
    bool generation_present = false;
    if (!generation_column_present(db, &generation_present))
        return false; /* raw-return-ok:introspection logged failure */
    /* Migrate only while replacing evidence inside the install transaction.
     * Legacy reads never manufacture a current-generation association. */
    if (!generation_present) {
        err = NULL;
        ok = sqlite3_exec(db,
            "ALTER TABLE consensus_state_proof_prefix_base ADD COLUMN "
            "authority_generation BLOB CHECK(authority_generation IS NULL OR "
            "(typeof(authority_generation)='blob' AND length(authority_generation)=8))",
            NULL, NULL, &err) == SQLITE_OK;
        if (!ok)
            LOG_WARN(PREFIX_SUBSYS, "prefix generation migration failed: %s",
                     err ? err : sqlite3_errmsg(db));
        if (err)
            sqlite3_free(err);
    }
    return ok;
}

static bool clear_rows(sqlite3 *db)
{
    char *err = NULL;
    bool ok = sqlite3_exec(
        db,
        "DELETE FROM consensus_state_proof_prefix_component;"
        "DELETE FROM consensus_state_proof_prefix_base",
        NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        LOG_WARN(PREFIX_SUBSYS, "prefix replacement clear failed: %s",
                 err ? err : sqlite3_errmsg(db));
    if (err)
        sqlite3_free(err);
    return ok;
}

static bool prefix_manifest_complete(const struct consensus_state_bundle_manifest *m)
{
    return m->height >= 0 && m->height < INT32_MAX && m->history_complete &&
        m->activation_boundary == 0 &&
        m->source_fold_cursor == (int64_t)m->height + 1 &&
        (m->validation_profile == CONSENSUS_STATE_VALIDATION_FULL ||
         m->validation_profile == CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
        zcl_bytes_any_set(m->proof_manifest_digest, 32) &&
        zcl_bytes_any_set(m->source_digest, 32) &&
        zcl_bytes_any_set(m->artifact_digest, 32);
}

static bool prefix_install_generation(sqlite3 *db, uint8_t bytes[8])
{
    uint64_t generation = 0;
    if (!coins_kv_get_authority_generation(db, &generation) || generation == 0)
        return prefix_fail("prefix install: current coins generation unavailable");
    zcl_write_u64_le(bytes, generation);
    return true;
}

static bool prefix_store_prepared(sqlite3 *db)
{
    return ensure_schema(db) && clear_rows(db);
}

static bool prefix_install_base_row(
    sqlite3 *db, const struct consensus_state_bundle_manifest *manifest,
    const uint8_t generation_bytes[8])
{
    static const char base_sql[] =
        "INSERT INTO consensus_state_proof_prefix_base("
        "singleton,height,block_hash,validation_profile,"
        "proof_manifest_digest,source_digest,artifact_digest,authority_generation) "
        "VALUES(1,?,?,?,?,?,?,?)";
    sqlite3_stmt *base = NULL;
    bool ok = sqlite3_prepare_v2(db, base_sql, -1, &base, NULL) ==
                  SQLITE_OK &&
              sqlite3_bind_int(base, 1, manifest->height) == SQLITE_OK &&
              sqlite3_bind_blob(base, 2, manifest->block_hash, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(base, 3, manifest->validation_profile) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(base, 4, manifest->proof_manifest_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(base, 5, manifest->source_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(base, 6, manifest->artifact_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(base, 7, generation_bytes,
                                8, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_step(base) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (base)
        sqlite3_finalize(base);
    return ok;
}

static bool prefix_install_component_row(
    sqlite3_stmt *st, size_t ordinal,
    const struct consensus_state_bundle_proof_summary *row)
{
    return sqlite3_bind_int(st, 1, (int)ordinal) == SQLITE_OK &&
           sqlite3_bind_text(st, 2, row->component, -1,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int64(st, 3,
                              (sqlite3_int64)row->cursor) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, 4, row->first_height) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, 5, row->last_height) ==
               SQLITE_OK &&
           sqlite3_bind_int64(st, 6,
                              (sqlite3_int64)row->row_count) ==
               SQLITE_OK &&
           sqlite3_bind_int64(
               st, 7, (sqlite3_int64)row->hash_bound_count) ==
               SQLITE_OK &&
           sqlite3_bind_blob(st, 8, row->component_digest, 32,
                             SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
}

static bool prefix_install_component_rows(
    sqlite3 *db,
    const struct consensus_state_bundle_proof_summary *components)
{
    static const char component_sql[] =
        "INSERT INTO consensus_state_proof_prefix_component("
        "ordinal,component,cursor,first_height,last_height,row_count,"
        "hash_bound_count,component_digest) VALUES(?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, component_sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        ok = prefix_install_component_row(st, i, &components[i]);
        if (ok && i + 1u < CONSENSUS_STATE_BUNDLE_PROOF_COUNT)
            ok = sqlite3_reset(st) == SQLITE_OK &&
                 sqlite3_clear_bindings(st) == SQLITE_OK;
    }
    if (st)
        sqlite3_finalize(st);
    return ok;
}

bool consensus_state_proof_prefix_install_in_tx(
    sqlite3 *progress_db, sqlite3 *bundle_db,
    const struct consensus_state_bundle_manifest *manifest)
{
    if (!progress_db || !bundle_db || !manifest)
        return prefix_fail("prefix install: NULL argument");
    if (!prefix_manifest_complete(manifest))
        return prefix_fail("prefix install: manifest is not a complete proof base");

    struct consensus_state_bundle_proof_summary
        components[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    if (!read_components(bundle_db, "bundle_proof", components,
                         manifest->height))
        return prefix_fail("prefix install: bundle proof rows malformed");
    uint8_t proof_digest[32];
    consensus_state_bundle_proof_manifest_digest(
        components, CONSENSUS_STATE_BUNDLE_PROOF_COUNT, proof_digest);
    if (memcmp(proof_digest, manifest->proof_manifest_digest, 32) != 0)
        return prefix_fail("prefix install: proof manifest digest mismatch");
    uint8_t generation_bytes[8];
    if (!prefix_install_generation(progress_db, generation_bytes))
        return false; /* raw-return-ok:generation refusal logged */
    if (!prefix_store_prepared(progress_db))
        return false; /* raw-return-ok:helper logged store failure */

    bool ok = prefix_install_base_row(progress_db, manifest,
                                      generation_bytes);
    if (ok)
        ok = prefix_install_component_rows(progress_db, components);
    if (!ok)
        return prefix_fail("prefix install: durable evidence write failed");
    LOG_INFO(PREFIX_SUBSYS,
             "retained admitted proof prefix h=%d components=%u",
             manifest->height, (unsigned)CONSENSUS_STATE_BUNDLE_PROOF_COUNT);
    return true;
}

static bool prefix_load_generation(sqlite3_stmt *st,
                                    struct consensus_state_proof_prefix *out)
{
    if (sqlite3_column_type(st, 6) == SQLITE_NULL)
        return true;
    const uint8_t *bytes = sqlite3_column_type(st, 6) == SQLITE_BLOB
                              ? sqlite3_column_blob(st, 6) : NULL;
    if (!bytes || sqlite3_column_bytes(st, 6) != 8)
        return false;
    out->authority_generation = zcl_read_u64_le(bytes);
    out->authority_generation_present = out->authority_generation != 0;
    return out->authority_generation_present;
}

static bool prefix_load_digests(sqlite3_stmt *st,
                                struct consensus_state_proof_prefix *out)
{
    return copy_blob32(st, 1, out->block_hash) &&
        copy_blob32(st, 3, out->proof_manifest_digest) &&
        copy_blob32(st, 4, out->source_digest) &&
        copy_blob32(st, 5, out->artifact_digest) &&
        zcl_bytes_any_set(out->proof_manifest_digest, 32) &&
        zcl_bytes_any_set(out->source_digest, 32) &&
        zcl_bytes_any_set(out->artifact_digest, 32);
}

static bool prefix_profile_supported(int profile)
{
    return profile == CONSENSUS_STATE_VALIDATION_FULL ||
           profile == CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD;
}

/* 0 = prepared; 1 = table legitimately absent; -1 = malformed evidence. */
static int prefix_base_query_prepare(sqlite3 *db, bool generation_present,
                                     sqlite3_stmt **st)
{
    const char *sql = generation_present ?
        "SELECT height,block_hash,validation_profile,proof_manifest_digest,"
        "source_digest,artifact_digest,authority_generation "
        "FROM consensus_state_proof_prefix_base WHERE singleton=1" :
        "SELECT height,block_hash,validation_profile,proof_manifest_digest,"
        "source_digest,artifact_digest,NULL "
        "FROM consensus_state_proof_prefix_base WHERE singleton=1";
    if (sqlite3_prepare_v2(db, sql, -1, st, NULL) != SQLITE_OK) {
        /* A pre-feature or full-replay datadir legitimately has no table;
         * every other prepare error is malformed evidence, not absence. */
        const char *msg = sqlite3_errmsg(db);
        if (msg && strstr(msg, "no such table") != NULL)
            return 1;
        return -1;
    }
    return 0;
}

static bool prefix_base_row_valid(sqlite3_stmt *st, int rc, int64_t *height,
                                  int *profile,
                                  struct consensus_state_proof_prefix *out)
{
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER;
    *height = ok ? sqlite3_column_int64(st, 0) : -1;
    *profile = ok && sqlite3_column_type(st, 2) == SQLITE_INTEGER
                   ? sqlite3_column_int(st, 2) : 0;
    ok = ok && *height >= 0 && *height < INT32_MAX &&
         prefix_profile_supported(*profile) &&
         prefix_load_digests(st, out);
    if (ok)
        ok = prefix_load_generation(st, out);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    return ok;
}

bool consensus_state_proof_prefix_load(
    sqlite3 *progress_db, struct consensus_state_proof_prefix *out)
{
    if (!progress_db || !out)
        return prefix_fail("prefix load: NULL argument");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    bool generation_present = false;
    if (!generation_column_present(progress_db, &generation_present))
        return false; /* raw-return-ok:introspection logged failure */
    int prep = prefix_base_query_prepare(progress_db, generation_present,
                                         &st);
    if (prep > 0)
        return true;
    if (prep < 0)
        return prefix_fail("prefix load: base query failed");
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return true;
    }
    int64_t height;
    int profile;
    bool ok = prefix_base_row_valid(st, rc, &height, &profile, out);
    sqlite3_finalize(st);
    if (!ok)
        return prefix_fail("prefix load: base row malformed");
    out->height = (int32_t)height;
    out->validation_profile = (uint8_t)profile;
    if (!read_components(progress_db,
                         "consensus_state_proof_prefix_component",
                         out->components, out->height))
        return prefix_fail("prefix load: component rows malformed");
    uint8_t recomputed[32];
    consensus_state_bundle_proof_manifest_digest(
        out->components, CONSENSUS_STATE_BUNDLE_PROOF_COUNT, recomputed);
    if (memcmp(recomputed, out->proof_manifest_digest, 32) != 0)
        return prefix_fail("prefix load: component manifest mismatch");
    out->present = true;
    return true;
}

static void prefix_to_parent(
    const struct consensus_state_proof_prefix *prefix,
    struct consensus_state_bundle_proof_parent *parent)
{
    memset(parent, 0, sizeof(*parent));
    parent->present = true;
    parent->base_height = prefix->height;
    memcpy(parent->base_block_hash, prefix->block_hash, 32);
    parent->validation_profile = prefix->validation_profile;
    memcpy(parent->proof_manifest_digest, prefix->proof_manifest_digest, 32);
    memcpy(parent->source_digest, prefix->source_digest, 32);
    memcpy(parent->artifact_digest, prefix->artifact_digest, 32);
    memcpy(parent->components, prefix->components,
           sizeof(parent->components));
}

static bool header_has_genesis(sqlite3 *db, bool *present)
{
    *present = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT 1 FROM header_admit_log WHERE height=0", -1, &st,
            NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_ROW) {
        *present = true;
        rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool header_args_valid(sqlite3 *progress_db,
                              const uint8_t expected_hash[32],
                              uint8_t out[32], int32_t height)
{
    return progress_db && expected_hash && out && height >= 0;
}

/* 0 = proceed; 1 = genesis probe failed; 2 = prefix load failed;
 * 3 = no genesis corpus and no admitted prefix;
 * 4 = target does not extend the admitted prefix. */
static int header_prefix_mode(sqlite3 *progress_db, int32_t height,
                              struct consensus_state_proof_prefix *prefix,
                              bool *composed, int64_t *first)
{
    bool genesis = false;
    if (!header_has_genesis(progress_db, &genesis))
        return 1;
    if (!consensus_state_proof_prefix_load(progress_db, prefix))
        return 2;
    *composed = !genesis && prefix->present;
    if (!genesis && !prefix->present)
        return 3;
    if (*composed && height <= prefix->height)
        return 4;
    *first = *composed ? (int64_t)prefix->height + 1 : 0;
    return 0;
}

static void header_seed_chain(struct sha3_256_ctx *ctx, bool composed,
                              const struct consensus_state_proof_prefix
                                  *prefix,
                              int32_t height, uint8_t prior[32])
{
    memset(prior, 0, 32);
    if (composed) {
        static const char suffix_domain[] =
            "zcl.consensus_state_bundle.v1/proof-extension-suffix/header";
        sha3_256_write(ctx, (const uint8_t *)suffix_domain,
                       sizeof(suffix_domain));
        proof_u64(ctx, (uint64_t)prefix->height);
        proof_u64(ctx, (uint64_t)height);
        sha3_256_write(ctx, prefix->block_hash, 32);
        memcpy(prior, prefix->block_hash, 32);
    } else {
        static const char domain[] =
            "zcl.consensus_state_bundle.v1/source-header-chain";
        sha3_256_write(ctx, (const uint8_t *)domain, sizeof(domain));
    }
}

static bool header_row_linked(sqlite3_stmt *st, int64_t row_height,
                              const void *parent, const uint8_t prior[32])
{
    bool genesis_parent = row_height == 0 &&
                          sqlite3_column_type(st, 2) == SQLITE_NULL;
    bool linked_parent = row_height > 0 && parent &&
                         sqlite3_column_bytes(st, 2) == 32 &&
                         memcmp(parent, prior, 32) == 0;
    return genesis_parent || linked_parent;
}

static void header_row_hash(struct sha3_256_ctx *ctx, int64_t row_height,
                            const void *hash, const void *parent)
{
    proof_u64(ctx, (uint64_t)row_height);
    sha3_256_write(ctx, hash, 32);
    if (row_height == 0) {
        uint8_t no_parent[32] = {0};
        sha3_256_write(ctx, no_parent, 32);
    } else {
        sha3_256_write(ctx, parent, 32);
    }
}

static bool header_corpus_rows_ok(sqlite3_stmt *st,
                                  struct sha3_256_ctx *ctx, int64_t first,
                                  int32_t height,
                                  const uint8_t expected_hash[32],
                                  uint8_t prior[32])
{
    int64_t expected_height = first;
    int rc = SQLITE_ERROR;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        int64_t row_height = sqlite3_column_type(st, 0) == SQLITE_INTEGER
                                 ? sqlite3_column_int64(st, 0) : -1;
        const void *hash = sqlite3_column_type(st, 1) == SQLITE_BLOB
                               ? sqlite3_column_blob(st, 1) : NULL;
        const void *parent = sqlite3_column_type(st, 2) == SQLITE_BLOB
                                 ? sqlite3_column_blob(st, 2) : NULL;
        bool linked = header_row_linked(st, row_height, parent, prior);
        if (row_height != expected_height || !hash ||
            sqlite3_column_bytes(st, 1) != 32 ||
            !linked)
            return false;
        header_row_hash(ctx, row_height, hash, parent);
        memcpy(prior, hash, 32);
        expected_height++;
    }
    return rc == SQLITE_DONE && expected_height == (int64_t)height + 1 &&
           memcmp(prior, expected_hash, 32) == 0;
}

/* 0 = corpus verified; 1 = query prepare failed; 2 = corpus unusable. */
static int header_corpus_chain_status(
    sqlite3 *progress_db, bool composed,
    const struct consensus_state_proof_prefix *prefix, int32_t height,
    int64_t first, const uint8_t expected_hash[32],
    struct sha3_256_ctx *ctx)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            progress_db,
            "SELECT height,hash,parent_hash FROM header_admit_log "
            "WHERE height BETWEEN ? AND ? ORDER BY height",
            -1, &st, NULL) != SQLITE_OK)
        return 1;
    bool ok = sqlite3_bind_int64(st, 1, first) == SQLITE_OK &&
              sqlite3_bind_int(st, 2, height) == SQLITE_OK;
    sha3_256_init(ctx);
    uint8_t prior[32];
    header_seed_chain(ctx, composed, prefix, height, prior);
    if (ok)
        ok = header_corpus_rows_ok(st, ctx, first, height, expected_hash,
                                   prior);
    sqlite3_finalize(st);
    return ok ? 0 : 2;
}

static bool header_composed_suffix_digest(
    struct sha3_256_ctx *ctx,
    const struct consensus_state_proof_prefix *prefix, uint8_t out[32],
    struct consensus_state_bundle_proof_parent *parent_out)
{
    struct consensus_state_bundle_proof_parent parent;
    prefix_to_parent(prefix, &parent);
    sha3_256_finalize(ctx, parent.suffix_digest[0]);
    bool ok = consensus_state_bundle_proof_extension_digest(&parent, 0, out);
    if (ok && parent_out)
        *parent_out = parent;
    return ok;
}

bool consensus_state_proof_header_digest(
    sqlite3 *progress_db, int32_t height, const uint8_t expected_hash[32],
    uint8_t out[32], struct consensus_state_bundle_proof_parent *parent_out)
{
    if (parent_out)
        memset(parent_out, 0, sizeof(*parent_out));
    if (!header_args_valid(progress_db, expected_hash, out, height))
        return prefix_fail("header proof: invalid argument");

    struct consensus_state_proof_prefix prefix;
    bool composed = false;
    int64_t first = 0;
    int mode = header_prefix_mode(progress_db, height, &prefix, &composed,
                                  &first);
    if (mode == 1)
        return prefix_fail("header proof: genesis probe failed");
    if (mode == 2)
        return false; /* raw-return-ok:prefix loader logged malformed evidence */
    if (mode == 3)
        return prefix_fail(
            "header proof: neither local genesis corpus nor admitted prefix exists");
    if (mode == 4)
        return prefix_fail(
            "header proof: target does not extend the admitted prefix");

    struct sha3_256_ctx ctx;
    int corpus = header_corpus_chain_status(progress_db, composed, &prefix,
                                            height, first, expected_hash,
                                            &ctx);
    if (corpus == 1)
        return prefix_fail("header proof: row query prepare failed");
    if (corpus == 2)
        return prefix_fail("header proof: corpus incomplete, unlinked, or wrong tip");

    if (!composed) {
        sha3_256_finalize(&ctx, out);
        return true;
    }
    if (!header_composed_suffix_digest(&ctx, &prefix, out, parent_out))
        return prefix_fail("header proof: extension digest failed");
    return true;
}
