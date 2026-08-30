/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable installed-bundle proof-prefix evidence.  Contract:
 * consensus_state_proof_prefix.h. */

#include "consensus_state_proof_prefix.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
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
    "artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32));"
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

static bool digest_nonzero(const uint8_t digest[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= digest[i];
    return any != 0;
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
        int64_t ordinal = rc == SQLITE_ROW &&
                                  sqlite3_column_type(st, 0) == SQLITE_INTEGER
                              ? sqlite3_column_int64(st, 0) : -1;
        int64_t cursor = rc == SQLITE_ROW &&
                                 sqlite3_column_type(st, 2) == SQLITE_INTEGER
                             ? sqlite3_column_int64(st, 2) : -1;
        int64_t first = rc == SQLITE_ROW &&
                                sqlite3_column_type(st, 3) == SQLITE_INTEGER
                            ? sqlite3_column_int64(st, 3) : -1;
        int64_t last = rc == SQLITE_ROW &&
                               sqlite3_column_type(st, 4) == SQLITE_INTEGER
                           ? sqlite3_column_int64(st, 4) : -1;
        int64_t row_count = rc == SQLITE_ROW &&
                                    sqlite3_column_type(st, 5) == SQLITE_INTEGER
                                ? sqlite3_column_int64(st, 5) : -1;
        int64_t hash_count = rc == SQLITE_ROW &&
                                     sqlite3_column_type(st, 6) == SQLITE_INTEGER
                                 ? sqlite3_column_int64(st, 6) : -1;
        uint64_t minimum = i == CONSENSUS_STATE_BUNDLE_PROOF_COUNT - 1u
                               ? (uint64_t)height : rows;
        if (rc != SQLITE_ROW || ordinal != (int64_t)i ||
            !text_equal(st, 1, k_component_names[i]) || cursor < 0 ||
            first != 0 || last != height || row_count < 0 ||
            (uint64_t)row_count != rows || hash_count < 0 ||
            (uint64_t)hash_count !=
                (k_component_hash_bound[i] ? rows : 0u) ||
            (uint64_t)cursor < minimum ||
            (i == 6u && (uint64_t)cursor != rows) ||
            (i == 7u && (uint64_t)cursor > minimum + 1u) ||
            !copy_blob32(st, 7, out[i].component_digest) ||
            !digest_nonzero(out[i].component_digest)) {
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

bool consensus_state_proof_prefix_install_in_tx(
    sqlite3 *progress_db, sqlite3 *bundle_db,
    const struct consensus_state_bundle_manifest *manifest)
{
    if (!progress_db || !bundle_db || !manifest)
        return prefix_fail("prefix install: NULL argument");
    if (manifest->height < 0 || manifest->height == INT32_MAX ||
        !manifest->history_complete || manifest->activation_boundary != 0 ||
        manifest->source_fold_cursor != (int64_t)manifest->height + 1 ||
        (manifest->validation_profile != CONSENSUS_STATE_VALIDATION_FULL &&
         manifest->validation_profile !=
             CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) ||
        !digest_nonzero(manifest->proof_manifest_digest) ||
        !digest_nonzero(manifest->source_digest) ||
        !digest_nonzero(manifest->artifact_digest))
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
    if (!ensure_schema(progress_db) || !clear_rows(progress_db))
        return false; /* raw-return-ok:helper logged store failure */

    static const char base_sql[] =
        "INSERT INTO consensus_state_proof_prefix_base("
        "singleton,height,block_hash,validation_profile,"
        "proof_manifest_digest,source_digest,artifact_digest) "
        "VALUES(1,?,?,?,?,?,?)";
    sqlite3_stmt *base = NULL;
    bool ok = sqlite3_prepare_v2(progress_db, base_sql, -1, &base, NULL) ==
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
              sqlite3_step(base) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (base)
        sqlite3_finalize(base);

    static const char component_sql[] =
        "INSERT INTO consensus_state_proof_prefix_component("
        "ordinal,component,cursor,first_height,last_height,row_count,"
        "hash_bound_count,component_digest) VALUES(?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (ok)
        ok = sqlite3_prepare_v2(progress_db, component_sql, -1, &st, NULL) ==
             SQLITE_OK;
    for (size_t i = 0; ok && i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        ok = sqlite3_bind_int(st, 1, (int)i) == SQLITE_OK &&
             sqlite3_bind_text(st, 2, components[i].component, -1,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_int64(st, 3,
                                (sqlite3_int64)components[i].cursor) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 4, components[i].first_height) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 5, components[i].last_height) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(st, 6,
                                (sqlite3_int64)components[i].row_count) ==
                 SQLITE_OK &&
             sqlite3_bind_int64(
                 st, 7, (sqlite3_int64)components[i].hash_bound_count) ==
                 SQLITE_OK &&
             sqlite3_bind_blob(st, 8, components[i].component_digest, 32,
                               SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
        if (ok && i + 1u < CONSENSUS_STATE_BUNDLE_PROOF_COUNT)
            ok = sqlite3_reset(st) == SQLITE_OK &&
                 sqlite3_clear_bindings(st) == SQLITE_OK;
    }
    if (st)
        sqlite3_finalize(st);
    if (!ok)
        return prefix_fail("prefix install: durable evidence write failed");
    LOG_INFO(PREFIX_SUBSYS,
             "retained admitted proof prefix h=%d components=%u",
             manifest->height, (unsigned)CONSENSUS_STATE_BUNDLE_PROOF_COUNT);
    return true;
}

bool consensus_state_proof_prefix_load(
    sqlite3 *progress_db, struct consensus_state_proof_prefix *out)
{
    if (!progress_db || !out)
        return prefix_fail("prefix load: NULL argument");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "SELECT height,block_hash,validation_profile,proof_manifest_digest,"
        "source_digest,artifact_digest "
        "FROM consensus_state_proof_prefix_base WHERE singleton=1";
    if (sqlite3_prepare_v2(progress_db, sql, -1, &st, NULL) != SQLITE_OK) {
        /* A pre-feature or full-replay datadir legitimately has no table;
         * every other prepare error is malformed evidence, not absence. */
        const char *msg = sqlite3_errmsg(progress_db);
        if (msg && strstr(msg, "no such table") != NULL)
            return true;
        return prefix_fail("prefix load: base query failed");
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return true;
    }
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER;
    int64_t height = ok ? sqlite3_column_int64(st, 0) : -1;
    int profile = ok && sqlite3_column_type(st, 2) == SQLITE_INTEGER
                      ? sqlite3_column_int(st, 2) : 0;
    ok = ok && height >= 0 && height < INT32_MAX &&
         (profile == CONSENSUS_STATE_VALIDATION_FULL ||
          profile == CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
         copy_blob32(st, 1, out->block_hash) &&
         copy_blob32(st, 3, out->proof_manifest_digest) &&
         copy_blob32(st, 4, out->source_digest) &&
         copy_blob32(st, 5, out->artifact_digest) &&
         digest_nonzero(out->proof_manifest_digest) &&
         digest_nonzero(out->source_digest) &&
         digest_nonzero(out->artifact_digest);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
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

bool consensus_state_proof_header_digest(
    sqlite3 *progress_db, int32_t height, const uint8_t expected_hash[32],
    uint8_t out[32], struct consensus_state_bundle_proof_parent *parent_out)
{
    if (parent_out)
        memset(parent_out, 0, sizeof(*parent_out));
    if (!progress_db || !expected_hash || !out || height < 0)
        return prefix_fail("header proof: invalid argument");

    bool genesis = false;
    if (!header_has_genesis(progress_db, &genesis))
        return prefix_fail("header proof: genesis probe failed");
    struct consensus_state_proof_prefix prefix;
    if (!consensus_state_proof_prefix_load(progress_db, &prefix))
        return false; /* raw-return-ok:prefix loader logged malformed evidence */
    bool composed = !genesis && prefix.present;
    if (!genesis && !prefix.present)
        return prefix_fail(
            "header proof: neither local genesis corpus nor admitted prefix exists");
    if (composed && height <= prefix.height)
        return prefix_fail(
            "header proof: target does not extend the admitted prefix");

    int64_t first = composed ? (int64_t)prefix.height + 1 : 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            progress_db,
            "SELECT height,hash,parent_hash FROM header_admit_log "
            "WHERE height BETWEEN ? AND ? ORDER BY height",
            -1, &st, NULL) != SQLITE_OK)
        return prefix_fail("header proof: row query prepare failed");
    bool ok = sqlite3_bind_int64(st, 1, first) == SQLITE_OK &&
              sqlite3_bind_int(st, 2, height) == SQLITE_OK;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    if (composed) {
        static const char suffix_domain[] =
            "zcl.consensus_state_bundle.v1/proof-extension-suffix/header";
        sha3_256_write(&ctx, (const uint8_t *)suffix_domain,
                       sizeof(suffix_domain));
        proof_u64(&ctx, (uint64_t)prefix.height);
        proof_u64(&ctx, (uint64_t)height);
        sha3_256_write(&ctx, prefix.block_hash, 32);
    } else {
        static const char domain[] =
            "zcl.consensus_state_bundle.v1/source-header-chain";
        sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    }

    uint8_t prior[32] = {0};
    if (composed)
        memcpy(prior, prefix.block_hash, 32);
    int64_t expected_height = first;
    int rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        int64_t row_height = sqlite3_column_type(st, 0) == SQLITE_INTEGER
                                 ? sqlite3_column_int64(st, 0) : -1;
        const void *hash = sqlite3_column_type(st, 1) == SQLITE_BLOB
                               ? sqlite3_column_blob(st, 1) : NULL;
        const void *parent = sqlite3_column_type(st, 2) == SQLITE_BLOB
                                 ? sqlite3_column_blob(st, 2) : NULL;
        bool genesis_parent = row_height == 0 &&
                              sqlite3_column_type(st, 2) == SQLITE_NULL;
        bool linked_parent = row_height > 0 && parent &&
                             sqlite3_column_bytes(st, 2) == 32 &&
                             memcmp(parent, prior, 32) == 0;
        if (row_height != expected_height || !hash ||
            sqlite3_column_bytes(st, 1) != 32 ||
            (!genesis_parent && !linked_parent)) {
            ok = false;
            break;
        }
        proof_u64(&ctx, (uint64_t)row_height);
        sha3_256_write(&ctx, hash, 32);
        if (row_height == 0) {
            uint8_t no_parent[32] = {0};
            sha3_256_write(&ctx, no_parent, 32);
        } else {
            sha3_256_write(&ctx, parent, 32);
        }
        memcpy(prior, hash, 32);
        expected_height++;
    }
    if (rc != SQLITE_DONE || expected_height != (int64_t)height + 1 ||
        memcmp(prior, expected_hash, 32) != 0)
        ok = false;
    sqlite3_finalize(st);
    if (!ok)
        return prefix_fail("header proof: corpus incomplete, unlinked, or wrong tip");

    if (!composed) {
        sha3_256_finalize(&ctx, out);
        return true;
    }
    struct consensus_state_bundle_proof_parent parent;
    prefix_to_parent(&prefix, &parent);
    sha3_256_finalize(&ctx, parent.suffix_digest[0]);
    if (!consensus_state_bundle_proof_extension_digest(&parent, 0, out))
        return prefix_fail("header proof: extension digest failed");
    if (parent_out)
        *parent_out = parent;
    return true;
}
