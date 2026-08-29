/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for private mesh object grants. */

#include "models/mesh_capability_grant.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(mesh_capability_grant)

static bool mesh_capability_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= value[i];
    return any != 0;
}

static bool mesh_capability_hex_id(const char *value)
{
    uint8_t decoded[32];
    return value && strlen(value) == MESH_CAPABILITY_GRANT_ID_HEX &&
           zcl_hex_decode_lower(value, decoded, sizeof(decoded));
}

bool mesh_capability_grant_id_derive(
    const struct db_mesh_capability_grant *grant,
    char out[MESH_CAPABILITY_GRANT_ID_HEX + 1])
{
    if (!grant || !out || !mesh_capability_hex_id(grant->pairing_id))
        LOG_FAIL("mesh_capability", "derive: invalid arguments or pairing");
    static const uint8_t domain[] =
        "zcl.mesh.capability.private-object-receive.v1";
    uint8_t fields[80];
    zcl_write_u32_le(fields, (uint32_t)grant->operation);
    zcl_write_u64_le(fields + 4, grant->object_size_bytes);
    zcl_write_u64_le(fields + 12, grant->ciphertext_size_bytes);
    zcl_write_u64_le(fields + 20, grant->storage_limit_bytes);
    zcl_write_u64_le(fields + 28, grant->transfer_limit_bytes);
    zcl_write_u32_le(fields + 36, grant->chunk_limit);
    zcl_write_u32_le(fields + 40, grant->max_chunk_bytes);
    zcl_write_u32_le(fields + 44, grant->wall_limit_seconds);
    zcl_write_u64_le(fields + 48, grant->deny_mask);
    zcl_write_u64_le(fields + 56, (uint64_t)grant->issued_at);
    zcl_write_u64_le(fields + 64, (uint64_t)grant->not_before);
    zcl_write_u64_le(fields + 72, (uint64_t)grant->expires_at);
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, (const uint8_t *)grant->pairing_id,
                   MESH_PAIRING_ID_HEX);
    sha3_256_write(&hash, grant->plaintext_root, 32);
    sha3_256_write(&hash, grant->ciphertext_root, 32);
    sha3_256_write(&hash, grant->nonce, 32);
    sha3_256_write(&hash, fields, 80);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

bool db_mesh_capability_grant_validate(
    const struct db_mesh_capability_grant *grant, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!grant) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    char derived[MESH_CAPABILITY_GRANT_ID_HEX + 1] = {0};
    bool pairing_ok = mesh_capability_hex_id(grant->pairing_id);
    bool derived_ok = pairing_ok &&
        mesh_capability_grant_id_derive(grant, derived);
    validates_custom(errors,
                     mesh_capability_hex_id(grant->grant_id) && derived_ok &&
                         strcmp(grant->grant_id, derived) == 0,
                     "grant_id", "must match every immutable grant field");
    validates_custom(errors, pairing_ok, "pairing_id",
                     "must be 64 canonical lowercase hex chars");
    validates_custom(errors,
                     grant->operation == MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE,
                     "operation", "must be private-object receive");
    validates_custom(errors, mesh_capability_nonzero(grant->plaintext_root),
                     "plaintext_root", "must be non-zero");
    validates_custom(errors, mesh_capability_nonzero(grant->ciphertext_root),
                     "ciphertext_root", "must be non-zero");
    validates_custom(errors,
                     grant->object_size_bytes > 0 &&
                         grant->object_size_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_OBJECT_BYTES,
                     "object_size_bytes", "is outside the private-object cap");
    validates_custom(errors,
                     grant->ciphertext_size_bytes >= grant->object_size_bytes &&
                         grant->ciphertext_size_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES,
                     "ciphertext_size_bytes", "is outside the ciphertext cap");
    validates_custom(errors,
                     grant->storage_limit_bytes >=
                             grant->ciphertext_size_bytes &&
                         grant->storage_limit_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES,
                     "storage_limit_bytes", "does not bound the ciphertext");
    validates_custom(errors,
                     grant->transfer_limit_bytes >=
                             grant->ciphertext_size_bytes &&
                         grant->transfer_limit_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES,
                     "transfer_limit_bytes", "does not bound the ciphertext");
    validates_custom(errors,
                     grant->chunk_limit > 0 &&
                         grant->chunk_limit <= MESH_CAPABILITY_GRANT_MAX_CHUNKS,
                     "chunk_limit", "is outside the chunk-count cap");
    validates_custom(errors,
                     grant->max_chunk_bytes > 0 &&
                         grant->max_chunk_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_CHUNK_BYTES,
                     "max_chunk_bytes", "is outside the chunk-size cap");
    uint64_t chunk_capacity =
        (uint64_t)grant->chunk_limit * grant->max_chunk_bytes;
    validates_custom(errors, chunk_capacity >= grant->ciphertext_size_bytes,
                     "chunk_limits", "cannot carry the exact ciphertext");
    validates_custom(errors,
                     grant->wall_limit_seconds > 0 &&
                         grant->wall_limit_seconds <=
                             MESH_CAPABILITY_GRANT_MAX_WALL_SECONDS,
                     "wall_limit_seconds", "is outside the wall-time cap");
    validates_custom(errors, mesh_capability_nonzero(grant->nonce), "nonce",
                     "must be non-zero");
    validates_custom(errors,
                     grant->deny_mask == MESH_CAPABILITY_DENY_MANDATORY,
                     "deny_mask", "must deny every protected authority");
    validates_custom(errors, grant->issued_at > 0, "issued_at",
                     "must be positive");
    validates_custom(errors,
                     grant->not_before >= grant->issued_at &&
                         grant->expires_at > grant->not_before &&
                         grant->expires_at - grant->issued_at <=
                             MESH_CAPABILITY_GRANT_MAX_LIFETIME_SECONDS,
                     "validity", "has an invalid or excessive window");
    validates_custom(errors,
                     grant->consumed_at == 0 ||
                         (grant->consumed_at >= grant->not_before &&
                          grant->consumed_at < grant->expires_at),
                     "consumed_at", "is outside the grant window");
    validates_custom(errors,
                     (grant->revoked_at == 0 &&
                      grant->revocation_generation == 0) ||
                         (grant->revoked_at >= grant->issued_at &&
                          grant->revocation_generation > 0),
                     "revocation", "timestamp and generation disagree");
    return !ar_errors_any(errors);
}

#define MESH_CAPABILITY_COLS \
    "grant_id,pairing_id,operation,plaintext_root,ciphertext_root," \
    "object_size_bytes,ciphertext_size_bytes,storage_limit_bytes," \
    "transfer_limit_bytes,chunk_limit,max_chunk_bytes,wall_limit_seconds," \
    "nonce,deny_mask,issued_at,not_before,expires_at,consumed_at,revoked_at," \
    "revocation_generation"

static void mesh_capability_read(struct db_mesh_capability_grant *out,
                                 sqlite3_stmt *st)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(st, 0, out->grant_id, sizeof(out->grant_id));
    AR_READ_STR(st, 1, out->pairing_id, sizeof(out->pairing_id));
    out->operation = (enum mesh_capability_operation)AR_COL_INT(st, 2);
    AR_READ_BLOB(st, 3, out->plaintext_root, 32);
    AR_READ_BLOB(st, 4, out->ciphertext_root, 32);
    out->object_size_bytes = (uint64_t)AR_COL_INT(st, 5);
    out->ciphertext_size_bytes = (uint64_t)AR_COL_INT(st, 6);
    out->storage_limit_bytes = (uint64_t)AR_COL_INT(st, 7);
    out->transfer_limit_bytes = (uint64_t)AR_COL_INT(st, 8);
    out->chunk_limit = (uint32_t)AR_COL_INT(st, 9);
    out->max_chunk_bytes = (uint32_t)AR_COL_INT(st, 10);
    out->wall_limit_seconds = (uint32_t)AR_COL_INT(st, 11);
    AR_READ_BLOB(st, 12, out->nonce, 32);
    out->deny_mask = (uint64_t)AR_COL_INT(st, 13);
    out->issued_at = AR_COL_INT(st, 14);
    out->not_before = AR_COL_INT(st, 15);
    out->expires_at = AR_COL_INT(st, 16);
    out->consumed_at = AR_COL_INT(st, 17);
    out->revoked_at = AR_COL_INT(st, 18);
    out->revocation_generation = (uint64_t)AR_COL_INT(st, 19);
}

bool db_mesh_capability_grant_find(
    struct node_db *ndb, const char *grant_id,
    struct db_mesh_capability_grant *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !mesh_capability_hex_id(grant_id) || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " MESH_CAPABILITY_COLS
        " FROM mesh_capability_grants WHERE grant_id=?",
        AR_BIND_TEXT(st, 1, grant_id), mesh_capability_read(out, st));
}

static bool mesh_capability_immutable_equal(
    const struct db_mesh_capability_grant *left,
    const struct db_mesh_capability_grant *right)
{
    return strcmp(left->grant_id, right->grant_id) == 0 &&
           strcmp(left->pairing_id, right->pairing_id) == 0 &&
           left->operation == right->operation &&
           memcmp(left->plaintext_root, right->plaintext_root, 32) == 0 &&
           memcmp(left->ciphertext_root, right->ciphertext_root, 32) == 0 &&
           left->object_size_bytes == right->object_size_bytes &&
           left->ciphertext_size_bytes == right->ciphertext_size_bytes &&
           left->storage_limit_bytes == right->storage_limit_bytes &&
           left->transfer_limit_bytes == right->transfer_limit_bytes &&
           left->chunk_limit == right->chunk_limit &&
           left->max_chunk_bytes == right->max_chunk_bytes &&
           left->wall_limit_seconds == right->wall_limit_seconds &&
           memcmp(left->nonce, right->nonce, 32) == 0 &&
           left->deny_mask == right->deny_mask &&
           left->issued_at == right->issued_at &&
           left->not_before == right->not_before &&
           left->expires_at == right->expires_at;
}

bool db_mesh_capability_grant_insert(
    struct node_db *ndb, const struct db_mesh_capability_grant *grant)
{
    if (!ndb || !ndb->open || !grant || grant->consumed_at != 0 ||
        grant->revoked_at != 0 || grant->revocation_generation != 0)
        LOG_FAIL("mesh_capability", "insert: bad arguments or mutable state");
    struct db_mesh_pairing pairing;
    if (!db_mesh_pairing_find(ndb, grant->pairing_id, &pairing) ||
        pairing.revoked_at != 0 || grant->issued_at < pairing.paired_at ||
        grant->expires_at > pairing.expires_at) {
        LOG_ERROR("mesh_capability",
                  "insert: grant window or authority exceeds pairing %.64s",
                  grant->pairing_id);
        return false;
    }
    struct ar_callbacks *callbacks = db_mesh_capability_grant_callbacks();
    AR_BEGIN_SAVE(callbacks, "mesh_capability_grant", grant,
                  db_mesh_capability_grant_validate);
    sqlite3_stmt *st = NULL;
    AR_PREPARE_BOOL(ndb, st,
        "INSERT OR IGNORE INTO mesh_capability_grants(" MESH_CAPABILITY_COLS
        ") SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
        "SELECT 1 FROM mesh_pairings p WHERE p.pairing_id=? AND "
        "p.revoked_at=0 AND p.paired_at<=? AND p.expires_at>=?) "
        "RETURNING grant_id");
    AR_BIND_TEXT(st, 1, grant->grant_id);
    AR_BIND_TEXT(st, 2, grant->pairing_id);
    AR_BIND_INT(st, 3, grant->operation);
    AR_BIND_BLOB(st, 4, grant->plaintext_root, 32);
    AR_BIND_BLOB(st, 5, grant->ciphertext_root, 32);
    AR_BIND_INT(st, 6, (int64_t)grant->object_size_bytes);
    AR_BIND_INT(st, 7, (int64_t)grant->ciphertext_size_bytes);
    AR_BIND_INT(st, 8, (int64_t)grant->storage_limit_bytes);
    AR_BIND_INT(st, 9, (int64_t)grant->transfer_limit_bytes);
    AR_BIND_INT(st, 10, grant->chunk_limit);
    AR_BIND_INT(st, 11, grant->max_chunk_bytes);
    AR_BIND_INT(st, 12, grant->wall_limit_seconds);
    AR_BIND_BLOB(st, 13, grant->nonce, 32);
    AR_BIND_INT(st, 14, (int64_t)grant->deny_mask);
    AR_BIND_INT(st, 15, grant->issued_at);
    AR_BIND_INT(st, 16, grant->not_before);
    AR_BIND_INT(st, 17, grant->expires_at);
    AR_BIND_INT(st, 18, 0);
    AR_BIND_INT(st, 19, 0);
    AR_BIND_INT(st, 20, 0);
    AR_BIND_TEXT(st, 21, grant->pairing_id);
    AR_BIND_INT(st, 22, grant->issued_at);
    AR_BIND_INT(st, 23, grant->expires_at);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    if (!saved) {
        struct db_mesh_capability_grant existing;
        saved = db_mesh_capability_grant_find(ndb, grant->grant_id,
                                              &existing) &&
                mesh_capability_immutable_equal(&existing, grant);
    }
    if (!saved)
        LOG_ERROR("mesh_capability", "insert: grant collision refused");
    AR_FINISH_SAVE(callbacks, grant, saved);
}

bool mesh_capability_grant_allows(
    const struct db_mesh_capability_grant *grant, int64_t now)
{
    if (!grant || now <= 0)
        return false;
    return grant->operation == MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE &&
           grant->deny_mask == MESH_CAPABILITY_DENY_MANDATORY &&
           grant->consumed_at == 0 && grant->revoked_at == 0 &&
           now >= grant->not_before && now < grant->expires_at;
}

bool db_mesh_capability_grant_revoke(
    struct node_db *ndb, const char *grant_id, int64_t revoked_at)
{
    struct db_mesh_capability_grant row;
    if (!ndb || !ndb->open || revoked_at <= 0 ||
        !db_mesh_capability_grant_find(ndb, grant_id, &row))
        LOG_FAIL("mesh_capability", "revoke: grant not found or bad arguments");
    if (row.revoked_at != 0)
        return true;
    if (revoked_at < row.issued_at || row.revocation_generation == UINT64_MAX)
        LOG_FAIL("mesh_capability", "revoke: invalid time or generation");
    uint64_t prior_generation = row.revocation_generation;
    row.revoked_at = revoked_at;
    row.revocation_generation++;
    struct ar_callbacks *callbacks = db_mesh_capability_grant_callbacks();
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(callbacks, "mesh_capability_grant", &row,
                  db_mesh_capability_grant_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE mesh_capability_grants SET revoked_at=?,"
        "revocation_generation=? WHERE grant_id=? AND revoked_at=0 AND "
        "revocation_generation=? RETURNING grant_id");
    AR_BIND_INT(st, 1, row.revoked_at);
    AR_BIND_INT(st, 2, (int64_t)row.revocation_generation);
    AR_BIND_TEXT(st, 3, row.grant_id);
    AR_BIND_INT(st, 4, (int64_t)prior_generation);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    AR_FINISH_SAVE(callbacks, &row, saved);
}

bool db_mesh_capability_grant_consume(
    struct node_db *ndb, const char *grant_id, const uint8_t nonce[32],
    int64_t now)
{
    struct db_mesh_capability_grant row;
    if (!ndb || !ndb->open || !nonce || now <= 0 ||
        !db_mesh_capability_grant_find(ndb, grant_id, &row) ||
        memcmp(row.nonce, nonce, 32) != 0 ||
        !mesh_capability_grant_allows(&row, now)) {
        LOG_ERROR("mesh_capability",
                  "consume: grant unavailable, mismatched, or already used");
        return false;
    }
    row.consumed_at = now;
    struct ar_callbacks *callbacks = db_mesh_capability_grant_callbacks();
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(callbacks, "mesh_capability_grant", &row,
                  db_mesh_capability_grant_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE mesh_capability_grants SET consumed_at=? "
        "WHERE grant_id=? AND nonce=? AND consumed_at=0 AND revoked_at=0 "
        "AND not_before<=? AND expires_at>? AND EXISTS(SELECT 1 FROM "
        "mesh_pairings p WHERE p.pairing_id=mesh_capability_grants.pairing_id "
        "AND p.revoked_at=0 AND p.expires_at>?) RETURNING grant_id");
    AR_BIND_INT(st, 1, now);
    AR_BIND_TEXT(st, 2, row.grant_id);
    AR_BIND_BLOB(st, 3, nonce, 32);
    AR_BIND_INT(st, 4, now);
    AR_BIND_INT(st, 5, now);
    AR_BIND_INT(st, 6, now);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    if (!saved)
        LOG_ERROR("mesh_capability",
                  "consume: authority changed before one-use transition");
    AR_FINISH_SAVE(callbacks, &row, saved);
}
