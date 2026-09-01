/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for private mesh object grants. */

#include "models/mesh_capability_grant.h"

#include "base/bytes.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(mesh_capability_grant)

static bool capability_hex_id(const char *value)
{
    uint8_t decoded[32];
    return value && strlen(value) == MESH_CAPABILITY_GRANT_ID_HEX &&
           zcl_hex_decode_lower(value, decoded, sizeof(decoded));
}

static uint32_t capability_chunk_count(uint64_t object_size)
{
    return (uint32_t)(object_size /
                          MESH_CAPABILITY_GRANT_CHUNK_PAYLOAD_BYTES +
                      (object_size %
                           MESH_CAPABILITY_GRANT_CHUNK_PAYLOAD_BYTES != 0));
}

bool mesh_capability_grant_id_derive(
    const struct db_mesh_capability_grant *grant,
    char out[MESH_CAPABILITY_GRANT_ID_HEX + 1])
{
    if (!grant || !out || !capability_hex_id(grant->pairing_id))
        LOG_FAIL("mesh_capability", "derive: invalid arguments or pairing");
    static const uint8_t domain[] =
        "zcl.mesh.capability.private-object-receive.v2";
    uint8_t fields[80];
    zcl_write_u32_le(fields, (uint32_t)grant->operation);
    zcl_write_u64_le(fields + 4, grant->object_size_bytes);
    zcl_write_u64_le(fields + 12, grant->ciphertext_size_bytes);
    zcl_write_u64_le(fields + 20, grant->storage_limit_bytes);
    zcl_write_u64_le(fields + 28, grant->transfer_limit_bytes);
    zcl_write_u32_le(fields + 36, grant->max_chunk_bytes);
    zcl_write_u32_le(fields + 40, grant->chunk_count);
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
    sha3_256_write(&hash, grant->target_master_pubkey, 32);
    sha3_256_write(&hash, grant->target_noise_static, 32);
    sha3_256_write(&hash, grant->plaintext_root, 32);
    sha3_256_write(&hash, grant->ciphertext_root, 32);
    sha3_256_write(&hash, grant->nonce, 32);
    sha3_256_write(&hash, fields, sizeof(fields));
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool capability_geometry_valid(
    const struct db_mesh_capability_grant *grant)
{
    if (grant->object_size_bytes == 0 ||
        grant->object_size_bytes > MESH_CAPABILITY_GRANT_MAX_OBJECT_BYTES)
        return false;
    uint32_t chunks = capability_chunk_count(grant->object_size_bytes);
    uint64_t ciphertext = grant->object_size_bytes +
        (uint64_t)chunks * MESH_CAPABILITY_GRANT_CHUNK_TAG_BYTES;
    return chunks > 0 && chunks <= MESH_CAPABILITY_GRANT_MAX_CHUNKS &&
           grant->max_chunk_bytes == MESH_CAPABILITY_GRANT_CHUNK_BYTES &&
           grant->chunk_count == chunks &&
           grant->ciphertext_size_bytes == ciphertext &&
           ciphertext <= MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES;
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
    bool pairing_ok = capability_hex_id(grant->pairing_id);
    bool derived_ok = pairing_ok &&
        mesh_capability_grant_id_derive(grant, derived);
    validates_custom(errors,
                     capability_hex_id(grant->grant_id) && derived_ok &&
                         strcmp(grant->grant_id, derived) == 0,
                     "grant_id", "must match every immutable grant field");
    validates_custom(errors, pairing_ok, "pairing_id",
                     "must be 64 canonical lowercase hex chars");
    validates_custom(errors, zcl_bytes_any_set(grant->target_master_pubkey, 32),
                     "target_master_pubkey", "must be non-zero");
    validates_custom(errors, zcl_bytes_any_set(grant->target_noise_static, 32),
                     "target_noise_static", "must be non-zero");
    validates_custom(errors,
                     grant->operation == MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE,
                     "operation", "must be private-object receive");
    validates_custom(errors, zcl_bytes_any_set(grant->plaintext_root, 32),
                     "plaintext_root", "must be non-zero");
    validates_custom(errors, zcl_bytes_any_set(grant->ciphertext_root, 32),
                     "ciphertext_root", "must be non-zero");
    validates_custom(errors, capability_geometry_valid(grant), "geometry",
                     "must use canonical sealed 64 KiB chunks");
    bool storage_sum_ok = grant->ciphertext_size_bytes <=
        UINT64_MAX - grant->object_size_bytes;
    uint64_t required_storage = storage_sum_ok
        ? grant->ciphertext_size_bytes + grant->object_size_bytes
        : UINT64_MAX;
    validates_custom(errors,
                     storage_sum_ok &&
                         grant->storage_limit_bytes >= required_storage &&
                         grant->storage_limit_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_STORAGE_BYTES,
                     "storage_limit_bytes", "does not bound both stages");
    validates_custom(errors,
                     grant->transfer_limit_bytes >=
                             grant->ciphertext_size_bytes &&
                         grant->transfer_limit_bytes <=
                             MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES,
                     "transfer_limit_bytes", "does not bound the ciphertext");
    validates_custom(errors,
                     grant->wall_limit_seconds > 0 &&
                         grant->wall_limit_seconds <=
                             MESH_CAPABILITY_GRANT_MAX_WALL_SECONDS,
                     "wall_limit_seconds", "is outside the wall-time cap");
    validates_custom(errors, zcl_bytes_any_set(grant->nonce, 32), "nonce",
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
    bool transfer_set = zcl_bytes_any_set(grant->transfer_id, 32);
    validates_custom(errors,
                     (grant->claimed_at == 0 && !transfer_set &&
                      grant->consumed_at == 0) ||
                         (grant->claimed_at >= grant->not_before &&
                          grant->claimed_at < grant->expires_at && transfer_set &&
                          (grant->consumed_at == 0 ||
                           (grant->consumed_at >= grant->claimed_at &&
                            grant->consumed_at < grant->expires_at))),
                     "lifecycle", "claim, transfer, and completion disagree");
    validates_custom(errors,
                     (grant->revoked_at == 0 &&
                      grant->revocation_generation == 0) ||
                         (grant->revoked_at >= grant->issued_at &&
                          grant->revocation_generation > 0),
                     "revocation", "timestamp and generation disagree");
    return !ar_errors_any(errors);
}

#define MESH_CAPABILITY_COLS \
    "grant_id,pairing_id,target_master_pubkey,target_noise_static,operation," \
    "plaintext_root,ciphertext_root,object_size_bytes,ciphertext_size_bytes," \
    "storage_limit_bytes,transfer_limit_bytes,max_chunk_bytes,chunk_count," \
    "wall_limit_seconds,nonce,deny_mask,issued_at,not_before,expires_at," \
    "transfer_id,claimed_at,consumed_at,revoked_at,revocation_generation"

static void capability_read(struct db_mesh_capability_grant *out,
                            sqlite3_stmt *st)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(st, 0, out->grant_id, sizeof(out->grant_id));
    AR_READ_STR(st, 1, out->pairing_id, sizeof(out->pairing_id));
    AR_READ_BLOB(st, 2, out->target_master_pubkey, 32);
    AR_READ_BLOB(st, 3, out->target_noise_static, 32);
    out->operation = (enum mesh_capability_operation)AR_COL_INT(st, 4);
    AR_READ_BLOB(st, 5, out->plaintext_root, 32);
    AR_READ_BLOB(st, 6, out->ciphertext_root, 32);
    out->object_size_bytes = (uint64_t)AR_COL_INT(st, 7);
    out->ciphertext_size_bytes = (uint64_t)AR_COL_INT(st, 8);
    out->storage_limit_bytes = (uint64_t)AR_COL_INT(st, 9);
    out->transfer_limit_bytes = (uint64_t)AR_COL_INT(st, 10);
    out->max_chunk_bytes = (uint32_t)AR_COL_INT(st, 11);
    out->chunk_count = (uint32_t)AR_COL_INT(st, 12);
    out->wall_limit_seconds = (uint32_t)AR_COL_INT(st, 13);
    AR_READ_BLOB(st, 14, out->nonce, 32);
    out->deny_mask = (uint64_t)AR_COL_INT(st, 15);
    out->issued_at = AR_COL_INT(st, 16);
    out->not_before = AR_COL_INT(st, 17);
    out->expires_at = AR_COL_INT(st, 18);
    int transfer_len = AR_COL_BYTES(st, 19);
    if (transfer_len == 32)
        AR_READ_BLOB(st, 19, out->transfer_id, 32);
    out->claimed_at = AR_COL_INT(st, 20);
    out->consumed_at = AR_COL_INT(st, 21);
    out->revoked_at = AR_COL_INT(st, 22);
    out->revocation_generation = (uint64_t)AR_COL_INT(st, 23);
}

bool db_mesh_capability_grant_find(
    struct node_db *ndb, const char *grant_id,
    struct db_mesh_capability_grant *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !capability_hex_id(grant_id) || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " MESH_CAPABILITY_COLS
        " FROM mesh_capability_grants WHERE grant_id=?",
        AR_BIND_TEXT(st, 1, grant_id), capability_read(out, st));
}

static bool capability_immutable_equal(
    const struct db_mesh_capability_grant *left,
    const struct db_mesh_capability_grant *right)
{
    return strcmp(left->grant_id, right->grant_id) == 0 &&
           strcmp(left->pairing_id, right->pairing_id) == 0 &&
           memcmp(left->target_master_pubkey,
                  right->target_master_pubkey, 32) == 0 &&
           memcmp(left->target_noise_static,
                  right->target_noise_static, 32) == 0 &&
           left->operation == right->operation &&
           memcmp(left->plaintext_root, right->plaintext_root, 32) == 0 &&
           memcmp(left->ciphertext_root, right->ciphertext_root, 32) == 0 &&
           left->object_size_bytes == right->object_size_bytes &&
           left->ciphertext_size_bytes == right->ciphertext_size_bytes &&
           left->storage_limit_bytes == right->storage_limit_bytes &&
           left->transfer_limit_bytes == right->transfer_limit_bytes &&
           left->max_chunk_bytes == right->max_chunk_bytes &&
           left->chunk_count == right->chunk_count &&
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
    if (!ndb || !ndb->open || !grant || grant->claimed_at != 0 ||
        grant->consumed_at != 0 || zcl_bytes_any_set(grant->transfer_id, 32) ||
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
        ") SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? "
        "WHERE EXISTS(SELECT 1 FROM mesh_pairings p WHERE p.pairing_id=? "
        "AND p.revoked_at=0 AND p.paired_at<=? AND p.expires_at>=?) "
        "RETURNING grant_id");
    AR_BIND_TEXT(st, 1, grant->grant_id);
    AR_BIND_TEXT(st, 2, grant->pairing_id);
    AR_BIND_BLOB(st, 3, grant->target_master_pubkey, 32);
    AR_BIND_BLOB(st, 4, grant->target_noise_static, 32);
    AR_BIND_INT(st, 5, grant->operation);
    AR_BIND_BLOB(st, 6, grant->plaintext_root, 32);
    AR_BIND_BLOB(st, 7, grant->ciphertext_root, 32);
    AR_BIND_INT(st, 8, (int64_t)grant->object_size_bytes);
    AR_BIND_INT(st, 9, (int64_t)grant->ciphertext_size_bytes);
    AR_BIND_INT(st, 10, (int64_t)grant->storage_limit_bytes);
    AR_BIND_INT(st, 11, (int64_t)grant->transfer_limit_bytes);
    AR_BIND_INT(st, 12, grant->max_chunk_bytes);
    AR_BIND_INT(st, 13, grant->chunk_count);
    AR_BIND_INT(st, 14, grant->wall_limit_seconds);
    AR_BIND_BLOB(st, 15, grant->nonce, 32);
    AR_BIND_INT(st, 16, (int64_t)grant->deny_mask);
    AR_BIND_INT(st, 17, grant->issued_at);
    AR_BIND_INT(st, 18, grant->not_before);
    AR_BIND_INT(st, 19, grant->expires_at);
    AR_BIND_BLOB(st, 20, grant->transfer_id, 0);
    AR_BIND_INT(st, 21, 0);
    AR_BIND_INT(st, 22, 0);
    AR_BIND_INT(st, 23, 0);
    AR_BIND_INT(st, 24, 0);
    AR_BIND_TEXT(st, 25, grant->pairing_id);
    AR_BIND_INT(st, 26, grant->issued_at);
    AR_BIND_INT(st, 27, grant->expires_at);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    if (!saved) {
        struct db_mesh_capability_grant existing;
        saved = db_mesh_capability_grant_find(ndb, grant->grant_id,
                                              &existing) &&
                capability_immutable_equal(&existing, grant);
    }
    if (!saved)
        LOG_ERROR("mesh_capability", "insert: grant collision refused");
    AR_FINISH_SAVE(callbacks, grant, saved);
}

bool mesh_capability_grant_allows(
    const struct db_mesh_capability_grant *grant, int64_t now)
{
    return grant && now > 0 &&
           grant->operation == MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE &&
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

static bool capability_claim_new(
    struct node_db *ndb, struct db_mesh_capability_grant *row,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    memcpy(row->transfer_id, transfer_id, 32);
    row->claimed_at = now;
    struct ar_callbacks *callbacks = db_mesh_capability_grant_callbacks();
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(callbacks, "mesh_capability_grant", row,
                  db_mesh_capability_grant_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE mesh_capability_grants SET transfer_id=?,claimed_at=? "
        "WHERE grant_id=? AND length(transfer_id)=0 AND claimed_at=0 AND "
        "consumed_at=0 AND revoked_at=0 AND revocation_generation=? AND "
        "not_before<=? AND expires_at>? AND EXISTS(SELECT 1 FROM "
        "mesh_pairings p WHERE p.pairing_id=mesh_capability_grants.pairing_id "
        "AND p.revoked_at=0 AND p.revocation_generation=? AND "
        "p.expires_at>?) RETURNING grant_id");
    AR_BIND_BLOB(st, 1, transfer_id, 32);
    AR_BIND_INT(st, 2, now);
    AR_BIND_TEXT(st, 3, row->grant_id);
    AR_BIND_INT(st, 4, (int64_t)grant_generation);
    AR_BIND_INT(st, 5, now);
    AR_BIND_INT(st, 6, now);
    AR_BIND_INT(st, 7, (int64_t)pairing_generation);
    AR_BIND_INT(st, 8, now);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    AR_FINISH_SAVE(callbacks, row, saved);
}

static bool capability_resume_authorized(
    struct node_db *ndb, const char *grant_id,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    sqlite3_stmt *st = NULL;
    AR_QUERY_EXISTS(ndb, st,
        "SELECT 1 FROM mesh_capability_grants g WHERE g.grant_id=? AND "
        "g.transfer_id=? AND g.claimed_at>0 AND g.consumed_at=0 AND "
        "g.revoked_at=0 AND g.revocation_generation=? AND g.not_before<=? "
        "AND g.expires_at>? AND EXISTS(SELECT 1 FROM mesh_pairings p WHERE "
        "p.pairing_id=g.pairing_id AND p.revoked_at=0 AND "
        "p.revocation_generation=? AND p.expires_at>?)",
        AR_BIND_TEXT(st, 1, grant_id);
        AR_BIND_BLOB(st, 2, transfer_id, 32);
        AR_BIND_INT(st, 3, (int64_t)grant_generation);
        AR_BIND_INT(st, 4, now);
        AR_BIND_INT(st, 5, now);
        AR_BIND_INT(st, 6, (int64_t)pairing_generation);
        AR_BIND_INT(st, 7, now));
}

enum mesh_capability_claim_result db_mesh_capability_grant_claim(
    struct node_db *ndb, const char *grant_id,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    struct db_mesh_capability_grant row;
    if (!ndb || !ndb->open || !transfer_id ||
        !zcl_bytes_any_set(transfer_id, 32) || now <= 0 ||
        pairing_generation > (uint64_t)INT64_MAX ||
        grant_generation > (uint64_t)INT64_MAX ||
        !db_mesh_capability_grant_find(ndb, grant_id, &row) ||
        row.revocation_generation != grant_generation ||
        !mesh_capability_grant_allows(&row, now))
        return MESH_CAPABILITY_CLAIM_REFUSED;
    if (row.claimed_at == 0 && capability_claim_new(
            ndb, &row, transfer_id, pairing_generation, grant_generation, now))
        return MESH_CAPABILITY_CLAIM_NEW;
    return capability_resume_authorized(
               ndb, grant_id, transfer_id, pairing_generation,
               grant_generation, now)
               ? MESH_CAPABILITY_CLAIM_RESUME
               : MESH_CAPABILITY_CLAIM_REFUSED;
}

static bool capability_complete_new(
    struct node_db *ndb, struct db_mesh_capability_grant *row,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    row->consumed_at = now;
    struct ar_callbacks *callbacks = db_mesh_capability_grant_callbacks();
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(callbacks, "mesh_capability_grant", row,
                  db_mesh_capability_grant_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE mesh_capability_grants SET consumed_at=? WHERE grant_id=? "
        "AND transfer_id=? AND claimed_at>0 AND consumed_at=0 AND "
        "revoked_at=0 AND revocation_generation=? AND not_before<=? AND "
        "expires_at>? AND EXISTS(SELECT 1 FROM mesh_pairings p WHERE "
        "p.pairing_id=mesh_capability_grants.pairing_id AND p.revoked_at=0 "
        "AND p.revocation_generation=? AND p.expires_at>?) RETURNING grant_id");
    AR_BIND_INT(st, 1, now);
    AR_BIND_TEXT(st, 2, row->grant_id);
    AR_BIND_BLOB(st, 3, transfer_id, 32);
    AR_BIND_INT(st, 4, (int64_t)grant_generation);
    AR_BIND_INT(st, 5, now);
    AR_BIND_INT(st, 6, now);
    AR_BIND_INT(st, 7, (int64_t)pairing_generation);
    AR_BIND_INT(st, 8, now);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    AR_FINISH_SAVE(callbacks, row, saved);
}

static bool capability_completion_replay_authorized(
    struct node_db *ndb, const char *grant_id,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    sqlite3_stmt *st = NULL;
    AR_QUERY_EXISTS(ndb, st,
        "SELECT 1 FROM mesh_capability_grants g WHERE g.grant_id=? AND "
        "g.transfer_id=? AND g.claimed_at>0 AND g.consumed_at>0 AND "
        "g.revoked_at=0 AND g.revocation_generation=? AND g.expires_at>? "
        "AND EXISTS(SELECT 1 FROM mesh_pairings p WHERE "
        "p.pairing_id=g.pairing_id AND p.revoked_at=0 AND "
        "p.revocation_generation=? AND p.expires_at>?)",
        AR_BIND_TEXT(st, 1, grant_id);
        AR_BIND_BLOB(st, 2, transfer_id, 32);
        AR_BIND_INT(st, 3, (int64_t)grant_generation);
        AR_BIND_INT(st, 4, now);
        AR_BIND_INT(st, 5, (int64_t)pairing_generation);
        AR_BIND_INT(st, 6, now));
}

enum mesh_capability_complete_result db_mesh_capability_grant_complete(
    struct node_db *ndb, const char *grant_id,
    const uint8_t transfer_id[32], uint64_t pairing_generation,
    uint64_t grant_generation, int64_t now)
{
    struct db_mesh_capability_grant row;
    if (!ndb || !ndb->open || !transfer_id ||
        !zcl_bytes_any_set(transfer_id, 32) || now <= 0 ||
        pairing_generation > (uint64_t)INT64_MAX ||
        grant_generation > (uint64_t)INT64_MAX ||
        !db_mesh_capability_grant_find(ndb, grant_id, &row) ||
        memcmp(row.transfer_id, transfer_id, 32) != 0)
        return MESH_CAPABILITY_COMPLETE_REFUSED;
    if (row.consumed_at != 0)
        return capability_completion_replay_authorized(
                   ndb, grant_id, transfer_id, pairing_generation,
                   grant_generation, now)
                   ? MESH_CAPABILITY_COMPLETE_REPLAY
                   : MESH_CAPABILITY_COMPLETE_REFUSED;
    if (row.claimed_at == 0 ||
        row.revocation_generation != grant_generation ||
        !mesh_capability_grant_allows(&row, now))
        return MESH_CAPABILITY_COMPLETE_REFUSED;
    return capability_complete_new(
               ndb, &row, transfer_id, pairing_generation,
               grant_generation, now)
               ? MESH_CAPABILITY_COMPLETE_NEW
               : MESH_CAPABILITY_COMPLETE_REFUSED;
}
