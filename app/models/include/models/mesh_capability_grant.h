/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable least-authority grants for private mesh object receipt. */

#ifndef ZCL_MODELS_MESH_CAPABILITY_GRANT_H
#define ZCL_MODELS_MESH_CAPABILITY_GRANT_H

#include "models/activerecord.h"
#include "models/database.h"
#include "models/mesh_pairing.h"

#include <stdbool.h>
#include <stdint.h>

#define MESH_CAPABILITY_GRANT_ID_HEX 64
#define MESH_CAPABILITY_GRANT_MAX_LIFETIME_SECONDS INT64_C(2592000)
#define MESH_CAPABILITY_GRANT_MAX_OBJECT_BYTES UINT64_C(1073741824)
#define MESH_CAPABILITY_GRANT_MAX_CIPHERTEXT_BYTES UINT64_C(2147483648)
#define MESH_CAPABILITY_GRANT_MAX_CHUNKS UINT32_C(4096)
#define MESH_CAPABILITY_GRANT_MAX_CHUNK_BYTES UINT32_C(4194304)
#define MESH_CAPABILITY_GRANT_MAX_WALL_SECONDS UINT32_C(86400)

enum mesh_capability_operation {
    MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE = 1,
};

enum mesh_capability_denial {
    MESH_CAPABILITY_DENY_WALLET = UINT64_C(1) << 0,
    MESH_CAPABILITY_DENY_CONSENSUS = UINT64_C(1) << 1,
    MESH_CAPABILITY_DENY_CANONICAL_DATADIR = UINT64_C(1) << 2,
    MESH_CAPABILITY_DENY_DEPLOYMENT = UINT64_C(1) << 3,
    MESH_CAPABILITY_DENY_SECRETS = UINT64_C(1) << 4,
    MESH_CAPABILITY_DENY_DELEGATION = UINT64_C(1) << 5,
};

#define MESH_CAPABILITY_DENY_MANDATORY \
    (MESH_CAPABILITY_DENY_WALLET | MESH_CAPABILITY_DENY_CONSENSUS | \
     MESH_CAPABILITY_DENY_CANONICAL_DATADIR | \
     MESH_CAPABILITY_DENY_DEPLOYMENT | MESH_CAPABILITY_DENY_SECRETS | \
     MESH_CAPABILITY_DENY_DELEGATION)
#define MESH_CAPABILITY_DENY_KNOWN MESH_CAPABILITY_DENY_MANDATORY

struct db_mesh_capability_grant {
    char grant_id[MESH_CAPABILITY_GRANT_ID_HEX + 1];
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    enum mesh_capability_operation operation;
    uint8_t plaintext_root[32];
    uint8_t ciphertext_root[32];
    uint64_t object_size_bytes;
    uint64_t ciphertext_size_bytes;
    uint64_t storage_limit_bytes;
    uint64_t transfer_limit_bytes;
    uint32_t chunk_limit;
    uint32_t max_chunk_bytes;
    uint32_t wall_limit_seconds;
    uint8_t nonce[32];
    uint64_t deny_mask;
    int64_t issued_at;
    int64_t not_before;
    int64_t expires_at;
    int64_t consumed_at;
    int64_t revoked_at;
    uint64_t revocation_generation;
};

struct ar_callbacks *db_mesh_capability_grant_callbacks(void);

bool mesh_capability_grant_id_derive(
    const struct db_mesh_capability_grant *grant,
    char out[MESH_CAPABILITY_GRANT_ID_HEX + 1]);
bool db_mesh_capability_grant_validate(
    const struct db_mesh_capability_grant *grant, struct ar_errors *errors);

/* Insert only. An exact replay is idempotent and never resets consumed or
 * revoked state; any identity collision is refused. */
bool db_mesh_capability_grant_insert(
    struct node_db *ndb, const struct db_mesh_capability_grant *grant);
bool db_mesh_capability_grant_find(
    struct node_db *ndb, const char *grant_id,
    struct db_mesh_capability_grant *out);

/* Revocation is sticky and idempotent. Consumption succeeds exactly once and
 * additionally requires the bound pairing to remain active at `now`. */
bool db_mesh_capability_grant_revoke(
    struct node_db *ndb, const char *grant_id, int64_t revoked_at);
bool db_mesh_capability_grant_consume(
    struct node_db *ndb, const char *grant_id, const uint8_t nonce[32],
    int64_t now);

bool mesh_capability_grant_allows(
    const struct db_mesh_capability_grant *grant, int64_t now);

#endif /* ZCL_MODELS_MESH_CAPABILITY_GRANT_H */
