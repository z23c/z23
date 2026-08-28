/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable local authority for sovereign machine pairing. */

#ifndef ZCL_MODELS_MESH_PAIRING_H
#define ZCL_MODELS_MESH_PAIRING_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_PAIRING_ID_HEX 64
#define MESH_PAIRING_CAP_STATUS_READ UINT64_C(1)
#define MESH_PAIRING_CAP_KNOWN MESH_PAIRING_CAP_STATUS_READ

struct db_mesh_pairing {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    uint8_t network_genesis[32];
    uint8_t peer_master_pubkey[32];
    uint8_t peer_noise_pubkey[32];
    uint64_t capability_mask;
    uint64_t delegation_sequence;
    int64_t paired_at;
    int64_t expires_at;
    int64_t revoked_at;
    uint64_t revocation_generation;
};

struct ar_callbacks *db_mesh_pairing_callbacks(void);

/* Stable local key for one network/master/static-key tuple. No mutable policy
 * or time field participates in this identity. */
bool mesh_pairing_id_derive(
    const uint8_t network_genesis[32], const uint8_t peer_master_pubkey[32],
    const uint8_t peer_noise_pubkey[32],
    char out[MESH_PAIRING_ID_HEX + 1]);

bool db_mesh_pairing_validate(const struct db_mesh_pairing *row,
                              struct ar_errors *errors);

/* Insert-only. A prior record cannot be widened or resurrected through save. */
bool db_mesh_pairing_insert(struct node_db *ndb,
                            const struct db_mesh_pairing *row);
bool db_mesh_pairing_find(struct node_db *ndb, const char *pairing_id,
                          struct db_mesh_pairing *out);
int db_mesh_pairing_list(struct node_db *ndb, struct db_mesh_pairing *out,
                         size_t max);

/* Idempotent sticky revocation. The first transition increments the durable
 * generation; later calls preserve the original timestamp and generation. */
bool db_mesh_pairing_revoke(struct node_db *ndb, const char *pairing_id,
                            int64_t revoked_at);

bool mesh_pairing_allows(const struct db_mesh_pairing *row,
                         uint64_t required_capability, int64_t now);

#endif /* ZCL_MODELS_MESH_PAIRING_H */
