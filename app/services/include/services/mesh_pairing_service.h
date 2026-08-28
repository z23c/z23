/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify, accept, revoke, and authorize machine pairings. */

#ifndef ZCL_SERVICES_MESH_PAIRING_SERVICE_H
#define ZCL_SERVICES_MESH_PAIRING_SERVICE_H

#include "models/mesh_pairing.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdint.h>

#define MESH_PAIRING_MAX_LIFETIME_SECONDS INT64_C(2592000)

enum mesh_pairing_reason {
    MESH_PAIRING_OK = 0,
    MESH_PAIRING_BAD_ARGUMENT,
    MESH_PAIRING_CAPABILITY_UNAVAILABLE,
    MESH_PAIRING_FINGERPRINT_MISMATCH,
    MESH_PAIRING_NETWORK_MISMATCH,
    MESH_PAIRING_MASTER_INACTIVE,
    MESH_PAIRING_BEACON_UNAVAILABLE,
    MESH_PAIRING_BEACON_PROVISIONAL,
    MESH_PAIRING_DELEGATION_INVALID,
    MESH_PAIRING_WINDOW_INVALID,
    MESH_PAIRING_ALREADY_REVOKED,
    MESH_PAIRING_IDENTITY_COLLISION,
    MESH_PAIRING_PERSIST_FAILED,
    MESH_PAIRING_NOT_FOUND,
    MESH_PAIRING_EXPIRED,
    MESH_PAIRING_SESSION_MISMATCH,
    MESH_PAIRING_AUTHORITY_CHANGED,
};

const char *mesh_pairing_reason_token(enum mesh_pairing_reason reason);

/* Accept one peer only after its public Noise fingerprint was compared out of
 * band. The signed delegation is rechecked against this node's connected
 * genesis, active ZID projection, finality-delayed beacon, and current time.
 * The first product capability is deliberately status-read only. */
enum mesh_pairing_reason mesh_pairing_service_accept(
    struct node_db *ndb,
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_noise_fingerprint[32],
    const uint8_t authenticated_session_noise_static[32],
    bool session_authenticated, uint64_t capability_mask, int64_t now,
    int64_t expires_at, struct db_mesh_pairing *out);

enum mesh_pairing_reason mesh_pairing_service_revoke(
    struct node_db *ndb, const char *pairing_id, int64_t now);

/* Authorize the private status operation against current local revocation and
 * chain state plus the exact established Noise peer. The delegation is live
 * session evidence, never a substitute for the local pairing record. */
enum mesh_pairing_reason mesh_pairing_service_authorize_status(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now);

#endif /* ZCL_SERVICES_MESH_PAIRING_SERVICE_H */
