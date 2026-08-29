/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: One exact authority decision before private-object transfer work. */

#ifndef ZCL_SERVICES_MESH_PRIVATE_OBJECT_ADMISSION_H
#define ZCL_SERVICES_MESH_PRIVATE_OBJECT_ADMISSION_H

#include "base/result.h"
#include "models/mesh_capability_grant.h"
#include "net/v2_transport.h"
#include "session/mesh_private_object_proto.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdint.h>

enum mesh_private_object_admission_reason {
    MESH_PRIVATE_OBJECT_ADMISSION_NEW = 0,
    MESH_PRIVATE_OBJECT_ADMISSION_RESUME,
    MESH_PRIVATE_OBJECT_ADMISSION_BAD_ARGUMENT,
    MESH_PRIVATE_OBJECT_ADMISSION_OFFER_INVALID,
    MESH_PRIVATE_OBJECT_ADMISSION_SESSION_MISMATCH,
    MESH_PRIVATE_OBJECT_ADMISSION_DELEGATION_INVALID,
    MESH_PRIVATE_OBJECT_ADMISSION_PAIRING_INVALID,
    MESH_PRIVATE_OBJECT_ADMISSION_GRANT_INVALID,
    MESH_PRIVATE_OBJECT_ADMISSION_TARGET_MISMATCH,
    MESH_PRIVATE_OBJECT_ADMISSION_LIMIT_MISMATCH,
    MESH_PRIVATE_OBJECT_ADMISSION_TIME_MISMATCH,
    MESH_PRIVATE_OBJECT_ADMISSION_NONCE_MISMATCH,
    MESH_PRIVATE_OBJECT_ADMISSION_CLAIM_REFUSED,
};

struct mesh_private_object_admission {
    enum mesh_private_object_admission_reason reason;
    uint8_t offer_root[32];
    uint8_t transfer_id[32];
    uint64_t pairing_revocation_generation;
    uint64_t grant_revocation_generation;
};

const char *mesh_private_object_admission_reason_string(
    enum mesh_private_object_admission_reason reason);

/* Validate one already decoded signed offer against the authenticated Noise
 * session, active source delegation, target-local identities, pairing, and
 * exact durable grant. NEW/RESUME atomically claims the grant for the derived
 * transfer id. Expected policy refusals return ZCL_OK with a non-success
 * reason; infrastructure failure returns a non-ok zcl_result. */
struct zcl_result mesh_private_object_admit_offer(
    struct node_db *ndb, const struct mesh_private_object_offer_v1 *offer,
    const struct v2_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *source_delegation,
    const uint8_t local_master_pubkey[32],
    const uint8_t local_noise_static[32], uint64_t now_unix,
    struct mesh_private_object_admission *out);

#endif /* ZCL_SERVICES_MESH_PRIVATE_OBJECT_ADMISSION_H */
