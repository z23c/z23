/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Session, delegation, pairing, grant, and claim convergence. */

#include "services/mesh_private_object_admission.h"

#include "base/hex.h"
#include "models/mesh_pairing.h"
#include "services/mesh_pairing_service.h"

#include <limits.h>
#include <string.h>

const char *mesh_private_object_admission_reason_string(
    enum mesh_private_object_admission_reason reason)
{
    switch (reason) {
    case MESH_PRIVATE_OBJECT_ADMISSION_NEW: return "new";
    case MESH_PRIVATE_OBJECT_ADMISSION_RESUME: return "resume";
    case MESH_PRIVATE_OBJECT_ADMISSION_BAD_ARGUMENT: return "bad_argument";
    case MESH_PRIVATE_OBJECT_ADMISSION_OFFER_INVALID: return "offer_invalid";
    case MESH_PRIVATE_OBJECT_ADMISSION_SESSION_MISMATCH:
        return "session_mismatch";
    case MESH_PRIVATE_OBJECT_ADMISSION_DELEGATION_INVALID:
        return "delegation_invalid";
    case MESH_PRIVATE_OBJECT_ADMISSION_PAIRING_INVALID:
        return "pairing_invalid";
    case MESH_PRIVATE_OBJECT_ADMISSION_GRANT_INVALID: return "grant_invalid";
    case MESH_PRIVATE_OBJECT_ADMISSION_TARGET_MISMATCH:
        return "target_mismatch";
    case MESH_PRIVATE_OBJECT_ADMISSION_LIMIT_MISMATCH:
        return "limit_mismatch";
    case MESH_PRIVATE_OBJECT_ADMISSION_TIME_MISMATCH: return "time_mismatch";
    case MESH_PRIVATE_OBJECT_ADMISSION_NONCE_MISMATCH:
        return "nonce_mismatch";
    case MESH_PRIVATE_OBJECT_ADMISSION_CLAIM_REFUSED: return "claim_refused";
    }
    return "bad_argument";
}

static struct zcl_result admission_refuse(
    struct mesh_private_object_admission *out,
    enum mesh_private_object_admission_reason reason)
{
    out->reason = reason;
    return ZCL_OK;
}

static bool admission_session_matches(
    const struct mesh_private_object_offer_v1 *offer,
    const struct v2_transport_snapshot *session)
{
    return session->established &&
           memcmp(offer->source_noise_static, session->remote_static, 32) == 0 &&
           memcmp(offer->transcript_hash, session->transcript_hash, 32) == 0 &&
           offer->connection_generation == session->connection_generation;
}

static bool admission_delegation_matches(
    const struct mesh_private_object_offer_v1 *offer,
    const struct vcs_zcode_dht_delegation *delegation)
{
    return memcmp(delegation->network_genesis,
                  offer->network_genesis, 32) == 0 &&
           memcmp(delegation->doc.master_pubkey,
                  offer->source_master_pubkey, 32) == 0 &&
           memcmp(delegation->online_pubkey,
                  offer->source_online_pubkey, 32) == 0 &&
           memcmp(delegation->noise_static_pubkey,
                  offer->source_noise_static, 32) == 0;
}

static bool admission_pairing_matches(
    const struct mesh_private_object_offer_v1 *offer,
    const struct db_mesh_pairing *pairing,
    const struct vcs_zcode_dht_delegation *delegation, uint64_t now)
{
    uint8_t pairing_id[32];
    return zcl_hex_decode_lower(pairing->pairing_id, pairing_id, 32) &&
           memcmp(pairing_id, offer->pairing_id, 32) == 0 &&
           memcmp(pairing->network_genesis, offer->network_genesis, 32) == 0 &&
           memcmp(pairing->peer_master_pubkey,
                  offer->source_master_pubkey, 32) == 0 &&
           memcmp(pairing->peer_noise_pubkey,
                  offer->source_noise_static, 32) == 0 &&
           delegation->doc.seq >= pairing->delegation_sequence &&
           pairing->revoked_at == 0 && now >= (uint64_t)pairing->paired_at &&
           now < (uint64_t)pairing->expires_at &&
           pairing->revocation_generation ==
               offer->pairing_revocation_generation;
}

static bool admission_grant_exact(
    const struct mesh_private_object_offer_v1 *offer,
    const struct db_mesh_capability_grant *grant)
{
    uint8_t grant_id[32];
    uint64_t storage_needed = offer->object_size_bytes +
                              offer->ciphertext_size_bytes;
    return zcl_hex_decode_lower(grant->grant_id, grant_id, 32) &&
           memcmp(grant_id, offer->grant_id, 32) == 0 &&
           memcmp(grant->plaintext_root, offer->plaintext_root, 32) == 0 &&
           memcmp(grant->ciphertext_root, offer->ciphertext_root, 32) == 0 &&
           grant->object_size_bytes == offer->object_size_bytes &&
           grant->ciphertext_size_bytes == offer->ciphertext_size_bytes &&
           grant->storage_limit_bytes >= storage_needed &&
           grant->transfer_limit_bytes >= offer->ciphertext_size_bytes &&
           grant->max_chunk_bytes == offer->chunk_size &&
           grant->chunk_count == offer->chunk_count &&
           grant->deny_mask == offer->deny_mask;
}

static bool admission_delegation_authority_failure(
    enum mesh_pairing_reason reason)
{
    return reason == MESH_PAIRING_NETWORK_MISMATCH ||
           reason == MESH_PAIRING_MASTER_INACTIVE ||
           reason == MESH_PAIRING_BEACON_UNAVAILABLE ||
           reason == MESH_PAIRING_BEACON_PROVISIONAL ||
           reason == MESH_PAIRING_DELEGATION_INVALID;
}

struct zcl_result mesh_private_object_admit_offer(
    struct node_db *ndb, const struct mesh_private_object_offer_v1 *offer,
    const struct v2_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *source_delegation,
    const uint8_t local_master_pubkey[32],
    const uint8_t local_noise_static[32], uint64_t now_unix,
    struct mesh_private_object_admission *out)
{
    if (!out)
        return ZCL_ERR(-1, "private-object admission requires output");
    memset(out, 0, sizeof(*out));
    out->reason = MESH_PRIVATE_OBJECT_ADMISSION_BAD_ARGUMENT;
    if (!ndb || !ndb->open || !offer || !session || !source_delegation ||
        !local_master_pubkey || !local_noise_static || now_unix == 0 ||
        now_unix > (uint64_t)INT64_MAX)
        return ZCL_ERR(-1, "private-object admission context unavailable");
    if (mesh_private_object_offer_v1_validate(offer) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_OFFER_INVALID);
    if (!admission_session_matches(offer, session))
        return admission_refuse(
            out, MESH_PRIVATE_OBJECT_ADMISSION_SESSION_MISMATCH);
    if (!admission_delegation_matches(offer, source_delegation))
        return admission_refuse(
            out, MESH_PRIVATE_OBJECT_ADMISSION_DELEGATION_INVALID);

    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    zcl_hex_encode(offer->pairing_id, 32, pairing_id);
    struct db_mesh_pairing pairing;
    if (!db_mesh_pairing_find(ndb, pairing_id, &pairing) ||
        !admission_pairing_matches(
            offer, &pairing, source_delegation, now_unix))
        return admission_refuse(
            out, MESH_PRIVATE_OBJECT_ADMISSION_PAIRING_INVALID);
    enum mesh_pairing_reason delegated =
        mesh_pairing_service_authorize_delegation(
            ndb, pairing_id, source_delegation,
            offer->source_noise_static, (int64_t)now_unix);
    if (delegated != MESH_PAIRING_OK)
        return admission_refuse(
            out, admission_delegation_authority_failure(delegated)
                     ? MESH_PRIVATE_OBJECT_ADMISSION_DELEGATION_INVALID
                     : MESH_PRIVATE_OBJECT_ADMISSION_PAIRING_INVALID);
    char grant_id[MESH_CAPABILITY_GRANT_ID_HEX + 1];
    zcl_hex_encode(offer->grant_id, 32, grant_id);
    struct db_mesh_capability_grant grant;
    if (!db_mesh_capability_grant_find(ndb, grant_id, &grant))
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_GRANT_INVALID);
    if (memcmp(grant.pairing_id, pairing_id, MESH_PAIRING_ID_HEX + 1) != 0 ||
        !admission_grant_exact(offer, &grant))
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_LIMIT_MISMATCH);
    if (memcmp(offer->target_master_pubkey, local_master_pubkey, 32) != 0 ||
        memcmp(offer->target_noise_static, local_noise_static, 32) != 0 ||
        memcmp(grant.target_master_pubkey, local_master_pubkey, 32) != 0 ||
        memcmp(grant.target_noise_static, local_noise_static, 32) != 0)
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_TARGET_MISMATCH);
    if (now_unix < offer->issued_unix || now_unix >= offer->expires_unix ||
        offer->issued_unix < (uint64_t)grant.not_before ||
        offer->expires_unix > (uint64_t)grant.expires_at ||
        offer->expires_unix - offer->issued_unix > grant.wall_limit_seconds)
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_TIME_MISMATCH);
    uint8_t expected_request[32];
    if (mesh_private_object_offer_request_id_v1_derive(
            offer, grant.nonce, expected_request) !=
            MESH_PRIVATE_OBJECT_PROTO_OK ||
        memcmp(expected_request, offer->request_id, 32) != 0)
        return admission_refuse(out, MESH_PRIVATE_OBJECT_ADMISSION_NONCE_MISMATCH);
    if (mesh_private_object_offer_v1_root(offer, out->offer_root) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return ZCL_ERR(-1, "private-object offer root failed after validation");
    if (mesh_private_object_offer_transfer_id_v1(
            offer, out->transfer_id) != MESH_PRIVATE_OBJECT_PROTO_OK)
        return ZCL_ERR(-1, "private-object transfer id failed after validation");
    out->pairing_revocation_generation = pairing.revocation_generation;
    out->grant_revocation_generation = grant.revocation_generation;
    enum mesh_capability_claim_result claimed = db_mesh_capability_grant_claim(
        ndb, grant_id, out->transfer_id, pairing.revocation_generation,
        grant.revocation_generation, (int64_t)now_unix);
    if (claimed == MESH_CAPABILITY_CLAIM_NEW)
        out->reason = MESH_PRIVATE_OBJECT_ADMISSION_NEW;
    else if (claimed == MESH_CAPABILITY_CLAIM_RESUME)
        out->reason = MESH_PRIVATE_OBJECT_ADMISSION_RESUME;
    else
        out->reason = MESH_PRIVATE_OBJECT_ADMISSION_CLAIM_REFUSED;
    return ZCL_OK;
}
