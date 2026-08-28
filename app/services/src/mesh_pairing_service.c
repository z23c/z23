/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Chain-bound local authorization for paired machine identities. */

// one-result-type-ok:closed-security-verdict — callers must branch on the
// bounded mesh_pairing_reason taxonomy; no diagnostic text crosses the wire.

#include "services/mesh_pairing_service.h"

#include "models/block.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "validation/main_constants.h"

#include <limits.h>
#include <string.h>

const char *mesh_pairing_reason_token(enum mesh_pairing_reason reason)
{
    switch (reason) {
    case MESH_PAIRING_OK: return "ok";
    case MESH_PAIRING_BAD_ARGUMENT: return "bad_argument";
    case MESH_PAIRING_CAPABILITY_UNAVAILABLE: return "capability_unavailable";
    case MESH_PAIRING_FINGERPRINT_MISMATCH: return "fingerprint_mismatch";
    case MESH_PAIRING_NETWORK_MISMATCH: return "network_mismatch";
    case MESH_PAIRING_MASTER_INACTIVE: return "master_inactive";
    case MESH_PAIRING_BEACON_UNAVAILABLE: return "beacon_unavailable";
    case MESH_PAIRING_BEACON_PROVISIONAL: return "beacon_provisional";
    case MESH_PAIRING_DELEGATION_INVALID: return "delegation_invalid";
    case MESH_PAIRING_WINDOW_INVALID: return "window_invalid";
    case MESH_PAIRING_ALREADY_REVOKED: return "already_revoked";
    case MESH_PAIRING_IDENTITY_COLLISION: return "identity_collision";
    case MESH_PAIRING_PERSIST_FAILED: return "persist_failed";
    case MESH_PAIRING_NOT_FOUND: return "not_found";
    case MESH_PAIRING_EXPIRED: return "expired";
    case MESH_PAIRING_SESSION_MISMATCH: return "session_mismatch";
    case MESH_PAIRING_AUTHORITY_CHANGED: return "authority_changed";
    }
    return "bad_argument";
}

static enum mesh_pairing_reason mesh_pairing_delegation_check(
    struct node_db *ndb,
    const struct vcs_zcode_dht_delegation *delegation, int64_t now)
{
    if (!ndb || !ndb->open || !delegation || now <= 0)
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_block genesis;
    if (!db_block_find_by_height(ndb, 0, &genesis) ||
        memcmp(genesis.hash, delegation->network_genesis, 32) != 0)
        return MESH_PAIRING_NETWORK_MISMATCH;
    struct zid_identity identity;
    if (!db_zid_identity_find(ndb, delegation->doc.master_pubkey, &identity) ||
        strcmp(identity.status, ZID_IDENTITY_STATUS_ACTIVE) != 0)
        return MESH_PAIRING_MASTER_INACTIVE;
    if (identity.anchor_height < 0 ||
        identity.anchor_height > INT_MAX - 2 * ZCL_FINALITY_DEPTH ||
        delegation->beacon_height !=
            (uint32_t)(identity.anchor_height + ZCL_FINALITY_DEPTH))
        return MESH_PAIRING_BEACON_UNAVAILABLE;
    struct db_block beacon;
    if (!db_block_find_by_height(ndb, (int)delegation->beacon_height,
                                 &beacon) ||
        memcmp(beacon.hash, delegation->beacon_hash, 32) != 0)
        return MESH_PAIRING_BEACON_UNAVAILABLE;
    int tip = db_block_max_height(ndb);
    if (tip < 0 || tip < (int)delegation->beacon_height + ZCL_FINALITY_DEPTH)
        return MESH_PAIRING_BEACON_PROVISIONAL;
    enum vcs_zcode_dht_delegation_error result =
        vcs_zcode_dht_delegation_verify(
            delegation, genesis.hash, delegation->noise_static_pubkey,
            delegation->beacon_height, beacon.hash, (uint64_t)now);
    return result == VCS_ZCODE_DHT_DELEGATION_OK
        ? MESH_PAIRING_OK : MESH_PAIRING_DELEGATION_INVALID;
}

static bool mesh_pairing_same(const struct db_mesh_pairing *left,
                              const struct db_mesh_pairing *right)
{
    return left && right &&
           strcmp(left->pairing_id, right->pairing_id) == 0 &&
           memcmp(left->network_genesis, right->network_genesis, 32) == 0 &&
           memcmp(left->peer_master_pubkey,
                  right->peer_master_pubkey, 32) == 0 &&
           memcmp(left->peer_noise_pubkey,
                  right->peer_noise_pubkey, 32) == 0 &&
           left->capability_mask == right->capability_mask &&
           left->delegation_sequence == right->delegation_sequence &&
           left->paired_at == right->paired_at &&
           left->expires_at == right->expires_at;
}

enum mesh_pairing_reason mesh_pairing_service_accept(
    struct node_db *ndb,
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_noise_fingerprint[32],
    const uint8_t authenticated_session_noise_static[32],
    bool session_authenticated, uint64_t capability_mask, int64_t now,
    int64_t expires_at, struct db_mesh_pairing *out)
{
    if (!ndb || !ndb->open || !delegation ||
        !expected_noise_fingerprint || !authenticated_session_noise_static ||
        now <= 0 || !out)
        return MESH_PAIRING_BAD_ARGUMENT;
    if (!session_authenticated ||
        memcmp(authenticated_session_noise_static,
               delegation->noise_static_pubkey, 32) != 0)
        return MESH_PAIRING_SESSION_MISMATCH;
    if (capability_mask != MESH_PAIRING_CAP_STATUS_READ)
        return MESH_PAIRING_CAPABILITY_UNAVAILABLE;
    if (expires_at <= now ||
        expires_at - now > MESH_PAIRING_MAX_LIFETIME_SECONDS)
        return MESH_PAIRING_WINDOW_INVALID;
    uint8_t actual_fingerprint[32];
    if (!v2_identity_public_fingerprint(delegation->noise_static_pubkey,
                                        actual_fingerprint) ||
        memcmp(actual_fingerprint, expected_noise_fingerprint, 32) != 0)
        return MESH_PAIRING_FINGERPRINT_MISMATCH;
    enum mesh_pairing_reason verified =
        mesh_pairing_delegation_check(ndb, delegation, now);
    if (verified != MESH_PAIRING_OK)
        return verified;

    struct db_mesh_pairing next = {0};
    memcpy(next.network_genesis, delegation->network_genesis, 32);
    memcpy(next.peer_master_pubkey, delegation->doc.master_pubkey, 32);
    memcpy(next.peer_noise_pubkey, delegation->noise_static_pubkey, 32);
    next.capability_mask = capability_mask;
    next.delegation_sequence = delegation->doc.seq;
    next.paired_at = now;
    next.expires_at = expires_at;
    if (!mesh_pairing_id_derive(
            next.network_genesis, next.peer_master_pubkey,
            next.peer_noise_pubkey, next.pairing_id))
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_mesh_pairing existing;
    if (db_mesh_pairing_find(ndb, next.pairing_id, &existing)) {
        if (existing.revoked_at != 0)
            return MESH_PAIRING_ALREADY_REVOKED;
        if (!mesh_pairing_same(&existing, &next))
            return MESH_PAIRING_IDENTITY_COLLISION;
        *out = existing;
        return MESH_PAIRING_OK;
    }
    if (!db_mesh_pairing_insert(ndb, &next))
        return MESH_PAIRING_PERSIST_FAILED;
    *out = next;
    return MESH_PAIRING_OK;
}

enum mesh_pairing_reason mesh_pairing_service_revoke(
    struct node_db *ndb, const char *pairing_id, int64_t now)
{
    if (!ndb || !ndb->open || !pairing_id || now <= 0)
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id, &row))
        return MESH_PAIRING_NOT_FOUND;
    if (row.revoked_at != 0)
        return MESH_PAIRING_OK;
    return db_mesh_pairing_revoke(ndb, pairing_id, now)
        ? MESH_PAIRING_OK : MESH_PAIRING_PERSIST_FAILED;
}

enum mesh_pairing_reason mesh_pairing_service_authorize_status(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now)
{
    if (!ndb || !ndb->open || !pairing_id || !live_delegation ||
        !session_noise_static || now <= 0)
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_mesh_pairing before;
    if (!db_mesh_pairing_find(ndb, pairing_id, &before))
        return MESH_PAIRING_NOT_FOUND;
    if (!mesh_pairing_allows(&before, MESH_PAIRING_CAP_STATUS_READ, now))
        return before.revoked_at != 0
            ? MESH_PAIRING_ALREADY_REVOKED : MESH_PAIRING_EXPIRED;
    if (memcmp(before.peer_master_pubkey,
               live_delegation->doc.master_pubkey, 32) != 0 ||
        memcmp(before.peer_noise_pubkey,
               live_delegation->noise_static_pubkey, 32) != 0 ||
        memcmp(before.peer_noise_pubkey, session_noise_static, 32) != 0 ||
        memcmp(before.network_genesis,
               live_delegation->network_genesis, 32) != 0 ||
        live_delegation->doc.seq < before.delegation_sequence)
        return MESH_PAIRING_SESSION_MISMATCH;
    uint64_t zid_generation = zid_identity_status_generation();
    enum mesh_pairing_reason verified =
        mesh_pairing_delegation_check(ndb, live_delegation, now);
    if (verified != MESH_PAIRING_OK)
        return verified;
    struct db_mesh_pairing after;
    if (zid_generation != zid_identity_status_generation() ||
        !db_mesh_pairing_find(ndb, pairing_id, &after) ||
        before.revocation_generation != after.revocation_generation ||
        !mesh_pairing_allows(&after, MESH_PAIRING_CAP_STATUS_READ, now))
        return MESH_PAIRING_AUTHORITY_CHANGED;
    return MESH_PAIRING_OK;
}
