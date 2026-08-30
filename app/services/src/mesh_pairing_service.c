/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Chain-bound local authorization for paired machine identities. */

// one-result-type-ok:closed-security-verdict — callers must branch on the
// bounded mesh_pairing_reason taxonomy; no diagnostic text crosses the wire.

#include "services/mesh_pairing_service.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "models/block.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"

#include <limits.h>
#include <stdlib.h>
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
    case MESH_PAIRING_CONFIRMATION_INVALID: return "confirmation_invalid";
    case MESH_PAIRING_PLAN_EXPIRED: return "plan_expired";
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
    /* Status-read is the always-granted base capability; terminal-exec may
     * ride alongside it (the operator opted in at commit time), never alone
     * and never with a bit outside the known set. */
    if (capability_mask != MESH_PAIRING_CAP_STATUS_READ &&
        capability_mask !=
            (MESH_PAIRING_CAP_STATUS_READ | MESH_PAIRING_CAP_TERMINAL_EXEC))
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

static bool mesh_pairing_canonical_id(const char *pairing_id)
{
    uint8_t decoded[32];
    return pairing_id && zcl_hex_decode_lower(pairing_id, decoded,
                                               sizeof(decoded));
}

static void mesh_pairing_fingerprint(const char *domain,
                                     const uint8_t key[32], char out[65])
{
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&hash, key, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static void mesh_pairing_public_project(
    const struct db_mesh_pairing *row, int64_t now,
    struct mesh_pairing_public_view *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->pairing_id, row->pairing_id, sizeof(out->pairing_id));
    mesh_pairing_fingerprint("zcl.mesh.master.fingerprint.v1",
                             row->peer_master_pubkey,
                             out->peer_master_fingerprint);
    uint8_t noise_fingerprint[32];
    if (v2_identity_public_fingerprint(row->peer_noise_pubkey,
                                       noise_fingerprint))
        zcl_hex_encode(noise_fingerprint, sizeof(noise_fingerprint),
                       out->peer_noise_fingerprint);
    out->capability_mask = row->capability_mask;
    out->delegation_sequence = row->delegation_sequence;
    out->paired_at = row->paired_at;
    out->expires_at = row->expires_at;
    out->revoked_at = row->revoked_at;
    out->revocation_generation = row->revocation_generation;
    const char *state = row->revoked_at != 0 ? "revoked" :
                        now >= row->expires_at ? "expired" : "active";
    memcpy(out->state, state, strlen(state) + 1);
}

bool mesh_pairing_service_list(
    struct node_db *ndb, int64_t now, struct mesh_pairing_public_view *out,
    size_t max, size_t *count, struct db_mesh_pairing_counts *counts)
{
    if (count)
        *count = 0;
    if (!ndb || !ndb->open || now <= 0 || !out || max == 0 || !count ||
        !counts)
        return false;
    if (max > MESH_PAIRING_LIST_MAX)
        max = MESH_PAIRING_LIST_MAX;
    if (!db_mesh_pairing_count_states(ndb, now, counts))
        LOG_FAIL("mesh_pairing", "list: count states failed");
    struct db_mesh_pairing *rows = zcl_calloc(
        max, sizeof(*rows), "mesh_pairing.redacted_list");
    if (!rows) {
        LOG_ERROR("mesh_pairing", "list: allocate %zu rows failed", max);
        return false;
    }
    int found = db_mesh_pairing_list(ndb, rows, max);
    for (int i = 0; i < found; i++)
        mesh_pairing_public_project(&rows[i], now, &out[i]);
    free(rows);
    *count = found > 0 ? (size_t)found : 0;
    return true;
}

static void mesh_pairing_revoke_digest(
    const char *pairing_id, uint64_t generation, int64_t issued_at,
    int64_t expires_at, uint8_t out[32])
{
    static const char domain[] = "zcl.mesh.pairing.revoke.plan.v1";
    uint8_t binding[24];
    zcl_write_u64_le(binding, generation);
    zcl_write_u64_le(binding + 8, (uint64_t)issued_at);
    zcl_write_u64_le(binding + 16, (uint64_t)expires_at);
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1);
    sha3_256_write(&hash, (const uint8_t *)pairing_id, MESH_PAIRING_ID_HEX);
    sha3_256_write(&hash, binding, sizeof(binding));
    sha3_256_finalize(&hash, out);
}

static void mesh_pairing_revoke_token(
    const char *pairing_id, uint64_t generation, int64_t issued_at,
    int64_t expires_at, char out[MESH_PAIRING_REVOKE_TOKEN_HEX + 1])
{
    uint8_t raw[MESH_PAIRING_REVOKE_TOKEN_BYTES];
    zcl_write_u64_le(raw, generation);
    zcl_write_u64_le(raw + 8, (uint64_t)issued_at);
    zcl_write_u64_le(raw + 16, (uint64_t)expires_at);
    mesh_pairing_revoke_digest(pairing_id, generation, issued_at, expires_at,
                               raw + 24);
    zcl_hex_encode(raw, sizeof(raw), out);
}

enum mesh_pairing_reason mesh_pairing_service_revoke_plan(
    struct node_db *ndb, const char *pairing_id, int64_t now,
    struct mesh_pairing_revoke_plan *out)
{
    if (!ndb || !ndb->open || !mesh_pairing_canonical_id(pairing_id) ||
        now <= 0 || now > INT64_MAX - MESH_PAIRING_REVOKE_PLAN_SECONDS || !out)
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id, &row))
        return MESH_PAIRING_NOT_FOUND;
    if (row.revoked_at != 0)
        return MESH_PAIRING_ALREADY_REVOKED;
    memset(out, 0, sizeof(*out));
    memcpy(out->pairing_id, row.pairing_id, sizeof(out->pairing_id));
    out->revocation_generation = row.revocation_generation;
    out->issued_at = now;
    out->expires_at = now + MESH_PAIRING_REVOKE_PLAN_SECONDS;
    mesh_pairing_revoke_token(pairing_id, out->revocation_generation,
                              out->issued_at, out->expires_at,
                              out->confirmation_token);
    return MESH_PAIRING_OK;
}

static bool mesh_pairing_token_equal(const uint8_t left[32],
                                     const uint8_t right[32])
{
    uint8_t different = 0;
    for (size_t i = 0; i < 32; i++)
        different |= (uint8_t)(left[i] ^ right[i]);
    return different == 0;
}

enum mesh_pairing_reason mesh_pairing_service_revoke_commit(
    struct node_db *ndb, const char *pairing_id,
    const char *confirmation_token, int64_t now,
    struct mesh_pairing_revoke_result *out)
{
    uint8_t raw[MESH_PAIRING_REVOKE_TOKEN_BYTES];
    if (!ndb || !ndb->open || !mesh_pairing_canonical_id(pairing_id) ||
        !zcl_hex_decode_lower(confirmation_token, raw, sizeof(raw)) ||
        now <= 0 || !out)
        return MESH_PAIRING_BAD_ARGUMENT;
    uint64_t generation = zcl_read_u64_le(raw);
    uint64_t issued_u = zcl_read_u64_le(raw + 8);
    uint64_t expires_u = zcl_read_u64_le(raw + 16);
    if (issued_u == 0 || issued_u > INT64_MAX || expires_u > INT64_MAX ||
        expires_u <= issued_u ||
        expires_u - issued_u > MESH_PAIRING_REVOKE_PLAN_SECONDS)
        return MESH_PAIRING_CONFIRMATION_INVALID;
    int64_t issued_at = (int64_t)issued_u;
    int64_t expires_at = (int64_t)expires_u;
    uint8_t expected[32];
    mesh_pairing_revoke_digest(pairing_id, generation, issued_at, expires_at,
                               expected);
    if (!mesh_pairing_token_equal(raw + 24, expected))
        return MESH_PAIRING_CONFIRMATION_INVALID;

    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id, &row))
        return MESH_PAIRING_NOT_FOUND;
    memset(out, 0, sizeof(*out));
    if (row.revoked_at != 0) {
        if (generation == UINT64_MAX ||
            row.revocation_generation != generation + 1 ||
            row.revoked_at < issued_at || row.revoked_at >= expires_at)
            return MESH_PAIRING_AUTHORITY_CHANGED;
        out->pairing = row;
        out->replayed = true;
        return MESH_PAIRING_OK;
    }
    if (now < issued_at || now >= expires_at)
        return MESH_PAIRING_PLAN_EXPIRED;
    if (row.revocation_generation != generation)
        return MESH_PAIRING_AUTHORITY_CHANGED;
    if (!db_mesh_pairing_revoke(ndb, pairing_id, now) ||
        !db_mesh_pairing_find(ndb, pairing_id, &out->pairing))
        return MESH_PAIRING_PERSIST_FAILED;
    out->replayed = false;
    return MESH_PAIRING_OK;
}

static enum mesh_pairing_reason mesh_pairing_authorize(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], uint64_t required_capability,
    int64_t now)
{
    if (!ndb || !ndb->open || !pairing_id || !live_delegation ||
        !session_noise_static || now <= 0)
        return MESH_PAIRING_BAD_ARGUMENT;
    struct db_mesh_pairing before;
    if (!db_mesh_pairing_find(ndb, pairing_id, &before))
        return MESH_PAIRING_NOT_FOUND;
    if (before.revoked_at != 0)
        return MESH_PAIRING_ALREADY_REVOKED;
    if (now >= before.expires_at)
        return MESH_PAIRING_EXPIRED;
    if (required_capability != 0 &&
        (before.capability_mask & required_capability) != required_capability)
        return MESH_PAIRING_CAPABILITY_UNAVAILABLE;
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
        after.revoked_at != 0 || now >= after.expires_at ||
        (required_capability != 0 &&
         (after.capability_mask & required_capability) != required_capability))
        return MESH_PAIRING_AUTHORITY_CHANGED;
    return MESH_PAIRING_OK;
}

enum mesh_pairing_reason mesh_pairing_service_authorize_status(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now)
{
    return mesh_pairing_authorize(
        ndb, pairing_id, live_delegation, session_noise_static,
        MESH_PAIRING_CAP_STATUS_READ, now);
}

enum mesh_pairing_reason mesh_pairing_service_authorize_terminal(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now)
{
    return mesh_pairing_authorize(
        ndb, pairing_id, live_delegation, session_noise_static,
        MESH_PAIRING_CAP_TERMINAL_EXEC, now);
}

enum mesh_pairing_reason mesh_pairing_service_authorize_delegation(
    struct node_db *ndb, const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now)
{
    return mesh_pairing_authorize(
        ndb, pairing_id, live_delegation, session_noise_static, 0, now);
}
