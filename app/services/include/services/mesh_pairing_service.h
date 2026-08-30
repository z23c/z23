/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify, accept, revoke, and authorize machine pairings. */

#ifndef ZCL_SERVICES_MESH_PAIRING_SERVICE_H
#define ZCL_SERVICES_MESH_PAIRING_SERVICE_H

#include "models/mesh_pairing.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_PAIRING_MAX_LIFETIME_SECONDS INT64_C(2592000)
#define MESH_PAIRING_REVOKE_PLAN_SECONDS INT64_C(60)
#define MESH_PAIRING_REVOKE_TOKEN_BYTES 56u
#define MESH_PAIRING_REVOKE_TOKEN_HEX \
    (MESH_PAIRING_REVOKE_TOKEN_BYTES * 2u)
#define MESH_PAIRING_PUBLIC_FINGERPRINT_HEX 64u
#define MESH_PAIRING_LIST_MAX 64u

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
    MESH_PAIRING_CONFIRMATION_INVALID,
    MESH_PAIRING_PLAN_EXPIRED,
};

struct mesh_pairing_public_view {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    char peer_master_fingerprint[MESH_PAIRING_PUBLIC_FINGERPRINT_HEX + 1];
    char peer_noise_fingerprint[MESH_PAIRING_PUBLIC_FINGERPRINT_HEX + 1];
    uint64_t capability_mask;
    uint64_t delegation_sequence;
    int64_t paired_at;
    int64_t expires_at;
    int64_t revoked_at;
    uint64_t revocation_generation;
    char state[8];
};

struct mesh_pairing_revoke_plan {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    uint64_t revocation_generation;
    int64_t issued_at;
    int64_t expires_at;
    char confirmation_token[MESH_PAIRING_REVOKE_TOKEN_HEX + 1];
};

struct mesh_pairing_revoke_result {
    struct db_mesh_pairing pairing;
    bool replayed;
};

const char *mesh_pairing_reason_token(enum mesh_pairing_reason reason);

/* `network_genesis` is THIS node's own network identity — the compiled
 * consensus genesis the caller resolves (boot_zcode_dht_network_genesis), not
 * a node.db row: a locally-mining node never persists a genesis row, because
 * ConnectBlock special-cases the genesis hash and returns before any block
 * write. Accept one peer only after its public Noise fingerprint was compared
 * out of band. The signed delegation is rechecked against that genesis, the
 * active ZID projection, the finality-delayed beacon row, and current time.
 * The capability set is status-read by default, with confined terminal-exec
 * as the only opt-in addition at accept time. */
enum mesh_pairing_reason mesh_pairing_service_accept(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_noise_fingerprint[32],
    const uint8_t authenticated_session_noise_static[32],
    bool session_authenticated, uint64_t capability_mask, int64_t now,
    int64_t expires_at, struct db_mesh_pairing *out);

enum mesh_pairing_reason mesh_pairing_service_revoke(
    struct node_db *ndb, const char *pairing_id, int64_t now);

/* Redacted owner view. Raw ZID and Noise public keys never leave the service;
 * the view carries only domain-separated fingerprints and local policy. */
bool mesh_pairing_service_list(
    struct node_db *ndb, int64_t now, struct mesh_pairing_public_view *out,
    size_t max, size_t *count, struct db_mesh_pairing_counts *counts);

/* Revocation is a short-lived compare-and-set transaction. The confirmation
 * token binds the exact pairing, current revocation generation, issue time,
 * and exclusive expiry. It is confirmation evidence, not a capability: RPC
 * owner authentication remains the authority. */
enum mesh_pairing_reason mesh_pairing_service_revoke_plan(
    struct node_db *ndb, const char *pairing_id, int64_t now,
    struct mesh_pairing_revoke_plan *out);
enum mesh_pairing_reason mesh_pairing_service_revoke_commit(
    struct node_db *ndb, const char *pairing_id,
    const char *confirmation_token, int64_t now,
    struct mesh_pairing_revoke_result *out);

/* Authorize the private status operation against current local revocation and
 * chain state plus the exact established Noise peer. `network_genesis` is the
 * caller-resolved local consensus genesis (see mesh_pairing_service_accept).
 * The delegation is live session evidence, never a substitute for the local
 * pairing record. */
enum mesh_pairing_reason mesh_pairing_service_authorize_status(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now);

/* Authorize the confined terminal operation against current local revocation
 * and chain state plus the exact established Noise peer. Requires the pairing
 * to carry MESH_PAIRING_CAP_TERMINAL_EXEC, granted only at commit time. The
 * delegation is live session evidence, never a substitute for the local
 * pairing record. */
enum mesh_pairing_reason mesh_pairing_service_authorize_terminal(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now);

/* Prove that an active local pairing, exact Noise peer, and current delegated
 * identity converge on this node's active chain. This grants no operation;
 * the caller must separately require one exact local capability. */
enum mesh_pairing_reason mesh_pairing_service_authorize_delegation(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const char *pairing_id,
    const struct vcs_zcode_dht_delegation *live_delegation,
    const uint8_t session_noise_static[32], int64_t now);

#endif /* ZCL_SERVICES_MESH_PAIRING_SERVICE_H */
