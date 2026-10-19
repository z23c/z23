/* purpose: Define durable owner-approved pairing grants, credential bindings and held authority guards. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_MODELS_DEVICE_PAIRING_H
#define ZCL_MODELS_DEVICE_PAIRING_H
#include "models/activerecord.h"
#include "platform/private_file_state.h"
#include <stdbool.h>
#include <stdint.h>

#define DEVICE_PAIRING_CAP_STATUS_READ UINT64_C(1)
#define DEVICE_PAIRING_CAP_GUEST_STREAM UINT64_C(2)
#define DEVICE_PAIRING_CAP_GUEST_BIND UINT64_C(4)
#define DEVICE_PAIRING_CAP_HOST_FORWARD UINT64_C(8)
#define DEVICE_PAIRING_CAP_KNOWN (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM | DEVICE_PAIRING_CAP_GUEST_BIND | DEVICE_PAIRING_CAP_HOST_FORWARD)
struct device_pairing_psk_binding {
    uint8_t credential_id[32];
    uint64_t key_epoch;
    uint8_t endpoint_a[32], endpoint_b[32];
};
struct device_pairing_host_binding {
    uint32_t backend_profile;
    uint8_t local_pq_key_root[32], peer_pq_key_root[32];
    struct device_pairing_psk_binding psk;
};
struct device_pairing_host_scope {
    uint16_t inbound_port, outbound_port;
    struct device_pairing_host_binding binding;
};
enum device_pairing_host_backend {
    /* Candidate contract only: MLKEM768X25519 KEX plus composite
     * MLDSA44Ed25519 authentication. This is not backend qualification. */
    DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519 = 1,
    DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK = 2
};
/* PQ key roots identify canonical SSH public-key wire blobs, not authorized_keys
 * text: SHA3-256("Z23HOSTSSHKEY1" || uint32_le(backend_profile) ||
 * uint32_be(blob_length) || blob). The blob includes its SSH algorithm string
 * and exact composite authentication public key. An adapter must validate the
 * profile's canonical encoding and prove possession independently; ephemeral
 * KEX keys are not these identity roots. No algorithm is implemented here. */
enum device_pairing_host_direction {
    DEVICE_PAIRING_HOST_INBOUND,
    DEVICE_PAIRING_HOST_OUTBOUND
};
struct device_pairing_guest_scope {
    uint8_t guest_id[32], requester_ssh_key[32], owner_grant_root[32];
    uint64_t enrollment_generation, port_mask;
};
struct db_device_pairing {
    uint8_t profile[32], local_key[32], peer_key[32];
    uint64_t paired_at, expires_at, revoked_at, generation, capabilities;
    struct device_pairing_guest_scope guest_scope;
    struct device_pairing_host_scope host_scope;
};
struct device_pairing_store {
    char directory[1024];
    uint8_t profile[32], local_key[32];
};
/* Opaque shared-lock lease a revalidating guard borrows from its cache. */
struct device_pairing_lock_lease;
struct device_pairing_guard {
    struct platform_private_file lock;
    struct db_device_pairing row;
    uint8_t root[32];
    bool held;
    struct device_pairing_lock_lease *lease;
};
enum device_pairing_publication {
    DEVICE_PAIRING_NOT_PUBLISHED,
    DEVICE_PAIRING_DURABLE,
    DEVICE_PAIRING_DURABILITY_UNKNOWN
};
/* This offline authority grants explicit status, guest or scoped host authority, never
 * anchored mesh access. Legacy v1 grants and zero-initialized inserts are
 * status-only. Nonbinding v2 bytes are unchanged; scoped guest binds use v3
 * and directional host forwards use v4 (backend1) or v5 (backend2).
 * Old grants never imply host authority.
 * Bind requires stream and complete scope. Runtime owner/session/receiver-pin,
 * instance and epoch checks remain independent; this does not bind a runtime.
 * Open validates an existing private profile; it does not create an identity.
 * A held guard serializes revocation with response encryption/release.
 * Windows insert, upgrade and revocation refuse before filesystem mutation
 * until directory publication durability is qualified. Reads are unaffected. */
bool device_pairing_store_open(struct device_pairing_store *store,
                               const char *directory,
                               const uint8_t profile[32],
                               const uint8_t local_key[32]);
bool db_device_pairing_validate(const struct db_device_pairing *row,
                                struct ar_errors *errors);
bool db_device_pairing_insert(struct device_pairing_store *store,
                              struct db_device_pairing *row,
                              const uint8_t confirmed_fingerprint[32],
                              enum device_pairing_publication *publication);
/* Complete owner-approved proposal: SHA3-256("Z23HOSTPROPOSAL1" || exact
 * checksummed v4/v5 wire), domain-separated from persisted roots. Computing a
 * reference is not owner approval; callers supply independently confirmed roots.
 * Refuses invalid, revoked or non-host rows; output unchanged on failure. */
bool device_pairing_host_proposal_root(const struct db_device_pairing *row,
    uint8_t root[32]);
bool db_device_pairing_insert_host(struct device_pairing_store *store,
    struct db_device_pairing *row, const uint8_t confirmed_proposal_root[32],
    enum device_pairing_publication *publication);
bool db_device_pairing_upgrade_host(struct device_pairing_store *store,
    const struct db_device_pairing *replacement,
    const uint8_t confirmed_proposal_root[32], const uint8_t expected_root[32],
    uint64_t now, enum device_pairing_publication *publication);
/* Generic insert/upgrade refuse HOST rows: a peer-key fingerprint does not
 * approve backend, PQ keys, ports or lifetime. Rotation uses upgrade_host with
 * both the complete new proposal approval and exact inspected previous root. */
bool db_device_pairing_find(struct device_pairing_store *store,
                            const uint8_t peer_key[32],
                            struct db_device_pairing *row);
/* Shared-lock inspection hashes exact full persisted bytes, including checksum.
 * Both outputs remain unchanged on failure; pending publication fails closed. */
bool db_device_pairing_inspect(struct device_pairing_store *store,
    const uint8_t peer_key[32], struct db_device_pairing *row, uint8_t root[32]);
/* Exclusive-lock owner-confirmed replacement requires an exact inspected root,
 * explicit validated authority and immutable identity/paired_at. Unknown
 * publication requires fresh inspection/reconciliation; never automatic retry
 * or clearing a pending marker. Revoked grants cannot be upgraded. */
bool db_device_pairing_upgrade(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t confirmed_fingerprint[32],
    const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_publication *publication);
bool db_device_pairing_revoke(struct device_pairing_store *store,
                              const uint8_t peer_key[32], uint64_t now,
                              enum device_pairing_publication *publication);
/* Owner approval names the exact inspected full-wire root. Compare and revoke
 * under one exclusive authority lock; stale roots must not change the grant. */
bool db_device_pairing_revoke_expected(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, const uint8_t expected_root[32],
    enum device_pairing_publication *publication);
/* Every acquire requires a fresh, unheld guard. Release a successful guard
 * before reuse; acquisition initializes its storage and cannot preserve a
 * previously held lock. The caller releases guards on every exit path. */
bool device_pairing_guard_acquire(struct device_pairing_store *store,
                                  const uint8_t peer_key[32], uint64_t now,
                                  struct device_pairing_guard *guard);
/* required is a nonzero subset of status/guest-stream capabilities. The held authority
 * lock covers the exact current record, expiry, revocation and full subset.
 * root hashes the full persisted bytes, including checksum, under that lock. */
bool device_pairing_guard_acquire_capability(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, uint64_t required,
    struct device_pairing_guard *guard);
/* Exact directional scope and bit(slot * 2 + role), with slot and role below 2.
 * Use a fresh unheld guard. Success holds the authority lock; refusal releases it. */
bool device_pairing_guard_acquire_guest_bind(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now,
    const struct device_pairing_guest_scope *scope, unsigned slot, unsigned role,
    struct device_pairing_guard *guard);
void device_pairing_guard_release(struct device_pairing_guard *guard);
/* Local inbound accepts a peer into this exact loopback target; outbound
 * initiates toward the peer target. Zero denies a direction. Host authority
 * This legacy API admits backend1 PQ-bound v4 only and explicitly refuses
 * backend2. Host cannot mix with guest authority and grants no transport by itself.
 * authenticated_binding must come from independent handshake possession and
 * canonical key verification, never merely from reading this grant.
 * Fresh unheld guard required; success retains the current authority lock. */
bool device_pairing_guard_acquire_host_forward(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now,
    const struct device_pairing_host_binding *authenticated_binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard);
/* Backend2 uses a distinct v5 public row and an immutable owner-private
 * credential file, under this same authority.lock and peer.grant.pending.
 * A/B are canonical lexicographically ordered local/peer owner labels; wire
 * client/server roles are independently bound by the future handshake.
 * Existing host_forward guard and insert/upgrade_host refuse backend2.
 * Inputs/outputs must be independent valid storage. Secret import is explicit
 * owner authority: caller establishes authenticated confidential provisioning
 * and qualified random256-bit provenance; bytes cannot establish entropy.
 * Never serialize secrets/snapshots in argv/env/logs/CAS/public receipts.
 * Trusted private profile/ancestors required; no general path-confinement claim.
 * IDs are never reused/adopted, even for an identical orphan. Rotation requires
 * a new ID, increasing epoch, exact old root and complete new proposal approval;
 * paired_at remains immutable, revoked rows cannot rotate. No backend1 conversion.
 * Old secrets remain private until explicit retirement (not supplied here).
 * After mutation_attempted, authority.lock/intent/staging may exist even when
 * publication says NOT_PUBLISHED. After intent retirement, final directory
 * barrier failure is UNKNOWN: bytes may be readable, never auto-retry. */
struct device_pairing_psk_publication {
    enum device_pairing_publication secret, grant;
    bool mutation_attempted, intent_retired;
};
struct device_pairing_psk_snapshot {
    struct db_device_pairing row;
    uint8_t root[32], secret[32];
};
bool db_device_pairing_insert_host_psk(struct device_pairing_store *store,
    struct db_device_pairing *row, const uint8_t secret[32],
    const uint8_t confirmed_proposal_root[32], struct device_pairing_psk_publication *report);
bool db_device_pairing_rotate_host_psk(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t secret[32],
    const uint8_t confirmed_proposal_root[32], const uint8_t expected_root[32],
    uint64_t now, struct device_pairing_psk_publication *report);
/* Fresh unheld guard. Snapshot unchanged on failure, owning private secret on
 * success. Current grant/root and secret metadata are read/copied under the
 * same retained guard; release before every network wait, destroy snapshot on
 * every exit. Snapshot alone is not peer secret possession/authentication. */
bool device_pairing_psk_snapshot_acquire(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard, struct device_pairing_psk_snapshot *snapshot);
bool device_pairing_guard_acquire_host_psk(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard);
void device_pairing_psk_snapshot_destroy(struct device_pairing_psk_snapshot *snapshot);
/* Per-session revalidation memo for device_pairing_guard_acquire_host_psk.
 * A full acquisition retains the grant file it read (pinning its inode), keeps
 * an open descriptor of authority.lock (pinning that inode, never locked between
 * acquisitions) and records directory, lock and grant identity. A later
 * acquisition with identical arguments takes the shared lock on that descriptor,
 * then accepts the remembered row only if the directory identity and the lock
 * path inode are unchanged, the grant path stat is unchanged, no
 * <grant>.pending intent exists and the last full read is under
 * DEVICE_PAIRING_GUARD_CACHE_NS old. The guard holds the shared lock until
 * device_pairing_guard_release; while one is outstanding the memo is not lent
 * again (a second acquisition takes the full path); destroying the memo while
 * a guard is outstanding is safe, the lease outlives it. Every grant mutation
 * renames a freshly created inode over the path, so a committed revoke,
 * rotation or upgrade always misses and the full acquisition decides.
 * Zero-initialized storage is empty. One owner; never copy a live memo. */
enum { DEVICE_PAIRING_GUARD_CACHE_NS = 250000000 };
struct device_pairing_guard_cache {
    struct platform_private_file grant;
    struct platform_private_path_state directory, grant_state;
    struct device_pairing_lock_lease *lease;
    struct db_device_pairing row;
    struct device_pairing_psk_binding binding;
    const struct device_pairing_store *store;
    int64_t validated_ns;
    uint8_t root[32], peer[32], expected_root[32];
    enum device_pairing_host_direction direction;
    uint16_t port;
    bool valid;
};
/* Same contract and refusals as device_pairing_guard_acquire_host_psk; a NULL
 * cache always takes the full path. Any miss or refusal empties the cache. */
bool device_pairing_guard_acquire_host_psk_cached(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard_cache *cache, struct device_pairing_guard *guard);
/* Closes the retained grant and wipes the memo; safe on empty storage. */
void device_pairing_guard_cache_destroy(struct device_pairing_guard_cache *cache);
/* Process-wide counts of full grant acquisitions and cheap revalidations. */
void device_pairing_guard_counts(uint64_t *full, uint64_t *cached);
#ifdef ZCL_TESTING
/* One-shot interruption of the actual durable publication sequence. */
void device_pairing_test_interrupt(unsigned stage);
#endif
#endif
