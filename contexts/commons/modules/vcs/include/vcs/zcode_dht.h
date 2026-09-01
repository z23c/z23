/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded Kademlia routing and authenticated contact persistence. */

#ifndef ZCL_VCS_ZCODE_DHT_H
#define ZCL_VCS_ZCODE_DHT_H

#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_K 16u
#define VCS_ZCODE_DHT_ALPHA 3u
#define VCS_ZCODE_DHT_MAX_CONTACTS 1024u
#define VCS_ZCODE_DHT_MAX_PENDING 256u
#define VCS_ZCODE_DHT_PROBE_TIMEOUT_S 10u
#define VCS_ZCODE_DHT_PROBE_WAIT_TIMEOUT_S 30u
#define VCS_ZCODE_DHT_LOOKUP_CEILING_S 30u
#define VCS_ZCODE_DHT_ID_BYTES 32u
#define VCS_ZCODE_DHT_BUCKET_COUNT 256u
#define VCS_ZCODE_DHT_NODE_ID_DOMAIN "zcl.zcode.dht.nodeid.v1"

#define VCS_ZCODE_DHT_CONTACTS_WIRE_VERSION 2u
#define VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES 78u
#define VCS_ZCODE_DHT_CONTACT_ENTRY_WIRE_BYTES \
    (32u + VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES + 8u + 4u)
#define VCS_ZCODE_DHT_CONTACTS_MAX_WIRE_BYTES \
    (VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES + VCS_ZCODE_DHT_MAX_CONTACTS * \
     VCS_ZCODE_DHT_CONTACT_ENTRY_WIRE_BYTES)

enum vcs_zcode_dht_error {
    VCS_ZCODE_DHT_OK = 0,
    VCS_ZCODE_DHT_ERR_NULL,
    VCS_ZCODE_DHT_ERR_VERSION,
    VCS_ZCODE_DHT_ERR_LIMIT,
    VCS_ZCODE_DHT_ERR_ID_ZERO,
    VCS_ZCODE_DHT_ERR_KEY_ZERO,
    VCS_ZCODE_DHT_ERR_LAST_SEEN,
    VCS_ZCODE_DHT_ERR_WIRE_SIZE,
    VCS_ZCODE_DHT_ERR_WIRE_MAGIC,
    VCS_ZCODE_DHT_ERR_WIRE_ORDER,
    VCS_ZCODE_DHT_ERR_WIRE_KIND,
    VCS_ZCODE_DHT_ERR_QUERY_ID,
    VCS_ZCODE_DHT_ERR_NETWORK,
    VCS_ZCODE_DHT_ERR_SELF,
    VCS_ZCODE_DHT_ERR_DELEGATION,
    VCS_ZCODE_DHT_ERR_SESSION,
    VCS_ZCODE_DHT_ERR_SIGNATURE,
    VCS_ZCODE_DHT_ERR_IDENTITY,
    VCS_ZCODE_DHT_ERR_EXPIRED,
};

const char *vcs_zcode_dht_error_string(enum vcs_zcode_dht_error error);

enum vcs_zcode_dht_add_result {
    VCS_ZCODE_DHT_ADD_ADDED = 0,
    VCS_ZCODE_DHT_ADD_REFRESHED,
    VCS_ZCODE_DHT_ADD_PENDING_PROBE,
    VCS_ZCODE_DHT_ADD_REJECTED_SELF,
    VCS_ZCODE_DHT_ADD_REJECTED_ZERO_ID,
    VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY,
    VCS_ZCODE_DHT_ADD_REJECTED_STALE,
    VCS_ZCODE_DHT_ADD_REJECTED_BINDING,
    VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP,
    VCS_ZCODE_DHT_ADD_REJECTED_PENDING,
    VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP,
};

const char *vcs_zcode_dht_add_result_string(
    enum vcs_zcode_dht_add_result result);

/* Only directly authenticated Noise sessions may construct contacts. The
 * canonical delegation bytes are retained so persistence can reverify them;
 * last_success and failures are local observations and never come from NODES. */
struct vcs_zcode_dht_contact {
    uint8_t node_id[32];
    uint8_t master_pubkey[32];
    uint8_t online_pubkey[32];
    uint8_t noise_static_pubkey[32];
    uint8_t beacon_hash[32];
    uint32_t beacon_height;
    uint64_t delegation_sequence;
    uint64_t delegation_not_before;
    uint64_t delegation_expiry;
    uint8_t delegation_wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
    int64_t last_success_unix;
    uint32_t consecutive_failures;
};

bool vcs_zcode_dht_contact_from_delegation(
    struct vcs_zcode_dht_contact *out,
    const struct vcs_zcode_dht_delegation *delegation,
    int64_t last_success_unix, uint32_t consecutive_failures);

enum vcs_zcode_dht_probe_state {
    VCS_ZCODE_DHT_PROBE_WAITING = 0,
    VCS_ZCODE_DHT_PROBE_IN_FLIGHT,
    VCS_ZCODE_DHT_PROBE_RESPONDED,
    VCS_ZCODE_DHT_PROBE_FAILED,
    VCS_ZCODE_DHT_PROBE_EXPIRED,
    VCS_ZCODE_DHT_PROBE_STATE_COUNT
};

struct vcs_zcode_dht_pending {
    bool active;
    enum vcs_zcode_dht_probe_state state;
    uint8_t victim_node_id[32];
    struct vcs_zcode_dht_contact candidate;
    int64_t deadline_mono;
};

/* The long-lived service heap-owns this object. Fixed storage makes every cap
 * independent of peer lengths and keeps mutation allocation-free. */
struct vcs_zcode_dht_table {
    uint8_t self_id[32];
    uint32_t contact_count;
    uint8_t bucket_sizes[VCS_ZCODE_DHT_BUCKET_COUNT];
    struct vcs_zcode_dht_contact buckets[VCS_ZCODE_DHT_BUCKET_COUNT]
                                         [VCS_ZCODE_DHT_K];
    uint32_t pending_count;
    struct vcs_zcode_dht_pending pending[VCS_ZCODE_DHT_MAX_PENDING];
    uint64_t probe_transitions[VCS_ZCODE_DHT_PROBE_STATE_COUNT];
};

bool vcs_zcode_dht_node_id(uint8_t out[32],
                           const uint8_t network_genesis_root[32],
                           const uint8_t master_pubkey[32],
                           const uint8_t delayed_block_hash[32]);
void vcs_zcode_dht_xor_distance(const uint8_t a[32], const uint8_t b[32],
                                uint8_t out[32]);
int vcs_zcode_dht_bucket_index(const uint8_t distance[32]);
bool vcs_zcode_dht_table_init(struct vcs_zcode_dht_table *table,
                              const uint8_t self_id[32]);

/* A full bucket/table schedules exactly one incumbent probe. First eligible
 * candidate wins until the probe resolves; no immediate eviction occurs. */
enum vcs_zcode_dht_add_result vcs_zcode_dht_table_add_contact(
    struct vcs_zcode_dht_table *table,
    const struct vcs_zcode_dht_contact *contact, int64_t now_mono);
/* WAITING has only a queue deadline.  IN_FLIGHT and its liveness deadline are
 * armed atomically after the FIND_NODE frame has entered the outbound queue. */
bool vcs_zcode_dht_table_probe_started(struct vcs_zcode_dht_table *table,
                                       const uint8_t victim_node_id[32],
                                       int64_t now_mono);
/* Complete an actually transmitted probe. FAILED/EXPIRED may replace the
 * incumbent only when the caller has freshly revalidated the candidate. */
bool vcs_zcode_dht_table_probe_complete(
    struct vcs_zcode_dht_table *table, const uint8_t victim_node_id[32],
    enum vcs_zcode_dht_probe_state terminal_state, bool candidate_valid,
    int64_t now_unix);
bool vcs_zcode_dht_table_probe_state(
    const struct vcs_zcode_dht_table *table,
    const uint8_t victim_node_id[32], enum vcs_zcode_dht_probe_state *out);
uint64_t vcs_zcode_dht_table_probe_transition_count(
    const struct vcs_zcode_dht_table *table,
    enum vcs_zcode_dht_probe_state state);
/* Record a terminal outcome while discarding only the candidate. */
bool vcs_zcode_dht_table_probe_discard(
    struct vcs_zcode_dht_table *table, const uint8_t victim_node_id[32],
    enum vcs_zcode_dht_probe_state terminal_state);
size_t vcs_zcode_dht_table_expire_probes(struct vcs_zcode_dht_table *table,
                                         int64_t now_mono);
/* Drop a pending candidate without evicting its incumbent. Used when the
 * candidate's signed delegation or chain status went stale while the
 * incumbent probe was in flight. */
bool vcs_zcode_dht_table_discard_candidate(
    struct vcs_zcode_dht_table *table, const uint8_t victim_node_id[32]);
size_t vcs_zcode_dht_table_pending_count(
    const struct vcs_zcode_dht_table *table);

bool vcs_zcode_dht_table_touch(struct vcs_zcode_dht_table *table,
                               const uint8_t node_id[32],
                               int64_t last_success_unix);
bool vcs_zcode_dht_table_note_failure(struct vcs_zcode_dht_table *table,
                                      const uint8_t node_id[32]);
bool vcs_zcode_dht_table_remove(struct vcs_zcode_dht_table *table,
                                const uint8_t node_id[32]);
bool vcs_zcode_dht_table_find(const struct vcs_zcode_dht_table *table,
                              const uint8_t node_id[32],
                              struct vcs_zcode_dht_contact *out);
size_t vcs_zcode_dht_table_closest(
    const struct vcs_zcode_dht_table *table, const uint8_t target_id[32],
    struct vcs_zcode_dht_contact *out_contacts, size_t max);
uint32_t vcs_zcode_dht_table_count(const struct vcs_zcode_dht_table *table);

typedef bool (*vcs_zcode_dht_chain_verify_fn)(
    void *ctx, const struct vcs_zcode_dht_delegation *delegation);

/* Canonical zcode_dht_contacts.v2: network genesis and local node ID are in
 * the header; entries are strictly node-ID sorted and contain the complete
 * signed delegation plus local observations. */
size_t vcs_zcode_dht_contacts_wire_bytes(uint32_t count);
enum vcs_zcode_dht_error vcs_zcode_dht_contacts_serialize(
    const struct vcs_zcode_dht_contact *contacts, uint32_t count,
    const uint8_t network_genesis[32], const uint8_t self_id[32],
    uint8_t *wire, size_t wire_capacity, size_t *wire_len_out);
enum vcs_zcode_dht_error vcs_zcode_dht_contacts_parse(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_genesis[32], const uint8_t expected_self_id[32],
    uint64_t now_unix, vcs_zcode_dht_chain_verify_fn chain_verify,
    void *chain_ctx, struct vcs_zcode_dht_contact *contacts_out,
    uint32_t contact_capacity, uint32_t *count_out);

#endif /* ZCL_VCS_ZCODE_DHT_H */
