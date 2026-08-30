/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded Kademlia routing and authenticated contact persistence. */

#include "vcs/zcode_dht.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <limits.h>
#include <string.h>

static const uint8_t contacts_magic[8] =
    {'Z','C','D','H','T','C',0x0D,0x0A};

const char *vcs_zcode_dht_error_string(enum vcs_zcode_dht_error e)
{
    switch (e) {
    case VCS_ZCODE_DHT_OK: return "ok";
    case VCS_ZCODE_DHT_ERR_NULL: return "null-argument";
    case VCS_ZCODE_DHT_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_DHT_ERR_LIMIT: return "limit-invalid";
    case VCS_ZCODE_DHT_ERR_ID_ZERO: return "id-zero";
    case VCS_ZCODE_DHT_ERR_KEY_ZERO: return "key-zero";
    case VCS_ZCODE_DHT_ERR_LAST_SEEN: return "last-success-invalid";
    case VCS_ZCODE_DHT_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_DHT_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_DHT_ERR_WIRE_ORDER: return "entry-order";
    case VCS_ZCODE_DHT_ERR_WIRE_KIND: return "wire-kind";
    case VCS_ZCODE_DHT_ERR_QUERY_ID: return "query-id-zero";
    case VCS_ZCODE_DHT_ERR_NETWORK: return "wrong-network";
    case VCS_ZCODE_DHT_ERR_SELF: return "wrong-local-node";
    case VCS_ZCODE_DHT_ERR_DELEGATION: return "delegation-invalid";
    case VCS_ZCODE_DHT_ERR_SESSION: return "noise-session";
    case VCS_ZCODE_DHT_ERR_SIGNATURE: return "online-signature";
    case VCS_ZCODE_DHT_ERR_IDENTITY: return "identity-mismatch";
    case VCS_ZCODE_DHT_ERR_EXPIRED: return "expired";
    }
    return "unknown";
}

const char *vcs_zcode_dht_add_result_string(enum vcs_zcode_dht_add_result r)
{
    switch (r) {
    case VCS_ZCODE_DHT_ADD_ADDED: return "added";
    case VCS_ZCODE_DHT_ADD_REFRESHED: return "refreshed";
    case VCS_ZCODE_DHT_ADD_PENDING_PROBE: return "pending-probe";
    case VCS_ZCODE_DHT_ADD_REJECTED_SELF: return "rejected-self";
    case VCS_ZCODE_DHT_ADD_REJECTED_ZERO_ID: return "rejected-zero-id";
    case VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY: return "rejected-zero-key";
    case VCS_ZCODE_DHT_ADD_REJECTED_STALE: return "rejected-stale";
    case VCS_ZCODE_DHT_ADD_REJECTED_BINDING: return "rejected-binding";
    case VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP: return "rejected-timestamp";
    case VCS_ZCODE_DHT_ADD_REJECTED_PENDING: return "rejected-pending";
    case VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP: return "rejected-pending-cap";
    }
    return "unknown";
}

bool vcs_zcode_dht_node_id(uint8_t out[32], const uint8_t genesis[32],
                           const uint8_t master[32], const uint8_t beacon[32])
{
    if (!out) return false;
    memset(out, 0, 32);
    if (!zcl_bytes_any_set(genesis, 32) || !zcl_bytes_any_set(master, 32) ||
        !zcl_bytes_any_set(beacon, 32)) return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DHT_NODE_ID_DOMAIN,
                   sizeof(VCS_ZCODE_DHT_NODE_ID_DOMAIN));
    sha3_256_write(&sha, genesis, 32);
    sha3_256_write(&sha, master, 32);
    sha3_256_write(&sha, beacon, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

void vcs_zcode_dht_xor_distance(const uint8_t a[32], const uint8_t b[32],
                                uint8_t out[32])
{
    if (!a || !b || !out) return;
    for (size_t i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
}

int vcs_zcode_dht_bucket_index(const uint8_t distance[32])
{
    if (!distance) return -1;
    for (size_t i = 0; i < 32; i++) {
        if (!distance[i]) continue;
        for (int bit = 7; bit >= 0; bit--)
            if (distance[i] & (uint8_t)(1u << bit))
                return 255 - (int)(8 * i + (size_t)(7 - bit));
    }
    return -1;
}

bool vcs_zcode_dht_contact_from_delegation(
    struct vcs_zcode_dht_contact *out,
    const struct vcs_zcode_dht_delegation *d, int64_t seen, uint32_t failures)
{
    if (!out || !d || seen < 0) return false;
    memset(out, 0, sizeof(*out));
    if (!vcs_zcode_dht_delegation_node_id(out->node_id, d) ||
        vcs_zcode_dht_delegation_encode(d, out->delegation_wire) !=
            VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    memcpy(out->master_pubkey, d->doc.master_pubkey, 32);
    memcpy(out->online_pubkey, d->online_pubkey, 32);
    memcpy(out->noise_static_pubkey, d->noise_static_pubkey, 32);
    memcpy(out->beacon_hash, d->beacon_hash, 32);
    out->beacon_height = d->beacon_height;
    out->delegation_sequence = d->doc.seq;
    out->delegation_not_before = d->not_before;
    out->delegation_expiry = d->doc.expiry;
    out->last_success_unix = seen;
    out->consecutive_failures = failures;
    return true;
}

bool vcs_zcode_dht_table_init(struct vcs_zcode_dht_table *t,
                              const uint8_t self[32])
{
    if (!t) return false;
    memset(t, 0, sizeof(*t));
    if (!zcl_bytes_any_set(self, 32)) return false;
    memcpy(t->self_id, self, 32);
    return true;
}

static int table_slot(const struct vcs_zcode_dht_table *t,
                      const uint8_t id[32], size_t *slot_out)
{
    uint8_t distance[32];
    vcs_zcode_dht_xor_distance(t->self_id, id, distance);
    int bucket = vcs_zcode_dht_bucket_index(distance);
    if (bucket < 0) return -1;
    for (size_t i = 0; i < t->bucket_sizes[bucket]; i++)
        if (memcmp(t->buckets[bucket][i].node_id, id, 32) == 0) {
            if (slot_out) *slot_out = i;
            return bucket;
        }
    return -1;
}

static bool older(const struct vcs_zcode_dht_contact *a,
                  const struct vcs_zcode_dht_contact *b)
{
    return a->last_success_unix < b->last_success_unix ||
        (a->last_success_unix == b->last_success_unix &&
         memcmp(a->node_id, b->node_id, 32) < 0);
}

static size_t bucket_victim(const struct vcs_zcode_dht_table *t, size_t b)
{
    size_t victim = 0;
    for (size_t i = 1; i < t->bucket_sizes[b]; i++)
        if (older(&t->buckets[b][i], &t->buckets[b][victim])) victim = i;
    return victim;
}

static void table_victim(const struct vcs_zcode_dht_table *t,
                         size_t *bucket_out, size_t *slot_out)
{
    bool have = false;
    for (size_t b = 0; b < VCS_ZCODE_DHT_BUCKET_COUNT; b++)
        for (size_t s = 0; s < t->bucket_sizes[b]; s++)
            if (!have || older(&t->buckets[b][s],
                               &t->buckets[*bucket_out][*slot_out])) {
                *bucket_out = b; *slot_out = s; have = true;
            }
}

static void remove_at(struct vcs_zcode_dht_table *t, size_t b, size_t s)
{
    size_t n = t->bucket_sizes[b];
    if (s + 1 < n)
        memmove(&t->buckets[b][s], &t->buckets[b][s + 1],
                (n - s - 1) * sizeof(t->buckets[b][0]));
    t->bucket_sizes[b]--; t->contact_count--;
}

static bool identity_binding_same(const struct vcs_zcode_dht_contact *a,
                                  const struct vcs_zcode_dht_contact *b)
{
    return memcmp(a->master_pubkey, b->master_pubkey, 32) == 0 &&
        a->beacon_height == b->beacon_height &&
        memcmp(a->beacon_hash, b->beacon_hash, 32) == 0;
}

static bool contact_keys_valid(const struct vcs_zcode_dht_contact *c)
{
    return c && zcl_bytes_any_set(c->node_id, 32) && zcl_bytes_any_set(c->master_pubkey, 32) &&
        zcl_bytes_any_set(c->online_pubkey, 32) && zcl_bytes_any_set(c->noise_static_pubkey, 32) &&
        zcl_bytes_any_set(c->beacon_hash, 32) && c->beacon_height > 0;
}

static struct vcs_zcode_dht_pending *pending_for(
    struct vcs_zcode_dht_table *t, const uint8_t victim[32])
{
    for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++)
        if (t->pending[i].active &&
            memcmp(t->pending[i].victim_node_id, victim, 32) == 0)
            return &t->pending[i];
    return NULL;
}

static struct vcs_zcode_dht_pending *pending_free(
    struct vcs_zcode_dht_table *t)
{
    for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++)
        if (!t->pending[i].active) return &t->pending[i];
    return NULL;
}

static void pending_transition(struct vcs_zcode_dht_table *t,
                               struct vcs_zcode_dht_pending *p,
                               enum vcs_zcode_dht_probe_state state)
{
    p->state = state;
    if ((unsigned)state < VCS_ZCODE_DHT_PROBE_STATE_COUNT)
        t->probe_transitions[state]++;
}

static void insert_direct(struct vcs_zcode_dht_table *t,
                          const struct vcs_zcode_dht_contact *c)
{
    uint8_t distance[32];
    vcs_zcode_dht_xor_distance(t->self_id, c->node_id, distance);
    int b = vcs_zcode_dht_bucket_index(distance);
    size_t n = t->bucket_sizes[b];
    t->buckets[b][n] = *c;
    t->buckets[b][n].consecutive_failures = 0;
    t->bucket_sizes[b]++; t->contact_count++;
}

enum vcs_zcode_dht_add_result vcs_zcode_dht_table_add_contact(
    struct vcs_zcode_dht_table *t, const struct vcs_zcode_dht_contact *c,
    int64_t now)
{
    if (!t || !c || !zcl_bytes_any_set(c->node_id, 32))
        return VCS_ZCODE_DHT_ADD_REJECTED_ZERO_ID;
    if (!contact_keys_valid(c)) return VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY;
    if (c->last_success_unix < 0)
        return VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP;
    if (memcmp(c->node_id, t->self_id, 32) == 0)
        return VCS_ZCODE_DHT_ADD_REJECTED_SELF;
    size_t slot = 0;
    int b = table_slot(t, c->node_id, &slot);
    if (b >= 0) {
        struct vcs_zcode_dht_contact *old = &t->buckets[b][slot];
        /* The node ID is stable across an online/Noise-key rotation because
         * it binds the master and delayed beacon. A changed session key is
         * accepted only inside a strictly newer master-signed delegation;
         * same-sequence byte drift and every rollback fail closed. */
        if (!identity_binding_same(old, c))
            return VCS_ZCODE_DHT_ADD_REJECTED_BINDING;
        if (c->delegation_sequence < old->delegation_sequence ||
            (c->delegation_sequence == old->delegation_sequence &&
             memcmp(c->delegation_wire, old->delegation_wire,
                    sizeof(c->delegation_wire)) != 0))
            return VCS_ZCODE_DHT_ADD_REJECTED_STALE;
        if (c->last_success_unix < old->last_success_unix)
            return VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP;
        *old = *c; old->consecutive_failures = 0;
        return VCS_ZCODE_DHT_ADD_REFRESHED;
    }
    uint8_t distance[32];
    vcs_zcode_dht_xor_distance(t->self_id, c->node_id, distance);
    b = vcs_zcode_dht_bucket_index(distance);
    if (t->bucket_sizes[b] < VCS_ZCODE_DHT_K &&
        t->contact_count < VCS_ZCODE_DHT_MAX_CONTACTS) {
        insert_direct(t, c);
        return VCS_ZCODE_DHT_ADD_ADDED;
    }
    size_t vb = (size_t)b, vs = 0;
    if (t->bucket_sizes[b] == VCS_ZCODE_DHT_K)
        vs = bucket_victim(t, (size_t)b);
    else
        table_victim(t, &vb, &vs);
    const uint8_t *victim = t->buckets[vb][vs].node_id;
    if (pending_for(t, victim)) return VCS_ZCODE_DHT_ADD_REJECTED_PENDING;
    if (t->pending_count == VCS_ZCODE_DHT_MAX_PENDING)
        return VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP;
    struct vcs_zcode_dht_pending *p = pending_free(t);
    if (!p) return VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP;
    memset(p, 0, sizeof(*p)); p->active = true;
    memcpy(p->victim_node_id, victim, 32); p->candidate = *c;
    pending_transition(t, p, VCS_ZCODE_DHT_PROBE_WAITING);
    p->deadline_mono = now + VCS_ZCODE_DHT_PROBE_WAIT_TIMEOUT_S;
    t->pending_count++;
    return VCS_ZCODE_DHT_ADD_PENDING_PROBE;
}

bool vcs_zcode_dht_table_probe_started(struct vcs_zcode_dht_table *t,
                                       const uint8_t victim[32], int64_t now)
{
    if (!t || !victim) return false;
    struct vcs_zcode_dht_pending *p = pending_for(t, victim);
    if (!p || p->state != VCS_ZCODE_DHT_PROBE_WAITING) return false;
    pending_transition(t, p, VCS_ZCODE_DHT_PROBE_IN_FLIGHT);
    p->deadline_mono = now + VCS_ZCODE_DHT_PROBE_TIMEOUT_S;
    return true;
}

bool vcs_zcode_dht_table_probe_complete(
    struct vcs_zcode_dht_table *t, const uint8_t victim[32],
    enum vcs_zcode_dht_probe_state terminal, bool candidate_valid, int64_t now)
{
    if (!t || !victim || (terminal != VCS_ZCODE_DHT_PROBE_RESPONDED &&
                          terminal != VCS_ZCODE_DHT_PROBE_FAILED &&
                          terminal != VCS_ZCODE_DHT_PROBE_EXPIRED))
        return false;
    struct vcs_zcode_dht_pending *p = pending_for(t, victim);
    if (!p || p->state != VCS_ZCODE_DHT_PROBE_IN_FLIGHT) return false;
    struct vcs_zcode_dht_contact candidate = p->candidate;
    pending_transition(t, p, terminal);
    memset(p, 0, sizeof(*p)); t->pending_count--;
    if (terminal == VCS_ZCODE_DHT_PROBE_RESPONDED)
        return vcs_zcode_dht_table_touch(t, victim, now);
    if (!candidate_valid) return true;
    size_t slot = 0; int b = table_slot(t, victim, &slot);
    if (b >= 0) remove_at(t, (size_t)b, slot);
    uint8_t distance[32];
    vcs_zcode_dht_xor_distance(t->self_id, candidate.node_id, distance);
    int cb = vcs_zcode_dht_bucket_index(distance);
    if (cb < 0 || t->bucket_sizes[cb] >= VCS_ZCODE_DHT_K ||
        t->contact_count >= VCS_ZCODE_DHT_MAX_CONTACTS) return false;
    insert_direct(t, &candidate);
    return true;
}

bool vcs_zcode_dht_table_probe_state(
    const struct vcs_zcode_dht_table *t, const uint8_t victim[32],
    enum vcs_zcode_dht_probe_state *out)
{
    if (!t || !victim || !out) return false;
    for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++)
        if (t->pending[i].active &&
            memcmp(t->pending[i].victim_node_id, victim, 32) == 0) {
            *out = t->pending[i].state;
            return true;
        }
    return false;
}

uint64_t vcs_zcode_dht_table_probe_transition_count(
    const struct vcs_zcode_dht_table *t, enum vcs_zcode_dht_probe_state state)
{
    return t && (unsigned)state < VCS_ZCODE_DHT_PROBE_STATE_COUNT
               ? t->probe_transitions[state] : 0;
}

bool vcs_zcode_dht_table_probe_discard(
    struct vcs_zcode_dht_table *t, const uint8_t victim[32],
    enum vcs_zcode_dht_probe_state terminal)
{
    if (!t || !victim || (terminal != VCS_ZCODE_DHT_PROBE_RESPONDED &&
                          terminal != VCS_ZCODE_DHT_PROBE_FAILED &&
                          terminal != VCS_ZCODE_DHT_PROBE_EXPIRED))
        return false;
    struct vcs_zcode_dht_pending *p = pending_for(t, victim);
    if (!p) return false;
    pending_transition(t, p, terminal);
    memset(p, 0, sizeof(*p));
    t->pending_count--;
    return true;
}

size_t vcs_zcode_dht_table_expire_probes(struct vcs_zcode_dht_table *t,
                                         int64_t now)
{
    if (!t) return 0;
    size_t n = 0;
    for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++)
        if (t->pending[i].active && t->pending[i].deadline_mono <= now) {
            /* This routing-only helper cannot establish chain freshness, so
             * expiry always discards the candidate and preserves incumbent.
             * The service performs validated IN_FLIGHT promotion itself. */
            (void)vcs_zcode_dht_table_probe_discard(
                t, t->pending[i].victim_node_id,
                VCS_ZCODE_DHT_PROBE_EXPIRED);
            n++;
        }
    return n;
}

size_t vcs_zcode_dht_table_pending_count(const struct vcs_zcode_dht_table *t)
{ return t ? t->pending_count : 0; }

bool vcs_zcode_dht_table_discard_candidate(struct vcs_zcode_dht_table *t,
                                            const uint8_t victim[32])
{
    if (!t || !victim) return false;
    struct vcs_zcode_dht_pending *p = pending_for(t, victim);
    if (!p) return false;
    memset(p, 0, sizeof(*p));
    t->pending_count--;
    return true;
}

bool vcs_zcode_dht_table_touch(struct vcs_zcode_dht_table *t,
                               const uint8_t id[32], int64_t seen)
{
    if (!t || !id || seen < 0) return false;
    size_t s = 0; int b = table_slot(t, id, &s);
    if (b < 0 || seen < t->buckets[b][s].last_success_unix) return false;
    t->buckets[b][s].last_success_unix = seen;
    t->buckets[b][s].consecutive_failures = 0;
    return true;
}

bool vcs_zcode_dht_table_note_failure(struct vcs_zcode_dht_table *t,
                                      const uint8_t id[32])
{
    if (!t || !id) return false;
    size_t s = 0; int b = table_slot(t, id, &s);
    if (b < 0) return false;
    uint32_t *f = &t->buckets[b][s].consecutive_failures;
    if (*f != UINT32_MAX) (*f)++;
    return true;
}

bool vcs_zcode_dht_table_remove(struct vcs_zcode_dht_table *t,
                                const uint8_t id[32])
{
    if (!t || !id) return false;
    struct vcs_zcode_dht_pending *p = pending_for(t, id);
    if (p) {
        pending_transition(t, p, VCS_ZCODE_DHT_PROBE_FAILED);
        memset(p, 0, sizeof(*p));
        t->pending_count--;
    }
    size_t s = 0; int b = table_slot(t, id, &s);
    if (b < 0) return false;
    remove_at(t, (size_t)b, s); return true;
}

bool vcs_zcode_dht_table_find(const struct vcs_zcode_dht_table *t,
                              const uint8_t id[32],
                              struct vcs_zcode_dht_contact *out)
{
    if (!t || !id || !out) return false;
    size_t s = 0; int b = table_slot(t, id, &s);
    if (b < 0) return false;
    *out = t->buckets[b][s]; return true;
}

static bool closer(const uint8_t candidate[32], const uint8_t incumbent[32],
                   const uint8_t target[32])
{
    uint8_t a[32], b[32];
    vcs_zcode_dht_xor_distance(candidate, target, a);
    vcs_zcode_dht_xor_distance(incumbent, target, b);
    int cmp = memcmp(a, b, 32);
    return cmp < 0 || (cmp == 0 && memcmp(candidate, incumbent, 32) < 0);
}

size_t vcs_zcode_dht_table_closest(const struct vcs_zcode_dht_table *t,
    const uint8_t target[32], struct vcs_zcode_dht_contact *out, size_t max)
{
    if (!t || !target || !out || !max) return 0;
    if (max > VCS_ZCODE_DHT_MAX_CONTACTS) max = VCS_ZCODE_DHT_MAX_CONTACTS;
    size_t count = 0;
    for (size_t b = 0; b < VCS_ZCODE_DHT_BUCKET_COUNT; b++)
        for (size_t s = 0; s < t->bucket_sizes[b]; s++) {
            const struct vcs_zcode_dht_contact *c = &t->buckets[b][s];
            if (count == max && !closer(c->node_id, out[count - 1].node_id,
                                        target)) continue;
            size_t at = count;
            while (at && closer(c->node_id, out[at - 1].node_id, target)) at--;
            if (count < max) count++;
            memmove(&out[at + 1], &out[at],
                    (count - at - 1) * sizeof(*out));
            out[at] = *c;
        }
    return count;
}

uint32_t vcs_zcode_dht_table_count(const struct vcs_zcode_dht_table *t)
{ return t ? t->contact_count : 0; }

size_t vcs_zcode_dht_contacts_wire_bytes(uint32_t count)
{
    return count > VCS_ZCODE_DHT_MAX_CONTACTS ? 0 :
        VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES +
        (size_t)count * VCS_ZCODE_DHT_CONTACT_ENTRY_WIRE_BYTES;
}

static enum vcs_zcode_dht_error contact_consistent(
    const struct vcs_zcode_dht_contact *c,
    struct vcs_zcode_dht_delegation *d_out)
{
    if (!contact_keys_valid(c)) return VCS_ZCODE_DHT_ERR_KEY_ZERO;
    struct vcs_zcode_dht_delegation d;
    if (vcs_zcode_dht_delegation_decode(&d, c->delegation_wire,
            sizeof(c->delegation_wire)) != VCS_ZCODE_DHT_DELEGATION_OK)
        return VCS_ZCODE_DHT_ERR_DELEGATION;
    struct vcs_zcode_dht_contact rebuilt;
    if (!vcs_zcode_dht_contact_from_delegation(
            &rebuilt, &d, c->last_success_unix, c->consecutive_failures) ||
        memcmp(&rebuilt, c, sizeof(*c)) != 0)
        return VCS_ZCODE_DHT_ERR_DELEGATION;
    if (d_out) *d_out = d;
    return VCS_ZCODE_DHT_OK;
}

enum vcs_zcode_dht_error vcs_zcode_dht_contacts_serialize(
    const struct vcs_zcode_dht_contact *contacts, uint32_t count,
    const uint8_t genesis[32], const uint8_t self[32], uint8_t *wire,
    size_t cap, size_t *len_out)
{
    if (!wire || !len_out || !genesis || !self || (count && !contacts))
        return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    size_t need = vcs_zcode_dht_contacts_wire_bytes(count);
    if (!need || cap < need) return VCS_ZCODE_DHT_ERR_LIMIT;
    uint16_t order[VCS_ZCODE_DHT_MAX_CONTACTS];
    for (uint32_t i = 0; i < count; i++) {
        if (contact_consistent(&contacts[i], NULL) != VCS_ZCODE_DHT_OK)
            return VCS_ZCODE_DHT_ERR_DELEGATION;
        size_t at = i;
        while (at && memcmp(contacts[i].node_id,
                            contacts[order[at - 1]].node_id, 32) < 0) {
            order[at] = order[at - 1]; at--;
        }
        order[at] = (uint16_t)i;
    }
    for (uint32_t i = 1; i < count; i++)
        if (memcmp(contacts[order[i - 1]].node_id,
                   contacts[order[i]].node_id, 32) == 0)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    size_t off = 0;
    memcpy(wire + off, contacts_magic, 8); off += 8;
    zcl_write_u16_le(wire + off, VCS_ZCODE_DHT_CONTACTS_WIRE_VERSION); off += 2;
    memcpy(wire + off, genesis, 32); off += 32;
    memcpy(wire + off, self, 32); off += 32;
    zcl_write_u32_le(wire + off, count); off += 4;
    for (uint32_t i = 0; i < count; i++) {
        const struct vcs_zcode_dht_contact *c = &contacts[order[i]];
        memcpy(wire + off, c->node_id, 32); off += 32;
        memcpy(wire + off, c->delegation_wire,
               VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES);
        off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
        zcl_write_i64_le(wire + off, c->last_success_unix); off += 8;
        zcl_write_u32_le(wire + off, c->consecutive_failures); off += 4;
    }
    *len_out = off; return off == need ? VCS_ZCODE_DHT_OK
                                       : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

enum vcs_zcode_dht_error vcs_zcode_dht_contacts_parse(
    const uint8_t *wire, size_t len, const uint8_t genesis[32],
    const uint8_t self[32], uint64_t now,
    vcs_zcode_dht_chain_verify_fn chain_verify, void *chain_ctx,
    struct vcs_zcode_dht_contact *out, uint32_t out_cap, uint32_t *count_out)
{
    if (!wire || !genesis || !self || !count_out || (out_cap && !out))
        return VCS_ZCODE_DHT_ERR_NULL;
    *count_out = 0;
    if (len < VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    if (memcmp(wire, contacts_magic, 8) != 0)
        return VCS_ZCODE_DHT_ERR_WIRE_MAGIC;
    if (zcl_read_u16_le(wire + 8) != VCS_ZCODE_DHT_CONTACTS_WIRE_VERSION)
        return VCS_ZCODE_DHT_ERR_VERSION;
    if (memcmp(wire + 10, genesis, 32) != 0) return VCS_ZCODE_DHT_ERR_NETWORK;
    if (memcmp(wire + 42, self, 32) != 0) return VCS_ZCODE_DHT_ERR_SELF;
    uint32_t count = zcl_read_u32_le(wire + 74);
    if (count > VCS_ZCODE_DHT_MAX_CONTACTS || count > out_cap)
        return VCS_ZCODE_DHT_ERR_LIMIT;
    if (len != vcs_zcode_dht_contacts_wire_bytes(count))
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *node_id = wire + off; off += 32;
        if (!zcl_bytes_any_set(node_id, 32)) return VCS_ZCODE_DHT_ERR_ID_ZERO;
        if (i && memcmp(out[i - 1].node_id, node_id, 32) >= 0)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        struct vcs_zcode_dht_delegation d;
        enum vcs_zcode_dht_delegation_error de =
            vcs_zcode_dht_delegation_decode(&d, wire + off,
                VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES);
        off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
        int64_t seen = zcl_read_i64_le(wire + off); off += 8;
        uint32_t failures = zcl_read_u32_le(wire + off); off += 4;
        if (de != VCS_ZCODE_DHT_DELEGATION_OK || seen < 0 ||
            vcs_zcode_dht_delegation_verify(&d, genesis, NULL, 0, NULL, now) !=
                VCS_ZCODE_DHT_DELEGATION_OK ||
            (chain_verify && !chain_verify(chain_ctx, &d)) ||
            !vcs_zcode_dht_contact_from_delegation(&out[i], &d, seen, failures) ||
            memcmp(out[i].node_id, node_id, 32) != 0)
            return de != VCS_ZCODE_DHT_DELEGATION_OK
                ? VCS_ZCODE_DHT_ERR_DELEGATION
                : (seen < 0 ? VCS_ZCODE_DHT_ERR_LAST_SEEN
                            : VCS_ZCODE_DHT_ERR_DELEGATION);
    }
    *count_out = count; return VCS_ZCODE_DHT_OK;
}
