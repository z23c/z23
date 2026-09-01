/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "base/hex.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_dht.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill32(uint8_t out[32], uint8_t v) { memset(out, v, 32); }

static void fake_contact(struct vcs_zcode_dht_contact *c,
                         const uint8_t id[32], uint8_t binding,
                         uint64_t seq, int64_t seen)
{
    memset(c, 0, sizeof(*c));
    memcpy(c->node_id, id, 32);
    fill32(c->master_pubkey, binding);
    fill32(c->online_pubkey, (uint8_t)(binding + seq));
    fill32(c->noise_static_pubkey, (uint8_t)(binding + 1));
    fill32(c->beacon_hash, (uint8_t)(binding + 2));
    c->beacon_height = 100;
    c->delegation_sequence = seq;
    c->delegation_not_before = 1;
    c->delegation_expiry = 100000;
    memset(c->delegation_wire, (int)(binding + seq),
           sizeof(c->delegation_wire));
    c->last_success_unix = seen;
}

static void bucket_id(uint8_t id[32], uint8_t n)
{
    memset(id, 0, 32); id[0] = 0x80; id[31] = n;
}

static void cap_id(uint8_t id[32], uint32_t top, uint32_t r)
{
    memset(id, 0, 32);
    id[top / 8] |= (uint8_t)(1u << (7 - top % 8));
    for (uint32_t k = 0; k < 8 && top + 1 + k < 256; k++)
        if (r & (1u << k)) {
            uint32_t p = top + 1 + k;
            id[p / 8] |= (uint8_t)(1u << (7 - p % 8));
        }
}

static struct vcs_zcode_dht_table *new_table(const uint8_t self[32])
{
    struct vcs_zcode_dht_table *t =
        zcl_calloc(1, sizeof(*t), "test.zcode_dht.table");
    if (!t || !vcs_zcode_dht_table_init(t, self)) { free(t); return NULL; }
    return t;
}

static int test_node_id_and_distance(void)
{
    int failures = 0;
    TEST("zcode dht: stable node-id golden and XOR buckets") {
        uint8_t genesis[32], master[32], beacon[32], out[32], zero[32] = {0};
        fill32(genesis, 1); fill32(master, 0x11); fill32(beacon, 0x22);
        ASSERT(vcs_zcode_dht_node_id(out, genesis, master, beacon));
        char hex[65]; zcl_hex_encode(out, 32, hex);
        ASSERT_STR_EQ(hex,
            "7a14deaa1ca7ffaaf30e0359aa89c8cc5b95b92e35800d00d6e2141032f7d3a7");
        ASSERT(!vcs_zcode_dht_node_id(out, zero, master, beacon));
        uint8_t d[32] = {0}; d[0] = 0x80;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), 255);
        memset(d, 0, sizeof(d)); d[31] = 1;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refresh_rules(void)
{
    int failures = 0;
    TEST("zcode dht: duplicate IDs require stable binding and monotonic data") {
        uint8_t self[32], id[32]; fill32(self, 1); fill32(id, 0x80);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        struct vcs_zcode_dht_contact c, got;
        fake_contact(&c, id, 0x20, 5, 100);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100),
                  VCS_ZCODE_DHT_ADD_ADDED);
        fake_contact(&c, id, 0x20, 6, 101);
        memset(c.noise_static_pubkey, 0x7e, 32);
        c.delegation_wire[17] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 101),
                  VCS_ZCODE_DHT_ADD_REFRESHED);
        fake_contact(&c, id, 0x20, 6, 102);
        memset(c.noise_static_pubkey, 0x7f, 32);
        c.delegation_wire[18] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_STALE);
        fake_contact(&c, id, 0x20, 5, 102);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_STALE);
        fake_contact(&c, id, 0x20, 7, 99);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP);
        fake_contact(&c, id, 0x21, 7, 102);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_BINDING);
        fake_contact(&c, id, 0x20, 7, 102);
        memset(c.node_id, 0, 32);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_ZERO_ID);
        fake_contact(&c, id, 0x20, 7, 102);
        memset(c.noise_static_pubkey, 0, 32);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY);
        fake_contact(&c, id, 0x20, 7, -1);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 102),
                  VCS_ZCODE_DHT_ADD_REJECTED_TIMESTAMP);
        ASSERT(vcs_zcode_dht_table_find(t, id, &got));
        ASSERT_EQ(got.delegation_sequence, 6);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int test_probe_policy(void)
{
    int failures = 0;
    TEST("zcode dht: bucket floods cannot rotate pending replacement") {
        uint8_t self[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        uint8_t ids[19][32];
        for (uint8_t i = 0; i < 19; i++) bucket_id(ids[i], i);
        for (uint32_t i = 0; i < VCS_ZCODE_DHT_K; i++) {
            struct vcs_zcode_dht_contact c; fake_contact(&c, ids[i], 0x20, 1, 100);
            ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100),
                      VCS_ZCODE_DHT_ADD_ADDED);
        }
        struct vcs_zcode_dht_contact c, got;
        fake_contact(&c, ids[16], 0x20, 1, 101);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 1000),
                  VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        enum vcs_zcode_dht_probe_state probe_state;
        ASSERT(vcs_zcode_dht_table_probe_state(t, ids[0], &probe_state));
        ASSERT_EQ(probe_state, VCS_ZCODE_DHT_PROBE_WAITING);
        fake_contact(&c, ids[17], 0x20, 1, 102);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 1001),
                  VCS_ZCODE_DHT_ADD_REJECTED_PENDING);
        ASSERT_EQ(vcs_zcode_dht_table_count(t), VCS_ZCODE_DHT_K);
        ASSERT(vcs_zcode_dht_table_probe_started(t, ids[0], 1002));
        ASSERT(vcs_zcode_dht_table_probe_state(t, ids[0], &probe_state));
        ASSERT_EQ(probe_state, VCS_ZCODE_DHT_PROBE_IN_FLIGHT);
        ASSERT(vcs_zcode_dht_table_probe_complete(
            t, ids[0], VCS_ZCODE_DHT_PROBE_RESPONDED, true, 1002));
        ASSERT(vcs_zcode_dht_table_find(t, ids[0], &got));
        ASSERT(!vcs_zcode_dht_table_find(t, ids[16], &got));
        fake_contact(&c, ids[18], 0x20, 1, 103);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 2000),
                  VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        ASSERT_EQ(vcs_zcode_dht_table_expire_probes(t, 2029), 0);
        ASSERT_EQ(vcs_zcode_dht_table_expire_probes(t, 2030), 1);
        ASSERT(vcs_zcode_dht_table_find(t, ids[1], &got));
        ASSERT(!vcs_zcode_dht_table_find(t, ids[18], &got));

        /* Only a transmitted, failed probe can evict.  Promotion requires
         * the caller's fresh candidate validation at completion time. */
        fake_contact(&c, ids[17], 0x20, 1, 104);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 3000),
                  VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        ASSERT(vcs_zcode_dht_table_probe_started(t, ids[1], 3000));
        ASSERT(vcs_zcode_dht_table_probe_complete(
            t, ids[1], VCS_ZCODE_DHT_PROBE_EXPIRED, true, 3010));
        ASSERT(!vcs_zcode_dht_table_find(t, ids[1], &got));
        ASSERT(vcs_zcode_dht_table_find(t, ids[17], &got));
        ASSERT_EQ(vcs_zcode_dht_table_probe_transition_count(
                      t, VCS_ZCODE_DHT_PROBE_WAITING), 3);
        ASSERT_EQ(vcs_zcode_dht_table_probe_transition_count(
                      t, VCS_ZCODE_DHT_PROBE_IN_FLIGHT), 2);
        ASSERT_EQ(vcs_zcode_dht_table_probe_transition_count(
                      t, VCS_ZCODE_DHT_PROBE_RESPONDED), 1);
        ASSERT_EQ(vcs_zcode_dht_table_probe_transition_count(
                      t, VCS_ZCODE_DHT_PROBE_EXPIRED), 2);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int test_global_cap_and_failures(void)
{
    int failures = 0;
    TEST("zcode dht: table cap probes deterministic victim and failures saturate") {
        uint8_t self[32] = {0}; self[31] = 1;
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        uint8_t id[32], first[32]; uint32_t n = 0;
        for (uint32_t p = 0; p <= 253; p++)
            for (uint32_t r = 0; r < 4; r++) {
                cap_id(id, p, r);
                if (!n || memcmp(id, first, 32) < 0) memcpy(first, id, 32);
                struct vcs_zcode_dht_contact c; fake_contact(&c, id, 0x20, 1, 50);
                ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 50),
                          VCS_ZCODE_DHT_ADD_ADDED); n++;
            }
        for (uint32_t r = 0; r < 2; r++) {
            cap_id(id, 254, r);
            if (memcmp(id, first, 32) < 0) memcpy(first, id, 32);
            struct vcs_zcode_dht_contact c;
            fake_contact(&c, id, 0x20, 1, 50);
            ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 50),
                      VCS_ZCODE_DHT_ADD_ADDED); n++;
        }
        for (uint32_t r = 4; r < 10; r++) {
            cap_id(id, 0, r);
            if (memcmp(id, first, 32) < 0) memcpy(first, id, 32);
            struct vcs_zcode_dht_contact c;
            fake_contact(&c, id, 0x20, 1, 50);
            ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 50),
                      VCS_ZCODE_DHT_ADD_ADDED); n++;
        }
        ASSERT_EQ(n, VCS_ZCODE_DHT_MAX_CONTACTS);
        cap_id(id, 252, 4); struct vcs_zcode_dht_contact c, got;
        fake_contact(&c, id, 0x20, 1, 60);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 60),
                  VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        ASSERT(vcs_zcode_dht_table_probe_started(t, first, 60));
        ASSERT(vcs_zcode_dht_table_probe_complete(
            t, first, VCS_ZCODE_DHT_PROBE_FAILED, true, 70));
        ASSERT_EQ(vcs_zcode_dht_table_count(t), VCS_ZCODE_DHT_MAX_CONTACTS);
        ASSERT(vcs_zcode_dht_table_find(t, id, &got));
        got.consecutive_failures = UINT32_MAX;
        /* Refresh the stored row through the test-owned pointer lookup. */
        size_t slot = 0; int b = -1;
        uint8_t distance[32]; vcs_zcode_dht_xor_distance(self, id, distance);
        b = vcs_zcode_dht_bucket_index(distance);
        for (; slot < t->bucket_sizes[b]; slot++)
            if (memcmp(t->buckets[b][slot].node_id, id, 32) == 0) break;
        t->buckets[b][slot].consecutive_failures = UINT32_MAX;
        ASSERT(vcs_zcode_dht_table_note_failure(t, id));
        ASSERT(vcs_zcode_dht_table_find(t, id, &got));
        ASSERT_EQ(got.consecutive_failures, UINT32_MAX);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int test_closest(void)
{
    int failures = 0;
    TEST("zcode dht: closest ordering uses bounded caller output") {
        uint8_t self[32]; fill32(self, 0xaa);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        const uint8_t vals[] = {5, 3, 9};
        for (size_t i = 0; i < 3; i++) {
            uint8_t id[32] = {0}; id[31] = vals[i];
            struct vcs_zcode_dht_contact c; fake_contact(&c, id, 0x20, 1, 1);
            ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 1),
                      VCS_ZCODE_DHT_ADD_ADDED);
        }
        uint8_t target[32] = {0}; struct vcs_zcode_dht_contact out[2];
        ASSERT_EQ(vcs_zcode_dht_table_closest(t, target, out, 2), 2);
        ASSERT_EQ(out[0].node_id[31], 3); ASSERT_EQ(out[1].node_id[31], 5);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static bool real_contact(struct vcs_zcode_dht_contact *c, uint8_t seed_byte,
                         int64_t seen)
{
    uint8_t genesis[32], online[32], noise[32], beacon[32], seed[32];
    fill32(genesis, 1); fill32(online, (uint8_t)(0x20 + seed_byte));
    fill32(noise, (uint8_t)(0x30 + seed_byte));
    fill32(beacon, (uint8_t)(0x40 + seed_byte)); fill32(seed, seed_byte);
    struct vcs_zcode_dht_delegation d;
    return vcs_zcode_dht_delegation_sign(&d, genesis, online, noise,
               120, beacon, 1000, 2000, 1, seed) ==
               VCS_ZCODE_DHT_DELEGATION_OK &&
           vcs_zcode_dht_contact_from_delegation(c, &d, seen, 0);
}

static bool chain_accept(void *ctx,
                         const struct vcs_zcode_dht_delegation *d)
{
    size_t *calls = ctx; (*calls)++;
    return d->beacon_height == 120;
}

static int test_persistence_v2(void)
{
    int failures = 0;
    TEST("zcode dht: contacts.v2 is canonical, bound, strict, and empty-safe") {
        uint8_t genesis[32], self[32], other[32];
        fill32(genesis, 1); fill32(self, 2); fill32(other, 3);
        struct vcs_zcode_dht_contact contacts[2];
        ASSERT(real_contact(&contacts[0], 0x55, 1100));
        ASSERT(real_contact(&contacts[1], 0x66, 1200));
        if (memcmp(contacts[0].node_id, contacts[1].node_id, 32) < 0) {
            struct vcs_zcode_dht_contact tmp = contacts[0];
            contacts[0] = contacts[1]; contacts[1] = tmp;
        }
        uint8_t wire[VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES +
                     2 * VCS_ZCODE_DHT_CONTACT_ENTRY_WIRE_BYTES + 1];
        size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_contacts_serialize(
                      contacts, 2, genesis, self, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        struct vcs_zcode_dht_contact parsed[2]; uint32_t count = 0;
        size_t calls = 0;
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      wire, len, genesis, self, 1500, chain_accept, &calls,
                      parsed, 2, &count), VCS_ZCODE_DHT_OK);
        ASSERT_EQ(count, 2); ASSERT_EQ(calls, 2);
        ASSERT(memcmp(parsed[0].node_id, parsed[1].node_id, 32) < 0);
        uint8_t tampered[sizeof(wire)];
        memcpy(tampered, wire, len);
        uint8_t entry[VCS_ZCODE_DHT_CONTACT_ENTRY_WIRE_BYTES];
        memcpy(entry, tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES,
               sizeof(entry));
        memcpy(tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES,
               tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES + sizeof(entry),
               sizeof(entry));
        memcpy(tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES + sizeof(entry),
               entry, sizeof(entry));
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      tampered, len, genesis, self, 1500, NULL, NULL,
                      parsed, 2, &count), VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        memcpy(tampered, wire, len);
        memcpy(tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES + sizeof(entry),
               tampered + VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES, sizeof(entry));
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      tampered, len, genesis, self, 1500, NULL, NULL,
                      parsed, 2, &count), VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      wire, len, other, self, 1500, NULL, NULL,
                      parsed, 2, &count), VCS_ZCODE_DHT_ERR_NETWORK);
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      wire, len, genesis, other, 1500, NULL, NULL,
                      parsed, 2, &count), VCS_ZCODE_DHT_ERR_SELF);
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      wire, len + 1, genesis, self, 1500, NULL, NULL,
                      parsed, 2, &count), VCS_ZCODE_DHT_ERR_WIRE_SIZE);
        size_t empty_len = 0;
        ASSERT_EQ(vcs_zcode_dht_contacts_serialize(
                      NULL, 0, genesis, self, wire, sizeof(wire), &empty_len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(vcs_zcode_dht_contacts_parse(
                      wire, empty_len, genesis, self, 1500, NULL, NULL,
                      NULL, 0, &count), VCS_ZCODE_DHT_OK);
        ASSERT_EQ(count, 0); PASS();
    } _test_next:;
    return failures;
}

int test_zcode_dht(void)
{
    int failures = 0;
    failures += test_node_id_and_distance();
    failures += test_refresh_rules();
    failures += test_probe_policy();
    failures += test_global_cap_and_failures();
    failures += test_closest();
    failures += test_persistence_v2();
    printf("=== zcode_dht: %d failures ===\n", failures);
    return failures;
}
