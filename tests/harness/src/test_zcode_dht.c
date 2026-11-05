/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "base/hex.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_dht.h"

#include <limits.h>
#include <stddef.h>
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

/* ---- Mutation-sweep additions: error strings, ids, bounds, table edges ---- */

static int sweep_error_strings(void)
{
    int failures = 0;
    TEST("zcode dht: every error code has its stable name and unknown codes are named unknown") {
        static const char *const names[] = {
            "ok", "null-argument", "schema-version", "limit-invalid", "id-zero",
            "key-zero", "last-success-invalid", "wire-size", "wire-magic",
            "entry-order", "wire-kind", "query-id-zero", "wrong-network",
            "wrong-local-node", "delegation-invalid", "noise-session",
            "online-signature", "identity-mismatch", "expired"};
        for (int e = 0; e <= (int)VCS_ZCODE_DHT_ERR_EXPIRED; e++) {
            const char *s = vcs_zcode_dht_error_string((enum vcs_zcode_dht_error)e);
            ASSERT(s != NULL);
            ASSERT_STR_EQ(s, names[e]);
        }
        ASSERT_STR_EQ(vcs_zcode_dht_error_string(
                          (enum vcs_zcode_dht_error)(VCS_ZCODE_DHT_ERR_EXPIRED + 1)),
                      "unknown");
        ASSERT_STR_EQ(vcs_zcode_dht_error_string((enum vcs_zcode_dht_error)9999),
                      "unknown");
        PASS();
    } _test_next:;
    return failures;
}

static int sweep_roster_node_id(void)
{
    int failures = 0;
    TEST("zcode dht: roster node id hashes domain, genesis and master and zeroes refusals") {
        uint8_t buf[72], out[40], expected[32];
        memset(buf, 0x77, sizeof(buf));
        memset(buf, 0x11, 32); memset(buf + 32, 0x22, 32);
        uint8_t msg[sizeof(VCS_ZCODE_DHT_ROSTER_NODE_ID_DOMAIN) + 64];
        memcpy(msg, VCS_ZCODE_DHT_ROSTER_NODE_ID_DOMAIN,
               sizeof(VCS_ZCODE_DHT_ROSTER_NODE_ID_DOMAIN));
        memcpy(msg + sizeof(VCS_ZCODE_DHT_ROSTER_NODE_ID_DOMAIN), buf, 64);
        sha3_256(msg, sizeof(msg), expected);
        memset(out, 0xaa, sizeof(out));
        ASSERT(vcs_zcode_dht_roster_node_id(out, buf, buf + 32));
        ASSERT(!memcmp(out, expected, 32));
        for (int i = 32; i < 40; i++) ASSERT_EQ(out[i], 0xaa);
        ASSERT(!vcs_zcode_dht_roster_node_id(NULL, buf, buf + 32));
        PASS();
    } _test_next:;
    return failures;
}

static bool refused_zeroed(bool refused, const uint8_t out[40])
{
    for (int i = 0; i < 32; i++) if (out[i]) return false;
    for (int i = 32; i < 40; i++) if (out[i] != 0xaa) return false;
    return refused;
}

static int sweep_roster_node_id_refusals(void)
{
    int failures = 0;
    TEST("zcode dht: roster node id refuses a zero input over its full 32 bytes") {
        uint8_t good[33], zero[33] = {0}, last[33] = {0}, wide[33] = {0}, out[40];
        memset(good, 0x33, sizeof(good));
        last[31] = 0x01; wide[32] = 0xff;
        memset(out, 0xaa, sizeof(out));
        ASSERT(refused_zeroed(!vcs_zcode_dht_roster_node_id(out, zero, good), out));
        memset(out, 0xaa, sizeof(out));
        ASSERT(refused_zeroed(!vcs_zcode_dht_roster_node_id(out, good, zero), out));
        memset(out, 0xaa, sizeof(out));
        ASSERT(refused_zeroed(!vcs_zcode_dht_roster_node_id(out, wide, good), out));
        memset(out, 0xaa, sizeof(out));
        ASSERT(refused_zeroed(!vcs_zcode_dht_roster_node_id(out, good, wide), out));
        ASSERT(vcs_zcode_dht_roster_node_id(out, last, good));
        ASSERT(vcs_zcode_dht_roster_node_id(out, good, last));
        uint8_t b[32] = {0}, c[32] = {0};
        b[31] = 1; c[31] = 1;
        ASSERT(vcs_zcode_dht_node_id(out, last, b, c));
        PASS();
    } _test_next:;
    return failures;
}

static int sweep_distance_and_bucket(void)
{
    int failures = 0;
    TEST("zcode dht: xor distance stays inside 32 bytes and bucket index is exact") {
        uint8_t a[40], b[40], out[40];
        for (int i = 0; i < 40; i++) {
            a[i] = (uint8_t)(i + 1); b[i] = (uint8_t)(2 * i + 3); out[i] = 0x5a;
        }
        vcs_zcode_dht_xor_distance(a, b, out);
        for (int i = 0; i < 32; i++) ASSERT_EQ(out[i], (uint8_t)(a[i] ^ b[i]));
        for (int i = 32; i < 40; i++) ASSERT_EQ(out[i], 0x5a);
        uint8_t d[40] = {0};
        ASSERT_EQ(vcs_zcode_dht_bucket_index(NULL), -1);
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), -1);
        d[32] = 0x01;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), -1);
        d[0] = 0x01;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), 248);
        d[0] = 0; d[1] = 0x40;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), 246);
        d[1] = 0; d[31] = 0x80;
        ASSERT_EQ(vcs_zcode_dht_bucket_index(d), 7);
        PASS();
    } _test_next:;
    return failures;
}

static bool real_delegation(struct vcs_zcode_dht_delegation *d, uint8_t seed_byte)
{
    uint8_t genesis[32], online[32], noise[32], beacon[32], seed[32];
    fill32(genesis, 1); fill32(online, (uint8_t)(0x20 + seed_byte));
    fill32(noise, (uint8_t)(0x30 + seed_byte));
    fill32(beacon, (uint8_t)(0x40 + seed_byte)); fill32(seed, seed_byte);
    return vcs_zcode_dht_delegation_sign(d, genesis, online, noise, 120, beacon,
                                         1000, 2000, 1, seed) ==
           VCS_ZCODE_DHT_DELEGATION_OK;
}

static bool contact_padding_clear(const struct vcs_zcode_dht_contact *c)
{
    const uint8_t *p = (const uint8_t *)c;
    size_t a = offsetof(struct vcs_zcode_dht_contact, beacon_height) + sizeof(c->beacon_height);
    for (size_t i = a; i < offsetof(struct vcs_zcode_dht_contact, delegation_sequence); i++)
        if (p[i]) return false;
    size_t z = offsetof(struct vcs_zcode_dht_contact, consecutive_failures) +
               sizeof(c->consecutive_failures);
    for (size_t i = z; i < sizeof(*c); i++)
        if (p[i]) return false;
    return true;
}

static int sweep_contact_from_delegation(void)
{
    int failures = 0;
    TEST("zcode dht: contact copies every delegation field in full and refuses bad input") {
        struct vcs_zcode_dht_delegation d;
        ASSERT(real_delegation(&d, 0x55));
        struct vcs_zcode_dht_contact c;
        memset(&c, 0xff, sizeof(c));
        ASSERT(vcs_zcode_dht_contact_from_delegation(&c, &d, 0, 7));
        ASSERT(!memcmp(c.master_pubkey, d.doc.master_pubkey, 32));
        ASSERT(!memcmp(c.online_pubkey, d.online_pubkey, 32));
        ASSERT(!memcmp(c.noise_static_pubkey, d.noise_static_pubkey, 32));
        ASSERT(!memcmp(c.beacon_hash, d.beacon_hash, 32));
        ASSERT_EQ(c.beacon_height, 120);
        ASSERT_EQ(c.delegation_sequence, d.doc.seq);
        ASSERT_EQ(c.delegation_not_before, d.not_before);
        ASSERT_EQ(c.delegation_expiry, d.doc.expiry);
        ASSERT_EQ(c.last_success_unix, 0);
        ASSERT_EQ(c.consecutive_failures, 7);
        ASSERT(contact_padding_clear(&c));
        uint8_t id[32], wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
        ASSERT(vcs_zcode_dht_delegation_node_id(id, &d));
        ASSERT(!memcmp(c.node_id, id, 32));
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&d, wire), VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT(!memcmp(c.delegation_wire, wire, sizeof(wire)));
        PASS();
    } _test_next:;
    return failures;
}

static int sweep_contact_from_delegation_refusals(void)
{
    int failures = 0;
    TEST("zcode dht: contact refuses null, negative time, unencodable and unidentifiable delegations") {
        struct vcs_zcode_dht_delegation d, bad;
        ASSERT(real_delegation(&d, 0x55));
        struct vcs_zcode_dht_contact c;
        ASSERT(!vcs_zcode_dht_contact_from_delegation(NULL, &d, 1, 0));
        ASSERT(!vcs_zcode_dht_contact_from_delegation(&c, NULL, 1, 0));
        ASSERT(!vcs_zcode_dht_contact_from_delegation(&c, &d, -1, 0));
        bad = d; bad.doc.body_len = 0;
        ASSERT(!vcs_zcode_dht_contact_from_delegation(&c, &bad, 1, 0));
        bad = d; memset(bad.doc.master_pubkey, 0, 32);
        ASSERT(!vcs_zcode_dht_contact_from_delegation(&c, &bad, 1, 0));
        PASS();
    } _test_next:;
    return failures;
}

static int sweep_table_init(void)
{
    int failures = 0;
    TEST("zcode dht: table init clears the table, copies the whole id and refuses zero ids") {
        struct vcs_zcode_dht_table *t = zcl_calloc(1, sizeof(*t), "test.zcode_dht.init");
        ASSERT(t != NULL);
        uint8_t zero[33] = {0}, wide[33] = {0}, last[33] = {0};
        wide[32] = 0xff; last[31] = 0x09;
        ASSERT(!vcs_zcode_dht_table_init(NULL, last));
        memset(t, 0xaa, sizeof(*t));
        ASSERT(!vcs_zcode_dht_table_init(t, zero));
        ASSERT_EQ(t->contact_count, 0); ASSERT_EQ(t->pending_count, 0);
        ASSERT_EQ(t->bucket_sizes[0], 0); ASSERT_EQ(t->self_id[0], 0);
        ASSERT(!vcs_zcode_dht_table_init(t, wide));
        memset(t, 0xaa, sizeof(*t));
        ASSERT(vcs_zcode_dht_table_init(t, last));
        ASSERT(!memcmp(t->self_id, last, 32));
        ASSERT_EQ(t->contact_count, 0); ASSERT_EQ(t->pending_count, 0);
        ASSERT_EQ(t->bucket_sizes[255], 0);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static void sweep_dist_id(uint8_t out[32], const uint8_t self[32], unsigned bit, unsigned low)
{
    memcpy(out, self, 32);
    out[31 - bit / 8] ^= (uint8_t)(1u << (bit % 8));
    out[31] ^= (uint8_t)low;
}

static size_t sweep_bucket_of(const uint8_t self[32], const uint8_t id[32])
{
    uint8_t d[32];
    vcs_zcode_dht_xor_distance(self, id, d);
    return (size_t)vcs_zcode_dht_bucket_index(d);
}

static int sweep_refresh_edges(void)
{
    int failures = 0;
    TEST("zcode dht: an identical refresh succeeds, resets failures and binds every key byte") {
        uint8_t self[32], id[32]; fill32(self, 1); fill32(id, 0x80);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        struct vcs_zcode_dht_contact c, got;
        fake_contact(&c, id, 0x20, 5, 100); c.consecutive_failures = 5;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_ADDED);
        ASSERT(vcs_zcode_dht_table_find(t, id, &got));
        ASSERT_EQ(got.consecutive_failures, 0);
        size_t b = sweep_bucket_of(self, id);
        t->buckets[b][0].consecutive_failures = 4;
        fake_contact(&c, id, 0x20, 5, 100); c.consecutive_failures = 9;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_REFRESHED);
        ASSERT(vcs_zcode_dht_table_find(t, id, &got));
        ASSERT_EQ(got.consecutive_failures, 0);
        fake_contact(&c, id, 0x20, 5, 100); c.master_pubkey[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_REJECTED_BINDING);
        fake_contact(&c, id, 0x20, 5, 100); c.beacon_hash[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_REJECTED_BINDING);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static uint8_t *contact_key_field(struct vcs_zcode_dht_contact *c, int which)
{
    switch (which) {
    case 0: return c->master_pubkey;
    case 1: return c->online_pubkey;
    case 2: return c->noise_static_pubkey;
    default: return c->beacon_hash;
    }
}

static enum vcs_zcode_dht_add_result sweep_add_field(
    struct vcs_zcode_dht_table *t, uint8_t n, int which, uint8_t last)
{
    uint8_t id[32]; bucket_id(id, n);
    struct vcs_zcode_dht_contact c; fake_contact(&c, id, 0x20, 1, 100);
    uint8_t *f = contact_key_field(&c, which);
    memset(f, 0, 32); f[31] = last;
    return vcs_zcode_dht_table_add_contact(t, &c, 100);
}

static int sweep_contact_key_validation(void)
{
    int failures = 0;
    TEST("zcode dht: each contact key is checked over its own 32 bytes") {
        uint8_t self[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        for (int which = 0; which < 4; which++) {
            ASSERT_EQ(sweep_add_field(t, (uint8_t)(10 + which), which, 0),
                      VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY);
            ASSERT_EQ(sweep_add_field(t, (uint8_t)(20 + which), which, 0x42),
                      VCS_ZCODE_DHT_ADD_ADDED);
        }
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 4);
        uint8_t id[32]; bucket_id(id, 40);
        struct vcs_zcode_dht_contact c; fake_contact(&c, id, 0x20, 1, 0);
        c.beacon_height = 0;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 0), VCS_ZCODE_DHT_ADD_REJECTED_ZERO_KEY);
        c.beacon_height = 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 0), VCS_ZCODE_DHT_ADD_ADDED);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int sweep_self_and_bucket_zero(void)
{
    int failures = 0;
    TEST("zcode dht: the self id is refused and bucket zero is a real bucket") {
        uint8_t self[32], id0[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        struct vcs_zcode_dht_contact c, got;
        fake_contact(&c, self, 0x20, 1, 100);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_REJECTED_SELF);
        sweep_dist_id(id0, self, 0, 0);
        fake_contact(&c, id0, 0x20, 1, 0);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 0), VCS_ZCODE_DHT_ADD_ADDED);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 0), VCS_ZCODE_DHT_ADD_REFRESHED);
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 1); ASSERT_EQ(t->bucket_sizes[0], 1);
        ASSERT(!vcs_zcode_dht_table_find(t, self, &got));
        ASSERT(!vcs_zcode_dht_table_note_failure(t, self));
        ASSERT(!vcs_zcode_dht_table_touch(t, self, 50));
        ASSERT(!vcs_zcode_dht_table_remove(t, self));
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 1);
        ASSERT(vcs_zcode_dht_table_remove(t, id0));
        ASSERT(!vcs_zcode_dht_table_find(t, id0, &got));
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 0);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 0), VCS_ZCODE_DHT_ADD_ADDED);
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 1);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int sweep_remove_shifts_bucket(void)
{
    int failures = 0;
    TEST("zcode dht: removal keeps the remaining bucket contacts in order") {
        uint8_t self[32], id[3][32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        struct vcs_zcode_dht_contact c;
        for (unsigned j = 0; j < 3; j++) {
            sweep_dist_id(id[j], self, 7, j);
            fake_contact(&c, id[j], 0x20, 1, 100);
            ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_ADDED);
        }
        ASSERT(vcs_zcode_dht_table_remove(t, id[0]));
        ASSERT_EQ(t->bucket_sizes[7], 2);
        ASSERT(!memcmp(t->buckets[7][0].node_id, id[1], 32));
        ASSERT(!memcmp(t->buckets[7][1].node_id, id[2], 32));
        fake_contact(&c, id[0], 0x20, 1, 100);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 100), VCS_ZCODE_DHT_ADD_ADDED);
        ASSERT(vcs_zcode_dht_table_remove(t, id[2]));
        ASSERT_EQ(t->bucket_sizes[7], 2);
        ASSERT(!memcmp(t->buckets[7][0].node_id, id[1], 32));
        ASSERT(!memcmp(t->buckets[7][1].node_id, id[0], 32));
        ASSERT_EQ(vcs_zcode_dht_table_count(t), 2);
        free(t); PASS();
    } _test_next:;
    return failures;
}

/* Fill bucket 7 with K contacts of equal age, largest node id first. */
static bool sweep_fill_bucket7(struct vcs_zcode_dht_table *t, const uint8_t self[32],
                               uint8_t smallest[32])
{
    uint8_t ids[VCS_ZCODE_DHT_K][32];
    for (unsigned j = 0; j < VCS_ZCODE_DHT_K; j++) sweep_dist_id(ids[j], self, 7, j);
    for (unsigned i = 0; i < VCS_ZCODE_DHT_K; i++)
        for (unsigned k = i + 1; k < VCS_ZCODE_DHT_K; k++)
            if (memcmp(ids[k], ids[i], 32) > 0) {
                uint8_t tmp[32];
                memcpy(tmp, ids[i], 32); memcpy(ids[i], ids[k], 32); memcpy(ids[k], tmp, 32);
            }
    memcpy(smallest, ids[VCS_ZCODE_DHT_K - 1], 32);
    for (unsigned i = 0; i < VCS_ZCODE_DHT_K; i++) {
        struct vcs_zcode_dht_contact c; fake_contact(&c, ids[i], 0x20, 1, 100);
        if (vcs_zcode_dht_table_add_contact(t, &c, 100) != VCS_ZCODE_DHT_ADD_ADDED)
            return false;
    }
    return true;
}

static int sweep_full_bucket_victim(void)
{
    int failures = 0;
    TEST("zcode dht: a full bucket probes its oldest contact, ties by smallest id, in the first slot") {
        uint8_t self[32], smallest[32], cid[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        ASSERT(sweep_fill_bucket7(t, self, smallest));
        sweep_dist_id(cid, self, 7, 64);
        struct vcs_zcode_dht_contact c; fake_contact(&c, cid, 0x20, 1, 101);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 101), VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        ASSERT(t->pending[0].active);
        ASSERT(!memcmp(t->pending[0].victim_node_id, smallest, 32));
        ASSERT(!memcmp(t->pending[0].candidate.node_id, cid, 32));
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int sweep_pending_lookup(void)
{
    int failures = 0;
    TEST("zcode dht: a probe is found only by its exact victim id") {
        uint8_t self[32], smallest[32], other[32], near[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        ASSERT(sweep_fill_bucket7(t, self, smallest));
        uint8_t cid[32]; sweep_dist_id(cid, self, 7, 64);
        struct vcs_zcode_dht_contact c; fake_contact(&c, cid, 0x20, 1, 101);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 101), VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        sweep_dist_id(other, self, 3, 0);
        memcpy(near, smallest, 32); near[31] ^= 0x40;
        ASSERT(!vcs_zcode_dht_table_probe_started(t, other, 105));
        ASSERT(!vcs_zcode_dht_table_probe_started(t, near, 105));
        enum vcs_zcode_dht_probe_state st = VCS_ZCODE_DHT_PROBE_FAILED;
        ASSERT(vcs_zcode_dht_table_probe_state(t, smallest, &st));
        ASSERT_EQ(st, VCS_ZCODE_DHT_PROBE_WAITING);
        ASSERT(!vcs_zcode_dht_table_probe_discard(t, near, VCS_ZCODE_DHT_PROBE_FAILED));
        ASSERT_EQ(vcs_zcode_dht_table_pending_count(t), 1);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int sweep_pending_caps(void)
{
    int failures = 0;
    TEST("zcode dht: a saturated pending table refuses a further probe") {
        uint8_t self[32], smallest[32], cid[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        ASSERT(sweep_fill_bucket7(t, self, smallest));
        sweep_dist_id(cid, self, 7, 64);
        struct vcs_zcode_dht_contact c; fake_contact(&c, cid, 0x20, 1, 101);
        t->pending_count = VCS_ZCODE_DHT_MAX_PENDING;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 101),
                  VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP);
        for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++) t->pending[i].active = true;
        t->pending_count = VCS_ZCODE_DHT_MAX_PENDING - 1;
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 101),
                  VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static bool sweep_fill_to_cap(struct vcs_zcode_dht_table *t, const uint8_t self[32],
                              uint8_t oldest[32])
{
    uint8_t id[32];
    sweep_dist_id(id, self, 0, 0);
    memcpy(oldest, id, 32);
    struct vcs_zcode_dht_contact c; fake_contact(&c, id, 0x20, 1, 10);
    if (vcs_zcode_dht_table_add_contact(t, &c, 10) != VCS_ZCODE_DHT_ADD_ADDED) return false;
    for (unsigned b = 8; b <= 71; b++)
        for (unsigned j = 0; j < VCS_ZCODE_DHT_K && vcs_zcode_dht_table_count(t) < 1024u; j++) {
            sweep_dist_id(id, self, b, j);
            fake_contact(&c, id, 0x20, 1, 100 + b);
            if (vcs_zcode_dht_table_add_contact(t, &c, 100) != VCS_ZCODE_DHT_ADD_ADDED)
                return false;
        }
    return vcs_zcode_dht_table_count(t) == VCS_ZCODE_DHT_MAX_CONTACTS;
}

static int sweep_global_cap_victim(void)
{
    int failures = 0;
    TEST("zcode dht: at the table cap the globally oldest contact, even in bucket zero, is probed") {
        uint8_t self[32], oldest[32], cid[32]; fill32(self, 1);
        struct vcs_zcode_dht_table *t = new_table(self); ASSERT(t != NULL);
        ASSERT(sweep_fill_to_cap(t, self, oldest));
        sweep_dist_id(cid, self, 100, 0);
        struct vcs_zcode_dht_contact c; fake_contact(&c, cid, 0x20, 1, 500);
        ASSERT_EQ(vcs_zcode_dht_table_add_contact(t, &c, 500), VCS_ZCODE_DHT_ADD_PENDING_PROBE);
        ASSERT(t->pending[0].active);
        ASSERT(!memcmp(t->pending[0].victim_node_id, oldest, 32));
        ASSERT_EQ(t->pending[0].state, VCS_ZCODE_DHT_PROBE_WAITING);
        free(t); PASS();
    } _test_next:;
    return failures;
}

static int sweep_contacts_magic(void)
{
    int failures = 0;
    TEST("zcode dht: contacts file starts with the exact CRLF-guarded magic") {
        uint8_t genesis[32], self[32], wire[VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES];
        fill32(genesis, 1); fill32(self, 2);
        size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_contacts_serialize(NULL, 0, genesis, self, wire,
                                                   sizeof(wire), &len), VCS_ZCODE_DHT_OK);
        ASSERT_EQ(len, VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES);
        static const uint8_t magic[8] = {'Z', 'C', 'D', 'H', 'T', 'C', 0x0d, 0x0a};
        ASSERT(!memcmp(wire, magic, 8));
        PASS();
    } _test_next:;
    return failures;
}

static int sweep_cases(void)
{
    return sweep_error_strings() + sweep_roster_node_id() +
           sweep_roster_node_id_refusals() + sweep_distance_and_bucket() +
           sweep_contact_from_delegation() + sweep_contact_from_delegation_refusals() +
           sweep_table_init() + sweep_refresh_edges() + sweep_contact_key_validation() +
           sweep_self_and_bucket_zero() + sweep_remove_shifts_bucket() +
           sweep_full_bucket_victim() + sweep_pending_lookup() + sweep_pending_caps() +
           sweep_global_cap_victim() + sweep_contacts_magic();
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
    failures += sweep_cases();
    printf("=== zcode_dht: %d failures ===\n", failures);
    return failures;
}
