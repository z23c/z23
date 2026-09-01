/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "support/cleanse.h"
#include "vcs/zcode_dht_msgs.h"

#include <stdio.h>
#include <string.h>

static void fill(uint8_t *out, size_t n, uint8_t v) { memset(out, v, n); }

struct msg_fixture {
    uint8_t online_seed[32];
    uint8_t transcript[32];
    struct vcs_zcode_dht_delegation delegation;
    struct vcs_zcode_dht_msg_verify_context verify;
    uint8_t node_id[32];
};

static bool chain_accept(void *ctx,
                         const struct vcs_zcode_dht_delegation *d)
{
    int *calls = ctx; (*calls)++;
    return d->beacon_height == 120;
}

static bool fixture_init(struct msg_fixture *f, int *chain_calls)
{
    memset(f, 0, sizeof(*f));
    uint8_t online_pub[32], online_secret[32], genesis[32], noise[32];
    uint8_t beacon[32], master_seed[32];
    fill(f->online_seed, 32, 0x22);
    ed25519_keypair(online_pub, online_secret, f->online_seed);
    memory_cleanse(online_secret, sizeof(online_secret));
    fill(genesis, 32, 1); fill(noise, 32, 0x33);
    fill(beacon, 32, 0x44); fill(master_seed, 32, 0x55);
    if (vcs_zcode_dht_delegation_sign(
            &f->delegation, genesis, online_pub, noise, 120, beacon,
            1000, 2000, 7, master_seed) != VCS_ZCODE_DHT_DELEGATION_OK ||
        !vcs_zcode_dht_delegation_node_id(f->node_id, &f->delegation))
        return false;
    fill(f->transcript, 32, 0x77);
    f->verify.noise_established = true;
    memcpy(f->verify.noise_transcript_hash, f->transcript, 32);
    memcpy(f->verify.remote_noise_static, noise, 32);
    memcpy(f->verify.network_genesis, genesis, 32);
    f->verify.session_generation = 9;
    f->verify.now_unix = 1500;
    f->verify.chain_verify = chain_accept;
    f->verify.chain_ctx = chain_calls;
    return true;
}

static void fill_query(uint8_t out[16])
{
    for (size_t i = 0; i < 16; i++) out[i] = (uint8_t)(i + 1);
}

static int test_find_node_bound(void)
{
    int failures = 0;
    TEST("zcode dht msgs v2: FIND_NODE binds delegation and Noise transcript") {
        struct msg_fixture f; int chain_calls = 0; ASSERT(fixture_init(&f, &chain_calls));
        struct vcs_zcode_dht_msg_find_node m; memset(&m, 0, sizeof(m));
        m.session_generation = 9; memcpy(m.sender_node_id, f.node_id, 32);
        fill_query(m.query_id); m.delegation = f.delegation;
        fill(m.target_node_id, 32, 0x99);
        uint8_t wire[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES + 1]; size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, f.online_seed, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(len, VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES);
        struct vcs_zcode_dht_msg parsed;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.kind, VCS_ZCODE_DHT_MSG_FIND_NODE);
        ASSERT_EQ(parsed.find_node.session_generation, 9);
        ASSERT_EQ(chain_calls, 1);
        struct vcs_zcode_dht_msg_verify_context wrong = f.verify;
        wrong.noise_transcript_hash[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &wrong, &parsed),
                  VCS_ZCODE_DHT_ERR_SIGNATURE);
        wrong = f.verify; wrong.noise_established = false;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &wrong, &parsed),
                  VCS_ZCODE_DHT_ERR_SESSION);
        wrong = f.verify; wrong.session_generation++;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &wrong, &parsed),
                  VCS_ZCODE_DHT_ERR_SESSION);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nodes_hints(void)
{
    int failures = 0;
    TEST("zcode dht msgs v2: NODES carries only ordered untrusted hints") {
        struct msg_fixture f; int chain_calls = 0; ASSERT(fixture_init(&f, &chain_calls));
        struct vcs_zcode_dht_msg_nodes m; memset(&m, 0, sizeof(m));
        m.session_generation = 9; memcpy(m.sender_node_id, f.node_id, 32);
        fill_query(m.query_id); m.delegation = f.delegation; m.contact_count = 3;
        fill(m.node_ids[0], 32, 1); fill(m.node_ids[1], 32, 2);
        fill(m.node_ids[2], 32, 3);
        uint8_t wire[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES + 1]; size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &m, f.transcript, f.online_seed, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        struct vcs_zcode_dht_msg parsed;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.nodes.contact_count, 3);
        ASSERT(memcmp(parsed.nodes.node_ids[2], m.node_ids[2], 32) == 0);
        struct vcs_zcode_dht_msg_nodes bad = m;
        memcpy(bad.node_ids[1], bad.node_ids[0], 32);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &bad, f.transcript, f.online_seed,
                      wire, sizeof(wire), &len), VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        bad = m; memset(bad.node_ids[1], 0, 32);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &bad, f.transcript, f.online_seed,
                      wire, sizeof(wire), &len), VCS_ZCODE_DHT_ERR_ID_ZERO);
        PASS();
    } _test_next:;
    return failures;
}

static int test_rejections(void)
{
    int failures = 0;
    TEST("zcode dht msgs v2: tamper, truncation, key mismatch reject") {
        struct msg_fixture f; int chain_calls = 0; ASSERT(fixture_init(&f, &chain_calls));
        struct vcs_zcode_dht_msg_find_node m; memset(&m, 0, sizeof(m));
        m.session_generation = 9; memcpy(m.sender_node_id, f.node_id, 32);
        fill_query(m.query_id); m.delegation = f.delegation;
        fill(m.target_node_id, 32, 0x99);
        uint8_t wire[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES + 1]; size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, f.online_seed, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        struct vcs_zcode_dht_msg parsed;
        memset(&parsed, 0xa5, sizeof(parsed));
        int before_bounds = chain_calls;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len - 1, &f.verify, &parsed),
                  VCS_ZCODE_DHT_ERR_WIRE_SIZE);
        struct vcs_zcode_dht_msg zero;
        memset(&zero, 0, sizeof(zero));
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len + 1, &f.verify, &parsed),
                  VCS_ZCODE_DHT_ERR_WIRE_SIZE);
        ASSERT_EQ(chain_calls, before_bounds);
        wire[len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES - 1] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_ERR_SIGNATURE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        wire[len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES - 1] ^= 1;
        struct vcs_zcode_dht_msg_verify_context wrong = f.verify;
        wrong.remote_noise_static[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &wrong, &parsed),
                  VCS_ZCODE_DHT_ERR_DELEGATION);
        uint8_t wrong_seed[32]; fill(wrong_seed, 32, 0x23);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, wrong_seed, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_ERR_IDENTITY);
        PASS();
    } _test_next:;
    return failures;
}

static bool fixture_auth_record(struct msg_fixture *f,
                                struct vcs_zcode_dht_msg_records *message)
{
    memset(message, 0, sizeof(*message));
    message->session_generation = 9;
    memcpy(message->sender_node_id, f->node_id, 32);
    fill_query(message->query_id);
    message->delegation = f->delegation;
    message->selector.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(message->selector.namespace_name,
                   sizeof(message->selector.namespace_name), "science.study");
    fill(message->selector.root, 32, 0x61);
    message->record_count = 1;
    struct vcs_zcode_dht_record *record = &message->records[0];
    record->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                   "science.study");
    memcpy(record->network_genesis, f->verify.network_genesis, 32);
    fill(record->semantic_root, 32, 0x61);
    fill(record->transport_root, 32, 0x71);
    memcpy(record->provider_node_id, f->node_id, 32);
    record->sequence = 1;
    record->not_before = 1200;
    record->expiry = 1800;
    record->delegation = f->delegation;
    return vcs_zcode_dht_record_sign(record, f->online_seed) ==
           VCS_ZCODE_DHT_RECORD_OK;
}

static int test_record_frames(void)
{
    int failures = 0;
    TEST("zcode dht msgs v2: generic record lookup and store stay Noise-bound") {
        struct msg_fixture f;
        int chain_calls = 0;
        ASSERT(fixture_init(&f, &chain_calls));
        struct vcs_zcode_dht_msg_records records;
        ASSERT(fixture_auth_record(&f, &records));
        records.page_offset = 8;
        uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES + 1];
        size_t len = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &records, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        struct vcs_zcode_dht_msg parsed;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.kind, VCS_ZCODE_DHT_MSG_RECORDS);
        ASSERT_EQ(parsed.records.record_count, 1);
        ASSERT_EQ(parsed.records.page_offset, 8);
        ASSERT_EQ(parsed.records.next_offset, 0);
        ASSERT(memcmp(parsed.records.records[0].transport_root,
                      records.records[0].transport_root, 32) == 0);

        struct vcs_zcode_dht_msg_find_record find;
        memset(&find, 0, sizeof(find));
        find.session_generation = 9;
        memcpy(find.sender_node_id, f.node_id, 32);
        fill_query(find.query_id);
        find.delegation = f.delegation;
        find.selector = records.selector;
        find.page_offset = 8;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &find, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(len, VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.find_record.page_offset, 8);

        find.page_offset = 1;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &find, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        find.page_offset = 8;
        records.next_offset = 17;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &records, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        records.next_offset = 0;

        struct vcs_zcode_dht_msg_store_record store;
        memset(&store, 0, sizeof(store));
        store.session_generation = 9;
        memcpy(store.sender_node_id, f.node_id, 32);
        fill_query(store.query_id);
        store.delegation = f.delegation;
        store.record = records.records[0];
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &store, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.kind, VCS_ZCODE_DHT_MSG_STORE_RECORD);

        struct vcs_zcode_dht_msg_store_result result;
        memset(&result, 0, sizeof(result));
        result.session_generation = 9;
        memcpy(result.sender_node_id, f.node_id, 32);
        fill_query(result.query_id);
        result.delegation = f.delegation;
        result.status = VCS_ZCODE_DHT_STORE_STORED;
        fill(result.record_digest, 32, 0x91);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &result, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &f.verify, &parsed),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(parsed.store_result.status, VCS_ZCODE_DHT_STORE_STORED);

        records.selector.root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &records, f.transcript, f.online_seed, wire,
                      sizeof(wire), &len),
                  VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_dht_msgs(void)
{
    int failures = 0;
    failures += test_find_node_bound();
    failures += test_nodes_hints();
    failures += test_rejections();
    failures += test_record_frames();
    printf("=== zcode_dht_msgs: %d failures ===\n", failures);
    return failures;
}
