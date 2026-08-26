/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "base/hex.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_replication.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "support/cleanse.h"
#include "command/native_command.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_record_store.h"
#include "vcs/zcode_replication.h"
#include "vcs/zcode_sovereignty_policy.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct record_fixture {
  uint8_t online_seed[32];
  struct vcs_zcode_dht_record_verify_context verify;
  struct vcs_zcode_dht_delegation delegation;
  uint8_t node_id[32];
};

#ifdef ZCL_TESTING
struct replication_backend_fixture {
  struct vcs_zcode_dht_time now;
  uint64_t generation;
  size_t begin_calls, poll_calls, cancel_calls;
  size_t fail_begin_call, interrupt_poll_call;
  bool mismatch_second_generation;
  bool terminal;
  bool truncate_provider;
};

static struct vcs_zcode_dht_time replication_fake_now(void *ctx)
{
  return ((struct replication_backend_fixture *)ctx)->now;
}

static bool replication_fake_begin(
    void *ctx, const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id,
    uint64_t *generation)
{
  struct replication_backend_fixture *fixture = ctx;
  (void)selector;
  (void)now;
  fixture->begin_calls++;
  if (fixture->fail_begin_call == fixture->begin_calls)
    return false;
  *operation_id = fixture->begin_calls;
  *generation = fixture->generation +
      (fixture->mismatch_second_generation && fixture->begin_calls == 2);
  return true;
}

static bool replication_fake_poll(
    void *ctx, uint64_t operation_id, uint64_t generation,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_discovery_result *out)
{
  struct replication_backend_fixture *fixture = ctx;
  (void)generation;
  (void)now;
  fixture->poll_calls++;
  if (fixture->interrupt_poll_call == fixture->poll_calls)
    return false;
  memset(out, 0, sizeof(*out));
  out->state = fixture->terminal
                   ? VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE
                   : VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
  out->nodes_queried = 1;
  out->truncated = fixture->truncate_provider && operation_id % 2 == 1;
  return true;
}

static bool replication_fake_cancel(void *ctx, uint64_t operation_id,
                                    uint64_t generation)
{
  struct replication_backend_fixture *fixture = ctx;
  (void)operation_id;
  (void)generation;
  fixture->cancel_calls++;
  return true;
}

static void replication_backend_install(
    struct replication_backend_fixture *fixture)
{
  struct boot_zcode_dht_replication_test_backend backend = {
      .ctx = fixture,
      .now = replication_fake_now,
      .begin = replication_fake_begin,
      .poll = replication_fake_poll,
      .cancel = replication_fake_cancel,
  };
  boot_zcode_dht_replication_test_set_backend(&backend);
}

static bool replication_rpc(const struct rpc_table *table, const char *method,
                            const struct json_value *input,
                            struct json_value *result)
{
  const struct rpc_command *command = rpc_table_find(table, method);
  if (!command || !command->actor)
    return false;
  struct json_value params;
  json_init(&params);
  json_set_array(&params);
  json_push_back(&params, input);
  json_init(result);
  bool ok = command->actor(&params, false, result);
  json_free(&params);
  return ok;
}

static void replication_capability_input(
    struct json_value *input, const char *lookup, const char *owner)
{
  json_set_object(input);
  json_push_kv_str(input, "lookup_id", lookup);
  json_push_kv_str(input, "owner_token", owner);
}

static bool replication_json_bool(const struct json_value *doc,
                                  const char *key, bool fallback)
{
  const struct json_value *value = json_get(doc, key);
  return value && value->type == JSON_BOOL ? json_get_bool(value) : fallback;
}
#endif

static void rf_fill(uint8_t *out, size_t n, uint8_t value)
{
  memset(out, value, n);
}

static bool rf_chain_accept(void *ctx,
                            const struct vcs_zcode_dht_delegation *delegation)
{
  int *calls = ctx;
  (*calls)++;
  return delegation->beacon_height == 120;
}

static bool rf_init_values(struct record_fixture *f, int *chain_calls,
                           uint8_t online_value, uint8_t master_value)
{
  memset(f, 0, sizeof(*f));
  uint8_t online_pub[32], online_secret[32], noise[32], beacon[32], master[32];
  rf_fill(f->online_seed, 32, online_value);
  ed25519_keypair(online_pub, online_secret, f->online_seed);
  memory_cleanse(online_secret, sizeof(online_secret));
  rf_fill(f->verify.network_genesis, 32, 0x01);
  rf_fill(noise, 32, 0x33);
  rf_fill(beacon, 32, 0x44);
  rf_fill(master, 32, master_value);
  f->verify.now_unix = 1500;
  f->verify.chain_verify = rf_chain_accept;
  f->verify.chain_ctx = chain_calls;
  if (vcs_zcode_dht_delegation_sign(
          &f->delegation, f->verify.network_genesis, online_pub, noise, 120,
          beacon, 1000, 3000, 7, master) != VCS_ZCODE_DHT_DELEGATION_OK)
    return false;
  return vcs_zcode_dht_delegation_node_id(f->node_id, &f->delegation);
}

static bool rf_init(struct record_fixture *f, int *chain_calls)
{
  return rf_init_values(f, chain_calls, 0x22, 0x55);
}

static void rf_record(struct record_fixture *f,
                      struct vcs_zcode_dht_record *record,
                      enum vcs_zcode_dht_record_kind kind)
{
  memset(record, 0, sizeof(*record));
  record->kind = kind;
  (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                 "science.study");
  memcpy(record->network_genesis, f->verify.network_genesis, 32);
  rf_fill(record->transport_root, 32, 0x71);
  memcpy(record->provider_node_id, f->node_id, 32);
  record->sequence = 11;
  record->not_before = 1200;
  record->expiry = 1800;
  record->delegation = f->delegation;
  if (kind == VCS_ZCODE_DHT_RECORD_POINTER ||
      kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK)
    rf_fill(record->semantic_root, 32, 0x61);
  if (kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
      kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK)
    rf_fill(record->owner_group, 32, 0x81);
}

static int test_record_roundtrip(void)
{
  int failures = 0;
  TEST("zcode dht record: all signed kinds round-trip canonically") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    for (int kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
         kind <= VCS_ZCODE_DHT_RECORD_AGENT_SCOPE; kind++) {
      struct vcs_zcode_dht_record record, parsed;
      rf_record(&f, &record, (enum vcs_zcode_dht_record_kind)kind);
      ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
                VCS_ZCODE_DHT_RECORD_OK);
      uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
      ASSERT_EQ(vcs_zcode_dht_record_encode(&record, wire),
                VCS_ZCODE_DHT_RECORD_OK);
      uint8_t record_id[32];
      ASSERT_EQ(vcs_zcode_dht_record_id(&record, record_id),
                VCS_ZCODE_DHT_RECORD_OK);
      if (kind == VCS_ZCODE_DHT_RECORD_PROVIDER) {
        uint8_t digest[32];
        char digest_hex[65], record_id_hex[65];
        char wire_hex[VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u + 1u];
        sha3_256(wire, sizeof(wire), digest);
        zcl_hex_encode(digest, sizeof(digest), digest_hex);
        zcl_hex_encode(record_id, sizeof(record_id), record_id_hex);
        zcl_hex_encode(wire, sizeof(wire), wire_hex);
        ASSERT(strcmp(digest_hex,
                      "284d3f369bf3dd2644e4843f310b8bba1c4f64a4d081269f"
                      "5460dee197092839") == 0);
        ASSERT(strcmp(record_id_hex,
                      "0dbad9e66c96e559946a778971bedd006da2dbfc896d58cd"
                      "18bb17403679dff2") == 0);
        struct json_value publication;
        json_init(&publication);
        boot_zcode_dht_publication_record_test_render(&publication, &record);
        ASSERT(strcmp(json_get_str(json_get(&publication, "record_root")),
                      record_id_hex) == 0);
        const char *published_wire =
            json_get_str(json_get(&publication, "record_wire"));
        ASSERT(published_wire != NULL);
        ASSERT(strlen(published_wire) == VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u);
        ASSERT(strcmp(published_wire, wire_hex) == 0);
        json_free(&publication);
      }
      ASSERT_EQ(vcs_zcode_dht_record_parse(wire, sizeof(wire), &f.verify,
                                           &parsed),
                VCS_ZCODE_DHT_RECORD_OK);
      uint8_t parsed_id[32];
      ASSERT_EQ(vcs_zcode_dht_record_id(&parsed, parsed_id),
                VCS_ZCODE_DHT_RECORD_OK);
      ASSERT(memcmp(parsed_id, record_id, sizeof(parsed_id)) == 0);
      ASSERT_EQ((int)parsed.kind, kind);
      ASSERT_EQ(parsed.sequence, 11);
      ASSERT(memcmp(parsed.provider_node_id, f.node_id, 32) == 0);
      ASSERT(strcmp(parsed.namespace_name, "science.study") == 0);
    }
    ASSERT_EQ(chain_calls, 5);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_key(void)
{
  int failures = 0;
  TEST("zcode dht record: routing key is canonical and domain separated") {
    uint8_t network[32], root[32], key[32], same[32], changed[32];
    char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES] = {0};
    rf_fill(network, sizeof(network), 0x11);
    rf_fill(root, sizeof(root), 0x22);
    (void)snprintf(namespace_name, sizeof(namespace_name), "science.study");
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, key));
    char key_hex[65];
    zcl_hex_encode(key, sizeof(key), key_hex);
    ASSERT(strcmp(key_hex,
                  "424fffbf7112bf08bb46a275889a09c0252b33e146f2d4f"
                  "cb00cc62290f48aa1") == 0);
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, same));
    ASSERT(memcmp(key, same, sizeof(key)) == 0);

    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_POINTER, namespace_name, root, changed));
    ASSERT(memcmp(key, changed, sizeof(key)) != 0);
    memcpy(same, changed, sizeof(same));
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK,
        namespace_name, root, changed));
    ASSERT(memcmp(key, changed, sizeof(key)) != 0);
    ASSERT(memcmp(same, changed, sizeof(same)) != 0);
    namespace_name[0] = 'x';
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, changed));
    ASSERT(memcmp(key, changed, sizeof(key)) != 0);
    namespace_name[0] = 's';
    network[0] ^= 1;
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, changed));
    ASSERT(memcmp(key, changed, sizeof(key)) != 0);
    network[0] ^= 1;
    root[0] ^= 1;
    ASSERT(vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, changed));
    ASSERT(memcmp(key, changed, sizeof(key)) != 0);

    memset(root, 0, sizeof(root));
    ASSERT(!vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, changed));
    namespace_name[0] = 'S';
    root[0] = 1;
    ASSERT(!vcs_zcode_dht_record_key(
        network, VCS_ZCODE_DHT_RECORD_PROVIDER, namespace_name, root, changed));
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_shape_and_windows(void)
{
  int failures = 0;
  TEST("zcode dht record: canonical roots, namespace and windows fail closed") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record record;
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_PROVIDER);
    record.semantic_root[0] = 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_ROOT);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_POINTER);
    memset(record.semantic_root, 0, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_ROOT);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_STORAGE_ACK);
    memset(record.owner_group, 0, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OWNER_GROUP);
    rf_record(&f, &record,
              VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK);
    memset(record.semantic_root, 0, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_ROOT);
    rf_record(&f, &record,
              VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK);
    memset(record.owner_group, 0, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OWNER_GROUP);
    rf_record(&f, &record,
              VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_PROVIDER);
    (void)snprintf(record.namespace_name, sizeof(record.namespace_name),
                   "Science.Bad");
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_NAMESPACE);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_PROVIDER);
    record.expiry = record.not_before + VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS + 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_WINDOW);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_PROVIDER);
    record.sequence = (uint64_t)INT64_MAX;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    record.sequence = (uint64_t)INT64_MAX + 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_SEQUENCE);
    /* A scope grant addresses exactly one key: any semantic or owner
     * content rides out of band, and its window is bounded like a
     * pointer's. */
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_AGENT_SCOPE);
    record.semantic_root[0] = 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_ROOT);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_AGENT_SCOPE);
    record.owner_group[0] = 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OWNER_GROUP);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_AGENT_SCOPE);
    record.expiry = record.not_before + VCS_ZCODE_DHT_AGENT_SCOPE_MAX_SECONDS + 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_WINDOW);
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_AGENT_SCOPE);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_adversarial(void)
{
  int failures = 0;
  TEST("zcode dht record: bounds, tamper, network and signer reject to zero") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record record;
    rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_POINTER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES + 1];
    ASSERT_EQ(vcs_zcode_dht_record_encode(&record, wire),
              VCS_ZCODE_DHT_RECORD_OK);
    struct vcs_zcode_dht_record parsed, zero;
    memset(&zero, 0, sizeof(zero));
    memset(&parsed, 0xa5, sizeof(parsed));
    ASSERT_EQ(vcs_zcode_dht_record_parse(wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES - 1,
                                         &f.verify, &parsed),
              VCS_ZCODE_DHT_RECORD_SIZE);
    ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
    ASSERT_EQ(chain_calls, 0);
    wire[80] ^= 1;
    ASSERT_EQ(vcs_zcode_dht_record_parse(wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                                         &f.verify, &parsed),
              VCS_ZCODE_DHT_RECORD_SIGNATURE);
    ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
    wire[80] ^= 1;
    struct vcs_zcode_dht_record_verify_context wrong = f.verify;
    wrong.network_genesis[0] ^= 1;
    ASSERT_EQ(vcs_zcode_dht_record_parse(wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                                         &wrong, &parsed),
              VCS_ZCODE_DHT_RECORD_NETWORK);
    uint8_t wrong_seed[32];
    rf_fill(wrong_seed, 32, 0x23);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&record, wrong_seed),
              VCS_ZCODE_DHT_RECORD_SIGNER);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_conflicts(void)
{
  int failures = 0;
  TEST("zcode dht record: conflicting valid pointer slots are preserved") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record a, b;
    rf_record(&f, &a, VCS_ZCODE_DHT_RECORD_POINTER);
    b = a;
    b.transport_root[0] ^= 1;
    ASSERT(vcs_zcode_dht_record_conflicts(&a, &b));
    b = a;
    b.sequence++;
    ASSERT(!vcs_zcode_dht_record_conflicts(&a, &b));
    b = a;
    b.semantic_root[0] ^= 1;
    ASSERT(!vcs_zcode_dht_record_conflicts(&a, &b));
    ASSERT(!vcs_zcode_dht_record_conflicts(&a, &a));

    struct vcs_zcode_dht_record streams[3];
    rf_record(&f, &streams[0], VCS_ZCODE_DHT_RECORD_POINTER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&streams[0], f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    streams[1] = streams[0];
    streams[1].sequence++;
    streams[1].transport_root[0] ^= 2;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&streams[1], f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    struct record_fixture attacker;
    int attacker_calls = 0;
    ASSERT(rf_init_values(&attacker, &attacker_calls, 0x52, 0x75));
    rf_record(&attacker, &streams[2], VCS_ZCODE_DHT_RECORD_POINTER);
    memcpy(streams[2].semantic_root, streams[0].semantic_root, 32);
    streams[2].sequence = (uint64_t)INT64_MAX;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&streams[2], attacker.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    ASSERT(vcs_zcode_dht_record_same_stream(&streams[0], &streams[1]));
    ASSERT(!vcs_zcode_dht_record_same_stream(&streams[1], &streams[2]));
    ASSERT(vcs_zcode_dht_record_superseded_at(streams, 3, 0));
    ASSERT(!vcs_zcode_dht_record_superseded_at(streams, 3, 1));
    ASSERT(!vcs_zcode_dht_record_superseded_at(streams, 3, 2));
    PASS();
  }
  _test_next:;
  return failures;
}

static void rf_cleanup_store(const char *datadir)
{
  char path[512];
  (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                 VCS_ZCODE_DHT_RECORD_STORE_FILE);
  (void)unlink(path);
  (void)snprintf(path, sizeof(path), "%s/zcode/dht", datadir);
  (void)rmdir(path);
  (void)snprintf(path, sizeof(path), "%s/zcode", datadir);
  (void)rmdir(path);
  (void)rmdir(datadir);
}

static int test_record_store_restart(void)
{
  int failures = 0;
  TEST("zcode dht records: conflicts persist canonically across cold restart") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record a, b;
    rf_record(&f, &a, VCS_ZCODE_DHT_RECORD_POINTER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&a, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    b = a;
    b.transport_root[0] ^= 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&b, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    struct vcs_zcode_dht_record_store *before =
        vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    struct vcs_zcode_dht_record_store *after =
        vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    ASSERT(before != NULL && after != NULL);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(before, &a, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(before, &a, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(before, &b, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_CONFLICT);
    ASSERT_EQ(vcs_zcode_dht_record_store_count(before), 2);

    char datadir[] = "test-tmp/zcode_dht_records_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    char error[160] = {0};
    ASSERT_EQ(vcs_zcode_dht_record_store_save(before, datadir, error,
                                               sizeof(error)),
              VCS_ZCODE_DHT_RECORD_STORE_OK);
    ASSERT_EQ(vcs_zcode_dht_record_store_load(after, datadir, &f.verify,
                                               error, sizeof(error)),
              VCS_ZCODE_DHT_RECORD_STORE_OK);
    ASSERT_EQ(vcs_zcode_dht_record_store_count(after), 2);
    uint8_t before_digest[32], after_digest[32];
    vcs_zcode_dht_record_store_digest(before, before_digest);
    vcs_zcode_dht_record_store_digest(after, after_digest);
    ASSERT(memcmp(before_digest, after_digest, 32) == 0);
    struct vcs_zcode_dht_record found[2];
    ASSERT_EQ(vcs_zcode_dht_record_store_query(
                  after, VCS_ZCODE_DHT_RECORD_POINTER, "science.study",
                  a.semantic_root, 1500, found, 2),
              2);
    ASSERT(vcs_zcode_dht_record_conflicts(&found[0], &found[1]));
    ASSERT_EQ(vcs_zcode_dht_record_store_query(
                  before, VCS_ZCODE_DHT_RECORD_POINTER, "science.study",
                  a.semantic_root, 1800, found, 2),
              0);

    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                   VCS_ZCODE_DHT_RECORD_STORE_FILE);
    struct stat st;
    ASSERT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    ASSERT(fd >= 0);
    uint8_t byte = 0;
    ASSERT(pread(fd, &byte, 1, VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES + 20) ==
           1);
    byte ^= 1;
    ASSERT(pwrite(fd, &byte, 1,
                  VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES + 20) == 1);
    ASSERT(close(fd) == 0);
    ASSERT_EQ(vcs_zcode_dht_record_store_load(after, datadir, &f.verify,
                                               error, sizeof(error)),
              VCS_ZCODE_DHT_RECORD_STORE_CORRUPT);
    ASSERT_EQ(vcs_zcode_dht_record_store_count(after), 2);
    ASSERT_EQ(vcs_zcode_dht_record_store_save(before, datadir, error,
                                               sizeof(error)),
              VCS_ZCODE_DHT_RECORD_STORE_OK);
    struct vcs_zcode_dht_record_verify_context expired_verify = f.verify;
    expired_verify.now_unix = 1800;
    ASSERT_EQ(vcs_zcode_dht_record_store_load(after, datadir, &expired_verify,
                                               error, sizeof(error)),
              VCS_ZCODE_DHT_RECORD_STORE_OK);
    ASSERT_EQ(vcs_zcode_dht_record_store_count(after), 0);
    vcs_zcode_dht_record_store_free(after);
    vcs_zcode_dht_record_store_free(before);
    rf_cleanup_store(datadir);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_store_caps(void)
{
  int failures = 0;
  TEST("zcode dht records: root, provider and conflict caps are exact") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record_store *store =
        vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    ASSERT(store != NULL);
    struct vcs_zcode_dht_record record;
    for (size_t i = 0; i <= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT; i++) {
      rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_POINTER);
      (void)snprintf(record.namespace_name, sizeof(record.namespace_name),
                     "science.root.%zu", i);
      record.transport_root[0] = (uint8_t)(i + 1);
      ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
                VCS_ZCODE_DHT_RECORD_OK);
      enum vcs_zcode_dht_record_store_result result =
          vcs_zcode_dht_record_store_put(store, &record, 1500);
      ASSERT_EQ(result, i < VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT
                            ? VCS_ZCODE_DHT_RECORD_STORE_ADDED
                            : VCS_ZCODE_DHT_RECORD_STORE_ROOT_CAP);
    }
    vcs_zcode_dht_record_store_free(store);

    store = vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    ASSERT(store != NULL);
    for (size_t i = 0; i <= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_PROVIDER; i++) {
      rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_PROVIDER);
      record.transport_root[0] = (uint8_t)(i & 0xffu);
      record.transport_root[1] = (uint8_t)(i >> 8);
      ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
                VCS_ZCODE_DHT_RECORD_OK);
      enum vcs_zcode_dht_record_store_result result =
          vcs_zcode_dht_record_store_put(store, &record, 1500);
      ASSERT_EQ(result, i < VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_PROVIDER
                            ? VCS_ZCODE_DHT_RECORD_STORE_ADDED
                            : VCS_ZCODE_DHT_RECORD_STORE_PROVIDER_CAP);
    }
    vcs_zcode_dht_record_store_free(store);

    store = vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    ASSERT(store != NULL);
    for (size_t i = 0; i <= VCS_ZCODE_DHT_RECORD_STORE_MAX_CONFLICTS; i++) {
      rf_record(&f, &record, VCS_ZCODE_DHT_RECORD_POINTER);
      record.transport_root[0] = (uint8_t)(i + 1);
      ASSERT_EQ(vcs_zcode_dht_record_sign(&record, f.online_seed),
                VCS_ZCODE_DHT_RECORD_OK);
      enum vcs_zcode_dht_record_store_result result =
          vcs_zcode_dht_record_store_put(store, &record, 1500);
      ASSERT_EQ(result, i == 0
                            ? VCS_ZCODE_DHT_RECORD_STORE_ADDED
                            : i < VCS_ZCODE_DHT_RECORD_STORE_MAX_CONFLICTS
                                  ? VCS_ZCODE_DHT_RECORD_STORE_CONFLICT
                                  : VCS_ZCODE_DHT_RECORD_STORE_CONFLICT_CAP);
    }
    vcs_zcode_dht_record_store_free(store);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_record_store_sequence_and_expiry(void)
{
  int failures = 0;
  TEST("zcode dht records: sequence replay and expiry fail closed") {
    struct record_fixture f;
    int chain_calls = 0;
    ASSERT(rf_init(&f, &chain_calls));
    struct vcs_zcode_dht_record current, stale, next;
    rf_record(&f, &current, VCS_ZCODE_DHT_RECORD_PROVIDER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&current, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    stale = current;
    stale.sequence--;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&stale, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    next = current;
    next.sequence++;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&next, f.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    struct vcs_zcode_dht_record_store *store =
        vcs_zcode_dht_record_store_create(f.verify.network_genesis);
    ASSERT(store != NULL);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(store, &current, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(store, &stale, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_STALE);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(store, &next, 1500),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_record_store_count(store), 1);
    ASSERT_EQ(vcs_zcode_dht_record_store_put(store, &current, 1800),
              VCS_ZCODE_DHT_RECORD_STORE_EXPIRED);
    vcs_zcode_dht_record_store_free(store);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_declared_replication(void)
{
  int failures = 0;
  TEST("zcode replication: durable means five live ACKs in three declared groups") {
    struct vcs_zcode_dht_record records[10];
    memset(records, 0, sizeof(records));
    uint8_t root[32];
    memset(root, 0x91, sizeof(root));
    for (size_t i = 0; i < 6; i++) {
      records[i].kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
      snprintf(records[i].namespace_name, sizeof(records[i].namespace_name),
               "science");
      memcpy(records[i].transport_root, root, 32);
      memset(records[i].provider_node_id, (int)(i + 1), 32);
      memset(records[i].owner_group, (int)(0xa0 + i % 3), 32);
      records[i].not_before = 1000;
      records[i].expiry = 1600;
    }
    records[6] = records[0]; /* same signer cannot inflate the count */
    records[7] = records[1];
    records[7].provider_node_id[0] = 0x80;
    records[7].expiry = 1400;
    for (size_t i = 8; i < 10; i++) {
      records[i] = records[0];
      records[i].kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
      memset(records[i].provider_node_id, (int)i, 32);
    }
    struct vcs_zcode_replication_status status;
    vcs_zcode_replication_evaluate(records, 10, "science", root, 1500,
                                   &status);
    ASSERT_EQ(status.provider_hints, 2);
    ASSERT_EQ(status.valid_acks, 6);
    ASSERT_EQ(status.declared_owner_groups, 3);
    ASSERT_EQ(status.expired_acks, 1);
    ASSERT(status.partial);
    ASSERT(status.local_cache_only);
    ASSERT(!status.durable);
    uint8_t authenticated[2][32];
    memcpy(authenticated[0], records[8].provider_node_id, 32);
    memcpy(authenticated[1], records[9].provider_node_id, 32);
    struct vcs_zcode_replication_evidence evidence = {
        .records = records,
        .count = 10,
        .authenticated_node_ids = authenticated,
        .authenticated_count = 2,
        .local_possession_current = true,
        .provider_evidence_complete = true,
        .ack_evidence_complete = true,
    };
    memcpy(evidence.local_node_id, records[0].provider_node_id, 32);
    vcs_zcode_replication_evaluate_evidence(
        &evidence, "science", root, 1500, &status);
    ASSERT_EQ(status.authenticated_providers, 2);
    ASSERT_EQ(status.locally_revalidated_acks, 1);
    ASSERT(!status.partial);
    ASSERT(!status.local_cache_only);
    ASSERT(status.durable);
    vcs_zcode_replication_evaluate(records, 10, "science", root, 1600,
                                   &status);
    ASSERT(!status.durable);
    ASSERT_EQ(status.valid_acks, 0);

    struct record_fixture fixture;
    int chain_calls = 0;
    struct vcs_zcode_dht_record conflict[2];
    ASSERT(rf_init(&fixture, &chain_calls));
    rf_record(&fixture, &conflict[0], VCS_ZCODE_DHT_RECORD_STORAGE_ACK);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&conflict[0], fixture.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    conflict[1] = conflict[0];
    conflict[1].owner_group[0] ^= 1;
    ASSERT_EQ(vcs_zcode_dht_record_sign(&conflict[1], fixture.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    evidence.records = conflict;
    evidence.count = 2;
    evidence.authenticated_node_ids = NULL;
    evidence.authenticated_count = 0;
    memcpy(evidence.local_node_id, fixture.node_id, 32);
    vcs_zcode_replication_evaluate_evidence(
        &evidence, "science.study", conflict[0].transport_root, 1500,
        &status);
    ASSERT_EQ(status.conflicted_records, 2);
    ASSERT_EQ(status.valid_acks, 0);
    ASSERT(!status.durable);

    /* Sequence is monotonic only inside one signed stream. An expired newer
     * claim supersedes that stream's older live ACK; it must not resurrect an
     * obsolete owner group and manufacture a durable verdict. */
    struct vcs_zcode_dht_record supersession[6];
    memset(supersession, 0, sizeof(supersession));
    for (size_t i = 0; i < 5; i++) {
      supersession[i].kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
      (void)snprintf(supersession[i].namespace_name,
                     sizeof(supersession[i].namespace_name), "science");
      memcpy(supersession[i].transport_root, root, 32);
      memset(supersession[i].provider_node_id, (int)(0x31 + i), 32);
      memset(supersession[i].owner_group,
             i == 0 ? 0xa1 : (i < 3 ? 0xb2 : 0xc3), 32);
      supersession[i].sequence = 1;
      supersession[i].not_before = 1000;
      supersession[i].expiry = 1600;
    }
    supersession[5] = supersession[0];
    supersession[5].sequence = 2;
    supersession[5].expiry = 1400;
    memset(supersession[5].owner_group, 0xb2, 32);
    evidence.records = supersession;
    evidence.count = 6;
    evidence.local_possession_current = false;
    memset(evidence.local_node_id, 0, sizeof(evidence.local_node_id));
    vcs_zcode_replication_evaluate_evidence(
        &evidence, "science", root, 1500, &status);
    ASSERT_EQ(status.valid_acks, 4);
    ASSERT_EQ(status.expired_acks, 1);
    ASSERT_EQ(status.declared_owner_groups, 2);
    ASSERT(!status.durable);
    PASS();
  }
  _test_next:;
  return failures;
}

#ifdef ZCL_TESTING
static int test_science_pointer_ranking(void)
{
  int failures = 0;
  TEST("zcode pointer ranking: high sequences and Sybil rows do not crowd roots") {
    struct zcl_science_pointer_test_observation observations[
        VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
    memset(observations, 0, sizeof(observations));
    for (size_t i = 0; i < 8; i++) {
      memset(observations[i].transport_root, 0x01, 32);
      memset(observations[i].publisher_zid, (int)(0x10 + i), 32);
      memset(observations[i].provider_node_id, (int)(0x20 + i), 32);
      observations[i].sequence = (uint64_t)INT64_MAX - i;
    }
    for (size_t i = 8; i < 62; i++) {
      memset(observations[i].transport_root, (int)i, 32);
      memset(observations[i].publisher_zid, (int)i, 32);
      memset(observations[i].provider_node_id, (int)i, 32);
      observations[i].sequence = (uint64_t)INT64_MAX;
      observations[i].conflicted = true;
    }
    memset(observations[62].transport_root, 0xf0, 32);
    memset(observations[62].publisher_zid, 0xa1, 32);
    memset(observations[62].provider_node_id, 0xa2, 32);
    observations[62].sequence = 1;
    observations[62].provider_authenticated = true;
    memset(observations[63].transport_root, 0x02, 32);
    memset(observations[63].publisher_zid, 0xb1, 32);
    memset(observations[63].provider_node_id, 0xb2, 32);
    observations[63].sequence = 1;
    uint32_t order[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
    uint32_t conflicts = 0, superseded = 0;
    ASSERT_EQ(zcl_native_zcode_science_test_rank_pointers(
                  observations,
                  VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS, order,
                  VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS, &conflicts,
                  &superseded),
              10);
    ASSERT_EQ(conflicts, 54);
    ASSERT_EQ(superseded, 0);
    ASSERT_EQ(order[0], 62);
    ASSERT(order[1] < 8);
    ASSERT_EQ(order[2], 63);
    for (size_t i = 3; i < 10; i++)
      ASSERT(order[i] < 8);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_record_projection_fields(void)
{
  int failures = 0;
  TEST("zcode record projection: conflicts and supersession stay explicit") {
    struct record_fixture fixture;
    int chain_calls = 0;
    ASSERT(rf_init(&fixture, &chain_calls));
    struct vcs_zcode_dht_record_discovery_result discovery;
    memset(&discovery, 0, sizeof(discovery));
    discovery.state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    discovery.record_count = 5;
    rf_record(&fixture, &discovery.records[0],
              VCS_ZCODE_DHT_RECORD_POINTER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[0],
                                        fixture.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    discovery.records[1] = discovery.records[0];
    discovery.records[1].sequence = 12;
    discovery.records[1].expiry = 1900;
    memset(discovery.records[1].transport_root, 0x72, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[1],
                                        fixture.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    discovery.records[2] = discovery.records[1];
    memset(discovery.records[2].transport_root, 0x73, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[2],
                                        fixture.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    struct record_fixture independent;
    int independent_calls = 0;
    ASSERT(rf_init_values(&independent, &independent_calls, 0x42, 0x45));
    rf_record(&independent, &discovery.records[3],
              VCS_ZCODE_DHT_RECORD_POINTER);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[3],
                                        independent.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    discovery.records[4] = discovery.records[3];
    discovery.records[4].sequence++;
    discovery.records[4].expiry = 1900;
    memset(discovery.records[4].transport_root, 0x75, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[4],
                                        independent.online_seed),
              VCS_ZCODE_DHT_RECORD_OK);
    struct json_value rendered;
    json_init(&rendered);
    boot_zcode_dht_record_test_render(&rendered, &discovery, false);
    ASSERT_EQ(json_get_int(json_get(&rendered, "usable_count")), 2);
    ASSERT_EQ(json_get_int(json_get(&rendered, "evidence_wire_count")), 0);
    ASSERT_EQ(json_get_int(json_get(&rendered, "superseded_count")), 1);
    ASSERT_EQ(json_get_int(json_get(&rendered, "conflict_count")), 2);
    const struct json_value *rows = json_get(&rendered, "records");
    ASSERT(rows != NULL);
    ASSERT_EQ(json_size(rows), 5);
    uint8_t first_root[32];
    char first_root_hex[65];
    ASSERT_EQ(vcs_zcode_dht_record_id(&discovery.records[0], first_root),
              VCS_ZCODE_DHT_RECORD_OK);
    zcl_hex_encode(first_root, sizeof(first_root), first_root_hex);
    ASSERT(strcmp(json_get_str(json_get(json_at(rows, 0), "record_root")),
                  first_root_hex) == 0);
    ASSERT(!json_get_bool_or(json_at(rows, 0), "superseded", false));
    ASSERT(!json_get_bool_or(json_at(rows, 0), "conflicted", false));
    ASSERT(json_get(json_at(rows, 0), "record_wire") == NULL);
    ASSERT(json_get_bool_or(json_at(rows, 1), "conflicted", false));
    ASSERT(json_get_bool_or(json_at(rows, 2), "conflicted", false));
    ASSERT(!json_get_bool_or(json_at(rows, 1),
                             "provider_authenticated", true));
    ASSERT(json_get(json_at(rows, 1), "publisher_authenticated") == NULL);
    ASSERT(json_get_bool_or(json_at(rows, 3), "superseded", false));
    ASSERT(!json_get_bool_or(json_at(rows, 4), "superseded", false));
    json_free(&rendered);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_record_projection_evidence_wires(void)
{
  int failures = 0;
  TEST("zcode record projection: usable ACK evidence is bounded and diverse") {
    struct record_fixture fixtures[3];
    int chain_calls[3] = {0};
    ASSERT(rf_init_values(&fixtures[0], &chain_calls[0], 0x22, 0x55));
    ASSERT(rf_init_values(&fixtures[1], &chain_calls[1], 0x23, 0x56));
    ASSERT(rf_init_values(&fixtures[2], &chain_calls[2], 0x24, 0x57));
    struct vcs_zcode_dht_record_discovery_result discovery;
    memset(&discovery, 0, sizeof(discovery));
    discovery.state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    discovery.record_count = 3;
    for (size_t i = 0; i < discovery.record_count; i++) {
      rf_record(&fixtures[i], &discovery.records[i],
                VCS_ZCODE_DHT_RECORD_STORAGE_ACK);
      memset(discovery.records[i].owner_group, (int)(0x81 + i), 32);
      ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[i],
                                          fixtures[i].online_seed),
                VCS_ZCODE_DHT_RECORD_OK);
    }
    /* A distinct signer declaring the first group remains visible, but its
     * wire is omitted from the bounded handoff because it adds no diversity. */
    memset(discovery.records[2].owner_group, 0x81, 32);
    ASSERT_EQ(vcs_zcode_dht_record_sign(&discovery.records[2],
                                        fixtures[2].online_seed),
              VCS_ZCODE_DHT_RECORD_OK);

    struct json_value rendered;
    json_init(&rendered);
    boot_zcode_dht_record_test_render(&rendered, &discovery, true);
    ASSERT_EQ(json_get_int(json_get(&rendered, "usable_count")), 3);
    ASSERT_EQ(json_get_int(json_get(&rendered, "evidence_wire_count")), 2);
    const struct json_value *rows = json_get(&rendered, "records");
    ASSERT(rows != NULL);
    ASSERT_EQ(json_size(rows), 3);
    for (size_t i = 0; i < 2; i++) {
      const char *wire_hex = json_get_str(json_get(json_at(rows, i),
                                                   "record_wire"));
      uint8_t rendered_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
      uint8_t expected_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
      ASSERT(wire_hex != NULL);
      ASSERT_EQ(strlen(wire_hex), sizeof(rendered_wire) * 2u);
      ASSERT(zcl_hex_decode_lower(wire_hex, rendered_wire,
                                  sizeof(rendered_wire)));
      ASSERT_EQ(vcs_zcode_dht_record_encode(&discovery.records[i],
                                             expected_wire),
                VCS_ZCODE_DHT_RECORD_OK);
      ASSERT(memcmp(rendered_wire, expected_wire,
                    sizeof(rendered_wire)) == 0);
    }
    ASSERT(json_get(json_at(rows, 2), "record_wire") == NULL);
    json_free(&rendered);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_science_pointer_candidate_policy(void)
{
  int failures = 0;
  TEST("zcode pointer policy: one denied publisher does not deny another") {
    char datadir[] = "/tmp/zcl_pointer_policy_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    struct record_fixture fixture;
    int chain_calls = 0;
    ASSERT(rf_init(&fixture, &chain_calls));
    uint8_t online_pub[32], online_secret[32], noise[32], beacon[32];
    uint8_t master_seed[32];
    ed25519_keypair(online_pub, online_secret, fixture.online_seed);
    memory_cleanse(online_secret, sizeof(online_secret));
    memset(noise, 0x33, 32);
    memset(beacon, 0x44, 32);
    memset(master_seed, 0x55, 32);
    uint64_t wall = (uint64_t)platform_time_wall_unix();
    ASSERT_EQ(vcs_zcode_dht_delegation_sign(
                  &fixture.delegation, fixture.verify.network_genesis,
                  online_pub, noise, 120, beacon, wall - 1, wall + 90000,
                  8, master_seed),
              VCS_ZCODE_DHT_DELEGATION_OK);
    char error[192] = {0};
    ASSERT(vcs_zcode_dht_delegation_save(datadir, &fixture.delegation,
                                         error, sizeof(error)));
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(fixture.verify.network_genesis);
    ASSERT(policy != NULL);
    struct vcs_zcode_sovereignty_rule block;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID,
                  (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_FETCH) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_STORE) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_INDEX)),
                  fixture.delegation.doc.master_pubkey),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    uint8_t service_type[32] = {0};
    memcpy(service_type, "science", 7);
    struct vcs_zcode_sovereignty_rule allow;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &allow, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_ALLOW,
                  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
                  (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_FETCH) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_STORE) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_INDEX)),
                  service_type),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &allow),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(policy, datadir, error,
                                                sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    uint8_t semantic[32], transport[32], permitted_publisher[32];
    memset(semantic, 0x61, 32);
    memset(transport, 0x71, 32);
    memset(permitted_publisher, 0x99, 32);
    ASSERT(!zcl_native_zcode_science_test_candidate_allowed(
        datadir, semantic, transport,
        fixture.delegation.doc.master_pubkey));
    ASSERT(zcl_native_zcode_science_test_candidate_allowed(
        datadir, semantic, transport, permitted_publisher));
    struct vcs_zcode_sovereignty_rule exact_block;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &exact_block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_FULL_ROOT,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_FETCH), transport),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &exact_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(policy, datadir, error,
                                                sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(!zcl_native_zcode_science_test_candidate_allowed(
        datadir, semantic, transport, permitted_publisher));
    ASSERT_EQ(vcs_zcode_sovereignty_policy_remove(policy, exact_block.id),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &exact_block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_FULL_ROOT,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_STORE), semantic),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &exact_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(policy, datadir, error,
                                                sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(!zcl_native_zcode_science_test_candidate_allowed(
        datadir, semantic, transport, permitted_publisher));
    ASSERT_EQ(vcs_zcode_sovereignty_policy_remove(policy, exact_block.id),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &exact_block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_INDEX),
                  service_type),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &exact_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(policy, datadir, error,
                                                sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(!zcl_native_zcode_science_test_candidate_allowed(
        datadir, semantic, transport, permitted_publisher));
    vcs_zcode_sovereignty_policy_free(policy);
    test_rm_rf_recursive(datadir);
    memory_cleanse(master_seed, sizeof(master_seed));
    PASS();
  }
_test_next:;
  return failures;
}

static int test_replication_public_lifecycle(void)
{
  int failures = 0;
  TEST("zcode replication: owner lifecycle cleans children and fails partial") {
    struct rpc_table table;
    rpc_table_init(&table);
    boot_zcode_dht_replication_register_rpc(&table);
    struct json_value begin_input;
    json_init(&begin_input);
    json_set_object(&begin_input);
    json_push_kv_str(&begin_input, "namespace", "science");
    uint8_t root[32];
    char root_hex[65];
    memset(root, 0x91, sizeof(root));
    zcl_hex_encode(root, sizeof(root), root_hex);
    json_push_kv_str(&begin_input, "transport_root", root_hex);

    struct replication_backend_fixture fixture = {
        .now = {.wall_unix = 1500, .monotonic_s = 1000},
        .generation = 7,
    };
    replication_backend_install(&fixture);
    struct json_value result;
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    ASSERT(replication_json_bool(&result, "ok", false));
    char lookup[33], owner[33], wrong_owner[33];
    (void)snprintf(lookup, sizeof(lookup), "%s",
                   json_get_str(json_get(&result, "lookup_id")));
    (void)snprintf(owner, sizeof(owner), "%s",
                   json_get_str(json_get(&result, "owner_token")));
    json_free(&result);
    memcpy(wrong_owner, owner, sizeof(wrong_owner));
    wrong_owner[0] = wrong_owner[0] == '0' ? '1' : '0';
    struct json_value capability;
    json_init(&capability);
    replication_capability_input(&capability, lookup, wrong_owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_cancel",
                           &capability, &result));
    ASSERT(!replication_json_bool(&result, "ok", true));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "code")), "LOOKUP_UNKNOWN");
    ASSERT_EQ(fixture.cancel_calls, 0);
    json_free(&result);
    json_free(&capability);
    json_init(&capability);
    replication_capability_input(&capability, lookup, owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_cancel",
                           &capability, &result));
    ASSERT(replication_json_bool(&result, "canceled", false));
    ASSERT_EQ(fixture.cancel_calls, 2);
    json_free(&result);
    json_free(&capability);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    ASSERT(replication_json_bool(&result, "ok", false));
    (void)snprintf(lookup, sizeof(lookup), "%s",
                   json_get_str(json_get(&result, "lookup_id")));
    (void)snprintf(owner, sizeof(owner), "%s",
                   json_get_str(json_get(&result, "owner_token")));
    json_free(&result);
    json_init(&capability);
    replication_capability_input(&capability, lookup, owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_cancel",
                           &capability, &result));
    ASSERT_EQ(fixture.cancel_calls, 4);
    json_free(&result);
    json_free(&capability);

    memset(&fixture, 0, sizeof(fixture));
    fixture.now = (struct vcs_zcode_dht_time){.wall_unix = 1500,
                                              .monotonic_s = 2000};
    fixture.generation = 8;
    fixture.fail_begin_call = 2;
    replication_backend_install(&fixture);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    ASSERT(!replication_json_bool(&result, "ok", true));
    ASSERT_EQ(fixture.cancel_calls, 1);
    json_free(&result);

    memset(&fixture, 0, sizeof(fixture));
    fixture.now = (struct vcs_zcode_dht_time){.wall_unix = 1500,
                                              .monotonic_s = 3000};
    fixture.generation = 9;
    fixture.mismatch_second_generation = true;
    replication_backend_install(&fixture);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    ASSERT(!replication_json_bool(&result, "ok", true));
    ASSERT_EQ(fixture.cancel_calls, 2);
    json_free(&result);

    memset(&fixture, 0, sizeof(fixture));
    fixture.now = (struct vcs_zcode_dht_time){.wall_unix = 1500,
                                              .monotonic_s = 4000};
    fixture.generation = 10;
    fixture.interrupt_poll_call = 1;
    replication_backend_install(&fixture);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    (void)snprintf(lookup, sizeof(lookup), "%s",
                   json_get_str(json_get(&result, "lookup_id")));
    (void)snprintf(owner, sizeof(owner), "%s",
                   json_get_str(json_get(&result, "owner_token")));
    json_free(&result);
    json_init(&capability);
    replication_capability_input(&capability, lookup, owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_poll",
                           &capability, &result));
    ASSERT(!replication_json_bool(&result, "ok", true));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "code")),
                  "LOOKUP_INTERRUPTED");
    ASSERT_EQ(fixture.cancel_calls, 2);
    json_free(&result);
    json_free(&capability);

    memset(&fixture, 0, sizeof(fixture));
    fixture.now = (struct vcs_zcode_dht_time){.wall_unix = 1500,
                                              .monotonic_s = 5000};
    fixture.generation = 11;
    fixture.terminal = true;
    fixture.truncate_provider = true;
    replication_backend_install(&fixture);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    (void)snprintf(lookup, sizeof(lookup), "%s",
                   json_get_str(json_get(&result, "lookup_id")));
    (void)snprintf(owner, sizeof(owner), "%s",
                   json_get_str(json_get(&result, "owner_token")));
    json_free(&result);
    json_init(&capability);
    replication_capability_input(&capability, lookup, owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_poll",
                           &capability, &result));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "state")), "complete");
    ASSERT(replication_json_bool(&result, "partial", false));
    ASSERT(replication_json_bool(&result, "provider_discovery_truncated",
                                 false));
    ASSERT(!replication_json_bool(&result, "provider_evidence_complete",
                                  true));
    ASSERT(!replication_json_bool(&result, "durable", true));
    json_free(&result);
    fixture.now.monotonic_s += 29;
    ASSERT(replication_rpc(&table, "zcode_dht_replication_poll",
                           &capability, &result));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "state")), "complete");
    json_free(&result);
    fixture.now.monotonic_s += 2;
    boot_zcode_dht_replication_public_tick(fixture.now.monotonic_s);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_poll",
                           &capability, &result));
    ASSERT(!replication_json_bool(&result, "ok", true));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "code")), "LOOKUP_UNKNOWN");
    json_free(&result);
    json_free(&capability);

    memset(&fixture, 0, sizeof(fixture));
    fixture.now = (struct vcs_zcode_dht_time){.wall_unix = 1500,
                                              .monotonic_s = 6000};
    fixture.generation = 12;
    replication_backend_install(&fixture);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_begin",
                           &begin_input, &result));
    (void)snprintf(lookup, sizeof(lookup), "%s",
                   json_get_str(json_get(&result, "lookup_id")));
    (void)snprintf(owner, sizeof(owner), "%s",
                   json_get_str(json_get(&result, "owner_token")));
    json_free(&result);
    fixture.now.monotonic_s += 1000;
    boot_zcode_dht_replication_public_tick(fixture.now.monotonic_s);
    ASSERT_EQ(fixture.cancel_calls, 2);
    json_init(&capability);
    replication_capability_input(&capability, lookup, owner);
    ASSERT(replication_rpc(&table, "zcode_dht_replication_poll",
                           &capability, &result));
    ASSERT_STR_EQ(json_get_str(json_get(&result, "code")), "LOOKUP_UNKNOWN");
    json_free(&result);
    json_free(&capability);
    json_free(&begin_input);
    boot_zcode_dht_replication_test_set_backend(NULL);
    PASS();
  }
  _test_next:;
  boot_zcode_dht_replication_test_set_backend(NULL);
  return failures;
}
#endif

int test_zcode_dht_record(void)
{
  int failures = 0;
  failures += test_record_key();
  failures += test_record_roundtrip();
  failures += test_record_shape_and_windows();
  failures += test_record_adversarial();
  failures += test_record_conflicts();
  failures += test_record_store_restart();
  failures += test_record_store_sequence_and_expiry();
  failures += test_record_store_caps();
  failures += test_declared_replication();
#ifdef ZCL_TESTING
  failures += test_science_pointer_ranking();
  failures += test_record_projection_fields();
  failures += test_record_projection_evidence_wires();
  failures += test_science_pointer_candidate_policy();
  failures += test_replication_public_lifecycle();
#endif
  printf("=== zcode_dht_record: %d failures ===\n", failures);
  return failures;
}
