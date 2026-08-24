/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove canonical ZCODE task/candidate/policy/review/receipt wires. */

#include "test/test_core.h"

#include "base/hex.h"
#include "codeindex/codeindex_merkle.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "models/zcode_lane.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_lane_service.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/package_mapping.h"
#include "vcs/package_index.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/source_package_checkout.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_devloop_mirror.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_build.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_commons_v2.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_work_swarm.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_candidate_tree.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_task_index.h"
#include "vcs/vcs.h"

#include <secp256k1.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void zd_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static unsigned zd_boot_probe_calls;

static bool zd_count_boot_probe(const char *path)
{
    (void)path;
    zd_boot_probe_calls++;
    return false;
}

static bool zd_provider_chain_accept(
    void *context, const struct vcs_zcode_dht_delegation *delegation)
{
    unsigned *calls = context;
    (*calls)++;
    return delegation->beacon_height == 120u;
}

static bool zd_provider_record(
    const uint8_t transport_root[32],
    struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES], unsigned *chain_calls)
{
    uint8_t online_seed[32], online_pub[32], online_secret[32];
    uint8_t noise[32], beacon[32], master_seed[32];
    zd_root(online_seed, 0x22);
    zd_root(noise, 0x33);
    zd_root(beacon, 0x44);
    zd_root(master_seed, 0x55);
    ed25519_keypair(online_pub, online_secret, online_seed);
    memset(online_secret, 0, sizeof(online_secret));
    memset(verify, 0, sizeof(*verify));
    zd_root(verify->network_genesis, 0x01);
    verify->now_unix = 1500;
    verify->chain_verify = zd_provider_chain_accept;
    verify->chain_ctx = chain_calls;
    memset(record, 0, sizeof(*record));
    record->kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
    (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                   "zclassic23.source");
    memcpy(record->network_genesis, verify->network_genesis, 32);
    memcpy(record->transport_root, transport_root, 32);
    record->sequence = 1;
    record->not_before = 1200;
    record->expiry = 1800;
    bool ok = vcs_zcode_dht_delegation_sign(
            &record->delegation, verify->network_genesis, online_pub, noise,
            120, beacon, 1000, 3000, 1, master_seed) ==
            VCS_ZCODE_DHT_DELEGATION_OK &&
        vcs_zcode_dht_delegation_node_id(
            record->provider_node_id, &record->delegation) &&
        vcs_zcode_dht_record_sign(record, online_seed) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_encode(record, wire) ==
            VCS_ZCODE_DHT_RECORD_OK;
    memset(online_seed, 0, sizeof(online_seed));
    memset(master_seed, 0, sizeof(master_seed));
    return ok;
}

static bool zd_storage_ack_record(
    const uint8_t transport_root[32], uint8_t identity_byte,
    uint8_t owner_group_byte, uint64_t now_unix,
    struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES])
{
    uint8_t online_seed[32], online_pub[32], online_secret[32];
    uint8_t noise[32], beacon[32], master_seed[32], genesis[32];
    memset(online_seed, identity_byte, sizeof(online_seed));
    memset(noise, (uint8_t)(identity_byte + 1u), sizeof(noise));
    memset(beacon, 0x44, sizeof(beacon));
    memset(master_seed, (uint8_t)(identity_byte + 2u),
           sizeof(master_seed));
    memset(genesis, 0x01, sizeof(genesis));
    ed25519_keypair(online_pub, online_secret, online_seed);
    memset(online_secret, 0, sizeof(online_secret));
    memset(record, 0, sizeof(*record));
    record->kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
    (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                   "zclassic23.source");
    memcpy(record->network_genesis, genesis, 32);
    memcpy(record->transport_root, transport_root, 32);
    memset(record->owner_group, owner_group_byte,
           sizeof(record->owner_group));
    record->sequence = 1;
    record->not_before = now_unix > 60u ? now_unix - 60u : 0u;
    record->expiry = now_unix + 3600u;
    bool ok = vcs_zcode_dht_delegation_sign(
            &record->delegation, genesis, online_pub, noise, 120, beacon,
            now_unix > 120u ? now_unix - 120u : 0u,
            now_unix + 7200u, 1, master_seed) ==
            VCS_ZCODE_DHT_DELEGATION_OK &&
        vcs_zcode_dht_delegation_node_id(
            record->provider_node_id, &record->delegation) &&
        vcs_zcode_dht_record_sign(record, online_seed) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_encode(record, wire) ==
            VCS_ZCODE_DHT_RECORD_OK;
    memset(online_seed, 0, sizeof(online_seed));
    memset(master_seed, 0, sizeof(master_seed));
    return ok;
}

static bool zd_source_reproduction_record(
    const uint8_t transport_root[32], const uint8_t source_root[32],
    uint8_t identity_byte, uint8_t master_byte, uint8_t owner_group_byte,
    const char *namespace_name, uint64_t now_unix,
    struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES])
{
    uint8_t online_seed[32], online_pub[32], online_secret[32];
    uint8_t noise[32], beacon[32], master_seed[32], genesis[32];
    memset(online_seed, identity_byte, sizeof(online_seed));
    memset(noise, (uint8_t)(identity_byte + 1u), sizeof(noise));
    memset(beacon, 0x44, sizeof(beacon));
    memset(master_seed, master_byte, sizeof(master_seed));
    memset(genesis, 0x01, sizeof(genesis));
    ed25519_keypair(online_pub, online_secret, online_seed);
    memset(online_secret, 0, sizeof(online_secret));
    memset(record, 0, sizeof(*record));
    record->kind = VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK;
    (void)snprintf(record->namespace_name,
                   sizeof(record->namespace_name), "%s", namespace_name);
    memcpy(record->network_genesis, genesis, 32);
    memcpy(record->semantic_root, source_root, 32);
    memcpy(record->transport_root, transport_root, 32);
    memset(record->owner_group, owner_group_byte,
           sizeof(record->owner_group));
    record->sequence = 1;
    record->not_before = now_unix > 60u ? now_unix - 60u : 0u;
    record->expiry = now_unix + 3600u;
    bool ok = vcs_zcode_dht_delegation_sign(
            &record->delegation, genesis, online_pub, noise, 120, beacon,
            now_unix > 120u ? now_unix - 120u : 0u,
            now_unix + 7200u, 1, master_seed) ==
            VCS_ZCODE_DHT_DELEGATION_OK &&
        vcs_zcode_dht_delegation_node_id(
            record->provider_node_id, &record->delegation) &&
        vcs_zcode_dht_record_sign(record, online_seed) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_encode(record, wire) ==
            VCS_ZCODE_DHT_RECORD_OK;
    memset(online_seed, 0, sizeof(online_seed));
    memset(master_seed, 0, sizeof(master_seed));
    return ok;
}

static char zd_collect_ack_wires[2]
    [VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u + 1u];
static char zd_collect_transport_hex[65];
static size_t zd_collect_ack_wire_count;
static const char *zd_collect_kind = "storage_ack";
static unsigned zd_collect_genesis_calls;
static unsigned zd_collect_begin_calls;
static unsigned zd_collect_poll_calls;
static unsigned zd_collect_cancel_calls;
static bool zd_collect_selector_exact;

static char *zd_collect_rpc_hook(const char *method, const char *params_json)
{
    if (strcmp(method, "getblockhash") == 0) {
        zd_collect_genesis_calls++;
        return zcl_strdup(
            "\"0101010101010101010101010101010101010101010101010101010101010101\"",
            "test.zcode_dev.collect_genesis");
    }
    if (strcmp(method, "zcode_dht_record_begin") == 0) {
        zd_collect_begin_calls++;
        char kind_selector[96];
        int kind_len = snprintf(kind_selector, sizeof(kind_selector),
                                "\"kind\":\"%s\"", zd_collect_kind);
        zd_collect_selector_exact = params_json &&
            kind_len > 0 && (size_t)kind_len < sizeof(kind_selector) &&
            strstr(params_json, kind_selector) &&
            strstr(params_json, "\"namespace\":\"zclassic23.source\"") &&
            strstr(params_json, "\"include_evidence_wires\":true") &&
            strstr(params_json, zd_collect_transport_hex);
        return zcl_strdup(
            "{\"ok\":true,\"state\":\"pending\","
            "\"lookup_id\":\"11111111111111111111111111111111\","
            "\"owner_token\":\"22222222222222222222222222222222\"}",
            "test.zcode_dev.collect_begin");
    }
    if (strcmp(method, "zcode_dht_record_poll") == 0) {
        zd_collect_poll_calls++;
        size_t cap = 256u + zd_collect_ack_wire_count *
            (VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u + 32u);
        char *body = zcl_malloc(cap, "test.zcode_dev.collect_poll");
        if (!body)
            return NULL;
        int n = zd_collect_ack_wire_count == 0u
            ? snprintf(body, cap,
                       "{\"ok\":true,\"state\":\"complete\","
                       "\"records\":[]}")
            : zd_collect_ack_wire_count == 1u
            ? snprintf(body, cap,
                       "{\"ok\":true,\"state\":\"complete\","
                       "\"records\":[{\"record_wire\":\"%s\"}]}",
                       zd_collect_ack_wires[0])
            : snprintf(body, cap,
                       "{\"ok\":true,\"state\":\"complete\","
                       "\"records\":[{\"record_wire\":\"%s\"},"
                       "{\"record_wire\":\"%s\"}]}",
                       zd_collect_ack_wires[0],
                       zd_collect_ack_wires[1]);
        if (n <= 0 || (size_t)n >= cap) {
            free(body);
            return NULL;
        }
        return body;
    }
    if (strcmp(method, "zcode_dht_record_cancel") == 0) {
        zd_collect_cancel_calls++;
        return zcl_strdup("{\"ok\":true,\"canceled\":true}",
                          "test.zcode_dev.collect_cancel");
    }
    return zcl_strdup("{\"ok\":false,\"code\":\"UNEXPECTED_RPC\"}",
                      "test.zcode_dev.collect_unexpected");
}

static bool zd_secp_pubkey(secp256k1_context *ctx,
                           const uint8_t secret[32], uint8_t out[33])
{
    secp256k1_pubkey key;
    size_t len = 33;
    return secp256k1_ec_pubkey_create(ctx, &key, secret) == 1 &&
        secp256k1_ec_pubkey_serialize(
            ctx, out, &len, &key, SECP256K1_EC_COMPRESSED) == 1 &&
        len == 33;
}

static bool zd_secp_signature(secp256k1_context *ctx,
                              const uint8_t secret[32],
                              const uint8_t digest[32], uint8_t out[64])
{
    secp256k1_ecdsa_signature signature, normalized;
    if (secp256k1_ecdsa_sign(
            ctx, &signature, digest, secret, NULL, NULL) != 1)
        return false;
    (void)secp256k1_ecdsa_signature_normalize(
        ctx, &normalized, &signature);
    return secp256k1_ecdsa_signature_serialize_compact(
               ctx, out, &normalized) == 1;
}

static bool zd_write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, file) == len;
    return fclose(file) == 0 && ok;
}

static bool zd_seed_offline_vendor_inputs(const char *workspace)
{
    static const char *const names[] = {
        "leveldb-1.23.tar.gz",
        "libevent-2.1.12.tar.gz",
        "openssl-3.0.16.tar.gz",
        "sqlite-amalgamation-3490000.zip",
        "zlib-1.3.1.tar.gz",
    };
    char vendor[1024], cache[1024], path[1200];
    int vn = snprintf(vendor, sizeof(vendor), "%s/vendor", workspace);
    int cn = snprintf(cache, sizeof(cache), "%s/.cache", vendor);
    if (vn <= 0 || (size_t)vn >= sizeof(vendor) ||
        cn <= 0 || (size_t)cn >= sizeof(cache) ||
        (mkdir(vendor, 0700) != 0 && errno != EEXIST) ||
        (mkdir(cache, 0700) != 0 && errno != EEXIST))
        return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", cache, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !zd_write_text(path, names[i]))
            return false;
    }
    return true;
}

static bool zd_copy_tagged_object(
    const char *source_store, const char *destination_store,
    const uint8_t root[32], uint8_t tag)
{
    uint8_t *wire = NULL, copied[32];
    size_t wire_len = 0;
    bool ok = vcs_object_get(source_store, root, tag,
                             &wire, &wire_len) == 0 &&
        vcs_object_put(destination_store, wire, wire_len, tag, copied) &&
        memcmp(copied, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zd_no_accept_publish_stage(const char *datadir)
{
    DIR *dir = opendir(datadir);
    if (!dir) return false;
    bool clean = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, ".accept-publish-", 16) == 0) {
            clean = false;
            break;
        }
    }
    closedir(dir);
    return clean;
}

static bool zd_copy_executable(const char *source, const char *destination)
{
    FILE *in = fopen(source, "rb");
    FILE *out = in ? fopen(destination, "wb") : NULL;
    if (!in || !out) {
        if (out) fclose(out);
        if (in) fclose(in);
        return false;
    }
    uint8_t buffer[16384]; bool ok = true;
    for (;;) {
        size_t got = fread(buffer, 1, sizeof(buffer), in);
        if (got > 0 && fwrite(buffer, 1, got, out) != got) ok = false;
        if (got < sizeof(buffer)) {
            if (ferror(in)) ok = false;
            break;
        }
    }
    ok = fclose(out) == 0 && fclose(in) == 0 && ok;
    return ok && chmod(destination, 0500) == 0;
}

static void zd_policy(struct vcs_zcode_proof_policy_v1 *p)
{
    memset(p, 0, sizeof(*p));
    p->schema_version = VCS_ZCODE_DEV_VERSION;
    p->required_proofs = VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST |
                         VCS_ZCODE_PROOF_FUZZ | VCS_ZCODE_PROOF_REVIEW |
                         VCS_ZCODE_PROOF_LOCAL_REPRODUCTION;
    p->minimum_compile_receipts = 2;
    p->minimum_test_receipts = 2;
    p->minimum_fuzz_receipts = 1;
    p->minimum_reviews = 1;
    p->minimum_matching_receipts = 2;
    p->flags = VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS |
               VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
    p->deterministic_fuzz_seeds = 64;
    p->audit_basis_points = 100;
    p->maximum_proof_age_seconds = 3600;
}

static void zd_task(struct vcs_zcode_task_v1 *t,
                    const uint8_t policy_root[32])
{
    memset(t, 0, sizeof(*t));
    t->schema_version = VCS_ZCODE_DEV_VERSION;
    zd_root(t->source_root, 1);
    zd_root(t->dependency_lock_root, 2);
    zd_root(t->toolchain_capsule_root, 3);
    zd_root(t->write_scope_root, 4);
    zd_root(t->acceptance_tests_root, 5);
    memcpy(t->proof_policy_root, policy_root, 32);
    zd_root(t->model_policy_root, 7);
    zd_root(t->goal_root, 8);
    t->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    t->max_changed_files = 32;
    t->max_patch_bytes = 1024 * 1024;
    t->max_context_bytes = 2 * 1024 * 1024;
    t->max_cpu_seconds = 120;
    t->max_memory_bytes = UINT64_C(512) * 1024 * 1024;
    t->max_output_bytes = UINT64_C(64) * 1024 * 1024;
    t->expires_unix = 2000;
}

static void zd_candidate(struct vcs_zcode_candidate_v1 *c,
                         const struct vcs_zcode_task_v1 *task,
                         const uint8_t task_root[32])
{
    memset(c, 0, sizeof(*c));
    c->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(c->task_root, task_root, 32);
    memcpy(c->base_source_root, task->source_root, 32);
    zd_root(c->patch_root, 9);
    zd_root(c->candidate_source_root, 10);
    zd_root(c->adapter_policy_root, 11);
    zd_root(c->author_pubkey, 12);
    c->sequence = 1;
    c->created_unix = 1000;
}

static int test_zd_agent_context(void)
{
    int failures = 0;
    TEST("zcode_dev: agent context is canonical bounded source evidence") {
        static const char header[] = "int widget(int);\n";
        static const char source[] =
            "int widget(int x) { return x + 1; }\n";
        struct vcs_zcode_agent_context_v1 context;
        vcs_zcode_agent_context_init(&context);
        zd_root(context.task_root, 1);
        zd_root(context.source_root, 2);
        zd_root(context.goal_root, 3);
        zd_root(context.source_tree_root, 4);
        (void)snprintf(context.query, sizeof(context.query), "widget");
        context.file_count = 2;
        (void)snprintf(context.files[0].path,
                       sizeof(context.files[0].path), "include/widget.h");
        context.files[0].start_line = 1;
        context.files[0].full_file_bytes = sizeof(header) - 1u;
        context.files[0].content_len = sizeof(header) - 1u;
        context.files[0].content = zcl_malloc(
            context.files[0].content_len, "test.agent_context.header");
        ASSERT(context.files[0].content != NULL);
        memcpy(context.files[0].content, header,
               context.files[0].content_len);
        sha3_256(context.files[0].content, context.files[0].content_len,
                 context.files[0].content_root);
        (void)snprintf(context.files[1].path,
                       sizeof(context.files[1].path), "src/widget.c");
        context.files[1].start_line = 7;
        context.files[1].full_file_bytes = sizeof(source) - 1u;
        context.files[1].content_len = sizeof(source) - 1u;
        context.files[1].content = zcl_malloc(
            context.files[1].content_len, "test.agent_context.source");
        ASSERT(context.files[1].content != NULL);
        memcpy(context.files[1].content, source,
               context.files[1].content_len);
        sha3_256(context.files[1].content, context.files[1].content_len,
                 context.files[1].content_root);

        uint8_t root[32]; char root_hex[65];
        ASSERT_EQ(vcs_zcode_agent_context_validate(&context, 4096),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT_EQ(vcs_zcode_agent_context_validate(&context, 374),
                  VCS_ZCODE_AGENT_CONTEXT_LIMIT);
        ASSERT_EQ(vcs_zcode_agent_context_root(&context, 4096, root),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "261759f65d9bc99924d7f45375f73b598d8f695a740e28f7b7b9135623e0c1ed");
        uint8_t *wire = NULL; size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_agent_context_serialize(
                      &context, 4096, &wire, &wire_len),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT_EQ(wire_len, 375);
        struct vcs_zcode_agent_context_v1 parsed;
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      wire, wire_len, 4096, &parsed),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        uint8_t parsed_root[32];
        ASSERT_EQ(vcs_zcode_agent_context_root(&parsed, 4096, parsed_root),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT(memcmp(root, parsed_root, 32) == 0);
        ASSERT_STR_EQ(parsed.files[0].path, "include/widget.h");
        ASSERT_STR_EQ(parsed.files[1].path, "src/widget.c");
        vcs_zcode_agent_context_free(&parsed);

        wire[152] ^= 1u;
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      wire, wire_len, 4096, &parsed),
                  VCS_ZCODE_AGENT_CONTEXT_ROOT);
        wire[152] ^= 1u;
        wire[wire_len - 1u] ^= 1u;
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      wire, wire_len, 4096, &parsed),
                  VCS_ZCODE_AGENT_CONTEXT_ROOT);
        wire[wire_len - 1u] ^= 1u;
        uint8_t *trailed = zcl_malloc(wire_len + 1u,
                                      "test.agent_context.trailing");
        ASSERT(trailed != NULL);
        memcpy(trailed, wire, wire_len); trailed[wire_len] = 0;
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      trailed, wire_len + 1u, 4096, &parsed),
                  VCS_ZCODE_AGENT_CONTEXT_SHAPE);
        free(trailed); free(wire);
        (void)snprintf(context.files[0].path,
                       sizeof(context.files[0].path), "z/widget.h");
        ASSERT_EQ(vcs_zcode_agent_context_validate(&context, 4096),
                  VCS_ZCODE_AGENT_CONTEXT_SHAPE);
        vcs_zcode_agent_context_free(&context);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_write_scope(void)
{
    int failures = 0;
    TEST("zcode_dev: write scope is canonical component-bounded authority") {
        struct vcs_zcode_write_scope_v1 scope, parsed;
        vcs_zcode_write_scope_init(&scope);
        ASSERT_EQ(vcs_zcode_write_scope_add(&scope, "src"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(&scope, "include"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_STR_EQ(scope.paths[0], "include");
        ASSERT_STR_EQ(scope.paths[1], "src");
        ASSERT_EQ(vcs_zcode_write_scope_add(&scope, "src"),
                  VCS_ZCODE_WRITE_SCOPE_SHAPE);
        ASSERT_EQ(vcs_zcode_write_scope_add(&scope, "../wallet"),
                  VCS_ZCODE_WRITE_SCOPE_SHAPE);
        ASSERT(vcs_zcode_write_scope_contains(&scope, "src/widget.c"));
        ASSERT(vcs_zcode_write_scope_contains(&scope, "include"));
        ASSERT(!vcs_zcode_write_scope_contains(&scope, "src-old/widget.c"));
        ASSERT(!vcs_zcode_write_scope_contains(&scope, "wallet/key.c"));
        uint8_t root[32]; char root_hex[65];
        ASSERT_EQ(vcs_zcode_write_scope_root(&scope, root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "a3e7d3ed2af5c6efe7385b9a95ea4971200cee292853da5a0a43db48b9ea504d");
        uint8_t *wire = NULL; size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_write_scope_serialize(&scope, &wire, &wire_len),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(wire_len, 30);
        ASSERT_EQ(vcs_zcode_write_scope_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        uint8_t parsed_root[32];
        ASSERT_EQ(vcs_zcode_write_scope_root(&parsed, parsed_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT(memcmp(root, parsed_root, 32) == 0);
        wire[wire_len - 1u] = '/';
        ASSERT_EQ(vcs_zcode_write_scope_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_WRITE_SCOPE_SHAPE);
        wire[wire_len - 1u] = 'c';
        uint8_t *trailed = zcl_malloc(wire_len + 1u,
                                      "test.write_scope.trailing");
        ASSERT(trailed != NULL);
        memcpy(trailed, wire, wire_len); trailed[wire_len] = 0;
        ASSERT_EQ(vcs_zcode_write_scope_parse(
                      trailed, wire_len + 1u, &parsed),
                  VCS_ZCODE_WRITE_SCOPE_SHAPE);
        free(trailed); free(wire);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_patch(void)
{
    int failures = 0;
    TEST("zcode_dev: patch is derived from manifests and planned scope") {
        struct vcs_manifest base, candidate, outside;
        vcs_manifest_init(&base); vcs_manifest_init(&candidate);
        vcs_manifest_init(&outside);
        uint8_t a_blob[32], b_blob[32], c_blob[32], d_blob[32];
        zd_root(a_blob, 101); zd_root(b_blob, 102);
        zd_root(c_blob, 103); zd_root(d_blob, 104);
        ASSERT(vcs_manifest_add(&base, "include/api.h", 0100644, 2, b_blob));
        ASSERT(vcs_manifest_add(&base, "src/a.c", 0100644, 3, a_blob));
        ASSERT(vcs_manifest_add(&candidate, "include/api.h", 0100644, 2,
                                b_blob));
        ASSERT(vcs_manifest_add(&candidate, "src/a.c", 0100644, 4, c_blob));
        ASSERT(vcs_manifest_add(&candidate, "src/new.c", 0100644, 5,
                                d_blob));
        uint8_t base_root[32], candidate_root[32];
        ASSERT(vcs_manifest_tree_hash(&base, base_root));
        ASSERT(vcs_manifest_tree_hash(&candidate, candidate_root));
        struct vcs_zcode_write_scope_v1 scope;
        vcs_zcode_write_scope_init(&scope);
        ASSERT_EQ(vcs_zcode_write_scope_add(&scope, "src"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        struct vcs_zcode_patch_v1 patch, parsed;
        ASSERT_EQ(vcs_zcode_patch_derive(
                      &base, base_root, &candidate, candidate_root, &scope,
                      4, 9, &patch), VCS_ZCODE_PATCH_OK);
        ASSERT_EQ(patch.count, 2); ASSERT_EQ(patch.content_bytes, 9);
        ASSERT_STR_EQ(patch.changes[0].path, "src/a.c");
        ASSERT_EQ(patch.changes[0].kind, VCS_DIFF_MODIFIED);
        ASSERT_STR_EQ(patch.changes[1].path, "src/new.c");
        ASSERT_EQ(patch.changes[1].kind, VCS_DIFF_ADDED);
        uint8_t root[32]; char root_hex[65];
        ASSERT_EQ(vcs_zcode_patch_root(&patch, root), VCS_ZCODE_PATCH_OK);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "c1e813f265783c205ae98a8b27da5698905c32a74d1faf2a5f87a176c11493da");
        uint8_t *wire = NULL; size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_patch_serialize(&patch, &wire, &wire_len),
                  VCS_ZCODE_PATCH_OK);
        ASSERT_EQ(vcs_zcode_patch_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_PATCH_OK);
        uint8_t parsed_root[32];
        ASSERT_EQ(vcs_zcode_patch_root(&parsed, parsed_root),
                  VCS_ZCODE_PATCH_OK);
        ASSERT(memcmp(root, parsed_root, 32) == 0);
        vcs_zcode_patch_free(&parsed);
        wire[89] = 1;
        ASSERT_EQ(vcs_zcode_patch_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_PATCH_SHAPE);
        free(wire);
        ASSERT_EQ(vcs_zcode_patch_derive(
                      &base, base_root, &candidate, candidate_root, &scope,
                      1, 9, &parsed), VCS_ZCODE_PATCH_LIMIT);
        ASSERT_EQ(vcs_zcode_patch_derive(
                      &base, base_root, &candidate, candidate_root, &scope,
                      4, 8, &parsed), VCS_ZCODE_PATCH_LIMIT);
        uint8_t wrong_root[32]; zd_root(wrong_root, 77);
        ASSERT_EQ(vcs_zcode_patch_derive(
                      &base, wrong_root, &candidate, candidate_root, &scope,
                      4, 9, &parsed), VCS_ZCODE_PATCH_MANIFEST_MISMATCH);
        ASSERT(vcs_manifest_add(&outside, "include/api.h", 0100644, 2,
                                b_blob));
        ASSERT(vcs_manifest_add(&outside, "src/a.c", 0100644, 4, c_blob));
        ASSERT(vcs_manifest_add(&outside, "src/new.c", 0100644, 5, d_blob));
        ASSERT(vcs_manifest_add(&outside, "wallet/key.c", 0100600, 1,
                                a_blob));
        uint8_t outside_root[32];
        ASSERT(vcs_manifest_tree_hash(&outside, outside_root));
        ASSERT_EQ(vcs_zcode_patch_derive(
                      &base, base_root, &outside, outside_root, &scope,
                      4, 10, &parsed), VCS_ZCODE_PATCH_SCOPE);
        vcs_zcode_patch_free(&patch);
        vcs_manifest_free(&outside); vcs_manifest_free(&candidate);
        vcs_manifest_free(&base);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_policy_and_task(void)
{
    int failures = 0;
    TEST("zcode_dev: proof policy and task are canonical closed wires") {
        struct vcs_zcode_proof_policy_v1 policy, policy2;
        zd_policy(&policy);
        uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
        uint8_t policy_root[32], policy_root2[32];
        ASSERT_EQ(vcs_zcode_proof_policy_serialize(&policy, policy_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(policy_wire, "ZCPOLY\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_proof_policy_parse(policy_wire,
                  sizeof(policy_wire), &policy2), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy2, policy_root2),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(policy_root, policy_root2, 32) == 0);

        struct vcs_zcode_task_v1 task, task2;
        zd_task(&task, policy_root);
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        uint8_t task_root[32], task_root2[32];
        ASSERT_EQ(vcs_zcode_task_serialize(&task, task_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(task_wire, "ZCTASK\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_task_parse(task_wire, sizeof(task_wire), &task2),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_task_root(&task2, task_root2), VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(task_root, task_root2, 32) == 0);
        char policy_hex[65], task_hex[65];
        zcl_hex_encode(policy_root, 32, policy_hex);
        zcl_hex_encode(task_root, 32, task_hex);
        ASSERT_STR_EQ(policy_hex,
            "ab021a505c125b7aacc05499a4ec0ca153d7762a394d5bf612ce4ca83a2c9346");
        ASSERT_STR_EQ(task_hex,
            "973ef3c8d799329d22e6b802878ddfe20659f419fe8b5076259549a81d1282fd");
        ASSERT_EQ(vcs_zcode_task_validate_at(&task, 1999), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_task_validate_at(&task, 2000),
                  VCS_ZCODE_DEV_ERR_EXPIRY);

        task2.capabilities |= 1u << 31;
        ASSERT_EQ(vcs_zcode_task_validate(&task2),
                  VCS_ZCODE_DEV_ERR_CAPABILITY);
        policy2.deterministic_fuzz_seeds = VCS_ZCODE_FUZZ_SEEDS_MAX + 1u;
        ASSERT_EQ(vcs_zcode_proof_policy_validate(&policy2),
                  VCS_ZCODE_DEV_ERR_POLICY);
        policy2 = policy;
        policy2.required_proofs &= ~VCS_ZCODE_PROOF_FUZZ;
        ASSERT_EQ(vcs_zcode_proof_policy_validate(&policy2),
                  VCS_ZCODE_DEV_ERR_POLICY);
        policy_wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_proof_policy_parse(policy_wire,
                  sizeof(policy_wire), &policy2),
                  VCS_ZCODE_DEV_ERR_WIRE_MAGIC);
        ASSERT_EQ(vcs_zcode_task_parse(task_wire, sizeof(task_wire) - 1,
                                       &task2),
                  VCS_ZCODE_DEV_ERR_WIRE_SIZE);
        uint8_t proof_roots[2][32], parsed_roots[2][32], proof_set_root[32];
        zd_root(proof_roots[0], 21); zd_root(proof_roots[1], 22);
        uint8_t proof_set_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
        size_t proof_set_len = 0, parsed_count = 0;
        ASSERT_EQ(vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])proof_roots, 2, proof_set_wire,
            sizeof(proof_set_wire), &proof_set_len), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_set_parse(
            proof_set_wire, proof_set_len, parsed_roots, 2, &parsed_count),
            VCS_ZCODE_DEV_OK);
        ASSERT_EQ(parsed_count, 2);
        ASSERT_EQ(vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])proof_roots, 2, proof_set_root),
            VCS_ZCODE_DEV_OK);
        uint8_t swap[32]; memcpy(swap, proof_roots[0], 32);
        memcpy(proof_roots[0], proof_roots[1], 32);
        memcpy(proof_roots[1], swap, 32);
        ASSERT_EQ(vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])proof_roots, 2, proof_set_wire,
            sizeof(proof_set_wire), &proof_set_len),
            VCS_ZCODE_DEV_ERR_POLICY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_candidate_review(void)
{
    int failures = 0;
    TEST("zcode_dev: candidates and reviews bind the exact task and source") {
        struct vcs_zcode_proof_policy_v1 policy;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate, candidate2;
        struct vcs_zcode_review_v1 review, review2;
        uint8_t policy_root[32], task_root[32], candidate_root[32];
        zd_policy(&policy);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        zd_task(&task, policy_root);
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        zd_candidate(&candidate, &task, task_root);
        ASSERT_EQ(vcs_zcode_candidate_validate_for_task(
                      &task, &candidate, 1500), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                  VCS_ZCODE_DEV_OK);

        uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_candidate_serialize(&candidate, candidate_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(candidate_wire, "ZCCAND\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_candidate_parse(candidate_wire,
                  sizeof(candidate_wire), &candidate2), VCS_ZCODE_DEV_OK);

        memset(&review, 0, sizeof(review));
        review.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(review.task_root, task_root, 32);
        memcpy(review.candidate_root, candidate_root, 32);
        memcpy(review.proof_policy_root, policy_root, 32);
        zd_root(review.proof_set_root, 13);
        zd_root(review.findings_root, 14);
        zd_root(review.reviewer_pubkey, 15);
        review.verdict = VCS_ZCODE_REVIEW_APPROVE;
        review.sequence = 1;
        review.created_unix = 1300;
        ASSERT_EQ(vcs_zcode_review_validate_for_candidate(
                      &task, &candidate, &review, 1500), VCS_ZCODE_DEV_OK);
        uint8_t review_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_review_serialize(&review, review_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(review_wire, "ZCREVW\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_review_parse(review_wire, sizeof(review_wire),
                                         &review2), VCS_ZCODE_DEV_OK);
        uint8_t review_root[32];
        char candidate_hex[65], review_hex[65];
        ASSERT_EQ(vcs_zcode_review_root(&review, review_root),
                  VCS_ZCODE_DEV_OK);
        zcl_hex_encode(candidate_root, 32, candidate_hex);
        zcl_hex_encode(review_root, 32, review_hex);
        ASSERT_STR_EQ(candidate_hex,
            "fc65669e05d9a84cee90be08469cb00640fbe92eb1254b39cb24d40731235ca6");
        ASSERT_STR_EQ(review_hex,
            "a6f77d69c421c5cfee7b8f40578f53fc22abcaa88a8b789f4b59448fdac53713");

        candidate2.base_source_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_candidate_validate_for_task(
                      &task, &candidate2, 1500),
                  VCS_ZCODE_DEV_ERR_SOURCE_STALE);
        review2.candidate_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_review_validate_for_candidate(
                      &task, &candidate, &review2, 1500),
                  VCS_ZCODE_DEV_ERR_OUTPUT_MISMATCH);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_lane_receipt(void)
{
    int failures = 0;
    TEST("zcode_dev: signed lane receipts are canonical chained CAS objects") {
        struct vcs_zcode_proof_policy_v1 policy;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        uint8_t policy_root[32], task_root[32], candidate_root[32];
        zd_policy(&policy);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        zd_task(&task, policy_root);
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        zd_candidate(&candidate, &task, task_root);
        ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                  VCS_ZCODE_DEV_OK);
        uint8_t seed[32], signer_secret[32], signer_pubkey[32];
        zd_root(seed, 0x42);
        ed25519_keypair(signer_pubkey, signer_secret, seed);
        struct vcs_zcode_lane_receipt_v1 frontier = {
            .schema_version = VCS_ZCODE_DEV_VERSION,
            .lane = VCS_ZCODE_LANE_FRONTIER,
            .created_unix = 1500,
        };
        memcpy(frontier.source_root, candidate.candidate_source_root, 32);
        memcpy(frontier.task_root, task_root, 32);
        memcpy(frontier.candidate_root, candidate_root, 32);
        memcpy(frontier.proof_policy_root, policy_root, 32);
        ASSERT_EQ(vcs_zcode_lane_receipt_seal(
                      &frontier, signer_secret, signer_pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_verify(&frontier, signer_pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_validate_for_candidate(
                      &frontier, &task, &candidate, &policy),
                  VCS_ZCODE_DEV_OK);
        uint8_t wire[VCS_ZCODE_LANE_WIRE_BYTES], frontier_root[32];
        struct vcs_zcode_lane_receipt_v1 parsed;
        ASSERT_EQ(vcs_zcode_lane_receipt_serialize(&frontier, wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(wire, "ZCLANE\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_lane_receipt_parse(wire, sizeof(wire), &parsed),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_id(&frontier, frontier_root),
                  VCS_ZCODE_DEV_OK);
        char frontier_hex[65];
        zcl_hex_encode(frontier_root, 32, frontier_hex);
        ASSERT_STR_EQ(frontier_hex,
            "f2b5a2d11457039dbda6a82c756b38ae80b60e84ba82aaf4e35bbe6fa181e4c2");
        uint8_t parsed_root[32];
        ASSERT_EQ(vcs_zcode_lane_receipt_id(&parsed, parsed_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(frontier_root, parsed_root, 32) == 0);

        struct vcs_zcode_lane_receipt_v1 promoted = frontier;
        promoted.lane = VCS_ZCODE_LANE_CANDIDATE;
        promoted.created_unix = 1600;
        zd_root(promoted.proof_set_root, 0x16);
        memcpy(promoted.prior_receipt_root, frontier_root, 32);
        memset(promoted.signature, 0, sizeof(promoted.signature));
        ASSERT_EQ(vcs_zcode_lane_receipt_seal(
                      &promoted, signer_secret, signer_pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_validate_for_candidate(
                      &promoted, &task, &candidate, &policy),
                  VCS_ZCODE_DEV_OK);
        promoted.prior_receipt_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_lane_receipt_verify(&promoted, signer_pubkey),
                  VCS_ZCODE_DEV_ERR_SIGNATURE);
        promoted.prior_receipt_root[0] ^= 1;
        wire[11] = 1;
        ASSERT_EQ(vcs_zcode_lane_receipt_parse(wire, sizeof(wire), &parsed),
                  VCS_ZCODE_DEV_ERR_WIRE_MAGIC);
        ASSERT_EQ(vcs_zcode_lane_receipt_parse(wire, sizeof(wire) - 1,
                                               &parsed),
                  VCS_ZCODE_DEV_ERR_WIRE_SIZE);
        memset(signer_secret, 0, sizeof(signer_secret));
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_receipt(void)
{
    int failures = 0;
    TEST("zcode_dev: signed work receipts refuse stale task inputs") {
        struct vcs_zcode_proof_policy_v1 policy;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_work_receipt_v1 receipt, parsed;
        uint8_t policy_root[32], task_root[32], candidate_root[32];
        zd_policy(&policy);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        zd_task(&task, policy_root);
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        zd_candidate(&candidate, &task, task_root);
        ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                  VCS_ZCODE_DEV_OK);

        memset(&receipt, 0, sizeof(receipt));
        receipt.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(receipt.task_root, task_root, 32);
        memcpy(receipt.candidate_root, candidate_root, 32);
        zd_root(receipt.action_root, 16);
        memcpy(receipt.input_root, task.source_root, 32);
        memcpy(receipt.output_root, candidate_root, 32);
        memcpy(receipt.proof_policy_root, policy_root, 32);
        memcpy(receipt.toolchain_capsule_root,
               task.toolchain_capsule_root, 32);
        zd_root(receipt.lease_id, 17);
        zd_root(receipt.evidence_root, 18);
        zd_root(receipt.confinement_root, 19);
        receipt.work_kind = VCS_ZCODE_WORK_PROPOSE;
        receipt.status = VCS_ZCODE_WORK_PASS;
        receipt.exit_status = 0;
        receipt.started_unix = 1100;
        receipt.finished_unix = 1200;

        uint8_t seed[32], secret[32], pubkey[32];
        zd_root(seed, 20);
        ed25519_keypair(pubkey, secret, seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(&receipt, secret, pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_verify(&receipt, pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
                      &task, &candidate, &receipt, 1500), VCS_ZCODE_DEV_OK);

        uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&receipt, wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(wire, "ZCWRCP\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_work_receipt_parse(wire, sizeof(wire), &parsed),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_verify(&parsed, pubkey),
                  VCS_ZCODE_DEV_OK);
        uint8_t receipt_id[32];
        char receipt_hex[65];
        ASSERT_EQ(vcs_zcode_work_receipt_id(&receipt, receipt_id),
                  VCS_ZCODE_DEV_OK);
        zcl_hex_encode(receipt_id, 32, receipt_hex);
        ASSERT_STR_EQ(receipt_hex,
            "20483010b65179890c2a7bc9d0f4a19444e68c9a8346723dd49be13676848822");

        parsed.toolchain_capsule_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
                      &task, &candidate, &parsed, 1500),
                  VCS_ZCODE_DEV_ERR_TOOLCHAIN_STALE);
        parsed = receipt;
        parsed.input_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
                      &task, &candidate, &parsed, 1500),
                  VCS_ZCODE_DEV_ERR_SOURCE_STALE);
        parsed = receipt;
        parsed.signature[0] ^= 1;
        ASSERT_EQ(vcs_zcode_work_receipt_verify(&parsed, pubkey),
                  VCS_ZCODE_DEV_ERR_SIGNATURE);
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
                      &task, &candidate, &receipt, 2000),
                  VCS_ZCODE_DEV_ERR_EXPIRY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_work_context(void)
{
    int failures = 0;
    TEST("zcode_dev: content.v2 context reconstructs the exact action") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "zcode_dev", "context");
        struct vcs_package_store *store = vcs_package_store_open(
            dir, UINT64_C(256) * 1024u * 1024u);
        ASSERT(store != NULL);
        struct vcs_zcode_work_context_v1 context;
        vcs_zcode_work_context_init(&context);
        zd_policy(&context.proof_policy);
        uint8_t policy_root[32], task_root[32];
        ASSERT_EQ(vcs_zcode_proof_policy_root(&context.proof_policy,
                                              policy_root),
                  VCS_ZCODE_DEV_OK);
        zd_task(&context.task, policy_root);
        ASSERT_EQ(vcs_zcode_task_root(&context.task, task_root),
                  VCS_ZCODE_DEV_OK);
        zd_candidate(&context.candidate, &context.task, task_root);
        zd_root(context.source_sha256, 90);
        (void)snprintf(context.profile, sizeof(context.profile), "dev");
        context.fixed_input_len = VCS_PACKAGE_CHUNK_BYTES + 73u;
        context.fixed_input = malloc(context.fixed_input_len);
        ASSERT(context.fixed_input != NULL);
        for (size_t i = 0; i < context.fixed_input_len; i++)
            context.fixed_input[i] = (uint8_t)(i * 31u + 7u);
        context.candidate_authority_len = 73;
        context.candidate_authority = zcl_malloc(
            context.candidate_authority_len, "test.context.authority");
        ASSERT(context.candidate_authority != NULL);
        for (size_t i = 0; i < context.candidate_authority_len; i++)
            context.candidate_authority[i] = (uint8_t)(i * 17u + 3u);
        uint8_t package_root[32], action_root[32], direct_action[32];
        uint8_t input_root[32];
        ASSERT_EQ(vcs_zcode_work_context_action_root(
                      &context, 1500, direct_action, input_root),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        ASSERT_EQ(vcs_zcode_work_context_put(
                      store, &context, 1500, package_root, action_root),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        ASSERT(memcmp(action_root, direct_action, 32) == 0);
        struct vcs_package_store_status status;
        ASSERT(vcs_package_store_package_status(store, package_root,
                                                 &status));
        ASSERT(status.complete);
        ASSERT_EQ(status.total_chunks, 3);
        struct vcs_zcode_work_context_v1 loaded;
        ASSERT_EQ(vcs_zcode_work_context_get(store, package_root, 1500,
                                              &loaded),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        uint8_t loaded_action[32], loaded_input[32];
        ASSERT_EQ(vcs_zcode_work_context_action_root(
                      &loaded, 1500, loaded_action, loaded_input),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        ASSERT(memcmp(loaded_action, action_root, 32) == 0);
        ASSERT(memcmp(loaded_input, input_root, 32) == 0);
        ASSERT_EQ(loaded.fixed_input_len, context.fixed_input_len);
        ASSERT(memcmp(loaded.fixed_input, context.fixed_input,
                      context.fixed_input_len) == 0);
        ASSERT_EQ(loaded.candidate_authority_len,
                  context.candidate_authority_len);
        ASSERT(memcmp(loaded.candidate_authority,
                      context.candidate_authority,
                      context.candidate_authority_len) == 0);
        uint8_t test_action[32], test_input[32];
        ASSERT_EQ(vcs_zcode_work_context_action_root_for_kind(
                      &loaded, VCS_BUILD_ACTION_KIND_TEST_V1, 1500,
                      test_action, test_input),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        ASSERT(memcmp(test_action, loaded_action, 32) != 0);
        ASSERT(memcmp(test_input, loaded_input, 32) == 0);
        ASSERT_EQ(vcs_zcode_work_context_action_root_for_kind(
                      &loaded, "c23.shell.v1", 1500,
                      test_action, test_input),
                  VCS_ZCODE_WORK_CONTEXT_ACTION);
        uint8_t *wire = NULL; size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_work_context_serialize(
                      &context, 1500, &wire, &wire_len),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        wire[12] = 1;
        struct vcs_zcode_work_context_v1 rejected;
        ASSERT_EQ(vcs_zcode_work_context_parse(wire, wire_len, 1500,
                                                &rejected),
                  VCS_ZCODE_WORK_CONTEXT_SHAPE);
        free(wire);
        vcs_zcode_work_context_free(&loaded);
        vcs_zcode_work_context_free(&context);
        vcs_package_store_close(store);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static void zd_swarm_result(
    struct vcs_zcode_work_result_v1 *result,
    const struct vcs_zcode_work_request_v1 *request,
    uint8_t output_value, uint8_t signer_value)
{
    memset(result, 0, sizeof(*result));
    result->request_id = request->request_id;
    memcpy(result->task_root, request->task_root, 32);
    memcpy(result->candidate_root, request->candidate_root, 32);
    memcpy(result->action_root, request->action_root, 32);
    zd_root(result->output_root, output_value);
    struct vcs_zcode_work_receipt_v1 *receipt = &result->receipt;
    receipt->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(receipt->task_root, request->task_root, 32);
    memcpy(receipt->candidate_root, request->candidate_root, 32);
    memcpy(receipt->action_root, request->action_root, 32);
    memcpy(receipt->input_root, request->input_root, 32);
    memcpy(receipt->output_root, result->output_root, 32);
    memcpy(receipt->proof_policy_root, request->proof_policy_root, 32);
    memcpy(receipt->toolchain_capsule_root,
           request->toolchain_capsule_root, 32);
    zd_root(receipt->lease_id, 40);
    zd_root(receipt->evidence_root, 41);
    zd_root(receipt->confinement_root, 42);
    receipt->work_kind = request->work_kind;
    receipt->status = VCS_ZCODE_WORK_PASS;
    receipt->started_unix = 1000;
    receipt->finished_unix = 1001;
    uint8_t seed[32], secret[32], public_key[32];
    zd_root(seed, signer_value);
    ed25519_keypair(public_key, secret, seed);
    (void)vcs_zcode_work_receipt_seal(receipt, secret, public_key);
}

static void zd_swarm_progress(
    struct vcs_zcode_work_progress_v1 *progress,
    const struct vcs_zcode_work_request_v1 *request, uint8_t stage,
    int64_t observed_unix, uint8_t signer_value)
{
    memset(progress, 0, sizeof(*progress));
    progress->request_id = request->request_id;
    memcpy(progress->task_root, request->task_root, 32);
    memcpy(progress->candidate_root, request->candidate_root, 32);
    memcpy(progress->action_root, request->action_root, 32);
    progress->stage = stage;
    progress->observed_unix = observed_unix;
    uint8_t seed[32], secret[32], public_key[32];
    zd_root(seed, signer_value);
    ed25519_keypair(public_key, secret, seed);
    (void)vcs_zcode_work_progress_seal(
        progress, secret, public_key);
}

static bool zd_kind_action(
    struct node_db *ndb, const struct db_build_job *job,
    const struct db_build_action *base, const char *kind, int64_t sequence,
    const uint8_t input_root[32], struct db_build_action *out)
{
    memset(out, 0, sizeof(*out));
    out->sequence = sequence;
    (void)snprintf(out->kind, sizeof(out->kind), "%s", kind);
    (void)snprintf(out->state, sizeof(out->state), "SNAPSHOTTED");
    zcl_hex_encode(input_root, 32, out->input_root_sha3);
    (void)snprintf(out->task_root_sha3, sizeof(out->task_root_sha3), "%s",
                   base->task_root_sha3);
    (void)snprintf(out->candidate_root_sha3,
                   sizeof(out->candidate_root_sha3), "%s",
                   base->candidate_root_sha3);
    (void)snprintf(out->proof_policy_root_sha3,
                   sizeof(out->proof_policy_root_sha3), "%s",
                   base->proof_policy_root_sha3);
    (void)snprintf(out->target, sizeof(out->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(kind, flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            kind, environment))
        return false;
    zcl_hex_encode(flags, 32, out->flags_sha3);
    zcl_hex_encode(environment, 32, out->environment_sha3);
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_TEST_V1) == 0) {
        (void)snprintf(out->virtual_workdir, sizeof(out->virtual_workdir),
                       "%s", VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1);
        (void)snprintf(out->declared_outputs,
                       sizeof(out->declared_outputs), "%s",
                       VCS_BUILD_TEST_OUTPUT_V1);
        (void)snprintf(out->resource_policy,
                       sizeof(out->resource_policy), "%s",
                       VCS_BUILD_TEST_RESOURCE_POLICY_V1);
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0) {
        (void)snprintf(out->virtual_workdir, sizeof(out->virtual_workdir),
                       "%s", VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1);
        (void)snprintf(out->declared_outputs,
                       sizeof(out->declared_outputs), "%s",
                       VCS_BUILD_FUZZ_OUTPUT_V1);
        (void)snprintf(out->resource_policy,
                       sizeof(out->resource_policy), "%s",
                       VCS_BUILD_FUZZ_RESOURCE_POLICY_V1);
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_REVIEW_V1) == 0) {
        (void)snprintf(out->virtual_workdir, sizeof(out->virtual_workdir),
                       "%s", VCS_BUILD_REVIEW_VIRTUAL_ROOT_V1);
        (void)snprintf(out->declared_outputs,
                       sizeof(out->declared_outputs), "%s",
                       VCS_BUILD_REVIEW_OUTPUT_V1);
        (void)snprintf(out->resource_policy,
                       sizeof(out->resource_policy), "%s",
                       VCS_BUILD_REVIEW_RESOURCE_POLICY_V1);
    } else {
        return false;
    }
    out->created_at = out->updated_at = base->created_at;
    struct db_build_job kind_job = *job;
    kind_job.job_id[0] = '\0';
    (void)snprintf(kind_job.state, sizeof(kind_job.state), "PLANNED");
    kind_job.outcome[0] = '\0';
    if (!build_fabric_action_id(&kind_job, out, out->action_id).ok ||
        !build_fabric_job_id(
            &kind_job, out->action_id, kind_job.job_id).ok)
        return false;
    (void)snprintf(out->job_id, sizeof(out->job_id), "%s", kind_job.job_id);
    return db_build_job_save(ndb, &kind_job) && db_build_action_save(ndb, out);
}

static bool zd_observe_kind(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_task_v1 *task,
    const struct db_build_action *action, uint8_t work_kind,
    const uint8_t output_root[32], uint8_t signer_value, int64_t now,
    char observed_id[65])
{
    struct vcs_zcode_work_request_v1 request = {
        .request_id = UINT64_C(10000) + signer_value,
        .work_kind = work_kind,
        .target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3,
        .max_cpu_seconds = 60,
        .max_memory_bytes = UINT64_C(512) * 1024u * 1024u,
        .max_output_bytes = UINT64_C(64) * 1024u * 1024u,
        .deadline_unix = task->expires_unix - 1,
    };
    if (!zcl_hex_decode_lower(action->task_root_sha3,
                              request.task_root, 32) ||
        !zcl_hex_decode_lower(action->candidate_root_sha3,
                              request.candidate_root, 32) ||
        !zcl_hex_decode_lower(action->action_id,
                              request.action_root, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3,
                              request.input_root, 32) ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3,
                              request.proof_policy_root, 32))
        return false;
    zd_root(request.context_root, (uint8_t)(signer_value + 1u));
    memcpy(request.toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    uint8_t requester_seed[32], requester_secret[32], requester_key[32];
    zd_root(requester_seed, (uint8_t)(signer_value + 2u));
    ed25519_keypair(requester_key, requester_secret, requester_seed);
    if (!vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key))
        return false;
    struct vcs_zcode_work_result_v1 result;
    zd_swarm_result(&result, &request, 1, signer_value);
    memcpy(result.output_root, output_root, 32);
    memcpy(result.receipt.output_root, output_root, 32);
    result.receipt.started_unix = now > 0 ? now - 1 : 0;
    result.receipt.finished_unix = now;
    uint8_t seed[32], secret[32], public_key[32];
    zd_root(seed, signer_value);
    ed25519_keypair(public_key, secret, seed);
    if (vcs_zcode_work_receipt_seal(
            &result.receipt, secret, public_key) != VCS_ZCODE_DEV_OK ||
        !build_fabric_receipt_observe_remote(
            ndb, workspace, &request, &result, now, observed_id).ok)
        return false;
    struct db_build_receipt observed;
    struct db_build_worker worker;
    return db_build_receipt_find(ndb, observed_id, &observed) &&
           db_build_worker_find(ndb, observed.worker_id, &worker) &&
           build_fabric_worker_approve(ndb, &worker, now).ok;
}

static int test_zd_work_swarm(void)
{
    int failures = 0;
    TEST("zcode_dev: work swarm binds requests and counts signer quorum") {
        struct vcs_zcode_work_swarm_message message = {0}, parsed = {0};
        message.type = VCS_ZCODE_WORK_SWARM_CAPABILITY;
        zd_root(message.body.capability.toolchain_capsule_root, 31);
        message.body.capability.work_kinds =
            (UINT32_C(1) << VCS_ZCODE_WORK_BUILD) |
            (UINT32_C(1) << VCS_ZCODE_WORK_TEST);
        message.body.capability.target =
            VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        message.body.capability.confinement =
            VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
        message.body.capability.max_cpu_seconds = 60;
        message.body.capability.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        message.body.capability.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        message.body.capability.max_lease_seconds = 120;
        message.body.capability.slots = 2;
        message.body.capability.queue_headroom = 2;
        message.body.capability.expires_unix = 2000;
        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        zd_root(requester_seed, 30);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        ASSERT(vcs_zcode_work_capability_seal(&message.body.capability,
                                              requester_secret,
                                              requester_key));
        uint8_t wire[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_work_swarm_wire_size(&message), 184);
        ASSERT(vcs_zcode_work_swarm_serialize(&message, wire, sizeof(wire),
                                              &wire_len));
        ASSERT_EQ(wire_len, 184);
        ASSERT(vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));
        ASSERT_EQ(parsed.body.capability.slots, 2);
        wire[110] ^= 1;
        ASSERT(!vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));

        memset(&message, 0, sizeof(message));
        message.type = VCS_ZCODE_WORK_SWARM_REQUEST;
        struct vcs_zcode_work_request_v1 *request = &message.body.request;
        request->request_id = 77;
        zd_root(request->task_root, 33);
        zd_root(request->candidate_root, 34);
        zd_root(request->action_root, 35);
        zd_root(request->input_root, 36);
        zd_root(request->context_root, 39);
        zd_root(request->proof_policy_root, 37);
        zd_root(request->toolchain_capsule_root, 38);
        request->work_kind = VCS_ZCODE_WORK_BUILD;
        request->target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        request->max_cpu_seconds = 60;
        request->max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        request->max_output_bytes = UINT64_C(64) * 1024 * 1024;
        request->deadline_unix = 2000;
        ASSERT(vcs_zcode_work_request_seal(request, requester_secret,
                                           requester_key));
        ASSERT(vcs_zcode_work_swarm_serialize(&message, wire, sizeof(wire),
                                              &wire_len));
        ASSERT_EQ(wire_len, 372);
        ASSERT(vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));
        ASSERT_EQ(parsed.body.request.request_id, 77);
        struct vcs_zcode_work_request_v1 pinned_request = parsed.body.request;
        request = &pinned_request;

        struct vcs_zcode_work_progress_v1 progress;
        zd_swarm_progress(&progress, request,
                          VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY, 1000, 44);
        ASSERT(vcs_zcode_work_progress_verify(&progress));
        ASSERT(vcs_zcode_work_progress_verify_for_request(
            request, &progress, progress.signer_pubkey));
        memset(&message, 0, sizeof(message));
        message.type = VCS_ZCODE_WORK_SWARM_PROGRESS;
        message.body.progress = progress;
        ASSERT_EQ(vcs_zcode_work_swarm_wire_size(&message), 224);
        ASSERT(vcs_zcode_work_swarm_serialize(
            &message, wire, sizeof(wire), &wire_len));
        ASSERT_EQ(wire_len, 224);
        ASSERT(vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));
        wire[wire_len - 1u] ^= 1u;
        ASSERT(!vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));

        memset(&message, 0, sizeof(message));
        message.type = VCS_ZCODE_WORK_SWARM_ADMISSION;
        struct vcs_zcode_work_admission_v1 *admission =
            &message.body.admission;
        admission->request_id = request->request_id;
        memcpy(admission->requester_pubkey, request->requester_pubkey, 32);
        memcpy(admission->action_root, request->action_root, 32);
        admission->lease_generation = 9;
        admission->deadline_unix = request->deadline_unix;
        admission->slot = 1;
        admission->disposition = VCS_ZCODE_WORK_ADMISSION_GRANTED;
        ASSERT(vcs_zcode_work_admission_seal(
            admission, requester_secret, requester_key));
        ASSERT(vcs_zcode_work_admission_verify_for_request(
            request, admission, requester_key));
        ASSERT_EQ(vcs_zcode_work_swarm_wire_size(&message), 200);
        ASSERT(vcs_zcode_work_swarm_serialize(
            &message, wire, sizeof(wire), &wire_len));
        ASSERT_EQ(wire_len, 200);
        ASSERT(vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));
        wire[wire_len - 1u] ^= 1u;
        ASSERT(!vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));

        struct vcs_zcode_work_result_v1 results[2], mismatched[2];
        zd_swarm_result(&results[0], request, 43, 44);
        zd_swarm_result(&results[1], request, 43, 45);
        uint8_t approved[2][32];
        memcpy(approved[0], results[0].receipt.signer_pubkey, 32);
        memcpy(approved[1], results[1].receipt.signer_pubkey, 32);
        ASSERT(vcs_zcode_work_result_verify(request, &results[0],
                                            approved[0]));
        ASSERT(!vcs_zcode_work_result_verify(request, &results[0],
                                             approved[1]));
        memset(&message, 0, sizeof(message));
        message.type = VCS_ZCODE_WORK_SWARM_RESULT;
        message.body.result = results[0];
        ASSERT(vcs_zcode_work_swarm_serialize(&message, wire, sizeof(wire),
                                              &wire_len));
        ASSERT_EQ(wire_len, 592);
        ASSERT(vcs_zcode_work_swarm_parse(wire, wire_len, &parsed));
        ASSERT(vcs_zcode_work_result_verify(request, &parsed.body.result,
                                            approved[0]));
        uint8_t agreed_root[32];
        ASSERT_EQ(vcs_zcode_work_result_quorum(request, results, 2, approved,
                  2, 2, agreed_root), 2);
        ASSERT(memcmp(agreed_root, results[0].output_root, 32) == 0);

        mismatched[0] = results[0];
        zd_swarm_result(&mismatched[1], request, 46, 45);
        ASSERT_EQ(vcs_zcode_work_result_quorum(request, mismatched, 2,
                  approved, 2, 2, agreed_root), 1);
        uint8_t zero[32] = {0};
        ASSERT(memcmp(agreed_root, zero, 32) == 0);
        zd_swarm_result(&results[1], request, 43, 45);
        results[1].receipt.status = VCS_ZCODE_WORK_FAIL;
        uint8_t failed_seed[32], failed_secret[32], failed_key[32];
        zd_root(failed_seed, 45);
        ed25519_keypair(failed_key, failed_secret, failed_seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
            &results[1].receipt, failed_secret, failed_key),
            VCS_ZCODE_DEV_OK);
        ASSERT(vcs_zcode_work_result_verify(request, &results[1],
                                            approved[1]));
        ASSERT_EQ(vcs_zcode_work_result_quorum(request, results, 2,
                  approved, 2, 2, agreed_root), 1);
        ASSERT(memcmp(agreed_root, zero, 32) == 0);
        results[1] = results[0];
        ASSERT_EQ(vcs_zcode_work_result_quorum(request, results, 2, approved,
                  2, 2, agreed_root), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_work_node_duplicate_sessions(void)
{
    int failures = 0;
    TEST("zcode_dev: duplicate peer sessions cannot multiply worker slots") {
        struct vcs_zcode_work_node *requester = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *worker = vcs_zcode_work_node_create();
        ASSERT(requester && worker);
        ASSERT(vcs_zcode_work_node_peer_add(requester, 11));
        ASSERT(vcs_zcode_work_node_peer_add(requester, 12));
        ASSERT(vcs_zcode_work_node_peer_add(worker, 21));
        ASSERT(vcs_zcode_work_node_peer_add(worker, 22));
        uint8_t worker_seed[32], worker_secret[32], worker_key[32];
        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        zd_root(worker_seed, 61); zd_root(requester_seed, 62);
        ed25519_keypair(worker_key, worker_secret, worker_seed);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        struct vcs_zcode_work_capability_v1 capability = {0};
        memcpy(capability.signer_pubkey, worker_key, 32);
        zd_root(capability.toolchain_capsule_root, 63);
        capability.work_kinds = UINT32_C(1) << VCS_ZCODE_WORK_BUILD;
        capability.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        capability.confinement = VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
        capability.max_cpu_seconds = 60;
        capability.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        capability.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        capability.max_lease_seconds = 120;
        capability.slots = capability.queue_headroom = 1;
        capability.expires_unix = 2000;
        ASSERT(vcs_zcode_work_capability_seal(
            &capability, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(
            worker, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(worker, &capability));
        uint8_t frame[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
        uint64_t peer = 0; size_t frame_len = 0;
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 21, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 12, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);

        struct vcs_zcode_work_request_v1 request = {0};
        request.request_id = 600;
        zd_root(request.task_root, 64); zd_root(request.candidate_root, 65);
        zd_root(request.action_root, 66); zd_root(request.input_root, 67);
        zd_root(request.context_root, 68); zd_root(request.proof_policy_root, 69);
        memcpy(request.toolchain_capsule_root,
               capability.toolchain_capsule_root, 32);
        request.work_kind = VCS_ZCODE_WORK_BUILD;
        request.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        request.max_cpu_seconds = 60;
        request.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        request.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        request.deadline_unix = 1100;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 11, &request, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_request_v1 retry = request;
        struct vcs_zcode_work_capability_v1 effective;
        ASSERT(vcs_zcode_work_node_peer_capability(
            requester, 12, 1000, &effective));
        ASSERT_EQ(effective.queue_headroom, 0);
        vcs_zcode_work_node_peer_drop(requester, 11);
        ASSERT(vcs_zcode_work_node_peer_capability(
            requester, 12, 1000, &effective));
        ASSERT_EQ(effective.queue_headroom, 0);
        request.request_id = 601;
        zd_root(request.action_root, 70);
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 12, &request, 1000),
                  VCS_ZCODE_WORK_NODE_CAPABILITY_MISMATCH);
        vcs_zcode_work_node_tick(requester, 1100);
        ASSERT(vcs_zcode_work_node_peer_capability(
            requester, 12, 1100, &effective));
        ASSERT_EQ(effective.queue_headroom, 1);

        /* A lost result and capacity-refresh frame leave the alternate
         * worker's last signed headroom at zero.  Once the original exact
         * lease expires, the requester may transmit that same immutable
         * binding to the alternate peer; the worker still owns admission. */
        capability.queue_headroom = 0;
        capability.expires_unix = 2100;
        ASSERT(vcs_zcode_work_capability_seal(
            &capability, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(worker, &capability));
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 12, frame, frame_len, 1100),
            VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_peer_capability(
            requester, 12, 1100, &effective));
        ASSERT_EQ(effective.queue_headroom, 0);
        retry.deadline_unix = 1200;
        ASSERT(vcs_zcode_work_request_seal(
            &retry, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 12, &retry, 1100),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            requester, 12, &peer, frame, &frame_len));
        vcs_zcode_work_node_free(requester);
        vcs_zcode_work_node_free(worker);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_work_node_atomic_admission(void)
{
    int failures = 0;
    TEST("zcode_dev: worker atomically grants attaches and refuses busy work") {
        struct vcs_zcode_work_node *a = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *b = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *c = vcs_zcode_work_node_create();
        ASSERT(a && b && c);
        ASSERT(vcs_zcode_work_node_peer_add(a, 11));
        ASSERT(vcs_zcode_work_node_peer_add(c, 12));
        ASSERT(vcs_zcode_work_node_peer_add(b, 21));
        ASSERT(vcs_zcode_work_node_peer_add(b, 22));
        uint8_t b_seed[32], b_secret[32], b_key[32];
        uint8_t a_seed[32], a_secret[32], a_key[32];
        uint8_t c_seed[32], c_secret[32], c_key[32];
        zd_root(b_seed, 110); zd_root(a_seed, 111); zd_root(c_seed, 112);
        ed25519_keypair(b_key, b_secret, b_seed);
        ed25519_keypair(a_key, a_secret, a_seed);
        ed25519_keypair(c_key, c_secret, c_seed);
        struct vcs_zcode_work_capability_v1 cap = {0};
        zd_root(cap.toolchain_capsule_root, 113);
        cap.work_kinds = UINT32_C(1) << VCS_ZCODE_WORK_BUILD;
        cap.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        cap.confinement = VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
        cap.max_cpu_seconds = 60;
        cap.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        cap.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        cap.max_lease_seconds = 120;
        cap.slots = cap.queue_headroom = 1;
        cap.expires_unix = 2000;
        ASSERT(vcs_zcode_work_capability_seal(&cap, b_secret, b_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(b, b_secret, b_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(b, &cap));
        uint8_t frame[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
        size_t frame_len = 0;
        uint64_t peer = 0;
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);

        struct vcs_zcode_work_request_v1 qa = {0};
        qa.request_id = 900;
        zd_root(qa.task_root, 114); zd_root(qa.candidate_root, 115);
        zd_root(qa.action_root, 116); zd_root(qa.input_root, 117);
        zd_root(qa.context_root, 118); zd_root(qa.proof_policy_root, 119);
        memcpy(qa.toolchain_capsule_root, cap.toolchain_capsule_root, 32);
        qa.work_kind = VCS_ZCODE_WORK_BUILD;
        qa.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        qa.max_cpu_seconds = 60;
        qa.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        qa.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        qa.deadline_unix = 1100;
        ASSERT(vcs_zcode_work_request_seal(&qa, a_secret, a_key));
        struct vcs_zcode_work_request_v1 qc = qa;
        qc.request_id = 901;
        zd_root(qc.action_root, 120);
        ASSERT(vcs_zcode_work_request_seal(&qc, c_secret, c_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(a, 11, &qa, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT_EQ(vcs_zcode_work_node_submit(c, 12, &qc, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            a, 11, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 21, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 12, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 22, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_admission_v1 admission;
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(a, &peer, &admission));
        ASSERT_EQ(admission.disposition, VCS_ZCODE_WORK_ADMISSION_GRANTED);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(c, &peer, &admission));
        ASSERT_EQ(admission.disposition, VCS_ZCODE_WORK_ADMISSION_BUSY);
        ASSERT_EQ(admission.reason, VCS_ZCODE_WORK_ADMISSION_REASON_NO_SLOT);
        struct vcs_zcode_work_capability_v1 observed_capability;
        ASSERT(vcs_zcode_work_node_peer_capability(
            c, 12, 1000, &observed_capability));
        ASSERT_EQ(observed_capability.queue_headroom, 0);
        cap.expires_unix++;
        ASSERT(vcs_zcode_work_capability_seal(&cap, b_secret, b_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(b, &cap));
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_peer_capability(
            c, 12, 1000, &observed_capability));
        ASSERT_EQ(observed_capability.queue_headroom, 1);
        struct vcs_zcode_work_request_v1 physical;
        ASSERT(vcs_zcode_work_node_next_request(b, &peer, &physical));
        ASSERT_EQ(physical.request_id, qa.request_id);
        ASSERT(!vcs_zcode_work_node_next_request(b, &peer, &physical));

        struct vcs_zcode_work_request_v1 attached = qa;
        attached.request_id = 902;
        ASSERT(vcs_zcode_work_request_seal(&attached, c_secret, c_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(c, 12, &attached, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 12, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 22, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(c, &peer, &admission));
        ASSERT_EQ(admission.disposition, VCS_ZCODE_WORK_ADMISSION_ATTACHED);
        ASSERT(vcs_zcode_work_node_next_request(b, &peer, &physical));
        ASSERT_EQ(physical.request_id, attached.request_id);
        ASSERT(!vcs_zcode_work_node_next_request(b, &peer, &physical));

        struct vcs_zcode_work_swarm_message request_message = {
            .type = VCS_ZCODE_WORK_SWARM_REQUEST, .body.request = qa,
        };
        ASSERT(vcs_zcode_work_swarm_serialize(
            &request_message, frame, sizeof(frame), &frame_len));
        vcs_zcode_work_node_peer_drop(b, 21);
        ASSERT(vcs_zcode_work_node_peer_add(b, 21));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 21, frame, frame_len, 1001), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len)); /* refreshed capability */
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len)); /* repeated grant */
        struct vcs_zcode_work_swarm_message parsed;
        ASSERT(vcs_zcode_work_swarm_parse(frame, frame_len, &parsed));
        ASSERT_EQ(parsed.type, VCS_ZCODE_WORK_SWARM_ADMISSION);
        ASSERT_EQ(parsed.body.admission.disposition,
                  VCS_ZCODE_WORK_ADMISSION_GRANTED);
        struct vcs_zcode_work_request_v1 qbusy = qc;
        qbusy.request_id = 903;
        zd_root(qbusy.action_root, 121);
        ASSERT(vcs_zcode_work_request_seal(&qbusy, c_secret, c_key));
        request_message.body.request = qbusy;
        ASSERT(vcs_zcode_work_swarm_serialize(
            &request_message, frame, sizeof(frame), &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 21, frame, frame_len, 1001), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len));
        ASSERT(vcs_zcode_work_swarm_parse(frame, frame_len, &parsed));
        ASSERT_EQ(parsed.body.admission.disposition,
                  VCS_ZCODE_WORK_ADMISSION_BUSY);

        struct vcs_zcode_work_result_v1 result;
        zd_swarm_result(&result, &qa, 122, 110);
        ASSERT_EQ(vcs_zcode_work_node_publish_result(b, 21, &result),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 11, frame, frame_len, 1002), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1002), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_result_v1 received;
        ASSERT(vcs_zcode_work_node_next_result(a, &peer, &received));
        ASSERT_EQ(received.request_id, qa.request_id);
        ASSERT(vcs_zcode_work_node_next_result(c, &peer, &received));
        ASSERT_EQ(received.request_id, attached.request_id);

        /* Slot release is a capacity transition, not a timer event. The
         * worker publishes a strictly newer signed capability immediately;
         * that fact clears C's earlier BUSY observation and makes a distinct
         * immutable action admissible without waiting for expiry. */
        cap.expires_unix++;
        ASSERT(vcs_zcode_work_capability_seal(&cap, b_secret, b_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(b, &cap));
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 12, frame, frame_len, 1002), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_peer_capability(
            c, 12, 1002, &observed_capability));
        ASSERT_EQ(observed_capability.queue_headroom, 1);
        ASSERT_EQ(vcs_zcode_work_node_submit(c, 12, &qbusy, 1002),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 12, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 22, frame, frame_len, 1002), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 22, &peer, frame, &frame_len));
        ASSERT(vcs_zcode_work_swarm_parse(frame, frame_len, &parsed));
        ASSERT_EQ(parsed.body.admission.disposition,
                  VCS_ZCODE_WORK_ADMISSION_GRANTED);
        vcs_zcode_work_node_free(a);
        vcs_zcode_work_node_free(b);
        vcs_zcode_work_node_free(c);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_work_node(void)
{
    int failures = 0;
    TEST("zcode_dev: existing package peers carry requester-owned work") {
        struct vcs_zcode_work_node *requester = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *worker = vcs_zcode_work_node_create();
        ASSERT(requester && worker);
        ASSERT(vcs_zcode_work_node_peer_add(requester, 11));
        ASSERT(vcs_zcode_work_node_peer_add(worker, 22));
        uint8_t worker_seed[32], worker_secret[32], worker_key[32];
        zd_root(worker_seed, 71);
        ed25519_keypair(worker_key, worker_secret, worker_seed);
        struct vcs_zcode_work_capability_v1 capability = {0};
        memcpy(capability.signer_pubkey, worker_key, 32);
        zd_root(capability.toolchain_capsule_root, 72);
        capability.work_kinds = UINT32_C(1) << VCS_ZCODE_WORK_BUILD;
        capability.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        capability.confinement = VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
        capability.max_cpu_seconds = 60;
        capability.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        capability.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        capability.max_lease_seconds = 120;
        capability.slots = 2;
        capability.queue_headroom = 2;
        capability.expires_unix = 2000;
        ASSERT(vcs_zcode_work_capability_seal(
            &capability, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(
            worker, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(worker, &capability));
        uint8_t frame[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
        uint64_t peer_out = 0; size_t frame_len = 0;
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(peer_out, 22);
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_capability_v1 observed;
        ASSERT(vcs_zcode_work_node_peer_capability(
            requester, 11, 1000, &observed));
        ASSERT(memcmp(observed.signer_pubkey, worker_key, 32) == 0);
        uint64_t capable_peers[2] = {0};
        struct vcs_zcode_work_capability_v1 capable[2];
        ASSERT_EQ(vcs_zcode_work_node_capable_peers(
            requester, 1000, capable_peers, capable, 2), 1);
        ASSERT_EQ(capable_peers[0], 11);
        ASSERT(memcmp(capable[0].signer_pubkey, worker_key, 32) == 0);
        struct vcs_zcode_work_node *prior = vcs_zcode_work_node_global();
        struct json_value dump;
        char requester_next[160] = {0}, worker_next[160] = {0};
        int64_t requester_capable = -1;
        bool requester_dumped = false, worker_dumped = false;
        bool requester_enabled = true, worker_enabled = false;
        vcs_zcode_work_node_set_global(requester);
        json_init(&dump);
        requester_dumped = vcs_zcode_work_node_dump_state_json(&dump, NULL);
        if (requester_dumped) {
            requester_capable = json_get_int(json_get(&dump, "capable_peers"));
            requester_enabled = json_get_bool(json_get(&dump, "enabled"));
            (void)snprintf(requester_next, sizeof(requester_next), "%s",
                           json_get_str(json_get(&dump, "next_action")));
        }
        json_free(&dump);
        vcs_zcode_work_node_set_global(worker);
        json_init(&dump);
        worker_dumped = vcs_zcode_work_node_dump_state_json(&dump, NULL);
        if (worker_dumped) {
            worker_enabled = json_get_bool(json_get(&dump, "enabled"));
            (void)snprintf(worker_next, sizeof(worker_next), "%s",
                           json_get_str(json_get(&dump, "next_action")));
        }
        json_free(&dump);
        vcs_zcode_work_node_set_global(prior);
        ASSERT(requester_dumped && worker_dumped);
        ASSERT_EQ(requester_capable, 1);
        ASSERT(!requester_enabled);
        ASSERT(strstr(requester_next, "-buildworker=1") != NULL);
        ASSERT(worker_enabled);
        ASSERT(strstr(worker_next, "zcode work toolchain") != NULL);

        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        zd_root(requester_seed, 73);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        struct vcs_zcode_work_request_v1 request = {0};
        request.request_id = 700;
        zd_root(request.task_root, 74); zd_root(request.candidate_root, 75);
        zd_root(request.action_root, 76); zd_root(request.input_root, 77);
        zd_root(request.context_root, 78); zd_root(request.proof_policy_root, 79);
        memcpy(request.toolchain_capsule_root,
               capability.toolchain_capsule_root, 32);
        request.work_kind = VCS_ZCODE_WORK_BUILD;
        request.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        request.max_cpu_seconds = 60;
        request.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        request.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        request.deadline_unix = 1100;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 11, &request, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            requester, 11, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            worker, 22, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_admission_v1 observed_admission;
        ASSERT(vcs_zcode_work_node_next_admission(
            requester, &peer_out, &observed_admission));
        ASSERT_EQ(observed_admission.disposition,
                  VCS_ZCODE_WORK_ADMISSION_GRANTED);
        struct vcs_zcode_work_request_v1 received;
        ASSERT(vcs_zcode_work_node_peek_request(
            worker, &peer_out, &received));
        ASSERT_EQ(received.request_id, 700);
        uint64_t inbound_peers[2];
        struct vcs_zcode_work_request_v1 inbound_requests[2];
        ASSERT_EQ(vcs_zcode_work_node_inbound_requests(
            worker, inbound_peers, inbound_requests, 2), 1);
        ASSERT(vcs_zcode_work_node_next_request(worker, &peer_out, &received));
        ASSERT_EQ(received.request_id, 700);
        struct vcs_zcode_work_progress_v1 progress;
        zd_swarm_progress(&progress, &received,
                          VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED,
                          1000, 71);
        ASSERT_EQ(vcs_zcode_work_node_publish_progress(
            worker, 22, &progress), VCS_ZCODE_WORK_NODE_BINDING);
        zd_swarm_progress(&progress, &received,
                          VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY, 1000, 71);
        ASSERT_EQ(vcs_zcode_work_node_publish_progress(
            worker, 22, &progress), VCS_ZCODE_WORK_NODE_OK);
        ASSERT_EQ(vcs_zcode_work_node_publish_progress(
            worker, 22, &progress), VCS_ZCODE_WORK_NODE_REPLAY);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000),
            VCS_ZCODE_WORK_NODE_OK);
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000),
            VCS_ZCODE_WORK_NODE_REPLAY);
        struct vcs_zcode_work_progress_v1 observed_progress;
        ASSERT(vcs_zcode_work_node_next_progress(
            requester, &peer_out, &observed_progress));
        ASSERT_EQ(observed_progress.stage,
                  VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY);
        zd_swarm_progress(&progress, &received,
                          VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED,
                          1001, 71);
        struct vcs_zcode_work_swarm_message corrupt_progress = {
            .type = VCS_ZCODE_WORK_SWARM_PROGRESS,
            .body.progress = progress,
        };
        ASSERT(vcs_zcode_work_swarm_serialize(
            &corrupt_progress, frame, sizeof(frame), &frame_len));
        frame[frame_len - 1u] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1001),
            VCS_ZCODE_WORK_NODE_MALFORMED);
        ASSERT_EQ(vcs_zcode_work_node_publish_progress(
            worker, 22, &progress), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1001),
            VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_progress(
            requester, &peer_out, &observed_progress));
        ASSERT_EQ(observed_progress.stage,
                  VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED);
        struct vcs_zcode_work_result_v1 result;
        zd_swarm_result(&result, &received, 80, 71);
        ASSERT_EQ(vcs_zcode_work_node_publish_result(worker, 22, &result),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1001), VCS_ZCODE_WORK_NODE_OK);
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1001),
                  VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_result_v1 accepted;
        ASSERT(vcs_zcode_work_node_next_result(
            requester, &peer_out, &accepted));
        ASSERT(vcs_zcode_work_result_verify(&request, &accepted, worker_key));
        ASSERT(!vcs_zcode_work_node_next_result(
            requester, &peer_out, &accepted));
        ASSERT_EQ(vcs_zcode_work_node_requeue_results(worker, 1001), 0);
        ASSERT_EQ(vcs_zcode_work_node_requeue_results(worker, 1005), 0);
        ASSERT_EQ(vcs_zcode_work_node_requeue_results(worker, 1006), 1);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1006), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(!vcs_zcode_work_node_next_result(
            requester, &peer_out, &accepted));

        request.request_id = 701;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 11, &request, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            requester, 11, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            worker, 22, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(
            requester, &peer_out, &observed_admission));
        struct vcs_zcode_work_cancel_v1 cancel = { .request_id = 701 };
        memcpy(cancel.task_root, request.task_root, 32);
        ASSERT(vcs_zcode_work_cancel_seal(
            &cancel, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_cancel(requester, 11, &cancel),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            requester, 11, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            worker, 22, frame, frame_len, 1001), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_cancel_v1 received_cancel;
        ASSERT(vcs_zcode_work_node_next_cancel(
            worker, &peer_out, &received_cancel));
        ASSERT_EQ(received_cancel.request_id, 701);
        bool was_cancelled = false;
        ASSERT(vcs_zcode_work_node_inbound_request(
            worker, 22, 701, &received, &was_cancelled));
        ASSERT(was_cancelled);
        request.request_id = 702;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 11, &request, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        vcs_zcode_work_node_tick(requester, 1100);
        ASSERT(!vcs_zcode_work_node_next_outbound(
            requester, 11, &peer_out, frame, &frame_len));
        request.deadline_unix = 1150;
        request.request_id = 703;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(requester, 11, &request, 1100),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            requester, 11, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            worker, 22, frame, frame_len, 1100), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1100), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(
            requester, &peer_out, &observed_admission));
        ASSERT(vcs_zcode_work_node_next_request(
            worker, &peer_out, &received));
        zd_swarm_result(&result, &received, 81, 71);
        vcs_zcode_work_node_tick(worker, 1150);
        ASSERT(vcs_zcode_work_node_inbound_request(
            worker, 22, 703, &received, NULL));
        ASSERT_EQ(vcs_zcode_work_node_publish_result(worker, 22, &result),
                  VCS_ZCODE_WORK_NODE_LEASE_EXPIRED);
        ASSERT(vcs_zcode_work_node_inbound_request(
            worker, 22, 703, &received, NULL));
        ASSERT(vcs_zcode_work_node_next_outbound(
            worker, 22, &peer_out, frame, &frame_len) == false);
        zd_swarm_progress(&progress, &received,
                          VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY, 1149, 71);
        struct vcs_zcode_work_swarm_message late_progress = {
            .type = VCS_ZCODE_WORK_SWARM_PROGRESS,
            .body.progress = progress,
        };
        ASSERT(vcs_zcode_work_swarm_serialize(
            &late_progress, frame, sizeof(frame), &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1150),
            VCS_ZCODE_WORK_NODE_LEASE_EXPIRED);
        struct vcs_zcode_work_swarm_message late = {
            .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = result,
        };
        ASSERT(vcs_zcode_work_swarm_serialize(
            &late, frame, sizeof(frame), &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            requester, 11, frame, frame_len, 1150),
            VCS_ZCODE_WORK_NODE_LEASE_EXPIRED);
        vcs_zcode_work_node_free(requester);
        vcs_zcode_work_node_free(worker);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_work_node_three(void)
{
    int failures = 0;
    TEST("zcode_dev: three equal nodes retry a dead peer and refuse stale proof") {
        struct vcs_zcode_work_node *a = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *b = vcs_zcode_work_node_create();
        struct vcs_zcode_work_node *c = vcs_zcode_work_node_create();
        ASSERT(a && b && c);
        ASSERT(vcs_zcode_work_node_peer_add(a, 11));
        ASSERT(vcs_zcode_work_node_peer_add(a, 12));
        ASSERT(vcs_zcode_work_node_peer_add(b, 21));
        ASSERT(vcs_zcode_work_node_peer_add(b, 23));
        ASSERT(vcs_zcode_work_node_peer_add(c, 31));
        ASSERT(vcs_zcode_work_node_peer_add(c, 32));
        uint8_t a_seed[32], a_secret[32], a_key[32];
        uint8_t b_seed[32], b_secret[32], b_key[32];
        uint8_t c_seed[32], c_secret[32], c_key[32];
        zd_root(a_seed, 89); zd_root(b_seed, 90); zd_root(c_seed, 91);
        ed25519_keypair(a_key, a_secret, a_seed);
        ed25519_keypair(b_key, b_secret, b_seed);
        ed25519_keypair(c_key, c_secret, c_seed);
        struct vcs_zcode_work_capability_v1 cap_a = {0}, cap_b = {0},
            cap_c = {0};
        zd_root(cap_a.toolchain_capsule_root, 92);
        cap_b = cap_a; cap_c = cap_a;
        memcpy(cap_a.signer_pubkey, a_key, 32);
        memcpy(cap_b.signer_pubkey, b_key, 32);
        memcpy(cap_c.signer_pubkey, c_key, 32);
        struct vcs_zcode_work_capability_v1 *caps[] = {
            &cap_a, &cap_b, &cap_c,
        };
        for (size_t i = 0; i < 3; i++) {
            caps[i]->work_kinds = UINT32_C(1) << VCS_ZCODE_WORK_BUILD;
            caps[i]->target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
            caps[i]->confinement = VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
            caps[i]->max_cpu_seconds = 60;
            caps[i]->max_memory_bytes = UINT64_C(512) * 1024 * 1024;
            caps[i]->max_output_bytes = UINT64_C(64) * 1024 * 1024;
            caps[i]->max_lease_seconds = 100;
            caps[i]->slots = 2; caps[i]->queue_headroom = 2;
            caps[i]->expires_unix = 2000;
        }
        ASSERT(vcs_zcode_work_capability_seal(&cap_a, a_secret, a_key));
        ASSERT(vcs_zcode_work_capability_seal(&cap_b, b_secret, b_key));
        ASSERT(vcs_zcode_work_capability_seal(&cap_c, c_secret, c_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(a, a_secret, a_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(b, b_secret, b_key));
        ASSERT(vcs_zcode_work_node_set_local_signer(c, c_secret, c_key));
        ASSERT(vcs_zcode_work_node_set_local_capability(a, &cap_a));
        ASSERT(vcs_zcode_work_node_set_local_capability(b, &cap_b));
        ASSERT(vcs_zcode_work_node_set_local_capability(c, &cap_c));
        uint8_t frame[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
        uint64_t peer = 0; size_t frame_len = 0;
#define ZD_DELIVER_CAP(from, filter, to, seen) do { \
    ASSERT(vcs_zcode_work_node_next_outbound( \
        (from), (filter), &peer, frame, &frame_len)); \
    ASSERT_EQ(vcs_zcode_work_node_handle_frame( \
        (to), (seen), frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK); \
} while (0)
        ZD_DELIVER_CAP(a, 11, b, 21); ZD_DELIVER_CAP(a, 12, c, 31);
        ZD_DELIVER_CAP(b, 21, a, 11); ZD_DELIVER_CAP(b, 23, c, 32);
        ZD_DELIVER_CAP(c, 31, a, 12); ZD_DELIVER_CAP(c, 32, b, 23);
#undef ZD_DELIVER_CAP
        struct vcs_zcode_work_request_v1 request = {0};
        request.request_id = 800;
        zd_root(request.task_root, 93); zd_root(request.candidate_root, 94);
        zd_root(request.action_root, 95); zd_root(request.input_root, 96);
        zd_root(request.context_root, 97); zd_root(request.proof_policy_root, 98);
        memcpy(request.toolchain_capsule_root,
               cap_a.toolchain_capsule_root, 32);
        request.work_kind = VCS_ZCODE_WORK_BUILD;
        request.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        request.max_cpu_seconds = 60;
        request.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        request.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        request.deadline_unix = 1100;
        ASSERT(vcs_zcode_work_request_seal(&request, a_secret, a_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(a, 11, &request, 1000),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            a, 11, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 21, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 21, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 11, frame, frame_len, 1000), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_admission_v1 observed_admission;
        ASSERT(vcs_zcode_work_node_next_admission(
            a, &peer, &observed_admission));
        struct vcs_zcode_work_request_v1 stale_request;
        ASSERT(vcs_zcode_work_node_next_request(b, &peer, &stale_request));
        vcs_zcode_work_node_tick(a, 1100);
        request.deadline_unix = 1200;
        ASSERT(vcs_zcode_work_request_seal(&request, a_secret, a_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(a, 12, &request, 1100),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            a, 12, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 31, frame, frame_len, 1100), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 31, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 12, frame, frame_len, 1100), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(
            a, &peer, &observed_admission));
        struct vcs_zcode_work_request_v1 c_request;
        ASSERT(vcs_zcode_work_node_next_request(c, &peer, &c_request));
        struct vcs_zcode_work_result_v1 result;
        zd_swarm_result(&result, &c_request, 99, 91);
        ASSERT_EQ(vcs_zcode_work_node_publish_result(c, 31, &result),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 31, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 12, frame, frame_len, 1101), VCS_ZCODE_WORK_NODE_OK);
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 12, frame, frame_len, 1101), VCS_ZCODE_WORK_NODE_OK);
        struct vcs_zcode_work_result_v1 accepted;
        ASSERT(vcs_zcode_work_node_next_result(a, &peer, &accepted));
        ASSERT(vcs_zcode_work_result_verify(&c_request, &accepted, c_key));
        zd_swarm_result(&result, &stale_request, 100, 90);
        struct vcs_zcode_work_swarm_message stale = {
            .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = result,
        };
        ASSERT(vcs_zcode_work_swarm_serialize(
            &stale, frame, sizeof(frame), &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            a, 11, frame, frame_len, 1101),
            VCS_ZCODE_WORK_NODE_LEASE_EXPIRED);
        vcs_zcode_work_node_free(a); /* A dies; B and C remain full peers. */
        request.request_id = 801; request.deadline_unix = 1300;
        ASSERT(vcs_zcode_work_request_seal(&request, b_secret, b_key));
        ASSERT_EQ(vcs_zcode_work_node_submit(b, 23, &request, 1200),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            b, 23, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            c, 32, frame, frame_len, 1200), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 32, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 23, frame, frame_len, 1200), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_admission(
            b, &peer, &observed_admission));
        ASSERT(vcs_zcode_work_node_next_request(c, &peer, &c_request));
        zd_swarm_result(&result, &c_request, 101, 91);
        ASSERT_EQ(vcs_zcode_work_node_publish_result(c, 32, &result),
                  VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_outbound(
            c, 32, &peer, frame, &frame_len));
        ASSERT_EQ(vcs_zcode_work_node_handle_frame(
            b, 23, frame, frame_len, 1201), VCS_ZCODE_WORK_NODE_OK);
        ASSERT(vcs_zcode_work_node_next_result(b, &peer, &accepted));
        ASSERT(vcs_zcode_work_result_verify(&c_request, &accepted, c_key));
        vcs_zcode_work_node_free(b); vcs_zcode_work_node_free(c);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zd_improve_command(void)
{
    int failures = 0;
    TEST("zcode_dev: improve stores canonical task and queues existing ZBuild") {
        char dir[256], candidate_dir[256], preprocessed[320], source_dir[320];
        char source_path[384], workspace[4096], candidate_workspace[4096];
        char base_true[4352], base_false[4352];
        test_make_tmpdir(dir, sizeof(dir), "zcode_dev", "improve");
        ASSERT(realpath(dir, workspace) != NULL);
        (void)snprintf(source_dir, sizeof(source_dir), "%s/src", workspace);
        ASSERT(mkdir(source_dir, 0700) == 0);
        (void)snprintf(source_path, sizeof(source_path), "%s/widget.c",
                       source_dir);
        FILE *source_file = fopen(source_path, "wb");
        ASSERT(source_file != NULL);
        static const char indexed_source[] =
            "int context_widget(int x) { return x + 1; }\n";
        ASSERT(fwrite(indexed_source, 1, sizeof(indexed_source) - 1u,
                      source_file) == sizeof(indexed_source) - 1u);
        ASSERT(fclose(source_file) == 0);
        char license_path[4352];
        (void)snprintf(license_path, sizeof(license_path), "%s/LICENSE",
                       workspace);
        ASSERT(zd_write_text(license_path, "Apache License 2.0\n"));
        static const char package_meta[] =
            "{\"schema\":1,\"name\":\"fixture/accepted\","
            "\"semver\":\"1.0.0\",\"language\":\"c23\","
            "\"license\":\"Apache-2.0\",\"include_dir\":\"include\","
            "\"source_dir\":\"src\",\"dependencies\":[]}\n";
        char package_meta_path[4352];
        (void)snprintf(package_meta_path, sizeof(package_meta_path),
                       "%s/zcode-package.json", workspace);
        ASSERT(zd_write_text(package_meta_path, package_meta));
        (void)snprintf(preprocessed, sizeof(preprocessed), "%s/unit.i",
                       workspace);
        FILE *f = fopen(preprocessed, "wb");
        ASSERT(f != NULL);
        static const char source[] = "int zcode_improve_fixture(void){return 1;}\n";
        ASSERT(fwrite(source, 1, sizeof(source) - 1u, f) ==
               sizeof(source) - 1u);
        ASSERT(fclose(f) == 0);
        (void)snprintf(base_true, sizeof(base_true), "%s/test.true",
                       workspace);
        (void)snprintf(base_false, sizeof(base_false), "%s/test.false",
                       workspace);
        ASSERT(zd_copy_executable("/usr/bin/true", base_true));
        ASSERT(zd_copy_executable("/usr/bin/false", base_false));
        test_make_tmpdir(candidate_dir, sizeof(candidate_dir), "zcode_dev",
                         "candidate");
        ASSERT(realpath(candidate_dir, candidate_workspace) != NULL);
        char candidate_source_dir[4352], candidate_source_path[4608];
        char candidate_input_path[4352];
        char candidate_true[4352], candidate_false[4352];
        (void)snprintf(candidate_source_dir, sizeof(candidate_source_dir),
                       "%s/src", candidate_workspace);
        ASSERT(mkdir(candidate_source_dir, 0700) == 0);
        (void)snprintf(candidate_source_path, sizeof(candidate_source_path),
                       "%s/widget.c", candidate_source_dir);
        source_file = fopen(candidate_source_path, "wb");
        ASSERT(source_file != NULL);
        static const char candidate_source[] =
            "int context_widget(int x) { return x + 2; }\n";
        ASSERT(fwrite(candidate_source, 1, sizeof(candidate_source) - 1u,
                      source_file) == sizeof(candidate_source) - 1u);
        ASSERT(fclose(source_file) == 0);
        (void)snprintf(license_path, sizeof(license_path), "%s/LICENSE",
                       candidate_workspace);
        ASSERT(zd_write_text(license_path, "Apache License 2.0\n"));
        (void)snprintf(package_meta_path, sizeof(package_meta_path),
                       "%s/zcode-package.json", candidate_workspace);
        ASSERT(zd_write_text(package_meta_path, package_meta));
        (void)snprintf(candidate_input_path, sizeof(candidate_input_path),
                       "%s/unit.i", candidate_workspace);
        f = fopen(candidate_input_path, "wb");
        ASSERT(f != NULL);
        ASSERT(fwrite(source, 1, sizeof(source) - 1u, f) ==
               sizeof(source) - 1u);
        ASSERT(fclose(f) == 0);
        (void)snprintf(candidate_true, sizeof(candidate_true),
                       "%s/test.true", candidate_workspace);
        (void)snprintf(candidate_false, sizeof(candidate_false),
                       "%s/test.false", candidate_workspace);
        ASSERT(zd_copy_executable("/usr/bin/true", candidate_true));
        ASSERT(zd_copy_executable("/usr/bin/false", candidate_false));

        struct vcs_zcode_proof_policy_v1 policy;
        zd_policy(&policy);
        policy.flags &= (uint16_t)~VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
        uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
        char policy_hex[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES * 2u + 1u];
        ASSERT_EQ(vcs_zcode_proof_policy_serialize(&policy, policy_wire),
                  VCS_ZCODE_DEV_OK);
        zcl_hex_encode(policy_wire, sizeof(policy_wire), policy_hex);
        char roots[10][65];
        for (size_t i = 0; i < 10; i++) {
            uint8_t root[32];
            zd_root(root, (uint8_t)(i + 1));
            zcl_hex_encode(root, 32, roots[i]);
        }
        struct db_build_worker admission_worker;
        uint8_t admission_secret[32], admission_key[32];
        ASSERT(build_fabric_worker_identity_load(
            workspace, &admission_worker,
            admission_secret, admission_key).ok);
        zcl_hex_encode(admission_key, 32, roots[8]);
        memset(admission_secret, 0, sizeof(admission_secret));
        struct ci_merkle *source_tree = ci_merkle_build_cold(workspace, NULL);
        struct ci_merkle_node source_tree_root;
        char indexed_source_root[65];
        ASSERT(source_tree != NULL);
        ASSERT(ci_merkle_root(source_tree, &source_tree_root));
        ci_merkle_hex(&source_tree_root.digest, indexed_source_root);
        ci_merkle_free(source_tree);
        uint8_t captured_source_root[32];
        ASSERT_EQ(vcs_tree_capture_path(workspace, captured_source_root),
                  VCS_OK);
        uint8_t captured_source_root_again[32];
        ASSERT_EQ(vcs_tree_capture_path(workspace, captured_source_root_again),
                  VCS_OK);
        ASSERT(memcmp(captured_source_root, captured_source_root_again, 32) ==
               0);
        struct vcs_manifest captured_manifest;
        ASSERT(vcs_tree_load(workspace, captured_source_root,
                             &captured_manifest));
        ASSERT_EQ(captured_manifest.count, 6);
        ASSERT_STR_EQ(captured_manifest.entries[0].path, "LICENSE");
        ASSERT_STR_EQ(captured_manifest.entries[1].path, "src/widget.c");
        ASSERT_STR_EQ(captured_manifest.entries[2].path, "test.false");
        ASSERT_STR_EQ(captured_manifest.entries[3].path, "test.true");
        ASSERT_STR_EQ(captured_manifest.entries[4].path, "unit.i");
        vcs_manifest_free(&captured_manifest);
        zcl_hex_encode(captured_source_root, 32, roots[0]);
        struct vcs_package_lock task_lock;
        vcs_package_lock_init(&task_lock);
        uint8_t fixture_dependency_root[32];
        zd_root(fixture_dependency_root, 209);
        task_lock.count = 2;
        memcpy(task_lock.nodes[0].root, fixture_dependency_root, 32);
        (void)snprintf(task_lock.nodes[0].name,
                       sizeof(task_lock.nodes[0].name), "publisher/dependency");
        (void)snprintf(task_lock.nodes[0].semver,
                       sizeof(task_lock.nodes[0].semver), "1.0.0");
        task_lock.nodes[0].depth = 1;
        memcpy(task_lock.nodes[1].root, captured_source_root, 32);
        (void)snprintf(task_lock.nodes[1].name,
                       sizeof(task_lock.nodes[1].name), "publisher/fixture");
        (void)snprintf(task_lock.nodes[1].semver,
                       sizeof(task_lock.nodes[1].semver), "1.0.0");
        task_lock.nodes[1].direct_deps = 1;
        uint8_t *task_lock_wire = NULL; size_t task_lock_wire_len = 0;
        uint8_t task_lock_root[32];
        ASSERT_EQ(vcs_package_lock_serialize(
                      &task_lock, &task_lock_wire, &task_lock_wire_len),
                  VCS_PACKAGE_DEPS_OK);
        ASSERT_EQ(vcs_package_lock_root(&task_lock, task_lock_root),
                  VCS_PACKAGE_DEPS_OK);
        zcl_hex_encode(task_lock_root, 32, roots[1]);
        char *task_lock_hex = zcl_malloc(
            task_lock_wire_len * 2u + 1u, "test.task_lock_hex");
        ASSERT(task_lock_hex != NULL);
        zcl_hex_encode(task_lock_wire, task_lock_wire_len, task_lock_hex);
        struct vcs_package_recipe task_recipe;
        vcs_package_recipe_init(&task_recipe);
        enum vcs_package_recipe_error recipe_error;
        ASSERT(vcs_package_recipe_add_source(
            &task_recipe, "src/widget.c", &recipe_error));
        vcs_package_recipe_set_test_limits(
            &task_recipe, 0, 30, UINT64_C(64) * 1024u * 1024u);
        uint8_t *task_recipe_wire = NULL; size_t task_recipe_wire_len = 0;
        uint8_t task_recipe_root[32];
        ASSERT_EQ(vcs_package_recipe_serialize(
                      &task_recipe, &task_recipe_wire,
                      &task_recipe_wire_len), VCS_PACKAGE_RECIPE_OK);
        ASSERT_EQ(vcs_package_recipe_root(&task_recipe, task_recipe_root),
                  VCS_PACKAGE_RECIPE_OK);
        zcl_hex_encode(task_recipe_root, 32, roots[3]);
        char *task_recipe_hex = zcl_malloc(
            task_recipe_wire_len * 2u + 1u, "test.task_recipe_hex");
        ASSERT(task_recipe_hex != NULL);
        zcl_hex_encode(task_recipe_wire, task_recipe_wire_len,
                       task_recipe_hex);
        vcs_package_recipe_free(&task_recipe);
        int64_t expires = (int64_t)platform_time_wall_unix() + 3600;
        int64_t candidate_created = expires - 3600;

        /* Planning is a model-neutral handoff. It needs no candidate, patch,
         * fixed executable, agent process, or ZBuild database mutation. */
        struct json_value plan_input;
        json_init(&plan_input); json_set_object(&plan_input);
        (void)json_push_kv_str(&plan_input, "mode", "plan");
        (void)json_push_kv_str(&plan_input, "workspace", workspace);
        (void)json_push_kv_str(&plan_input, "datadir", workspace);
        (void)json_push_kv_str(&plan_input, "dependency_lock_root", roots[1]);
        (void)json_push_kv_str(&plan_input, "dependency_lock_hex",
                               task_lock_hex);
        (void)json_push_kv_str(&plan_input, "write_scope_csv", "src");
        (void)json_push_kv_str(&plan_input, "acceptance_tests_root", roots[3]);
        (void)json_push_kv_str(&plan_input, "acceptance_recipe_hex",
                               task_recipe_hex);
        (void)json_push_kv_str(&plan_input, "model_policy_root", roots[4]);
        (void)json_push_kv_str(&plan_input, "goal",
                               "fix deterministic fixture");
        (void)json_push_kv_str(&plan_input, "proof_policy_hex", policy_hex);
        (void)json_push_kv_str(&plan_input, "context_symbol",
                               "context_widget");
        (void)json_push_kv_int(&plan_input, "expires_unix", expires);
        struct zcl_command_request plan_request = { .input = &plan_input };
        struct zcl_command_reply plan_reply;
        zcl_command_reply_init(&plan_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&plan_request, &plan_reply);
        ASSERT_EQ(plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&plan_reply.data, "mode")),
                      "plan");
        ASSERT_STR_EQ(json_get_str(json_get(&plan_reply.data, "state")),
                      "AWAITING_CANDIDATE");
        ASSERT_STR_EQ(json_get_str(json_get(&plan_reply.data, "authority")),
                      "TASK_CONTEXT_AND_SCOPE_ROOTS");
        const char *planned_task = json_get_str(json_get(
            &plan_reply.data, "task_root"));
        const char *planned_context = json_get_str(json_get(
            &plan_reply.data, "agent_context_root"));
        const char *planned_scope = json_get_str(json_get(
            &plan_reply.data, "write_scope_root"));
        ASSERT(planned_task && strlen(planned_task) == 64);
        ASSERT(planned_context && strlen(planned_context) == 64);
        ASSERT(planned_scope && strlen(planned_scope) == 64);
        ASSERT_STR_EQ(json_get_str(json_get(&plan_reply.data, "source_root")),
                      roots[0]);
        char planned_task_saved[65], planned_context_saved[65];
        char planned_scope_saved[65];
        (void)snprintf(planned_task_saved, sizeof(planned_task_saved), "%s",
                       planned_task);
        (void)snprintf(planned_context_saved,
                       sizeof(planned_context_saved), "%s", planned_context);
        (void)snprintf(planned_scope_saved, sizeof(planned_scope_saved), "%s",
                       planned_scope);
        ASSERT(json_get(&plan_reply.data, "candidate_root") == NULL);
        ASSERT(json_get(&plan_reply.data, "action_id") == NULL);
        char recipe_magic = task_recipe_hex[0];
        task_recipe_hex[0] = recipe_magic == '0' ? '1' : '0';
        json_set_str((struct json_value *)json_get(
                         &plan_input, "acceptance_recipe_hex"),
                     task_recipe_hex);
        struct zcl_command_reply corrupt_recipe_reply;
        zcl_command_reply_init(&corrupt_recipe_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&plan_request,
                                        &corrupt_recipe_reply);
        ASSERT_EQ(corrupt_recipe_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(corrupt_recipe_reply.error.code,
                      "TASK_AUTHORITY_REFUSED");
        zcl_command_reply_free(&corrupt_recipe_reply);
        task_recipe_hex[0] = recipe_magic;
        json_set_str((struct json_value *)json_get(
                         &plan_input, "acceptance_recipe_hex"),
                     task_recipe_hex);
        json_set_str((struct json_value *)json_get(
                         &plan_input, "acceptance_tests_root"), roots[5]);
        struct zcl_command_reply false_recipe_root_reply;
        zcl_command_reply_init(&false_recipe_root_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&plan_request,
                                        &false_recipe_root_reply);
        ASSERT_EQ(false_recipe_root_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(false_recipe_root_reply.error.code,
                      "TASK_AUTHORITY_ROOT_MISMATCH");
        zcl_command_reply_free(&false_recipe_root_reply);
        json_set_str((struct json_value *)json_get(
                         &plan_input, "acceptance_tests_root"), roots[3]);
        char plan_db[320];
        (void)snprintf(plan_db, sizeof(plan_db), "%s/node.db", workspace);
        ASSERT(access(plan_db, F_OK) != 0);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "mode", "admit");
        (void)json_push_kv_str(&input, "planned_task_root",
                               planned_task_saved);
        (void)json_push_kv_str(&input, "planned_context_root",
                               planned_context_saved);
        (void)json_push_kv_str(&input, "write_scope_csv", "src");
        (void)json_push_kv_str(&input, "workspace", workspace);
        (void)json_push_kv_str(&input, "datadir", workspace);
        (void)json_push_kv_str(&input, "candidate_workspace",
                               candidate_workspace);
        (void)json_push_kv_str(&input, "source_root", roots[0]);
        (void)json_push_kv_str(&input, "dependency_lock_root", roots[1]);
        (void)json_push_kv_str(&input, "dependency_lock_hex", task_lock_hex);
        (void)json_push_kv_str(&input, "write_scope_root",
                               planned_scope_saved);
        (void)json_push_kv_str(&input, "acceptance_tests_root", roots[3]);
        (void)json_push_kv_str(&input, "acceptance_recipe_hex",
                               task_recipe_hex);
        (void)json_push_kv_str(&input, "model_policy_root", roots[4]);
        (void)json_push_kv_str(&input, "adapter_policy_root", roots[7]);
        (void)json_push_kv_str(&input, "author_pubkey", roots[8]);
        (void)json_push_kv_int(&input, "remote_peer", 99);
        (void)json_push_kv_str(&input, "goal", "fix deterministic fixture");
        (void)json_push_kv_str(&input, "proof_policy_hex", policy_hex);
        (void)json_push_kv_str(&input, "fixed_input_path",
                               candidate_input_path);
        (void)json_push_kv_str(&input, "context_symbol", "context_widget");
        (void)json_push_kv_int(&input, "candidate_created_unix",
                               candidate_created);
        (void)json_push_kv_int(&input, "expires_unix", expires);
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const char *task_hex = json_get_str(json_get(&reply.data, "task_root"));
        const char *candidate_hex =
            json_get_str(json_get(&reply.data, "candidate_root"));
        const char *action_id = json_get_str(json_get(&reply.data, "action_id"));
        const char *agent_context_hex = json_get_str(json_get(
            &reply.data, "agent_context_root"));
        const char *candidate_source_hex = json_get_str(json_get(
            &reply.data, "candidate_source_root"));
        const char *patch_hex = json_get_str(json_get(
            &reply.data, "patch_root"));
        const char *candidate_sha256 = json_get_str(json_get(
            &reply.data, "candidate_source_sha256"));
        ASSERT(task_hex && candidate_hex && action_id && agent_context_hex &&
               candidate_source_hex && patch_hex && candidate_sha256);
        ASSERT(strlen(candidate_source_hex) == 64 && strlen(patch_hex) == 64 &&
               strlen(candidate_sha256) == 64);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "source_sha256_schema")),
                      VCS_SOURCE_MANIFEST_ID_SCHEMA);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "input_schema")),
                      "zcl.zcode.action_input.v1");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "fixed_input_relpath")), "unit.i");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "changed_files")), 1);
        ASSERT_EQ(json_get_int(json_get(
                      &reply.data, "patch_content_bytes")),
                  (int64_t)(sizeof(candidate_source) - 1u));
        char candidate_source_saved[65], patch_saved[65], sha256_saved[65];
        (void)snprintf(candidate_source_saved,
                       sizeof(candidate_source_saved), "%s",
                       candidate_source_hex);
        (void)snprintf(patch_saved, sizeof(patch_saved), "%s", patch_hex);
        (void)snprintf(sha256_saved, sizeof(sha256_saved), "%s",
                       candidate_sha256);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "mode")), "admit");
        ASSERT_STR_EQ(task_hex, planned_task);
        ASSERT_STR_EQ(agent_context_hex, planned_context);
        zcl_command_reply_free(&plan_reply);
        json_free(&plan_input);
        ASSERT(strlen(agent_context_hex) == 64);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "agent_context_source_tree_root")),
                      indexed_source_root);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "agent_context_symbol")),
                      "context_widget");
        ASSERT(json_get_int(json_get(
                   &reply.data, "agent_context_files")) >= 1);
        uint8_t scope_root[32], *scope_wire = NULL;
        size_t scope_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(planned_scope_saved, scope_root, 32));
        ASSERT_EQ(vcs_object_load_raw(workspace, scope_root, &scope_wire,
                                      &scope_wire_len), 0);
        struct vcs_zcode_write_scope_v1 stored_scope;
        ASSERT_EQ(vcs_zcode_write_scope_parse(
                      scope_wire, scope_wire_len, &stored_scope),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        free(scope_wire);
        ASSERT(vcs_zcode_write_scope_contains(&stored_scope,
                                               "src/widget.c"));
        ASSERT(!vcs_zcode_write_scope_contains(&stored_scope, "unit.i"));
        uint8_t patch_root[32], *patch_wire = NULL;
        size_t patch_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(patch_saved, patch_root, 32));
        ASSERT_EQ(vcs_object_load_raw(workspace, patch_root, &patch_wire,
                                      &patch_wire_len), 0);
        struct vcs_zcode_patch_v1 stored_patch;
        ASSERT_EQ(vcs_zcode_patch_parse(patch_wire, patch_wire_len,
                                        &stored_patch), VCS_ZCODE_PATCH_OK);
        free(patch_wire);
        ASSERT_EQ(stored_patch.count, 1);
        ASSERT_STR_EQ(stored_patch.changes[0].path, "src/widget.c");
        ASSERT_EQ(stored_patch.changes[0].kind, VCS_DIFF_MODIFIED);
        ASSERT(memcmp(stored_patch.base_source_root, captured_source_root,
                      32) == 0);
        vcs_zcode_patch_free(&stored_patch);
        (void)json_push_kv_str(&input, "patch_root", patch_saved);
        (void)json_push_kv_str(&input, "candidate_source_root",
                               candidate_source_saved);
        (void)json_push_kv_str(&input, "candidate_source_sha256",
                               sha256_saved);
        json_set_str((struct json_value *)json_get(&input, "mode"), "");
        struct zcl_command_reply legacy_reply;
        zcl_command_reply_init(&legacy_reply, "zcl.zcode_improve.v1");
        zd_boot_probe_calls = 0;
        node_db_set_quick_check_skip_probe(zd_count_boot_probe);
        zcl_native_handle_zcode_improve(&request, &legacy_reply);
        node_db_set_quick_check_skip_probe(NULL);
        ASSERT_EQ(zd_boot_probe_calls, 0);
        ASSERT_EQ(legacy_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&legacy_reply.data, "task_root")),
                      task_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&legacy_reply.data, "action_id")),
                      action_id);
        zcl_command_reply_free(&legacy_reply);
        json_set_str((struct json_value *)json_get(&input, "mode"), "admit");
        json_set_str((struct json_value *)json_get(
                         &input, "fixed_input_path"), "/usr/bin/true");
        struct zcl_command_reply detached_input_reply;
        zcl_command_reply_init(&detached_input_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &detached_input_reply);
        ASSERT_EQ(detached_input_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(detached_input_reply.error.code,
                      "FIXED_INPUT_OUTSIDE_CANDIDATE");
        zcl_command_reply_free(&detached_input_reply);
        json_set_str((struct json_value *)json_get(
                         &input, "fixed_input_path"), candidate_input_path);
        json_set_str((struct json_value *)json_get(&input, "patch_root"), "");
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_root"), "");
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_sha256"), "");
        ASSERT(unlink(candidate_source_path) == 0);
        struct zcl_command_reply missing_recipe_path_reply;
        zcl_command_reply_init(&missing_recipe_path_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request,
                                        &missing_recipe_path_reply);
        ASSERT_EQ(missing_recipe_path_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(missing_recipe_path_reply.error.code,
                      "CANDIDATE_RECIPE_REFUSED");
        zcl_command_reply_free(&missing_recipe_path_reply);
        source_file = fopen(candidate_source_path, "wb");
        ASSERT(source_file != NULL);
        ASSERT(fwrite(candidate_source, 1, sizeof(candidate_source) - 1u,
                      source_file) == sizeof(candidate_source) - 1u);
        ASSERT(fclose(source_file) == 0);
        char outside_path[4352];
        (void)snprintf(outside_path, sizeof(outside_path), "%s/outside.c",
                       candidate_workspace);
        FILE *outside_file = fopen(outside_path, "wb");
        ASSERT(outside_file != NULL);
        ASSERT(fwrite("int outside;\n", 1, 13, outside_file) == 13);
        ASSERT(fclose(outside_file) == 0);
        struct zcl_command_reply outside_reply;
        zcl_command_reply_init(&outside_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &outside_reply);
        ASSERT_EQ(outside_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(outside_reply.error.code, "PATCH_OUTSIDE_SCOPE");
        zcl_command_reply_free(&outside_reply);
        ASSERT(unlink(outside_path) == 0);
        json_set_str((struct json_value *)json_get(&input, "patch_root"),
                     roots[5]);
        struct zcl_command_reply false_claim_reply;
        zcl_command_reply_init(&false_claim_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &false_claim_reply);
        ASSERT_EQ(false_claim_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(false_claim_reply.error.code,
                      "CANDIDATE_ROOT_MISMATCH");
        zcl_command_reply_free(&false_claim_reply);
        json_set_str((struct json_value *)json_get(&input, "patch_root"),
                     patch_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_root"),
                     candidate_source_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_sha256"), sha256_saved);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "state")), "QUEUED");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "lane")), "FRONTIER");
        const char *frontier_receipt = json_get_str(json_get(
            &reply.data, "lane_receipt_root"));
        ASSERT(frontier_receipt && strlen(frontier_receipt) == 64);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "remote_outcome")),
                      "BACKGROUND_PENDING");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "async_proof_state")), "REQUESTED");
        const char *async_event = json_get_str(json_get(
            &reply.data, "async_proof_event_root"));
        ASSERT(async_event && strlen(async_event) == 64);
        uint8_t task_root[32], *task_wire = NULL;
        size_t task_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(task_hex, task_root, 32));
        ASSERT_EQ(vcs_object_load_raw(workspace, task_root, &task_wire,
                                      &task_wire_len), 0);
        struct vcs_zcode_task_v1 task;
        ASSERT_EQ(vcs_zcode_task_parse(task_wire, task_wire_len, &task),
                  VCS_ZCODE_DEV_OK);
        free(task_wire);
        ASSERT_EQ(task.expires_unix, expires);
        uint8_t agent_context_root[32], *agent_context_wire = NULL;
        size_t agent_context_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(agent_context_hex,
                                    agent_context_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, agent_context_root, &agent_context_wire,
                      &agent_context_wire_len), 0);
        struct vcs_zcode_agent_context_v1 agent_context;
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      agent_context_wire, agent_context_wire_len,
                      (size_t)task.max_context_bytes, &agent_context),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        free(agent_context_wire);
        ASSERT(memcmp(agent_context.task_root, task_root, 32) == 0);
        ASSERT(memcmp(agent_context.source_root, task.source_root, 32) == 0);
        ASSERT_STR_EQ(agent_context.query, "context_widget");
        ASSERT_STR_EQ(agent_context.files[0].path, "src/widget.c");
        ASSERT_EQ(agent_context.files[0].content_len,
                  sizeof(indexed_source) - 1u);
        ASSERT(memcmp(agent_context.files[0].content, indexed_source,
                      sizeof(indexed_source) - 1u) == 0);
        uint8_t agent_context_check[32];
        ASSERT_EQ(vcs_zcode_agent_context_root(
                      &agent_context, (size_t)task.max_context_bytes,
                      agent_context_check), VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT(memcmp(agent_context_root, agent_context_check, 32) == 0);
        vcs_zcode_agent_context_free(&agent_context);

        /* Context capture is source-authoritative and refuses a task whose
         * claimed source identity is stale before creating a ZBuild job. */
        json_set_str((struct json_value *)json_get(&input, "source_root"),
                     roots[1]);
        struct zcl_command_reply stale_reply;
        zcl_command_reply_init(&stale_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &stale_reply);
        ASSERT_EQ(stale_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(stale_reply.error.code, "SOURCE_ROOT_MISMATCH");
        zcl_command_reply_free(&stale_reply);
        json_set_str((struct json_value *)json_get(&input, "source_root"),
                     roots[0]);
        FILE *drift_file = fopen(source_path, "ab");
        ASSERT(drift_file != NULL);
        static const char drift[] = "/* drift */\n";
        ASSERT(fwrite(drift, 1, sizeof(drift) - 1u, drift_file) ==
               sizeof(drift) - 1u);
        ASSERT(fclose(drift_file) == 0);
        json_set_str((struct json_value *)json_get(&input, "source_root"), "");
        struct zcl_command_reply drift_reply;
        zcl_command_reply_init(&drift_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &drift_reply);
        ASSERT_EQ(drift_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(drift_reply.error.code, "PLANNED_TASK_MISMATCH");
        ASSERT_STR_EQ(drift_reply.error.message,
                      "admit parameters changed planned source_root");
        zcl_command_reply_free(&drift_reply);
        drift_file = fopen(source_path, "wb");
        ASSERT(drift_file != NULL);
        ASSERT(fwrite(indexed_source, 1, sizeof(indexed_source) - 1u,
                      drift_file) == sizeof(indexed_source) - 1u);
        ASSERT(fclose(drift_file) == 0);
        json_set_str((struct json_value *)json_get(&input, "source_root"),
                     roots[0]);
        json_set_str((struct json_value *)json_get(&input, "write_scope_csv"),
                     "include");
        json_set_str((struct json_value *)json_get(&input, "write_scope_root"),
                     "");
        struct zcl_command_reply scope_mismatch_reply;
        zcl_command_reply_init(&scope_mismatch_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &scope_mismatch_reply);
        ASSERT_EQ(scope_mismatch_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(scope_mismatch_reply.error.code,
                      "PLANNED_TASK_MISMATCH");
        ASSERT_STR_EQ(scope_mismatch_reply.error.message,
                      "admit parameters changed planned write_scope_root");
        zcl_command_reply_free(&scope_mismatch_reply);
        json_set_str((struct json_value *)json_get(&input, "write_scope_csv"),
                     "src");
        json_set_str((struct json_value *)json_get(&input, "write_scope_root"),
                     planned_scope_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "planned_context_root"), roots[1]);
        struct zcl_command_reply context_mismatch_reply;
        zcl_command_reply_init(&context_mismatch_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &context_mismatch_reply);
        ASSERT_EQ(context_mismatch_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(context_mismatch_reply.error.code,
                      "PLANNED_CONTEXT_MISMATCH");
        zcl_command_reply_free(&context_mismatch_reply);
        json_set_str((struct json_value *)json_get(
                         &input, "planned_context_root"),
                     planned_context_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "planned_task_root"), "");
        struct zcl_command_reply missing_binding_reply;
        zcl_command_reply_init(&missing_binding_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &missing_binding_reply);
        ASSERT_EQ(missing_binding_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(missing_binding_reply.error.code, "MISSING_INPUT");
        zcl_command_reply_free(&missing_binding_reply);
        json_set_str((struct json_value *)json_get(
                         &input, "planned_task_root"), planned_task_saved);
        json_set_str((struct json_value *)json_get(&input, "mode"), "invalid");
        struct zcl_command_reply mode_reply;
        zcl_command_reply_init(&mode_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &mode_reply);
        ASSERT_EQ(mode_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(mode_reply.error.code, "BAD_MODE");
        zcl_command_reply_free(&mode_reply);
        json_set_str((struct json_value *)json_get(&input, "mode"), "admit");
        char db_path[320];
        (void)snprintf(db_path, sizeof(db_path), "%s/node.db", workspace);
        struct node_db ndb = {0};
        ASSERT(node_db_open(&ndb, db_path));
        struct zcode_lane_status frontier_status;
        ASSERT(zcode_lane_find(&ndb, workspace, candidate_source_saved,
                               &frontier_status).ok);
        ASSERT_EQ(frontier_status.lane, VCS_ZCODE_LANE_FRONTIER);
        ASSERT_STR_EQ(frontier_status.lane_name, "FRONTIER");
        ASSERT_STR_EQ(frontier_status.receipt_root_sha3, frontier_receipt);
        ASSERT(frontier_status.capability[0] != '\0');
        ASSERT_STR_EQ(
            frontier_status.next_action,
            "zcode accept --input='<action_id and lane CANDIDATE>'");
        struct db_build_action action;
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "QUEUED");
        ASSERT_STR_EQ(action.task_root_sha3, task_hex);
        ASSERT_STR_EQ(action.candidate_root_sha3, candidate_hex);
        ASSERT_STR_EQ(action.context_root_sha3, "");
        uint8_t candidate_root[32], *candidate_wire = NULL;
        size_t candidate_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(candidate_hex, candidate_root, 32));
        ASSERT_EQ(vcs_object_load_raw(workspace, candidate_root,
                                      &candidate_wire,
                                      &candidate_wire_len), 0);
        struct vcs_zcode_candidate_v1 candidate;
        ASSERT_EQ(vcs_zcode_candidate_parse(candidate_wire,
                  candidate_wire_len, &candidate), VCS_ZCODE_DEV_OK);
        free(candidate_wire);
        uint8_t action_input_root[32], *action_input_wire = NULL;
        size_t action_input_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(action.input_root_sha3,
                                    action_input_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, action_input_root, &action_input_wire,
                      &action_input_wire_len), 0);
        struct vcs_zcode_action_input_v1 action_input;
        ASSERT_EQ(vcs_zcode_action_input_parse(
                      action_input_wire, action_input_wire_len,
                      &action_input), VCS_ZCODE_ACTION_INPUT_OK);
        uint8_t *corrupt_action_input = zcl_malloc(
            action_input_wire_len + 1u, "test.action_input.corrupt");
        ASSERT(corrupt_action_input != NULL);
        memcpy(corrupt_action_input, action_input_wire,
               action_input_wire_len);
        corrupt_action_input[action_input_wire_len - 1u] ^= 1u;
        struct vcs_zcode_action_input_v1 refused_action_input;
        ASSERT_EQ(vcs_zcode_action_input_parse(
                      corrupt_action_input, action_input_wire_len,
                      &refused_action_input),
                  VCS_ZCODE_ACTION_INPUT_BINDING);
        memcpy(corrupt_action_input, action_input_wire,
               action_input_wire_len);
        corrupt_action_input[action_input_wire_len] = 0;
        ASSERT_EQ(vcs_zcode_action_input_parse(
                      corrupt_action_input, action_input_wire_len + 1u,
                      &refused_action_input),
                  VCS_ZCODE_ACTION_INPUT_SHAPE);
        free(corrupt_action_input);
        free(action_input_wire);
        ASSERT_STR_EQ(action_input.path, "unit.i");
        uint8_t action_input_check[32];
        ASSERT_EQ(vcs_zcode_action_input_root(
                      &action_input, action_input_check),
                  VCS_ZCODE_ACTION_INPUT_OK);
        ASSERT(memcmp(action_input_check, action_input_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_action_input_validate_for_candidate(
                      workspace, &task, &candidate, &action_input,
                      task_root, candidate_root, VCS_ZCODE_WORK_BUILD),
                  VCS_ZCODE_ACTION_INPUT_OK);
        action_input.payload[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_action_input_validate_for_candidate(
                      workspace, &task, &candidate, &action_input,
                      task_root, candidate_root, VCS_ZCODE_WORK_BUILD),
                  VCS_ZCODE_ACTION_INPUT_BINDING);
        action_input.payload[0] ^= 1u;
        vcs_zcode_action_input_free(&action_input);
        ASSERT_EQ(vcs_zcode_patch_verify_cas(workspace, &task, &candidate),
                  VCS_ZCODE_PATCH_OK);
        struct vcs_zcode_candidate_v1 missing_patch = candidate;
        zd_root(missing_patch.patch_root, 201);
        ASSERT_EQ(vcs_zcode_patch_verify_cas(
                      workspace, &task, &missing_patch),
                  VCS_ZCODE_PATCH_CAS);
        uint8_t *authority_bundle = NULL, *authority_bundle_again = NULL;
        size_t authority_bundle_len = 0, authority_bundle_again_len = 0;
        ASSERT_EQ(vcs_zcode_candidate_bundle_export(
                      workspace, &task, &candidate, &authority_bundle,
                      &authority_bundle_len),
                  VCS_ZCODE_CANDIDATE_BUNDLE_OK);
        ASSERT_EQ(vcs_zcode_candidate_bundle_export(
                      workspace, &task, &candidate, &authority_bundle_again,
                      &authority_bundle_again_len),
                  VCS_ZCODE_CANDIDATE_BUNDLE_OK);
        ASSERT_EQ(authority_bundle_len, authority_bundle_again_len);
        ASSERT(memcmp(authority_bundle, authority_bundle_again,
                      authority_bundle_len) == 0);
        free(authority_bundle_again);
        char transfer_dir[256], receiver[256], corrupt_receiver[256];
        char task_corrupt_receiver[256], task_mismatch_receiver[256];
        test_make_tmpdir(transfer_dir, sizeof(transfer_dir), "zcode_dev",
                         "authority_transfer");
        struct vcs_package_store *transfer_store = vcs_package_store_open(
            transfer_dir, UINT64_C(256) * 1024u * 1024u);
        ASSERT(transfer_store != NULL);
        struct vcs_zcode_work_context_v1 transfer;
        vcs_zcode_work_context_init(&transfer);
        transfer.task = task; transfer.candidate = candidate;
        transfer.proof_policy = policy;
        ASSERT(zcl_hex_decode_lower(sha256_saved, transfer.source_sha256, 32));
        (void)snprintf(transfer.profile, sizeof(transfer.profile), "dev");
        transfer.fixed_input_len = sizeof(source) - 1u;
        transfer.fixed_input = zcl_malloc(transfer.fixed_input_len,
                                          "test.transfer.input");
        ASSERT(transfer.fixed_input != NULL);
        memcpy(transfer.fixed_input, source, transfer.fixed_input_len);
        transfer.candidate_authority_len = authority_bundle_len;
        transfer.candidate_authority = zcl_malloc(
            authority_bundle_len, "test.transfer.authority");
        ASSERT(transfer.candidate_authority != NULL);
        memcpy(transfer.candidate_authority, authority_bundle,
               authority_bundle_len);
        ASSERT_EQ(vcs_zcode_task_authority_bundle_export(
                      workspace, &task, &transfer.task_authority,
                      &transfer.task_authority_len),
                  VCS_ZCODE_TASK_AUTHORITY_OK);
        struct vcs_package_manifest bounded_tree_manifest;
        vcs_package_manifest_init(&bounded_tree_manifest);
        uint64_t bounded_tree_bytes = 0;
        ASSERT_EQ(vcs_zcode_candidate_tree_add_manifest(
                      workspace, &task, &candidate, 1,
                      &bounded_tree_manifest, &bounded_tree_bytes),
                  VCS_ZCODE_CANDIDATE_TREE_LIMIT);
        vcs_package_manifest_free(&bounded_tree_manifest);
        uint8_t transfer_root[32], transfer_action[32];
        int64_t transfer_now = (int64_t)platform_time_wall_unix();
        ASSERT_EQ(vcs_zcode_work_context_put_for_kind_with_candidate(
                      transfer_store, &transfer, VCS_BUILD_ACTION_KIND_V1,
                      transfer_now, workspace, transfer_root,
                      transfer_action),
                  VCS_ZCODE_WORK_CONTEXT_OK);
        uint8_t *transfer_manifest_wire = NULL;
        size_t transfer_manifest_len = 0;
        ASSERT_EQ(vcs_package_store_get_manifest_wire(
                      transfer_store, transfer_root,
                      &transfer_manifest_wire, &transfer_manifest_len),
                  VCS_PACKAGE_STORE_OK);
        struct vcs_package_manifest transfer_manifest;
        ASSERT(vcs_package_manifest_parse(
            transfer_manifest_wire, transfer_manifest_len,
            &transfer_manifest));
        ASSERT_EQ(transfer_manifest.count, 9);
        vcs_package_manifest_free(&transfer_manifest);
        free(transfer_manifest_wire);
        struct vcs_zcode_work_context_v1 received_transfer;
        ASSERT_EQ(vcs_zcode_work_context_get(
                      transfer_store, transfer_root, transfer_now,
                      &received_transfer), VCS_ZCODE_WORK_CONTEXT_OK);
        ASSERT_EQ(received_transfer.candidate_authority_len,
                  authority_bundle_len);
        ASSERT(received_transfer.task_authority_len > 0);
        test_make_tmpdir(receiver, sizeof(receiver), "zcode_dev",
                         "authority_receiver");
        ASSERT_EQ(vcs_zcode_task_authority_bundle_import(
                      receiver, &received_transfer.task,
                      received_transfer.task_authority,
                      received_transfer.task_authority_len),
                  VCS_ZCODE_TASK_AUTHORITY_OK);
        ASSERT_EQ(vcs_zcode_candidate_bundle_import(
                      receiver, &received_transfer.task,
                      &received_transfer.candidate,
                      received_transfer.candidate_authority,
                      received_transfer.candidate_authority_len),
                  VCS_ZCODE_CANDIDATE_BUNDLE_OK);
        struct vcs_manifest remote_candidate_manifest;
        ASSERT(vcs_tree_load(receiver, candidate.candidate_source_root,
                             &remote_candidate_manifest));
        const struct vcs_entry *unchanged_input = NULL;
        for (size_t i = 0; i < remote_candidate_manifest.count; i++)
            if (strcmp(remote_candidate_manifest.entries[i].path,
                       "unit.i") == 0)
                unchanged_input = &remote_candidate_manifest.entries[i];
        ASSERT(unchanged_input != NULL);
        uint8_t unchanged_blob[32];
        memcpy(unchanged_blob, unchanged_input->blob, 32);
        ASSERT(!vcs_object_has(receiver, unchanged_blob));
        vcs_manifest_free(&remote_candidate_manifest);
        ASSERT_EQ(vcs_zcode_candidate_tree_import(
                      transfer_store, transfer_root, receiver, &task,
                      &candidate), VCS_ZCODE_CANDIDATE_TREE_OK);
        ASSERT(vcs_object_has(receiver, unchanged_blob));
        ASSERT_EQ(vcs_zcode_patch_verify_cas(receiver, &task, &candidate),
                  VCS_ZCODE_PATCH_OK);
        ASSERT_EQ(vcs_zcode_task_authority_validate_for_candidate(
                      receiver, &task, &candidate),
                  VCS_ZCODE_TASK_AUTHORITY_OK);
        struct vcs_zcode_task_v1 mismatched_task = received_transfer.task;
        mismatched_task.acceptance_tests_root[0] ^= 1u;
        test_make_tmpdir(task_mismatch_receiver,
                         sizeof(task_mismatch_receiver), "zcode_dev",
                         "task_authority_mismatch");
        ASSERT_EQ(vcs_zcode_task_authority_bundle_import(
                      task_mismatch_receiver, &mismatched_task,
                      received_transfer.task_authority,
                      received_transfer.task_authority_len),
                  VCS_ZCODE_TASK_AUTHORITY_CAS);
        ASSERT(!vcs_object_has(task_mismatch_receiver,
                               task.dependency_lock_root));
        received_transfer.task_authority[
            received_transfer.task_authority_len - 1u] ^= 1u;
        test_make_tmpdir(task_corrupt_receiver,
                         sizeof(task_corrupt_receiver), "zcode_dev",
                         "task_authority_corrupt");
        ASSERT(vcs_zcode_task_authority_bundle_import(
                   task_corrupt_receiver, &received_transfer.task,
                   received_transfer.task_authority,
                   received_transfer.task_authority_len) !=
               VCS_ZCODE_TASK_AUTHORITY_OK);
        ASSERT(!vcs_object_has(task_corrupt_receiver,
                               task.dependency_lock_root));
        received_transfer.task_authority[
            received_transfer.task_authority_len - 1u] ^= 1u;
        vcs_zcode_work_context_free(&received_transfer);
        vcs_zcode_work_context_free(&transfer);
        vcs_package_store_close(transfer_store);
        test_rm_rf(transfer_dir);
        authority_bundle[authority_bundle_len - 1u] ^= 1u;
        test_make_tmpdir(corrupt_receiver, sizeof(corrupt_receiver),
                         "zcode_dev", "authority_corrupt");
        ASSERT_EQ(vcs_zcode_candidate_bundle_import(
                      corrupt_receiver, &task, &candidate, authority_bundle,
                      authority_bundle_len),
                  VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY);
        ASSERT(!vcs_object_has(corrupt_receiver, candidate.patch_root));
        free(authority_bundle);
        test_rm_rf(task_mismatch_receiver); test_rm_rf(task_corrupt_receiver);
        test_rm_rf(corrupt_receiver);
        test_rm_rf(receiver);
        struct db_build_worker worker;
        uint8_t worker_secret[32], worker_key[32];
        ASSERT(build_fabric_worker_identity_load(
            workspace, &worker, worker_secret, worker_key).ok);
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(build_fabric_worker_approve(&ndb, &worker, now).ok);
        uint8_t lease_root[32]; char lease_hex[65];
        zd_root(lease_root, 60); zcl_hex_encode(lease_root, 32, lease_hex);
        bool claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, lease_hex, now,
                                  300, &action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt receipt;
        ASSERT(build_fabric_worker_execute(
            &ndb, workspace, workspace, action_id, lease_hex, worker_secret,
            worker_key, &receipt, NULL).ok);
        ASSERT(build_fabric_receipt_admit(
            &ndb, workspace, receipt.receipt_id, now + 1).ok);
        ASSERT(strlen(receipt.work_receipt_sha3) == 64);
        uint8_t receipt_root[32], *receipt_wire = NULL;
        size_t receipt_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(receipt.work_receipt_sha3,
                                    receipt_root, 32));
        ASSERT_EQ(vcs_object_load_raw(workspace, receipt_root, &receipt_wire,
                                      &receipt_wire_len), 0);
        struct vcs_zcode_work_receipt_v1 work_receipt;
        ASSERT_EQ(vcs_zcode_work_receipt_parse(
            receipt_wire, receipt_wire_len, &work_receipt), VCS_ZCODE_DEV_OK);
        free(receipt_wire);
        ASSERT_EQ(vcs_zcode_work_receipt_verify(&work_receipt, worker_key),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
            &task, &candidate, &work_receipt,
            (int64_t)platform_time_wall_unix()), VCS_ZCODE_DEV_OK);
        uint8_t compile_output_root[32];
        memcpy(compile_output_root, work_receipt.output_root, 32);

        /* Install one receipt-checked dependency closure member. The recipe
         * action must refuse if either this report or its output bytes drift. */
        char dependency_hex[65], installed_dir[512], installed_lib[560];
        char installed_archive[640], installed_report[640];
        zcl_hex_encode(fixture_dependency_root, 32, dependency_hex);
        (void)snprintf(installed_dir, sizeof(installed_dir),
                       "%s/zcode/installed", workspace);
        ASSERT(mkdir(installed_dir, 0700) == 0 || errno == EEXIST);
        (void)snprintf(installed_dir, sizeof(installed_dir),
                       "%s/zcode/installed/%s", workspace, dependency_hex);
        ASSERT(mkdir(installed_dir, 0700) == 0);
        (void)snprintf(installed_lib, sizeof(installed_lib), "%s/lib",
                       installed_dir);
        ASSERT(mkdir(installed_lib, 0700) == 0);
        (void)snprintf(installed_archive, sizeof(installed_archive),
                       "%s/libdependency.a", installed_lib);
        static const uint8_t dependency_bytes[] = "fixed-dependency-artifact";
        FILE *dependency_file = fopen(installed_archive, "wb");
        ASSERT(dependency_file != NULL);
        ASSERT(fwrite(dependency_bytes, 1, sizeof(dependency_bytes) - 1u,
                      dependency_file) == sizeof(dependency_bytes) - 1u);
        ASSERT(fclose(dependency_file) == 0);
        struct vcs_package_build_receipt dependency_receipt;
        vcs_package_build_receipt_init(&dependency_receipt);
        memcpy(dependency_receipt.package_root, fixture_dependency_root, 32);
        zd_root(dependency_receipt.recipe_root, 211);
        zd_root(dependency_receipt.lock_root, 212);
        (void)snprintf(dependency_receipt.compiler_id,
                       sizeof(dependency_receipt.compiler_id), "gcc");
        (void)snprintf(dependency_receipt.compiler_version,
                       sizeof(dependency_receipt.compiler_version), "fixture");
        (void)snprintf(dependency_receipt.flags,
                       sizeof(dependency_receipt.flags), "-std=c23 -O1 -c");
        dependency_receipt.result_class =
            VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
        dependency_receipt.isolation = VCS_PACKAGE_BUILD_ISOLATION_FULL;
        uint8_t dependency_sha[32];
        sha3_256(dependency_bytes, sizeof(dependency_bytes) - 1u,
                 dependency_sha);
        ASSERT_EQ(vcs_package_build_add_output(
                      &dependency_receipt, "lib/libdependency.a",
                      dependency_sha, sizeof(dependency_bytes) - 1u),
                  VCS_PACKAGE_BUILD_OK);
        uint8_t *dependency_report_wire = NULL;
        size_t dependency_report_len = 0;
        ASSERT_EQ(vcs_package_build_serialize(
                      &dependency_receipt, &dependency_report_wire,
                      &dependency_report_len), VCS_PACKAGE_BUILD_OK);
        (void)snprintf(installed_report, sizeof(installed_report),
                       "%s/build-report", installed_dir);
        dependency_file = fopen(installed_report, "wb");
        ASSERT(dependency_file != NULL);
        ASSERT(fwrite(dependency_report_wire, 1, dependency_report_len,
                      dependency_file) == dependency_report_len);
        ASSERT(fclose(dependency_file) == 0);
        free(dependency_report_wire);

        /* The recipe-package action accepts no prebuilt executable. It
         * rebuilds the complete candidate tree selected by the canonical
         * recipe and emits a checked package build receipt. */
        (void)json_push_kv_str(&input, "action_kind",
                               VCS_BUILD_ACTION_KIND_PACKAGE_V1);
        struct zcl_command_reply package_prebuilt_reply;
        zcl_command_reply_init(&package_prebuilt_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &package_prebuilt_reply);
        ASSERT_EQ(package_prebuilt_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(package_prebuilt_reply.error.code, "BAD_ACTION_INPUT");
        zcl_command_reply_free(&package_prebuilt_reply);
        json_set_str((struct json_value *)json_get(
                         &input, "fixed_input_path"), "");
        struct zcl_command_reply package_reply;
        zcl_command_reply_init(&package_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &package_reply);
        ASSERT_EQ(package_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &package_reply.data, "input_schema")),
                      "zcl.zcode.package_action_input.v1");
        ASSERT(json_get(&package_reply.data, "fixed_input_relpath") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &package_reply.data, "action_kind")),
                      VCS_BUILD_ACTION_KIND_PACKAGE_V1);
        const char *package_action_id = json_get_str(json_get(
            &package_reply.data, "action_id"));
        ASSERT(package_action_id && strcmp(package_action_id, action_id) != 0);
        char package_action_saved[65];
        (void)snprintf(package_action_saved, sizeof(package_action_saved),
                       "%s", package_action_id);
        struct db_build_action package_action_row;
        ASSERT(db_build_action_find(&ndb, package_action_saved,
                                    &package_action_row));
        uint8_t package_input_root[32], *package_input_wire = NULL;
        size_t package_input_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(package_action_row.input_root_sha3,
                                    package_input_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, package_input_root, &package_input_wire,
                      &package_input_wire_len), 0);
        struct vcs_zcode_package_action_input_v1 package_input;
        ASSERT_EQ(vcs_zcode_package_action_input_parse(
                      package_input_wire, package_input_wire_len,
                      &package_input), VCS_ZCODE_ACTION_INPUT_OK);
        uint8_t package_input_corrupt[
            VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES + 1u];
        memcpy(package_input_corrupt, package_input_wire,
               package_input_wire_len);
        package_input_corrupt[package_input_wire_len] = 0;
        struct vcs_zcode_package_action_input_v1 refused_package_input;
        ASSERT_EQ(vcs_zcode_package_action_input_parse(
                      package_input_corrupt, package_input_wire_len + 1u,
                      &refused_package_input),
                  VCS_ZCODE_ACTION_INPUT_SHAPE);
        package_input_corrupt[10] = 1;
        ASSERT_EQ(vcs_zcode_package_action_input_parse(
                      package_input_corrupt, package_input_wire_len,
                      &refused_package_input),
                  VCS_ZCODE_ACTION_INPUT_SHAPE);
        free(package_input_wire);
        ASSERT_EQ(vcs_zcode_package_action_input_validate_for_candidate(
                      workspace, &task, &candidate, &package_input,
                      task_root, candidate_root),
                  VCS_ZCODE_ACTION_INPUT_OK);
        package_input.base_source_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_package_action_input_validate_for_candidate(
                      workspace, &task, &candidate, &package_input,
                      task_root, candidate_root),
                  VCS_ZCODE_ACTION_INPUT_BINDING);
        uint8_t package_lease_root[32]; char package_lease_hex[65];
        zd_root(package_lease_root, 64);
        zcl_hex_encode(package_lease_root, 32, package_lease_hex);
        claimed = false;
        ASSERT(build_fabric_claim(
            &ndb, worker.worker_id, package_lease_hex, now, 300,
            &package_action_row, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt package_receipt;
        struct zcl_result package_executed = build_fabric_worker_execute(
            &ndb, workspace, workspace, package_action_saved,
            package_lease_hex, worker_secret, worker_key, &package_receipt,
            NULL);
        if (!package_executed.ok)
            printf("package worker detail: %s\n", package_executed.message);
        ASSERT(package_executed.ok);
        ASSERT_EQ(package_receipt.exit_status, 0);
        ASSERT_STR_EQ(package_receipt.confinement,
                      "landlock=1,seccomp=1,rlimits=1,network=0,package=recipe,source=cas,dependencies=receipted");
        uint8_t package_work_root[32];
        ASSERT(zcl_hex_decode_lower(package_receipt.work_receipt_sha3,
                                    package_work_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, package_work_root, &receipt_wire,
                      &receipt_wire_len), 0);
        ASSERT_EQ(vcs_zcode_work_receipt_parse(
                      receipt_wire, receipt_wire_len, &work_receipt),
                  VCS_ZCODE_DEV_OK);
        free(receipt_wire); receipt_wire = NULL;
        ASSERT_EQ(work_receipt.work_kind, VCS_ZCODE_WORK_BUILD);
        ASSERT_EQ(work_receipt.status, VCS_ZCODE_WORK_PASS);
        uint8_t *artifact_wire = NULL; size_t artifact_wire_len = 0;
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, work_receipt.output_root, &artifact_wire,
                      &artifact_wire_len), 0);
        struct vcs_build_artifact_manifest_v1 artifact;
        ASSERT(vcs_build_artifact_manifest_v1_parse(
            artifact_wire, artifact_wire_len, &artifact));
        free(artifact_wire);
        ASSERT_EQ(artifact.chunk_count, 1);
        uint8_t *build_report = NULL; size_t build_report_len = 0;
        ASSERT_EQ(vcs_object_load_raw(
                      workspace, artifact.chunk_sha3[0], &build_report,
                      &build_report_len), 0);
        ASSERT(vcs_build_artifact_manifest_v1_verify_chunk(
            &artifact, 0, build_report, build_report_len));
        struct vcs_package_build_receipt package_build;
        ASSERT_EQ(vcs_package_build_parse(
                      build_report, build_report_len, &package_build),
                  VCS_PACKAGE_BUILD_OK);
        free(build_report);
        ASSERT(memcmp(package_build.package_root,
                      candidate.candidate_source_root, 32) == 0);
        ASSERT(memcmp(package_build.recipe_root,
                      task.acceptance_tests_root, 32) == 0);
        ASSERT(memcmp(package_build.lock_root,
                      task.dependency_lock_root, 32) == 0);
        ASSERT_EQ(package_build.dep_count, 1);
        ASSERT(memcmp(package_build.dep_roots[0], fixture_dependency_root,
                      32) == 0);
        ASSERT_EQ(package_build.result_class,
                  VCS_PACKAGE_BUILD_RESULT_BUILD_PASS);
        ASSERT_EQ(package_build.output_count, 1);
        ASSERT_STR_EQ(package_build.outputs[0].path,
                      "lib/libfixture.a");

        dependency_file = fopen(installed_archive, "ab");
        ASSERT(dependency_file != NULL);
        ASSERT(fputc('x', dependency_file) == 'x');
        ASSERT(fclose(dependency_file) == 0);
        (void)json_push_kv_int(&input, "candidate_sequence", 2);
        dependency_file = fopen(candidate_source_path, "wb");
        ASSERT(dependency_file != NULL);
        static const char candidate_source_v2[] =
            "int context_widget(int x) { return x + 3; }\n";
        ASSERT(fwrite(candidate_source_v2, 1,
                      sizeof(candidate_source_v2) - 1u, dependency_file) ==
               sizeof(candidate_source_v2) - 1u);
        ASSERT(fclose(dependency_file) == 0);
        json_set_str((struct json_value *)json_get(&input, "patch_root"), "");
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_root"), "");
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_sha256"), "");
        struct zcl_command_reply dependency_drift_reply;
        zcl_command_reply_init(&dependency_drift_reply,
                               "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &dependency_drift_reply);
        if (dependency_drift_reply.exit_code != ZCL_COMMAND_EXIT_OK)
            printf("dependency drift admit: %s: %s\n",
                   dependency_drift_reply.error.code,
                   dependency_drift_reply.error.message);
        ASSERT_EQ(dependency_drift_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        dependency_file = fopen(candidate_source_path, "wb");
        ASSERT(dependency_file != NULL);
        ASSERT(fwrite(candidate_source, 1, sizeof(candidate_source) - 1u,
                      dependency_file) == sizeof(candidate_source) - 1u);
        ASSERT(fclose(dependency_file) == 0);
        json_set_str((struct json_value *)json_get(&input, "patch_root"),
                     patch_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_root"),
                     candidate_source_saved);
        json_set_str((struct json_value *)json_get(
                         &input, "candidate_source_sha256"), sha256_saved);
        const char *dependency_drift_action = json_get_str(json_get(
            &dependency_drift_reply.data, "action_id"));
        ASSERT(dependency_drift_action &&
               strcmp(dependency_drift_action, package_action_saved) != 0);
        struct db_build_action dependency_drift_row;
        ASSERT(db_build_action_find(&ndb, dependency_drift_action,
                                    &dependency_drift_row));
        uint8_t drift_lease_root[32]; char drift_lease_hex[65];
        zd_root(drift_lease_root, 65);
        zcl_hex_encode(drift_lease_root, 32, drift_lease_hex);
        claimed = false;
        ASSERT(build_fabric_claim(
            &ndb, worker.worker_id, drift_lease_hex, now, 300,
            &dependency_drift_row, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt refused_dependency_receipt;
        struct zcl_result dependency_refused = build_fabric_worker_execute(
            &ndb, workspace, workspace, dependency_drift_action,
            drift_lease_hex, worker_secret, worker_key,
            &refused_dependency_receipt, NULL);
        ASSERT(!dependency_refused.ok);
        ASSERT(strstr(dependency_refused.message,
                      "dependency-output-mismatch") != NULL);
        ASSERT(db_build_action_find(&ndb, dependency_drift_action,
                                    &dependency_drift_row));
        ASSERT_STR_EQ(dependency_drift_row.state, "LOCAL_FALLBACK");
        zcl_command_reply_free(&dependency_drift_reply);
        dependency_file = fopen(installed_archive, "wb");
        ASSERT(dependency_file != NULL);
        ASSERT(fwrite(dependency_bytes, 1, sizeof(dependency_bytes) - 1u,
                      dependency_file) == sizeof(dependency_bytes) - 1u);
        ASSERT(fclose(dependency_file) == 0);
        json_set_int((struct json_value *)json_get(
                         &input, "candidate_sequence"), 1);
        zcl_command_reply_free(&package_reply);

        /* Reuse the exact candidate timestamp to queue a second fixed proof
         * action in a distinct job. Evidence aggregation is candidate-bound,
         * not accidentally job-bound. */
        ASSERT_EQ(json_get_int(json_get(
                      &reply.data, "candidate_created_unix")),
                  candidate_created);
        json_set_str((struct json_value *)json_get(
                         &input, "fixed_input_path"), candidate_true);
        json_set_str((struct json_value *)json_get(&input, "action_kind"),
                     VCS_BUILD_ACTION_KIND_TEST_V1);
        struct zcl_command_reply test_reply;
        zcl_command_reply_init(&test_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &test_reply);
        ASSERT_EQ(test_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&test_reply.data, "task_root")),
                      task_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &test_reply.data, "agent_context_root")),
                      agent_context_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &test_reply.data, "candidate_root")), candidate_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &test_reply.data, "action_kind")),
                      VCS_BUILD_ACTION_KIND_TEST_V1);
        const char *test_action_id = json_get_str(json_get(
            &test_reply.data, "action_id"));
        ASSERT(test_action_id && strcmp(test_action_id, action_id) != 0);
        char test_action_id_saved[65];
        (void)snprintf(test_action_id_saved, sizeof(test_action_id_saved),
                       "%s", test_action_id);
        struct db_build_action local_test_action;
        ASSERT(db_build_action_find(&ndb, test_action_id,
                                    &local_test_action));
        uint8_t test_lease_root[32]; char test_lease_hex[65];
        zd_root(test_lease_root, 61);
        zcl_hex_encode(test_lease_root, 32, test_lease_hex);
        claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, test_lease_hex,
                                  now, 300, &local_test_action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt local_test_receipt;
        ASSERT(build_fabric_worker_execute(
            &ndb, workspace, workspace, test_action_id, test_lease_hex,
            worker_secret, worker_key, &local_test_receipt, NULL).ok);
        uint8_t local_test_receipt_root[32];
        ASSERT(zcl_hex_decode_lower(local_test_receipt.work_receipt_sha3,
                                    local_test_receipt_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            workspace, local_test_receipt_root, &receipt_wire,
            &receipt_wire_len), 0);
        ASSERT_EQ(vcs_zcode_work_receipt_parse(
            receipt_wire, receipt_wire_len, &work_receipt),
            VCS_ZCODE_DEV_OK);
        free(receipt_wire); receipt_wire = NULL;
        ASSERT_EQ(work_receipt.work_kind, VCS_ZCODE_WORK_TEST);
        ASSERT_EQ(work_receipt.status, VCS_ZCODE_WORK_PASS);
        zcl_command_reply_free(&test_reply);

        /* The same immutable candidate also executes the policy's exact
         * deterministic seed range in the fixed fuzz sandbox. */
        json_set_str((struct json_value *)json_get(&input, "action_kind"),
                     VCS_BUILD_ACTION_KIND_FUZZ_V1);
        struct zcl_command_reply fuzz_reply;
        zcl_command_reply_init(&fuzz_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &fuzz_reply);
        ASSERT_EQ(fuzz_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&fuzz_reply.data, "task_root")),
                      task_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &fuzz_reply.data, "candidate_root")), candidate_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &fuzz_reply.data, "action_kind")),
                      VCS_BUILD_ACTION_KIND_FUZZ_V1);
        const char *local_fuzz_action_id = json_get_str(json_get(
            &fuzz_reply.data, "action_id"));
        ASSERT(local_fuzz_action_id &&
               strcmp(local_fuzz_action_id, action_id) != 0 &&
               strcmp(local_fuzz_action_id, test_action_id_saved) != 0);
        char local_fuzz_action_id_saved[65];
        (void)snprintf(local_fuzz_action_id_saved,
                       sizeof(local_fuzz_action_id_saved), "%s",
                       local_fuzz_action_id);
        struct db_build_action local_fuzz_action;
        ASSERT(db_build_action_find(&ndb, local_fuzz_action_id,
                                    &local_fuzz_action));
        uint8_t fuzz_lease_root[32]; char fuzz_lease_hex[65];
        zd_root(fuzz_lease_root, 62);
        zcl_hex_encode(fuzz_lease_root, 32, fuzz_lease_hex);
        claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, fuzz_lease_hex,
                                  now, 300, &local_fuzz_action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt local_fuzz_receipt;
        ASSERT(build_fabric_worker_execute(
            &ndb, workspace, workspace, local_fuzz_action_id, fuzz_lease_hex,
            worker_secret, worker_key, &local_fuzz_receipt, NULL).ok);
        uint8_t local_fuzz_receipt_root[32];
        ASSERT(zcl_hex_decode_lower(local_fuzz_receipt.work_receipt_sha3,
                                    local_fuzz_receipt_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            workspace, local_fuzz_receipt_root, &receipt_wire,
            &receipt_wire_len), 0);
        ASSERT_EQ(vcs_zcode_work_receipt_parse(
            receipt_wire, receipt_wire_len, &work_receipt),
            VCS_ZCODE_DEV_OK);
        free(receipt_wire); receipt_wire = NULL;
        ASSERT_EQ(work_receipt.work_kind, VCS_ZCODE_WORK_FUZZ);
        ASSERT_EQ(work_receipt.status, VCS_ZCODE_WORK_PASS);
        zcl_command_reply_free(&fuzz_reply);

        /* A target-found defect is durable FAIL evidence, not a sandbox
         * transport error and never a false passing proof. */
        json_set_str((struct json_value *)json_get(
                         &input, "fixed_input_path"), candidate_false);
        struct zcl_command_reply fuzz_fail_reply;
        zcl_command_reply_init(&fuzz_fail_reply, "zcl.zcode_improve.v1");
        zcl_native_handle_zcode_improve(&request, &fuzz_fail_reply);
        ASSERT_EQ(fuzz_fail_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const char *fuzz_fail_action_id = json_get_str(json_get(
            &fuzz_fail_reply.data, "action_id"));
        ASSERT(fuzz_fail_action_id &&
               strcmp(fuzz_fail_action_id,
                      local_fuzz_action_id_saved) != 0);
        struct db_build_action fuzz_fail_action;
        ASSERT(db_build_action_find(&ndb, fuzz_fail_action_id,
                                    &fuzz_fail_action));
        uint8_t fail_lease_root[32]; char fail_lease_hex[65];
        zd_root(fail_lease_root, 63);
        zcl_hex_encode(fail_lease_root, 32, fail_lease_hex);
        claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, fail_lease_hex,
                                  now, 300, &fuzz_fail_action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt fuzz_fail_receipt;
        ASSERT(build_fabric_worker_execute(
            &ndb, workspace, workspace, fuzz_fail_action_id, fail_lease_hex,
            worker_secret, worker_key, &fuzz_fail_receipt, NULL).ok);
        ASSERT_EQ(fuzz_fail_receipt.exit_status, 1);
        ASSERT(db_build_action_find(&ndb, fuzz_fail_action_id,
                                    &fuzz_fail_action));
        ASSERT_STR_EQ(fuzz_fail_action.state, "VERIFYING");
        ASSERT(build_fabric_receipt_admit(
            &ndb, workspace, fuzz_fail_receipt.receipt_id, now + 1).ok);
        ASSERT(db_build_action_find(&ndb, fuzz_fail_action_id,
                                    &fuzz_fail_action));
        ASSERT_STR_EQ(fuzz_fail_action.state, "FAILED");
        ASSERT(zcl_hex_decode_lower(fuzz_fail_receipt.work_receipt_sha3,
                                    local_fuzz_receipt_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            workspace, local_fuzz_receipt_root, &receipt_wire,
            &receipt_wire_len), 0);
        ASSERT_EQ(vcs_zcode_work_receipt_parse(
            receipt_wire, receipt_wire_len, &work_receipt),
            VCS_ZCODE_DEV_OK);
        free(receipt_wire); receipt_wire = NULL;
        ASSERT_EQ(work_receipt.work_kind, VCS_ZCODE_WORK_FUZZ);
        ASSERT_EQ(work_receipt.status, VCS_ZCODE_WORK_FAIL);
        zcl_command_reply_free(&fuzz_fail_reply);

        struct vcs_zcode_work_request_v1 remote_request = {
            .request_id = 991,
            .work_kind = VCS_ZCODE_WORK_BUILD,
            .target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3,
            .max_cpu_seconds = 60,
            .max_memory_bytes = UINT64_C(512) * 1024u * 1024u,
            .max_output_bytes = UINT64_C(64) * 1024u * 1024u,
            .deadline_unix = expires - 1,
        };
        ASSERT(zcl_hex_decode_lower(task_hex, remote_request.task_root, 32));
        ASSERT(zcl_hex_decode_lower(candidate_hex,
                                    remote_request.candidate_root, 32));
        ASSERT(zcl_hex_decode_lower(action_id,
                                    remote_request.action_root, 32));
        ASSERT(zcl_hex_decode_lower(action.input_root_sha3,
                                    remote_request.input_root, 32));
        zd_root(remote_request.context_root, 92);
        memcpy(remote_request.proof_policy_root, task.proof_policy_root, 32);
        memcpy(remote_request.toolchain_capsule_root,
               task.toolchain_capsule_root, 32);
        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        zd_root(requester_seed, 93);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        ASSERT(vcs_zcode_work_request_seal(
            &remote_request, requester_secret, requester_key));
        struct vcs_zcode_work_result_v1 remote_result;
        zd_swarm_result(&remote_result, &remote_request, 94, 95);
        memcpy(remote_result.output_root, compile_output_root, 32);
        memcpy(remote_result.receipt.output_root, compile_output_root, 32);
        ASSERT(zcl_hex_decode_lower(receipt.observation_sha3,
                                    remote_result.receipt.evidence_root, 32));
        remote_result.receipt.started_unix = now > 0 ? now - 1 : 0;
        remote_result.receipt.finished_unix = now;
        uint8_t remote_seed[32], remote_secret[32], remote_key[32];
        zd_root(remote_seed, 95);
        ed25519_keypair(remote_key, remote_secret, remote_seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
            &remote_result.receipt, remote_secret, remote_key),
            VCS_ZCODE_DEV_OK);
        struct vcs_zcode_work_result_v1 mismatched_remote = remote_result;
        mismatched_remote.receipt.evidence_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
            &mismatched_remote.receipt, remote_secret, remote_key),
            VCS_ZCODE_DEV_OK);
        char mismatched_observed_id[65];
        ASSERT(build_fabric_receipt_observe_remote(
            &ndb, workspace, &remote_request, &mismatched_remote, now,
            mismatched_observed_id).ok);
        struct db_build_receipt mismatched_observed;
        ASSERT(db_build_receipt_find(
            &ndb, mismatched_observed_id, &mismatched_observed));
        struct db_build_worker mismatched_worker;
        ASSERT(db_build_worker_find(
            &ndb, mismatched_observed.worker_id, &mismatched_worker));
        ASSERT(!mismatched_worker.approved);
        struct build_fabric_shadow_match mismatched_shadow = {0};
        ASSERT(!build_fabric_clean_shadow_compare(
            &ndb, workspace, receipt.receipt_id, mismatched_observed_id,
            &mismatched_shadow).ok);
        ASSERT_STR_EQ(mismatched_shadow.first_bad_invariant,
                      "physical-observation-root-mismatch");
        struct build_fabric_proof_evaluation mismatched_evaluation = {0};
        ASSERT(build_fabric_proof_evaluate(
            &ndb, workspace, action_id,
            (int64_t)platform_time_wall_unix(),
            &mismatched_evaluation).ok);
        ASSERT(!mismatched_evaluation.local_reproduced);
        struct vcs_zcode_work_request_v1 wrong_kind_request = remote_request;
        wrong_kind_request.work_kind = VCS_ZCODE_WORK_TEST;
        ASSERT(vcs_zcode_work_request_seal(
            &wrong_kind_request, requester_secret, requester_key));
        struct vcs_zcode_work_result_v1 wrong_kind_result;
        zd_swarm_result(&wrong_kind_result, &wrong_kind_request, 97, 98);
        char refused_id[65];
        ASSERT(!build_fabric_receipt_observe_remote(
            &ndb, workspace, &wrong_kind_request, &wrong_kind_result, now,
            refused_id).ok);
        char observed_id[65];
        ASSERT(build_fabric_receipt_observe_remote(
            &ndb, workspace, &remote_request, &remote_result, now,
            observed_id).ok);
        struct db_build_receipt observed;
        ASSERT(db_build_receipt_find(&ndb, observed_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "REMOTE_OBSERVED");
        ASSERT_STR_EQ(observed.work_receipt_sha3, observed_id);
        ASSERT(!build_fabric_receipt_accept(&ndb, &observed, now).ok);
        struct db_build_worker remote_worker;
        ASSERT(db_build_worker_find(&ndb, observed.worker_id,
                                    &remote_worker));
        ASSERT(!remote_worker.approved);
        ASSERT(build_fabric_worker_approve(&ndb, &remote_worker, now).ok);
        struct vcs_zcode_work_result_v1 second_remote = remote_result;
        uint8_t second_seed[32], second_secret[32], second_key[32];
        zd_root(second_seed, 96);
        ed25519_keypair(second_key, second_secret, second_seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
            &second_remote.receipt, second_secret, second_key),
            VCS_ZCODE_DEV_OK);
        char second_observed_id[65];
        ASSERT(build_fabric_receipt_observe_remote(
            &ndb, workspace, &remote_request, &second_remote, now,
            second_observed_id).ok);
        struct db_build_receipt second_observed;
        ASSERT(db_build_receipt_find(&ndb, second_observed_id,
                                     &second_observed));
        struct db_build_worker second_worker;
        ASSERT(db_build_worker_find(&ndb, second_observed.worker_id,
                                    &second_worker));
        ASSERT(build_fabric_worker_approve(&ndb, &second_worker, now).ok);
        struct build_fabric_proof_evaluation evaluation;
        int64_t evaluation_now = (int64_t)platform_time_wall_unix();
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, workspace, action_id, evaluation_now, &evaluation).ok);
        ASSERT(evaluation.local_reproduced);
        ASSERT(evaluation.quorum_satisfied);
        ASSERT(strlen(evaluation.proof_set_root_sha3) == 64);
        ASSERT(db_build_receipt_find(&ndb, observed_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "REMOTE_OBSERVED");
        ASSERT(db_build_receipt_find(&ndb, second_observed_id,
                                     &second_observed));
        ASSERT_STR_EQ(second_observed.trust_state, "REMOTE_OBSERVED");
        ASSERT(build_fabric_proof_evaluate(
            &ndb, workspace, action_id, evaluation_now, &evaluation).ok);
        ASSERT(evaluation.local_reproduced);
        ASSERT(evaluation.quorum_satisfied);
        ASSERT(evaluation.approved_distinct_signers >= 2);
        ASSERT(evaluation.compile_satisfied);
        ASSERT(!evaluation.policy_satisfied);
        ASSERT(strlen(evaluation.proof_set_root_sha3) == 64);
        ASSERT(db_build_receipt_find(&ndb, observed_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "LOCAL_REPRODUCED");
        ASSERT(db_build_receipt_find(
            &ndb, mismatched_observed_id, &mismatched_observed));
        ASSERT_STR_EQ(mismatched_observed.trust_state, "REMOTE_OBSERVED");

        struct db_build_job job;
        ASSERT(db_build_job_find(&ndb, action.job_id, &job));
        struct db_build_action test_action, fuzz_action, review_action;
        ASSERT(zd_kind_action(
            &ndb, &job, &action, VCS_BUILD_ACTION_KIND_TEST_V1, 1,
            task.acceptance_tests_root, &test_action));
        uint8_t test_output[32]; zd_root(test_output, 120);
        char test_receipt_a[65], test_receipt_b[65];
        ASSERT(zd_observe_kind(
            &ndb, workspace, &task, &test_action, VCS_ZCODE_WORK_TEST,
            test_output, 121, now, test_receipt_a));
        ASSERT(zd_observe_kind(
            &ndb, workspace, &task, &test_action, VCS_ZCODE_WORK_TEST,
            test_output, 122, now, test_receipt_b));
        ASSERT(zd_kind_action(
            &ndb, &job, &action, VCS_BUILD_ACTION_KIND_FUZZ_V1, 2,
            task.acceptance_tests_root, &fuzz_action));
        uint8_t fuzz_output[32]; zd_root(fuzz_output, 123);
        char fuzz_receipt[65];
        ASSERT(zd_observe_kind(
            &ndb, workspace, &task, &fuzz_action, VCS_ZCODE_WORK_FUZZ,
            fuzz_output, 124, now, fuzz_receipt));
        struct build_fabric_proof_evaluation before_review;
        ASSERT(build_fabric_proof_evaluate(
            &ndb, workspace, action_id, evaluation_now,
            &before_review).ok);
        ASSERT(before_review.test_satisfied);
        ASSERT(before_review.fuzz_satisfied);
        ASSERT(!before_review.review_satisfied);
        ASSERT(!before_review.policy_satisfied);
        uint8_t review_seed[32], review_secret[32], review_key[32];
        zd_root(review_seed, 125);
        ed25519_keypair(review_key, review_secret, review_seed);
        struct vcs_zcode_review_v1 review = {
            .schema_version = VCS_ZCODE_DEV_VERSION,
            .verdict = VCS_ZCODE_REVIEW_APPROVE,
            .sequence = 1,
            .created_unix = now,
        };
        ASSERT(zcl_hex_decode_lower(task_hex, review.task_root, 32));
        ASSERT(zcl_hex_decode_lower(candidate_hex,
                                    review.candidate_root, 32));
        memcpy(review.proof_policy_root, task.proof_policy_root, 32);
        ASSERT(zcl_hex_decode_lower(before_review.proof_set_root_sha3,
                                    review.proof_set_root, 32));
        static const uint8_t findings[] = "reviewed: no findings";
        sha3_256(findings, sizeof(findings) - 1u, review.findings_root);
        ASSERT(vcs_object_put_addressed(
            workspace, review.findings_root, findings,
            sizeof(findings) - 1u));
        memcpy(review.reviewer_pubkey, review_key, 32);
        uint8_t review_wire[VCS_ZCODE_REVIEW_WIRE_BYTES], review_root[32];
        ASSERT_EQ(vcs_zcode_review_serialize(&review, review_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_review_root(&review, review_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, review_root, review_wire, sizeof(review_wire)));
        ASSERT(zd_kind_action(
            &ndb, &job, &action, VCS_BUILD_ACTION_KIND_REVIEW_V1, 3,
            candidate_root, &review_action));
        char review_receipt[65];
        ASSERT(zd_observe_kind(
            &ndb, workspace, &task, &review_action, VCS_ZCODE_WORK_REVIEW,
            review_root, 125, now, review_receipt));
        struct build_fabric_proof_evaluation complete;
        ASSERT(build_fabric_proof_evaluate(
            &ndb, workspace, action_id, evaluation_now, &complete).ok);
        if (complete.compile_receipts != 3 || complete.test_receipts != 3 ||
            complete.fuzz_receipts != 2 || complete.review_receipts != 1)
            printf("proof counts: valid=%zu compile=%zu test=%zu fuzz=%zu "
                   "review=%zu approved_signers=%zu local_reproduced=%d\n",
                   complete.valid_receipts, complete.compile_receipts,
                   complete.test_receipts, complete.fuzz_receipts,
                   complete.review_receipts,
                   complete.approved_distinct_signers,
                   complete.local_reproduced ? 1 : 0);
        ASSERT_EQ(complete.compile_receipts, 3);
        ASSERT_EQ(complete.test_receipts, 3);
        ASSERT_EQ(complete.fuzz_receipts, 2);
        ASSERT_EQ(complete.review_receipts, 1);
        ASSERT(complete.compile_satisfied);
        ASSERT(complete.test_satisfied);
        ASSERT(complete.fuzz_satisfied);
        ASSERT(complete.review_satisfied);
        ASSERT(complete.release_identity_satisfied);
        ASSERT(complete.policy_satisfied);
        node_db_close(&ndb);

        struct json_value accept_input;
        json_init(&accept_input); json_set_object(&accept_input);
        (void)json_push_kv_str(&accept_input, "workspace", workspace);
        (void)json_push_kv_str(&accept_input, "datadir", workspace);
        (void)json_push_kv_str(&accept_input, "action_id", action_id);
        (void)json_push_kv_str(&accept_input, "lane", "CANDIDATE");
        struct zcl_command_request accept_request = { .input = &accept_input };
        struct zcl_command_reply accept_reply;
        zcl_command_reply_init(&accept_reply, "zcl.zcode_accept.v1");
        zcl_native_handle_zcode_accept(&accept_request, &accept_reply);
        ASSERT_EQ(accept_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&accept_reply.data, "lane")),
                      "CANDIDATE");
        ASSERT(strlen(json_get_str(json_get(
            &accept_reply.data, "lane_receipt_root"))) == 64);
        ASSERT(strlen(json_get_str(json_get(
            &accept_reply.data, "proof_set_root"))) == 64);

        struct json_value lane_input;
        json_init(&lane_input); json_set_object(&lane_input);
        (void)json_push_kv_str(&lane_input, "workspace", workspace);
        (void)json_push_kv_str(&lane_input, "datadir", workspace);
        (void)json_push_kv_str(&lane_input, "source_root",
                               candidate_source_saved);
        struct zcl_command_request lane_request = { .input = &lane_input };
        struct zcl_command_reply lane_reply;
        zcl_command_reply_init(&lane_reply, "zcl.zcode_lane.v1");
        zcl_native_handle_zcode_lane(&lane_request, &lane_reply);
        ASSERT_EQ(lane_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&lane_reply.data, "lane")),
                      "CANDIDATE");
        ASSERT_STR_EQ(json_get_str(json_get(&lane_reply.data, "authority")),
                      "SIGNED_CAS_RECEIPT");

        /* Accepted-lane publication is plan -> offline detached signature
         * -> seal -> commit. The planning surface never receives a secret
         * and does not create the package store. */
        uint8_t publish_secret[32] = {0};
        publish_secret[31] = 7;
        secp256k1_context *publish_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        ASSERT(publish_ctx != NULL);
        uint8_t publish_pubkey[33];
        ASSERT(zd_secp_pubkey(publish_ctx, publish_secret,
                              publish_pubkey));
        char publish_pubkey_hex[67];
        zcl_hex_encode(publish_pubkey, sizeof(publish_pubkey),
                       publish_pubkey_hex);
        const char *accepted_receipt = json_get_str(json_get(
            &accept_reply.data, "lane_receipt_root"));
        ASSERT(accepted_receipt && strlen(accepted_receipt) == 64);
        char accepted_receipt_saved[65];
        (void)snprintf(accepted_receipt_saved,
                       sizeof(accepted_receipt_saved), "%s",
                       accepted_receipt);
        uint8_t accepted_source_root[32], accepted_lane_root[32];
        ASSERT(zcl_hex_decode_lower(candidate_source_saved,
                                    accepted_source_root, 32));
        ASSERT(zd_seed_offline_vendor_inputs(workspace));
        ASSERT(zcl_hex_decode_lower(accepted_receipt_saved,
                                    accepted_lane_root, 32));
        struct vcs_package_mapping_metrics cold_mapping, warm_mapping;
        uint8_t package_mapping_root[32], warm_package_mapping_root[32];
        ASSERT(vcs_package_mapping_set_build(
            workspace, accepted_source_root, accepted_lane_root,
            &cold_mapping, package_mapping_root));
        ASSERT(cold_mapping.bytes_scanned > 0);
        ASSERT(cold_mapping.new_chunks > 0);
        ASSERT_EQ(cold_mapping.reused_chunks, 0u);
        ASSERT(vcs_package_mapping_set_build(
            workspace, accepted_source_root, accepted_lane_root,
            &warm_mapping, warm_package_mapping_root));
        ASSERT_EQ(warm_mapping.bytes_scanned, 0u);
        ASSERT_EQ(warm_mapping.new_chunks, 0u);
        ASSERT_EQ(warm_mapping.reused_chunks, cold_mapping.new_chunks);
        ASSERT(memcmp(package_mapping_root,
                      warm_package_mapping_root, 32) == 0);
        char package_mapping_hex[65];
        zcl_hex_encode(package_mapping_root, 32, package_mapping_hex);
        char publication_seed[256];
        test_make_tmpdir(publication_seed, sizeof(publication_seed),
                         "zcode_dev", "publication_seed");
        ASSERT_EQ(vcs_tree_materialize(
                      workspace, accepted_source_root, publication_seed,
                      VCS_PACKAGE_MAX_TOTAL_BYTES, 0), VCS_OK);
        struct vcs_devloop_verdict publication_verdict = {
            .verdict_status = 0,
            .phase = "verify",
            .elapsed_ms = 17,
            .proof_complete = true,
            .proof_scope = "source_wide_compile_tests_lint_fast",
            .source_identity_hex = sha256_saved,
            .source_cas_hex = candidate_source_saved,
        };
        struct vcs_devloop_anchor_result publication_anchor;
        vcs_devloop_anchor_cycle(publication_seed, &publication_verdict,
                                 &publication_anchor);
        ASSERT_EQ(publication_anchor.status, VCS_DEVLOOP_ANCHOR_OK);
        ASSERT_EQ(publication_anchor.publication_status,
                  VCS_DEVLOOP_PUBLICATION_QUEUED);
        struct vcs_devloop_publication_job publication_job;
        ASSERT(vcs_devloop_publication_job_load(
            publication_seed, publication_anchor.publication_job_root,
            &publication_job));
        ASSERT(memcmp(publication_job.source_tree_root,
                      accepted_source_root, 32) == 0);
        ASSERT(zd_copy_tagged_object(
            publication_seed, workspace, publication_anchor.commit_id,
            VCS_TAG_COMMIT));
        ASSERT(zd_copy_tagged_object(
            publication_seed, workspace,
            publication_anchor.proof_receipt_root, VCS_TAG_DEV_PROOF));
        ASSERT(zd_copy_tagged_object(
            publication_seed, workspace,
            publication_anchor.publication_job_root,
            VCS_TAG_PUBLICATION_JOB));
        bool publication_reused = true;
        ASSERT(vcs_devloop_publication_job_requeue(
            workspace, publication_anchor.publication_job_root,
            &publication_reused));
        ASSERT(!publication_reused);
        uint8_t publication_progress[32];
        ASSERT(vcs_devloop_publication_advance_waiting_acceptance(
            workspace, publication_anchor.publication_job_root,
            publication_progress, &publication_reused));
        ASSERT(!publication_reused);
        ASSERT(!vcs_devloop_publication_advance_proven_work(
            workspace, publication_anchor.publication_job_root,
            accepted_lane_root, (int64_t)platform_time_wall_unix(),
            publication_progress,
            &publication_reused));
        char publication_job_hex[65];
        zcl_hex_encode(publication_anchor.publication_job_root, 32,
                       publication_job_hex);
        char publication_store[512];
        test_make_tmpdir(publication_store, sizeof(publication_store),
                         "zcode_dev", "accepted-publication-store");
        char zcode_store_path[4352];
        (void)snprintf(zcode_store_path, sizeof(zcode_store_path),
                       "%s/zcode", publication_store);
        struct vcs_package_index *pre_publish_index =
            vcs_package_index_build(zcode_store_path);
        ASSERT(pre_publish_index != NULL);
        ASSERT_EQ(vcs_package_index_count(pre_publish_index), 0);
        vcs_package_index_free(pre_publish_index);

        struct json_value publish_plan_input;
        json_init(&publish_plan_input);
        json_set_object(&publish_plan_input);
        (void)json_push_kv_str(&publish_plan_input, "workspace", workspace);
        (void)json_push_kv_str(&publish_plan_input, "datadir",
                               publication_store);
        (void)json_push_kv_str(&publish_plan_input,
                               "acceptance_datadir", workspace);
        (void)json_push_kv_str(&publish_plan_input, "source_root",
                               candidate_source_saved);
        (void)json_push_kv_str(&publish_plan_input, "publisher_pubkey",
                               publish_pubkey_hex);
        (void)json_push_kv_str(&publish_plan_input, "task_root", task_hex);
        (void)json_push_kv_str(&publish_plan_input, "lane_receipt_root",
                               roots[9]);
        (void)json_push_kv_str(&publish_plan_input,
                               "package_mapping_root",
                               package_mapping_hex);
        (void)json_push_kv_str(&publish_plan_input,
                               "publication_job_root",
                               publication_job_hex);
        struct zcl_command_request publish_plan_request = {
            .input = &publish_plan_input,
        };
        struct zcl_command_reply stale_publish_plan;
        zcl_command_reply_init(&stale_publish_plan,
                               "zcl.zcode_publish_plan.v1");
        zcl_native_handle_zcode_publish_plan(&publish_plan_request,
                                             &stale_publish_plan);
        ASSERT_EQ(stale_publish_plan.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(stale_publish_plan.error.code,
                      "LANE_NOT_ACCEPTED");
        zcl_command_reply_free(&stale_publish_plan);

        ASSERT(node_db_open(&ndb, db_path));
        struct db_build_worker proven_worker;
        uint8_t proven_secret[32], proven_key[32];
        ASSERT(build_fabric_worker_identity_load(
            workspace, &proven_worker, proven_secret, proven_key).ok);
        struct zcode_lane_status proven_status;
        ASSERT(zcode_lane_advance(
            &ndb, workspace, action_id, VCS_ZCODE_LANE_PROVEN,
            (int64_t)platform_time_wall_unix(), proven_secret, proven_key,
            &proven_status).ok);
        memset(proven_secret, 0, sizeof(proven_secret));
        node_db_close(&ndb);
        (void)snprintf(accepted_receipt_saved,
                       sizeof(accepted_receipt_saved), "%s",
                       proven_status.receipt_root_sha3);
        ASSERT(zcl_hex_decode_lower(accepted_receipt_saved,
                                    accepted_lane_root, 32));
        ASSERT(vcs_package_mapping_set_build(
            workspace, accepted_source_root, accepted_lane_root,
            &cold_mapping, package_mapping_root));
        zcl_hex_encode(package_mapping_root, 32, package_mapping_hex);
        publication_reused = true;
        ASSERT(vcs_devloop_publication_advance_proven_work(
            workspace, publication_anchor.publication_job_root,
            accepted_lane_root, (int64_t)platform_time_wall_unix(),
            publication_progress, &publication_reused));
        ASSERT(!publication_reused);
        ASSERT(vcs_devloop_publication_advance_package_mapping(
            workspace, publication_anchor.publication_job_root,
            package_mapping_root, cold_mapping.bytes_scanned,
            cold_mapping.new_chunks, cold_mapping.reused_chunks,
            publication_progress, &publication_reused));
        json_set_str((struct json_value *)json_get(
                         &publish_plan_input, "package_mapping_root"),
                     package_mapping_hex);
        struct zcl_command_reply stale_binding_plan;
        zcl_command_reply_init(&stale_binding_plan,
                               "zcl.zcode_publish_plan.v1");
        zcl_native_handle_zcode_publish_plan(&publish_plan_request,
                                             &stale_binding_plan);
        ASSERT_EQ(stale_binding_plan.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(stale_binding_plan.error.code,
                      "CLAIMED_BINDING_MISMATCH");
        zcl_command_reply_free(&stale_binding_plan);
        json_set_str((struct json_value *)json_get(
                         &publish_plan_input, "lane_receipt_root"),
                     accepted_receipt_saved);

        struct zcl_command_reply publish_plan_reply;
        zcl_command_reply_init(&publish_plan_reply,
                               "zcl.zcode_publish_plan.v1");
        zcl_native_handle_zcode_publish_plan(&publish_plan_request,
                                             &publish_plan_reply);
        ASSERT_EQ(publish_plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&publish_plan_reply.data,
                                      "read_only")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "signature_status")),
                      "unsigned");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "package_name")),
                      "fixture/accepted");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "package_version")),
                      "1.0.0");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "package_license")),
                      "Apache-2.0");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "package_facts")),
                      "exact_accepted_source");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "lane")),
                      "PROVEN");
        ASSERT_EQ(json_get_int(json_get(
                      &publish_plan_reply.data, "bytes_scanned")), 0);
        ASSERT_EQ(json_get_int(json_get(
                      &publish_plan_reply.data, "new_chunks")), 0);
        ASSERT_EQ((uint32_t)json_get_int(json_get(
                      &publish_plan_reply.data, "reused_chunks")),
                  cold_mapping.reused_chunks);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data,
                          "package_mapping_root")),
                      package_mapping_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data,
                          "publication_job_root")),
                      publication_job_hex);
        (void)json_push_kv_str(&publish_plan_input, "license", "MIT");
        struct zcl_command_reply conflicting_facts_reply;
        zcl_command_reply_init(&conflicting_facts_reply,
                               "zcl.zcode_publish_plan.v1");
        zcl_native_handle_zcode_publish_plan(&publish_plan_request,
                                             &conflicting_facts_reply);
        ASSERT_EQ(conflicting_facts_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(conflicting_facts_reply.error.code,
                      "PACKAGE_FACTS_MISMATCH");
        zcl_command_reply_free(&conflicting_facts_reply);
        json_set_str((struct json_value *)json_get(
                         &publish_plan_input, "license"), "");
        pre_publish_index = vcs_package_index_build(zcode_store_path);
        ASSERT(pre_publish_index != NULL);
        ASSERT_EQ(vcs_package_index_count(pre_publish_index), 0);
        vcs_package_index_free(pre_publish_index);
        const char *release_body_hex = json_get_str(json_get(
            &publish_plan_reply.data, "release_body_hex"));
        const char *signing_digest_hex = json_get_str(json_get(
            &publish_plan_reply.data, "release_signing_digest"));
        const char *planned_package_hex = json_get_str(json_get(
            &publish_plan_reply.data, "package_root"));
        const char *planned_recipe_hex = json_get_str(json_get(
            &publish_plan_reply.data, "recipe_root"));
        ASSERT(release_body_hex && signing_digest_hex &&
               planned_package_hex && planned_recipe_hex &&
               strlen(signing_digest_hex) == 64 &&
               strlen(planned_package_hex) == 64);
        char release_body_saved[2 * VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES + 1u];
        char planned_package_saved[65], planned_recipe_saved[65];
        ASSERT(strlen(release_body_hex) < sizeof(release_body_saved));
        (void)snprintf(release_body_saved, sizeof(release_body_saved), "%s",
                       release_body_hex);
        (void)snprintf(planned_package_saved,
                       sizeof(planned_package_saved), "%s",
                       planned_package_hex);
        (void)snprintf(planned_recipe_saved,
                       sizeof(planned_recipe_saved), "%s",
                       planned_recipe_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_plan_reply.data, "source_transport")),
                      "vcs_source_bundle.v2");
        ASSERT_EQ(json_get_int(json_get(
                      &publish_plan_reply.data, "source_files")), 6);
        ASSERT(json_get_int(json_get(
                   &publish_plan_reply.data, "source_bundle_bytes")) > 0);
        ASSERT(json_get_int(json_get(
                   &publish_plan_reply.data, "source_shards")) > 0);
        ASSERT_EQ(json_get_int(json_get(
                      &publish_plan_reply.data, "offline_input_files")), 5);
        int64_t planned_carrier_files = json_get_int(json_get(
            &publish_plan_reply.data, "carrier_files"));
        ASSERT(planned_carrier_files > 9);
        uint8_t signing_digest[32], publish_signature[64];
        ASSERT(zcl_hex_decode_lower(signing_digest_hex,
                                    signing_digest, 32));
        ASSERT(zd_secp_signature(publish_ctx, publish_secret,
                                 signing_digest, publish_signature));
        memset(publish_secret, 0, sizeof(publish_secret));
        char publish_signature_hex[129];
        zcl_hex_encode(publish_signature, sizeof(publish_signature),
                       publish_signature_hex);

        struct json_value seal_input;
        json_init(&seal_input);
        json_set_object(&seal_input);
        (void)json_push_kv_str(&seal_input, "release_body_hex",
                               release_body_saved);
        (void)json_push_kv_str(&seal_input, "signature_hex",
                               publish_signature_hex);
        struct zcl_command_request seal_request = { .input = &seal_input };
        struct zcl_command_reply seal_reply;
        zcl_command_reply_init(&seal_reply,
                               "zcl.zcode_package_dev_seal.v1");
        zcl_native_handle_zcode_package_dev_seal(&seal_request,
                                                 &seal_reply);
        ASSERT_EQ(seal_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const char *sealed_release = json_get_str(json_get(
            &seal_reply.data, "release_hex"));
        ASSERT(sealed_release != NULL);
        char sealed_release_saved[
            2 * VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES + 1u];
        ASSERT(strlen(sealed_release) < sizeof(sealed_release_saved));
        (void)snprintf(sealed_release_saved,
                       sizeof(sealed_release_saved), "%s", sealed_release);

        struct json_value publish_commit_input;
        json_init(&publish_commit_input);
        json_set_object(&publish_commit_input);
        (void)json_push_kv_str(&publish_commit_input, "workspace", workspace);
        (void)json_push_kv_str(&publish_commit_input, "datadir",
                               publication_store);
        (void)json_push_kv_str(&publish_commit_input,
                               "acceptance_datadir", workspace);
        (void)json_push_kv_str(&publish_commit_input, "source_root",
                               candidate_source_saved);
        (void)json_push_kv_str(&publish_commit_input, "release_hex",
                               sealed_release_saved);
        (void)json_push_kv_str(&publish_commit_input, "task_root", task_hex);
        (void)json_push_kv_str(&publish_commit_input,
                               "lane_receipt_root",
                               accepted_receipt_saved);
        (void)json_push_kv_str(&publish_commit_input,
                               "package_mapping_root",
                               package_mapping_hex);
        (void)json_push_kv_str(&publish_commit_input,
                               "publication_job_root",
                               publication_job_hex);
        (void)json_push_kv_int(&publish_commit_input, "day", 20000);
        struct zcl_command_request publish_commit_request = {
            .input = &publish_commit_input,
        };
        struct json_value *release_value = (struct json_value *)json_get(
            &publish_commit_input, "release_hex");
        size_t sealed_len = strlen(sealed_release_saved);
        char last = sealed_release_saved[sealed_len - 1u];
        sealed_release_saved[sealed_len - 1u] = last == '0' ? '1' : '0';
        json_set_str(release_value, sealed_release_saved);
        struct zcl_command_reply bad_publish_reply;
        zcl_command_reply_init(&bad_publish_reply,
                               "zcl.zcode_publish_commit.v1");
        zcl_native_handle_zcode_publish_commit(&publish_commit_request,
                                               &bad_publish_reply);
        ASSERT_EQ(bad_publish_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(bad_publish_reply.error.code,
                      "SIGNED_RELEASE_INVALID");
        ASSERT(zd_no_accept_publish_stage(publication_store));
        zcl_command_reply_free(&bad_publish_reply);
        sealed_release_saved[sealed_len - 1u] = last;
        json_set_str(release_value, sealed_release_saved);

        struct zcl_command_reply publish_commit_reply;
        zcl_command_reply_init(&publish_commit_reply,
                               "zcl.zcode_publish_commit.v1");
        zcl_native_handle_zcode_publish_commit(&publish_commit_request,
                                               &publish_commit_reply);
        ASSERT_EQ(publish_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_commit_reply.data, "result")),
                      "committed");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_commit_reply.data, "package_root")),
                      planned_package_saved);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_commit_reply.data, "authority")),
                      "SIGNED_LANE_RECEIPT_AND_RELEASE_ENVELOPE");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_commit_reply.data,
                          "publication_status")),
                      "RELEASE_PUBLISHED");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &publish_commit_reply.data,
                          "publication_job_root")),
                      publication_job_hex);
        ASSERT(!json_get_bool(json_get(
            &publish_commit_reply.data, "progress_reused")));
        struct vcs_devloop_publication_receipt release_progress;
        uint8_t release_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &release_progress, release_progress_root));
        ASSERT_EQ(release_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED);
        const char *published_release_root = json_get_str(json_get(
            &publish_commit_reply.data, "release_root"));
        ASSERT(published_release_root != NULL);
        uint8_t published_release[32];
        ASSERT(zcl_hex_decode_lower(published_release_root,
                                    published_release, 32));
        ASSERT(memcmp(release_progress.artifact_root,
                      published_release, 32) == 0);
        ASSERT(zd_no_accept_publish_stage(publication_store));
        struct vcs_package_index *published_index =
            vcs_package_index_build(zcode_store_path);
        ASSERT(published_index != NULL);
        ASSERT_EQ(vcs_package_index_count(published_index), 1);
        const struct vcs_package_index_entry *published_entry =
            vcs_package_index_at(published_index, 0);
        ASSERT(published_entry != NULL);
        ASSERT_STR_EQ(published_entry->package_root_hex,
                      planned_package_saved);
        ASSERT_STR_EQ(published_entry->name, "fixture/accepted");
        ASSERT(published_entry->manifest_present);
        ASSERT(published_entry->license_present);
        ASSERT_EQ(published_entry->file_count,
                  (uint32_t)planned_carrier_files);
        vcs_package_index_free(published_index);

        uint8_t published_package_root[32];
        ASSERT(zcl_hex_decode_lower(
            planned_package_saved, published_package_root, 32));
        struct vcs_package_store *published_store = vcs_package_store_open(
            publication_store, UINT64_C(256) * 1024u * 1024u);
        ASSERT(published_store != NULL);
        uint8_t *published_manifest_wire = NULL;
        size_t published_manifest_wire_len = 0;
        struct vcs_package_manifest published_manifest;
        ASSERT_EQ(vcs_package_store_get_manifest_wire(
                      published_store, published_package_root,
                      &published_manifest_wire,
                      &published_manifest_wire_len),
                  VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_manifest_parse(
            published_manifest_wire, published_manifest_wire_len,
            &published_manifest));
        bool authority_carried = false;
        for (size_t i = 0; i < published_manifest.count; i++)
            if (strcmp(published_manifest.files[i].path,
                       VCS_SOURCE_PACKAGE_AUTHORITY_PATH) == 0)
                authority_carried = true;
        ASSERT(authority_carried);
        vcs_package_manifest_free(&published_manifest);
        free(published_manifest_wire);
        char carrier_workspace[512], carrier_destination[512];
        test_make_tmpdir(carrier_workspace, sizeof(carrier_workspace),
                         "zcode_dev", "published-carrier-workspace");
        test_make_tmpdir(carrier_destination, sizeof(carrier_destination),
                         "zcode_dev", "published-carrier-destination");
        struct vcs_source_package_checkout_metrics carrier_metrics;
        uint8_t candidate_source_root[32];
        ASSERT(zcl_hex_decode_lower(
            candidate_source_saved, candidate_source_root, 32));
        ASSERT_EQ(vcs_source_package_checkout_accepted(
                      published_store, published_package_root,
                      candidate_source_root, accepted_lane_root,
                      carrier_workspace, carrier_destination,
                      &carrier_metrics),
                  VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(carrier_metrics.authority_objects >= 9);
        ASSERT(carrier_metrics.work_receipts >= 2);
        ASSERT(memcmp(carrier_metrics.accepted_signer,
                      admission_key, 32) == 0);
        uint8_t reconstructed_source_root[32];
        uint8_t reconstructed_work_root[32];
        struct vcs_source_package_checkout_metrics reconstruction_metrics;
        enum vcs_source_package_checkout_result reconstruction_result =
            vcs_source_package_reconstruct_verify(
                published_store, published_package_root,
                reconstructed_source_root, reconstructed_work_root,
                &reconstruction_metrics);
        if (reconstruction_result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
            printf("source reconstruction result: %s\n",
                   vcs_source_package_checkout_result_string(
                       reconstruction_result));
        ASSERT_EQ(reconstruction_result, VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(memcmp(reconstructed_source_root,
                      candidate_source_root, 32) == 0);
        ASSERT(memcmp(reconstructed_work_root,
                      accepted_lane_root, 32) == 0);
        ASSERT(reconstruction_metrics.source.file_count > 0);
        ASSERT(reconstruction_metrics.authority_objects >= 9);
        ASSERT(reconstruction_metrics.work_receipts >= 2);
        vcs_package_store_close(published_store);

        struct zcl_command_reply duplicate_publish_reply;
        zcl_command_reply_init(&duplicate_publish_reply,
                               "zcl.zcode_publish_commit.v1");
        zcl_native_handle_zcode_publish_commit(&publish_commit_request,
                                               &duplicate_publish_reply);
        ASSERT_EQ(duplicate_publish_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &duplicate_publish_reply.data, "result")),
                      "duplicate");
        ASSERT(json_get_bool(json_get(
            &duplicate_publish_reply.data, "progress_reused")));
        ASSERT(zd_no_accept_publish_stage(publication_store));
        zcl_command_reply_free(&duplicate_publish_reply);

        struct vcs_zcode_module_passport_v1 publication_passport = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_V2_REQUIRED_FLAGS,
        };
        uint8_t *accepted_lane_wire = NULL;
        size_t accepted_lane_wire_len = 0;
        struct vcs_zcode_lane_receipt_v1 accepted_lane;
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, accepted_lane_root,
                      VCS_ZCODE_LANE_WIRE_BYTES,
                      &accepted_lane_wire, &accepted_lane_wire_len), 0);
        ASSERT_EQ(vcs_zcode_lane_receipt_parse(
                      accepted_lane_wire, accepted_lane_wire_len,
                      &accepted_lane), VCS_ZCODE_DEV_OK);
        free(accepted_lane_wire);
        zd_root(publication_passport.stable_api_root, 0x81);
        ASSERT(zcl_hex_decode_lower(planned_recipe_saved,
                                    publication_passport.recipe_root, 32));
        zd_root(publication_passport.toolchain_root, 0x83);
        memcpy(publication_passport.tests_root,
               accepted_lane.proof_set_root, 32);
        zd_root(publication_passport.license_root, 0x85);
        zd_root(publication_passport.semantic_fingerprint_root, 0x86);
        memcpy(publication_passport.workspace_lineage_root,
               publication_job.vcs_commit_root, 32);
        zd_root(publication_passport.source_assignment_root, 0x88);
        zd_root(publication_passport.quality_profiles_root, 0x89);
        uint8_t passport_seed[32], passport_secret[32];
        zd_root(passport_seed, 0x8a);
        ed25519_keypair(publication_passport.signer_root,
                        passport_secret, passport_seed);
        static const char *passport_keys[] = {
            "stable_api_root", "recipe_root", "toolchain_root",
            "tests_root", "license_root", "semantic_fingerprint_root",
            "workspace_lineage_root", "source_assignment_root",
            "quality_profiles_root", "signer_pubkey",
        };
        uint8_t *passport_roots[] = {
            publication_passport.stable_api_root,
            publication_passport.recipe_root,
            publication_passport.toolchain_root,
            publication_passport.tests_root,
            publication_passport.license_root,
            publication_passport.semantic_fingerprint_root,
            publication_passport.workspace_lineage_root,
            publication_passport.source_assignment_root,
            publication_passport.quality_profiles_root,
            publication_passport.signer_root,
        };
        struct json_value passport_plan_input;
        json_init(&passport_plan_input);
        json_set_object(&passport_plan_input);
        for (size_t i = 0; i < 10; i++) {
            char root_hex[65];
            zcl_hex_encode(passport_roots[i], 32, root_hex);
            ASSERT(json_push_kv_str(&passport_plan_input,
                                    passport_keys[i], root_hex));
        }
        ASSERT(json_push_kv_str(&passport_plan_input, "workspace",
                                workspace));
        ASSERT(json_push_kv_str(&passport_plan_input,
                                "publication_job_root",
                                publication_job_hex));
        struct zcl_command_request passport_plan_request = {
            .input = &passport_plan_input,
        };
        struct json_value *passport_recipe_value =
            (struct json_value *)json_get(&passport_plan_input,
                                           "recipe_root");
        char correct_passport_recipe[65], wrong_passport_recipe[65];
        (void)snprintf(correct_passport_recipe,
                       sizeof(correct_passport_recipe), "%s",
                       json_get_str(passport_recipe_value));
        (void)snprintf(wrong_passport_recipe,
                       sizeof(wrong_passport_recipe), "%s",
                       correct_passport_recipe);
        wrong_passport_recipe[0] =
            wrong_passport_recipe[0] == '0' ? '1' : '0';
        json_set_str(passport_recipe_value, wrong_passport_recipe);
        struct zcl_command_reply wrong_recipe_passport_reply;
        zcl_command_reply_init(&wrong_recipe_passport_reply,
                               "zcl.zcode_passport_plan.v1");
        zcl_native_handle_zcode_passport_plan(
            &passport_plan_request, &wrong_recipe_passport_reply);
        ASSERT_EQ(wrong_recipe_passport_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(wrong_recipe_passport_reply.error.code,
                      "MODULE_PASSPORT_JOB_BINDING_INVALID");
        zcl_command_reply_free(&wrong_recipe_passport_reply);
        json_set_str(passport_recipe_value, correct_passport_recipe);
        struct json_value *passport_tests_value =
            (struct json_value *)json_get(&passport_plan_input,
                                           "tests_root");
        char correct_passport_tests[65], wrong_passport_tests[65];
        (void)snprintf(correct_passport_tests,
                       sizeof(correct_passport_tests), "%s",
                       json_get_str(passport_tests_value));
        (void)snprintf(wrong_passport_tests,
                       sizeof(wrong_passport_tests), "%s",
                       correct_passport_tests);
        wrong_passport_tests[0] = wrong_passport_tests[0] == '0' ? '1' : '0';
        json_set_str(passport_tests_value, wrong_passport_tests);
        struct zcl_command_reply wrong_passport_plan_reply;
        zcl_command_reply_init(&wrong_passport_plan_reply,
                               "zcl.zcode_passport_plan.v1");
        zcl_native_handle_zcode_passport_plan(
            &passport_plan_request, &wrong_passport_plan_reply);
        ASSERT_EQ(wrong_passport_plan_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(wrong_passport_plan_reply.error.code,
                      "MODULE_PASSPORT_JOB_BINDING_INVALID");
        zcl_command_reply_free(&wrong_passport_plan_reply);
        json_set_str(passport_tests_value, correct_passport_tests);
        struct zcl_command_reply passport_plan_reply;
        zcl_command_reply_init(&passport_plan_reply,
                               "zcl.zcode_passport_plan.v1");
        zcl_native_handle_zcode_passport_plan(&passport_plan_request,
                                              &passport_plan_reply);
        ASSERT_EQ(passport_plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_plan_reply.data,
                                      "will_persist_on_commit")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &passport_plan_reply.data,
                          "publication_job_root")),
                      publication_job_hex);
        const char *passport_payload_hex = json_get_str(json_get(
            &passport_plan_reply.data, "signing_payload"));
        ASSERT(passport_payload_hex != NULL);
        uint8_t passport_payload[
            VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES];
        ASSERT(zcl_hex_decode_lower(passport_payload_hex,
                                    passport_payload,
                                    sizeof(passport_payload)));
        ed25519_sign(publication_passport.signature, passport_payload,
                     sizeof(passport_payload), passport_secret,
                     publication_passport.signer_root);
        memset(passport_secret, 0, sizeof(passport_secret));
        zcl_command_reply_free(&passport_plan_reply);
        char passport_signature_hex[129];
        zcl_hex_encode(publication_passport.signature,
                       sizeof(publication_passport.signature),
                       passport_signature_hex);
        ASSERT(json_push_kv_str(&passport_plan_input, "signature",
                                passport_signature_hex));
        struct zcl_command_reply passport_commit_reply;
        zcl_command_reply_init(&passport_commit_reply,
                               "zcl.zcode_passport_commit.v1");
        zcl_native_handle_zcode_passport_commit(&passport_plan_request,
                                                &passport_commit_reply);
        ASSERT_EQ(passport_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_commit_reply.data,
                                      "persisted")));
        ASSERT(!json_get_bool(json_get(&passport_commit_reply.data,
                                       "published")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &passport_commit_reply.data,
                          "publication_status")),
                      "PASSPORT_PUBLISHED");
        ASSERT(!json_get_bool(json_get(&passport_commit_reply.data,
                                       "progress_reused")));
        const char *published_passport_root = json_get_str(json_get(
            &passport_commit_reply.data, "passport_root"));
        const char *published_passport_wire = json_get_str(json_get(
            &passport_commit_reply.data, "passport"));
        ASSERT(published_passport_root && published_passport_wire);
        char published_passport_root_saved[65];
        char published_passport_wire_saved[
            VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES * 2u + 1u];
        (void)snprintf(published_passport_root_saved,
                       sizeof(published_passport_root_saved), "%s",
                       published_passport_root);
        (void)snprintf(published_passport_wire_saved,
                       sizeof(published_passport_wire_saved), "%s",
                       published_passport_wire);
        uint8_t passport_root[32], *stored_passport = NULL;
        size_t stored_passport_len = 0;
        ASSERT(zcl_hex_decode_lower(published_passport_root,
                                    passport_root, 32));
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, passport_root,
                      VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES,
                      &stored_passport, &stored_passport_len), 0);
        ASSERT_EQ(stored_passport_len,
                  VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES);
        struct vcs_zcode_module_passport_v1 stored_passport_object;
        ASSERT_EQ(vcs_zcode_module_passport_v1_decode(
                      &stored_passport_object, stored_passport,
                      stored_passport_len), VCS_ZCODE_COMMONS_V2_OK);
        free(stored_passport);
        struct vcs_devloop_publication_receipt passport_progress;
        uint8_t passport_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &passport_progress, passport_progress_root));
        ASSERT_EQ(passport_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED);
        ASSERT(memcmp(passport_progress.artifact_root,
                      passport_root, 32) == 0);
        zcl_command_reply_free(&passport_commit_reply);
        zcl_command_reply_init(&passport_commit_reply,
                               "zcl.zcode_passport_commit.v1");
        zcl_native_handle_zcode_passport_commit(&passport_plan_request,
                                                &passport_commit_reply);
        ASSERT_EQ(passport_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_commit_reply.data,
                                      "progress_reused")));
        zcl_command_reply_free(&passport_commit_reply);

        uint8_t workspace_manifest_seed[32], workspace_manifest_secret[32];
        uint8_t workspace_manifest_pubkey[32];
        zd_root(workspace_manifest_seed, 0x91);
        ed25519_keypair(workspace_manifest_pubkey,
                        workspace_manifest_secret,
                        workspace_manifest_seed);
        char workspace_manifest_pubkey_hex[65];
        zcl_hex_encode(workspace_manifest_pubkey, 32,
                       workspace_manifest_pubkey_hex);
        struct json_value workspace_manifest_input;
        json_init(&workspace_manifest_input);
        json_set_object(&workspace_manifest_input);
        ASSERT(json_push_kv_str(&workspace_manifest_input, "passport",
                                published_passport_wire_saved));
        ASSERT(json_push_kv_str(&workspace_manifest_input,
                                "module_release_root",
                                published_release_root));
        ASSERT(json_push_kv_int(&workspace_manifest_input, "sequence", 1));
        ASSERT(json_push_kv_int(&workspace_manifest_input,
                                "workspace_sequence", 1));
        ASSERT(json_push_kv_str(&workspace_manifest_input, "signer_root",
                                workspace_manifest_pubkey_hex));
        ASSERT(json_push_kv_str(&workspace_manifest_input, "workspace",
                                workspace));
        ASSERT(json_push_kv_str(&workspace_manifest_input,
                                "publication_job_root",
                                publication_job_hex));
        struct zcl_command_request workspace_manifest_request = {
            .input = &workspace_manifest_input,
        };
        struct json_value *workspace_release_value =
            (struct json_value *)json_get(&workspace_manifest_input,
                                           "module_release_root");
        char correct_workspace_release[65], wrong_workspace_release[65];
        (void)snprintf(correct_workspace_release,
                       sizeof(correct_workspace_release), "%s",
                       published_release_root);
        (void)snprintf(wrong_workspace_release,
                       sizeof(wrong_workspace_release), "%s",
                       correct_workspace_release);
        wrong_workspace_release[0] =
            wrong_workspace_release[0] == '0' ? '1' : '0';
        json_set_str(workspace_release_value, wrong_workspace_release);
        struct zcl_command_reply wrong_workspace_manifest_reply;
        zcl_command_reply_init(
            &wrong_workspace_manifest_reply,
            "zcl.zcode_workspace_manifest_plan.v1");
        zcl_native_handle_zcode_workspace_manifest_plan(
            &workspace_manifest_request, &wrong_workspace_manifest_reply);
        ASSERT_EQ(wrong_workspace_manifest_reply.exit_code,
                  ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(wrong_workspace_manifest_reply.error.code,
                      "WORKSPACE_MANIFEST_JOB_BINDING_INVALID");
        zcl_command_reply_free(&wrong_workspace_manifest_reply);
        json_set_str(workspace_release_value, correct_workspace_release);
        struct zcl_command_reply workspace_manifest_plan_reply;
        zcl_command_reply_init(
            &workspace_manifest_plan_reply,
            "zcl.zcode_workspace_manifest_plan.v1");
        zcl_native_handle_zcode_workspace_manifest_plan(
            &workspace_manifest_request, &workspace_manifest_plan_reply);
        ASSERT_EQ(workspace_manifest_plan_reply.exit_code,
                  ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&workspace_manifest_plan_reply.data,
                                      "will_persist_on_commit")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &workspace_manifest_plan_reply.data,
                          "passport_root")),
                      published_passport_root_saved);
        const char *workspace_signing_payload_hex = json_get_str(json_get(
            &workspace_manifest_plan_reply.data, "signing_payload"));
        ASSERT(workspace_signing_payload_hex != NULL);
        uint8_t workspace_signing_payload[
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES];
        ASSERT(zcl_hex_decode_lower(
            workspace_signing_payload_hex, workspace_signing_payload,
            sizeof(workspace_signing_payload)));
        uint8_t workspace_manifest_signature[64];
        ed25519_sign(workspace_manifest_signature,
                     workspace_signing_payload,
                     sizeof(workspace_signing_payload),
                     workspace_manifest_secret,
                     workspace_manifest_pubkey);
        memset(workspace_manifest_secret, 0,
               sizeof(workspace_manifest_secret));
        zcl_command_reply_free(&workspace_manifest_plan_reply);
        char workspace_manifest_signature_hex[129];
        zcl_hex_encode(workspace_manifest_signature,
                       sizeof(workspace_manifest_signature),
                       workspace_manifest_signature_hex);
        ASSERT(json_push_kv_str(&workspace_manifest_input, "signature",
                                workspace_manifest_signature_hex));
        struct zcl_command_reply workspace_manifest_commit_reply;
        zcl_command_reply_init(
            &workspace_manifest_commit_reply,
            "zcl.zcode_workspace_manifest_commit.v1");
        zcl_native_handle_zcode_workspace_manifest_commit(
            &workspace_manifest_request, &workspace_manifest_commit_reply);
        ASSERT_EQ(workspace_manifest_commit_reply.exit_code,
                  ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&workspace_manifest_commit_reply.data,
                                      "persisted")));
        ASSERT(!json_get_bool(json_get(
            &workspace_manifest_commit_reply.data, "published")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &workspace_manifest_commit_reply.data,
                          "publication_status")),
                      "WORKSPACE_PUBLISHED");
        ASSERT(!json_get_bool(json_get(
            &workspace_manifest_commit_reply.data, "progress_reused")));
        const char *published_workspace_root = json_get_str(json_get(
            &workspace_manifest_commit_reply.data, "manifest_root"));
        const char *published_workspace_wire = json_get_str(json_get(
            &workspace_manifest_commit_reply.data, "manifest"));
        ASSERT(published_workspace_root && published_workspace_wire);
        uint8_t workspace_root[32], *stored_workspace = NULL;
        size_t stored_workspace_len = 0;
        ASSERT(zcl_hex_decode_lower(published_workspace_root,
                                    workspace_root, 32));
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, workspace_root,
                      VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES +
                          VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES,
                      &stored_workspace, &stored_workspace_len), 0);
        struct vcs_zcode_workspace_manifest_v1_decoded stored_manifest = {0};
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_decode(
                      &stored_manifest, stored_workspace,
                      stored_workspace_len), VCS_ZCODE_COMMONS_V2_OK);
        ASSERT(memcmp(stored_manifest.manifest.entries[0].module_passport_root,
                      passport_root, 32) == 0);
        vcs_zcode_workspace_manifest_v1_decoded_free(&stored_manifest);
        free(stored_workspace);
        struct vcs_devloop_publication_receipt workspace_progress;
        uint8_t workspace_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED);
        ASSERT(memcmp(workspace_progress.artifact_root,
                      workspace_root, 32) == 0);
        zcl_command_reply_free(&workspace_manifest_commit_reply);
        zcl_command_reply_init(
            &workspace_manifest_commit_reply,
            "zcl.zcode_workspace_manifest_commit.v1");
        zcl_native_handle_zcode_workspace_manifest_commit(
            &workspace_manifest_request, &workspace_manifest_commit_reply);
        ASSERT_EQ(workspace_manifest_commit_reply.exit_code,
                  ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(
            &workspace_manifest_commit_reply.data, "progress_reused")));
        zcl_command_reply_free(&workspace_manifest_commit_reply);
        zcl_command_reply_init(&passport_commit_reply,
                               "zcl.zcode_passport_commit.v1");
        zcl_native_handle_zcode_passport_commit(&passport_plan_request,
                                                &passport_commit_reply);
        ASSERT_EQ(passport_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_commit_reply.data,
                                      "progress_reused")));
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED);
        zcl_command_reply_free(&passport_commit_reply);

        uint8_t provider_transport_root[32];
        ASSERT(zcl_hex_decode_lower(planned_package_saved,
                                    provider_transport_root, 32));
        struct vcs_zcode_dht_record_verify_context provider_verify;
        struct vcs_zcode_dht_record provider_record;
        uint8_t provider_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        unsigned provider_chain_calls = 0;
        ASSERT(zd_provider_record(
            provider_transport_root, &provider_verify, &provider_record,
            provider_wire, &provider_chain_calls));
        uint8_t wrong_provider_transport[32];
        memcpy(wrong_provider_transport, provider_transport_root, 32);
        wrong_provider_transport[0] ^= 0x80u;
        struct vcs_zcode_dht_record_verify_context wrong_provider_verify;
        struct vcs_zcode_dht_record wrong_provider_record;
        uint8_t wrong_provider_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        unsigned wrong_provider_chain_calls = 0;
        ASSERT(zd_provider_record(
            wrong_provider_transport, &wrong_provider_verify,
            &wrong_provider_record, wrong_provider_wire,
            &wrong_provider_chain_calls));
        uint8_t refused_provider_root[32];
        bool refused_provider_reused = true;
        ASSERT(!vcs_devloop_publication_advance_provider(
            workspace, publication_anchor.publication_job_root,
            wrong_provider_wire, sizeof(wrong_provider_wire),
            &wrong_provider_verify, refused_provider_root,
            &refused_provider_reused));
        ASSERT(!refused_provider_reused);
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED);
        uint8_t provider_progress_root[32];
        bool provider_reused = true;
        ASSERT(vcs_devloop_publication_advance_provider(
            workspace, publication_anchor.publication_job_root,
            provider_wire, sizeof(provider_wire), &provider_verify,
            provider_progress_root, &provider_reused));
        ASSERT(!provider_reused);
        ASSERT(provider_chain_calls > 0);
        struct vcs_devloop_publication_receipt provider_progress;
        uint8_t loaded_provider_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &provider_progress, loaded_provider_progress_root));
        ASSERT_EQ(provider_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED);
        ASSERT_EQ(provider_progress.providers, 1u);
        ASSERT_EQ(provider_progress.storage_acks, 0u);
        ASSERT(memcmp(provider_progress.predecessor_receipt_root,
                      workspace_progress_root, 32) == 0);
        uint8_t provider_record_root[32];
        ASSERT_EQ(vcs_zcode_dht_record_id(
                      &provider_record, provider_record_root),
                  VCS_ZCODE_DHT_RECORD_OK);
        ASSERT(memcmp(provider_progress.artifact_root,
                      provider_record_root, 32) == 0);
        uint8_t *stored_provider_wire = NULL;
        size_t stored_provider_wire_len = 0;
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, provider_record_root,
                      VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                      &stored_provider_wire, &stored_provider_wire_len), 0);
        ASSERT_EQ(stored_provider_wire_len,
                  VCS_ZCODE_DHT_RECORD_WIRE_BYTES);
        ASSERT(memcmp(stored_provider_wire, provider_wire,
                      sizeof(provider_wire)) == 0);
        free(stored_provider_wire);
        provider_reused = false;
        uint8_t provider_retry_root[32];
        ASSERT(vcs_devloop_publication_advance_provider(
            workspace, publication_anchor.publication_job_root,
            provider_wire, sizeof(provider_wire), &provider_verify,
            provider_retry_root, &provider_reused));
        ASSERT(provider_reused);
        ASSERT(memcmp(provider_retry_root,
                      provider_progress_root, 32) == 0);
        struct vcs_devloop_publication_ack_target ack_target;
        ASSERT(vcs_devloop_publication_storage_ack_target(
            workspace, publication_anchor.publication_job_root,
            &provider_verify, &ack_target));
        ASSERT_STR_EQ(ack_target.namespace_name, "zclassic23.source");
        ASSERT(memcmp(ack_target.transport_root,
                      provider_transport_root, 32) == 0);
        ASSERT_EQ(ack_target.existing_acks, 0u);
        ASSERT(!ack_target.already_acknowledged);
        struct json_value provider_status_input;
        json_init(&provider_status_input);
        json_set_object(&provider_status_input);
        ASSERT(json_push_kv_str(&provider_status_input, "job_root",
                                publication_job_hex));
        struct zcl_command_context provider_status_context = {
            .source_root = workspace,
            .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR,
            .dev_build = true,
        };
        struct zcl_command_request provider_status_request = {
            .context = &provider_status_context,
            .input = &provider_status_input,
        };
        struct zcl_command_reply provider_status_reply;
        zcl_command_reply_init(&provider_status_reply,
                               "zcl.dev_publication_status.v1");
        zcl_native_handle_dev_publication_status(
            &provider_status_request, &provider_status_reply);
        ASSERT_EQ(provider_status_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "status")),
                      "PROVIDER_ANNOUNCED");
        char provider_record_hex[65];
        zcl_hex_encode(provider_record_root, 32, provider_record_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data,
                          "provider_record_root")),
                      provider_record_hex);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "p2p")),
                      "announced");
        ASSERT_EQ(json_get_int(json_get(
                      &provider_status_reply.data, "providers")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "blocker")),
                      "storage_ack_required");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "github_mirror")),
                      "mirror_pending");
        zcl_command_reply_free(&provider_status_reply);

        uint8_t mirror_git_oid[20];
        for (size_t i = 0; i < sizeof(mirror_git_oid); i++)
            mirror_git_oid[i] = (uint8_t)(0xb1u + i);
        char mirror_git_hex[41];
        zcl_hex_encode(mirror_git_oid, sizeof(mirror_git_oid),
                       mirror_git_hex);
        struct json_value mirror_input;
        json_init(&mirror_input);
        json_set_object(&mirror_input);
        ASSERT(json_push_kv_str(&mirror_input, "job_root",
                                publication_job_hex));
        ASSERT(json_push_kv_str(&mirror_input, "git_oid", mirror_git_hex));
        struct zcl_command_request mirror_request = {
            .context = &provider_status_context,
            .input = &mirror_input,
        };
        struct zcl_command_reply mirror_reply;
        zcl_command_reply_init(
            &mirror_reply, "zcl.dev_publication_mirror_record.v1");
        zcl_native_handle_dev_publication_mirror_record(
            &mirror_request, &mirror_reply);
        ASSERT_EQ(mirror_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &mirror_reply.data, "status")),
                      "RECORDED_DECLARED");
        ASSERT(!json_get_bool(json_get(
            &mirror_reply.data, "receipt_reused")));
        ASSERT(!json_get_bool(json_get(&mirror_reply.data, "git_called")));
        ASSERT(!json_get_bool(json_get(
            &mirror_reply.data, "network_called")));
        const char *mirror_receipt_hex = json_get_str(json_get(
            &mirror_reply.data, "mirror_receipt_root"));
        ASSERT(mirror_receipt_hex);
        char mirror_receipt_saved[65];
        ASSERT(snprintf(mirror_receipt_saved, sizeof(mirror_receipt_saved),
                        "%s", mirror_receipt_hex) == 64);
        uint8_t mirror_receipt_root[32], loaded_mirror_root[32];
        ASSERT(zcl_hex_decode_lower(mirror_receipt_saved,
                                    mirror_receipt_root, 32));
        struct vcs_devloop_mirror_receipt mirror_receipt;
        ASSERT_EQ(vcs_devloop_mirror_load_for_job(
                      workspace, publication_anchor.publication_job_root,
                      &mirror_receipt, loaded_mirror_root),
                  VCS_DEVLOOP_MIRROR_FOUND);
        ASSERT(memcmp(loaded_mirror_root, mirror_receipt_root, 32) == 0);
        ASSERT(memcmp(mirror_receipt.vcs_commit_root,
                      publication_anchor.commit_id, 32) == 0);
        ASSERT(memcmp(mirror_receipt.proof_receipt_root,
                      publication_anchor.proof_receipt_root, 32) == 0);
        ASSERT(memcmp(mirror_receipt.release_root,
                      published_release, 32) == 0);
        ASSERT(memcmp(mirror_receipt.workspace_root,
                      workspace_root, 32) == 0);
        ASSERT(memcmp(mirror_receipt.provider_record_root,
                      provider_record_root, 32) == 0);
        ASSERT_EQ(mirror_receipt.git_oid_len, sizeof(mirror_git_oid));
        ASSERT(memcmp(mirror_receipt.git_oid, mirror_git_oid,
                      sizeof(mirror_git_oid)) == 0);
        zcl_command_reply_free(&mirror_reply);
        zcl_command_reply_init(
            &mirror_reply, "zcl.dev_publication_mirror_record.v1");
        zcl_native_handle_dev_publication_mirror_record(
            &mirror_request, &mirror_reply);
        ASSERT_EQ(mirror_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(
            &mirror_reply.data, "receipt_reused")));
        zcl_command_reply_free(&mirror_reply);
        uint8_t different_git_oid[20], refused_mirror_root[32];
        memcpy(different_git_oid, mirror_git_oid, sizeof(different_git_oid));
        different_git_oid[0] ^= 1u;
        bool refused_mirror_reused = true;
        ASSERT(!vcs_devloop_mirror_record(
            workspace, publication_anchor.publication_job_root,
            different_git_oid, sizeof(different_git_oid),
            refused_mirror_root, &refused_mirror_reused));
        ASSERT(!refused_mirror_reused);

        zcl_command_reply_init(&provider_status_reply,
                               "zcl.dev_publication_status.v1");
        zcl_native_handle_dev_publication_status(
            &provider_status_request, &provider_status_reply);
        ASSERT_EQ(provider_status_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "github_mirror")),
                      "recorded_declared");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data,
                          "mirror_receipt_root")),
                      mirror_receipt_saved);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "mirror_git_oid")),
                      mirror_git_hex);
        zcl_command_reply_free(&provider_status_reply);

        struct vcs_zcode_dht_record ack_records[2];
        uint8_t ack_wires[2][VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        uint64_t ack_now = (uint64_t)platform_time_wall_time_t();
        ASSERT(zd_storage_ack_record(
            provider_transport_root, 0x31, 0x41, ack_now,
            &ack_records[0], ack_wires[0]));
        ASSERT(zd_storage_ack_record(
            provider_transport_root, 0x32, 0x42, ack_now,
            &ack_records[1], ack_wires[1]));
        const uint8_t *ack_wire_ptrs[2] = {ack_wires[0], ack_wires[1]};
        size_t ack_wire_lengths[2] = {
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
        };
        uint8_t ack_progress_root[32];
        bool ack_reused = true;
        struct vcs_zcode_dht_record_verify_context ack_verify = {
            .now_unix = ack_now,
        };
        memset(ack_verify.network_genesis, 0x01,
               sizeof(ack_verify.network_genesis));
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            workspace, publication_anchor.publication_job_root,
            ack_wire_ptrs, ack_wire_lengths, 1, &ack_verify,
            ack_progress_root, &ack_reused));
        ASSERT(!ack_reused);

        struct vcs_zcode_dht_record same_group_record;
        uint8_t same_group_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        ASSERT(zd_storage_ack_record(
            provider_transport_root, 0x33, 0x41, ack_now,
            &same_group_record, same_group_wire));
        const uint8_t *same_group_ptrs[2] = {
            ack_wires[0], same_group_wire,
        };
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            workspace, publication_anchor.publication_job_root,
            same_group_ptrs, ack_wire_lengths, 2, &ack_verify,
            ack_progress_root, &ack_reused));

        uint8_t wrong_ack_transport[32];
        memcpy(wrong_ack_transport, provider_transport_root, 32);
        wrong_ack_transport[0] ^= 0x80u;
        struct vcs_zcode_dht_record wrong_package_record;
        uint8_t wrong_package_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        ASSERT(zd_storage_ack_record(
            wrong_ack_transport, 0x34, 0x44, ack_now,
            &wrong_package_record, wrong_package_wire));
        const uint8_t *wrong_package_ptrs[2] = {
            ack_wires[0], wrong_package_wire,
        };
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            workspace, publication_anchor.publication_job_root,
            wrong_package_ptrs, ack_wire_lengths, 2, &ack_verify,
            ack_progress_root, &ack_reused));

        struct vcs_zcode_dht_record_verify_context wrong_network_verify =
            ack_verify;
        memset(wrong_network_verify.network_genesis, 0x02,
               sizeof(wrong_network_verify.network_genesis));
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            workspace, publication_anchor.publication_job_root,
            ack_wire_ptrs, ack_wire_lengths, 2, &wrong_network_verify,
            ack_progress_root, &ack_reused));
        struct vcs_zcode_dht_record_verify_context expired_ack_verify =
            ack_verify;
        expired_ack_verify.now_unix = ack_now + 3601u;
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            workspace, publication_anchor.publication_job_root,
            ack_wire_ptrs, ack_wire_lengths, 2, &expired_ack_verify,
            ack_progress_root, &ack_reused));
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED);

        zcl_hex_encode(ack_wires[0], sizeof(ack_wires[0]),
                       zd_collect_ack_wires[0]);
        zcl_hex_encode(ack_wires[1], sizeof(ack_wires[1]),
                       zd_collect_ack_wires[1]);
        zcl_hex_encode(provider_transport_root, 32,
                       zd_collect_transport_hex);
        zd_collect_ack_wire_count = 1;
        zd_collect_genesis_calls = 0;
        zd_collect_begin_calls = 0;
        zd_collect_poll_calls = 0;
        zd_collect_cancel_calls = 0;
        zd_collect_selector_exact = false;
        node_rpc_client_set_test_hook(zd_collect_rpc_hook);
        struct zcl_command_reply collect_reply;
        zcl_command_reply_init(&collect_reply,
                               "zcl.dev_publication_collect.v1");
        zcl_native_handle_dev_publication_collect(
            &provider_status_request, &collect_reply);
        ASSERT_EQ(collect_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&collect_reply.data, "status")),
                      "ACKS_PENDING");
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "records_seen")), 1);
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "evidence_wires")), 1);
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_written")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_reused")));
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "network_called")));
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "discovery_called")));
        ASSERT_EQ(zd_collect_genesis_calls, 1u);
        ASSERT_EQ(zd_collect_begin_calls, 1u);
        ASSERT_EQ(zd_collect_poll_calls, 1u);
        /* One terminal poll, one release. The bounded lookup capability
         * goes back to the node as soon as the answer is in hand; holding
         * it through the retention window would refuse the next honest
         * discovery for a reason that has nothing to do with the network.
         * This used to assert 0 — the old wrapper cancelled only when the
         * poll had NOT passed. */
        ASSERT_EQ(zd_collect_cancel_calls, 1u);
        ASSERT(zd_collect_selector_exact);
        zcl_command_reply_free(&collect_reply);
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED);

        zd_collect_ack_wire_count = 2;
        zcl_command_reply_init(&collect_reply,
                               "zcl.dev_publication_collect.v1");
        zcl_native_handle_dev_publication_collect(
            &provider_status_request, &collect_reply);
        ASSERT_EQ(collect_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&collect_reply.data, "status")),
                      "STORAGE_ACKNOWLEDGED");
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "records_seen")), 2);
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "evidence_wires")), 2);
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "storage_acks")), 2);
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "receipt_written")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_reused")));
        const char *ack_progress_hex = json_get_str(json_get(
            &collect_reply.data, "progress_receipt_root"));
        ASSERT(ack_progress_hex != NULL);
        ASSERT(zcl_hex_decode_lower(ack_progress_hex,
                                    ack_progress_root, 32));
        zcl_command_reply_free(&collect_reply);
        struct vcs_devloop_publication_receipt ack_progress;
        uint8_t loaded_ack_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &ack_progress, loaded_ack_progress_root));
        ASSERT_EQ(ack_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED);
        ASSERT_EQ(ack_progress.providers, 2u);
        ASSERT_EQ(ack_progress.storage_acks, 2u);
        ASSERT(memcmp(ack_progress.predecessor_receipt_root,
                      provider_progress_root, 32) == 0);
        ASSERT(memcmp(ack_progress_root,
                      loaded_ack_progress_root, 32) == 0);
        ASSERT(vcs_devloop_publication_storage_ack_target(
            workspace, publication_anchor.publication_job_root,
            &provider_verify, &ack_target));
        ASSERT_EQ(ack_target.existing_acks, 2u);
        ASSERT(ack_target.already_acknowledged);

        struct vcs_devloop_publication_ack_target reproduction_target;
        ASSERT(vcs_devloop_publication_source_reproduction_target(
            workspace, publication_anchor.publication_job_root,
            &provider_verify, &reproduction_target));
        ASSERT_STR_EQ(reproduction_target.namespace_name,
                      "zclassic23.source");
        ASSERT(memcmp(reproduction_target.transport_root,
                      provider_transport_root, 32) == 0);
        ASSERT(memcmp(reproduction_target.source_root,
                      candidate_source_root, 32) == 0);
        ASSERT_EQ(reproduction_target.existing_acks, 2u);
        ASSERT(reproduction_target.already_acknowledged);
        ASSERT(!reproduction_target.already_reproduced);

        struct vcs_zcode_dht_record reproduction_record;
        uint8_t reproduction_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        ASSERT(zd_source_reproduction_record(
            provider_transport_root, candidate_source_root,
            0x51, 0x53, 0x61, "zclassic23.source", ack_now,
            &reproduction_record, reproduction_wire));
        struct vcs_zcode_dht_record conflicting_reproduction;
        uint8_t conflicting_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        uint8_t reproduction_progress_root[32];
        bool reproduction_reused = true;

        ASSERT(zd_source_reproduction_record(
            provider_transport_root, candidate_source_root,
            0x31, 0x33, 0x62, "zclassic23.source", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));
        ASSERT(!reproduction_reused);

        ASSERT(zd_source_reproduction_record(
            provider_transport_root, candidate_source_root,
            0x52, 0x54, 0x41, "zclassic23.source", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));

        ASSERT(zd_source_reproduction_record(
            provider_transport_root, candidate_source_root,
            0x52, 0x55, 0x62, "zclassic23.source", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));

        uint8_t wrong_reproduction_source[32];
        memcpy(wrong_reproduction_source, candidate_source_root, 32);
        wrong_reproduction_source[0] ^= 0x40u;
        ASSERT(zd_source_reproduction_record(
            provider_transport_root, wrong_reproduction_source,
            0x52, 0x54, 0x62, "zclassic23.source", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));

        ASSERT(zd_source_reproduction_record(
            wrong_ack_transport, candidate_source_root,
            0x52, 0x54, 0x62, "zclassic23.source", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));

        ASSERT(zd_source_reproduction_record(
            provider_transport_root, candidate_source_root,
            0x52, 0x54, 0x62, "zclassic23.other", ack_now,
            &conflicting_reproduction, conflicting_wire));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            conflicting_wire, sizeof(conflicting_wire), &ack_verify,
            reproduction_progress_root, &reproduction_reused));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            reproduction_wire, sizeof(reproduction_wire),
            &wrong_network_verify, reproduction_progress_root,
            &reproduction_reused));
        ASSERT(!vcs_devloop_publication_advance_source_reproduction_ack(
            workspace, publication_anchor.publication_job_root,
            reproduction_wire, sizeof(reproduction_wire),
            &expired_ack_verify, reproduction_progress_root,
            &reproduction_reused));
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &workspace_progress, workspace_progress_root));
        ASSERT_EQ(workspace_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED);

        zd_collect_kind = "source_reproduction_ack";
        zd_collect_ack_wire_count = 0;
        zd_collect_genesis_calls = 0;
        zd_collect_begin_calls = 0;
        zd_collect_poll_calls = 0;
        zd_collect_selector_exact = false;
        zcl_command_reply_init(&collect_reply,
                               "zcl.dev_publication_collect.v1");
        zcl_native_handle_dev_publication_collect(
            &provider_status_request, &collect_reply);
        ASSERT_EQ(collect_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&collect_reply.data, "status")),
                      "SOURCE_REPRODUCTION_PENDING");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &collect_reply.data, "blocker")),
                      "distinct_signed_source_reconstruction_required");
        ASSERT(strstr(json_get_str(json_get(
                          &collect_reply.data, "next_command")),
                      "zcode package source reproduce") != NULL);
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_reused")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_written")));
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "network_called")));
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "discovery_called")));
        ASSERT_EQ(zd_collect_genesis_calls, 1u);
        ASSERT_EQ(zd_collect_begin_calls, 1u);
        ASSERT_EQ(zd_collect_poll_calls, 1u);
        ASSERT(zd_collect_selector_exact);
        zcl_command_reply_free(&collect_reply);

        zcl_hex_encode(conflicting_wire, sizeof(conflicting_wire),
                       zd_collect_ack_wires[0]);
        zcl_hex_encode(reproduction_wire, sizeof(reproduction_wire),
                       zd_collect_ack_wires[1]);
        zd_collect_ack_wire_count = 2;
        zcl_command_reply_init(&collect_reply,
                               "zcl.dev_publication_collect.v1");
        zcl_native_handle_dev_publication_collect(
            &provider_status_request, &collect_reply);
        ASSERT_EQ(collect_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&collect_reply.data, "status")),
                      "SOURCE_REPRODUCED");
        ASSERT_EQ(json_get_int(json_get(
                      &collect_reply.data, "storage_acks")), 2);
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "receipt_written")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_reused")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &collect_reply.data, "reproduced")),
                      "signed_distinct_source_reconstruction");
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "physical_independence_attested")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &collect_reply.data, "blocker")),
                      "physical_off_host_attestation_not_represented");
        const char *reproduction_progress_hex = json_get_str(json_get(
            &collect_reply.data, "progress_receipt_root"));
        ASSERT(reproduction_progress_hex != NULL);
        ASSERT(zcl_hex_decode_lower(reproduction_progress_hex,
                                    reproduction_progress_root, 32));
        zcl_command_reply_free(&collect_reply);

        struct vcs_devloop_publication_receipt reproduction_progress;
        uint8_t loaded_reproduction_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            workspace, publication_anchor.publication_job_root,
            &reproduction_progress, loaded_reproduction_progress_root));
        ASSERT_EQ(reproduction_progress.phase,
                  VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED);
        ASSERT_EQ(reproduction_progress.storage_acks, 2u);
        ASSERT(memcmp(reproduction_progress.predecessor_receipt_root,
                      ack_progress_root, 32) == 0);
        ASSERT(memcmp(reproduction_progress_root,
                      loaded_reproduction_progress_root, 32) == 0);
        uint8_t reproduction_record_root[32];
        ASSERT_EQ(vcs_zcode_dht_record_id(
                      &reproduction_record, reproduction_record_root),
                  VCS_ZCODE_DHT_RECORD_OK);
        ASSERT(memcmp(reproduction_progress.artifact_root,
                      reproduction_record_root, 32) == 0);
        uint8_t *saved_reproduction_wire = NULL;
        size_t saved_reproduction_wire_len = 0;
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, reproduction_record_root,
                      VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                      &saved_reproduction_wire,
                      &saved_reproduction_wire_len), 0);
        ASSERT_EQ(saved_reproduction_wire_len,
                  VCS_ZCODE_DHT_RECORD_WIRE_BYTES);
        ASSERT(memcmp(saved_reproduction_wire, reproduction_wire,
                      sizeof(reproduction_wire)) == 0);
        free(saved_reproduction_wire);

        zd_collect_ack_wire_count = 0;
        zd_collect_genesis_calls = 0;
        zd_collect_begin_calls = 0;
        zd_collect_poll_calls = 0;
        zcl_command_reply_init(&collect_reply,
                               "zcl.dev_publication_collect.v1");
        zcl_native_handle_dev_publication_collect(
            &provider_status_request, &collect_reply);
        ASSERT_EQ(collect_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&collect_reply.data, "status")),
                      "SOURCE_REPRODUCED");
        ASSERT(json_get_bool(json_get(
            &collect_reply.data, "receipt_reused")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "receipt_written")));
        ASSERT(!json_get_bool(json_get(
            &collect_reply.data, "discovery_called")));
        ASSERT_EQ(zd_collect_genesis_calls, 1u);
        ASSERT_EQ(zd_collect_begin_calls, 0u);
        ASSERT_EQ(zd_collect_poll_calls, 0u);
        zcl_command_reply_free(&collect_reply);
        node_rpc_client_set_test_hook(NULL);
        zcl_command_reply_init(&provider_status_reply,
                               "zcl.dev_publication_status.v1");
        zcl_native_handle_dev_publication_status(
            &provider_status_request, &provider_status_reply);
        ASSERT_EQ(provider_status_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "status")),
                      "SOURCE_REPRODUCED");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "storage_ack")),
                      "2/2");
        ASSERT_EQ(json_get_int(json_get(
                      &provider_status_reply.data, "providers")), 2);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "blocker")),
                      "physical_off_host_attestation_not_represented");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "reproduced")),
                      "signed_distinct_source_reconstruction");
        ASSERT(!json_get_bool(json_get(
            &provider_status_reply.data,
            "physical_independence_attested")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data, "github_mirror")),
                      "recorded_declared");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &provider_status_reply.data,
                          "provider_record_root")),
                      provider_record_hex);
        zcl_command_reply_free(&provider_status_reply);
        json_free(&mirror_input);
        json_free(&provider_status_input);

        json_free(&workspace_manifest_input);
        json_free(&passport_plan_input);
        zcl_command_reply_free(&publish_commit_reply);
        json_free(&publish_commit_input);
        zcl_command_reply_free(&seal_reply);
        json_free(&seal_input);
        zcl_command_reply_free(&publish_plan_reply);
        json_free(&publish_plan_input);
        secp256k1_context_destroy(publish_ctx);
        test_rm_rf(publication_seed);

        json_set_str((struct json_value *)json_get(&accept_input, "lane"),
                     "PROVEN");
        struct zcl_command_reply proven_reply;
        zcl_command_reply_init(&proven_reply, "zcl.zcode_accept.v1");
        zcl_native_handle_zcode_accept(&accept_request, &proven_reply);
        ASSERT_EQ(proven_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(proven_reply.error.code, "BAD_ACCEPT_INPUT");
        zcl_command_reply_free(&proven_reply);
        zcl_command_reply_free(&lane_reply);
        json_free(&lane_input);
        zcl_command_reply_free(&accept_reply);
        json_free(&accept_input);

        struct json_value evidence_input;
        json_init(&evidence_input); json_set_object(&evidence_input);
        (void)json_push_kv_str(&evidence_input, "workspace", workspace);
        (void)json_push_kv_str(&evidence_input, "datadir", workspace);
        (void)json_push_kv_str(&evidence_input, "action_id", action_id);
        struct zcl_command_request evidence_request = {
            .input = &evidence_input,
        };
        struct zcl_command_reply evidence_reply;
        zcl_command_reply_init(&evidence_reply, "zcl.zcode_evidence.v1");
        zcl_native_handle_zcode_evidence(&evidence_request, &evidence_reply);
        ASSERT_EQ(evidence_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&evidence_reply.data, "authority")),
                      "LOCAL_REPRODUCTION");
        ASSERT_EQ(json_get_int(json_get(&evidence_reply.data,
                                        "test_receipts")), 3);
        ASSERT_EQ(json_get_int(json_get(&evidence_reply.data,
                                        "fuzz_receipts")), 2);
        ASSERT_EQ(json_get_int(json_get(&evidence_reply.data,
                                        "review_receipts")), 1);
        ASSERT(json_get_bool(json_get(&evidence_reply.data,
                                      "test_satisfied")));
        ASSERT(json_get_bool(json_get(&evidence_reply.data,
                                      "fuzz_satisfied")));
        ASSERT(json_get_bool(json_get(&evidence_reply.data,
                                      "review_satisfied")));
        ASSERT(json_get_bool(json_get(&evidence_reply.data,
                                      "release_identity_satisfied")));
        ASSERT(json_get_bool(json_get(&evidence_reply.data,
                                      "policy_satisfied")));
        zcl_command_reply_free(&evidence_reply);
        json_free(&evidence_input);
        free(task_recipe_hex); free(task_recipe_wire);
        free(task_lock_hex); free(task_lock_wire);
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static bool zd_index_store_task(const char *workspace,
                                struct vcs_zcode_task_v1 *task,
                                uint8_t out_root[32])
{
    uint8_t wire[VCS_ZCODE_TASK_WIRE_BYTES];
    return vcs_zcode_task_serialize(task, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, out_root) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, out_root, wire, sizeof(wire));
}

static bool zd_index_store_candidate(const char *workspace,
                                     struct vcs_zcode_candidate_v1 *candidate,
                                     uint8_t out_root[32])
{
    uint8_t wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_candidate_serialize(candidate, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(candidate, out_root) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, out_root, wire, sizeof(wire));
}

static bool zd_index_drop_object(const char *workspace, const uint8_t root[32])
{
    char hex[65], path[4608];
    zcl_hex_encode(root, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/.zvcs/objects/%c%c/%s",
                     workspace, hex[0], hex[1], hex + 2);
    return n > 0 && (size_t)n < sizeof(path) && unlink(path) == 0;
}

static int test_zd_task_index(void)
{
    int failures = 0;
    TEST("zcode_dev: task index is a rebuildable projection over CAS wires") {
        char dir[256], workspace[4096];
        test_make_tmpdir(dir, sizeof(dir), "zcode_dev", "task_index");
        ASSERT(realpath(dir, workspace) != NULL);
        ASSERT(vcs_object_store_init(workspace));
        struct vcs_zcode_proof_policy_v1 policy;
        zd_policy(&policy);
        uint8_t policy_root[32];
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);

        /* Two live tasks and one expired task, each a distinct CAS wire. */
        struct vcs_zcode_task_v1 task_a, task_b, task_expired;
        zd_task(&task_a, policy_root);
        zd_task(&task_b, policy_root);
        zd_root(task_b.model_policy_root, 0x17);
        zd_root(task_b.goal_root, 0x18);
        zd_task(&task_expired, policy_root);
        zd_root(task_expired.model_policy_root, 0x27);
        zd_root(task_expired.goal_root, 0x28);
        task_expired.expires_unix = 1000;
        uint8_t root_a[32], root_b[32], root_expired[32];
        ASSERT(zd_index_store_task(workspace, &task_a, root_a));
        ASSERT(zd_index_store_task(workspace, &task_b, root_b));
        ASSERT(zd_index_store_task(workspace, &task_expired, root_expired));

        /* Decoys: a same-size blob without task magic, and a valid task
         * wire stored under a false address. Neither may be projected. */
        uint8_t blob[VCS_ZCODE_TASK_WIRE_BYTES];
        memset(blob, 0x5a, sizeof(blob));
        uint8_t blob_hash[32];
        ASSERT(vcs_object_put(workspace, blob, sizeof(blob), VCS_TAG_BLOB,
                              blob_hash));
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_task_serialize(&task_b, task_wire),
                  VCS_ZCODE_DEV_OK);
        uint8_t false_address[32];
        zd_root(false_address, 0x66);
        ASSERT(vcs_object_put_addressed(workspace, false_address, task_wire,
                                        sizeof(task_wire)));

        const int64_t now = 1500;
        struct vcs_zcode_task_index *index =
            vcs_zcode_task_index_build(workspace, now);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_task_index_task_count(index), 3);
        ASSERT_EQ(vcs_zcode_task_index_candidate_count(index), 0);
        char root_a_hex[65], root_b_hex[65], root_expired_hex[65];
        zcl_hex_encode(root_a, 32, root_a_hex);
        zcl_hex_encode(root_b, 32, root_b_hex);
        zcl_hex_encode(root_expired, 32, root_expired_hex);
        for (size_t i = 1; i < vcs_zcode_task_index_task_count(index); i++)
            ASSERT(strcmp(
                vcs_zcode_task_index_task_at(index, i - 1u)->task_root_hex,
                vcs_zcode_task_index_task_at(index, i)->task_root_hex) < 0);
        const struct vcs_zcode_task_index_entry *entry_a =
            vcs_zcode_task_index_find(index, root_a);
        ASSERT(entry_a != NULL);
        ASSERT_STR_EQ(entry_a->state, "AWAITING_CANDIDATE");
        ASSERT(!entry_a->expired);
        ASSERT_EQ(entry_a->expires_unix, 2000);
        const struct vcs_zcode_task_index_entry *entry_expired =
            vcs_zcode_task_index_find(index, root_expired);
        ASSERT(entry_expired != NULL);
        ASSERT(entry_expired->expired);
        ASSERT_STR_EQ(entry_expired->state, "EXPIRED");

        /* A fresh build is the restart proof: nothing is cached, so the
         * projection agrees field-for-field with the previous one. */
        struct vcs_zcode_task_index *restarted =
            vcs_zcode_task_index_build(workspace, now);
        ASSERT(restarted != NULL);
        ASSERT_EQ(vcs_zcode_task_index_task_count(restarted),
                  vcs_zcode_task_index_task_count(index));
        for (size_t i = 0; i < vcs_zcode_task_index_task_count(index); i++) {
            const struct vcs_zcode_task_index_entry *before =
                vcs_zcode_task_index_task_at(index, i);
            const struct vcs_zcode_task_index_entry *after =
                vcs_zcode_task_index_task_at(restarted, i);
            ASSERT_STR_EQ(before->task_root_hex, after->task_root_hex);
            ASSERT_STR_EQ(before->source_root_hex, after->source_root_hex);
            ASSERT_STR_EQ(before->state, after->state);
        }
        vcs_zcode_task_index_free(restarted);

        /* A persisted candidate moves its task to CANDIDATE_ADMITTED. */
        struct vcs_zcode_candidate_v1 candidate;
        zd_candidate(&candidate, &task_a, root_a);
        uint8_t candidate_root[32];
        ASSERT(zd_index_store_candidate(workspace, &candidate, candidate_root));
        vcs_zcode_task_index_free(index);
        index = vcs_zcode_task_index_build(workspace, now);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_task_index_candidate_count(index), 1);
        entry_a = vcs_zcode_task_index_find(index, root_a);
        ASSERT(entry_a != NULL);
        ASSERT_EQ(entry_a->candidate_count, 1u);
        ASSERT_STR_EQ(entry_a->state, "CANDIDATE_ADMITTED");
        const struct vcs_zcode_task_candidate_entry *candidate_entry =
            vcs_zcode_task_index_candidate_at(index, 0);
        ASSERT_STR_EQ(candidate_entry->task_root_hex, root_a_hex);
        uint8_t author[32];
        zd_root(author, 12);
        char author_hex[65];
        zcl_hex_encode(author, 32, author_hex);
        ASSERT_STR_EQ(candidate_entry->author_pubkey_hex, author_hex);

        /* Search filters compose and report totals. */
        struct vcs_zcode_task_search search = {0};
        const struct vcs_zcode_task_index_entry *rows[8];
        ASSERT_EQ(vcs_zcode_task_index_search(index, &search, rows, 8), 3);
        search.state = "AWAITING_CANDIDATE";
        ASSERT_EQ(vcs_zcode_task_index_search(index, &search, rows, 8), 1);
        ASSERT_STR_EQ(rows[0]->task_root_hex, root_b_hex);
        search.state = NULL;
        search.author = author_hex;
        ASSERT_EQ(vcs_zcode_task_index_search(index, &search, rows, 8), 1);
        ASSERT_STR_EQ(rows[0]->task_root_hex, root_a_hex);
        search.author = NULL;
        char task_prefix[9];
        memcpy(task_prefix, root_b_hex, 8);
        task_prefix[8] = '\0';
        search.task_root = task_prefix;
        ASSERT_EQ(vcs_zcode_task_index_search(index, &search, rows, 8), 1);
        search.task_root = NULL;
        search.state = "EXPIRED";
        ASSERT_EQ(vcs_zcode_task_index_search(index, &search, rows, 8), 1);
        ASSERT_STR_EQ(rows[0]->task_root_hex, root_expired_hex);
        search.state = NULL;

        /* The CAS object is the only truth: deleting the candidate wire
         * drops it from the projection; deleting a task wire drops the
         * task. */
        ASSERT(zd_index_drop_object(workspace, candidate_root));
        vcs_zcode_task_index_free(index);
        index = vcs_zcode_task_index_build(workspace, now);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_task_index_candidate_count(index), 0);
        entry_a = vcs_zcode_task_index_find(index, root_a);
        ASSERT(entry_a != NULL);
        ASSERT_STR_EQ(entry_a->state, "AWAITING_CANDIDATE");
        ASSERT(zd_index_drop_object(workspace, root_b));
        vcs_zcode_task_index_free(index);
        index = vcs_zcode_task_index_build(workspace, now);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_task_index_task_count(index), 2);
        ASSERT(vcs_zcode_task_index_find(index, root_b) == NULL);
        vcs_zcode_task_index_free(index);

        /* The typed surface lists the same projection. It judges expiry at
         * the real wall clock, so add one task that is still live. */
        struct vcs_zcode_task_v1 task_live;
        zd_task(&task_live, policy_root);
        zd_root(task_live.model_policy_root, 0x37);
        zd_root(task_live.goal_root, 0x38);
        task_live.expires_unix = (int64_t)platform_time_wall_unix() + 3600;
        uint8_t root_live[32];
        ASSERT(zd_index_store_task(workspace, &task_live, root_live));
        char root_live_hex[65];
        zcl_hex_encode(root_live, 32, root_live_hex);
        struct json_value tasks_input;
        json_init(&tasks_input);
        json_set_object(&tasks_input);
        (void)json_push_kv_str(&tasks_input, "workspace", workspace);
        struct zcl_command_request tasks_request = { .input = &tasks_input };
        struct zcl_command_reply tasks_reply;
        zcl_command_reply_init(&tasks_reply, "zcl.zcode_tasks.v1");
        zcl_native_handle_zcode_tasks(&tasks_request, &tasks_reply);
        ASSERT_EQ(tasks_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&tasks_reply.data, "tasks_scanned")),
                  3);
        ASSERT_STR_EQ(json_get_str(json_get(&tasks_reply.data, "authority")),
                      "CAS_TASK_AND_CANDIDATE_WIRES");
        const struct json_value *tasks = json_get(&tasks_reply.data, "tasks");
        ASSERT(tasks != NULL);
        ASSERT_EQ(json_size(tasks), 3u);
        bool saw_awaiting = false, saw_expired = false;
        for (size_t i = 0; i < 3; i++) {
            const char *state =
                json_get_str(json_get(json_at(tasks, i), "state"));
            saw_awaiting = saw_awaiting ||
                (state && strcmp(state, "AWAITING_CANDIDATE") == 0);
            saw_expired = saw_expired ||
                (state && strcmp(state, "EXPIRED") == 0);
        }
        ASSERT(saw_awaiting && saw_expired);
        zcl_command_reply_free(&tasks_reply);
        (void)json_push_kv_str(&tasks_input, "state", "AWAITING_CANDIDATE");
        struct zcl_command_reply live_reply;
        zcl_command_reply_init(&live_reply, "zcl.zcode_tasks.v1");
        zcl_native_handle_zcode_tasks(&tasks_request, &live_reply);
        ASSERT_EQ(live_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&live_reply.data,
                                        "total_matches")), 1);
        const struct json_value *live_tasks =
            json_get(&live_reply.data, "tasks");
        ASSERT(live_tasks != NULL);
        ASSERT_STR_EQ(
            json_get_str(json_get(json_at(live_tasks, 0), "task_root")),
            root_live_hex);
        zcl_command_reply_free(&live_reply);
        json_set_str((struct json_value *)json_get(&tasks_input, "state"),
                     "EXPIRED");
        struct zcl_command_reply expired_reply;
        zcl_command_reply_init(&expired_reply, "zcl.zcode_tasks.v1");
        zcl_native_handle_zcode_tasks(&tasks_request, &expired_reply);
        ASSERT_EQ(expired_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&expired_reply.data,
                                        "total_matches")), 2);
        const struct json_value *expired_tasks =
            json_get(&expired_reply.data, "tasks");
        ASSERT(expired_tasks != NULL);
        bool saw_expired_root = false;
        for (size_t i = 0; i < 2; i++) {
            const char *root =
                json_get_str(json_get(json_at(expired_tasks, i), "task_root"));
            saw_expired_root = saw_expired_root ||
                (root && strcmp(root, root_expired_hex) == 0);
        }
        ASSERT(saw_expired_root);
        zcl_command_reply_free(&expired_reply);
        json_free(&tasks_input);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_dev_objects(void)
{
    int failures = 0;
    failures += test_zd_write_scope();
    failures += test_zd_patch();
    failures += test_zd_agent_context();
    failures += test_zd_policy_and_task();
    failures += test_zd_candidate_review();
    failures += test_zd_lane_receipt();
    failures += test_zd_receipt();
    failures += test_zd_work_context();
    failures += test_zd_work_swarm();
    failures += test_zd_work_node_duplicate_sessions();
    failures += test_zd_work_node_atomic_admission();
    failures += test_zd_work_node();
    failures += test_zd_work_node_three();
    failures += test_zd_improve_command();
    failures += test_zd_task_index();
    printf("=== zcode_dev_objects: %d failures ===\n", failures);
    return failures;
}
