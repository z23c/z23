/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical, bounded and delegated Sovereign Space v1 proofs. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "crypto/ed25519.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "services/metaverse_space_service.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/space.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_sovereignty_policy.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void space_root(uint8_t out[32], uint8_t value)
{
  memset(out, value, 32);
}

static bool space_delegation(struct vcs_zcode_dht_delegation *out,
                             uint8_t online_seed[32],
                             uint8_t genesis[32])
{
  uint8_t master_seed[32], master_pub[32], master_secret[32];
  uint8_t online_pub[32], online_secret[32], noise[32], beacon[32];
  memset(master_seed, 0x21, 32);
  memset(online_seed, 0x31, 32);
  memset(noise, 0x41, 32);
  memset(beacon, 0x51, 32);
  memset(genesis, 0x61, 32);
  ed25519_keypair(master_pub, master_secret, master_seed);
  ed25519_keypair(online_pub, online_secret, online_seed);
  bool ok = vcs_zcode_dht_delegation_sign(
                out, genesis, online_pub, noise, 100, beacon,
                900, 5000, 7, master_seed) ==
            VCS_ZCODE_DHT_DELEGATION_OK;
  (void)master_pub;
  memset(master_secret, 0, sizeof(master_secret));
  memset(online_secret, 0, sizeof(online_secret));
  return ok;
}

static bool space_current_delegation(
    struct vcs_zcode_dht_delegation *out)
{
  uint8_t master_seed[32], online_seed[32], online_pub[32], online_secret[32];
  uint8_t noise[32], beacon[32], genesis[32];
  memset(master_seed, 0x72, 32);
  memset(online_seed, 0x73, 32);
  memset(noise, 0x74, 32);
  memset(beacon, 0x75, 32);
  memset(genesis, 0x76, 32);
  ed25519_keypair(online_pub, online_secret, online_seed);
  uint64_t now = (uint64_t)platform_time_wall_unix();
  bool ok = now > 1 && vcs_zcode_dht_delegation_sign(
      out, genesis, online_pub, noise, 100, beacon, now - 1,
      now + 3600, 1, master_seed) == VCS_ZCODE_DHT_DELEGATION_OK;
  memset(online_secret, 0, sizeof(online_secret));
  return ok;
}

static void service_fixture(struct vcs_service_descriptor_v1 *service)
{
  memset(service, 0, sizeof(*service));
  service->schema_version = VCS_SERVICE_DESCRIPTOR_VERSION;
  space_root(service->protocol_root, 0x10);
  service->read_verbs = VCS_SERVICE_VERB_DISCOVER |
                        VCS_SERVICE_VERB_FETCH |
                        VCS_SERVICE_VERB_QUERY;
  service->object_count = 2;
  space_root(service->object_roots[0], 0x20);
  space_root(service->object_roots[1], 0x21);
  service->capability_count = 2;
  space_root(service->capability_roots[0], 0x30);
  space_root(service->capability_roots[1], 0x31);
}

static void manifest_fixture(struct vcs_space_manifest_v1 *manifest,
                             uint8_t online_seed[32],
                             uint8_t genesis[32])
{
  memset(manifest, 0, sizeof(*manifest));
  manifest->schema_version = VCS_SPACE_MANIFEST_VERSION;
  manifest->sequence = 9;
  manifest->not_before = 1000;
  manifest->expiry = 2000;
  memcpy(manifest->name, "sovereign lab", 14);
  memcpy(manifest->description, "read-only public research space", 32);
  manifest->service_count = 2;
  space_root(manifest->service_roots[0], 0x10);
  space_root(manifest->service_roots[1], 0x11);
  manifest->object_count = 2;
  space_root(manifest->object_roots[0], 0x20);
  space_root(manifest->object_roots[1], 0x21);
  manifest->portal_count = 2;
  space_root(manifest->portal_roots[0], 0x30);
  space_root(manifest->portal_roots[1], 0x31);
  manifest->has_admission = true;
  space_root(manifest->admission_root, 0x40);
  (void)space_delegation(&manifest->delegation, online_seed, genesis);
}

static bool space_chain(void *ctx,
                        const struct vcs_zcode_dht_delegation *delegation)
{
  int *calls = ctx;
  (*calls)++;
  return delegation && *calls == 1;
}

static bool space_chain_accept(
    void *ctx, const struct vcs_zcode_dht_delegation *delegation)
{
  int *calls = ctx;
  (*calls)++;
  return delegation != NULL;
}

static int test_service_descriptor_wire(void)
{
  int failures = 0;
  TEST("space service descriptor: canonical full-root read-only wire") {
    struct vcs_service_descriptor_v1 service, parsed;
    service_fixture(&service);
    uint8_t wire[VCS_SERVICE_DESCRIPTOR_WIRE_MAX], first_root[32], second_root[32];
    size_t wire_len = 0;
    ASSERT_EQ(vcs_service_descriptor_validate(&service), VCS_SPACE_OK);
    ASSERT_EQ(vcs_service_descriptor_encode(
                  &service, wire, sizeof(wire), &wire_len), VCS_SPACE_OK);
    ASSERT(wire_len > 0 && wire_len <= sizeof(wire));
    ASSERT_EQ(vcs_service_descriptor_decode(&parsed, wire, wire_len),
              VCS_SPACE_OK);
    ASSERT(memcmp(&service, &parsed, sizeof(service)) == 0);
    ASSERT_EQ(vcs_service_descriptor_root(&service, first_root), VCS_SPACE_OK);
    ASSERT_EQ(vcs_service_descriptor_root(&parsed, second_root), VCS_SPACE_OK);
    ASSERT(memcmp(first_root, second_root, 32) == 0);

    uint8_t malformed[VCS_SERVICE_DESCRIPTOR_WIRE_MAX];
    memcpy(malformed, wire, wire_len);
    malformed[43] = VCS_SERVICE_OBJECT_MAX + 1u;
    memset(&parsed, 0xa5, sizeof(parsed));
    ASSERT_EQ(vcs_service_descriptor_decode(&parsed, malformed, wire_len),
              VCS_SPACE_ERR_LIMIT);
    struct vcs_service_descriptor_v1 zero_service;
    memset(&zero_service, 0, sizeof(zero_service));
    ASSERT(memcmp(&parsed, &zero_service, sizeof(parsed)) == 0);

    service.read_verbs |= 0x80;
    ASSERT_EQ(vcs_service_descriptor_validate(&service), VCS_SPACE_ERR_VERB);
    service_fixture(&service);
    memcpy(service.object_roots[1], service.object_roots[0], 32);
    ASSERT_EQ(vcs_service_descriptor_validate(&service), VCS_SPACE_ERR_ORDER);
    service_fixture(&service);
    memset(service.protocol_root, 0, 32);
    ASSERT_EQ(vcs_service_descriptor_validate(&service), VCS_SPACE_ERR_ROOT);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_manifest_wire(void)
{
  int failures = 0;
  TEST("space manifest: delegated signature, bounds and validity fail closed") {
    struct vcs_space_manifest_v1 manifest, parsed;
    uint8_t online_seed[32], genesis[32], wire[VCS_SPACE_MANIFEST_WIRE_MAX];
    uint8_t first_root[32], second_root[32];
    size_t wire_len = 0;
    manifest_fixture(&manifest, online_seed, genesis);
    ASSERT_EQ(vcs_space_manifest_sign(&manifest, online_seed), VCS_SPACE_OK);
    ASSERT_EQ(vcs_space_manifest_validate_at(&manifest, genesis, 1000),
              VCS_SPACE_OK);
    ASSERT_EQ(vcs_space_manifest_encode(&manifest, wire, sizeof(wire),
                                        &wire_len), VCS_SPACE_OK);
    ASSERT(wire_len > 0 && wire_len <= sizeof(wire));
    ASSERT_EQ(vcs_space_manifest_decode(&parsed, wire, wire_len), VCS_SPACE_OK);
    ASSERT_EQ(vcs_space_manifest_root(&manifest, first_root), VCS_SPACE_OK);
    ASSERT_EQ(vcs_space_manifest_root(&parsed, second_root), VCS_SPACE_OK);
    ASSERT(memcmp(first_root, second_root, 32) == 0);
    ASSERT(memcmp(parsed.delegation.doc.master_pubkey,
                  manifest.delegation.doc.master_pubkey, 32) == 0);
    ASSERT_EQ(vcs_space_manifest_validate_at(&parsed, genesis, 1999),
              VCS_SPACE_OK);
    int chain_calls = 0;
    struct vcs_space_manifest_verify_context verify = {
        .now_unix = 1500,
        .chain_verify = space_chain,
        .chain_ctx = &chain_calls,
    };
    memcpy(verify.network_genesis, genesis, 32);
    ASSERT_EQ(vcs_space_manifest_verify(&parsed, &verify), VCS_SPACE_OK);
    ASSERT_EQ(chain_calls, 1);
    ASSERT_EQ(vcs_space_manifest_verify(&parsed, &verify),
              VCS_SPACE_ERR_CHAIN);
    ASSERT_EQ(chain_calls, 2);
    ASSERT_EQ(vcs_space_manifest_validate_at(&parsed, genesis, 2000),
              VCS_SPACE_ERR_TIME);

    uint8_t wrong_genesis[32];
    memset(wrong_genesis, 0x99, 32);
    ASSERT_EQ(vcs_space_manifest_validate_at(&parsed, wrong_genesis, 1500),
              VCS_SPACE_ERR_NETWORK);
    wire[wire_len - 1] ^= 1;
    ASSERT_EQ(vcs_space_manifest_decode(&parsed, wire, wire_len),
              VCS_SPACE_ERR_SIGNATURE);

    manifest_fixture(&manifest, online_seed, genesis);
    manifest.portal_count = VCS_SPACE_PORTAL_MAX + 1u;
    ASSERT_EQ(vcs_space_manifest_validate(&manifest), VCS_SPACE_ERR_LIMIT);
    manifest_fixture(&manifest, online_seed, genesis);
    memcpy(manifest.portal_roots[1], manifest.portal_roots[0], 32);
    ASSERT_EQ(vcs_space_manifest_validate(&manifest), VCS_SPACE_ERR_ORDER);
    manifest_fixture(&manifest, online_seed, genesis);
    memset(manifest.admission_root, 0, 32);
    ASSERT_EQ(vcs_space_manifest_validate(&manifest), VCS_SPACE_ERR_ROOT);
    manifest_fixture(&manifest, online_seed, genesis);
    manifest.sequence = (uint64_t)INT64_MAX + 1u;
    ASSERT_EQ(vcs_space_manifest_validate(&manifest), VCS_SPACE_ERR_LIMIT);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_space_plan_commit_carrier(void)
{
  int failures = 0;
  TEST("space service: exact stateless plan, CAS recheck and blob carrier") {
    char workspace[] = "/tmp/zcl_space_service_XXXXXX";
    char admitted_workspace[] = "/tmp/zcl_space_admit_XXXXXX";
    char store_dir[] = "/tmp/zcl_space_store_XXXXXX";
    ASSERT(mkdtemp(workspace) != NULL);
    ASSERT(mkdtemp(admitted_workspace) != NULL);
    ASSERT(mkdtemp(store_dir) != NULL);
    struct vcs_service_descriptor_v1 service;
    service_fixture(&service);
    struct metaverse_space_plan_out plan;
    ASSERT(metaverse_space_service_plan(&service, &plan).ok);
    char object_dir[512];
    ASSERT(snprintf(object_dir, sizeof(object_dir), "%s/.zvcs", workspace) > 0);
    ASSERT(access(object_dir, F_OK) != 0); /* plan is side-effect free */
    struct metaverse_space_commit_out committed;
    ASSERT(!metaverse_space_service_commit(
                workspace, &service, plan.plan_token, false, &committed).ok);
    char stale[65];
    memset(stale, '0', 64);
    stale[64] = '\0';
    ASSERT(!metaverse_space_service_commit(
                workspace, &service, stale, true, &committed).ok);
    ASSERT(metaverse_space_service_commit(
               workspace, &service, plan.plan_token, true, &committed).ok);
    ASSERT(!committed.already_committed);
    ASSERT(strcmp(committed.object_root, plan.object_root) == 0);
    ASSERT(metaverse_space_service_commit(
               workspace, &service, plan.plan_token, true, &committed).ok);
    ASSERT(committed.already_committed);
    struct metaverse_space_object shown;
    ASSERT(metaverse_space_show(workspace, plan.object_root, &shown).ok);
    ASSERT_EQ(shown.kind, METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR);
    ASSERT(memcmp(&shown.as.service, &service, sizeof(service)) == 0);

    struct vcs_service_descriptor_v1 changed = service;
    changed.protocol_root[0] ^= 0x7f;
    struct metaverse_space_plan_out changed_plan;
    ASSERT(metaverse_space_service_plan(&changed, &changed_plan).ok);
    ASSERT(!metaverse_space_service_commit(
                workspace, &changed, plan.plan_token, true, &committed).ok);
    uint8_t changed_root[32];
    ASSERT(zcl_hex_decode_lower(changed_plan.object_root, changed_root, 32));
    static const uint8_t corrupt[] = "not a service descriptor";
    ASSERT(vcs_object_put_addressed(workspace, changed_root, corrupt,
                                    sizeof(corrupt)));
    ASSERT(!metaverse_space_service_commit(
                workspace, &changed, changed_plan.plan_token, true,
                &committed).ok);

    uint8_t online_seed[32], genesis[32];
    struct vcs_space_manifest_v1 manifest;
    manifest_fixture(&manifest, online_seed, genesis);
    ASSERT_EQ(vcs_space_manifest_sign(&manifest, online_seed), VCS_SPACE_OK);
    int chain_calls = 0;
    struct vcs_space_manifest_verify_context verify = {
        .now_unix = 1500,
        .chain_verify = space_chain_accept,
        .chain_ctx = &chain_calls,
    };
    memcpy(verify.network_genesis, genesis, 32);
    struct metaverse_space_plan_out manifest_plan;
    ASSERT(metaverse_space_manifest_plan(
               &manifest, &verify, &manifest_plan).ok);
    ASSERT(metaverse_space_manifest_commit(
               workspace, &manifest, &verify, manifest_plan.plan_token,
               true, &committed).ok);
    ASSERT(metaverse_space_show(
               workspace, manifest_plan.object_root, &shown).ok);
    ASSERT_EQ(shown.kind, METAVERSE_SPACE_OBJECT_MANIFEST);
    ASSERT(memcmp(shown.as.manifest.delegation.doc.master_pubkey,
                  manifest.delegation.doc.master_pubkey, 32) == 0);
    ASSERT(chain_calls >= 2);

    struct vcs_package_store *store =
        vcs_package_store_open(store_dir, 4u * 1024u * 1024u);
    ASSERT(store != NULL);
    char blob_root[65];
    enum metaverse_space_object_kind published_kind;
    ASSERT(metaverse_space_publish(
               store, workspace, manifest_plan.object_root, blob_root,
               &published_kind).ok);
    ASSERT_EQ(published_kind, METAVERSE_SPACE_OBJECT_MANIFEST);
    bool is_new = false;
    ASSERT(metaverse_space_admit(
               store, admitted_workspace, manifest_plan.object_root,
               blob_root, &published_kind, &is_new).ok);
    ASSERT(is_new);
    ASSERT_EQ(published_kind, METAVERSE_SPACE_OBJECT_MANIFEST);
    ASSERT(metaverse_space_show(
               admitted_workspace, manifest_plan.object_root, &shown).ok);
    ASSERT(metaverse_space_admit(
               store, admitted_workspace, manifest_plan.object_root,
               blob_root, &published_kind, &is_new).ok);
    ASSERT(!is_new);
    vcs_package_store_close(store);

    char cleanup[1800];
    ASSERT(snprintf(cleanup, sizeof(cleanup), "rm -rf '%s' '%s' '%s'",
                    workspace, admitted_workspace, store_dir) > 0);
    ASSERT(system(cleanup) == 0);
    PASS();
  }
_test_next:;
  return failures;
}

static void space_push_read_verb(struct json_value *input,
                                 const char *verb)
{
  struct json_value verbs, value;
  json_init(&verbs);
  json_init(&value);
  json_set_array(&verbs);
  json_set_str(&value, verb);
  json_push_back(&verbs, &value);
  json_push_kv(input, "read_only_verbs", &verbs);
  json_free(&value);
  json_free(&verbs);
}

static int test_space_native_plan_commit_show(void)
{
  int failures = 0;
  TEST("space commands: exact plan/commit/show and no executable authority") {
    char datadir[] = "/tmp/zcl_space_command_XXXXXX";
    char workspace[] = "/tmp/zcl_space_command_ws_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    ASSERT(mkdtemp(workspace) != NULL);
    struct vcs_zcode_dht_delegation delegation;
    char identity_error[192] = {0};
    ASSERT(space_current_delegation(&delegation));
    ASSERT(vcs_zcode_dht_delegation_save(
        datadir, &delegation, identity_error, sizeof(identity_error)));
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(delegation.network_genesis);
    ASSERT(policy != NULL);
    uint8_t service_policy[32] = {0};
    memcpy(service_policy, "space.service", sizeof("space.service"));
    struct vcs_zcode_sovereignty_rule allow;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &allow, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_ALLOW,
                  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
                  (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_STORE) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_INDEX)),
                  service_policy),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &allow),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(
                  policy, datadir, identity_error, sizeof(identity_error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    vcs_zcode_sovereignty_policy_free(policy);
    uint8_t protocol_root[32];
    char protocol_hex[65];
    space_root(protocol_root, 0x73);
    zcl_hex_encode(protocol_root, 32, protocol_hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "kind", "service_descriptor");
    json_push_kv_str(&input, "protocol_root", protocol_hex);
    json_push_kv_str(&input, "datadir", datadir);
    space_push_read_verb(&input, "discover");
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_plan.v1");
    zcl_native_handle_metaverse_space_plan(&request, &reply);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED)
      printf(" plan failed: %s %s\n", reply.error.code,
             reply.error.message);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    const char *root = json_get_str(json_get(&reply.data, "object_root"));
    const char *token = json_get_str(json_get(&reply.data, "plan_token"));
    ASSERT(root && strlen(root) == 64u);
    ASSERT(token && strlen(token) == 64u);
    char root_copy[65], token_copy[65], object_dir[512];
    memcpy(root_copy, root, 65);
    memcpy(token_copy, token, 65);
    ASSERT(snprintf(object_dir, sizeof(object_dir), "%s/.zvcs", workspace) > 0);
    ASSERT(access(object_dir, F_OK) != 0);
    zcl_command_reply_free(&reply);

    json_push_kv_str(&input, "workspace", workspace);
    json_push_kv_str(&input, "plan_token", token_copy);
    json_push_kv_bool(&input, "confirm", true);
    zcl_command_reply_init(&reply, "zcl.metaverse_space_commit.v1");
    zcl_native_handle_metaverse_space_commit(&request, &reply);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED)
      printf(" commit failed: %s %s\n", reply.error.code,
             reply.error.message);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "object_root")),
                  root_copy) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "root", root_copy);
    json_push_kv_str(&input, "workspace", workspace);
    request.input = &input;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_show.v1");
    zcl_native_handle_metaverse_space_show(&request, &reply);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED)
      printf(" show failed: %s %s\n", reply.error.code,
             reply.error.message);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "kind")),
                  "service_descriptor.v1") == 0);
    ASSERT(!json_get_bool_or(&reply.data, "executable", true));
    ASSERT(!json_get_bool_or(&reply.data, "grants_authority", true));
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "root", root_copy);
    json_push_kv_str(&input, "kind", "service_descriptor");
    json_push_kv_str(&input, "workspace", workspace);
    json_push_kv_str(&input, "datadir", datadir);
    request.input = &input;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_status.v1");
    zcl_native_handle_metaverse_space_status(&request, &reply);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    const struct json_value *visibility = json_get(&reply.data, "visibility");
    ASSERT(visibility != NULL);
    ASSERT(strcmp(json_get_str(json_get(visibility, "state")), "present") == 0);
    ASSERT_EQ(json_get_int(json_get(visibility, "descriptors_total")), 1);
    ASSERT_EQ(json_get_int(json_get(visibility, "descriptors_visible")), 1);
    ASSERT(json_get_bool_or(&reply.data, "side_effect_free", false));
    ASSERT(json_get(&reply.data, "ready_to_publish") != NULL);
    ASSERT(json_get(&reply.data, "ready_to_discover") != NULL);
    ASSERT(json_get(&reply.data, "ready_to_scout") != NULL);
    ASSERT(json_size(json_get(&reply.data, "blockers")) > 0);
    const char *next = json_get_str(json_get(&reply.data,
                                             "next_safe_command"));
    ASSERT(next && strncmp(next, "z23 ", 4) == 0);
    char status_wire[16384];
    size_t status_bytes = json_write(&reply.data, status_wire,
                                     sizeof(status_wire));
    ASSERT(status_bytes > 0 && status_bytes < sizeof(status_wire));
    ASSERT(strstr(status_wire, "online_pubkey") == NULL);
    ASSERT(strstr(status_wire, "local_node_id") == NULL);
    ASSERT(strstr(status_wire, datadir) == NULL);
    ASSERT(strstr(status_wire, workspace) == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    char cleanup[1200];
    ASSERT(snprintf(cleanup, sizeof(cleanup), "rm -rf '%s' '%s'",
                    datadir, workspace) > 0);
    ASSERT(system(cleanup) == 0);
    PASS();
  }
_test_next:;
  return failures;
}

static void space_pointer_row(struct json_value *records,
                              uint8_t transport_value,
                              uint8_t publisher_value,
                              uint8_t provider_value,
                              int64_t sequence, bool conflicted)
{
  uint8_t root[32];
  char transport[65], publisher[65], provider[65];
  space_root(root, transport_value);
  zcl_hex_encode(root, 32, transport);
  space_root(root, publisher_value);
  zcl_hex_encode(root, 32, publisher);
  space_root(root, provider_value);
  zcl_hex_encode(root, 32, provider);
  struct json_value row;
  json_init(&row);
  json_set_object(&row);
  json_push_kv_str(&row, "transport_root", transport);
  json_push_kv_str(&row, "publisher_zid", publisher);
  json_push_kv_str(&row, "provider_node_id", provider);
  json_push_kv_int(&row, "sequence", sequence);
  json_push_kv_bool(&row, "provider_authenticated", true);
  json_push_kv_bool(&row, "conflicted", conflicted);
  json_push_kv_bool(&row, "superseded", false);
  json_push_back(records, &row);
  json_free(&row);
}

static int test_space_pointer_diversity(void)
{
  int failures = 0;
  TEST("space discovery: duplicate publishers cannot crowd distinct roots") {
    struct json_value records;
    json_init(&records);
    json_set_array(&records);
    for (uint8_t i = 0; i < 20; i++)
      space_pointer_row(&records, 0x10, (uint8_t)(0x20 + i),
                        (uint8_t)(0x50 + i),
                        i == 0 ? INT64_MAX : (int64_t)i + 1, false);
    space_pointer_row(&records, 0x11, 0x40, 0x70, 1, false);
    space_pointer_row(&records, 0x12, 0x41, 0x71, INT64_MAX, true);
    struct zcl_native_zcode_pointer_candidates candidates;
    ASSERT(zcl_native_zcode_pointer_candidates_build(&records, &candidates));
    ASSERT_EQ(candidates.records_seen, 22);
    ASSERT_EQ(candidates.count, 21);
    ASSERT_EQ(candidates.conflicts, 1);
    ASSERT_EQ(candidates.superseded, 0);
    ASSERT(strcmp(candidates.rows[0].transport_root,
                  candidates.rows[1].transport_root) != 0);
    ASSERT(candidates.rows[0].source_index != 21 &&
           candidates.rows[1].source_index != 21);
    json_free(&records);
    PASS();
  }
_test_next:;
  return failures;
}

static bool space_policy_allow_service(
    struct vcs_zcode_sovereignty_policy *policy, const char *service_type)
{
  uint8_t value[32] = {0};
  size_t length = strlen(service_type) + 1u;
  if (length > sizeof(value))
    return false;
  memcpy(value, service_type, length);
  struct vcs_zcode_sovereignty_rule rule;
  return vcs_zcode_sovereignty_rule_build(
             &rule, VCS_ZCODE_SOVEREIGNTY_LOCAL,
             VCS_ZCODE_SOVEREIGNTY_ALLOW,
             VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
             (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_DISCOVER) |
                       (1u << VCS_ZCODE_SOVEREIGNTY_FETCH) |
                       (1u << VCS_ZCODE_SOVEREIGNTY_STORE) |
                       (1u << VCS_ZCODE_SOVEREIGNTY_INDEX) |
                       (1u << VCS_ZCODE_SOVEREIGNTY_SERVE) |
                       (1u << VCS_ZCODE_SOVEREIGNTY_FORWARD)), value) ==
             VCS_ZCODE_SOVEREIGNTY_OK &&
         vcs_zcode_sovereignty_policy_add(policy, &rule) ==
             VCS_ZCODE_SOVEREIGNTY_OK;
}

static int test_space_admit_policy_identities(void)
{
  int failures = 0;
  TEST("space admission: pointer publisher and manifest owner both gate") {
    char datadir[] = "/tmp/zcl_space_policy_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    struct vcs_zcode_dht_delegation delegation;
    char error[192] = {0};
    ASSERT(space_current_delegation(&delegation));
    ASSERT(vcs_zcode_dht_delegation_save(
        datadir, &delegation, error, sizeof(error)));
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(delegation.network_genesis);
    ASSERT(policy != NULL);
    ASSERT(space_policy_allow_service(policy, "space.service"));
    ASSERT(space_policy_allow_service(policy, "space.manifest"));

    uint8_t semantic[32], transport[32], pointer[32], owner[32];
    space_root(semantic, 0x81);
    space_root(transport, 0x82);
    space_root(pointer, 0x83);
    space_root(owner, 0x84);
    struct vcs_zcode_sovereignty_rule pointer_block;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &pointer_block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_STORE), pointer),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &pointer_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(
                  policy, datadir, error, sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(!zcl_native_metaverse_space_test_admit_allowed(
        datadir, semantic, transport, pointer, NULL, false));

    ASSERT_EQ(vcs_zcode_sovereignty_policy_remove(
                  policy, pointer_block.id), VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(
                  policy, datadir, error, sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(zcl_native_metaverse_space_test_admit_allowed(
        datadir, semantic, transport, pointer, owner, true));

    struct vcs_zcode_sovereignty_rule owner_block;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &owner_block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_INDEX), owner),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &owner_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(
                  policy, datadir, error, sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(!zcl_native_metaverse_space_test_admit_allowed(
        datadir, semantic, transport, pointer, owner, true));
    vcs_zcode_sovereignty_policy_free(policy);
    char cleanup[600];
    ASSERT(snprintf(cleanup, sizeof(cleanup), "rm -rf '%s'", datadir) > 0);
    ASSERT(system(cleanup) == 0);
    PASS();
  }
_test_next:;
  return failures;
}

static uint32_t space_provider_fake_count;
static uint32_t space_provider_discover_calls;
static uint32_t space_provider_route_calls;
static uint32_t space_pointer_fake_count;
static char space_pointer_fake_transport[65];

static bool space_provider_fake_discover(
    struct json_value *selector, struct json_value *result)
{
  space_provider_discover_calls++;
  json_init(result);
  json_set_object(result);
  const char *kind = selector
      ? json_get_str(json_get(selector, "kind")) : NULL;
  bool pointer = kind && strcmp(kind, "pointer") == 0;
  uint32_t count = pointer ? space_pointer_fake_count
                           : space_provider_fake_count;
  json_push_kv_bool(result, "ok", true);
  json_push_kv_int(result, "count", count);
  if (pointer) {
    struct json_value records;
    json_init(&records);
    json_set_array(&records);
    if (count) {
      uint8_t root[32];
      char publisher[65], provider[65];
      space_root(root, 0xa1);
      zcl_hex_encode(root, 32, publisher);
      space_root(root, 0xa2);
      zcl_hex_encode(root, 32, provider);
      struct json_value row;
      json_init(&row);
      json_set_object(&row);
      json_push_kv_str(&row, "transport_root",
                       space_pointer_fake_transport);
      json_push_kv_str(&row, "publisher_zid", publisher);
      json_push_kv_str(&row, "provider_node_id", provider);
      json_push_kv_int(&row, "sequence", 1);
      json_push_kv_bool(&row, "provider_authenticated", true);
      json_push_kv_bool(&row, "conflicted", false);
      json_push_kv_bool(&row, "superseded", false);
      json_push_back(&records, &row);
      json_free(&row);
    }
    json_push_kv(result, "records", &records);
    json_free(&records);
  }
  return selector != NULL;
}

static bool space_provider_fake_route(
    struct json_value *selector, struct json_value *result)
{
  space_provider_route_calls++;
  json_init(result);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  return selector != NULL;
}

static int test_space_provider_discovery_order(void)
{
  int failures = 0;
  TEST("space provider route: iterative records precede restricted fetch") {
    struct json_value selector, route;
    json_init(&selector);
    json_set_object(&selector);
    json_push_kv_str(&selector, "kind", "provider");
    space_provider_discover_calls = 0;
    space_provider_route_calls = 0;
    zcl_native_zcode_discovery_test_backend(
        space_provider_fake_discover, space_provider_fake_route);

    uint32_t records = UINT32_MAX;
    space_provider_fake_count = 0;
    json_init(&route);
    ASSERT(!zcl_native_zcode_provider_discover_and_route(
        &selector, &route, &records));
    ASSERT_EQ(records, 0);
    ASSERT_EQ(space_provider_discover_calls, 1);
    ASSERT_EQ(space_provider_route_calls, 0);
    json_free(&route);

    space_provider_fake_count = 2;
    json_init(&route);
    ASSERT(zcl_native_zcode_provider_discover_and_route(
        &selector, &route, &records));
    ASSERT_EQ(records, 2);
    ASSERT_EQ(space_provider_discover_calls, 2);
    ASSERT_EQ(space_provider_route_calls, 1);
    json_free(&route);
    json_free(&selector);
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    PASS();
  }
_test_next:;
  zcl_native_zcode_discovery_test_backend(NULL, NULL);
  return failures;
}

static int test_space_discovery_closed_states(void)
{
  int failures = 0;
  TEST("space discovery: invalid, not-found and pending are closed states") {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;

    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "root", "not-a-root");
    request.input = &input;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_discover.v1");
    zcl_native_metaverse_space_discover_until(
        &request, &reply, platform_time_monotonic_ms() + 100, SIZE_MAX);
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                  "invalid") == 0);
    ASSERT(!json_get_bool_or(&reply.data, "retryable", true));
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "phase")),
                  "validate") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    char datadir[] = "/tmp/zcl_space_discovery_state_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    struct vcs_zcode_dht_delegation delegation;
    char error[192] = {0};
    ASSERT(space_current_delegation(&delegation));
    ASSERT(vcs_zcode_dht_delegation_save(
        datadir, &delegation, error, sizeof(error)));
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(delegation.network_genesis);
    ASSERT(policy != NULL);
    ASSERT(space_policy_allow_service(policy, "space.service"));
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(
                  policy, datadir, error, sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    vcs_zcode_sovereignty_policy_free(policy);

    uint8_t root_bytes[32], transport_bytes[32];
    char root[65];
    space_root(root_bytes, 0xb1);
    space_root(transport_bytes, 0xb2);
    zcl_hex_encode(root_bytes, 32, root);
    zcl_hex_encode(transport_bytes, 32, space_pointer_fake_transport);
    zcl_native_zcode_discovery_test_backend(
        space_provider_fake_discover, space_provider_fake_route);

    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "root", root);
    json_push_kv_str(&input, "kind", "service_descriptor");
    json_push_kv_str(&input, "datadir", datadir);
    request.input = &input;
    space_pointer_fake_count = 0;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_discover.v1");
    zcl_native_metaverse_space_discover_until(
        &request, &reply, platform_time_monotonic_ms() + 100, SIZE_MAX);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                  "not_found") == 0);
    ASSERT(json_get_bool_or(&reply.data, "retryable", false));
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "phase")),
                  "pointer_selection") == 0);
    zcl_command_reply_free(&reply);

    space_pointer_fake_count = 1;
    space_provider_fake_count = 1;
    space_provider_discover_calls = 0;
    space_provider_route_calls = 0;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_discover.v1");
    zcl_native_metaverse_space_discover_until(
        &request, &reply, platform_time_monotonic_ms() + 5, SIZE_MAX);
    ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                  "pending") == 0);
    ASSERT(json_get_bool_or(&reply.data, "retryable", false));
    ASSERT(strcmp(json_get_str(json_get(&reply.data, "phase")),
                  "package_fetch") == 0);
    ASSERT(json_get_bool_or(&reply.data, "fetch_scheduled", false));
    ASSERT(space_provider_discover_calls >= 2);
    ASSERT_EQ(space_provider_route_calls, 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    char cleanup[600];
    ASSERT(snprintf(cleanup, sizeof(cleanup), "rm -rf '%s'", datadir) > 0);
    ASSERT(system(cleanup) == 0);
    PASS();
  }
_test_next:;
  zcl_native_zcode_discovery_test_backend(NULL, NULL);
  return failures;
}

/* Regression: a manifest whose window does not fit inside the DHT
 * delegation's window must be refused WITH THAT REASON NAMED. The handler
 * used to collapse every signer-side failure into the bare "local online
 * key/delegation cannot sign this manifest" body — which reads as a missing
 * identity and sends operators to re-delegate a healthy one (the metaverse
 * tour hit exactly this by backdating not_before 60s before a delegation
 * minted seconds earlier). The positive arm proves a fitting window passes
 * the signer gate and fails only at the next one (chain authorization —
 * offline in this test process). */
static int test_space_native_manifest_sign_refusal_named(void)
{
  int failures = 0;
  TEST("space plan: signer/window refusals are named, not collapsed") {
    char datadir[] = "/tmp/zcl_space_signrefuse_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);

    /* Provision the identity exactly as zcode network delegate would: an
     * online key file plus a delegation over that same key, current now. */
    uint8_t online_seed[32], online_pub[32];
    char identity_error[192] = {0};
    ASSERT(vcs_zcode_dht_online_key_load_or_create(
        datadir, online_seed, online_pub, identity_error,
        sizeof(identity_error)));
    uint8_t master_seed[32], master_pub[32], master_secret[32];
    uint8_t noise[32], beacon[32], genesis[32];
    memset(master_seed, 0x2a, 32);
    memset(noise, 0x4a, 32);
    memset(beacon, 0x5a, 32);
    memset(genesis, 0x6a, 32);
    ed25519_keypair(master_pub, master_secret, master_seed);
    uint64_t now = (uint64_t)platform_time_wall_unix();
    ASSERT(now > 120);
    struct vcs_zcode_dht_delegation delegation;
    ASSERT_EQ(vcs_zcode_dht_delegation_sign(
                  &delegation, genesis, online_pub, noise, 100, beacon,
                  now - 1, now + 3600, 1, master_seed),
              VCS_ZCODE_DHT_DELEGATION_OK);
    memset(master_seed, 0, sizeof(master_seed));
    memset(master_secret, 0, sizeof(master_secret));
    (void)master_pub;
    ASSERT(vcs_zcode_dht_delegation_save(
        datadir, &delegation, identity_error, sizeof(identity_error)));

    /* not_before 60s BEFORE the delegation's own window start: the signer
     * must refuse, and the refusal must name the validity window. */
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "kind", "space_manifest");
    json_push_kv_str(&input, "datadir", datadir);
    json_push_kv_int(&input, "sequence", 1);
    json_push_kv_str(&input, "name", "window regression");
    json_push_kv_str(&input, "description", "window must fit the delegation");
    json_push_kv_int(&input, "not_before", (int64_t)(now - 60));
    json_push_kv_int(&input, "expiry", (int64_t)(now + 1800));
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.metaverse_space_plan.v1");
    zcl_native_handle_metaverse_space_plan(&request, &reply);
    ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(reply.error.code, "IDENTITY_UNAVAILABLE") == 0);
    ASSERT(strstr(reply.error.message, "validity-window") != NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* A window that DOES fit clears the signer gate; the refusal then comes
     * from the NEXT gate (chain authorization, offline here) — proving the
     * identity itself was never the problem. */
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "kind", "space_manifest");
    json_push_kv_str(&input, "datadir", datadir);
    json_push_kv_int(&input, "sequence", 1);
    json_push_kv_str(&input, "name", "window regression");
    json_push_kv_str(&input, "description", "window must fit the delegation");
    json_push_kv_int(&input, "not_before", (int64_t)now);
    json_push_kv_int(&input, "expiry", (int64_t)(now + 1800));
    zcl_command_reply_init(&reply, "zcl.metaverse_space_plan.v1");
    zcl_native_handle_metaverse_space_plan(&request, &reply);
    ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT(strcmp(reply.error.code, "OWNER_NOT_CHAIN_AUTHORIZED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    char cleanup[600];
    ASSERT(snprintf(cleanup, sizeof(cleanup), "rm -rf '%s'", datadir) > 0);
    ASSERT(system(cleanup) == 0);
    PASS();
  }
_test_next:;
  return failures;
}

int test_space(void)
{
  int failures = 0;
  failures += test_service_descriptor_wire();
  failures += test_manifest_wire();
  failures += test_space_plan_commit_carrier();
  failures += test_space_native_plan_commit_show();
  failures += test_space_native_manifest_sign_refusal_named();
  failures += test_space_pointer_diversity();
  failures += test_space_admit_policy_identities();
  failures += test_space_provider_discovery_order();
  failures += test_space_discovery_closed_states();
  printf("=== space: %d failures ===\n", failures);
  return failures;
}
