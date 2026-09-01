/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic bounded read-only Space Scout v1 proofs. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "command/native_zcode_discovery.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/metaverse_space_scout_service.h"
#include "vcs/space_scout.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void scout_root(uint8_t out[32], uint8_t value)
{
  memset(out, value, 32);
}

static bool scout_delegation(struct vcs_zcode_dht_delegation *out,
                             uint8_t online_seed[32], uint8_t salt)
{
  uint8_t master_seed[32], online_pub[32], online_secret[32];
  uint8_t noise[32], beacon[32], genesis[32];
  memset(master_seed, (uint8_t)(0x20u + salt), 32);
  memset(online_seed, (uint8_t)(0x30u + salt), 32);
  memset(noise, (uint8_t)(0x40u + salt), 32);
  memset(beacon, (uint8_t)(0x50u + salt), 32);
  memset(genesis, 0x61, 32);
  ed25519_keypair(online_pub, online_secret, online_seed);
  bool ok = vcs_zcode_dht_delegation_sign(
      out, genesis, online_pub, noise, 100, beacon, 900, 5000, 7,
      master_seed) == VCS_ZCODE_DHT_DELEGATION_OK;
  memset(online_secret, 0, sizeof(online_secret));
  return ok;
}

struct scout_graph {
  unsigned observe_calls;
  unsigned execute_trap;
};

static enum vcs_space_scout_manifest_result scout_observe(
    void *opaque, const uint8_t root[32], size_t maximum_wire_bytes,
    struct vcs_space_manifest_v1 *manifest, size_t *wire_bytes)
{
  (void)maximum_wire_bytes;
  struct scout_graph *graph = opaque;
  graph->observe_calls++;
  memset(manifest, 0, sizeof(*manifest));
  *wire_bytes = 100;
  manifest->service_count = 1;
  scout_root(manifest->service_roots[0], (uint8_t)(root[0] + 0x60u));
  scout_root(manifest->delegation.doc.master_pubkey,
             (uint8_t)(root[0] + 0x70u));
  if (root[0] == 0x10) {
    manifest->portal_count = 2;
    scout_root(manifest->portal_roots[0], 0x20);
    scout_root(manifest->portal_roots[1], 0x30);
    return VCS_SPACE_SCOUT_MANIFEST_VERIFIED;
  }
  if (root[0] == 0x20) {
    manifest->portal_count = 2;
    scout_root(manifest->portal_roots[0], 0x10);
    scout_root(manifest->portal_roots[1], 0x40);
    return VCS_SPACE_SCOUT_MANIFEST_VERIFIED;
  }
  if (root[0] == 0x30)
    return VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
}

struct scout_clock {
  uint64_t now;
  uint64_t step;
};

static uint64_t scout_now(void *opaque)
{
  struct scout_clock *clock = opaque;
  uint64_t now = clock->now;
  clock->now += clock->step;
  return now;
}

static bool scout_store_allow(void *opaque, const uint8_t root[32],
                              const char *service_type)
{
  (void)opaque;
  return root && service_type;
}

struct scout_store_policy {
  unsigned calls;
  unsigned deny_call;
};

static bool scout_store_decide(void *opaque, const uint8_t root[32],
                               const char *service_type)
{
  struct scout_store_policy *policy = opaque;
  if (!policy || !root || !service_type)
    return false;
  policy->calls++;
  return policy->calls != policy->deny_call;
}

static void scout_mission(struct vcs_space_scout_mission_v1 *mission)
{
  memset(mission, 0, sizeof(*mission));
  mission->schema_version = VCS_SPACE_SCOUT_MISSION_VERSION;
  memset(mission->network_genesis, 0x61, 32);
  mission->observation_unix = 1500;
  mission->start_count = 1;
  scout_root(mission->starting_roots[0], 0x10);
  mission->maximum_depth = 4;
  mission->maximum_spaces = 8;
  mission->maximum_portals = 8;
  mission->maximum_bytes = 1000;
  mission->deadline_ms = 1000;
}

static int test_scout_canonical_evidence(void)
{
  int failures = 0;
  TEST("space scout: frozen mission and observations are canonical evidence") {
    struct vcs_space_scout_mission_v1 mission, decoded;
    scout_mission(&mission);
    uint8_t mission_wire[VCS_SPACE_SCOUT_MISSION_WIRE_BYTES], mission_root[32];
    ASSERT_EQ(vcs_space_scout_mission_encode(&mission, mission_wire),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_mission_decode(
                  &decoded, mission_wire, sizeof(mission_wire)),
              VCS_SPACE_SCOUT_OK);
    ASSERT(memcmp(&mission, &decoded, sizeof(mission)) == 0);
    ASSERT_EQ(vcs_space_scout_mission_root(&mission, mission_root),
              VCS_SPACE_SCOUT_OK);
    decoded.start_count = 2;
    scout_root(decoded.starting_roots[0], 0x20);
    scout_root(decoded.starting_roots[1], 0x10);
    ASSERT_EQ(vcs_space_scout_mission_validate(&decoded),
              VCS_SPACE_SCOUT_ERR_ORDER);

    struct scout_graph first_graph = {0}, second_graph = {0};
    struct scout_clock first_clock = {0}, second_clock = {0};
    struct vcs_space_scout_run_context first_context = {
        .observe = scout_observe,
        .observe_context = &first_graph,
        .monotonic_ms = scout_now,
        .clock_context = &first_clock,
    };
    struct vcs_space_scout_run_context second_context = first_context;
    second_context.observe_context = &second_graph;
    second_context.clock_context = &second_clock;
    struct vcs_space_scout_map_v1 *first = zcl_calloc(
        1, sizeof(*first), "test_space_scout_first");
    struct vcs_space_scout_map_v1 *second = zcl_calloc(
        1, sizeof(*second), "test_space_scout_second");
    uint8_t *first_wire = zcl_malloc(
        VCS_SPACE_SCOUT_MAP_WIRE_BYTES, "test_space_scout_first_wire");
    uint8_t *second_wire = zcl_malloc(
        VCS_SPACE_SCOUT_MAP_WIRE_BYTES, "test_space_scout_second_wire");
    ASSERT(first && second && first_wire && second_wire);
    ASSERT_EQ(vcs_space_scout_run(&mission, &first_context, first),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_run(&mission, &second_context, second),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(first_graph.observe_calls, 4);
    ASSERT_EQ(first_graph.execute_trap, 0);
    ASSERT_EQ(first->visit_count, 4);
    ASSERT_EQ(first->portal_count, 4);
    ASSERT_EQ(first->failure_count, 2);
    ASSERT_EQ(first->policy_denial_count, 1);
    ASSERT_EQ(first->truncation, VCS_SPACE_SCOUT_TRUNCATION_NONE);
    ASSERT_EQ(first->bytes_observed, 200);
    ASSERT_EQ(vcs_space_scout_map_encode(first, first_wire),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_map_encode(second, second_wire),
              VCS_SPACE_SCOUT_OK);
    ASSERT(memcmp(first_wire, second_wire,
                  VCS_SPACE_SCOUT_MAP_WIRE_BYTES) == 0);
    uint8_t first_root[32], second_root[32];
    ASSERT_EQ(vcs_space_scout_map_root(first, first_root),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_map_root(second, second_root),
              VCS_SPACE_SCOUT_OK);
    ASSERT(memcmp(first_root, second_root, 32) == 0);

    first->visits[2].service_count = 1;
    scout_root(first->visits[2].service_roots[0], 0xee);
    ASSERT_EQ(vcs_space_scout_map_validate(first),
              VCS_SPACE_SCOUT_ERR_ORDER);
    first->visits[2] = second->visits[2];
    first->portals[1] = first->portals[0];
    first->portals[1].result =
        first->portals[0].result == VCS_SPACE_SCOUT_PORTAL_CYCLE
            ? VCS_SPACE_SCOUT_PORTAL_FOLLOWED
            : VCS_SPACE_SCOUT_PORTAL_CYCLE;
    ASSERT_EQ(vcs_space_scout_map_validate(first),
              VCS_SPACE_SCOUT_ERR_ORDER);
    first->portals[1] = second->portals[1];
    struct vcs_space_scout_mission_v1 tighter = mission;
    tighter.maximum_spaces = 3;
    ASSERT_EQ(vcs_space_scout_mission_root(&tighter, first->mission_root),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(first, &tighter),
              VCS_SPACE_SCOUT_ERR_SHAPE);
    memcpy(first->mission_root, second->mission_root, 32);
    size_t followed_index = 0;
    while (followed_index < first->portal_count &&
           first->portals[followed_index].result !=
               VCS_SPACE_SCOUT_PORTAL_FOLLOWED)
      followed_index++;
    ASSERT(followed_index < first->portal_count);
    size_t target_index = 0;
    while (target_index < first->visit_count &&
           memcmp(first->visits[target_index].space_root,
                  first->portals[followed_index].to_root, 32) != 0)
      target_index++;
    ASSERT(target_index < first->visit_count);
    first->visits[target_index].depth++;
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(first, &mission),
              VCS_SPACE_SCOUT_ERR_SHAPE);
    first->visits[target_index] = second->visits[target_index];
    size_t cycle_index = 0;
    while (cycle_index < first->portal_count &&
           first->portals[cycle_index].result !=
               VCS_SPACE_SCOUT_PORTAL_CYCLE)
      cycle_index++;
    ASSERT(cycle_index < first->portal_count);
    scout_root(first->portals[cycle_index].to_root, 0x15);
    ASSERT_EQ(vcs_space_scout_map_validate(first), VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(first, &mission),
              VCS_SPACE_SCOUT_ERR_SHAPE);
    first->portals[cycle_index] = second->portals[cycle_index];

    first_wire[0] ^= 1;
    ASSERT(vcs_space_scout_map_decode(second, first_wire,
                                     VCS_SPACE_SCOUT_MAP_WIRE_BYTES) !=
           VCS_SPACE_SCOUT_OK);
    free(second_wire);
    free(first_wire);
    free(second);
    free(first);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_scout_bounds(void)
{
  int failures = 0;
  TEST("space scout: depth, spaces, portals, bytes and deadline are hard caps") {
    struct vcs_space_scout_mission_v1 mission;
    struct vcs_space_scout_map_v1 *map = zcl_calloc(
        1, sizeof(*map), "test_space_scout_bounds_map");
    struct scout_graph graph = {0};
    struct scout_clock clock = {0};
    struct vcs_space_scout_run_context context = {
        .observe = scout_observe, .observe_context = &graph,
        .monotonic_ms = scout_now, .clock_context = &clock,
    };
    ASSERT(map != NULL);

    scout_mission(&mission);
    mission.maximum_depth = 0;
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(map->visit_count, 1);
    ASSERT_EQ(map->truncation, VCS_SPACE_SCOUT_TRUNCATION_DEPTH);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(map, &mission),
              VCS_SPACE_SCOUT_OK);

    scout_mission(&mission);
    mission.start_count = 2;
    scout_root(mission.starting_roots[1], 0x11);
    mission.maximum_spaces = 1;
    graph.observe_calls = 0; clock.now = 0;
    ASSERT_EQ(vcs_space_scout_mission_validate(&mission),
              VCS_SPACE_SCOUT_ERR_SHAPE);
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_ERR_SHAPE);
    ASSERT_EQ(graph.observe_calls, 0);

    scout_mission(&mission);
    mission.maximum_spaces = 2;
    graph.observe_calls = 0; clock.now = 0;
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(map->visit_count, 2);
    ASSERT_EQ(map->truncation, VCS_SPACE_SCOUT_TRUNCATION_SPACES);

    scout_mission(&mission);
    mission.maximum_portals = 1;
    graph.observe_calls = 0; clock.now = 0;
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(map->portal_count, 1);
    ASSERT_EQ(map->truncation, VCS_SPACE_SCOUT_TRUNCATION_PORTALS);
    ASSERT_EQ(map->portals[0].result,
              VCS_SPACE_SCOUT_PORTAL_TRUNCATED);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(map, &mission),
              VCS_SPACE_SCOUT_OK);

    scout_mission(&mission);
    mission.maximum_bytes = 99;
    graph.observe_calls = 0; clock.now = 0;
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(map->visit_count, 1);
    ASSERT_EQ(map->visits[0].manifest_result,
              VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT);
    ASSERT_EQ(map->truncation, VCS_SPACE_SCOUT_TRUNCATION_BYTES);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(map, &mission),
              VCS_SPACE_SCOUT_OK);

    scout_mission(&mission);
    mission.deadline_ms = 5;
    graph.observe_calls = 0; clock.now = 0; clock.step = 3;
    ASSERT_EQ(vcs_space_scout_run(&mission, &context, map),
              VCS_SPACE_SCOUT_OK);
    ASSERT_EQ(map->visit_count, 1);
    ASSERT_EQ(map->bytes_observed, 0);
    ASSERT_EQ(map->visits[0].manifest_result,
              VCS_SPACE_SCOUT_MANIFEST_DEADLINE);
    ASSERT_EQ(map->truncation, VCS_SPACE_SCOUT_TRUNCATION_DEADLINE);
    ASSERT_EQ(vcs_space_scout_map_validate_for_mission(map, &mission),
              VCS_SPACE_SCOUT_OK);
    free(map);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_scout_attestation_and_service(void)
{
  int failures = 0;
  TEST("space scout: signed local attestation and restart-stable CAS") {
    char workspace[] = "/tmp/zcl_space_scout_XXXXXX";
    ASSERT(mkdtemp(workspace) != NULL);
    struct vcs_space_scout_mission_v1 mission;
    scout_mission(&mission);
    struct metaverse_space_scout_plan_out plan;
    ASSERT(metaverse_space_scout_plan(&mission, &plan).ok);
    char object_dir[512];
    ASSERT(snprintf(object_dir, sizeof(object_dir), "%s/.zvcs", workspace) > 0);
    ASSERT(access(object_dir, F_OK) != 0);

    struct vcs_zcode_dht_delegation delegation;
    uint8_t online_seed[32];
    ASSERT(scout_delegation(&delegation, online_seed, 1));
    struct scout_graph graph = {0};
    struct scout_clock clock = {0};
    struct vcs_space_scout_run_context context = {
        .observe = scout_observe, .observe_context = &graph,
        .monotonic_ms = scout_now, .clock_context = &clock,
    };
    struct metaverse_space_scout_run_out ran;
    bool mutated = false;
    ASSERT(!metaverse_space_scout_run(
        workspace, &mission, plan.plan_token, false, &context,
        &delegation, online_seed, scout_store_allow, NULL,
        &mutated, &ran).ok);
    ASSERT(!mutated);
    char stale[65];
    memset(stale, '0', 64); stale[64] = '\0';
    ASSERT(!metaverse_space_scout_run(
        workspace, &mission, stale, true, &context,
        &delegation, online_seed, scout_store_allow, NULL,
        &mutated, &ran).ok);
    ASSERT(!mutated);
    struct vcs_zcode_dht_delegation wrong_network = delegation;
    wrong_network.network_genesis[0] ^= 1;
    ASSERT(!metaverse_space_scout_run(
        workspace, &mission, plan.plan_token, true, &context,
        &wrong_network, online_seed, scout_store_allow, NULL,
        &mutated, &ran).ok);
    ASSERT(!mutated);
    struct scout_store_policy denied = {.deny_call = 2};
    ASSERT(!metaverse_space_scout_run(
        workspace, &mission, plan.plan_token, true, &context,
        &delegation, online_seed, scout_store_decide, &denied,
        &mutated, &ran).ok);
    ASSERT(!mutated);
    ASSERT_EQ(denied.calls, 2);
    ASSERT(access(object_dir, F_OK) != 0);
    graph.observe_calls = 0; clock.now = 0;
    ASSERT(metaverse_space_scout_run(
        workspace, &mission, plan.plan_token, true, &context,
        &delegation, online_seed, scout_store_allow, NULL,
        &mutated, &ran).ok);
    ASSERT(mutated);
    ASSERT(!ran.already_recorded);

    struct vcs_space_scout_map_v1 *map = zcl_calloc(
        1, sizeof(*map), "test_space_scout_service_map");
    struct vcs_space_scout_attestation_v1 attestation;
    ASSERT(map != NULL);
    ASSERT(metaverse_space_scout_show(workspace, ran.evidence_root, map).ok);
    ASSERT(metaverse_space_scout_attestation_show(
        workspace, ran.attestation_root, &attestation).ok);
    uint8_t evidence_root[32];
    ASSERT_EQ(vcs_space_scout_map_root(map, evidence_root),
              VCS_SPACE_SCOUT_OK);
    ASSERT(memcmp(evidence_root, attestation.evidence_map_root, 32) == 0);
    ASSERT(memcmp(map->mission_root, attestation.mission_root, 32) == 0);
    ASSERT_EQ(vcs_space_scout_attestation_validate(&attestation),
              VCS_SPACE_SCOUT_OK);
    uint8_t attestation_wire[VCS_SPACE_SCOUT_ATTESTATION_WIRE_BYTES];
    ASSERT_EQ(vcs_space_scout_attestation_encode(
                  &attestation, attestation_wire), VCS_SPACE_SCOUT_OK);
    attestation_wire[sizeof(attestation_wire) - 1u] ^= 1;
    struct vcs_space_scout_attestation_v1 tampered;
    ASSERT_EQ(vcs_space_scout_attestation_decode(
                  &tampered, attestation_wire, sizeof(attestation_wire)),
              VCS_SPACE_SCOUT_ERR_SIGNATURE);

    graph.observe_calls = 0; clock.now = 0; clock.step = 0;
    struct metaverse_space_scout_run_out rerun;
    ASSERT(metaverse_space_scout_run(
        workspace, &mission, plan.plan_token, true, &context,
        &delegation, online_seed, scout_store_allow, NULL,
        &mutated, &rerun).ok);
    ASSERT(!mutated);
    ASSERT(rerun.already_recorded);
    ASSERT(strcmp(ran.evidence_root, rerun.evidence_root) == 0);
    ASSERT(strcmp(ran.attestation_root, rerun.attestation_root) == 0);
    free(map);
    PASS();
  }
_test_next:;
  return failures;
}

static unsigned scout_rpc_begin_calls;
static unsigned scout_rpc_poll_calls;
static unsigned scout_rpc_cancel_calls;

static char *scout_rpc_pending(const char *method, const char *params_json)
{
  (void)params_json;
  if (strcmp(method, "zcode_dht_record_begin") == 0) {
    scout_rpc_begin_calls++;
    return zcl_strdup(
        "{\"ok\":true,\"state\":\"pending\","
        "\"lookup_id\":\"11111111111111111111111111111111\","
        "\"owner_token\":\"22222222222222222222222222222222\"}",
        "test_space_scout_rpc_begin");
  }
  if (strcmp(method, "zcode_dht_record_poll") == 0) {
    scout_rpc_poll_calls++;
    return zcl_strdup("{\"ok\":true,\"state\":\"pending\"}",
                      "test_space_scout_rpc_poll");
  }
  if (strcmp(method, "zcode_dht_record_cancel") == 0) {
    scout_rpc_cancel_calls++;
    return zcl_strdup("{\"ok\":true,\"canceled\":true}",
                      "test_space_scout_rpc_cancel");
  }
  return zcl_strdup("{\"ok\":false,\"code\":\"UNEXPECTED\"}",
                    "test_space_scout_rpc_unexpected");
}

static int test_scout_deadline_cancels_discovery(void)
{
  int failures = 0;
  TEST("space scout: caller deadline cancels existing DHT lookup capability") {
    struct json_value selector, result;
    json_init(&selector); json_set_object(&selector);
    json_push_kv_str(&selector, "kind", "pointer");
    json_push_kv_str(&selector, "namespace", "space.manifest");
    json_push_kv_str(&selector, "semantic_root",
                     "1010101010101010101010101010101010101010101010101010101010101010");
    scout_rpc_begin_calls = 0;
    scout_rpc_poll_calls = 0;
    scout_rpc_cancel_calls = 0;
    node_rpc_client_set_test_hook(scout_rpc_pending);
    bool deadline_reached = false;
    int64_t deadline = platform_time_monotonic_ms() + 5;
    ASSERT(!zcl_native_zcode_records_discover_until(
        &selector, &result, deadline, &deadline_reached));
    ASSERT(deadline_reached);
    ASSERT_EQ(scout_rpc_begin_calls, 0);
    ASSERT_EQ(scout_rpc_poll_calls, 0);
    ASSERT_EQ(scout_rpc_cancel_calls, 0);
    json_free(&result);
    deadline_reached = false;
    deadline = platform_time_monotonic_ms() + 70;
    ASSERT(!zcl_native_zcode_records_discover_until(
        &selector, &result, deadline, &deadline_reached));
    ASSERT(deadline_reached);
    ASSERT_EQ(scout_rpc_begin_calls, 1);
    ASSERT(scout_rpc_poll_calls >= 1);
    ASSERT_EQ(scout_rpc_cancel_calls, 1);
    json_free(&result);
    json_free(&selector);
    node_rpc_client_set_test_hook(NULL);
    PASS();
  }
_test_next:;
  node_rpc_client_set_test_hook(NULL);
  return failures;
}

int test_space_scout(void)
{
  int failures = 0;
  failures += test_scout_canonical_evidence();
  failures += test_scout_bounds();
  failures += test_scout_attestation_and_service();
  failures += test_scout_deadline_cancels_discovery();
  printf("=== space_scout: %d failures ===\n", failures);
  return failures;
}
