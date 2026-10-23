/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded read-only Space Scout v1 native command surface. */

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "command/native_zcode_policy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/metaverse_space_scout_service.h"
#include "services/metaverse_space_service.h"
#include "support/cleanse.h"
#include "vcs/space_scout.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MVSCOUT_PATH_MAX 4096u

static const char *scout_str(const struct json_value *input, const char *key)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static int64_t scout_int(const struct json_value *input, const char *key,
                         int64_t fallback)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_INT ? json_get_int(value) : fallback;
}

static bool scout_bool(const struct json_value *input, const char *key)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_BOOL && json_get_bool(value);
}

static void scout_fail(struct zcl_command_reply *reply, const char *code,
                       const char *phase, const char *detail)
{
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                         detail, "metaverse.space.scout");
}

static void scout_blocked(struct zcl_command_reply *reply, const char *code,
                          const char *phase, const char *detail,
                          bool mutated)
{
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                         ZCL_COMMAND_EXIT_FAILED, code, phase, true, mutated,
                         detail, "metaverse.space.scout");
}

static const char *scout_datadir(const struct json_value *input)
{
  const char *datadir = scout_str(input, "datadir");
  return datadir && datadir[0] ? datadir : zcl_native_command_datadir();
}

static const char *scout_workspace(const struct json_value *input,
                                   char out[MVSCOUT_PATH_MAX])
{
  const char *workspace = scout_str(input, "workspace");
  if (workspace && workspace[0]) {
    int n = snprintf(out, MVSCOUT_PATH_MAX, "%s", workspace);
    return n > 0 && n < (int)MVSCOUT_PATH_MAX ? out : NULL;
  }
  const char *datadir = scout_datadir(input);
  int n = datadir ? snprintf(out, MVSCOUT_PATH_MAX, "%s/zcode", datadir) : -1;
  return n > 0 && n < (int)MVSCOUT_PATH_MAX ? out : NULL;
}

static bool scout_hex_root(const char *hex, uint8_t out[32])
{
  return hex && strlen(hex) == 64u && zcl_hex_decode_lower(hex, out, 32);
}

static int scout_root_compare(const void *left, const void *right)
{
  return memcmp(left, right, 32);
}

static bool scout_starting_roots(const struct json_value *input,
                                 struct vcs_space_scout_mission_v1 *mission)
{
  const struct json_value *roots = input ? json_get(input, "starting_roots")
                                         : NULL;
  size_t count = roots && roots->type == JSON_ARR ? json_size(roots) : 0;
  if (!count || count > VCS_SPACE_SCOUT_START_MAX)
    return false;
  for (size_t i = 0; i < count; i++) {
    const struct json_value *value = json_at(roots, i);
    const char *hex = value && value->type == JSON_STR
                          ? json_get_str(value) : NULL;
    if (!scout_hex_root(hex, mission->starting_roots[i]))
      return false;
  }
  qsort(mission->starting_roots, count, 32u, scout_root_compare);
  for (size_t i = 1; i < count; i++)
    if (memcmp(mission->starting_roots[i - 1],
               mission->starting_roots[i], 32) == 0)
      return false;
  mission->start_count = (uint8_t)count;
  return true;
}

static bool scout_mission_bounds_ok(int64_t observation, int64_t depth,
                                    int64_t spaces, int64_t portals,
                                    int64_t bytes, int64_t deadline)
{
  return observation >= 1 && depth >= 0 && spaces >= 1 && portals >= 1 &&
         bytes >= 1 && deadline >= 1 &&
         depth <= VCS_SPACE_SCOUT_DEPTH_MAX &&
         spaces <= VCS_SPACE_SCOUT_SPACES_MAX &&
         portals <= VCS_SPACE_SCOUT_PORTALS_MAX &&
         bytes <= VCS_SPACE_SCOUT_BYTES_MAX &&
         deadline <= VCS_SPACE_SCOUT_DEADLINE_MS_MAX;
}

static bool scout_mission_input(
    const struct json_value *input,
    const struct vcs_zcode_dht_delegation *delegation,
    struct vcs_space_scout_mission_v1 *mission)
{
  memset(mission, 0, sizeof(*mission));
  if (!input || !delegation)
    return false;
  int64_t observation = scout_int(input, "observation_unix", -1);
  int64_t depth = scout_int(input, "maximum_depth", -1);
  int64_t spaces = scout_int(input, "maximum_spaces", -1);
  int64_t portals = scout_int(input, "maximum_portals", -1);
  int64_t bytes = scout_int(input, "maximum_bytes", -1);
  int64_t deadline = scout_int(input, "deadline_ms", -1);
  if (!scout_mission_bounds_ok(observation, depth, spaces, portals, bytes,
                               deadline) ||
      !scout_starting_roots(input, mission))
    return false;
  mission->schema_version = VCS_SPACE_SCOUT_MISSION_VERSION;
  memcpy(mission->network_genesis, delegation->network_genesis, 32);
  mission->observation_unix = (uint64_t)observation;
  mission->maximum_depth = (uint8_t)depth;
  mission->maximum_spaces = (uint8_t)spaces;
  mission->maximum_portals = (uint16_t)portals;
  mission->maximum_bytes = (uint32_t)bytes;
  mission->deadline_ms = (uint32_t)deadline;
  return vcs_space_scout_mission_validate(mission) == VCS_SPACE_SCOUT_OK &&
         vcs_zcode_dht_delegation_verify(
             delegation, NULL, NULL, 0, NULL,
             mission->observation_unix) == VCS_ZCODE_DHT_DELEGATION_OK;
}

static bool scout_load_public_mission(
    const struct json_value *input,
    struct vcs_zcode_dht_delegation *delegation,
    struct vcs_space_scout_mission_v1 *mission,
    struct zcl_command_reply *reply)
{
  char error[192] = {0};
  const char *datadir = scout_datadir(input);
  if (!datadir || !vcs_zcode_dht_delegation_load(
                       datadir, delegation, error, sizeof(error))) {
    scout_blocked(reply, "IDENTITY_UNAVAILABLE", "identity",
                  error[0] ? error : "local public delegation is unavailable",
                  false);
    return false;
  }
  if (!scout_mission_input(input, delegation, mission)) {
    scout_fail(reply, "BAD_SCOUT_MISSION", "validate",
               "starting_roots and every explicit mission bound must be "
               "canonical, nonzero, within the hard caps, and covered by "
               "the observer delegation");
    return false;
  }
  return true;
}

static void scout_push_roots(struct json_value *object, const char *key,
                             const uint8_t roots[][32], size_t count)
{
  struct json_value array;
  json_init(&array);
  json_set_array(&array);
  for (size_t i = 0; i < count; i++) {
    char hex[65];
    zcl_hex_encode(roots[i], 32, hex);
    struct json_value value;
    json_init(&value);
    json_set_str(&value, hex);
    json_push_back(&array, &value);
    json_free(&value);
  }
  json_push_kv(object, key, &array);
  json_free(&array);
}

static void scout_push_mission(
    struct json_value *data,
    const struct vcs_space_scout_mission_v1 *mission)
{
  scout_push_roots(data, "starting_roots", mission->starting_roots,
                   mission->start_count);
  json_push_kv_int(data, "observation_unix",
                   (int64_t)mission->observation_unix);
  json_push_kv_int(data, "maximum_depth", mission->maximum_depth);
  json_push_kv_int(data, "maximum_spaces", mission->maximum_spaces);
  json_push_kv_int(data, "maximum_portals", mission->maximum_portals);
  json_push_kv_int(data, "maximum_bytes", mission->maximum_bytes);
  json_push_kv_int(data, "deadline_ms", mission->deadline_ms);
}

void zcl_native_handle_metaverse_space_scout_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  struct vcs_zcode_dht_delegation delegation;
  struct vcs_space_scout_mission_v1 mission;
  if (!scout_load_public_mission(request->input, &delegation, &mission, reply))
    return;
  struct metaverse_space_scout_plan_out plan;
  struct zcl_result planned = metaverse_space_scout_plan(&mission, &plan);
  if (!planned.ok) {
    scout_fail(reply, "SCOUT_PLAN_REFUSED", "plan", planned.message);
    return;
  }
  json_push_kv_str(&reply->data, "mission_root", plan.mission_root);
  json_push_kv_str(&reply->data, "plan_token", plan.plan_token);
  json_push_kv_str(&reply->data, "state", "PLANNED");
  json_push_kv_bool(&reply->data, "side_effect_free", true);
  json_push_kv_bool(&reply->data, "read_only_mission", true);
  json_push_kv_str(&reply->data, "run_command",
                   "metaverse.space.scout.run");
  scout_push_mission(&reply->data, &mission);
}

struct scout_observer_context {
  const char *datadir;
  const char *workspace;
  int64_t deadline_mono_ms;
  const struct vcs_space_scout_mission_v1 *mission;
  bool *mutated_out;
};

static bool scout_policy_allows(const struct scout_observer_context *context,
                                const uint8_t root[32],
                                const uint8_t publisher[32])
{
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  memcpy(subject.semantic_root, root, 32);
  memcpy(subject.package_root, root, 32);
  if (publisher)
    memcpy(subject.publisher_zid, publisher, 32);
  (void)snprintf(subject.service_type, sizeof(subject.service_type), "%s",
                 "space.manifest");
  return zcl_native_zcode_policy_allows(
             context->datadir, VCS_ZCODE_SOVEREIGNTY_DISCOVER,
             &subject, NULL, 0) &&
         zcl_native_zcode_policy_allows(
             context->datadir, VCS_ZCODE_SOVEREIGNTY_FETCH,
             &subject, NULL, 0);
}

static enum vcs_space_scout_manifest_result scout_verify_local(
    const struct scout_observer_context *context, const uint8_t root[32],
    size_t maximum_wire_bytes,
    struct vcs_space_manifest_v1 *manifest_out, size_t *wire_bytes_out)
{
  char hex[65];
  zcl_hex_encode(root, 32, hex);
  struct metaverse_space_object object;
  struct zcl_result shown = metaverse_space_show_bounded(
      context->workspace, hex, maximum_wire_bytes, &object, wire_bytes_out);
  if (!shown.ok && strcmp(shown.message, "space-show-byte-limit") == 0)
    return VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT;
  if (!shown.ok)
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  if (object.kind != METAVERSE_SPACE_OBJECT_MANIFEST)
    return VCS_SPACE_SCOUT_MANIFEST_INVALID;
  enum vcs_space_result valid = vcs_space_manifest_validate_at(
      &object.as.manifest, context->mission->network_genesis,
      context->mission->observation_unix);
  if (valid == VCS_SPACE_ERR_TIME)
    return VCS_SPACE_SCOUT_MANIFEST_EXPIRED;
  if (valid != VCS_SPACE_OK)
    return VCS_SPACE_SCOUT_MANIFEST_INVALID;
  bool deadline_reached = false;
  if (!zcl_native_zcode_delegation_authorized_until(
          &object.as.manifest.delegation, context->deadline_mono_ms,
          NULL, 0, &deadline_reached))
    return deadline_reached ? VCS_SPACE_SCOUT_MANIFEST_DEADLINE
                            : VCS_SPACE_SCOUT_MANIFEST_CHAIN_DENIED;
  if (!scout_policy_allows(
          context, root,
          object.as.manifest.delegation.doc.master_pubkey))
    return VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  *manifest_out = object.as.manifest;
  return VCS_SPACE_SCOUT_MANIFEST_VERIFIED;
}

static bool scout_reply_flag(const struct zcl_command_reply *reply,
                             const char *code, const char *key)
{
  return strcmp(reply->error.code, code) == 0 ||
         json_get_bool_or(&reply->data, key, false);
}

static bool scout_policy_refused(const struct zcl_command_reply *reply)
{
  int64_t denials = json_get_int_or(&reply->data, "policy_denied", 0);
  int64_t tried = json_get_int_or(&reply->data, "candidates_tried", 0);
  return strcmp(reply->error.code, "SOVEREIGNTY_DENIED") == 0 ||
         (denials > 0 && tried == 0);
}

/* Returns the discovery verdict that ends observation early, or NOT_FOUND
 * when the reply raises none (the caller then decides on admission). */
static enum vcs_space_scout_manifest_result scout_discovery_verdict(
    const struct zcl_command_reply *reply)
{
  if (scout_reply_flag(reply, "DISCOVERY_DEADLINE", "deadline_reached"))
    return VCS_SPACE_SCOUT_MANIFEST_DEADLINE;
  if (scout_reply_flag(reply, "DISCOVERY_BYTE_LIMIT", "byte_limit_reached"))
    return VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT;
  if (scout_policy_refused(reply))
    return VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  if (json_get_bool_or(&reply->data, "fetch_scheduled", false))
    return VCS_SPACE_SCOUT_MANIFEST_FETCH_SCHEDULED;
  return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
}

static void scout_note_discovery_mutation(
    const struct scout_observer_context *context,
    const struct zcl_command_reply *reply, bool admitted)
{
  bool newly_admitted = admitted &&
      json_get_bool_or(&reply->data, "new", false);
  bool scheduled = json_get_bool_or(&reply->data, "fetch_scheduled", false);
  /* Provider routing may create/update a resumable transfer record. Its
   * current RPC does not expose a narrower mutation receipt, so fail closed
   * on truthfulness: any accepted schedule is reported as mutation. */
  if (newly_admitted || scheduled)
    *context->mutated_out = true;
}

static void scout_discovery_input(
    const struct scout_observer_context *context, const uint8_t root[32],
    size_t maximum_wire_bytes, struct json_value *input)
{
  char hex[65];
  zcl_hex_encode(root, 32, hex);
  json_init(input);
  json_set_object(input);
  json_push_kv_str(input, "root", hex);
  json_push_kv_str(input, "kind", "space_manifest");
  json_push_kv_str(input, "workspace", context->workspace);
  json_push_kv_str(input, "datadir", context->datadir);
  json_push_kv_int(input, "maximum_wire_bytes",
                   (int64_t)maximum_wire_bytes);
}

static enum vcs_space_scout_manifest_result scout_discover_manifest(
    const struct scout_observer_context *context, const uint8_t root[32],
    size_t maximum_wire_bytes, bool *admitted_out)
{
  struct json_value input;
  scout_discovery_input(context, root, maximum_wire_bytes, &input);
  struct zcl_command_request request;
  memset(&request, 0, sizeof(request));
  request.input = &input;
  struct zcl_command_reply reply;
  zcl_command_reply_init(&reply, "zcl.metaverse_space_discover.v1");
  zcl_native_metaverse_space_discover_until(
      &request, &reply, context->deadline_mono_ms, maximum_wire_bytes);
  bool admitted = json_get_bool_or(&reply.data, "admitted", false);
  enum vcs_space_scout_manifest_result verdict =
      scout_discovery_verdict(&reply);
  scout_note_discovery_mutation(context, &reply, admitted);
  zcl_command_reply_free(&reply);
  json_free(&input);
  *admitted_out = admitted;
  return verdict;
}

static enum vcs_space_scout_manifest_result scout_observe_manifest(
    void *opaque, const uint8_t root[32], size_t maximum_wire_bytes,
    struct vcs_space_manifest_v1 *manifest_out, size_t *wire_bytes_out)
{
  struct scout_observer_context *context = opaque;
  *wire_bytes_out = 0;
  if (platform_time_monotonic_ms() >= context->deadline_mono_ms)
    return VCS_SPACE_SCOUT_MANIFEST_DEADLINE;
  if (!scout_policy_allows(context, root, NULL))
    return VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  enum vcs_space_scout_manifest_result local = scout_verify_local(
      context, root, maximum_wire_bytes, manifest_out, wire_bytes_out);
  if (local != VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND)
    return local;

  bool admitted = false;
  enum vcs_space_scout_manifest_result found = scout_discover_manifest(
      context, root, maximum_wire_bytes, &admitted);
  if (found != VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND)
    return found;
  if (!admitted)
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  return scout_verify_local(context, root, maximum_wire_bytes,
                            manifest_out, wire_bytes_out);
}

static uint64_t scout_monotonic_ms(void *opaque)
{
  (void)opaque;
  int64_t now = platform_time_monotonic_ms();
  return now > 0 ? (uint64_t)now : 0;
}

static bool scout_evidence_store_allowed(
    void *opaque, const uint8_t semantic_root[32], const char *service_type)
{
  const char *datadir = opaque;
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  if (!datadir || !semantic_root || !service_type)
    return false;
  memcpy(subject.semantic_root, semantic_root, 32);
  memcpy(subject.package_root, semantic_root, 32);
  (void)snprintf(subject.service_type, sizeof(subject.service_type), "%s",
                 service_type);
  return zcl_native_zcode_policy_allows(
             datadir, VCS_ZCODE_SOVEREIGNTY_STORE, &subject, NULL, 0) &&
         zcl_native_zcode_policy_allows(
             datadir, VCS_ZCODE_SOVEREIGNTY_INDEX, &subject, NULL, 0);
}

void zcl_native_handle_metaverse_space_scout_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  struct vcs_zcode_dht_delegation delegation;
  struct vcs_space_scout_mission_v1 mission;
  if (!scout_load_public_mission(request->input, &delegation, &mission, reply))
    return;
  const char *plan_token = scout_str(request->input, "plan_token");
  if (!plan_token || !scout_bool(request->input, "confirm")) {
    scout_fail(reply, "BAD_SCOUT_RUN", "confirm",
               "run requires the exact plan_token and confirm:true");
    return;
  }
  const char *datadir = scout_datadir(request->input);
  char workspace[MVSCOUT_PATH_MAX], error[192] = {0};
  const char *resolved = scout_workspace(request->input, workspace);
  uint8_t online_seed[32] = {0}, online_pubkey[32] = {0};
  int64_t started = platform_time_monotonic_ms();
  int64_t deadline = started > INT64_MAX - (int64_t)mission.deadline_ms
                         ? INT64_MAX
                         : started + (int64_t)mission.deadline_ms;
  bool identity_deadline = false;
  if (!resolved || !vcs_zcode_dht_online_key_load(
                       datadir, online_seed, online_pubkey,
                       error, sizeof(error)) ||
      memcmp(online_pubkey, delegation.online_pubkey, 32) != 0 ||
      !zcl_native_zcode_delegation_authorized_until(
          &delegation, deadline, error, sizeof(error),
          &identity_deadline)) {
    memory_cleanse(online_seed, sizeof(online_seed));
    scout_blocked(reply, "IDENTITY_UNAVAILABLE", "identity",
                  identity_deadline ? "observer authorization exceeded the "
                                      "mission deadline" :
                  error[0] ? error :
                  "observer key and current chain authorization are required",
                  false);
    return;
  }
  struct scout_observer_context observer = {
      .datadir = datadir,
      .workspace = resolved,
      .deadline_mono_ms = deadline,
      .mission = &mission,
      .mutated_out = NULL,
  };
  bool observation_mutated = false;
  observer.mutated_out = &observation_mutated;
  struct vcs_space_scout_run_context run_context = {
      .observe = scout_observe_manifest,
      .observe_context = &observer,
      .monotonic_ms = scout_monotonic_ms,
      .clock_context = NULL,
  };
  struct metaverse_space_scout_run_out ran;
  bool mutated = false;
  struct zcl_result result = metaverse_space_scout_run(
      resolved, &mission, plan_token, true, &run_context,
      &delegation, online_seed, scout_evidence_store_allowed,
      (void *)datadir, &mutated, &ran);
  memory_cleanse(online_seed, sizeof(online_seed));
  if (!result.ok) {
    mutated |= observation_mutated;
    scout_blocked(reply, "SCOUT_RUN_REFUSED", "run", result.message,
                  mutated);
    return;
  }
  reply->error.mutated = mutated || observation_mutated;
  json_push_kv_str(&reply->data, "mission_root", ran.mission_root);
  json_push_kv_str(&reply->data, "evidence_map_root", ran.evidence_root);
  json_push_kv_str(&reply->data, "attestation_root", ran.attestation_root);
  json_push_kv_bool(&reply->data, "already_recorded", ran.already_recorded);
  json_push_kv_str(&reply->data, "state", "RECORDED");
  json_push_kv_bool(&reply->data, "read_only_mission", true);
  json_push_kv_bool(&reply->data, "local_evidence", true);
  json_push_kv_bool(&reply->data, "global_truth", false);
  json_push_kv_bool(&reply->data, "grants_authority", false);
  json_push_kv_bool(&reply->data, "executable", false);
}

static void scout_push_map(struct json_value *data,
                           const struct vcs_space_scout_map_v1 *map)
{
  json_push_kv_int(data, "observation_unix", (int64_t)map->observation_unix);
  json_push_kv_int(data, "bytes_observed", map->bytes_observed);
  json_push_kv_str(data, "truncation",
                   vcs_space_scout_truncation_string(map->truncation));
  json_push_kv_int(data, "policy_denials", map->policy_denial_count);
  struct json_value visits;
  json_init(&visits); json_set_array(&visits);
  for (size_t i = 0; i < map->visit_count; i++) {
    const struct vcs_space_scout_visit_v1 *visit = &map->visits[i];
    char root[65], owner[65];
    zcl_hex_encode(visit->space_root, 32, root);
    struct json_value row;
    json_init(&row); json_set_object(&row);
    json_push_kv_str(&row, "space_root", root);
    json_push_kv_int(&row, "depth", visit->depth);
    json_push_kv_str(&row, "manifest_result",
                     vcs_space_scout_manifest_result_string(
                         visit->manifest_result));
    if (visit->manifest_result == VCS_SPACE_SCOUT_MANIFEST_VERIFIED) {
      zcl_hex_encode(visit->owner_zid, 32, owner);
      json_push_kv_str(&row, "owner_zid", owner);
    }
    scout_push_roots(&row, "advertised_service_roots",
                     visit->service_roots, visit->service_count);
    json_push_back(&visits, &row); json_free(&row);
  }
  json_push_kv(data, "visited_spaces", &visits); json_free(&visits);

  struct json_value portals;
  json_init(&portals); json_set_array(&portals);
  for (size_t i = 0; i < map->portal_count; i++) {
    char from[65], to[65];
    zcl_hex_encode(map->portals[i].from_root, 32, from);
    zcl_hex_encode(map->portals[i].to_root, 32, to);
    struct json_value row;
    json_init(&row); json_set_object(&row);
    json_push_kv_str(&row, "from_root", from);
    json_push_kv_str(&row, "to_root", to);
    json_push_kv_str(&row, "result",
                     vcs_space_scout_portal_result_string(
                         map->portals[i].result));
    json_push_back(&portals, &row); json_free(&row);
  }
  json_push_kv(data, "portal_evidence", &portals); json_free(&portals);

  struct json_value failures;
  json_init(&failures); json_set_array(&failures);
  for (size_t i = 0; i < map->failure_count; i++) {
    char root[65];
    zcl_hex_encode(map->failures[i].space_root, 32, root);
    struct json_value row;
    json_init(&row); json_set_object(&row);
    json_push_kv_str(&row, "space_root", root);
    json_push_kv_str(&row, "result",
                     vcs_space_scout_manifest_result_string(
                         map->failures[i].result));
    json_push_back(&failures, &row); json_free(&row);
  }
  json_push_kv(data, "failures", &failures); json_free(&failures);
}

static bool scout_map_binds_attestation(
    struct vcs_space_scout_map_v1 *map,
    struct vcs_space_scout_mission_v1 *mission,
    const struct vcs_space_scout_attestation_v1 *attestation)
{
  return memcmp(map->mission_root, attestation->mission_root, 32) == 0 &&
         map->observation_unix == attestation->observation_unix &&
         mission->observation_unix == attestation->observation_unix &&
         vcs_space_scout_map_validate_for_mission(map, mission) ==
             VCS_SPACE_SCOUT_OK &&
         memcmp(mission->network_genesis,
                attestation->observer_delegation.network_genesis, 32) == 0;
}

/* On failure *failure carries the result that names the broken link. */
static bool scout_show_linked(
    const char *resolved, struct vcs_space_scout_attestation_v1 *attestation,
    struct vcs_space_scout_map_v1 *map,
    struct vcs_space_scout_mission_v1 *mission, struct zcl_result *failure)
{
  *failure = ZCL_OK;
  char evidence_root[65], mission_root[65];
  zcl_hex_encode(attestation->evidence_map_root, 32, evidence_root);
  zcl_hex_encode(attestation->mission_root, 32, mission_root);
  struct zcl_result shown = metaverse_space_scout_show(
      resolved, evidence_root, map);
  struct zcl_result mission_shown = shown.ok
      ? metaverse_space_scout_mission_show(resolved, mission_root, mission)
      : shown;
  if (!shown.ok) {
    *failure = shown;
    return false;
  }
  if (!mission_shown.ok) {
    *failure = mission_shown;
    return false;
  }
  if (!scout_map_binds_attestation(map, mission, attestation)) {
    *failure = ZCL_ERR(-1, "attestation does not bind this mission/map");
    return false;
  }
  return true;
}

static void scout_push_attestation(
    struct json_value *data, const char *attestation_root,
    struct vcs_space_scout_attestation_v1 *attestation)
{
  char evidence_root[65], mission_root[65], observer[65];
  zcl_hex_encode(attestation->evidence_map_root, 32, evidence_root);
  zcl_hex_encode(attestation->mission_root, 32, mission_root);
  zcl_hex_encode(attestation->observer_delegation.doc.master_pubkey, 32,
                 observer);
  json_push_kv_str(data, "attestation_root", attestation_root);
  json_push_kv_str(data, "evidence_map_root", evidence_root);
  json_push_kv_str(data, "mission_root", mission_root);
  json_push_kv_str(data, "observer_zid", observer);
  json_push_kv_bool(data, "signature_verified", true);
  json_push_kv_bool(data, "observer_currently_chain_authorized",
                    zcl_native_zcode_delegation_authorized(
                        &attestation->observer_delegation, NULL, 0));
  json_push_kv_bool(data, "local_evidence", true);
  json_push_kv_bool(data, "global_truth", false);
  json_push_kv_bool(data, "grants_authority", false);
  json_push_kv_bool(data, "executable", false);
}

void zcl_native_handle_metaverse_space_scout_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  const char *attestation_root = scout_str(request->input, "root");
  char workspace[MVSCOUT_PATH_MAX];
  const char *resolved = scout_workspace(request->input, workspace);
  struct vcs_space_scout_attestation_v1 attestation;
  struct zcl_result attested = attestation_root && resolved
      ? metaverse_space_scout_attestation_show(
            resolved, attestation_root, &attestation)
      : ZCL_ERR(-1, "space-scout-show-input-invalid");
  if (!attested.ok) {
    scout_fail(reply, "SCOUT_EVIDENCE_NOT_FOUND", "show",
               attested.message);
    return;
  }
  struct vcs_space_scout_map_v1 *map = zcl_malloc(
      sizeof(*map), "space_scout_show_map");
  if (!map) {
    scout_fail(reply, "SCOUT_EVIDENCE_ALLOCATION", "show",
               "evidence map allocation failed");
    return;
  }
  struct vcs_space_scout_mission_v1 mission;
  struct zcl_result link;
  if (!scout_show_linked(resolved, &attestation, map, &mission, &link)) {
    free(map);
    scout_fail(reply, "SCOUT_EVIDENCE_LINK_INVALID", "show", link.message);
    return;
  }
  scout_push_attestation(&reply->data, attestation_root, &attestation);
  struct json_value mission_data;
  json_init(&mission_data);
  json_set_object(&mission_data);
  scout_push_mission(&mission_data, &mission);
  json_push_kv(&reply->data, "mission", &mission_data);
  json_free(&mission_data);
  scout_push_map(&reply->data, map);
  free(map);
}
