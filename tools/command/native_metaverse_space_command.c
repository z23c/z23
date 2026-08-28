/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed Sovereign Space v1 plan/commit/show/publish/discover commands. */

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "command/native_zcode_policy.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "services/metaverse_space_service.h"
#include "support/cleanse.h"
#include "vcs/package_store.h"
#include "vcs/space.h"
#include "vcs/zcode_dht_service.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_sovereignty_policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MVSPACE_PATH_MAX 4096u
#define MVSPACE_RECORD_SECONDS INT64_C(3600)
#define MVSPACE_DISCOVERY_FOREGROUND_MS INT64_C(10000)

struct mvspace_chain_proof {
  uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
};

static const char *mvspace_str(const struct json_value *input,
                               const char *key)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static int64_t mvspace_int(const struct json_value *input, const char *key,
                           int64_t fallback)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_INT ? json_get_int(value) : fallback;
}

static bool mvspace_bool(const struct json_value *input, const char *key)
{
  const struct json_value *value = input ? json_get(input, key) : NULL;
  return value && value->type == JSON_BOOL && json_get_bool(value);
}

static void mvspace_fail(struct zcl_command_reply *reply, const char *code,
                         const char *detail, const char *leaf)
{
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                         false, detail, leaf);
}

static void mvspace_blocked(struct zcl_command_reply *reply, const char *code,
                            const char *detail, const char *leaf)
{
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                         ZCL_COMMAND_EXIT_FAILED, code, "policy", true,
                         false, detail, leaf);
}

static void mvspace_blocked_after_mutation(
    struct zcl_command_reply *reply, const char *code,
    const char *detail, const char *leaf)
{
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                         ZCL_COMMAND_EXIT_FAILED, code, "publish", true,
                         true, detail, leaf);
}

static void mvspace_discovery_state(
    struct zcl_command_reply *reply, const char *state, bool retryable,
    const char *phase, uint32_t completed, const char *root,
    enum metaverse_space_object_kind kind)
{
  if (!reply)
    return;
  json_push_kv_str(&reply->data, "state", state ? state : "invalid");
  json_push_kv_bool(&reply->data, "retryable", retryable);
  json_push_kv_str(&reply->data, "phase", phase ? phase : "validate");
  json_push_kv_int(&reply->data, "progress_steps_completed", completed);
  json_push_kv_int(&reply->data, "progress_steps_total", 4);
  char next[256];
  const char *kind_name = kind == METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR
                              ? "service_descriptor" : "space_manifest";
  if (state && strcmp(state, "present") == 0 && root)
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space show %s", root);
  else if (retryable && root)
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space discover %s --kind=%s",
                   root, kind_name);
  else
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space status");
  json_push_kv_str(&reply->data, "next_action", next);
}

static const char *mvspace_datadir(const struct json_value *input)
{
  const char *datadir = mvspace_str(input, "datadir");
  return datadir && datadir[0] ? datadir : zcl_native_command_datadir();
}

static const char *mvspace_workspace(const struct json_value *input,
                                     char out[MVSPACE_PATH_MAX])
{
  const char *workspace = mvspace_str(input, "workspace");
  if (workspace && workspace[0]) {
    int n = snprintf(out, MVSPACE_PATH_MAX, "%s", workspace);
    return n > 0 && n < (int)MVSPACE_PATH_MAX ? out : NULL;
  }
  const char *datadir = mvspace_datadir(input);
  int n = datadir ? snprintf(out, MVSPACE_PATH_MAX, "%s/zcode", datadir) : -1;
  return n > 0 && n < (int)MVSPACE_PATH_MAX ? out : NULL;
}

/* An absent object store is a valid empty/not-found state. A path that is
 * present but cannot be a directory is different: treating ENOTDIR as an
 * empty inventory would let a READ command hide local corruption. Keep this
 * preflight read-only; it exists only to preserve that distinction before the
 * lower CAS loader collapses both cases into its generic not-found result. */
static bool mvspace_workspace_store_shape_valid(const char *workspace)
{
  char path[MVSPACE_PATH_MAX];
  int n = workspace
      ? snprintf(path, sizeof(path), "%s/.zvcs", workspace) : -1;
  if (n <= 0 || n >= (int)sizeof(path))
    return false;
  enum platform_directory_probe_result result =
      platform_directory_probe_real(path);
  return result == PLATFORM_DIRECTORY_PROBE_OK ||
         result == PLATFORM_DIRECTORY_PROBE_MISSING;
}

static bool mvspace_root(const char *hex, uint8_t out[32])
{
  return hex && strlen(hex) == 64u && zcl_hex_decode_lower(hex, out, 32);
}

static int root_compare(const void *left, const void *right)
{
  return memcmp(left, right, 32);
}

static bool mvspace_roots(const struct json_value *input, const char *key,
                          uint8_t roots[][32], size_t maximum,
                          uint8_t *count_out)
{
  const struct json_value *array = input ? json_get(input, key) : NULL;
  *count_out = 0;
  if (!array)
    return true;
  size_t count = json_size(array);
  if (array->type != JSON_ARR || count > maximum)
    return false;
  for (size_t i = 0; i < count; i++) {
    const struct json_value *value = json_at(array, i);
    const char *hex = value && value->type == JSON_STR
                          ? json_get_str(value) : NULL;
    if (!mvspace_root(hex, roots[i]))
      return false;
  }
  qsort(roots, count, 32u, root_compare);
  for (size_t i = 1; i < count; i++)
    if (memcmp(roots[i - 1], roots[i], 32) == 0)
      return false;
  *count_out = (uint8_t)count;
  return true;
}

static bool mvspace_verbs(const struct json_value *input, uint8_t *out)
{
  const struct json_value *verbs =
      input ? json_get(input, "read_only_verbs") : NULL;
  if (!verbs || verbs->type != JSON_ARR || json_size(verbs) == 0 ||
      json_size(verbs) > 4u)
    return false;
  uint8_t mask = 0;
  for (size_t i = 0; i < json_size(verbs); i++) {
    const struct json_value *value = json_at(verbs, i);
    const char *verb = value && value->type == JSON_STR
                           ? json_get_str(value) : NULL;
    uint8_t bit = verb && strcmp(verb, "discover") == 0
                      ? VCS_SERVICE_VERB_DISCOVER
                  : verb && strcmp(verb, "fetch") == 0
                      ? VCS_SERVICE_VERB_FETCH
                  : verb && strcmp(verb, "list") == 0
                      ? VCS_SERVICE_VERB_LIST
                  : verb && strcmp(verb, "query") == 0
                      ? VCS_SERVICE_VERB_QUERY
                      : 0;
    if (!bit || (mask & bit))
      return false;
    mask |= bit;
  }
  *out = mask;
  return true;
}

static bool mvspace_service(const struct json_value *input,
                            struct vcs_service_descriptor_v1 *service)
{
  memset(service, 0, sizeof(*service));
  service->schema_version = VCS_SERVICE_DESCRIPTOR_VERSION;
  const char *protocol = mvspace_str(input, "protocol_root");
  return mvspace_root(protocol, service->protocol_root) &&
         mvspace_verbs(input, &service->read_verbs) &&
         mvspace_roots(input, "object_roots", service->object_roots,
                       VCS_SERVICE_OBJECT_MAX, &service->object_count) &&
         mvspace_roots(input, "capability_roots", service->capability_roots,
                       VCS_SERVICE_CAPABILITY_MAX,
                       &service->capability_count) &&
         vcs_service_descriptor_validate(service) == VCS_SPACE_OK;
}

static bool mvspace_chain_matches(
    void *opaque, const struct vcs_zcode_dht_delegation *delegation)
{
  struct mvspace_chain_proof *proof = opaque;
  uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  return proof && delegation &&
         vcs_zcode_dht_delegation_encode(delegation, wire) ==
             VCS_ZCODE_DHT_DELEGATION_OK &&
         memcmp(wire, proof->wire, sizeof(wire)) == 0;
}

static bool mvspace_manifest(
    const struct json_value *input, struct vcs_space_manifest_v1 *manifest,
    struct vcs_space_manifest_verify_context *verify,
    struct mvspace_chain_proof *proof, struct zcl_command_reply *reply,
    const char *leaf)
{
  memset(manifest, 0, sizeof(*manifest));
  manifest->schema_version = VCS_SPACE_MANIFEST_VERSION;
  int64_t sequence = mvspace_int(input, "sequence", 0);
  int64_t not_before = mvspace_int(input, "not_before", 0);
  int64_t expiry = mvspace_int(input, "expiry", 0);
  const char *name = mvspace_str(input, "name");
  const char *description = mvspace_str(input, "description");
  if (sequence < 1 || not_before < 1 || expiry <= not_before ||
      !name || !description || strlen(name) > VCS_SPACE_NAME_MAX ||
      strlen(description) > VCS_SPACE_DESCRIPTION_MAX) {
    mvspace_fail(reply, "BAD_MANIFEST",
                 "manifest requires bounded name/description and explicit "
                 "positive sequence, not_before and later expiry", leaf);
    return false;
  }
  manifest->sequence = (uint64_t)sequence;
  manifest->not_before = (uint64_t)not_before;
  manifest->expiry = (uint64_t)expiry;
  (void)snprintf(manifest->name, sizeof(manifest->name), "%s", name);
  (void)snprintf(manifest->description, sizeof(manifest->description), "%s",
                 description);
  if (!mvspace_roots(input, "service_roots", manifest->service_roots,
                     VCS_SPACE_SERVICE_MAX, &manifest->service_count) ||
      !mvspace_roots(input, "object_roots", manifest->object_roots,
                     VCS_SPACE_OBJECT_MAX, &manifest->object_count) ||
      !mvspace_roots(input, "portal_roots", manifest->portal_roots,
                     VCS_SPACE_PORTAL_MAX, &manifest->portal_count)) {
    mvspace_fail(reply, "BAD_ROOT_SET",
                 "root arrays must be bounded unique lowercase-hex sets",
                 leaf);
    return false;
  }
  const char *admission = mvspace_str(input, "admission_root");
  if (admission) {
    if (!mvspace_root(admission, manifest->admission_root)) {
      mvspace_fail(reply, "BAD_ADMISSION_ROOT",
                   "admission_root must be 64 lowercase hex", leaf);
      return false;
    }
    manifest->has_admission = true;
  }
  const char *datadir = mvspace_datadir(input);
  uint8_t online_seed[32], online_pubkey[32];
  char error[192] = {0};
  enum vcs_space_result sign_rc = VCS_SPACE_OK;
  bool identity_loaded =
      datadir && vcs_zcode_dht_delegation_load(
                     datadir, &manifest->delegation, error, sizeof(error)) &&
      vcs_zcode_dht_online_key_load(datadir, online_seed, online_pubkey,
                                    error, sizeof(error));
  if (identity_loaded) {
    /* A signer/window refusal is a DIFFERENT failure from a missing identity
     * file and must be named as itself: collapsing it into the generic
     * "cannot sign" body sent operators to re-provision a healthy identity
     * when the real problem was e.g. a manifest window (ERR_TIME) that does
     * not fit inside the delegation's, or an online key (ERR_SIGNER) that is
     * not the delegated one. */
    if (memcmp(online_pubkey, manifest->delegation.online_pubkey, 32) != 0)
      sign_rc = VCS_SPACE_ERR_SIGNER;
    else
      sign_rc = vcs_space_manifest_sign(manifest, online_seed);
    if (sign_rc != VCS_SPACE_OK)
      (void)snprintf(error, sizeof(error),
                     "local online key cannot sign this manifest: %s",
                     vcs_space_result_string(sign_rc));
  }
  memory_cleanse(online_seed, sizeof(online_seed));
  if (!identity_loaded || sign_rc != VCS_SPACE_OK) {
    /* A missing DHT identity file is provisioned by the delegate flow
     * (native_zcode_network_command.c load_or_create) — name the remedy
     * instead of leaving the operator with a bare I/O error. */
    if (strcmp(error, "cannot open DHT identity file") == 0)
      (void)snprintf(error, sizeof(error),
                     "cannot open DHT identity file — run `z23 zcode "
                     "network delegate` once to provision it");
    mvspace_blocked(reply, "IDENTITY_UNAVAILABLE",
                    error[0] ? error :
                    "local online key/delegation cannot sign this manifest",
                    leaf);
    return false;
  }
  if (!zcl_native_zcode_delegation_authorized(
          &manifest->delegation, error, sizeof(error)) ||
      vcs_zcode_dht_delegation_encode(&manifest->delegation, proof->wire) !=
          VCS_ZCODE_DHT_DELEGATION_OK) {
    mvspace_blocked(reply, "OWNER_NOT_CHAIN_AUTHORIZED",
                    error[0] ? error :
                    "the running node did not authorize this ZID delegation",
                    leaf);
    return false;
  }
  memset(verify, 0, sizeof(*verify));
  memcpy(verify->network_genesis, manifest->delegation.network_genesis, 32);
  verify->now_unix = (uint64_t)platform_time_wall_unix();
  verify->chain_verify = mvspace_chain_matches;
  verify->chain_ctx = proof;
  return true;
}

static const char *mvspace_service_type(
    enum metaverse_space_object_kind kind)
{
  return kind == METAVERSE_SPACE_OBJECT_MANIFEST ? "space.manifest"
                                                 : "space.service";
}

static const char *mvspace_namespace(enum metaverse_space_object_kind kind)
{
  return mvspace_service_type(kind);
}

static bool mvspace_policy(
    const char *datadir, enum vcs_zcode_sovereignty_action action,
    const char *semantic, const char *transport, const char *publisher,
    const char *service_type, char *error, size_t error_capacity)
{
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  if ((semantic && !mvspace_root(semantic, subject.semantic_root)) ||
      (transport && !mvspace_root(transport, subject.transport_root)) ||
      (publisher && !mvspace_root(publisher, subject.publisher_zid)))
    return false;
  if (transport)
    memcpy(subject.package_root, subject.transport_root, 32);
  if (service_type)
    (void)snprintf(subject.service_type, sizeof(subject.service_type), "%s",
                   service_type);
  return zcl_native_zcode_policy_allows(datadir, action, &subject,
                                        error, error_capacity);
}

static bool mvspace_policy_actions(
    const char *datadir, const enum vcs_zcode_sovereignty_action *actions,
    size_t action_count, const char *semantic, const char *transport,
    const char *publisher, const char *service_type,
    struct zcl_command_reply *reply, const char *leaf)
{
  char error[192] = {0};
  for (size_t i = 0; i < action_count; i++)
    if (!mvspace_policy(datadir, actions[i], semantic, transport, publisher,
                        service_type, error, sizeof(error))) {
      if (reply)
        mvspace_blocked(reply, "SOVEREIGNTY_DENIED",
                        error[0] ? error : "local policy denied the action",
                        leaf);
      return false;
    }
  return true;
}

static bool mvspace_admit_policy(
    const char *datadir, const char *semantic, const char *transport,
    const char *pointer_publisher, const char *manifest_owner,
    const char *service_type)
{
  static const enum vcs_zcode_sovereignty_action actions[] = {
      VCS_ZCODE_SOVEREIGNTY_STORE, VCS_ZCODE_SOVEREIGNTY_INDEX};
  if (!mvspace_policy_actions(
          datadir, actions, sizeof(actions) / sizeof(actions[0]), semantic,
          transport, pointer_publisher, service_type, NULL,
          "metaverse.space.discover"))
    return false;
  return !manifest_owner ||
         (pointer_publisher &&
          strcmp(pointer_publisher, manifest_owner) == 0) ||
         mvspace_policy_actions(
             datadir, actions, sizeof(actions) / sizeof(actions[0]), semantic,
             transport, manifest_owner, service_type, NULL,
             "metaverse.space.discover");
}

#ifdef ZCL_TESTING
bool zcl_native_metaverse_space_test_admit_allowed(
    const char *datadir, const uint8_t semantic_root[32],
    const uint8_t transport_root[32], const uint8_t pointer_publisher[32],
    const uint8_t manifest_owner[32], bool manifest)
{
  if (!datadir || !semantic_root || !transport_root || !pointer_publisher)
    return false;
  char semantic[65], transport[65], pointer[65], owner[65];
  zcl_hex_encode(semantic_root, 32, semantic);
  zcl_hex_encode(transport_root, 32, transport);
  zcl_hex_encode(pointer_publisher, 32, pointer);
  const char *owner_ptr = NULL;
  if (manifest_owner) {
    zcl_hex_encode(manifest_owner, 32, owner);
    owner_ptr = owner;
  }
  return mvspace_admit_policy(
      datadir, semantic, transport, pointer, owner_ptr,
      manifest ? "space.manifest" : "space.service");
}
#endif

static void push_root_array(struct json_value *data, const char *key,
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
  json_push_kv(data, key, &array);
  json_free(&array);
}

static void push_service(struct json_value *data,
                         const struct vcs_service_descriptor_v1 *service)
{
  char protocol[65];
  zcl_hex_encode(service->protocol_root, 32, protocol);
  json_push_kv_str(data, "kind", "service_descriptor.v1");
  json_push_kv_str(data, "protocol_root", protocol);
  struct json_value verbs;
  json_init(&verbs);
  json_set_array(&verbs);
  static const struct { uint8_t bit; const char *name; } known[] = {
      {VCS_SERVICE_VERB_DISCOVER, "discover"},
      {VCS_SERVICE_VERB_FETCH, "fetch"},
      {VCS_SERVICE_VERB_LIST, "list"},
      {VCS_SERVICE_VERB_QUERY, "query"},
  };
  for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
    if (service->read_verbs & known[i].bit) {
      struct json_value value;
      json_init(&value);
      json_set_str(&value, known[i].name);
      json_push_back(&verbs, &value);
      json_free(&value);
    }
  json_push_kv(data, "read_only_verbs", &verbs);
  json_free(&verbs);
  push_root_array(data, "object_roots", service->object_roots,
                  service->object_count);
  push_root_array(data, "capability_requirements",
                  service->capability_roots, service->capability_count);
  json_push_kv_bool(data, "grants_authority", false);
  json_push_kv_bool(data, "executable", false);
}

static void push_manifest(struct json_value *data,
                          const struct vcs_space_manifest_v1 *manifest)
{
  char owner[65], admission[65];
  zcl_hex_encode(manifest->delegation.doc.master_pubkey, 32, owner);
  json_push_kv_str(data, "kind", "space_manifest.v1");
  json_push_kv_str(data, "owner_zid", owner);
  json_push_kv_int(data, "sequence", (int64_t)manifest->sequence);
  json_push_kv_int(data, "not_before", (int64_t)manifest->not_before);
  json_push_kv_int(data, "expiry", (int64_t)manifest->expiry);
  json_push_kv_str(data, "name", manifest->name);
  json_push_kv_str(data, "description", manifest->description);
  push_root_array(data, "service_roots", manifest->service_roots,
                  manifest->service_count);
  push_root_array(data, "public_object_roots", manifest->object_roots,
                  manifest->object_count);
  push_root_array(data, "portal_space_roots", manifest->portal_roots,
                  manifest->portal_count);
  json_push_kv_bool(data, "has_admission_statement",
                    manifest->has_admission);
  if (manifest->has_admission) {
    zcl_hex_encode(manifest->admission_root, 32, admission);
    json_push_kv_str(data, "admission_root", admission);
  }
  json_push_kv_bool(data, "signature_verified", true);
  json_push_kv_bool(data, "executable", false);
}

static bool mvspace_object_input(
    const struct json_value *input,
    struct vcs_service_descriptor_v1 *service,
    struct vcs_space_manifest_v1 *manifest,
    struct vcs_space_manifest_verify_context *verify,
    struct mvspace_chain_proof *proof,
    enum metaverse_space_object_kind *kind,
    struct zcl_command_reply *reply, const char *leaf)
{
  const char *requested = mvspace_str(input, "kind");
  if (requested && strcmp(requested, "service_descriptor") == 0) {
    if (!mvspace_service(input, service)) {
      mvspace_fail(reply, "BAD_SERVICE_DESCRIPTOR",
                   "service_descriptor requires a full protocol_root, "
                   "known read-only verbs, and bounded unique root arrays",
                   leaf);
      return false;
    }
    *kind = METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR;
    return true;
  }
  if (requested && strcmp(requested, "space_manifest") == 0) {
    if (!mvspace_manifest(input, manifest, verify, proof, reply, leaf))
      return false;
    *kind = METAVERSE_SPACE_OBJECT_MANIFEST;
    return true;
  }
  mvspace_fail(reply, "BAD_KIND",
               "kind must be service_descriptor or space_manifest", leaf);
  return false;
}

void zcl_native_handle_metaverse_space_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  struct vcs_service_descriptor_v1 service;
  struct vcs_space_manifest_v1 manifest;
  struct vcs_space_manifest_verify_context verify;
  struct mvspace_chain_proof proof;
  enum metaverse_space_object_kind kind;
  if (!mvspace_object_input(request->input, &service, &manifest, &verify,
                            &proof, &kind, reply, "metaverse.space.plan"))
    return;
  struct metaverse_space_plan_out plan;
  struct zcl_result result = kind == METAVERSE_SPACE_OBJECT_MANIFEST
      ? metaverse_space_manifest_plan(&manifest, &verify, &plan)
      : metaverse_space_service_plan(&service, &plan);
  if (!result.ok) {
    mvspace_fail(reply, "PLAN_REFUSED", result.message,
                 "metaverse.space.plan");
    return;
  }
  json_push_kv_str(&reply->data, "object_root", plan.object_root);
  json_push_kv_str(&reply->data, "plan_token", plan.plan_token);
  json_push_kv_int(&reply->data, "wire_bytes", (int64_t)plan.wire_bytes);
  json_push_kv_str(&reply->data, "state", "PLANNED");
  json_push_kv_bool(&reply->data, "side_effect_free", true);
  json_push_kv_str(&reply->data, "commit_command", "metaverse.space.commit");
  if (kind == METAVERSE_SPACE_OBJECT_MANIFEST)
    push_manifest(&reply->data, &manifest);
  else
    push_service(&reply->data, &service);
}

void zcl_native_handle_metaverse_space_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  struct vcs_service_descriptor_v1 service;
  struct vcs_space_manifest_v1 manifest;
  struct vcs_space_manifest_verify_context verify;
  struct mvspace_chain_proof proof;
  enum metaverse_space_object_kind kind;
  if (!mvspace_object_input(request->input, &service, &manifest, &verify,
                            &proof, &kind, reply, "metaverse.space.commit"))
    return;
  const char *token = mvspace_str(request->input, "plan_token");
  bool confirm = mvspace_bool(request->input, "confirm");
  char workspace[MVSPACE_PATH_MAX];
  const char *resolved = mvspace_workspace(request->input, workspace);
  if (!token || !resolved) {
    mvspace_fail(reply, "BAD_COMMIT",
                 "commit requires plan_token, confirm:true and workspace",
                 "metaverse.space.commit");
    return;
  }
  struct metaverse_space_plan_out preview;
  struct zcl_result planned = kind == METAVERSE_SPACE_OBJECT_MANIFEST
      ? metaverse_space_manifest_plan(&manifest, &verify, &preview)
      : metaverse_space_service_plan(&service, &preview);
  if (!planned.ok) {
    mvspace_fail(reply, "COMMIT_REFUSED", planned.message,
                 "metaverse.space.commit");
    return;
  }
  const char *owner = NULL;
  char owner_hex[65];
  if (kind == METAVERSE_SPACE_OBJECT_MANIFEST) {
    zcl_hex_encode(manifest.delegation.doc.master_pubkey, 32, owner_hex);
    owner = owner_hex;
  }
  static const enum vcs_zcode_sovereignty_action actions[] = {
      VCS_ZCODE_SOVEREIGNTY_STORE, VCS_ZCODE_SOVEREIGNTY_INDEX};
  if (!mvspace_policy_actions(
          mvspace_datadir(request->input), actions,
          sizeof(actions) / sizeof(actions[0]), preview.object_root, NULL,
          owner, mvspace_service_type(kind), reply,
          "metaverse.space.commit"))
    return;
  struct metaverse_space_commit_out committed;
  struct zcl_result result = kind == METAVERSE_SPACE_OBJECT_MANIFEST
      ? metaverse_space_manifest_commit(resolved, &manifest, &verify, token,
                                        confirm, &committed)
      : metaverse_space_service_commit(resolved, &service, token, confirm,
                                       &committed);
  if (!result.ok) {
    mvspace_fail(reply, "COMMIT_REFUSED", result.message,
                 "metaverse.space.commit");
    return;
  }
  json_push_kv_str(&reply->data, "object_root", committed.object_root);
  json_push_kv_bool(&reply->data, "already_committed",
                    committed.already_committed);
  json_push_kv_str(&reply->data, "state", "COMMITTED");
  json_push_kv_str(&reply->data, "authority", "CANONICAL_CAS_WIRE");
}

void zcl_native_handle_metaverse_space_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  const char *root = mvspace_str(request->input, "root");
  char workspace[MVSPACE_PATH_MAX];
  const char *resolved = mvspace_workspace(request->input, workspace);
  struct metaverse_space_object object;
  struct zcl_result shown = root && resolved
      ? metaverse_space_show(resolved, root, &object)
      : ZCL_ERR(-1, "space-show-root-or-workspace-invalid");
  if (!shown.ok) {
    mvspace_fail(reply, "SPACE_NOT_FOUND", shown.message,
                 "metaverse.space.show");
    return;
  }
  json_push_kv_str(&reply->data, "object_root", root);
  if (object.kind == METAVERSE_SPACE_OBJECT_MANIFEST) {
    push_manifest(&reply->data, &object.as.manifest);
    uint64_t now = (uint64_t)platform_time_wall_unix();
    bool active = vcs_space_manifest_validate_at(
                      &object.as.manifest,
                      object.as.manifest.delegation.network_genesis,
                      now) == VCS_SPACE_OK;
    bool chain = active && zcl_native_zcode_delegation_authorized(
                               &object.as.manifest.delegation, NULL, 0);
    json_push_kv_bool(&reply->data, "currently_active", active);
    json_push_kv_bool(&reply->data, "chain_bound", chain);
    json_push_kv_str(&reply->data, "evidence_grade",
                     chain ? "chain_validated_local" : "local_signature");
  } else {
    push_service(&reply->data, &object.as.service);
    json_push_kv_bool(&reply->data, "chain_bound", false);
    json_push_kv_str(&reply->data, "evidence_grade", "local_content_hash");
  }
}

struct mvspace_status_identity {
  bool online_key;
  bool delegation_present;
  bool delegation_valid;
  bool chain_authorized;
};

struct mvspace_status_network {
  bool reachable;
  bool enabled;
  uint32_t authenticated_peers;
};

struct mvspace_status_visibility {
  bool requested;
  bool visible;
  bool kind_matches;
  enum metaverse_space_object_kind kind;
  char transport_root[65];
  uint32_t descriptors_total;
  uint32_t descriptors_visible;
};

static struct mvspace_status_identity mvspace_status_identity_read(
    const char *datadir)
{
  struct mvspace_status_identity status;
  struct vcs_zcode_dht_delegation delegation;
  uint8_t seed[32], public_key[32];
  char ignored[192] = {0};

  memset(&status, 0, sizeof(status));
  memset(seed, 0, sizeof(seed));
  memset(public_key, 0, sizeof(public_key));
  status.online_key = datadir && vcs_zcode_dht_online_key_load(
      datadir, seed, public_key, ignored, sizeof(ignored));
  memory_cleanse(seed, sizeof(seed));
  status.delegation_present = datadir && vcs_zcode_dht_delegation_load(
      datadir, &delegation, ignored, sizeof(ignored));
  int64_t wall = platform_time_wall_unix();
  status.delegation_valid =
      status.online_key && status.delegation_present && wall > 0 &&
      memcmp(public_key, delegation.online_pubkey, sizeof(public_key)) == 0 &&
      vcs_zcode_dht_delegation_verify(
          &delegation, NULL, NULL, 0, NULL, (uint64_t)wall) ==
          VCS_ZCODE_DHT_DELEGATION_OK;
  status.chain_authorized =
      status.delegation_valid &&
      zcl_native_zcode_delegation_authorized(&delegation, NULL, 0);
  memory_cleanse(public_key, sizeof(public_key));
  return status;
}

static struct mvspace_status_network mvspace_status_network_read(void)
{
  struct mvspace_status_network status;
  struct json_value dht;

  memset(&status, 0, sizeof(status));
  if (!zcl_native_zcode_dht_status_read(&dht)) {
    json_free(&dht);
    return status;
  }
  status.reachable = true;
  status.enabled = json_get_bool_or(&dht, "enabled", false);
  int64_t peers = json_get_int(json_get(&dht, "connected_authenticated"));
  status.authenticated_peers = peers > 0 && peers <= UINT32_MAX
                                   ? (uint32_t)peers : 0;
  json_free(&dht);
  return status;
}

static bool mvspace_status_live_datadir(const struct json_value *input,
                                        const char *datadir)
{
  const char *requested = mvspace_str(input, "datadir");
  const char *running = zcl_native_command_datadir();
  return (!requested || !requested[0]) ||
         (running && datadir && strcmp(running, datadir) == 0);
}

static struct mvspace_status_visibility mvspace_status_visibility_read(
    const char *workspace, const char *root,
    enum metaverse_space_object_kind expected)
{
  struct mvspace_status_visibility status;
  struct metaverse_space_object object;

  memset(&status, 0, sizeof(status));
  status.requested = root != NULL;
  if (!root || !workspace)
    return status;
  struct zcl_result shown = metaverse_space_show(workspace, root, &object);
  if (!shown.ok)
    return status;
  status.visible = true;
  status.kind = object.kind;
  status.kind_matches = object.kind == expected;
  enum metaverse_space_object_kind transport_kind;
  if (!metaverse_space_transport_root(
           workspace, root, status.transport_root, &transport_kind).ok ||
      transport_kind != object.kind)
    status.transport_root[0] = '\0';
  if (object.kind == METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR) {
    status.descriptors_total = 1;
    status.descriptors_visible = 1;
    return status;
  }
  status.descriptors_total = object.as.manifest.service_count;
  for (uint8_t i = 0; i < object.as.manifest.service_count; i++) {
    char descriptor_root[65];
    struct metaverse_space_object descriptor;
    zcl_hex_encode(object.as.manifest.service_roots[i], 32, descriptor_root);
    if (metaverse_space_show(workspace, descriptor_root, &descriptor).ok &&
        descriptor.kind == METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR)
      status.descriptors_visible++;
  }
  return status;
}

static uint32_t mvspace_status_local_records(
    const char *kind, const char *namespace_name, const char *root_key,
    const char *root)
{
  if (!kind || !namespace_name || !root_key || !root || !root[0])
    return 0;
  struct json_value selector, result;
  json_init(&selector);
  json_set_object(&selector);
  json_push_kv_str(&selector, "kind", kind);
  json_push_kv_str(&selector, "namespace", namespace_name);
  json_push_kv_str(&selector, root_key, root);
  bool read = zcl_native_zcode_records_local(&selector, &result);
  int64_t count = read ? json_get_int(json_get(&result, "count")) : 0;
  json_free(&result);
  json_free(&selector);
  return count > 0 && count <= UINT32_MAX ? (uint32_t)count : 0;
}

static void mvspace_status_policy_read(
    const char *datadir, const char *semantic, const char *transport,
    const char *service_type, bool allowed[6], bool *all_out)
{
  static const enum vcs_zcode_sovereignty_action actions[6] = {
      VCS_ZCODE_SOVEREIGNTY_DISCOVER, VCS_ZCODE_SOVEREIGNTY_FETCH,
      VCS_ZCODE_SOVEREIGNTY_STORE, VCS_ZCODE_SOVEREIGNTY_INDEX,
      VCS_ZCODE_SOVEREIGNTY_SERVE, VCS_ZCODE_SOVEREIGNTY_FORWARD};
  *all_out = true;
  for (size_t i = 0; i < 6; i++) {
    allowed[i] = mvspace_policy(datadir, actions[i], semantic, transport,
                                NULL, service_type, NULL, 0);
    *all_out = *all_out && allowed[i];
  }
}

static void mvspace_status_blocker(struct json_value *array,
                                   const char *code)
{
  struct json_value value;
  json_init(&value);
  json_set_str(&value, code);
  (void)json_push_back(array, &value);
  json_free(&value);
}

static void mvspace_status_push_identity(
    struct json_value *data, const struct mvspace_status_identity *identity)
{
  struct json_value row;
  json_init(&row);
  json_set_object(&row);
  json_push_kv_bool(&row, "online_key_ready", identity->online_key);
  json_push_kv_bool(&row, "delegation_present",
                    identity->delegation_present);
  json_push_kv_bool(&row, "delegation_valid", identity->delegation_valid);
  json_push_kv_bool(&row, "chain_authorized",
                    identity->chain_authorized);
  json_push_kv_bool(&row, "ready", identity->chain_authorized);
  json_push_kv(data, "identity", &row);
  json_free(&row);
}

static void mvspace_status_push_policy(struct json_value *data,
                                       const bool allowed[6], bool all)
{
  static const char *const names[6] = {
      "discover", "fetch", "store", "index", "serve", "forward"};
  struct json_value row;
  json_init(&row);
  json_set_object(&row);
  for (size_t i = 0; i < 6; i++)
    json_push_kv_bool(&row, names[i], allowed[i]);
  json_push_kv_bool(&row, "ready", all);
  json_push_kv_bool(&row, "candidate_specific_recheck_required", true);
  json_push_kv(data, "policy", &row);
  json_free(&row);
}

void zcl_native_handle_metaverse_space_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  const char *root = mvspace_str(request->input, "root");
  const char *kind_text = mvspace_str(request->input, "kind");
  enum metaverse_space_object_kind expected =
      !kind_text || strcmp(kind_text, "space_manifest") == 0
          ? METAVERSE_SPACE_OBJECT_MANIFEST
          : strcmp(kind_text, "service_descriptor") == 0
                ? METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR
                : METAVERSE_SPACE_OBJECT_NONE;
  uint8_t decoded[32];
  if (expected == METAVERSE_SPACE_OBJECT_NONE ||
      (root && !mvspace_root(root, decoded))) {
    mvspace_fail(reply, "BAD_STATUS_SUBJECT",
                 "kind must be space_manifest or service_descriptor and "
                 "root, when supplied, must be 64 lowercase hex",
                 "metaverse.space.status");
    return;
  }
  const char *datadir = mvspace_datadir(request->input);
  char workspace[MVSPACE_PATH_MAX];
  const char *resolved = mvspace_workspace(request->input, workspace);
  if (!resolved || !mvspace_workspace_store_shape_valid(resolved)) {
    mvspace_fail(reply, "WORKSPACE_UNREADABLE",
                 "the local workspace object store is present but unreadable",
                 "metaverse.space.status");
    return;
  }
  struct mvspace_status_identity identity =
      mvspace_status_identity_read(datadir);
  struct mvspace_status_network network = mvspace_status_network_read();
  struct mvspace_status_visibility visibility =
      mvspace_status_visibility_read(resolved, root, expected);
  const char *service_type = mvspace_service_type(expected);
  const char *transport = visibility.transport_root[0]
                              ? visibility.transport_root : NULL;
  bool policy[6], policy_all = false;
  mvspace_status_policy_read(datadir, root, transport, service_type,
                             policy, &policy_all);

  struct vcs_package_store_totals totals;
  enum vcs_package_store_totals_result totals_result =
      mvspace_status_live_datadir(request->input, datadir)
          ? vcs_package_store_try_totals(&totals)
          : VCS_PACKAGE_STORE_TOTALS_CLOSED;
  bool store_open = totals_result == VCS_PACKAGE_STORE_TOTALS_OK;
  bool store_busy = totals_result == VCS_PACKAGE_STORE_TOTALS_BUSY;
  bool hosting_enabled = vcs_package_store_hosting_enabled();
  bool authenticated_peer = network.authenticated_peers > 0;
  bool descriptor_visibility =
      visibility.visible && visibility.kind_matches &&
      visibility.descriptors_visible == visibility.descriptors_total;
  bool ready_to_publish = root && visibility.visible &&
      visibility.kind_matches && transport && identity.chain_authorized &&
      network.enabled && authenticated_peer && store_open &&
      hosting_enabled && policy[2] && policy[3] && policy[4] && policy[5] &&
      descriptor_visibility;
  bool ready_to_discover = root && network.enabled && authenticated_peer &&
      store_open && policy[0] && policy[1] && policy[2] && policy[3];
  bool ready_to_scout = ready_to_discover && identity.chain_authorized;

  uint32_t pointer_records = network.enabled && root
      ? mvspace_status_local_records("pointer", service_type,
                                     "semantic_root", root) : 0;
  uint32_t provider_records = network.enabled && transport
      ? mvspace_status_local_records("provider", service_type,
                                     "transport_root", transport) : 0;

  json_push_kv_str(&reply->data, "semantic_root", root ? root : "");
  json_push_kv_str(&reply->data, "transport_root",
                   transport ? transport : "");
  json_push_kv_str(&reply->data, "kind",
                   expected == METAVERSE_SPACE_OBJECT_MANIFEST
                       ? "space_manifest" : "service_descriptor");
  mvspace_status_push_identity(&reply->data, &identity);
  {
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_bool(&row, "status_reachable", network.reachable);
    json_push_kv_bool(&row, "dht_ready", network.enabled);
    json_push_kv_bool(&row, "authenticated_peer_ready",
                      authenticated_peer);
    json_push_kv_int(&row, "authenticated_peer_count",
                     network.authenticated_peers);
    json_push_kv(&reply->data, "network", &row);
    json_free(&row);
  }
  {
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_bool(&row, "open", store_open);
    json_push_kv_bool(&row, "busy", store_busy);
    json_push_kv_bool(&row, "hosting_enabled", hosting_enabled);
    json_push_kv_bool(&row, "ready", store_open && hosting_enabled);
    json_push_kv(&reply->data, "package_store", &row);
    json_free(&row);
  }
  mvspace_status_push_policy(&reply->data, policy, policy_all);
  {
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_bool(&row, "root_requested", visibility.requested);
    json_push_kv_str(&row, "state",
                     !visibility.requested ? "not_requested" :
                     !visibility.visible ? "not_found" :
                     !visibility.kind_matches ? "invalid" : "present");
    json_push_kv_bool(&row, "manifest_visible",
                      visibility.visible && visibility.kind ==
                          METAVERSE_SPACE_OBJECT_MANIFEST);
    json_push_kv_int(&row, "descriptors_total",
                     visibility.descriptors_total);
    json_push_kv_int(&row, "descriptors_visible",
                     visibility.descriptors_visible);
    json_push_kv_bool(&row, "all_descriptors_visible",
                      descriptor_visibility);
    json_push_kv(&reply->data, "visibility", &row);
    json_free(&row);
  }
  {
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_str(&row, "state",
                     pointer_records && provider_records ? "published" :
                     pointer_records ? "partial" : "not_published");
    json_push_kv_int(&row, "pointer_records", pointer_records);
    json_push_kv_int(&row, "provider_records", provider_records);
    json_push_kv_str(&row, "replication_state",
                     provider_records ? "declared" : "none");
    json_push_kv_bool(&row, "replication_is_possession_proof", false);
    json_push_kv(&reply->data, "publication", &row);
    json_free(&row);
  }

  struct json_value blockers;
  json_init(&blockers);
  json_set_array(&blockers);
  if (!identity.online_key)
    mvspace_status_blocker(&blockers, "identity_online_key_unavailable");
  if (!identity.delegation_present)
    mvspace_status_blocker(&blockers, "delegation_absent");
  else if (!identity.delegation_valid)
    mvspace_status_blocker(&blockers, "delegation_invalid_or_expired");
  else if (!identity.chain_authorized)
    mvspace_status_blocker(&blockers, "delegation_not_chain_authorized");
  if (!network.reachable)
    mvspace_status_blocker(&blockers, "dht_status_unreachable");
  else if (!network.enabled)
    mvspace_status_blocker(&blockers, "dht_disabled");
  if (network.enabled && !authenticated_peer)
    mvspace_status_blocker(&blockers, "authenticated_peer_absent");
  if (store_busy)
    mvspace_status_blocker(&blockers, "package_store_busy");
  else if (!store_open)
    mvspace_status_blocker(&blockers, "package_store_closed");
  if (!hosting_enabled)
    mvspace_status_blocker(&blockers, "package_hosting_disabled");
  if (!policy_all)
    mvspace_status_blocker(&blockers, "local_policy_not_ready");
  if (!root)
    mvspace_status_blocker(&blockers, "semantic_root_not_supplied");
  else if (!visibility.visible)
    mvspace_status_blocker(&blockers, "local_object_not_found");
  else if (!visibility.kind_matches)
    mvspace_status_blocker(&blockers, "local_object_kind_mismatch");
  else if (!descriptor_visibility)
    mvspace_status_blocker(&blockers, "advertised_descriptor_not_visible");
  json_push_kv(&reply->data, "blockers", &blockers);
  json_push_kv_int(&reply->data, "blocker_count",
                   (int64_t)json_size(&blockers));
  json_free(&blockers);

  json_push_kv_bool(&reply->data, "ready_to_publish", ready_to_publish);
  json_push_kv_bool(&reply->data, "ready_to_discover", ready_to_discover);
  json_push_kv_bool(&reply->data, "ready_to_scout", ready_to_scout);
  json_push_kv_str(&reply->data, "state",
                   ready_to_publish && ready_to_discover && ready_to_scout
                       ? "ready" : "blocked");
  json_push_kv_bool(&reply->data, "retryable", true);
  char next[256];
  if (!root)
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space status --input="
                   "'{\"root\":\"<64hex>\"}'");
  else if (!identity.chain_authorized || !network.enabled)
    (void)snprintf(next, sizeof(next),
                   "z23 zcode network status");
  else if (!store_open)
    (void)snprintf(next, sizeof(next),
                   "z23 ops state --subsystem=zcode_store");
  else if (!policy_all)
    (void)snprintf(next, sizeof(next),
                   "z23 zcode network policy list");
  else if (!visibility.visible && ready_to_discover)
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space discover %s --kind=%s",
                   root, expected == METAVERSE_SPACE_OBJECT_MANIFEST
                             ? "space_manifest" : "service_descriptor");
  else if (ready_to_publish && (!pointer_records || !provider_records))
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space publish %s", root);
  else
    (void)snprintf(next, sizeof(next),
                   "z23 metaverse space show %s", root);
  json_push_kv_str(&reply->data, "next_safe_command", next);
  json_push_kv_bool(&reply->data, "side_effect_free", true);
}

static bool mvspace_store(const char *datadir, bool *live,
                          struct vcs_package_store **out)
{
  *out = vcs_package_store_global();
  *live = *out != NULL;
  if (*out)
    return true;
  *out = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
  return *out != NULL;
}

void zcl_native_handle_metaverse_space_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  if (!request || !reply)
    return;
  const char *root = mvspace_str(request->input, "root");
  const char *datadir = mvspace_datadir(request->input);
  char workspace[MVSPACE_PATH_MAX], blob[65];
  const char *resolved = mvspace_workspace(request->input, workspace);
  enum metaverse_space_object_kind kind;
  struct metaverse_space_object object;
  struct zcl_result transport = root && resolved
      ? metaverse_space_transport_root(resolved, root, blob, &kind)
      : ZCL_ERR(-1, "space-publish-root-or-workspace-invalid");
  struct zcl_result shown = transport.ok
      ? metaverse_space_show(resolved, root, &object)
      : transport;
  if (!shown.ok) {
    mvspace_fail(reply, "PUBLISH_REFUSED", shown.message,
                 "metaverse.space.publish");
    return;
  }
  char owner[65];
  const char *publisher = NULL;
  if (kind == METAVERSE_SPACE_OBJECT_MANIFEST) {
    zcl_hex_encode(object.as.manifest.delegation.doc.master_pubkey, 32, owner);
    publisher = owner;
    uint64_t now = (uint64_t)platform_time_wall_unix();
    if (vcs_space_manifest_validate_at(
            &object.as.manifest,
            object.as.manifest.delegation.network_genesis, now) !=
            VCS_SPACE_OK ||
        !zcl_native_zcode_delegation_authorized(
            &object.as.manifest.delegation, NULL, 0)) {
      mvspace_blocked(reply, "OWNER_NOT_CHAIN_AUTHORIZED",
                      "manifest is not currently valid and chain-authorized",
                      "metaverse.space.publish");
      return;
    }
  }
  static const enum vcs_zcode_sovereignty_action actions[] = {
      VCS_ZCODE_SOVEREIGNTY_STORE, VCS_ZCODE_SOVEREIGNTY_INDEX,
      VCS_ZCODE_SOVEREIGNTY_SERVE, VCS_ZCODE_SOVEREIGNTY_FORWARD};
  if (!mvspace_policy_actions(
          datadir, actions, sizeof(actions) / sizeof(actions[0]), root, blob,
          publisher, mvspace_service_type(kind), reply,
          "metaverse.space.publish"))
    return;
  bool live = false;
  struct vcs_package_store *store = NULL;
  if (!mvspace_store(datadir, &live, &store)) {
    mvspace_blocked(reply, "NO_STORE", "package store failed to open",
                    "metaverse.space.publish");
    return;
  }
  struct zcl_result published = metaverse_space_publish(
      store, resolved, root, blob, &kind);
  if (!live)
    vcs_package_store_close(store);
  if (!published.ok) {
    mvspace_fail(reply, "PUBLISH_REFUSED", published.message,
                 "metaverse.space.publish");
    return;
  }
  int64_t now = platform_time_wall_unix();
  char pointer_token[65], provider_token[65], pointer_error[64] = {0};
  char provider_error[64] = {0};
  bool time_ok = now > 0 && now <= INT64_MAX - MVSPACE_RECORD_SECONDS;
  bool pointer = time_ok && zcl_native_zcode_publish_record(
      "pointer", mvspace_namespace(kind), root, blob, now, now,
      now + MVSPACE_RECORD_SECONDS, pointer_token, pointer_error,
      sizeof(pointer_error));
  bool provider = time_ok && zcl_native_zcode_publish_record(
      "provider", mvspace_namespace(kind), NULL, blob, now, now,
      now + MVSPACE_RECORD_SECONDS, provider_token, provider_error,
      sizeof(provider_error));
  json_push_kv_str(&reply->data, "object_root", root);
  json_push_kv_str(&reply->data, "blob_root", blob);
  json_push_kv_str(&reply->data, "namespace", mvspace_namespace(kind));
  json_push_kv_bool(&reply->data, "transport_object_committed", true);
  json_push_kv_bool(&reply->data, "pointer_published", pointer);
  json_push_kv_bool(&reply->data, "provider_published", provider);
  if (!pointer || !provider) {
    mvspace_blocked_after_mutation(
        reply, "DISCOVERY_PUBLICATION_INCOMPLETE",
        pointer_error[0] ? pointer_error :
        (provider_error[0] ? provider_error :
         "signed DHT publication did not complete"),
        "metaverse.space.publish");
  }
}

void zcl_native_metaverse_space_discover_until(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    int64_t discovery_deadline, size_t maximum_wire_bytes)
{
  if (!request || !reply)
    return;
  const char *root = mvspace_str(request->input, "root");
  const char *kind_text = mvspace_str(request->input, "kind");
  enum metaverse_space_object_kind kind =
      !kind_text || strcmp(kind_text, "space_manifest") == 0
          ? METAVERSE_SPACE_OBJECT_MANIFEST
          : strcmp(kind_text, "service_descriptor") == 0
                ? METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR
                : METAVERSE_SPACE_OBJECT_NONE;
  uint8_t decoded[32];
  if (!mvspace_root(root, decoded) || kind == METAVERSE_SPACE_OBJECT_NONE) {
    mvspace_discovery_state(reply, "invalid", false, "validate", 0,
                            root, kind);
    mvspace_fail(reply, "BAD_DISCOVERY_ROOT",
                 "discover requires one exact root and an optional known kind",
                 "metaverse.space.discover");
    return;
  }
  const char *datadir = mvspace_datadir(request->input);
  static const enum vcs_zcode_sovereignty_action discover_action[] = {
      VCS_ZCODE_SOVEREIGNTY_DISCOVER};
  if (!mvspace_policy_actions(
          datadir, discover_action, 1, root, NULL, NULL,
          mvspace_service_type(kind), reply, "metaverse.space.discover")) {
    mvspace_discovery_state(reply, "blocked", true, "policy_discover", 0,
                            root, kind);
    return;
  }
  struct json_value selector, result;
  json_init(&selector);
  json_set_object(&selector);
  json_push_kv_str(&selector, "kind", "pointer");
  json_push_kv_str(&selector, "namespace", mvspace_namespace(kind));
  json_push_kv_str(&selector, "semantic_root", root);
  bool deadline_reached = false;
  bool discovered = discovery_deadline > 0
      ? zcl_native_zcode_records_discover_until(
            &selector, &result, discovery_deadline, &deadline_reached)
      : zcl_native_zcode_records_discover(&selector, &result);
  if (!discovered) {
    json_free(&result);
    json_free(&selector);
    json_push_kv_str(&reply->data, "failure_code",
                     deadline_reached ? "DISCOVERY_DEADLINE"
                                      : "DISCOVERY_UNAVAILABLE");
    mvspace_discovery_state(reply, "pending", true, "pointer_lookup", 1,
                            root, kind);
    return;
  }
  struct zcl_native_zcode_pointer_candidates candidates;
  (void)zcl_native_zcode_pointer_candidates_build(
      json_get(&result, "records"), &candidates);
  size_t candidate_count = candidates.count;
  json_free(&result);
  json_free(&selector);
  if (!candidate_count) {
    json_push_kv_str(&reply->data, "failure_code",
                     "NO_USABLE_SPACE_CANDIDATE");
    mvspace_discovery_state(reply, "not_found", true,
                            "pointer_selection", 1, root, kind);
    return;
  }
  bool live = false;
  struct vcs_package_store *store = NULL;
  if (!mvspace_store(datadir, &live, &store)) {
    mvspace_discovery_state(reply, "blocked", true, "package_store", 1,
                            root, kind);
    mvspace_blocked(reply, "NO_STORE", "package store failed to open",
                    "metaverse.space.discover");
    return;
  }
  char workspace[MVSPACE_PATH_MAX];
  const char *resolved = mvspace_workspace(request->input, workspace);
  size_t policy_denied = 0, tried = 0;
  size_t provider_records_seen = 0;
  bool scheduled = false, admitted = false, is_new = false;
  bool byte_limit_reached = false;
  char selected_blob[65] = {0}, selected_pointer_publisher[65] = {0};
  struct metaverse_space_object object;
  memset(&object, 0, sizeof(object));
  static const enum vcs_zcode_sovereignty_action fetch_actions[] = {
      VCS_ZCODE_SOVEREIGNTY_DISCOVER, VCS_ZCODE_SOVEREIGNTY_FETCH};
  for (size_t i = 0; i < candidate_count && tried < VCS_ZCODE_DHT_K; i++) {
    if (!mvspace_policy_actions(
            datadir, fetch_actions, 2, root,
            candidates.rows[i].transport_root,
            candidates.rows[i].publisher_zid, mvspace_service_type(kind),
            NULL, "metaverse.space.discover")) {
      policy_denied++;
      continue;
    }
    tried++;
    size_t inspected_wire_bytes = 0;
    struct zcl_result inspected = metaverse_space_blob_inspect_bounded(
        store, candidates.rows[i].transport_root, maximum_wire_bytes,
        &object, &inspected_wire_bytes);
    if (!inspected.ok &&
        strcmp(inspected.message, "space-blob-inspect-byte-limit") == 0) {
      byte_limit_reached = true;
      break;
    }
    if (!inspected.ok) {
      struct json_value route_input, route_result;
      json_init(&route_input);
      json_init(&route_result);
      json_set_object(&route_input);
      json_push_kv_str(&route_input, "kind", "provider");
      json_push_kv_str(&route_input, "namespace", mvspace_namespace(kind));
      json_push_kv_str(&route_input, "transport_root",
                       candidates.rows[i].transport_root);
      if (maximum_wire_bytes <= (size_t)INT64_MAX)
        json_push_kv_int(&route_input, "maximum_bytes",
                         (int64_t)maximum_wire_bytes);
      uint32_t provider_count = 0;
      bool routed = discovery_deadline > 0
          ? zcl_native_zcode_provider_discover_and_route_until(
                &route_input, &route_result, &provider_count,
                discovery_deadline, &deadline_reached)
          : zcl_native_zcode_provider_discover_and_route(
                &route_input, &route_result, &provider_count);
      const char *fetch_result =
          json_get_str(json_get(&route_result, "fetch_result"));
      bool route_byte_limit = fetch_result &&
          (strcmp(fetch_result, "byte-limit") == 0 ||
           strcmp(fetch_result, "bound-not-owned") == 0);
      provider_records_seen += provider_count;
      json_free(&route_result);
      json_free(&route_input);
      if (deadline_reached)
        break;
      if (route_byte_limit) {
        byte_limit_reached = true;
        break;
      }
      if (!routed)
        continue;
      scheduled = true;
      (void)snprintf(selected_blob, sizeof(selected_blob), "%s",
                     candidates.rows[i].transport_root);
      (void)snprintf(selected_pointer_publisher,
                     sizeof(selected_pointer_publisher), "%s",
                     candidates.rows[i].publisher_zid);
      /* A healthy local swarm usually commits the fetched blob quickly.
       * Spend only the caller-owned foreground budget trying to finish the
       * exact same candidate; otherwise preserve PENDING rather than calling
       * the scheduled fetch a vague success or failure. */
      do {
        inspected = metaverse_space_blob_inspect_bounded(
            store, candidates.rows[i].transport_root, maximum_wire_bytes,
            &object, &inspected_wire_bytes);
        if (inspected.ok)
          break;
        if (strcmp(inspected.message,
                   "space-blob-inspect-byte-limit") == 0) {
          byte_limit_reached = true;
          break;
        }
        if (discovery_deadline <= 0 ||
            platform_time_monotonic_ms() >= discovery_deadline) {
          deadline_reached = discovery_deadline > 0;
          break;
        }
        platform_sleep_ms(50);
      } while (true);
      if (!inspected.ok)
        break;
    }
    char derived[65], owner[65];
    zcl_hex_encode(object.root, 32, derived);
    if (strcmp(derived, root) != 0 || object.kind != kind)
      continue;
    const char *owner_ptr = NULL;
    if (kind == METAVERSE_SPACE_OBJECT_MANIFEST) {
      zcl_hex_encode(object.as.manifest.delegation.doc.master_pubkey, 32,
                     owner);
      owner_ptr = owner;
      uint64_t now = (uint64_t)platform_time_wall_unix();
      bool authorization_deadline = false;
      bool authorized = discovery_deadline > 0
          ? zcl_native_zcode_delegation_authorized_until(
                &object.as.manifest.delegation, discovery_deadline,
                NULL, 0, &authorization_deadline)
          : zcl_native_zcode_delegation_authorized(
                &object.as.manifest.delegation, NULL, 0);
      if (authorization_deadline) {
        deadline_reached = true;
        break;
      }
      if (vcs_space_manifest_validate_at(
              &object.as.manifest,
              object.as.manifest.delegation.network_genesis, now) !=
              VCS_SPACE_OK ||
          !authorized)
        continue;
    }
    if (!mvspace_admit_policy(
            datadir, root, candidates.rows[i].transport_root,
            candidates.rows[i].publisher_zid, owner_ptr,
            mvspace_service_type(kind))) {
      policy_denied++;
      continue;
    }
    enum metaverse_space_object_kind admitted_kind;
    struct zcl_result stored = resolved ? metaverse_space_admit_bounded(
        store, resolved, root, candidates.rows[i].transport_root,
        maximum_wire_bytes, &admitted_kind, &is_new)
        : ZCL_ERR(-1, "workspace-invalid");
    if (!stored.ok && strcmp(stored.message, "space-admit-byte-limit") == 0) {
      byte_limit_reached = true;
      break;
    }
    if (!stored.ok || admitted_kind != kind)
      continue;
    admitted = true;
    (void)snprintf(selected_blob, sizeof(selected_blob), "%s",
                   candidates.rows[i].transport_root);
    (void)snprintf(selected_pointer_publisher,
                   sizeof(selected_pointer_publisher), "%s",
                   candidates.rows[i].publisher_zid);
    break;
  }
  if (!live)
    vcs_package_store_close(store);
  json_push_kv_str(&reply->data, "object_root", root);
  json_push_kv_str(&reply->data, "namespace", mvspace_namespace(kind));
  json_push_kv_int(&reply->data, "pointer_candidates",
                   (int64_t)candidate_count);
  json_push_kv_int(&reply->data, "pointer_conflicts", candidates.conflicts);
  json_push_kv_int(&reply->data, "pointer_superseded",
                   candidates.superseded);
  json_push_kv_int(&reply->data, "policy_denied", (int64_t)policy_denied);
  json_push_kv_int(&reply->data, "candidates_tried", (int64_t)tried);
  json_push_kv_int(&reply->data, "provider_records_seen",
                   (int64_t)provider_records_seen);
  json_push_kv_bool(&reply->data, "fetch_scheduled", scheduled);
  json_push_kv_bool(&reply->data, "admitted", admitted);
  json_push_kv_bool(&reply->data, "deadline_reached", deadline_reached);
  json_push_kv_bool(&reply->data, "byte_limit_reached", byte_limit_reached);
  if (selected_blob[0]) {
    json_push_kv_str(&reply->data, "blob_root", selected_blob);
    json_push_kv_str(&reply->data, "pointer_publisher_zid",
                     selected_pointer_publisher);
  }
  if (admitted) {
    json_push_kv_bool(&reply->data, "new", is_new);
    if (kind == METAVERSE_SPACE_OBJECT_MANIFEST) {
      push_manifest(&reply->data, &object.as.manifest);
      char owner[65];
      zcl_hex_encode(object.as.manifest.delegation.doc.master_pubkey, 32,
                     owner);
      json_push_kv_str(&reply->data, "space_owner_zid", owner);
      json_push_kv_bool(&reply->data, "owner_is_pointer_publisher",
                        strcmp(owner, selected_pointer_publisher) == 0);
    } else {
      push_service(&reply->data, &object.as.service);
    }
    mvspace_discovery_state(reply, "present", false, "complete", 4,
                            root, kind);
    return;
  }
  if (scheduled && !byte_limit_reached) {
    json_push_kv_str(&reply->data, "failure_code",
                     deadline_reached ? "FETCH_DEADLINE" : "FETCH_PENDING");
    mvspace_discovery_state(reply, "pending", true, "package_fetch", 2,
                            root, kind);
    return;
  }
  json_push_kv_str(&reply->data, "failure_code",
                   byte_limit_reached ? "FETCH_BYTE_LIMIT"
                                      : deadline_reached
                                            ? "PROVIDER_ROUTE_DEADLINE"
                                            : "PROVIDER_ROUTE_UNAVAILABLE");
  mvspace_discovery_state(reply, "blocked", !byte_limit_reached,
                          byte_limit_reached ? "fetch_verify"
                                             : "provider_route",
                          byte_limit_reached ? 2 : 1, root, kind);
  if (!scheduled)
    mvspace_blocked(reply,
                    deadline_reached ? "DISCOVERY_DEADLINE" :
                    byte_limit_reached ? "DISCOVERY_BYTE_LIMIT"
                                     : "NO_USABLE_SPACE_CANDIDATE",
                    deadline_reached
                    ? "the caller-owned discovery deadline expired"
                    : byte_limit_reached
                    ? "the exact object exceeds the caller-owned byte limit"
                    :
                    candidate_count ?
                    "all pointer candidates were denied, invalid, or lacked "
                    "an authenticated restricted provider" :
                    "no usable signed pointer evidence was discovered",
                    "metaverse.space.discover");
}

void zcl_native_handle_metaverse_space_discover(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
  int64_t now = platform_time_monotonic_ms();
  int64_t deadline = now > 0 && now <= INT64_MAX -
                                      MVSPACE_DISCOVERY_FOREGROUND_MS
                         ? now + MVSPACE_DISCOVERY_FOREGROUND_MS : 0;
  zcl_native_metaverse_space_discover_until(request, reply, deadline,
                                             SIZE_MAX);
}
