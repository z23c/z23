/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact, stale-plan-safe local sovereignty policy commands. */

#include "command/native_command.h"
#include "command/native_zcode_policy.h"

#include "base/hex.h"
#include "config/boot_zcode_dht.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_sovereignty_policy.h"
#include "json/json.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

enum policy_operation { POLICY_ADD = 1, POLICY_REMOVE, POLICY_ADVISORY };

struct policy_mutation {
  enum policy_operation operation;
  struct vcs_zcode_sovereignty_rule rule;
  uint8_t rule_id[32];
  bool enabled;
};

static const char *zp_str(const struct json_value *in, const char *key) {
  const struct json_value *v = in ? json_get(in, key) : NULL;
  return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void zp_fail(struct zcl_command_reply *reply, const char *code,
                    const char *message) {
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                         false, message, "zcode.network.policy");
}

static bool zp_genesis_rpc(uint8_t out[32]) {
  struct rpc_arg_builder params;
  rpc_arg_builder_init(&params);
  rpc_arg_builder_push_int(&params, 0);
  char *json_params = rpc_arg_builder_to_json(&params);
  zcl_native_bridge_ensure_rpc();
  char *raw = node_rpc_call("getblockhash", json_params);
  free(json_params);
  if (!raw)
    return false;
  struct json_value doc;
  bool ok = json_read(&doc, raw, strlen(raw)) && doc.type == JSON_STR;
  const char *hex = ok ? json_get_str(&doc) : NULL;
  uint8_t display_bytes[32];
  ok = ok && hex && strlen(hex) == 64 &&
       zcl_hex_decode_lower(hex, display_bytes, 32);
  if (ok) {
    struct uint256 genesis;
    uint256_set_hex(&genesis, hex);
    memcpy(out, genesis.data, 32);
  }
  json_free(&doc);
  free(raw);
  return ok;
}

static bool zp_genesis(const char *datadir, uint8_t out[32]) {
  if (boot_zcode_dht_network_genesis(out))
    return true;
  struct vcs_zcode_dht_delegation delegation;
  char error[192] = {0};
  if (datadir && vcs_zcode_dht_delegation_load(
                     datadir, &delegation, error, sizeof(error)) &&
      vcs_zcode_dht_delegation_verify(
          &delegation, NULL, NULL, 0, NULL,
          (uint64_t)platform_time_wall_unix()) ==
          VCS_ZCODE_DHT_DELEGATION_OK) {
    memcpy(out, delegation.network_genesis, 32);
    return true;
  }
  return zp_genesis_rpc(out);
}

static bool zp_error_writable(char *error_out, size_t error_capacity) {
  return error_out && error_capacity;
}

static bool zp_allows_inputs_ready(
    const char *datadir, const struct vcs_zcode_sovereignty_subject *subject,
    uint8_t genesis[32]) {
  bool have_genesis = zp_genesis(datadir, genesis);
  return datadir && subject && have_genesis;
}

bool zcl_native_zcode_policy_allows(
    const char *datadir, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject,
    char *error_out, size_t error_capacity) {
  if (zp_error_writable(error_out, error_capacity))
    error_out[0] = '\0';
  uint8_t genesis[32];
  if (!zp_allows_inputs_ready(datadir, subject, genesis)) {
    if (zp_error_writable(error_out, error_capacity))
      (void)snprintf(error_out, error_capacity,
                     "cannot bind local policy to the running network");
    return false;
  }
  struct vcs_zcode_sovereignty_policy *policy =
      vcs_zcode_sovereignty_policy_create(genesis);
  char load_error[192] = {0};
  if (!policy || vcs_zcode_sovereignty_policy_load(
                     policy, datadir, load_error, sizeof(load_error)) !=
                     VCS_ZCODE_SOVEREIGNTY_OK) {
    vcs_zcode_sovereignty_policy_free(policy);
    if (zp_error_writable(error_out, error_capacity))
      (void)snprintf(error_out, error_capacity, "%s",
                     load_error[0] ? load_error : "local policy allocation failed");
    return false;
  }
  struct vcs_zcode_sovereignty_decision decision =
      vcs_zcode_sovereignty_policy_check(policy, action, subject);
  vcs_zcode_sovereignty_policy_free(policy);
  if (!decision.allow && zp_error_writable(error_out, error_capacity))
    (void)snprintf(error_out, error_capacity,
                   "local sovereignty policy denied %s",
                   vcs_zcode_sovereignty_action_string(action));
  return decision.allow;
}

static bool zp_enum(const char *text, const char *const *names, size_t count,
                    int *out) {
  for (size_t i = 0; text && i < count; i++)
    if (strcmp(text, names[i]) == 0) {
      *out = (int)i + 1;
      return true;
    }
  return false;
}

static bool zp_hex32(const char *text, uint8_t out[32]) {
  return text && strlen(text) == 64 &&
         zcl_hex_decode_lower(text, out, 32);
}

static bool zp_mutation_rule_value(int scope, const char *text,
                                   uint8_t rule_value[32]) {
  if (!text)
    return false;
  if (scope <= VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID)
    return zp_hex32(text, rule_value);
  size_t n = strlen(text);
  if (!n || n > 31)
    return false;
  memcpy(rule_value, text, n);
  return true;
}

static bool zp_mutation_add(const struct json_value *in,
                            struct policy_mutation *out) {
  static const char *const sources[] = {"local", "advisory"};
  static const char *const effects[] = {"allow", "block"};
  static const char *const scopes[] = {"full_root", "package",
                                       "publisher_zid", "service_type",
                                       "classification"};
  int source = 0, effect = 0, scope = 0;
  const struct json_value *mask = json_get(in, "action_mask");
  int64_t action_mask = mask && mask->type == JSON_INT ? json_get_int(mask) : 0;
  uint8_t rule_value[32] = {0};
  return zp_enum(zp_str(in, "source"), sources, 2, &source) &&
         zp_enum(zp_str(in, "effect"), effects, 2, &effect) &&
         zp_enum(zp_str(in, "scope"), scopes, 5, &scope) &&
         action_mask >= 1 && action_mask <= 127 &&
         zp_mutation_rule_value(scope, zp_str(in, "value"), rule_value) &&
         vcs_zcode_sovereignty_rule_build(
             &out->rule, source, effect, scope, (uint8_t)action_mask,
             rule_value) == VCS_ZCODE_SOVEREIGNTY_OK;
}

static bool zp_mutation(const struct json_value *in,
                        struct policy_mutation *out) {
  static const char *const operations[] = {"add", "remove", "advisory"};
  memset(out, 0, sizeof(*out));
  int value = 0;
  if (!zp_enum(zp_str(in, "operation"), operations, 3, &value))
    return false;
  out->operation = (enum policy_operation)value;
  if (out->operation == POLICY_REMOVE)
    return zp_hex32(zp_str(in, "rule_id"), out->rule_id);
  if (out->operation == POLICY_ADVISORY) {
    const struct json_value *enabled = json_get(in, "enabled");
    if (!enabled || enabled->type != JSON_BOOL)
      return false;
    out->enabled = json_get_bool(enabled);
    return true;
  }
  return zp_mutation_add(in, out);
}

static bool zp_mutate_request_valid(const char *mode,
                                    const struct json_value *in,
                                    struct policy_mutation *out) {
  bool mode_ok = mode && (strcmp(mode, "plan") == 0 ||
                          strcmp(mode, "commit") == 0);
  return mode_ok && zp_mutation(in, out);
}

static void zp_token(const uint8_t genesis[32], const uint8_t digest[32],
                     const struct policy_mutation *mutation,
                     uint8_t out[32]) {
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)"zcl.sovereignty.plan.v1", 24);
  sha3_256_write(&sha, genesis, 32);
  sha3_256_write(&sha, digest, 32);
  uint8_t op = (uint8_t)mutation->operation;
  sha3_256_write(&sha, &op, 1);
  if (mutation->operation == POLICY_ADD) {
    sha3_256_write(&sha, mutation->rule.id, 32);
  } else if (mutation->operation == POLICY_REMOVE) {
    sha3_256_write(&sha, mutation->rule_id, 32);
  } else {
    uint8_t enabled = mutation->enabled ? 1 : 0;
    sha3_256_write(&sha, &enabled, 1);
  }
  sha3_256_finalize(&sha, out);
}

static struct vcs_zcode_sovereignty_policy *zp_load(
    const struct json_value *in, struct zcl_command_reply *reply,
    uint8_t genesis[32], const char **datadir_out) {
  const char *datadir = zp_str(in, "datadir");
  if (!datadir || !datadir[0])
    datadir = zcl_native_command_datadir();
  if (!datadir || !zp_genesis(datadir, genesis)) {
    zp_fail(reply, "NODE_UNAVAILABLE", "cannot resolve datadir/network genesis");
    return NULL;
  }
  struct vcs_zcode_sovereignty_policy *policy =
      vcs_zcode_sovereignty_policy_create(genesis);
  char error[192] = {0};
  if (!policy || vcs_zcode_sovereignty_policy_load(
                     policy, datadir, error, sizeof(error)) !=
                     VCS_ZCODE_SOVEREIGNTY_OK) {
    vcs_zcode_sovereignty_policy_free(policy);
    zp_fail(reply, "POLICY_UNREADABLE", error[0] ? error : "policy allocation failed");
    return NULL;
  }
  *datadir_out = datadir;
  return policy;
}

void zcl_native_handle_zcode_network_policy_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  uint8_t genesis[32], digest[32];
  const char *datadir = NULL;
  struct vcs_zcode_sovereignty_policy *policy =
      zp_load(request->input, reply, genesis, &datadir);
  (void)datadir;
  if (!policy)
    return;
  vcs_zcode_sovereignty_policy_digest(policy, digest);
  char hex[65];
  zcl_hex_encode(digest, 32, hex);
  json_push_kv_int(&reply->data, "rule_count",
                   (int64_t)vcs_zcode_sovereignty_policy_count(policy));
  json_push_kv_bool(&reply->data, "advisory_enabled",
                    vcs_zcode_sovereignty_policy_advisory(policy));
  json_push_kv_str(&reply->data, "policy_digest", hex);
  json_push_kv_bool(&reply->data, "private_rules_redacted", true);
  vcs_zcode_sovereignty_policy_free(policy);
}

static uint8_t zp_token_difference(const uint8_t supplied[32],
                                   const uint8_t token[32]) {
  uint8_t difference = 0;
  for (size_t i = 0; i < 32; i++)
    difference |= supplied[i] ^ token[i];
  return difference;
}

static enum vcs_zcode_sovereignty_result zp_commit_apply(
    struct vcs_zcode_sovereignty_policy *policy,
    struct policy_mutation *mutation, uint8_t difference) {
  enum vcs_zcode_sovereignty_result changed = VCS_ZCODE_SOVEREIGNTY_INVALID;
  if (!difference && mutation->operation == POLICY_ADD)
    changed = vcs_zcode_sovereignty_policy_add(policy, &mutation->rule);
  else if (!difference && mutation->operation == POLICY_REMOVE)
    changed = vcs_zcode_sovereignty_policy_remove(policy, mutation->rule_id);
  else if (!difference) {
    vcs_zcode_sovereignty_policy_set_advisory(policy, mutation->enabled);
    changed = VCS_ZCODE_SOVEREIGNTY_OK;
  }
  return changed;
}

static bool zp_commit_persisted(struct vcs_zcode_sovereignty_policy *policy,
                                const char *datadir, uint8_t difference,
                                enum vcs_zcode_sovereignty_result changed,
                                char *error, size_t error_size) {
  return !difference && changed == VCS_ZCODE_SOVEREIGNTY_OK &&
         vcs_zcode_sovereignty_policy_save(policy, datadir, error,
                                           error_size) ==
             VCS_ZCODE_SOVEREIGNTY_OK;
}

static void zp_reply_plan(struct zcl_command_reply *reply, const char *mode,
                          const uint8_t token[32],
                          const struct policy_mutation *mutation) {
  char token_hex[65], rule_hex[65] = {0};
  zcl_hex_encode(token, 32, token_hex);
  const uint8_t *rule_id = mutation->operation == POLICY_ADD
                               ? mutation->rule.id : mutation->rule_id;
  if (mutation->operation != POLICY_ADVISORY)
    zcl_hex_encode(rule_id, 32, rule_hex);
  json_push_kv_str(&reply->data, "mode", mode);
  json_push_kv_bool(&reply->data, "committed", strcmp(mode, "commit") == 0);
  json_push_kv_str(&reply->data, "plan_token", token_hex);
  if (rule_hex[0])
    json_push_kv_str(&reply->data, "rule_id", rule_hex);
  json_push_kv_bool(&reply->data, "private_rules_redacted", true);
  json_push_kv_bool(&reply->data, "effective_after_dht_restart", true);
}

void zcl_native_handle_zcode_network_policy_mutate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  const char *mode = zp_str(request->input, "mode");
  struct policy_mutation mutation;
  if (!zp_mutate_request_valid(mode, request->input, &mutation)) {
    zp_fail(reply, "INVALID_MUTATION", "exact mode and policy mutation fields required");
    return;
  }
  uint8_t genesis[32], digest[32], token[32];
  const char *datadir = NULL;
  struct vcs_zcode_sovereignty_policy *policy =
      zp_load(request->input, reply, genesis, &datadir);
  if (!policy)
    return;
  vcs_zcode_sovereignty_policy_digest(policy, digest);
  zp_token(genesis, digest, &mutation, token);
  if (strcmp(mode, "commit") == 0) {
    uint8_t supplied[32];
    if (!zp_hex32(zp_str(request->input, "plan_token"), supplied)) {
      vcs_zcode_sovereignty_policy_free(policy);
      zp_fail(reply, "INVALID_PLAN_TOKEN", "commit requires canonical plan_token");
      return;
    }
    uint8_t difference = zp_token_difference(supplied, token);
    enum vcs_zcode_sovereignty_result changed =
        zp_commit_apply(policy, &mutation, difference);
    char error[192] = {0};
    if (!zp_commit_persisted(policy, datadir, difference, changed, error,
                             sizeof(error))) {
      vcs_zcode_sovereignty_policy_free(policy);
      zp_fail(reply, difference ? "STALE_PLAN" : "POLICY_REFUSED",
              error[0] ? error : vcs_zcode_sovereignty_result_string(changed));
      return;
    }
  }
  zp_reply_plan(reply, mode, token, &mutation);
  vcs_zcode_sovereignty_policy_free(policy);
}
