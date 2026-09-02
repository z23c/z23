/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generic native composition over the existing ZCODE DHT records. */

#include "command/native_zcode_discovery.h"

#include "command/native_command.h"
#include "base/hex.h"
#include "controllers/rpc_client.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static zcl_native_zcode_discovery_test_fn g_test_discover;
static zcl_native_zcode_discovery_test_fn g_test_route;
#endif

static bool discovery_root(const char *hex);

static bool zcode_read_rpc(const char *method, const char *operation,
                           struct json_value *input,
                           struct json_value *result)
{
  json_init(result);
  if (!input || input->type != JSON_OBJ)
    return false;
  if (operation && !json_get(input, "operation"))
    json_push_kv_str(input, "operation", operation);
  struct json_value params;
  json_init(&params);
  json_set_array(&params);
  json_push_back(&params, input);
  size_t needed = json_write(&params, NULL, 0);
  char *wire = zcl_malloc(needed + 1u, "zcode.discovery.rpc");
  if (!wire || json_write(&params, wire, needed + 1u) != needed) {
    free(wire);
    json_free(&params);
    return false;
  }
  zcl_native_bridge_ensure_rpc();
  char *raw = node_rpc_call(method, wire);
  free(wire);
  json_free(&params);
  if (!raw)
    return false;
  bool ok = json_read(result, raw, strlen(raw)) &&
            result->type == JSON_OBJ &&
            json_get_bool_or(result, "ok", false);
  free(raw);
  return ok;
}

bool zcl_native_zcode_dht_status_read(struct json_value *result)
{
  if (!result)
    return false;
  struct json_value input;
  json_init(&input);
  json_set_object(&input);
  bool ok = zcode_read_rpc("zcode_dht_status", NULL, &input, result);
  json_free(&input);
  return ok;
}

bool zcl_native_zcode_swarm_status_read(struct json_value *result)
{
  return result &&
         zcl_native_presentation_dumpstate("zcode_swarm", NULL, result);
}

bool zcl_native_zcode_records_local(
    struct json_value *selector, struct json_value *result)
{
  if (!selector || !result)
    return false;
#ifdef ZCL_TESTING
  if (g_test_discover)
    return g_test_discover(selector, result);
#endif
  bool board = json_get_bool_or(selector, "board", false);
  return zcode_read_rpc(board ? "zcode_dht_record_board"
                              : "zcode_dht_status",
                        board ? NULL : "records", selector, result);
}

bool zcl_native_zcode_publication_snapshot_read(
    const char *namespace_name, const char *package_root,
    const char *transport_root, struct json_value *result)
{
  if (!namespace_name || !namespace_name[0] ||
      !discovery_root(package_root) || !discovery_root(transport_root) ||
      !result)
    return false;
  struct json_value input;
  json_init(&input);
  json_set_object(&input);
  json_push_kv_str(&input, "namespace", namespace_name);
  json_push_kv_str(&input, "semantic_root", package_root);
  json_push_kv_str(&input, "transport_root", transport_root);
  bool ok = zcode_read_rpc(
      "zcode_dht_status", "publication_snapshot", &input, result);
  json_free(&input);
  return ok;
}

bool zcl_native_zcode_package_status_read(
    const char *package_root, const char *transport_root,
    struct json_value *result)
{
  if (!discovery_root(package_root) || !discovery_root(transport_root) ||
      !result)
    return false;
  struct json_value input;
  json_init(&input);
  json_set_object(&input);
  json_push_kv_str(&input, "package_root", package_root);
  json_push_kv_str(&input, "transport_root", transport_root);
  bool ok = zcode_read_rpc("zcode_package_status", NULL, &input, result);
  json_free(&input);
  return ok;
}

static bool discovery_root(const char *hex)
{
  uint8_t decoded[32];
  return hex && strlen(hex) == 64u &&
         zcl_hex_decode_lower(hex, decoded, sizeof(decoded));
}

static int pointer_candidate_compare(const void *left, const void *right)
{
  const struct zcl_native_zcode_pointer_candidate *a = left, *b = right;
  if (a->provider_authenticated != b->provider_authenticated)
    return a->provider_authenticated ? -1 : 1;
  int compared = strcmp(a->transport_root, b->transport_root);
  if (compared != 0)
    return compared;
  compared = strcmp(a->publisher_zid, b->publisher_zid);
  return compared != 0 ? compared
                       : strcmp(a->provider_node_id, b->provider_node_id);
}

bool zcl_native_zcode_pointer_candidates_build(
    const struct json_value *records,
    struct zcl_native_zcode_pointer_candidates *out)
{
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));
  size_t count = records && records->type == JSON_ARR
                     ? json_size(records) : 0;
  for (size_t i = 0; i < count; i++) {
    const struct json_value *row = json_at(records, i);
    bool conflicted = json_get_bool_or(row, "conflicted", false);
    bool superseded = json_get_bool_or(row, "superseded", false);
    out->records_seen++;
    out->conflicts += conflicted;
    out->superseded += superseded;
    if (conflicted || superseded ||
        out->count == VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
      continue;
    const char *transport = json_get_str(json_get(row, "transport_root"));
    const char *publisher = json_get_str(json_get(row, "publisher_zid"));
    const char *provider = json_get_str(json_get(row, "provider_node_id"));
    if (!discovery_root(transport) || !discovery_root(publisher) ||
        !discovery_root(provider))
      continue;
    struct zcl_native_zcode_pointer_candidate *candidate =
        &out->rows[out->count++];
    memcpy(candidate->transport_root, transport, 65);
    memcpy(candidate->publisher_zid, publisher, 65);
    memcpy(candidate->provider_node_id, provider, 65);
    candidate->provider_authenticated =
        json_get_bool_or(row, "provider_authenticated", false);
    candidate->source_index = (uint32_t)i;
  }
  qsort(out->rows, out->count, sizeof(out->rows[0]),
        pointer_candidate_compare);
  struct zcl_native_zcode_pointer_candidate
      diverse[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
  bool selected[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS] = {false};
  size_t used = 0;
  for (size_t i = 0; i < out->count; i++) {
    bool seen = false;
    for (size_t j = 0; j < used; j++)
      seen |= strcmp(diverse[j].transport_root,
                     out->rows[i].transport_root) == 0;
    if (!seen) {
      diverse[used++] = out->rows[i];
      selected[i] = true;
    }
  }
  for (size_t i = 0; i < out->count; i++)
    if (!selected[i])
      diverse[used++] = out->rows[i];
  memcpy(out->rows, diverse, out->count * sizeof(out->rows[0]));
  return out->count != 0;
}

bool zcl_native_zcode_publish_record(
    const char *kind, const char *namespace_name,
    const char *semantic_root, const char *transport_root,
    int64_t sequence, int64_t not_before, int64_t expiry,
    char token_out[65], char *error_out, size_t error_capacity)
{
  if (error_out && error_capacity)
    error_out[0] = '\0';
  if (token_out)
    token_out[0] = '\0';
  if (!kind || !namespace_name || !transport_root || !token_out ||
      sequence < 1 || not_before < 1 || expiry <= not_before)
    return false;
  struct json_value input, result;
  json_init(&input);
  json_set_object(&input);
  json_push_kv_str(&input, "mode", "plan");
  json_push_kv_str(&input, "kind", kind);
  json_push_kv_str(&input, "namespace", namespace_name);
  if (semantic_root)
    json_push_kv_str(&input, "semantic_root", semantic_root);
  json_push_kv_str(&input, "transport_root", transport_root);
  json_push_kv_int(&input, "sequence", sequence);
  json_push_kv_int(&input, "not_before", not_before);
  json_push_kv_int(&input, "expiry", expiry);
  if (!zcode_read_rpc("zcode_dht_status", "publish", &input, &result)) {
    const char *code = json_get_str(json_get(&result, "code"));
    if (error_out && error_capacity)
      (void)snprintf(error_out, error_capacity, "%s",
                     code ? code : "RPC_UNAVAILABLE");
    json_free(&result);
    json_free(&input);
    return false;
  }
  const char *token = json_get_str(json_get(&result, "plan_token"));
  bool valid = token && strlen(token) == 64u;
  if (valid)
    memcpy(token_out, token, 65u);
  json_free(&result);
  if (!valid) {
    json_free(&input);
    return false;
  }
  json_set_str((struct json_value *)json_get(&input, "mode"), "commit");
  json_push_kv_str(&input, "plan_token", token_out);
  bool committed = zcode_read_rpc(
      "zcode_dht_status", "publish", &input, &result);
  if (!committed && error_out && error_capacity) {
    const char *code = json_get_str(json_get(&result, "code"));
    (void)snprintf(error_out, error_capacity, "%s",
                   code ? code : "RPC_UNAVAILABLE");
  }
  json_free(&result);
  json_free(&input);
  return committed;
}

bool zcl_native_zcode_records_discover(
    struct json_value *selector, struct json_value *result)
{
  if (!selector || !result)
    return false;
#ifdef ZCL_TESTING
  if (g_test_discover)
    return g_test_discover(selector, result);
#endif
  struct zcl_command_request request;
  memset(&request, 0, sizeof(request));
  request.input = selector;
  struct zcl_command_reply reply;
  zcl_command_reply_init(&reply, "zcl.zcode_network_records.v1");
  zcl_native_handle_zcode_network_records(&request, &reply);
  bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
  json_init(result);
  json_copy(result, &reply.data);
  zcl_command_reply_free(&reply);
  return ok;
}

#define RECORD_CANCEL_RESERVE_MS INT64_C(50)

static bool record_rpc_until(const char *method, struct json_value *input,
                             struct json_value *result,
                             int64_t deadline_mono_ms)
{
  json_init(result);
  if (!method || !input || input->type != JSON_OBJ)
    return false;
  int64_t remaining = deadline_mono_ms - platform_time_monotonic_ms();
  if (remaining <= 0)
    return false;
  struct json_value params;
  json_init(&params);
  json_set_array(&params);
  json_push_back(&params, input);
  size_t needed = json_write(&params, NULL, 0);
  char *wire = zcl_malloc(needed + 1u, "zcode.records.deadline.rpc");
  bool encoded = wire && json_write(&params, wire, needed + 1u) == needed;
  zcl_native_bridge_ensure_rpc();
  char *raw = encoded
      ? node_rpc_call_deadline(
            method, wire, remaining > LONG_MAX ? LONG_MAX : (long)remaining,
            remaining > LONG_MAX ? LONG_MAX : (long)remaining)
      : NULL;
  free(wire);
  json_free(&params);
  bool parsed = raw && json_read(result, raw, strlen(raw)) &&
                result->type == JSON_OBJ;
  free(raw);
  return parsed;
}

static void records_cancel_until(const char *lookup, const char *owner,
                                 int64_t deadline_mono_ms)
{
  struct json_value input, result;
  json_init(&input);
  json_set_object(&input);
  json_push_kv_str(&input, "lookup_id", lookup);
  json_push_kv_str(&input, "owner_token", owner);
  (void)record_rpc_until("zcode_dht_record_cancel", &input, &result,
                         deadline_mono_ms);
  json_free(&result);
  json_free(&input);
}

bool zcl_native_zcode_records_discover_until(
    struct json_value *selector, struct json_value *result,
    int64_t deadline_mono_ms, bool *deadline_reached_out)
{
  if (deadline_reached_out)
    *deadline_reached_out = false;
  if (!selector || !result || !deadline_reached_out ||
      deadline_mono_ms <= 0)
    return false;
#ifdef ZCL_TESTING
  if (g_test_discover)
    return g_test_discover(selector, result);
#endif
  json_init(result);
  int64_t cancel_at = deadline_mono_ms - RECORD_CANCEL_RESERVE_MS;
  if (cancel_at <= platform_time_monotonic_ms()) {
    *deadline_reached_out = true;
    return false;
  }
  struct json_value body;
  if (!record_rpc_until("zcode_dht_record_begin", selector, &body,
                        cancel_at) ||
      !json_get_bool_or(&body, "ok", false)) {
    json_free(&body);
    if (platform_time_monotonic_ms() >= cancel_at)
      *deadline_reached_out = true;
    return false;
  }
  const char *lookup_value = json_get_str(json_get(&body, "lookup_id"));
  const char *owner_value = json_get_str(json_get(&body, "owner_token"));
  char lookup[33], owner[33];
  bool admitted = lookup_value && owner_value &&
                  strlen(lookup_value) == 32u && strlen(owner_value) == 32u;
  if (admitted) {
    memcpy(lookup, lookup_value, sizeof(lookup));
    memcpy(owner, owner_value, sizeof(owner));
  }
  json_free(&body);
  if (!admitted)
    return false;

  for (;;) {
    int64_t now = platform_time_monotonic_ms();
    if (now >= cancel_at) {
      records_cancel_until(lookup, owner, deadline_mono_ms);
      *deadline_reached_out = true;
      return false;
    }
    struct json_value poll;
    json_init(&poll);
    json_set_object(&poll);
    json_push_kv_str(&poll, "lookup_id", lookup);
    json_push_kv_str(&poll, "owner_token", owner);
    bool called = record_rpc_until("zcode_dht_record_poll", &poll, &body,
                                   cancel_at);
    const char *state = called ? json_get_str(json_get(&body, "state")) : NULL;
    bool passed = called && json_get_bool_or(&body, "ok", false);
    bool pending = passed && state && strcmp(state, "pending") == 0;
    if (!pending) {
      if (passed)
        json_copy(result, &body);
      json_free(&body);
      json_free(&poll);
      /* Terminal either way: give the bounded lookup slot back. The node
       * retains a terminal result for a short window, so not cancelling
       * would make the next honest discovery fail for a reason that has
       * nothing to do with the network. */
      records_cancel_until(lookup, owner, deadline_mono_ms);
      if (!passed && platform_time_monotonic_ms() >= cancel_at)
        *deadline_reached_out = true;
      return passed;
    }
    json_free(&body);
    json_free(&poll);
    now = platform_time_monotonic_ms();
    if (now >= cancel_at)
      continue;
    int64_t remaining = cancel_at - now;
    platform_sleep_ms((unsigned)(remaining < 50 ? remaining : 50));
  }
}

static bool provider_route_budget(struct json_value *selector,
                                  struct json_value *result,
                                  long total_ms)
{
  if (!selector || !result)
    return false;
  json_init(result);
  struct json_value params;
  json_init(&params);
  json_set_array(&params);
  json_push_back(&params, selector);
  size_t needed = json_write(&params, NULL, 0);
  char *wire = zcl_malloc(needed + 1u, "zcode.provider.route.rpc");
  bool encoded = wire && json_write(&params, wire, needed + 1u) == needed;
  zcl_native_bridge_ensure_rpc();
  char *raw = encoded
      ? (total_ms > 0
             ? node_rpc_call_deadline("zcode_dht_provider_route", wire,
                                      total_ms, total_ms)
             : node_rpc_call("zcode_dht_provider_route", wire))
      : NULL;
  free(wire);
  json_free(&params);
  bool routed = raw && json_read(result, raw, strlen(raw)) &&
                result->type == JSON_OBJ &&
                json_get_bool_or(result, "ok", false);
  free(raw);
  return routed;
}

bool zcl_native_zcode_provider_route(
    struct json_value *selector, struct json_value *result)
{
  return provider_route_budget(selector, result, 0);
}

#ifdef ZCL_TESTING
void zcl_native_zcode_discovery_test_backend(
    zcl_native_zcode_discovery_test_fn discover,
    zcl_native_zcode_discovery_test_fn route)
{
  g_test_discover = discover;
  g_test_route = route;
}
#endif

bool zcl_native_zcode_provider_discover_and_route(
    struct json_value *selector, struct json_value *route_result,
    uint32_t *record_count_out)
{
  if (record_count_out)
    *record_count_out = 0;
  if (!selector || !route_result || !record_count_out)
    return false;
  struct json_value discovered;
  json_init(&discovered);
#ifdef ZCL_TESTING
  bool found = g_test_discover
      ? g_test_discover(selector, &discovered)
      : zcl_native_zcode_records_discover(selector, &discovered);
#else
  bool found = zcl_native_zcode_records_discover(selector, &discovered);
#endif
  int64_t count = found ? json_get_int(json_get(&discovered, "count")) : 0;
  json_free(&discovered);
  if (count <= 0 || count > UINT32_MAX)
    return false;
  *record_count_out = (uint32_t)count;
#ifdef ZCL_TESTING
  return g_test_route ? g_test_route(selector, route_result)
                      : zcl_native_zcode_provider_route(selector,
                                                        route_result);
#else
  return zcl_native_zcode_provider_route(selector, route_result);
#endif
}

bool zcl_native_zcode_provider_discover_and_route_until(
    struct json_value *selector, struct json_value *route_result,
    uint32_t *record_count_out, int64_t deadline_mono_ms,
    bool *deadline_reached_out)
{
  if (record_count_out)
    *record_count_out = 0;
  if (deadline_reached_out)
    *deadline_reached_out = false;
  if (!selector || !route_result || !record_count_out ||
      !deadline_reached_out)
    return false;
#ifdef ZCL_TESTING
  if (g_test_discover) {
    struct json_value discovered;
    json_init(&discovered);
    bool found = g_test_discover(selector, &discovered);
    int64_t count = found
                        ? json_get_int(json_get(&discovered, "count")) : 0;
    json_free(&discovered);
    if (count <= 0 || count > UINT32_MAX)
      return false;
    *record_count_out = (uint32_t)count;
    return g_test_route && g_test_route(selector, route_result);
  }
#endif
  struct json_value discovered;
  json_init(&discovered);
  bool found = zcl_native_zcode_records_discover_until(
      selector, &discovered, deadline_mono_ms, deadline_reached_out);
  int64_t count = found ? json_get_int(json_get(&discovered, "count")) : 0;
  json_free(&discovered);
  if (count <= 0 || count > UINT32_MAX || *deadline_reached_out)
    return false;
  *record_count_out = (uint32_t)count;
  if (platform_time_monotonic_ms() >= deadline_mono_ms) {
    *deadline_reached_out = true;
    return false;
  }
  int64_t remaining = deadline_mono_ms - platform_time_monotonic_ms();
  if (remaining <= 0) {
    *deadline_reached_out = true;
    return false;
  }
  bool routed = provider_route_budget(
      selector, route_result,
      remaining > LONG_MAX ? LONG_MAX : (long)remaining);
  if (platform_time_monotonic_ms() >= deadline_mono_ms) {
    *deadline_reached_out = true;
    return false;
  }
  return routed;
}

static bool delegation_authorized_budget(
    const struct vcs_zcode_dht_delegation *delegation,
    long total_ms, char *error_out, size_t error_capacity)
{
  if (error_out && error_capacity)
    error_out[0] = '\0';
  uint8_t delegation_wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  if (!delegation ||
      vcs_zcode_dht_delegation_encode(delegation, delegation_wire) !=
          VCS_ZCODE_DHT_DELEGATION_OK)
    return false;
  char hex[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES * 2u + 1u];
  zcl_hex_encode(delegation_wire, sizeof(delegation_wire), hex);
  struct json_value input, params, result;
  json_init(&input);
  json_init(&params);
  json_init(&result);
  json_set_object(&input);
  json_push_kv_str(&input, "delegation_wire", hex);
  json_set_array(&params);
  json_push_back(&params, &input);
  size_t needed = json_write(&params, NULL, 0);
  char *wire = zcl_malloc(needed + 1u, "zcode.delegation.check.rpc");
  bool encoded = wire && json_write(&params, wire, needed + 1u) == needed;
  zcl_native_bridge_ensure_rpc();
  char *raw = encoded
      ? (total_ms > 0
             ? node_rpc_call_deadline("zcode_dht_delegation_check", wire,
                                      total_ms, total_ms)
             : node_rpc_call("zcode_dht_delegation_check", wire))
      : NULL;
  free(wire);
  json_free(&params);
  json_free(&input);
  bool authorized = raw && json_read(&result, raw, strlen(raw)) &&
                    result.type == JSON_OBJ &&
                    json_get_bool_or(&result, "ok", false) &&
                    json_get_bool_or(&result, "chain_authorized", false);
  if (!authorized && error_out && error_capacity) {
    const char *code = json_get_str(json_get(&result, "code"));
    (void)snprintf(error_out, error_capacity, "%s",
                   code ? code : "RPC_UNAVAILABLE");
  }
  json_free(&result);
  free(raw);
  return authorized;
}

bool zcl_native_zcode_delegation_authorized(
    const struct vcs_zcode_dht_delegation *delegation,
    char *error_out, size_t error_capacity)
{
  return delegation_authorized_budget(delegation, 0, error_out,
                                      error_capacity);
}

bool zcl_native_zcode_delegation_authorized_until(
    const struct vcs_zcode_dht_delegation *delegation,
    int64_t deadline_mono_ms, char *error_out, size_t error_capacity,
    bool *deadline_reached_out)
{
  if (deadline_reached_out)
    *deadline_reached_out = false;
  if (!deadline_reached_out)
    return false;
  int64_t remaining = deadline_mono_ms - platform_time_monotonic_ms();
  if (remaining <= 0) {
    *deadline_reached_out = true;
    return false;
  }
  bool authorized = delegation_authorized_budget(
      delegation, remaining > LONG_MAX ? LONG_MAX : (long)remaining,
      error_out, error_capacity);
  if (platform_time_monotonic_ms() >= deadline_mono_ms) {
    *deadline_reached_out = true;
    return false;
  }
  return authorized;
}
