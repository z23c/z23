/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Capability-owned public lifecycle for iterative DHT records. */

#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_record_kind.h"

#include "base/hex.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

#define RECORD_PUBLIC_LOOKUPS_MAX 32u
#define RECORD_PUBLIC_TOKEN_BYTES 16u
#define RECORD_PUBLIC_ACTIVE_GRACE_S 5u
#define RECORD_PUBLIC_RESULT_RETENTION_S 30u
#define RECORD_PUBLIC_EVIDENCE_WIRES_MAX 16u

struct public_record_lookup {
  bool used, cached, include_evidence_wires;
  uint8_t lookup_token[RECORD_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[RECORD_PUBLIC_TOKEN_BYTES];
  uint64_t service_operation_id, service_generation, expires_mono;
  struct vcs_zcode_dht_record_discovery_result result;
};

static zcl_mutex_t g_record_public_lock;
static _Atomic int g_record_public_lock_state;
static struct public_record_lookup g_record_public[RECORD_PUBLIC_LOOKUPS_MAX];

static struct vcs_zcode_dht_time record_public_now(void) {
  return (struct vcs_zcode_dht_time){
      .wall_unix = (uint64_t)platform_time_wall_time_t(),
      .monotonic_s = (uint64_t)(platform_time_monotonic_ms() / 1000),
  };
}

static void record_public_lock(void) {
  if (atomic_load_explicit(&g_record_public_lock_state,
                           memory_order_acquire) != 2) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &g_record_public_lock_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      zcl_mutex_init(&g_record_public_lock);
      atomic_store_explicit(&g_record_public_lock_state, 2,
                            memory_order_release);
    } else {
      while (atomic_load_explicit(&g_record_public_lock_state,
                                  memory_order_acquire) != 2)
        ;
    }
  }
  zcl_mutex_lock(&g_record_public_lock);
}

static bool record_token_equal(
    const uint8_t a[RECORD_PUBLIC_TOKEN_BYTES],
    const uint8_t b[RECORD_PUBLIC_TOKEN_BYTES]) {
  uint8_t difference = 0;
  for (size_t i = 0; i < RECORD_PUBLIC_TOKEN_BYTES; i++)
    difference |= a[i] ^ b[i];
  return difference == 0;
}

static struct public_record_lookup *record_public_find_locked(
    const uint8_t lookup_token[RECORD_PUBLIC_TOKEN_BYTES],
    const uint8_t owner_token[RECORD_PUBLIC_TOKEN_BYTES]) {
  for (size_t i = 0; i < RECORD_PUBLIC_LOOKUPS_MAX; i++)
    if (g_record_public[i].used &&
        record_token_equal(g_record_public[i].lookup_token, lookup_token) &&
        record_token_equal(g_record_public[i].owner_token, owner_token))
      return &g_record_public[i];
  return NULL;
}

static void record_public_cleanup_locked(uint64_t monotonic_s) {
  for (size_t i = 0; i < RECORD_PUBLIC_LOOKUPS_MAX; i++) {
    struct public_record_lookup *entry = &g_record_public[i];
    if (!entry->used || monotonic_s < entry->expires_mono)
      continue;
    if (!entry->cached)
      (void)boot_zcode_dht_record_discovery_cancel(
          entry->service_operation_id, entry->service_generation);
    memset(entry, 0, sizeof(*entry));
  }
}

void boot_zcode_dht_record_public_tick(uint64_t monotonic_s) {
  record_public_lock();
  record_public_cleanup_locked(monotonic_s);
  zcl_mutex_unlock(&g_record_public_lock);
}

void boot_zcode_dht_record_public_reset(void) {
  record_public_lock();
  /* Mirror the expiry path and replication's reset: free every
   * in-flight discovery before the wipe. The only caller today is
   * shutdown, but a live-service caller would otherwise orphan slots
   * with no tick left to reap them. */
  for (size_t i = 0; i < RECORD_PUBLIC_LOOKUPS_MAX; i++) {
    if (!g_record_public[i].used || g_record_public[i].cached)
      continue;
    (void)boot_zcode_dht_record_discovery_cancel(
        g_record_public[i].service_operation_id,
        g_record_public[i].service_generation);
  }
  memset(g_record_public, 0, sizeof(g_record_public));
  zcl_mutex_unlock(&g_record_public_lock);
}

static const struct json_value *record_rpc_input(
    const struct json_value *params) {
  const struct json_value *first =
      params && json_size(params) ? json_at(params, 0) : NULL;
  return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *record_input_str(const struct json_value *in,
                                    const char *key) {
  const struct json_value *value = in ? json_get(in, key) : NULL;
  return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool record_input_root(const struct json_value *in, const char *key,
                              uint8_t out[32]) {
  const char *hex = record_input_str(in, key);
  memset(out, 0, 32);
  return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static bool record_input_namespace(const struct json_value *in, char out[32]) {
  const char *name = record_input_str(in, "namespace");
  size_t length = name ? strlen(name) : 0;
  memset(out, 0, 32);
  if (!length || length > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
    return false;
  for (size_t i = 0; i < length; i++)
    if (!((name[i] >= 'a' && name[i] <= 'z') ||
          (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
          name[i] == '-' || name[i] == '_'))
      return false;
  memcpy(out, name, length);
  return true;
}

static enum vcs_zcode_dht_record_kind record_input_kind(
    const struct json_value *in) {
  return boot_zcode_dht_record_kind_from_name(record_input_str(in, "kind"));
}

static bool record_parse_selector(
    const struct json_value *in,
    struct vcs_zcode_dht_record_selector *selector) {
  memset(selector, 0, sizeof(*selector));
  selector->kind = record_input_kind(in);
  if (!selector->kind ||
      !record_input_namespace(in, selector->namespace_name))
    return false;
  const char *root_key = selector->kind == VCS_ZCODE_DHT_RECORD_POINTER
                             ? "semantic_root"
                             : "transport_root";
  return record_input_root(in, root_key, selector->root);
}

static bool record_parse_capability(
    const struct json_value *in,
    uint8_t lookup_token[RECORD_PUBLIC_TOKEN_BYTES],
    uint8_t owner_token[RECORD_PUBLIC_TOKEN_BYTES]) {
  const char *lookup = record_input_str(in, "lookup_id");
  const char *owner = record_input_str(in, "owner_token");
  return lookup && owner &&
         strlen(lookup) == RECORD_PUBLIC_TOKEN_BYTES * 2 &&
         strlen(owner) == RECORD_PUBLIC_TOKEN_BYTES * 2 &&
         zcl_hex_decode_lower(lookup, lookup_token,
                              RECORD_PUBLIC_TOKEN_BYTES) &&
         zcl_hex_decode_lower(owner, owner_token, RECORD_PUBLIC_TOKEN_BYTES);
}

static void record_rpc_error(struct json_value *result, const char *code,
                             const char *message) {
  json_set_object(result);
  json_push_kv_bool(result, "ok", false);
  json_push_kv_str(result, "code", code);
  json_push_kv_str(result, "message", message);
}

static void record_row_json(struct json_value *row,
                            const struct vcs_zcode_dht_record *record,
                            bool conflicted, bool superseded,
                            bool provider_authenticated,
                            bool include_evidence_wire) {
  char semantic[65], transport[65], provider[65], owner[65], publisher[65];
  char record_root[65] = "";
  uint8_t record_id[32];
  if (vcs_zcode_dht_record_id(record, record_id) ==
      VCS_ZCODE_DHT_RECORD_OK)
    zcl_hex_encode(record_id, 32, record_root);
  zcl_hex_encode(record->semantic_root, 32, semantic);
  zcl_hex_encode(record->transport_root, 32, transport);
  zcl_hex_encode(record->provider_node_id, 32, provider);
  zcl_hex_encode(record->owner_group, 32, owner);
  zcl_hex_encode(record->delegation.doc.master_pubkey, 32, publisher);
  json_set_object(row);
  json_push_kv_str(
        row, "kind", boot_zcode_dht_record_kind_name(record->kind));
  json_push_kv_str(row, "record_root", record_root);
  json_push_kv_str(row, "namespace", record->namespace_name);
  json_push_kv_str(row, "semantic_root", semantic);
  json_push_kv_str(row, "transport_root", transport);
  json_push_kv_str(row, "provider_node_id", provider);
  json_push_kv_str(row, "publisher_zid", publisher);
  json_push_kv_str(row, "owner_group", owner);
  json_push_kv_int(row, "sequence", (int64_t)record->sequence);
  json_push_kv_int(row, "not_before", (int64_t)record->not_before);
  json_push_kv_int(row, "expiry", (int64_t)record->expiry);
  json_push_kv_bool(row, "possession_proof", false);
  json_push_kv_bool(row, "declared_diversity_only", true);
  json_push_kv_bool(row, "conflicted", conflicted);
  json_push_kv_bool(row, "superseded", superseded);
  json_push_kv_bool(row, "provider_authenticated",
                    provider_authenticated);
  if (include_evidence_wire) {
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
    char wire_hex[VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u + 1u];
    if (vcs_zcode_dht_record_encode(record, wire) ==
        VCS_ZCODE_DHT_RECORD_OK) {
      zcl_hex_encode(wire, sizeof(wire), wire_hex);
      json_push_kv_str(row, "record_wire", wire_hex);
    }
  }
}

static bool record_provider_authenticated(
    const struct vcs_zcode_dht_record *record,
    const struct vcs_zcode_dht_peer_view *peers, size_t peer_count) {
  for (size_t i = 0; i < peer_count; i++)
    if (peers[i].connected && peers[i].authenticated &&
        memcmp(peers[i].node_id, record->provider_node_id, 32) == 0)
      return true;
  return false;
}

static const char *record_state_name(
    enum vcs_zcode_dht_record_operation_state state) {
  if (state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE)
    return "complete";
  if (state == VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT)
    return "timeout";
  if (state == VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED)
    return "rejected";
  return "pending";
}

static void record_result_json(
    struct json_value *result,
    const struct vcs_zcode_dht_record_discovery_result *discovery,
    bool include_evidence_wires) {
  bool successful =
      discovery->state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING ||
      discovery->state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
  json_set_object(result);
  json_push_kv_bool(result, "ok", successful);
  json_push_kv_str(result, "state", record_state_name(discovery->state));
  json_push_kv_bool(result, "local_projection", false);
  json_push_kv_bool(result, "truncated", discovery->truncated);
  json_push_kv_bool(result, "incomplete", discovery->incomplete);
  json_push_kv_int(result, "routing_rounds", discovery->routing_rounds);
  json_push_kv_int(result, "xor_progress", discovery->xor_progress);
  json_push_kv_int(result, "nodes_queried", discovery->nodes_queried);
  if (!successful) {
    bool timeout =
        discovery->state == VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT;
    json_push_kv_str(result, "code",
                     timeout ? "LOOKUP_TIMEOUT" : "LOOKUP_REJECTED");
    json_push_kv_str(result, "message",
                     timeout ? "record discovery reached its bounded deadline"
                             : "record discovery was interrupted");
  }
  json_push_kv_int(result, "count", discovery->record_count);
  struct vcs_zcode_dht_peer_view peers[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
  size_t peer_count = 0;
  (void)boot_zcode_dht_peers((uint64_t)platform_time_wall_time_t(), peers,
                             VCS_ZCODE_DHT_SERVICE_MAX_PEERS, 0,
                             &peer_count);
  bool conflicted[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS] = {false};
  bool superseded[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS] = {false};
  uint32_t conflict_count = 0, superseded_count = 0, usable_count = 0;
  for (uint32_t i = 0; i < discovery->record_count; i++) {
    conflicted[i] = vcs_zcode_dht_record_conflicted_at(
        discovery->records, discovery->record_count, i);
    superseded[i] = !conflicted[i] && vcs_zcode_dht_record_superseded_at(
        discovery->records, discovery->record_count, i);
    conflict_count += conflicted[i];
    superseded_count += superseded[i];
    usable_count += !conflicted[i] && !superseded[i];
  }
  json_push_kv_int(result, "usable_count", usable_count);
  json_push_kv_int(result, "superseded_count", superseded_count);
  uint8_t evidence_providers[RECORD_PUBLIC_EVIDENCE_WIRES_MAX][32];
  uint8_t evidence_groups[RECORD_PUBLIC_EVIDENCE_WIRES_MAX][32];
  uint32_t evidence_wire_count = 0;
  struct json_value rows;
  json_init(&rows);
  json_set_array(&rows);
  for (uint32_t i = 0; i < discovery->record_count; i++) {
    bool include_wire = false;
    if (include_evidence_wires && !conflicted[i] && !superseded[i] &&
        (discovery->records[i].kind == VCS_ZCODE_DHT_RECORD_PROVIDER ||
         discovery->records[i].kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
         discovery->records[i].kind ==
             VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK) &&
        evidence_wire_count < RECORD_PUBLIC_EVIDENCE_WIRES_MAX) {
      include_wire = true;
      for (uint32_t j = 0; j < evidence_wire_count; j++)
        if (memcmp(discovery->records[i].provider_node_id,
                   evidence_providers[j], 32) == 0 ||
            ((discovery->records[i].kind ==
                  VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
              discovery->records[i].kind ==
                  VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK) &&
             memcmp(discovery->records[i].owner_group,
                    evidence_groups[j], 32) == 0)) {
          include_wire = false;
          break;
        }
      if (include_wire) {
        memcpy(evidence_providers[evidence_wire_count],
               discovery->records[i].provider_node_id, 32);
        memcpy(evidence_groups[evidence_wire_count],
               discovery->records[i].owner_group, 32);
        evidence_wire_count++;
      }
    }
    struct json_value row;
    json_init(&row);
    record_row_json(
        &row, &discovery->records[i], conflicted[i], superseded[i],
        record_provider_authenticated(&discovery->records[i], peers,
                                      peer_count), include_wire);
    json_push_back(&rows, &row);
    json_free(&row);
  }
  json_push_kv(result, "records", &rows);
  json_free(&rows);
  struct json_value conflicts;
  json_init(&conflicts);
  json_set_array(&conflicts);
  for (uint32_t i = 0; i < discovery->record_count; i++) {
    if (!conflicted[i])
      continue;
    struct json_value row;
    json_init(&row);
    record_row_json(
        &row, &discovery->records[i], true, false,
        record_provider_authenticated(&discovery->records[i], peers,
                                      peer_count), false);
    json_push_back(&conflicts, &row);
    json_free(&row);
  }
  json_push_kv_int(result, "conflict_count", conflict_count);
  json_push_kv_int(result, "evidence_wire_count", evidence_wire_count);
  json_push_kv(result, "conflicts", &conflicts);
  json_free(&conflicts);
}

#ifdef ZCL_TESTING
void boot_zcode_dht_record_test_render(
    struct json_value *result,
    const struct vcs_zcode_dht_record_discovery_result *discovery,
    bool include_evidence_wires) {
  record_result_json(result, discovery, include_evidence_wires);
}
#endif

static bool rpc_record_begin(const struct json_value *params, bool help,
                             struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_record_begin {kind,namespace,matching_root}");
    return true;
  }
  const struct json_value *in = record_rpc_input(params);
  struct vcs_zcode_dht_record_selector selector;
  if (!record_parse_selector(in, &selector)) {
    record_rpc_error(
        result, "INVALID_SELECTOR",
        "kind, canonical namespace and matching 64-hex root required");
    return true;
  }
  uint8_t tokens[RECORD_PUBLIC_TOKEN_BYTES * 2];
  if (!zcl_random_secret_bytes(tokens, sizeof(tokens),
                               "zcode_dht_public_record_lookup")) {
    record_rpc_error(result, "LOOKUP_ID_UNAVAILABLE",
                     "secure lookup capability generation failed");
    return true;
  }
  struct vcs_zcode_dht_time now = record_public_now();
  record_public_lock();
  record_public_cleanup_locked(now.monotonic_s);
  struct public_record_lookup *entry = NULL;
  bool collision = false;
  for (size_t i = 0; i < RECORD_PUBLIC_LOOKUPS_MAX; i++) {
    if (!g_record_public[i].used && !entry)
      entry = &g_record_public[i];
    if (g_record_public[i].used &&
        record_token_equal(g_record_public[i].lookup_token, tokens))
      collision = true;
  }
  uint64_t internal_id = 0, generation = 0;
  bool began = entry && !collision &&
               boot_zcode_dht_record_discovery_begin(
                   &selector, now, &internal_id, &generation);
  if (!began) {
    zcl_mutex_unlock(&g_record_public_lock);
    record_rpc_error(
        result, "LOOKUP_UNAVAILABLE",
        "DHT is disabled or its bounded discovery queue is full");
    return true;
  }
  memset(entry, 0, sizeof(*entry));
  entry->used = true;
  memcpy(entry->lookup_token, tokens, RECORD_PUBLIC_TOKEN_BYTES);
  memcpy(entry->owner_token, tokens + RECORD_PUBLIC_TOKEN_BYTES,
         RECORD_PUBLIC_TOKEN_BYTES);
  entry->service_operation_id = internal_id;
  entry->service_generation = generation;
  const struct json_value *include_wires =
      json_get(in, "include_evidence_wires");
  entry->include_evidence_wires =
      include_wires && include_wires->type == JSON_BOOL &&
      json_get_bool(include_wires);
  entry->expires_mono = now.monotonic_s + VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                        VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S +
                        RECORD_PUBLIC_ACTIVE_GRACE_S;
  char lookup_hex[RECORD_PUBLIC_TOKEN_BYTES * 2 + 1];
  char owner_hex[RECORD_PUBLIC_TOKEN_BYTES * 2 + 1];
  zcl_hex_encode(entry->lookup_token, RECORD_PUBLIC_TOKEN_BYTES, lookup_hex);
  zcl_hex_encode(entry->owner_token, RECORD_PUBLIC_TOKEN_BYTES, owner_hex);
  zcl_mutex_unlock(&g_record_public_lock);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_str(result, "state", "pending");
  json_push_kv_str(result, "lookup_id", lookup_hex);
  json_push_kv_str(result, "owner_token", owner_hex);
  json_push_kv_int(result, "expires_in_seconds",
                   VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                       VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S +
                       RECORD_PUBLIC_ACTIVE_GRACE_S);
  return true;
}

static bool rpc_record_poll(const struct json_value *params, bool help,
                            struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_record_poll {lookup_id,owner_token}");
    return true;
  }
  const struct json_value *in = record_rpc_input(params);
  uint8_t lookup_token[RECORD_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[RECORD_PUBLIC_TOKEN_BYTES];
  if (!record_parse_capability(in, lookup_token, owner_token)) {
    record_rpc_error(
        result, "INVALID_LOOKUP_CAPABILITY",
        "lookup_id and owner_token must be canonical 32-hex values");
    return true;
  }
  struct vcs_zcode_dht_time now = record_public_now();
  record_public_lock();
  record_public_cleanup_locked(now.monotonic_s);
  struct public_record_lookup *entry =
      record_public_find_locked(lookup_token, owner_token);
  if (!entry) {
    zcl_mutex_unlock(&g_record_public_lock);
    record_rpc_error(
        result, "LOOKUP_UNKNOWN",
        "lookup capability is unknown, expired, or not owned");
    return true;
  }
  if (!entry->cached && !boot_zcode_dht_record_discovery_poll(
                            entry->service_operation_id,
                            entry->service_generation, now, &entry->result)) {
    memset(entry, 0, sizeof(*entry));
    zcl_mutex_unlock(&g_record_public_lock);
    record_rpc_error(result, "LOOKUP_INTERRUPTED",
                     "DHT service restarted during record discovery");
    return true;
  }
  if (entry->result.state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING &&
      !entry->cached) {
    entry->cached = true;
    entry->expires_mono =
        now.monotonic_s + RECORD_PUBLIC_RESULT_RETENTION_S;
  }
  struct vcs_zcode_dht_record_discovery_result snapshot = entry->result;
  bool include_evidence_wires = entry->include_evidence_wires;
  zcl_mutex_unlock(&g_record_public_lock);
  record_result_json(result, &snapshot, include_evidence_wires);
  return true;
}

static bool rpc_record_cancel(const struct json_value *params, bool help,
                              struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_record_cancel {lookup_id,owner_token}");
    return true;
  }
  const struct json_value *in = record_rpc_input(params);
  uint8_t lookup_token[RECORD_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[RECORD_PUBLIC_TOKEN_BYTES];
  if (!record_parse_capability(in, lookup_token, owner_token)) {
    record_rpc_error(
        result, "INVALID_LOOKUP_CAPABILITY",
        "lookup_id and owner_token must be canonical 32-hex values");
    return true;
  }
  struct vcs_zcode_dht_time now = record_public_now();
  record_public_lock();
  record_public_cleanup_locked(now.monotonic_s);
  struct public_record_lookup *entry =
      record_public_find_locked(lookup_token, owner_token);
  if (!entry) {
    zcl_mutex_unlock(&g_record_public_lock);
    record_rpc_error(
        result, "LOOKUP_UNKNOWN",
        "lookup capability is unknown, expired, or not owned");
    return true;
  }
  if (!entry->cached)
    (void)boot_zcode_dht_record_discovery_cancel(
        entry->service_operation_id, entry->service_generation);
  memset(entry, 0, sizeof(*entry));
  zcl_mutex_unlock(&g_record_public_lock);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_bool(result, "canceled", true);
  return true;
}

static bool rpc_delegation_check(const struct json_value *params, bool help,
                                 struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_delegation_check {delegation_wire}");
    return true;
  }
  const struct json_value *in = record_rpc_input(params);
  const char *hex = record_input_str(in, "delegation_wire");
  uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
  struct vcs_zcode_dht_delegation delegation;
  if (!hex || strlen(hex) != sizeof(wire) * 2u ||
      !zcl_hex_decode_lower(hex, wire, sizeof(wire)) ||
      vcs_zcode_dht_delegation_decode(&delegation, wire, sizeof(wire)) !=
          VCS_ZCODE_DHT_DELEGATION_OK) {
    record_rpc_error(result, "INVALID_DELEGATION",
                     "delegation_wire must be one canonical signed v1 wire");
    return true;
  }
  uint64_t now = (uint64_t)platform_time_wall_time_t();
  uint8_t genesis[32];
  if (!boot_zcode_dht_network_genesis(genesis) ||
      vcs_zcode_dht_delegation_verify(
          &delegation, genesis, NULL, 0, NULL, now) !=
          VCS_ZCODE_DHT_DELEGATION_OK ||
      !boot_zcode_dht_chain_authorize_public(&delegation)) {
    record_rpc_error(result, "DELEGATION_NOT_ACTIVE",
                     "delegation is invalid, expired, wrong-network, or its "
                     "ZID/beacon is not active on this node's chain");
    return true;
  }
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_bool(result, "chain_authorized", true);
  return true;
}

/* Synchronous namespace board: what THIS node's record store holds in one
 * namespace, sovereignty-filtered, never a peer query. Discovery answers
 * "who names this root" asynchronously; a board answers "what has this
 * node seen" immediately — the distinction an operator needs when reading
 * an empty board (nothing seen yet, not nothing anywhere). */
#define RECORD_BOARD_MAX 64u

static bool rpc_record_board(const struct json_value *params, bool help,
                             struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_record_board {kind,namespace}");
    return true;
  }
  const struct json_value *in = record_rpc_input(params);
  enum vcs_zcode_dht_record_kind kind = record_input_kind(in);
  char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES];
  if (!kind ||
      !record_input_namespace(in, namespace_name)) {
    record_rpc_error(
        result, "INVALID_SELECTOR",
        "kind and canonical namespace required (no root: a board is "
        "namespace-wide by definition)");
    return true;
  }
  struct vcs_zcode_dht_record records[RECORD_BOARD_MAX];
  size_t count = 0, seen_total = 0;
  uint64_t now = (uint64_t)platform_time_wall_time_t();
  if (!boot_zcode_dht_record_board(now, kind, namespace_name, records,
                                   RECORD_BOARD_MAX, &count, &seen_total)) {
    record_rpc_error(result, "LOOKUP_UNAVAILABLE",
                     "DHT is disabled on this node");
    return true;
  }
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_str(result, "namespace", namespace_name);
  json_push_kv_bool(result, "local_projection", true);
  json_push_kv_int(result, "count", (int64_t)count);
  json_push_kv_int(result, "seen_total", (int64_t)seen_total);
  json_push_kv_bool(result, "truncated", seen_total > count);
  struct json_value rows;
  json_init(&rows);
  json_set_array(&rows);
  for (size_t i = 0; i < count; i++) {
    struct json_value row;
    json_init(&row);
    record_row_json(&row, &records[i], false, false, false, false);
    json_push_back(&rows, &row);
    json_free(&row);
  }
  json_push_kv(result, "records", &rows);
  json_free(&rows);
  return true;
}

void boot_zcode_dht_record_register_rpc(struct rpc_table *table) {
  const struct rpc_command commands[] = {
      {"zcode", "zcode_dht_record_begin", rpc_record_begin, true},
      {"zcode", "zcode_dht_record_poll", rpc_record_poll, true},
      {"zcode", "zcode_dht_record_cancel", rpc_record_cancel, true},
      {"zcode", "zcode_dht_record_board", rpc_record_board, true},
      {"zcode", "zcode_dht_delegation_check", rpc_delegation_check, true},
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
    rpc_table_must_append(table, &commands[i]);
}
