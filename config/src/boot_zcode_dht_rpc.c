/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Nonblocking, capability-owned public lookup lifecycle. */

#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_publish_gate.h"
#include "config/boot_zcode_dht_record_kind.h"
#include "config/boot_zcode_dht_render.h"
#include "config/boot_zcode_dht_replication.h"

#include "base/hex.h"
#include "crypto/random_secret.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/sync.h"
#include "json/json.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_swarm_node.h"
#include <stdatomic.h>
#include <string.h>
#define DHT_PUBLIC_LOOKUPS_MAX 32u
#define DHT_PUBLIC_TOKEN_BYTES 16u
#define DHT_PUBLIC_ACTIVE_GRACE_S 5u
#define DHT_PUBLIC_RESULT_RETENTION_S 30u
struct public_lookup {
  bool used, cached;
  uint8_t lookup_token[DHT_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[DHT_PUBLIC_TOKEN_BYTES];
  uint64_t service_lookup_id, service_generation, expires_mono;
  struct vcs_zcode_dht_lookup_result result;
};

static zcl_mutex_t g_public_lock;
static _Atomic int g_public_lock_state;
static struct public_lookup g_public[DHT_PUBLIC_LOOKUPS_MAX];
static struct vcs_zcode_dht_time public_now(void) {
  return (struct vcs_zcode_dht_time){
      .wall_unix = (uint64_t)platform_time_wall_time_t(),
      .monotonic_s = (uint64_t)(platform_time_monotonic_ms() / 1000),
  };
}

static void public_lock(void) {
  if (atomic_load_explicit(&g_public_lock_state, memory_order_acquire) != 2) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &g_public_lock_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      zcl_mutex_init(&g_public_lock);
      atomic_store_explicit(&g_public_lock_state, 2, memory_order_release);
    } else {
      while (atomic_load_explicit(&g_public_lock_state,
                                  memory_order_acquire) != 2)
        ;
    }
  }
  zcl_mutex_lock(&g_public_lock);
}

static bool token_equal(const uint8_t a[DHT_PUBLIC_TOKEN_BYTES],
                        const uint8_t b[DHT_PUBLIC_TOKEN_BYTES]) {
  uint8_t difference = 0;
  for (size_t i = 0; i < DHT_PUBLIC_TOKEN_BYTES; i++)
    difference |= a[i] ^ b[i];
  return difference == 0;
}

static struct public_lookup *public_find_locked(
    const uint8_t lookup_token[DHT_PUBLIC_TOKEN_BYTES],
    const uint8_t owner_token[DHT_PUBLIC_TOKEN_BYTES]) {
  for (size_t i = 0; i < DHT_PUBLIC_LOOKUPS_MAX; i++)
    if (g_public[i].used &&
        token_equal(g_public[i].lookup_token, lookup_token) &&
        token_equal(g_public[i].owner_token, owner_token))
      return &g_public[i];
  return NULL;
}

static void public_cleanup_locked(uint64_t monotonic_s) {
  for (size_t i = 0; i < DHT_PUBLIC_LOOKUPS_MAX; i++) {
    struct public_lookup *entry = &g_public[i];
    if (!entry->used || monotonic_s < entry->expires_mono)
      continue;
    if (!entry->cached)
      (void)boot_zcode_dht_lookup_cancel(entry->service_lookup_id,
                                         entry->service_generation);
    memset(entry, 0, sizeof(*entry));
  }
}

void boot_zcode_dht_public_tick(uint64_t monotonic_s) {
  public_lock();
  public_cleanup_locked(monotonic_s);
  zcl_mutex_unlock(&g_public_lock);
  boot_zcode_dht_record_public_tick(monotonic_s);
  boot_zcode_dht_replication_public_tick(monotonic_s);
}

void boot_zcode_dht_public_reset(void) {
  public_lock();
  memset(g_public, 0, sizeof(g_public));
  zcl_mutex_unlock(&g_public_lock);
  boot_zcode_dht_record_public_reset();
  boot_zcode_dht_replication_public_reset();
}

static const struct json_value *rpc_input(const struct json_value *params) {
  const struct json_value *first =
      params && json_size(params) ? json_at(params, 0) : NULL;
  return first && first->type == JSON_OBJ ? first : NULL;
}

static int64_t input_int(const struct json_value *in, const char *key,
                         int64_t fallback) {
  const struct json_value *value = in ? json_get(in, key) : NULL;
  return value && value->type == JSON_INT ? json_get_int(value) : fallback;
}

static const char *input_str(const struct json_value *in, const char *key) {
  const struct json_value *value = in ? json_get(in, key) : NULL;
  return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool input_root(const struct json_value *in, const char *key,
                       uint8_t out[32], bool optional) {
  const char *hex = input_str(in, key);
  memset(out, 0, 32);
  return (!hex && optional) ||
         (hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32));
}

static bool input_namespace(const struct json_value *in, char out[32]) {
  const char *name = input_str(in, "namespace");
  size_t n = name ? strlen(name) : 0;
  memset(out, 0, 32);
  if (!n || n > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
    return false;
  for (size_t i = 0; i < n; i++)
    if (!((name[i] >= 'a' && name[i] <= 'z') ||
          (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
          name[i] == '-' || name[i] == '_'))
      return false;
  memcpy(out, name, n);
  return true;
}

static enum vcs_zcode_dht_record_kind input_record_kind(
    const struct json_value *in) {
  return boot_zcode_dht_record_kind_from_name(input_str(in, "kind"));
}

static void rpc_error(struct json_value *result, const char *code,
                      const char *message) {
  json_set_object(result);
  json_push_kv_bool(result, "ok", false);
  json_push_kv_str(result, "code", code);
  json_push_kv_str(result, "message", message);
}

static bool parse_capability(const struct json_value *in,
                             uint8_t lookup_token[DHT_PUBLIC_TOKEN_BYTES],
                             uint8_t owner_token[DHT_PUBLIC_TOKEN_BYTES]) {
  const char *lookup = input_str(in, "lookup_id");
  const char *owner = input_str(in, "owner_token");
  return lookup && owner && strlen(lookup) == DHT_PUBLIC_TOKEN_BYTES * 2 &&
         strlen(owner) == DHT_PUBLIC_TOKEN_BYTES * 2 &&
         zcl_hex_decode_lower(lookup, lookup_token, DHT_PUBLIC_TOKEN_BYTES) &&
         zcl_hex_decode_lower(owner, owner_token, DHT_PUBLIC_TOKEN_BYTES);
}

static bool rpc_records(const struct json_value *, bool, struct json_value *);
static bool rpc_publish(const struct json_value *, bool, struct json_value *);
static bool rpc_storage_ack(const struct json_value *, bool, struct json_value *);
static bool rpc_source_reproduction_ack(const struct json_value *, bool, struct json_value *);
static bool rpc_provider_route(const struct json_value *, bool, struct json_value *);

static bool rpc_status(const struct json_value *params, bool help,
                       struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_status\nBounded authenticated DHT state");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  const char *operation = input_str(in, "operation");
  if (operation && strcmp(operation, "records") == 0)
    return rpc_records(params, false, result);
  if (operation && strcmp(operation, "publication_snapshot") == 0)
    return boot_zcode_dht_publication_snapshot_rpc(params, false, result);
  if (operation && strcmp(operation, "publish") == 0)
    return rpc_publish(params, false, result);
  if (operation && strcmp(operation, "storage_ack") == 0)
    return rpc_storage_ack(params, false, result);
  if (operation && strcmp(operation, "source_reproduction_ack") == 0)
    return rpc_source_reproduction_ack(params, false, result);
  if (operation) {
    rpc_error(result, "INVALID_OPERATION", "unknown bounded DHT operation");
    return true;
  }
  (void)boot_zcode_dht_dump_state_json(result, NULL);
  json_push_kv_bool(result, "ok", true);
  return true;
}

static bool rpc_peers(const struct json_value *params, bool help,
                      struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_peers {\"limit\":64,\"offset\":0}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  int64_t limit = input_int(in, "limit", 64);
  int64_t offset = input_int(in, "offset", 0);
  if (limit < 1 || limit > VCS_ZCODE_DHT_SERVICE_MAX_PEERS || offset < 0 ||
      offset > VCS_ZCODE_DHT_MAX_CONTACTS) {
    rpc_error(result, "INVALID_PAGE",
              "limit must be 1..64 and offset must be 0..1024");
    return true;
  }
  struct vcs_zcode_dht_peer_view peers[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
  size_t count = 0;
  if (!boot_zcode_dht_peers((uint64_t)platform_time_wall_time_t(), peers,
                            (size_t)limit, (size_t)offset, &count)) {
    rpc_error(result, "DHT_DISABLED",
              "the authenticated DHT service is disabled");
    return true;
  }
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_int(result, "limit", limit);
  json_push_kv_int(result, "offset", offset);
  json_push_kv_int(result, "count", (int64_t)count);
  struct json_value rows;
  json_init(&rows);
  json_set_array(&rows);
  for (size_t i = 0; i < count; i++) {
    char node_id[65];
    zcl_hex_encode(peers[i].node_id, 32, node_id);
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_str(&row, "node_id", node_id);
    json_push_kv_int(&row, "bucket", peers[i].bucket);
    json_push_kv_bool(&row, "connected", peers[i].connected);
    json_push_kv_bool(&row, "cold", peers[i].cold);
    json_push_kv_bool(&row, "probing", peers[i].probing);
    json_push_kv_int(&row, "last_seen_age_seconds",
                     (int64_t)peers[i].last_seen_age_s);
    json_push_kv_int(&row, "failure_count", peers[i].failures);
    json_push_kv_int(&row, "delegation_expiry",
                     (int64_t)peers[i].delegation_expiry);
    json_push_kv_int(&row, "beacon_height", peers[i].beacon_height);
    json_push_back(&rows, &row);
    json_free(&row);
  }
  json_push_kv(result, "peers", &rows);
  json_free(&rows);
  return true;
}

static bool rpc_find_begin(const struct json_value *params, bool help,
                           struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_find_begin {\"node_id\":\"<64 lowercase hex>\"}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  const char *hex = input_str(in, "node_id");
  uint8_t target[32], tokens[DHT_PUBLIC_TOKEN_BYTES * 2];
  if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, target, 32)) {
    rpc_error(result, "INVALID_NODE_ID",
              "node_id must be 64 canonical lowercase hex chars");
    return true;
  }
  if (!zcl_random_secret_bytes(tokens, sizeof(tokens),
                               "zcode_dht_public_lookup")) {
    rpc_error(result, "LOOKUP_ID_UNAVAILABLE",
              "secure lookup capability generation failed");
    return true;
  }
  struct vcs_zcode_dht_time now = public_now();
  public_lock();
  public_cleanup_locked(now.monotonic_s);
  struct public_lookup *entry = NULL;
  bool collision = false;
  for (size_t i = 0; i < DHT_PUBLIC_LOOKUPS_MAX; i++) {
    if (!g_public[i].used && !entry)
      entry = &g_public[i];
    if (g_public[i].used &&
        token_equal(g_public[i].lookup_token, tokens))
      collision = true;
  }
  uint64_t internal_id = 0, generation = 0;
  bool began = entry && !collision && boot_zcode_dht_lookup_begin(
                                                target, now, &internal_id,
                                                &generation);
  if (!began) {
    zcl_mutex_unlock(&g_public_lock);
    rpc_error(result, "LOOKUP_UNAVAILABLE",
              "DHT is disabled or its bounded lookup queue is full");
    return true;
  }
  memset(entry, 0, sizeof(*entry));
  entry->used = true;
  memcpy(entry->lookup_token, tokens, DHT_PUBLIC_TOKEN_BYTES);
  memcpy(entry->owner_token, tokens + DHT_PUBLIC_TOKEN_BYTES,
         DHT_PUBLIC_TOKEN_BYTES);
  entry->service_lookup_id = internal_id;
  entry->service_generation = generation;
  entry->expires_mono = now.monotonic_s + VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                        DHT_PUBLIC_ACTIVE_GRACE_S;
  char lookup_hex[DHT_PUBLIC_TOKEN_BYTES * 2 + 1];
  char owner_hex[DHT_PUBLIC_TOKEN_BYTES * 2 + 1];
  zcl_hex_encode(entry->lookup_token, DHT_PUBLIC_TOKEN_BYTES, lookup_hex);
  zcl_hex_encode(entry->owner_token, DHT_PUBLIC_TOKEN_BYTES, owner_hex);
  zcl_mutex_unlock(&g_public_lock);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_str(result, "state", "pending");
  json_push_kv_str(result, "lookup_id", lookup_hex);
  json_push_kv_str(result, "owner_token", owner_hex);
  json_push_kv_int(result, "expires_in_seconds",
                   VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                       DHT_PUBLIC_ACTIVE_GRACE_S);
  return true;
}

static bool rpc_find_poll(const struct json_value *params, bool help,
                          struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_find_poll {\"lookup_id\":\"<32hex>\","
                 "\"owner_token\":\"<32hex>\"}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  uint8_t lookup_token[DHT_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[DHT_PUBLIC_TOKEN_BYTES];
  if (!parse_capability(in, lookup_token, owner_token)) {
    rpc_error(result, "INVALID_LOOKUP_CAPABILITY",
              "lookup_id and owner_token must be canonical 32-hex values");
    return true;
  }
  struct vcs_zcode_dht_time now = public_now();
  public_lock();
  public_cleanup_locked(now.monotonic_s);
  struct public_lookup *entry =
      public_find_locked(lookup_token, owner_token);
  if (!entry) {
    zcl_mutex_unlock(&g_public_lock);
    rpc_error(result, "LOOKUP_UNKNOWN",
              "lookup capability is unknown, expired, or not owned");
    return true;
  }
  if (!entry->cached && !boot_zcode_dht_lookup_poll(
                            entry->service_lookup_id,
                            entry->service_generation, now, &entry->result)) {
    memset(entry, 0, sizeof(*entry));
    zcl_mutex_unlock(&g_public_lock);
    rpc_error(result, "LOOKUP_INTERRUPTED",
              "DHT service restarted during the lookup");
    return true;
  }
  if (entry->result.state != VCS_ZCODE_DHT_LOOKUP_PENDING && !entry->cached) {
    entry->cached = true;
    entry->expires_mono = now.monotonic_s + DHT_PUBLIC_RESULT_RETENTION_S;
  }
  struct vcs_zcode_dht_lookup_result snapshot = entry->result;
  zcl_mutex_unlock(&g_public_lock);
  boot_zcode_dht_lookup_json(result, &snapshot);
  return true;
}

static bool rpc_find_cancel(const struct json_value *params, bool help,
                            struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_find_cancel {\"lookup_id\":\"<32hex>\","
                 "\"owner_token\":\"<32hex>\"}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  uint8_t lookup_token[DHT_PUBLIC_TOKEN_BYTES];
  uint8_t owner_token[DHT_PUBLIC_TOKEN_BYTES];
  if (!parse_capability(in, lookup_token, owner_token)) {
    rpc_error(result, "INVALID_LOOKUP_CAPABILITY",
              "lookup_id and owner_token must be canonical 32-hex values");
    return true;
  }
  struct vcs_zcode_dht_time now = public_now();
  public_lock();
  public_cleanup_locked(now.monotonic_s);
  struct public_lookup *entry =
      public_find_locked(lookup_token, owner_token);
  if (!entry) {
    zcl_mutex_unlock(&g_public_lock);
    rpc_error(result, "LOOKUP_UNKNOWN",
              "lookup capability is unknown, expired, or not owned");
    return true;
  }
  if (!entry->cached)
    (void)boot_zcode_dht_lookup_cancel(entry->service_lookup_id,
                                       entry->service_generation);
  memset(entry, 0, sizeof(*entry));
  zcl_mutex_unlock(&g_public_lock);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_bool(result, "canceled", true);
  return true;
}

static bool parse_selector(const struct json_value *in,
                           struct vcs_zcode_dht_record_selector *selector) {
  memset(selector, 0, sizeof(*selector));
  selector->kind = input_record_kind(in);
  if (!selector->kind || !input_namespace(in, selector->namespace_name))
    return false;
  const char *key = selector->kind == VCS_ZCODE_DHT_RECORD_POINTER
                        ? "semantic_root" : "transport_root";
  return input_root(in, key, selector->root, false);
}
static bool rpc_records(const struct json_value *params, bool help,
                        struct json_value *result) {
  if (help) {
    json_set_str(result, "zcode_dht_records {kind,namespace,root}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  struct vcs_zcode_dht_record_selector selector;
  if (!parse_selector(in, &selector)) {
    rpc_error(result, "INVALID_SELECTOR",
              "kind, canonical namespace and matching 64-hex root required");
    return true;
  }
  struct vcs_zcode_dht_record records[VCS_ZCODE_DHT_RECORDS_PER_FRAME];
  size_t count = 0;
  if (!boot_zcode_dht_record_query((uint64_t)platform_time_wall_time_t(),
                                   &selector, records,
                                   VCS_ZCODE_DHT_RECORDS_PER_FRAME, &count)) {
    rpc_error(result, "DHT_DISABLED", "authenticated DHT is disabled");
    return true;
  }
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_bool(result, "local_projection", true);
  json_push_kv_int(result, "count", (int64_t)count);
  struct json_value rows;
  json_init(&rows);
  json_set_array(&rows);
  for (size_t i = 0; i < count; i++) {
    struct json_value row;
    json_init(&row);
    boot_zcode_dht_record_json(&row, &records[i], false);
    json_push_back(&rows, &row);
    json_free(&row);
  }
  json_push_kv(result, "records", &rows);
  json_free(&rows);
  return true;
}

static bool parse_publish_spec(const struct json_value *in,
                               struct vcs_zcode_dht_publish_spec *spec,
                               enum vcs_zcode_dht_record_kind forced_kind) {
  memset(spec, 0, sizeof(*spec));
  spec->kind = forced_kind ? forced_kind : input_record_kind(in);
  int64_t sequence = input_int(in, "sequence", -1);
  int64_t not_before = input_int(in, "not_before", -1);
  int64_t expiry = input_int(in, "expiry", -1);
  if (!spec->kind || !input_namespace(in, spec->namespace_name) ||
      sequence < 1 || not_before < 0 || expiry <= not_before ||
      !input_root(in, "semantic_root", spec->semantic_root, true) ||
      !input_root(in, "transport_root", spec->transport_root, false) ||
      !input_root(in, "owner_group", spec->owner_group, true))
    return false;
  spec->sequence = (uint64_t)sequence;
  spec->not_before = (uint64_t)not_before;
  spec->expiry = (uint64_t)expiry;
  return true;
}

/* A record-contract refusal names the exact operator action. "DHT_DISABLED"
 * stays reserved for what it says — the authenticated DHT is off — instead
 * of also swallowing spec/delegation mistakes that look nothing like it. */
static void publish_build_refusal(struct json_value *result,
                                  enum vcs_zcode_dht_record_error reason) {
  if (reason == VCS_ZCODE_DHT_RECORD_OK) {
    rpc_error(result, "DHT_DISABLED", "authenticated DHT is disabled");
    return;
  }
  if (reason == VCS_ZCODE_DHT_RECORD_DELEGATION_WINDOW) {
    rpc_error(result, "DELEGATION_WINDOW",
              "the loaded delegation's window does not cover the record "
              "window; delegate with a longer expiry or publish a shorter "
              "window");
    return;
  }
  rpc_error(result, "RECORD_REFUSED",
            vcs_zcode_dht_record_error_string(reason));
}

static bool rpc_publish_impl(
    const struct json_value *params, bool help, struct json_value *result,
    enum vcs_zcode_dht_record_kind evidence_kind) {
  if (help) {
    json_set_str(result, "zcode_dht_publish {mode,kind,namespace,roots,sequence,not_before,expiry,plan_token?}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  const char *mode = input_str(in, "mode");
  struct vcs_zcode_dht_publish_spec spec;
  if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0) ||
      !parse_publish_spec(in, &spec, evidence_kind)) {
    rpc_error(result, "INVALID_PUBLISH",
              "exact mode, kind, namespace, roots, sequence and window required");
    return true;
  }
  bool special = spec.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
                 spec.kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK;
  if ((!evidence_kind && special) ||
      (evidence_kind && spec.kind != evidence_kind)) {
    rpc_error(result, "DEDICATED_PROOF_REQUIRED",
              "ACK evidence uses its dedicated byte-proof path");
    return true;
  }
  if (!evidence_kind && spec.kind == VCS_ZCODE_DHT_RECORD_POINTER &&
      strcmp(spec.namespace_name, "zclassic23.package") == 0 &&
      !boot_zcode_dht_package_pointer_publish_gate(&spec, result))
    return true;
  /* The attestation lane rides the SAME frozen publish path: a POINTER in
   * VCS_PACKAGE_ATTEST_DHT_NAMESPACE binds the attested package root to the
   * attestation blob root. Its gate is local hygiene only — the binding a
   * READER can rely on is re-checked receiver-side by
   * vcs_package_attest_transport_admit(expect_package_root). PROVIDER
   * records in the same namespace are deliberately ungated. */
  if (!evidence_kind && spec.kind == VCS_ZCODE_DHT_RECORD_POINTER &&
      strcmp(spec.namespace_name, VCS_PACKAGE_ATTEST_DHT_NAMESPACE) == 0 &&
      !boot_zcode_dht_attestation_pointer_publish_gate(&spec, result))
    return true;
  uint8_t token[32];
  struct vcs_zcode_dht_record record;
  enum vcs_zcode_dht_record_error reason = VCS_ZCODE_DHT_RECORD_OK;
  if (strcmp(mode, "plan") == 0) {
    bool planned = evidence_kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK
        ? boot_zcode_dht_storage_ack_plan(&spec, token, &record)
        : evidence_kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK
          ? boot_zcode_dht_source_reproduction_ack_plan(
                &spec, token, &record)
          : boot_zcode_dht_record_publish_plan(&spec, token, &record,
                                               &reason);
    if (!planned) {
      if (!evidence_kind)
        publish_build_refusal(result, reason);
      else
        rpc_error(
            result,
            evidence_kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK
                ? "POSSESSION_REQUIRED" : "SOURCE_RECONSTRUCTION_REQUIRED",
            evidence_kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK
                ? "complete pinned bytes failed full possession proof"
                : "complete accepted source carrier failed exact "
                  "reconstruction");
      return true;
    }
  } else {
    const char *hex = input_str(in, "plan_token");
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, token, 32)) {
      rpc_error(result, "INVALID_PLAN_TOKEN",
                "commit requires the exact canonical plan_token");
      return true;
    }
    enum vcs_zcode_dht_record_store_result stored =
        evidence_kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK
            ? boot_zcode_dht_storage_ack_commit(
                  &spec, token, public_now(), &record)
        : evidence_kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK
          ? boot_zcode_dht_source_reproduction_ack_commit(
                &spec, token, public_now(), &record)
          : boot_zcode_dht_record_publish_commit(&spec, token, public_now(),
                                                 &record, &reason);
    if (stored != VCS_ZCODE_DHT_RECORD_STORE_ADDED &&
        stored != VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE &&
        stored != VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
      if (!evidence_kind && reason != VCS_ZCODE_DHT_RECORD_OK &&
          stored == VCS_ZCODE_DHT_RECORD_STORE_INVALID)
        publish_build_refusal(result, reason);
      else
        rpc_error(result,
                  stored == VCS_ZCODE_DHT_RECORD_STORE_STALE
                      ? "STALE_PLAN" : "PUBLISH_REFUSED",
                  vcs_zcode_dht_record_store_result_string(stored));
      return true;
    }
  }
  char token_hex[65];
  zcl_hex_encode(token, 32, token_hex);
  json_set_object(result);
  json_push_kv_bool(result, "ok", true);
  json_push_kv_str(result, "mode", mode);
  json_push_kv_bool(result, "committed", strcmp(mode, "commit") == 0);
  json_push_kv_str(result, "plan_token", token_hex);
  struct json_value row;
  json_init(&row);
  boot_zcode_dht_record_json(&row, &record, true);
  json_push_kv(result, "record", &row);
  json_free(&row);
  return true;
}

static bool rpc_publish(const struct json_value *params, bool help, struct json_value *result) {
  return rpc_publish_impl(params, help, result, 0);
}
static bool rpc_storage_ack(const struct json_value *params, bool help, struct json_value *result) {
  return rpc_publish_impl(
      params, help, result, VCS_ZCODE_DHT_RECORD_STORAGE_ACK);
}

static bool rpc_source_reproduction_ack(const struct json_value *params, bool help,
                                        struct json_value *result) {
  return rpc_publish_impl(params, help, result,
                          VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK);
}

static bool rpc_provider_route(const struct json_value *params, bool help,
                               struct json_value *result) {
  if (help) {
    json_set_str(result,
                 "zcode_dht_provider_route {namespace,transport_root,"
                 "maximum_bytes?}");
    return true;
  }
  const struct json_value *in = rpc_input(params);
  struct vcs_zcode_dht_record_selector selector;
  memset(&selector, 0, sizeof(selector));
  selector.kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
  if (!input_namespace(in, selector.namespace_name) ||
      !input_root(in, "transport_root", selector.root, false)) {
    rpc_error(result, "INVALID_SELECTOR",
              "canonical namespace and transport_root required");
    return true;
  }
  const struct json_value *maximum_value = json_get(in, "maximum_bytes");
  int64_t maximum_bytes = maximum_value && maximum_value->type == JSON_INT
                              ? json_get_int(maximum_value) : 0;
  if ((maximum_value && maximum_value->type != JSON_INT) ||
      maximum_bytes < 0) {
    rpc_error(result, "INVALID_SELECTOR",
              "maximum_bytes must be a nonnegative integer");
    return true;
  }
  uint64_t now = (uint64_t)platform_time_wall_time_t();
  struct vcs_zcode_dht_provider_route route;
  if (!boot_zcode_dht_provider_route(now, &selector, &route)) {
    rpc_error(result, "DHT_DISABLED", "authenticated DHT is disabled");
    return true;
  }
  struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
  enum vcs_swarm_fetch_result fetched = VCS_SWARM_FETCH_NO_STORE;
  if (engine)
    fetched = maximum_bytes > 0
        ? vcs_swarm_engine_fetch_from_bounded(
              engine, selector.root, (int64_t)(now / 86400u), now,
              route.peer_ids, route.authenticated_count,
              (uint64_t)maximum_bytes)
        : vcs_swarm_engine_fetch_from(
              engine, selector.root, (int64_t)(now / 86400u), now,
              route.peer_ids, route.authenticated_count);
  boot_zcode_dht_provider_route_json(result, &route, fetched);
  bool package_ns = strcmp(selector.namespace_name, "zclassic23.package") == 0;
  boot_zcode_package_import_render(package_ns ? engine : NULL, selector.root,
                                   fetched, result);
  return true;
}

void boot_zcode_dht_register_rpc(struct rpc_table *table) {
  const struct rpc_command commands[] = {
      {"zcode", "zcode_dht_status", rpc_status, true},
      {"zcode", "zcode_dht_peers", rpc_peers, true},
      {"zcode", "zcode_dht_find_begin", rpc_find_begin, true},
      {"zcode", "zcode_dht_find_poll", rpc_find_poll, true},
      {"zcode", "zcode_dht_find_cancel", rpc_find_cancel, true},
      {"zcode", "zcode_dht_storage_ack", rpc_storage_ack, true},
      {"zcode", "zcode_dht_source_reproduction_ack", rpc_source_reproduction_ack, true},
      {"zcode", "zcode_dht_provider_route", rpc_provider_route, true},
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
    rpc_table_must_append(table, &commands[i]);
  boot_zcode_dht_record_register_rpc(table);
  boot_zcode_dht_replication_register_rpc(table);
  boot_zcode_package_register_rpc(table);
}
