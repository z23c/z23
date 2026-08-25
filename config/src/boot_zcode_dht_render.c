/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: JSON wire rendering shared by the ZCODE DHT RPCs and tests. */

#include "config/boot_zcode_dht_render.h"

#include "base/hex.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_record_kind.h"

void boot_zcode_dht_record_json(struct json_value *row,
                                const struct vcs_zcode_dht_record *record,
                                bool include_wire) {
  char semantic[65], transport[65], provider[65], owner[65], publisher[65];
  char record_root[65] = "";
  char record_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u + 1u] = "";
  uint8_t record_id[32];
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_id(record, record_id) == VCS_ZCODE_DHT_RECORD_OK)
    zcl_hex_encode(record_id, 32, record_root);
  if (include_wire &&
      vcs_zcode_dht_record_encode(record, wire) == VCS_ZCODE_DHT_RECORD_OK)
    zcl_hex_encode(wire, sizeof(wire), record_wire);
  zcl_hex_encode(record->semantic_root, 32, semantic);
  zcl_hex_encode(record->transport_root, 32, transport);
  zcl_hex_encode(record->provider_node_id, 32, provider);
  zcl_hex_encode(record->owner_group, 32, owner);
  zcl_hex_encode(record->delegation.doc.master_pubkey, 32, publisher);
  json_set_object(row);
  json_push_kv_str(row, "kind", boot_zcode_dht_record_kind_name(record->kind));
  json_push_kv_str(row, "record_root", record_root);
  if (include_wire)
    json_push_kv_str(row, "record_wire", record_wire);
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
}

#ifdef ZCL_TESTING
void boot_zcode_dht_publication_record_test_render(
    struct json_value *result, const struct vcs_zcode_dht_record *record) {
  boot_zcode_dht_record_json(result, record, true);
}
#endif

static const char *lookup_state_name(enum vcs_zcode_dht_lookup_state state) {
  if (state == VCS_ZCODE_DHT_LOOKUP_COMPLETE)
    return "complete";
  if (state == VCS_ZCODE_DHT_LOOKUP_TIMEOUT)
    return "timeout";
  if (state == VCS_ZCODE_DHT_LOOKUP_NOT_FOUND)
    return "not_found";
  return "pending";
}

static const char *lookup_termination_name(
    enum vcs_zcode_dht_lookup_termination termination) {
  static const char *const names[] = {
      "none", "target_authenticated", "shortlist_stable", "timeout",
      "no_authenticated_result"};
  return (unsigned)termination < VCS_ZCODE_DHT_TERMINATION_COUNT
             ? names[termination]
             : "unknown";
}

void boot_zcode_dht_lookup_json(
    struct json_value *result,
    const struct vcs_zcode_dht_lookup_result *lookup) {
  bool successful = lookup->state == VCS_ZCODE_DHT_LOOKUP_PENDING ||
                    lookup->state == VCS_ZCODE_DHT_LOOKUP_COMPLETE;
  json_set_object(result);
  json_push_kv_bool(result, "ok", successful);
  json_push_kv_str(result, "state", lookup_state_name(lookup->state));
  json_push_kv_str(result, "termination",
                   lookup_termination_name(lookup->termination));
  json_push_kv_int(result, "rounds", lookup->rounds);
  json_push_kv_int(result, "xor_progress", lookup->xor_progress);
  json_push_kv_int(result, "queue_wait_seconds",
                   (int64_t)lookup->queue_wait_s);
  if (!successful) {
    bool timeout = lookup->state == VCS_ZCODE_DHT_LOOKUP_TIMEOUT;
    json_push_kv_str(result, "code",
                     timeout ? "LOOKUP_TIMEOUT" : "LOOKUP_NOT_FOUND");
    json_push_kv_str(
        result, "message",
        timeout ? "lookup reached its 30-second bounded deadline"
                : "all authenticated queries failed without a response");
  }
  json_push_kv_int(result, "count", lookup->count);
  struct json_value rows;
  json_init(&rows);
  json_set_array(&rows);
  for (uint32_t i = 0; i < lookup->count; i++) {
    char node_id[65];
    zcl_hex_encode(lookup->node_ids[i], 32, node_id);
    struct json_value row;
    json_init(&row);
    json_set_str(&row, node_id);
    json_push_back(&rows, &row);
    json_free(&row);
  }
  json_push_kv(result, "node_ids", &rows);
  json_free(&rows);
}

void boot_zcode_dht_provider_route_json(
    struct json_value *result, const struct vcs_zcode_dht_provider_route *route,
    enum vcs_swarm_fetch_result fetched) {
  bool scheduled = fetched == VCS_SWARM_FETCH_OK ||
                   fetched == VCS_SWARM_FETCH_ALREADY_COMPLETE;
  json_set_object(result);
  json_push_kv_bool(result, "ok", scheduled);
  if (!scheduled) {
    json_push_kv_str(result, "code", "FETCH_REFUSED");
    json_push_kv_str(result, "error",
                     vcs_swarm_fetch_result_string(fetched));
  }
  json_push_kv_int(result, "authenticated_providers",
                   route->authenticated_count);
  json_push_kv_int(result, "reachability_pending",
                   route->reachability_pending);
  json_push_kv_int(result, "policy_denied", route->policy_denied);
  json_push_kv_str(result, "fetch_result",
                   vcs_swarm_fetch_result_string(fetched));
  json_push_kv_bool(result, "restricted", true);
}

#ifdef ZCL_TESTING
void boot_zcode_dht_provider_route_test_render(
    struct json_value *result,
    const struct vcs_zcode_dht_provider_route *route, uint32_t fetch_result) {
  boot_zcode_dht_provider_route_json(result, route,
                                     (enum vcs_swarm_fetch_result)fetch_result);
}
#endif
