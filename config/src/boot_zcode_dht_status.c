/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded JSON projection of authenticated DHT service status. */

#include "config/boot_zcode_dht.h"

#include "base/hex.h"
#include "config/boot_zcode_dht_chain.h"
#include "config/boot_zcode_dht_frame_auth.h"
#include "config/boot_zcode_dht_reachability.h"
#include "json/json.h"

void boot_zcode_dht_status_json(
    struct json_value *out, const struct vcs_zcode_dht_service *service) {
  struct vcs_zcode_dht_service_status status;
  vcs_zcode_dht_service_status(service, &status);
  char node_id[65] = {0};
  if (status.enabled)
    zcl_hex_encode(status.local_node_id, 32, node_id);
  json_set_object(out);
  json_push_kv_bool(out, "enabled", status.enabled);
  json_push_kv_str(out, "disabled_reason", status.disabled_reason);
  json_push_kv_str(out, "local_node_id", node_id);
  json_push_kv_int(out, "k", VCS_ZCODE_DHT_K);
  json_push_kv_int(out, "alpha", VCS_ZCODE_DHT_ALPHA);
  json_push_kv_int(out, "max_contacts", VCS_ZCODE_DHT_MAX_CONTACTS);
  json_push_kv_int(out, "max_authenticated_peers",
                   VCS_ZCODE_DHT_SERVICE_MAX_PEERS);
  json_push_kv_int(out, "max_queued_lookups",
                   VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS);
  json_push_kv_int(out, "max_active_queries",
                   VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES);
  json_push_kv_int(out, "max_lookup_candidates",
                   VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES);
  json_push_kv_int(out, "lookup_ceiling_seconds",
                   VCS_ZCODE_DHT_LOOKUP_CEILING_S);
  json_push_kv_int(out, "replay_entries_per_peer",
                   VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER);
  json_push_kv_int(out, "replay_retention_seconds",
                   VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS);
  json_push_kv_int(out, "inbound_rate_per_second",
                   VCS_ZCODE_DHT_SERVICE_RATE_PER_SECOND);
  json_push_kv_int(out, "inbound_rate_burst",
                   VCS_ZCODE_DHT_SERVICE_RATE_BURST);
  json_push_kv_int(out, "max_outbound_frames",
                   VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND);
  json_push_kv_int(out, "max_record_operations",
                   VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS);
  json_push_kv_int(out, "max_records_per_peer",
                   VCS_ZCODE_DHT_SERVICE_MAX_RECORDS_PER_PEER);
  json_push_kv_int(out, "contacts", status.contacts);
  json_push_kv_int(out, "buckets_used", status.buckets_used);
  json_push_kv_int(out, "connected_authenticated",
                   status.connected_authenticated);
  json_push_kv_int(out, "cold_contacts", status.cold_contacts);
  json_push_kv_int(out, "pending_probes", status.pending_probes);
  static const char *const probe_names[] = {
      "waiting", "in_flight", "responded", "failed", "expired"};
  struct json_value probes;
  json_init(&probes);
  json_set_object(&probes);
  for (int i = 0; i < VCS_ZCODE_DHT_PROBE_STATE_COUNT; i++)
    json_push_kv_int(&probes, probe_names[i],
                     (int64_t)status.probe_transitions[i]);
  json_push_kv(out, "probe_transitions", &probes);
  json_free(&probes);
  json_push_kv_int(out, "active_queries", status.active_queries);
  json_push_kv_int(out, "queued_lookups", status.queued_lookups);
  json_push_kv_int(out, "outbound_queued", status.outbound_queued);
  json_push_kv_int(out, "frames_accepted", (int64_t)status.frames_accepted);
  struct json_value rejected;
  json_init(&rejected);
  json_set_object(&rejected);
  for (int i = 0; i < VCS_ZCODE_DHT_REJECT_COUNT; i++)
    json_push_kv_int(&rejected, vcs_zcode_dht_reject_reason_string(i),
                     (int64_t)status.frames_rejected[i]);
  json_push_kv(out, "frames_rejected", &rejected);
  json_free(&rejected);
  /* Frames this composition layer dropped without ever turning into
   * scoring evidence (service absent/disabled/stale/sessionless). Kept
   * beside frames_rejected because the two populations are disjoint:
   * counted rejections have a live service behind them; these do not. */
  json_push_kv_int(out, "frames_dropped_local",
                   (int64_t)boot_zcode_dht_frame_auth_local_drops());
  json_push_kv_int(out, "find_node_received",
                   (int64_t)status.find_node_received);
  json_push_kv_int(out, "nodes_received", (int64_t)status.nodes_received);
  json_push_kv_int(out, "find_node_sent", (int64_t)status.find_node_sent);
  json_push_kv_int(out, "nodes_sent", (int64_t)status.nodes_sent);
  json_push_kv_int(out, "find_record_received",
                   (int64_t)status.find_record_received);
  json_push_kv_int(out, "records_received",
                   (int64_t)status.records_received);
  json_push_kv_int(out, "store_record_received",
                   (int64_t)status.store_record_received);
  json_push_kv_int(out, "store_result_received",
                   (int64_t)status.store_result_received);
  json_push_kv_int(out, "find_record_sent",
                   (int64_t)status.find_record_sent);
  json_push_kv_int(out, "records_sent", (int64_t)status.records_sent);
  json_push_kv_int(out, "store_record_sent",
                   (int64_t)status.store_record_sent);
  json_push_kv_int(out, "store_result_sent",
                   (int64_t)status.store_result_sent);
  json_push_kv_int(out, "signed_records", status.signed_records);
  json_push_kv_int(out, "active_record_operations",
                   status.active_record_operations);
  json_push_kv_int(out, "publication_intents", status.publication_intents);
  json_push_kv_int(out, "active_publications", status.active_publications);
  json_push_kv_int(out, "stalled_possessions", status.stalled_possessions);
  json_push_kv_int(out, "possession_stall_releases",
                   (int64_t)status.possession_stall_releases);
  json_push_kv_int(out, "unauthenticated_expired",
                   (int64_t)status.unauthenticated_expired);
  json_push_kv_int(out, "duplicate_sessions_retired",
                   (int64_t)status.duplicate_sessions_retired);
  json_push_kv_int(out, "lookup_rounds", (int64_t)status.lookup_rounds);
  json_push_kv_int(out, "lookup_xor_progress",
                   (int64_t)status.lookup_xor_progress);
  json_push_kv_int(out, "lookup_queue_wait_seconds",
                   (int64_t)status.lookup_queue_wait_s);
  static const char *const candidate_names[] = {
      "unverified", "unreachable", "authenticated", "queried",
      "in_flight", "responded", "failed"};
  struct json_value shortlist;
  json_init(&shortlist);
  json_set_object(&shortlist);
  for (int i = 0; i < VCS_ZCODE_DHT_CANDIDATE_STATE_COUNT; i++)
    json_push_kv_int(&shortlist, candidate_names[i],
                     (int64_t)status.lookup_shortlist_states[i]);
  json_push_kv(out, "lookup_shortlist", &shortlist);
  json_free(&shortlist);
  static const char *const termination_names[] = {
      "none", "target_authenticated", "shortlist_stable", "timeout",
      "no_authenticated_result"};
  struct json_value terminations;
  json_init(&terminations);
  json_set_object(&terminations);
  for (int i = 0; i < VCS_ZCODE_DHT_TERMINATION_COUNT; i++)
    json_push_kv_int(&terminations, termination_names[i],
                     (int64_t)status.lookup_terminations[i]);
  json_push_kv(out, "lookup_terminations", &terminations);
  json_free(&terminations);
  struct json_value chain;
  json_init(&chain);
  boot_zcode_dht_chain_dump_json(&chain);
  json_push_kv(out, "chain_authorization", &chain);
  json_free(&chain);
  struct json_value reachability;
  json_init(&reachability);
  boot_zcode_dht_reachability_dump_json(&reachability);
  json_push_kv(out, "reachability", &reachability);
  json_free(&reachability);
  json_push_kv_bool(out, "persistence_loaded", status.persistence_loaded);
  json_push_kv_bool(out, "persistence_dirty", status.persistence_dirty);
  json_push_kv_int(out, "persistence_load_count",
                   (int64_t)status.persistence_load_count);
  json_push_kv_int(out, "persistence_save_count",
                   (int64_t)status.persistence_save_count);
  json_push_kv_str(out, "last_error", status.last_error);
}
