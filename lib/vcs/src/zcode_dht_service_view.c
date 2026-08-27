/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Privacy-bounded DHT views and chain-status revalidation sweep. */

#include "zcode_dht_service_internal.h"

#include <stdio.h>
#include <string.h>

static uint32_t active_query_count(const struct vcs_zcode_dht_service *s) {
  uint32_t n = 0;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    n += s->queries[i].used;
  return n;
}

void vcs_zcode_dht_service_status(const struct vcs_zcode_dht_service *s,
                                  struct vcs_zcode_dht_service_status *out) {
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!s)
    return;
  out->enabled = s->enabled;
  memcpy(out->local_node_id, s->self_id, 32);
  (void)snprintf(out->disabled_reason, sizeof(out->disabled_reason), "%s",
                 s->disabled_reason);
  (void)snprintf(out->last_error, sizeof(out->last_error), "%s", s->last_error);
  /* A missing transport or identity is an empty service, not a partially
   * initialized routing table.  In particular, do not inspect table counts
   * or discovery stores that were never admitted for use. */
  if (!s->enabled)
    return;
  out->contacts = vcs_zcode_dht_table_count(s->table);
  for (size_t i = 0; i < VCS_ZCODE_DHT_BUCKET_COUNT; i++)
    out->buckets_used += s->table->bucket_sizes[i] != 0;
  out->pending_probes = (uint32_t)vcs_zcode_dht_table_pending_count(s->table);
  for (size_t i = 0; i < VCS_ZCODE_DHT_PROBE_STATE_COUNT; i++)
    out->probe_transitions[i] = vcs_zcode_dht_table_probe_transition_count(
        s->table, (enum vcs_zcode_dht_probe_state)i);
  out->active_queries = active_query_count(s);
  out->outbound_queued = s->outbound_count;
  out->frames_accepted = s->frames_accepted;
  memcpy(out->frames_rejected, s->rejected, sizeof(out->frames_rejected));
  out->find_node_received = s->find_received;
  out->nodes_received = s->nodes_received;
  out->find_node_sent = s->find_sent;
  out->nodes_sent = s->nodes_sent;
  out->find_record_received = s->find_record_received;
  out->records_received = s->records_received;
  out->store_record_received = s->store_record_received;
  out->store_result_received = s->store_result_received;
  out->find_record_sent = s->find_record_sent;
  out->records_sent = s->records_sent;
  out->store_record_sent = s->store_record_sent;
  out->store_result_sent = s->store_result_sent;
  out->signed_records =
      (uint32_t)vcs_zcode_dht_record_store_count(s->record_store);
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++)
    out->active_record_operations += s->record_operations[i].used;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++)
    out->active_record_operations += s->discoveries[i].used;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (s->publications[i].used) {
      out->publication_intents++;
      out->active_publications +=
          s->publications[i].phase != SERVICE_PUBLICATION_WAITING;
      /* Also true during the ordinary renewal-window proof cycle, so a
       * nonzero reading is routine; the alarm signal is
       * possession_stall_releases climbing or this gauge pinned near MAX. */
      out->stalled_possessions +=
          s->publications[i].record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
          !s->publications[i].possession_current;
    }
  out->unauthenticated_expired = s->unauthenticated_expired;
  out->duplicate_sessions_retired = s->duplicate_sessions_retired;
  out->possession_stall_releases = s->possession_stall_releases;
  out->lookup_rounds = s->lookup_rounds;
  out->lookup_xor_progress = s->lookup_xor_progress;
  out->lookup_queue_wait_s = s->lookup_queue_wait_s;
  memcpy(out->lookup_terminations, s->lookup_terminations,
         sizeof(out->lookup_terminations));
  out->persistence_loaded = s->persistence_loaded;
  out->persistence_dirty = s->persistence_dirty;
  out->persistence_load_count = s->persistence_load_count;
  out->persistence_save_count = s->persistence_save_count;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (s->peers[i].used && s->peers[i].connected && s->peers[i].authenticated)
      out->connected_authenticated++;
  out->cold_contacts = out->contacts > out->connected_authenticated
                           ? out->contacts - out->connected_authenticated
                           : 0;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++) {
    const struct service_lookup *l = &s->lookups[i];
    out->queued_lookups += l->used && !l->completed;
    if (!l->used)
      continue;
    for (uint32_t c = 0; c < l->candidate_count; c++)
      if ((unsigned)l->candidates[c].state <
          VCS_ZCODE_DHT_CANDIDATE_STATE_COUNT)
        out->lookup_shortlist_states[l->candidates[c].state]++;
  }
}

size_t vcs_zcode_dht_service_peers(const struct vcs_zcode_dht_service *s,
                                   uint64_t now,
                                   struct vcs_zcode_dht_peer_view *out,
                                   size_t max, size_t offset) {
  if (!s || !s->enabled || !out || !max)
    return 0;
  if (max > VCS_ZCODE_DHT_SERVICE_MAX_PEERS)
    max = VCS_ZCODE_DHT_SERVICE_MAX_PEERS;
  size_t seen = 0, n = 0;
  for (size_t b = 0; b < VCS_ZCODE_DHT_BUCKET_COUNT; b++)
    for (size_t i = 0; i < s->table->bucket_sizes[b]; i++) {
      const struct vcs_zcode_dht_contact *c = &s->table->buckets[b][i];
      if (seen++ < offset)
        continue;
      if (n == max)
        return n;
      struct vcs_zcode_dht_peer_view *v = &out[n++];
      memset(v, 0, sizeof(*v));
      memcpy(v->node_id, c->node_id, 32);
      v->bucket = (int)b;
      v->failures = c->consecutive_failures;
      v->delegation_expiry = c->delegation_expiry;
      v->beacon_height = c->beacon_height;
      v->last_seen_age_s = now > (uint64_t)c->last_success_unix
                               ? now - (uint64_t)c->last_success_unix
                               : 0;
      v->cold = true;
      for (size_t p = 0; p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++)
        if (s->peers[p].used && s->peers[p].authenticated &&
            memcmp(s->peers[p].node_id, c->node_id, 32) == 0) {
          v->peer_id = s->peers[p].peer_id;
          v->connected = s->peers[p].connected;
          v->authenticated = true;
          v->cold = !v->connected;
          break;
        }
      for (size_t q = 0; q < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; q++)
        if (s->queries[q].used && s->queries[q].kind == QUERY_PROBE &&
            memcmp(s->queries[q].victim, c->node_id, 32) == 0)
          v->probing = true;
    }
  return n;
}

size_t vcs_zcode_dht_service_delegations(
    const struct vcs_zcode_dht_service *s,
    struct vcs_zcode_dht_delegation *out, size_t max) {
  if (!s || !s->enabled || !out || !max)
    return 0;
  size_t count = 0;
  if (s->enabled && count < max)
    out[count++] = s->delegation;
  for (size_t b = 0; b < VCS_ZCODE_DHT_BUCKET_COUNT && count < max; b++)
    for (size_t i = 0; i < s->table->bucket_sizes[b] && count < max; i++) {
      struct vcs_zcode_dht_delegation decoded;
      if (vcs_zcode_dht_delegation_decode(
              &decoded, s->table->buckets[b][i].delegation_wire,
              VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) ==
          VCS_ZCODE_DHT_DELEGATION_OK)
        out[count++] = decoded;
    }
  for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING && count < max; i++) {
    struct vcs_zcode_dht_delegation decoded;
    if (s->table->pending[i].active &&
        vcs_zcode_dht_delegation_decode(
            &decoded, s->table->pending[i].candidate.delegation_wire,
            VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) ==
            VCS_ZCODE_DHT_DELEGATION_OK)
      out[count++] = decoded;
  }
  return count;
}

void vcs_zcode_dht_service_set_chain_verify(
    struct vcs_zcode_dht_service *s,
    vcs_zcode_dht_chain_verify_fn chain_verify, void *chain_ctx) {
  if (!s)
    return;
  s->chain_verify = chain_verify;
  s->chain_ctx = chain_ctx;
}

bool vcs_zcode_dht_service_revalidate(struct vcs_zcode_dht_service *s,
                                      struct vcs_zcode_dht_time now) {
  if (!s || !s->enabled)
    return false;
  if (vcs_zcode_dht_delegation_verify(&s->delegation, s->genesis,
                                      s->local_noise_static, 0, NULL,
                                      now.wall_unix) !=
          VCS_ZCODE_DHT_DELEGATION_OK ||
      (s->chain_verify && !s->chain_verify(s->chain_ctx, &s->delegation))) {
    s->enabled = false;
    (void)snprintf(s->disabled_reason, sizeof(s->disabled_reason),
                   "LOCAL_IDENTITY_REVOKED_OR_STALE");
    memset(s->queries, 0, sizeof(s->queries));
    memset(s->lookups, 0, sizeof(s->lookups));
    memset(s->outbound, 0, sizeof(s->outbound));
    s->outbound_count = 0;
    return true;
  }
  uint8_t remove[VCS_ZCODE_DHT_MAX_CONTACTS][32];
  size_t n = 0;
  for (size_t b = 0; b < VCS_ZCODE_DHT_BUCKET_COUNT; b++)
    for (size_t i = 0; i < s->table->bucket_sizes[b]; i++) {
      struct vcs_zcode_dht_delegation d;
      const struct vcs_zcode_dht_contact *c = &s->table->buckets[b][i];
      if (vcs_zcode_dht_delegation_decode(&d, c->delegation_wire,
                                          sizeof(c->delegation_wire)) !=
              VCS_ZCODE_DHT_DELEGATION_OK ||
          vcs_zcode_dht_delegation_verify(&d, s->genesis, NULL, 0, NULL,
                                          now.wall_unix) !=
              VCS_ZCODE_DHT_DELEGATION_OK ||
          (s->chain_verify && !s->chain_verify(s->chain_ctx, &d)))
        memcpy(remove[n++], c->node_id, 32);
    }
  for (size_t i = 0; i < n; i++)
    (void)vcs_zcode_dht_table_remove(s->table, remove[i]);
  for (size_t p = 0; p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++)
    for (size_t i = 0; i < n; i++)
      if (s->peers[p].authenticated &&
          memcmp(s->peers[p].node_id, remove[i], 32) == 0)
        s->peers[p].authenticated = false;
  if (n) {
    if (!s->persistence_dirty)
      s->dirty_since_mono = now.monotonic_s;
    s->persistence_dirty = true;
    s->persistence_generation++;
  }
  return true;
}
