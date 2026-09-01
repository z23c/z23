/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local-serial DHT session admission, retirement and reconciliation. */

#include "zcode_dht_service_internal.h"

#include <limits.h>
#include <string.h>

static struct service_peer *session_peer_find(
    struct vcs_zcode_dht_service *service, uint64_t peer_id) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->peers[i].used && service->peers[i].peer_id == peer_id)
      return &service->peers[i];
  return NULL;
}

static uint32_t session_query_count(
    const struct vcs_zcode_dht_service *service) {
  uint32_t count = 0;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    count += service->queries[i].used;
  return count;
}

/* A replacement Noise connection can be bound immediately to an already
 * verified routing-table contact.  Requiring another DHT request/response
 * first creates an asymmetric reconnect window: the dialing side is
 * authenticated while the accepting side still cannot route a provider
 * record naming that exact node.  The cached delegation is signed, remains
 * chain-checked, and is accepted only when its Noise static key matches the
 * newly established transport byte-for-byte. */
static bool session_authenticate_cached_contact(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    struct vcs_zcode_dht_time now) {
  if (!service || !peer || !service->table)
    return false;
  for (size_t bucket = 0; bucket < VCS_ZCODE_DHT_BUCKET_COUNT; bucket++)
    for (size_t slot = 0; slot < service->table->bucket_sizes[bucket]; slot++) {
      const struct vcs_zcode_dht_contact *contact =
          &service->table->buckets[bucket][slot];
      if (memcmp(contact->noise_static_pubkey,
                 peer->session.remote_static, 32) != 0)
        continue;
      struct vcs_zcode_dht_delegation delegation;
      if (vcs_zcode_dht_delegation_decode(
              &delegation, contact->delegation_wire,
              VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) !=
              VCS_ZCODE_DHT_DELEGATION_OK ||
          vcs_zcode_dht_delegation_verify(
              &delegation, service->genesis, peer->session.remote_static,
              0, NULL, now.wall_unix) != VCS_ZCODE_DHT_DELEGATION_OK ||
          (service->chain_verify &&
           !service->chain_verify(service->chain_ctx, &delegation)))
        return false;
      peer->authenticated = true;
      memcpy(peer->node_id, contact->node_id, 32);
      peer->contact = *contact;
      if (!vcs_zcode_dht_service_retain_unique_node_session(
              service, peer, now))
        return false;
      (void)vcs_zcode_dht_table_touch(
          service->table, contact->node_id, (int64_t)now.wall_unix);
      if (!service->persistence_dirty)
        service->dirty_since_mono = now.monotonic_s;
      service->persistence_dirty = true;
      return true;
    }
  return false;
}

static bool retired_contains(const struct vcs_zcode_dht_service *service,
                             uint64_t peer_id, uint64_t generation,
                             uint64_t connection_serial) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->retired[i].used &&
        service->retired[i].peer_id == peer_id &&
        service->retired[i].generation == generation &&
        service->retired[i].connection_serial == connection_serial)
      return true;
  return false;
}

static void retired_remember(struct vcs_zcode_dht_service *service,
                             const struct service_peer *peer,
                             uint64_t now_mono) {
  size_t slot = 0;
  uint64_t oldest = UINT64_MAX;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
    if (!service->retired[i].used) {
      slot = i;
      break;
    }
    if (service->retired[i].retired_mono < oldest) {
      oldest = service->retired[i].retired_mono;
      slot = i;
    }
  }
  service->retired[slot] = (struct retired_session){
      .used = true,
      .peer_id = peer->peer_id,
      .generation = peer->session.generation,
      .connection_serial = peer->session.connection_serial,
      .retired_mono = now_mono};
}

static void session_peer_retire(struct vcs_zcode_dht_service *service,
                                struct service_peer *peer,
                                struct vcs_zcode_dht_time now) {
  if (!service || !peer || !peer->used)
    return;
  uint64_t peer_id = peer->peer_id;
  uint64_t generation = peer->session.generation;
  peer->connected = false;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (service->queries[i].used && service->queries[i].peer_id == peer_id &&
        service->queries[i].generation == generation)
      vcs_zcode_dht_service_query_finish(
          service, &service->queries[i], QUERY_OUTCOME_FAILED, now);
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND; i++)
    if (service->outbound[i].used &&
        service->outbound[i].peer_id == peer_id) {
      memset(&service->outbound[i], 0, sizeof(service->outbound[i]));
      service->outbound_count--;
    }
  retired_remember(service, peer, now.monotonic_s);
  memset(peer, 0, sizeof(*peer));
}

bool vcs_zcode_dht_service_session_open(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_session *session,
    struct vcs_zcode_dht_time now) {
  if (!service || !service->enabled || !peer_id || !session ||
      !session->established || !session->generation ||
      !session->connection_serial)
    return false;
  if (retired_contains(service, peer_id, session->generation,
                       session->connection_serial))
    return false;
  struct service_peer *peer = session_peer_find(service, peer_id);
  if (peer && peer->connected &&
      peer->session.generation == session->generation &&
      peer->session.connection_serial == session->connection_serial &&
      memcmp(peer->session.transcript_hash, session->transcript_hash, 32) == 0 &&
      memcmp(peer->session.remote_static, session->remote_static, 32) == 0)
    return true;
  if (peer &&
      session->connection_serial <= peer->session.connection_serial)
    return false;
  if (peer && peer->connected)
    session_peer_retire(service, peer, now);
  peer = session_peer_find(service, peer_id);
  if (!peer)
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
      if (!service->peers[i].used) {
        peer = &service->peers[i];
        break;
      }
  if (!peer)
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
      if (!service->peers[i].connected) {
        peer = &service->peers[i];
        break;
      }
  if (!peer) {
    service->rejected[VCS_ZCODE_DHT_REJECT_CAP]++;
    return false;
  }
  memset(peer, 0, sizeof(*peer));
  peer->used = true;
  peer->connected = true;
  peer->peer_id = peer_id;
  peer->session = *session;
  peer->opened_mono = now.monotonic_s;
  peer->rate_tokens = VCS_ZCODE_DHT_SERVICE_RATE_BURST;
  peer->rate_refill_mono = now.monotonic_s;
  (void)session_authenticate_cached_contact(service, peer, now);
  if (!peer->used || !peer->connected)
    return false;
  if (session_query_count(service) <
      VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES)
    (void)vcs_zcode_dht_service_send_find(
        service, peer, QUERY_BOOTSTRAP, 0, service->self_id, NULL,
        now.monotonic_s);
  return true;
}

void vcs_zcode_dht_service_session_close(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    uint64_t generation, struct vcs_zcode_dht_time now) {
  if (!service)
    return;
  struct service_peer *peer = session_peer_find(service, peer_id);
  if (!peer || peer->session.generation != generation)
    return;
  peer->connected = false;
  if (peer->authenticated &&
      vcs_zcode_dht_table_note_failure(service->table, peer->node_id)) {
    if (!service->persistence_dirty)
      service->dirty_since_mono = now.monotonic_s;
    service->persistence_dirty = true;
  }
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (service->queries[i].used &&
        service->queries[i].peer_id == peer_id)
      vcs_zcode_dht_service_query_finish(
          service, &service->queries[i], QUERY_OUTCOME_FAILED, now);
}

void vcs_zcode_dht_service_sessions_reconcile(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_live_session *live, size_t live_count,
    struct vcs_zcode_dht_time now) {
  if (!service || (live_count && !live))
    return;
  if (live_count > VCS_ZCODE_DHT_SERVICE_MAX_PEERS)
    live_count = VCS_ZCODE_DHT_SERVICE_MAX_PEERS;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
    struct service_peer *peer = &service->peers[i];
    if (!peer->used || !peer->connected)
      continue;
    bool found = false;
    for (size_t j = 0; j < live_count; j++)
      if (live[j].peer_id == peer->peer_id &&
          live[j].generation == peer->session.generation &&
          live[j].connection_serial == peer->session.connection_serial) {
        found = true;
        break;
      }
    if (!found)
      vcs_zcode_dht_service_session_close(
          service, peer->peer_id, peer->session.generation, now);
  }
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
    if (!service->retired[i].used)
      continue;
    bool found = false;
    for (size_t j = 0; j < live_count; j++)
      if (live[j].peer_id == service->retired[i].peer_id &&
          live[j].generation == service->retired[i].generation &&
          live[j].connection_serial ==
              service->retired[i].connection_serial) {
        found = true;
        break;
      }
    if (!found)
      memset(&service->retired[i], 0, sizeof(service->retired[i]));
  }
}

bool vcs_zcode_dht_service_retain_unique_node_session(
    struct vcs_zcode_dht_service *service, struct service_peer *current,
    struct vcs_zcode_dht_time now) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
    struct service_peer *other = &service->peers[i];
    if (other == current || !other->used || !other->connected ||
        !other->authenticated ||
        memcmp(other->node_id, current->node_id, 32) != 0)
      continue;
    bool current_wins =
        current->session.connection_serial > other->session.connection_serial ||
        (current->session.connection_serial ==
             other->session.connection_serial &&
         current->peer_id < other->peer_id);
    service->duplicate_sessions_retired++;
    if (!current_wins) {
      session_peer_retire(service, current, now);
      return false;
    }
    session_peer_retire(service, other, now);
  }
  return true;
}

void vcs_zcode_dht_service_expire_unauthenticated(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now) {
  if (!service)
    return;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->peers[i].used && service->peers[i].connected &&
        !service->peers[i].authenticated &&
        now.monotonic_s >= service->peers[i].opened_mono +
                                VCS_ZCODE_DHT_SERVICE_UNAUTH_TIMEOUT_S) {
      session_peer_retire(service, &service->peers[i], now);
      service->unauthenticated_expired++;
    }
}
