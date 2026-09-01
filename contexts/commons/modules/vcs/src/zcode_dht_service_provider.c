/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bind signed provider discovery to authenticated transport peers. */

#include "zcode_dht_service_internal.h"

#include <string.h>

static bool provider_policy_allows(
    const struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record)
{
  if (!service->policy_decide)
    return false;
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  memcpy(subject.semantic_root, record->semantic_root, 32);
  memcpy(subject.transport_root, record->transport_root, 32);
  memcpy(subject.publisher_zid, record->delegation.doc.master_pubkey, 32);
  memcpy(subject.service_type, record->namespace_name,
         VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
  static const enum vcs_zcode_sovereignty_action actions[] = {
      VCS_ZCODE_SOVEREIGNTY_FETCH, VCS_ZCODE_SOVEREIGNTY_STORE,
      VCS_ZCODE_SOVEREIGNTY_INDEX};
  for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++)
    if (!service->policy_decide(service->policy_ctx, actions[i], &subject))
      return false;
  return true;
}

static struct service_peer *provider_peer(
    struct vcs_zcode_dht_service *service, const uint8_t node_id[32])
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->peers[i].used && service->peers[i].connected &&
        service->peers[i].authenticated &&
        memcmp(service->peers[i].node_id, node_id, 32) == 0)
      return &service->peers[i];
  return NULL;
}

bool vcs_zcode_dht_service_provider_route(
    struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_provider_route *out)
{
  if (!service || !selector || !out ||
      selector->kind != VCS_ZCODE_DHT_RECORD_PROVIDER)
    return false;
  memset(out, 0, sizeof(*out));
  struct vcs_zcode_dht_record records[
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
  size_t count = vcs_zcode_dht_service_record_local_query(
      service, now_unix, selector, records,
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS);
  uint8_t seen[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS][32];
  size_t seen_count = 0;
  for (size_t i = 0; i < count; i++) {
    bool duplicate = false;
    for (size_t j = 0; j < seen_count; j++)
      duplicate |= memcmp(seen[j], records[i].provider_node_id, 32) == 0;
    if (duplicate)
      continue;
    memcpy(seen[seen_count++], records[i].provider_node_id, 32);
    if (!provider_policy_allows(service, &records[i])) {
      out->policy_denied++;
      continue;
    }
    struct service_peer *peer = provider_peer(
        service, records[i].provider_node_id);
    if (peer && out->authenticated_count < VCS_ZCODE_DHT_K) {
      size_t route_index = out->authenticated_count++;
      out->peer_ids[route_index] = peer->peer_id;
      out->expires_at[route_index] = records[i].expiry;
      continue;
    }
    if (service->request_reachability &&
        service->request_reachability(service->reachability_ctx,
                                      records[i].provider_node_id,
                                      now_unix))
      out->reachability_pending++;
  }
  return true;
}
