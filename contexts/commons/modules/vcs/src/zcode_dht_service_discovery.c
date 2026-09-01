/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Iterative signed-record discovery over the authenticated S6 DHT. */

#include "zcode_dht_service_internal.h"

#include <stdlib.h>
#include <string.h>

static struct service_record_discovery *discovery_find(
    struct vcs_zcode_dht_service *service, uint64_t id)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++)
    if (service->discoveries[i].used && service->discoveries[i].id == id)
      return &service->discoveries[i];
  return NULL;
}

static struct service_peer *discovery_peer_for_node(
    struct vcs_zcode_dht_service *service, const uint8_t node_id[32])
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->peers[i].used && service->peers[i].connected &&
        service->peers[i].authenticated &&
        memcmp(service->peers[i].node_id, node_id, 32) == 0)
      return &service->peers[i];
  return NULL;
}

static bool discovery_policy_allows(
    const struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record)
{
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  memcpy(subject.semantic_root, record->semantic_root, 32);
  memcpy(subject.transport_root, record->transport_root, 32);
  memcpy(subject.publisher_zid, record->delegation.doc.master_pubkey, 32);
  memcpy(subject.service_type, record->namespace_name,
         VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
  return service->policy_decide &&
         service->policy_decide(service->policy_ctx,
                                VCS_ZCODE_SOVEREIGNTY_DISCOVER, &subject);
}

static bool discovery_same_record(const struct vcs_zcode_dht_record *a,
                                  const struct vcs_zcode_dht_record *b)
{
  uint8_t aw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  uint8_t bw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  return vcs_zcode_dht_record_encode(a, aw) == VCS_ZCODE_DHT_RECORD_OK &&
         vcs_zcode_dht_record_encode(b, bw) == VCS_ZCODE_DHT_RECORD_OK &&
         memcmp(aw, bw, sizeof(aw)) == 0;
}

static int discovery_record_compare(const void *left, const void *right)
{
  const struct vcs_zcode_dht_record *a = left;
  const struct vcs_zcode_dht_record *b = right;
  uint8_t aw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  uint8_t bw[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_encode(a, aw) != VCS_ZCODE_DHT_RECORD_OK ||
      vcs_zcode_dht_record_encode(b, bw) != VCS_ZCODE_DHT_RECORD_OK)
    return 0;
  return memcmp(aw, bw, sizeof(aw));
}

static void discovery_normalize_records(
    struct service_record_discovery *discovery)
{
  qsort(discovery->records, discovery->record_count,
        sizeof(*discovery->records), discovery_record_compare);
  struct vcs_zcode_dht_record ordered[
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
  bool selected[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS] = {0};
  uint32_t count = 0;
  for (uint32_t i = 0; i < discovery->record_count; i++) {
    bool provider_seen = false;
    for (uint32_t j = 0; j < count; j++)
      if (memcmp(ordered[j].provider_node_id,
                 discovery->records[i].provider_node_id, 32) == 0) {
        provider_seen = true;
        break;
      }
    if (!provider_seen) {
      ordered[count++] = discovery->records[i];
      selected[i] = true;
    }
  }
  for (uint32_t i = 0; i < discovery->record_count; i++)
    if (!selected[i])
      ordered[count++] = discovery->records[i];
  memcpy(discovery->records, ordered,
         discovery->record_count * sizeof(*discovery->records));
}

static void discovery_merge_record(
    struct vcs_zcode_dht_service *service,
    struct service_record_discovery *discovery,
    const struct vcs_zcode_dht_record *record, struct vcs_zcode_dht_time now)
{
  if (!discovery_policy_allows(service, record))
    return;
  for (uint32_t i = 0; i < discovery->record_count; i++)
    if (discovery_same_record(&discovery->records[i], record))
      return;
  if (discovery->record_count < VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
    discovery->records[discovery->record_count++] = *record;
  (void)vcs_zcode_dht_service_record_admit(service, record, now);
}

static void discovery_merge_result(
    struct vcs_zcode_dht_service *service,
    struct service_record_discovery *discovery,
    const struct vcs_zcode_dht_record_operation_result *result,
    struct vcs_zcode_dht_time now)
{
  if (result->state != VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE)
    return;
  for (uint32_t i = 0; i < result->record_count; i++)
    discovery_merge_record(service, discovery, &result->records[i], now);
}

static void discovery_cancel_children(
    struct vcs_zcode_dht_service *service,
    struct service_record_discovery *discovery)
{
  if (discovery->phase == SERVICE_RECORD_DISCOVERY_ROUTING &&
      discovery->lookup_id)
    (void)vcs_zcode_dht_service_lookup_cancel(service, discovery->lookup_id);
  for (uint32_t i = 0;
       i < VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES; i++)
    if (discovery->child_operation_ids[i])
      (void)vcs_zcode_dht_service_record_operation_cancel(
          service, discovery->child_operation_ids[i]);
}

static bool discovery_responsible_set_covered(
    const struct service_record_discovery *discovery)
{
  uint32_t successes = 0;
  for (uint32_t i = 0; i < discovery->node_count; i++) {
    if (!discovery->node_complete[i])
      return false;
    successes += discovery->node_succeeded[i];
    if (successes == discovery->target_successes)
      return true;
  }
  return false;
}

static void discovery_drive_children(
    struct vcs_zcode_dht_service *service,
    struct service_record_discovery *discovery,
    struct vcs_zcode_dht_time now)
{
  for (uint32_t i = 0; i < discovery->node_count; i++) {
    uint64_t child_id = discovery->child_operation_ids[i];
    if (!child_id)
      continue;
    struct vcs_zcode_dht_record_operation_result result;
    if (!vcs_zcode_dht_service_record_operation_poll(service, child_id, now,
                                                       &result)) {
      discovery->child_operation_ids[i] = 0;
      discovery->node_complete[i] = true;
      discovery->failed_nodes++;
      if (discovery->active_children)
        discovery->active_children--;
      continue;
    }
    if (result.state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
      continue;
    discovery_merge_result(service, discovery, &result, now);
    discovery->child_operation_ids[i] = 0;
    if (result.state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE &&
        result.next_offset &&
        discovery->record_count <
            VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
      discovery->node_page_offsets[i] = result.next_offset;
    else {
      discovery->node_complete[i] = true;
      if (result.state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE) {
        discovery->node_succeeded[i] = true;
        discovery->successful_nodes++;
      } else
        discovery->failed_nodes++;
    }
    if (discovery->active_children)
      discovery->active_children--;
  }

  if (discovery->record_count >=
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS) {
    discovery_cancel_children(service, discovery);
    discovery->truncated = true;
    discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    return;
  }

  if (discovery_responsible_set_covered(discovery)) {
    discovery_cancel_children(service, discovery);
    discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    return;
  }

  while (discovery->active_children < VCS_ZCODE_DHT_ALPHA &&
         discovery->successful_nodes < discovery->target_successes) {
    uint32_t at = discovery->node_count;
    for (uint32_t i = 0; i < discovery->node_count; i++)
      if (!discovery->node_complete[i] &&
          !discovery->child_operation_ids[i]) {
        at = i;
        break;
      }
    if (at == discovery->node_count)
      break;
    /* The local responsible node was snapshotted through local_query() at
     * admission. It deliberately has no remote peer/session to query. */
    if (memcmp(discovery->node_ids[at], service->self_id, 32) == 0) {
      discovery->node_complete[at] = true;
      discovery->node_succeeded[at] = true;
      discovery->successful_nodes++;
      continue;
    }
    struct service_peer *peer = discovery_peer_for_node(
        service, discovery->node_ids[at]);
    if (!peer) {
      discovery->node_complete[at] = true;
      discovery->failed_nodes++;
      continue;
    }
    uint64_t child_id = 0;
    if (!vcs_zcode_dht_service_record_query_page_begin(
            service, peer->peer_id, &discovery->selector,
            discovery->node_page_offsets[at], now, &child_id))
      break;
    discovery->child_operation_ids[at] = child_id;
    discovery->active_children++;
    if (discovery->node_page_offsets[at] == 0)
      discovery->nodes_queried++;
  }
  bool all_complete = true;
  for (uint32_t i = 0; i < discovery->node_count; i++)
    all_complete &= discovery->node_complete[i];
  if (all_complete && discovery->active_children == 0) {
    discovery->incomplete |=
        discovery->successful_nodes < discovery->target_successes;
    discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
  }
}

static void discovery_drive(struct vcs_zcode_dht_service *service,
                            struct service_record_discovery *discovery,
                            struct vcs_zcode_dht_time now)
{
  if (discovery->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
    return;
  if (now.monotonic_s >= discovery->deadline_mono) {
    discovery_cancel_children(service, discovery);
    discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT;
    return;
  }
  if (discovery->phase == SERVICE_RECORD_DISCOVERY_ROUTING) {
    vcs_zcode_dht_service_tick(service, now);
    struct service_lookup *lookup = vcs_zcode_dht_lookup_find(
        service, discovery->lookup_id);
    if (!lookup) {
      discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED;
      return;
    }
    discovery->routing_rounds = lookup->rounds;
    discovery->xor_progress = lookup->xor_progress;
    if (!lookup->completed)
      return;
    if (lookup->termination == VCS_ZCODE_DHT_TERMINATION_TIMEOUT ||
        lookup->termination ==
            VCS_ZCODE_DHT_TERMINATION_NO_AUTHENTICATED_RESULT)
      discovery->incomplete = true;
    discovery->lookup_id = 0;
    discovery->phase = SERVICE_RECORD_DISCOVERY_QUERYING;
    for (uint32_t i = 0;
         i < lookup->candidate_count &&
         discovery->node_count < VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES;
         i++)
      if (vcs_zcode_dht_lookup_candidate_authenticated(
              lookup->candidates[i].state))
        memcpy(discovery->node_ids[discovery->node_count++],
               lookup->candidates[i].node_id, 32);
    discovery->target_successes =
        discovery->node_count < VCS_ZCODE_DHT_K
            ? discovery->node_count : VCS_ZCODE_DHT_K;
    memset(lookup, 0, sizeof(*lookup));
  }
  discovery_drive_children(service, discovery, now);
}

bool vcs_zcode_dht_service_record_discovery_begin(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out)
{
  uint8_t target[32];
  if (!service || !service->enabled || !selector || !operation_id_out ||
      !vcs_zcode_dht_record_key(service->genesis, selector->kind,
                                selector->namespace_name, selector->root,
                                target))
    return false;
  *operation_id_out = 0;
  struct service_record_discovery *discovery = NULL;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++)
    if (!service->discoveries[i].used) {
      discovery = &service->discoveries[i];
      break;
    }
  if (!discovery)
    return false;
  memset(discovery, 0, sizeof(*discovery));
  discovery->used = true;
  discovery->id = service->next_record_discovery_id++;
  if (!discovery->id)
    discovery->id = service->next_record_discovery_id++;
  discovery->state = VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
  discovery->selector = *selector;
  discovery->deadline_mono = now.monotonic_s +
                             VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                             VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S;

  struct vcs_zcode_dht_record cached[
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
  size_t cached_count = vcs_zcode_dht_service_record_local_query(
      service, now.wall_unix, selector, cached,
      VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS);
  if (cached_count > VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
    cached_count = VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS;
  for (size_t i = 0; i < cached_count; i++)
    discovery_merge_record(service, discovery, &cached[i], now);

  if (!vcs_zcode_dht_service_lookup_begin(service, target, now,
                                           &discovery->lookup_id)) {
    memset(discovery, 0, sizeof(*discovery));
    return false;
  }
  *operation_id_out = discovery->id;
  return true;
}

bool vcs_zcode_dht_service_record_discovery_poll(
    struct vcs_zcode_dht_service *service, uint64_t operation_id,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_discovery_result *out)
{
  if (!service || !out)
    return false;
  struct service_record_discovery *discovery =
      discovery_find(service, operation_id);
  if (!discovery)
    return false;
  discovery_drive(service, discovery, now);
  if (discovery->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
    discovery_normalize_records(discovery);
  memset(out, 0, sizeof(*out));
  out->state = discovery->state;
  out->truncated = discovery->truncated;
  out->incomplete = discovery->incomplete;
  out->routing_rounds = discovery->routing_rounds;
  out->xor_progress = discovery->xor_progress;
  out->nodes_queried = discovery->nodes_queried;
  out->record_count = discovery->record_count;
  memcpy(out->records, discovery->records,
         discovery->record_count * sizeof(*out->records));
  if (discovery->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
    memset(discovery, 0, sizeof(*discovery));
  return true;
}

bool vcs_zcode_dht_service_record_discovery_cancel(
    struct vcs_zcode_dht_service *service, uint64_t operation_id)
{
  if (!service)
    return false;
  struct service_record_discovery *discovery =
      discovery_find(service, operation_id);
  if (!discovery)
    return false;
  discovery_cancel_children(service, discovery);
  memset(discovery, 0, sizeof(*discovery));
  return true;
}
