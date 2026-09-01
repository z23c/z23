/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The publication intent state machine — supersede checks,
 * renewal, bounded routing/storing cycles, and the schedule entry point. */

#include "zcode_dht_service_internal.h"

#include "vcs/zcode_dht_record_store.h"

#include <string.h>

static uint64_t publication_max_window(enum vcs_zcode_dht_record_kind kind)
{
  if (kind == VCS_ZCODE_DHT_RECORD_PROVIDER)
    return VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS;
  if (kind == VCS_ZCODE_DHT_RECORD_POINTER)
    return VCS_ZCODE_DHT_POINTER_MAX_SECONDS;
  if (kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK)
    return VCS_ZCODE_DHT_STORAGE_ACK_MAX_SECONDS;
  return kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK
             ? VCS_ZCODE_DHT_SOURCE_REPRODUCTION_ACK_MAX_SECONDS : 0;
}

/* Also the pre-overwrite hook for superseding commits (see internal.h). */
void publication_cancel_active(struct vcs_zcode_dht_service *service,
                               struct service_publication *publication)
{
  if (publication->phase == SERVICE_PUBLICATION_ROUTING &&
      publication->lookup_id)
    (void)vcs_zcode_dht_service_lookup_cancel(service,
                                               publication->lookup_id);
  for (uint32_t i = 0;
       i < VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES; i++)
    if (publication->child_operation_ids[i])
      (void)vcs_zcode_dht_service_record_operation_cancel(
          service, publication->child_operation_ids[i]);
  publication->lookup_id = 0;
  memset(publication->child_operation_ids, 0,
         sizeof(publication->child_operation_ids));
  publication->active_children = 0;
  publication->phase = SERVICE_PUBLICATION_NEEDS_LOOKUP;
}

void publication_release(struct vcs_zcode_dht_service *service,
                         struct service_publication *publication,
                         uint64_t monotonic_s)
{
  publication_cancel_active(service, publication);
  memset(publication, 0, sizeof(*publication));
  publication_mark_dirty(service, monotonic_s);
}

static void publication_reset_cycle(struct service_publication *publication)
{
  memset(publication->node_ids, 0, sizeof(publication->node_ids));
  memset(publication->child_operation_ids, 0,
         sizeof(publication->child_operation_ids));
  memset(publication->node_complete, 0, sizeof(publication->node_complete));
  memset(publication->node_succeeded, 0,
         sizeof(publication->node_succeeded));
  publication->lookup_id = 0;
  publication->node_count = 0;
  publication->active_children = 0;
  publication->attempts = 0;
  publication->successes = 0;
  publication->phase = SERVICE_PUBLICATION_NEEDS_LOOKUP;
}

static bool publication_responsible_set_covered(
    const struct service_publication *publication, uint32_t target)
{
  uint32_t successes = 0;
  for (uint32_t i = 0; i < publication->node_count; i++) {
    if (!publication->node_complete[i])
      return false;
    successes += publication->node_succeeded[i];
    if (successes == target)
      return true;
  }
  return false;
}

uint64_t publication_renew_at(
    const struct service_publication *publication)
{
  uint64_t margin = publication->lifetime_s / 3u;
  if (margin < PUBLICATION_RENEW_FLOOR_S)
    margin = PUBLICATION_RENEW_FLOOR_S;
  return publication->record.expiry > margin
             ? publication->record.expiry - margin
             : publication->record.not_before;
}

static bool publication_renew(struct vcs_zcode_dht_service *service,
                              struct service_publication *publication,
                              struct vcs_zcode_dht_time now)
{
  uint64_t window = publication->lifetime_s;
  uint64_t maximum = publication_max_window(publication->record.kind);
  if (!window || window > maximum)
    window = maximum;
  if (service->delegation.doc.expiry <= now.wall_unix + 1u)
    return false;
  if (window > service->delegation.doc.expiry - now.wall_unix)
    window = service->delegation.doc.expiry - now.wall_unix;
  struct vcs_zcode_dht_record renewed = publication->record;
  renewed.sequence++;
  renewed.not_before = now.wall_unix;
  renewed.expiry = now.wall_unix + window;
  renewed.delegation = service->delegation;
  if (!renewed.sequence ||
      vcs_zcode_dht_record_sign(&renewed, service->online_seed) !=
          VCS_ZCODE_DHT_RECORD_OK)
    return false;
  enum vcs_zcode_dht_record_store_result admitted =
      vcs_zcode_dht_service_record_admit(service, &renewed, now);
  if (admitted != VCS_ZCODE_DHT_RECORD_STORE_ADDED &&
      admitted != VCS_ZCODE_DHT_RECORD_STORE_CONFLICT)
    return false;
  publication->record = renewed;
  publication->lifetime_s = window;
  publication->next_attempt_mono = 0;
  publication->backoff_s = PUBLICATION_RETRY_MIN_S;
  publication->renewal_proof_required = false;
  publication->renewal_proof_ready = false;
  publication_reset_cycle(publication);
  publication_mark_dirty(service, now.monotonic_s);
  return true;
}

static void publication_finish_cycle(
    struct service_publication *publication, struct vcs_zcode_dht_time now)
{
  publication->phase = SERVICE_PUBLICATION_WAITING;
  uint32_t target = publication->node_count < VCS_ZCODE_DHT_K
                        ? publication->node_count : VCS_ZCODE_DHT_K;
  if (publication->successes < target) {
    publication->next_attempt_mono =
        now.monotonic_s + publication->backoff_s;
    if (publication->backoff_s < PUBLICATION_RETRY_MAX_S / 2u)
      publication->backoff_s *= 2u;
    else
      publication->backoff_s = PUBLICATION_RETRY_MAX_S;
  } else {
    publication->next_attempt_mono = 0;
    publication->backoff_s = PUBLICATION_RETRY_MIN_S;
  }
}

static void publication_drive_routing(
    struct vcs_zcode_dht_service *service,
    struct service_publication *publication, struct vcs_zcode_dht_time now)
{
  struct service_lookup *lookup =
      vcs_zcode_dht_lookup_find(service, publication->lookup_id);
  if (!lookup) {
    publication_finish_cycle(publication, now);
    return;
  }
  if (!lookup->completed)
    return;
  for (size_t i = 0;
       i < lookup->candidate_count &&
       publication->node_count < VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES;
       i++)
    if (vcs_zcode_dht_lookup_candidate_authenticated(
            lookup->candidates[i].state) &&
        memcmp(lookup->candidates[i].node_id, service->self_id, 32) != 0)
      memcpy(publication->node_ids[publication->node_count++],
             lookup->candidates[i].node_id, 32);
  memset(lookup, 0, sizeof(*lookup));
  publication->lookup_id = 0;
  publication->phase = SERVICE_PUBLICATION_STORING;
  if (!publication->node_count)
    publication_finish_cycle(publication, now);
}

static void publication_drive_stores(
    struct vcs_zcode_dht_service *service,
    struct service_publication *publication, struct vcs_zcode_dht_time now)
{
  for (uint32_t i = 0; i < publication->node_count; i++) {
    uint64_t child_id = publication->child_operation_ids[i];
    if (!child_id)
      continue;
    struct service_record_operation *operation =
        vcs_zcode_dht_records_operation_find(service, child_id);
    if (operation &&
        operation->state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
      continue;
    if (operation &&
        operation->state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE) {
      publication->node_succeeded[i] = true;
      publication->successes++;
    }
    if (operation)
      vcs_zcode_dht_records_operation_release(service, child_id, operation);
    publication->child_operation_ids[i] = 0;
    publication->node_complete[i] = true;
    if (publication->active_children)
      publication->active_children--;
  }
  uint32_t target = publication->node_count < VCS_ZCODE_DHT_K
                        ? publication->node_count : VCS_ZCODE_DHT_K;
  if (publication_responsible_set_covered(publication, target)) {
    for (uint32_t i = 0; i < publication->node_count; i++) {
      if (publication->child_operation_ids[i])
        (void)vcs_zcode_dht_service_record_operation_cancel(
            service, publication->child_operation_ids[i]);
      publication->child_operation_ids[i] = 0;
      publication->node_complete[i] = true;
    }
    publication->active_children = 0;
    publication_finish_cycle(publication, now);
    return;
  }
  while (publication->active_children < VCS_ZCODE_DHT_ALPHA) {
    uint32_t at = publication->node_count;
    for (uint32_t i = 0; i < publication->node_count; i++)
      if (!publication->node_complete[i] &&
          !publication->child_operation_ids[i]) {
        at = i;
        break;
      }
    if (at == publication->node_count)
      break;
    struct service_peer *peer = vcs_zcode_dht_lookup_peer_for_node(
        service, publication->node_ids[at]);
    if (!peer) {
      publication->node_complete[at] = true;
      continue;
    }
    uint64_t child_id = 0;
    if (!vcs_zcode_dht_service_record_store_begin(
            service, peer->peer_id, &publication->record, now, &child_id))
      break;
    publication->child_operation_ids[at] = child_id;
    publication->active_children++;
    publication->attempts++;
  }
  bool all_complete = true;
  for (uint32_t i = 0; i < publication->node_count; i++)
    all_complete &= publication->node_complete[i];
  if (all_complete && publication->active_children == 0)
    publication_finish_cycle(publication, now);
}

void publication_drive(struct vcs_zcode_dht_service *service,
                       struct service_publication *publication,
                       struct vcs_zcode_dht_time now)
{
  uint64_t renew_at = publication_renew_at(publication);
  /* A superseded intention can never renew: the record store already holds a
   * higher sequence for this stream, so every renewal re-signs a record the
   * store refuses as STALE, forever. Free the slot instead of letting it
   * spin — this is also what heals an intent table polluted before commits
   * learned to supersede in place: the first schedule after boot frees the
   * historical sequences the persisted file restored. */
  if (vcs_zcode_dht_record_store_max_sequence(service->record_store,
                                              &publication->record) >
      publication->record.sequence) {
    publication_release(service, publication, now.monotonic_s);
    return;
  }
  if (publication->record.kind ==
          VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK &&
      now.wall_unix >= publication->record.expiry) {
    publication_release(service, publication, now.monotonic_s);
    return;
  }
  if (publication->record.kind ==
          VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK &&
      now.wall_unix >= renew_at) {
    bool quiescent = publication->phase == SERVICE_PUBLICATION_WAITING &&
        !publication->lookup_id && !publication->active_children &&
        !publication->next_attempt_mono;
    if (!quiescent) {
      publication_cancel_active(service, publication);
      publication->phase = SERVICE_PUBLICATION_WAITING;
      publication->next_attempt_mono = 0;
      publication_mark_dirty(service, now.monotonic_s);
    }
    return;
  }
  if (publication->record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
      now.wall_unix >= renew_at && !publication->renewal_proof_ready) {
    if (!publication->renewal_proof_required)
      publication->possession_proof_epoch =
          publication_next_proof_epoch(service);
    publication->renewal_proof_required = true;
    publication->possession_current = false;
  }
  if (publication->record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
      !publication->possession_current) {
    /* Gated custody gets bounded residency: a slot that can never re-verify
     * would otherwise hold its intent (and its renewal demand) forever,
     * since only SOURCE_REPRODUCTION_ACK records carry an expiry-based
     * release and POINTER/PROVIDER-style resume cannot apply when the
     * record's precondition, not its delegation, is broken. The stamp arms
     * on the first gated tick; custody regained in validation() clears it.
     * Monotonic arithmetic keeps wall-clock jumps inert. */
    if (!publication->possession_stall_since_mono)
      publication->possession_stall_since_mono = now.monotonic_s;
    if (now.monotonic_s - publication->possession_stall_since_mono >=
        PUBLICATION_POSSESSION_STALL_MAX_S) {
      service->possession_stall_releases++;
      publication_release(service, publication, now.monotonic_s);
      return;
    }
    publication_cancel_active(service, publication);
    return;
  }
  if (!vcs_zcode_dht_records_policy_allows(
          service, VCS_ZCODE_SOVEREIGNTY_FORWARD, &publication->record)) {
    publication_cancel_active(service, publication);
    return;
  }
  if (now.wall_unix >= renew_at) {
    if (publication->next_attempt_mono &&
        now.monotonic_s < publication->next_attempt_mono)
      return;
    if (publication->phase != SERVICE_PUBLICATION_WAITING)
      publication_cancel_active(service, publication);
    if (!publication_renew(service, publication, now)) {
      publication->phase = SERVICE_PUBLICATION_WAITING;
      publication->next_attempt_mono =
          now.monotonic_s + PUBLICATION_RETRY_MIN_S;
    }
    return;
  }
  if (publication->phase == SERVICE_PUBLICATION_WAITING) {
    if (!publication->next_attempt_mono ||
        now.monotonic_s < publication->next_attempt_mono)
      return;
    publication_reset_cycle(publication);
  }
  if (publication->phase == SERVICE_PUBLICATION_NEEDS_LOOKUP) {
    uint8_t root[32], target[32];
    memcpy(root, publication->record.kind == VCS_ZCODE_DHT_RECORD_POINTER
                     ? publication->record.semantic_root
                     : publication->record.transport_root,
           32);
    if (!vcs_zcode_dht_record_key(
            service->genesis, publication->record.kind,
            publication->record.namespace_name, root, target) ||
        !vcs_zcode_dht_service_lookup_begin(
            service, target, now, &publication->lookup_id))
      return;
    publication->phase = SERVICE_PUBLICATION_ROUTING;
  }
  if (publication->phase == SERVICE_PUBLICATION_ROUTING)
    publication_drive_routing(service, publication, now);
  if (publication->phase == SERVICE_PUBLICATION_STORING)
    publication_drive_stores(service, publication, now);
}

void vcs_zcode_dht_service_publication_schedule(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now)
{
  if (!service || !service->enabled)
    return;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (service->publications[i].used)
      publication_drive(service, &service->publications[i], now);
}

#ifdef ZCL_TESTING
bool vcs_zcode_dht_service_test_publication_retry(
    const struct vcs_zcode_dht_service *service,
    const uint8_t semantic_root[32],
    struct vcs_zcode_dht_publication_test_view *out)
{
  if (!service || !semantic_root || !out)
    return false;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (service->publications[i].used &&
        memcmp(service->publications[i].record.semantic_root,
               semantic_root, 32) == 0) {
      memset(out, 0, sizeof(*out));
      out->next_attempt_mono = service->publications[i].next_attempt_mono;
      out->phase = (uint32_t)service->publications[i].phase;
      out->node_count = service->publications[i].node_count;
      out->attempts = service->publications[i].attempts;
      out->successes = service->publications[i].successes;
      memcpy(out->node_ids, service->publications[i].node_ids,
             sizeof(out->node_ids));
      for (uint32_t node = VCS_ZCODE_DHT_K;
           node < service->publications[i].node_count; node++)
        out->succeeded_beyond_k +=
            service->publications[i].node_succeeded[node];
      return true;
    }
  return false;
}
#endif
