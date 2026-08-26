/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closest-node record publication, renewal, and bounded retries. */

#include "zcode_dht_service_internal.h"

#include "crypto/sha3.h"
#include "vcs/package_store.h"
#include "vcs/zcode_dht_record_store.h"

#include <string.h>

#define PUBLICATION_RETRY_MIN_S 30u
#define PUBLICATION_RETRY_MAX_S 3600u
#define PUBLICATION_RENEW_FLOOR_S 60u

static uint64_t publication_renew_at(
    const struct service_publication *publication);
static void publication_drive(struct vcs_zcode_dht_service *service,
                              struct service_publication *publication,
                              struct vcs_zcode_dht_time now);

static uint64_t publication_next_proof_epoch(
    struct vcs_zcode_dht_service *service)
{
  service->next_possession_proof_epoch++;
  if (!service->next_possession_proof_epoch)
    service->next_possession_proof_epoch++;
  return service->next_possession_proof_epoch;
}

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

static void publication_mark_dirty(struct vcs_zcode_dht_service *service,
                                   uint64_t monotonic_s)
{
  service->publication_intents_dirty = true;
  if (!service->persistence_dirty)
    service->dirty_since_mono = monotonic_s;
  service->persistence_dirty = true;
  service->persistence_generation++;
}

/* Build the signed record and its plan token. On refusal, *reason (when
 * non-NULL) says which named record contract failed — VCS_ZCODE_DHT_RECORD_OK
 * still means "not a record-contract refusal" (service disabled, null input,
 * or ack-kind guard), so callers can tell "enable the DHT" apart from "fix
 * the spec or re-delegate". */
static bool publication_build(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    struct vcs_zcode_dht_record *record, uint8_t token[32], bool allow_ack,
    enum vcs_zcode_dht_record_error *reason)
{
  if (reason)
    *reason = VCS_ZCODE_DHT_RECORD_OK;
  if (!service || !service->enabled || !service->record_store || !spec ||
      !record || !token ||
      ((spec->kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
        spec->kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK) &&
       !allow_ack))
    return false;
  memset(record, 0, sizeof(*record));
  record->kind = spec->kind;
  memcpy(record->namespace_name, spec->namespace_name,
         sizeof(record->namespace_name));
  memcpy(record->network_genesis, service->genesis, 32);
  memcpy(record->semantic_root, spec->semantic_root, 32);
  memcpy(record->transport_root, spec->transport_root, 32);
  memcpy(record->provider_node_id, service->self_id, 32);
  memcpy(record->owner_group, spec->owner_group, 32);
  record->sequence = spec->sequence;
  record->not_before = spec->not_before;
  record->expiry = spec->expiry;
  record->delegation = service->delegation;
  /* sequence 0 means "derive it": max+1 read from THIS store under the
   * caller's service lock. Two operators renewing the same stream through
   * one node can then never both commit the same derived sequence — the
   * loser's commit rebuild lands on a different stream digest and refuses
   * STALE, exactly the protection a concurrent renewal needs. Client-side
   * max+1 derivations raced the store's visibility lag instead and produced
   * duplicate sequences whose records conflicted into unusability. The
   * derivation is deterministic per store state, so an uncontended plan and
   * its commit rebuild the identical record and token. */
  if (record->sequence == 0)
    record->sequence = vcs_zcode_dht_record_store_max_sequence(
                            service->record_store, record) +
                       1;
  enum vcs_zcode_dht_record_error signed_error =
      vcs_zcode_dht_record_sign(record, service->online_seed);
  if (signed_error != VCS_ZCODE_DHT_RECORD_OK) {
    if (reason)
      *reason = signed_error;
    return false;
  }
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES], stream_digest[32];
  enum vcs_zcode_dht_record_error encoded_error =
      vcs_zcode_dht_record_encode(record, wire);
  if (encoded_error != VCS_ZCODE_DHT_RECORD_OK) {
    if (reason)
      *reason = encoded_error;
    return false;
  }
  /* A plan governs one signed publication stream. Hashing the entire record
   * store made unrelated incoming gossip race every local plan/commit pair. */
  vcs_zcode_dht_record_store_stream_digest(
      service->record_store, record, stream_digest);
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)"zcl.dht.publish.plan.v1", 23);
  sha3_256_write(&sha, service->genesis, 32);
  sha3_256_write(&sha, stream_digest, 32);
  sha3_256_write(&sha, wire, sizeof(wire));
  sha3_256_finalize(&sha, token);
  return true;
}

bool vcs_zcode_dht_service_record_publish_plan(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason)
{
  if (plan_token)
    memset(plan_token, 0, 32);
  if (record_out)
    memset(record_out, 0, sizeof(*record_out));
  return publication_build(service, spec, record_out, plan_token, false,
                           reason);
}

static struct service_publication *publication_slot(
    struct vcs_zcode_dht_service *service)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (!service->publications[i].used)
      return &service->publications[i];
  return NULL;
}

/* The slot a commit REPLACES rather than grows past. A used slot holding the
 * same publication stream at a sequence the incoming record supersedes is
 * the same intention, refreshed out-of-band: reusing it keeps a manual
 * re-publish from leaking a second permanent slot. Without this, every
 * out-of-band renewal of a live stream consumed a fresh slot, the old slot
 * spun forever on renewals the store refused as STALE, and the intent table
 * filled with historical sequences of one stream until every new commit on
 * the node was refused "global-cap" — on a real host, at 16/16. */
static struct service_publication *publication_slot_for_stream(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++) {
    struct service_publication *slot = &service->publications[i];
    if (slot->used &&
        vcs_zcode_dht_record_stream_equal(&slot->record, record) &&
        slot->record.sequence <= record->sequence)
      return slot;
  }
  return NULL;
}

/* The slot a commit claims: the same stream's existing intention when the
 * incoming record supersedes it, otherwise a fresh free slot. NULL only when
 * the table is full of streams this record neither belongs to nor beats. */
static struct service_publication *publication_claim(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record)
{
  struct service_publication *slot =
      publication_slot_for_stream(service, record);
  return slot ? slot : publication_slot(service);
}

enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_service_record_publish_commit(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason)
{
  uint8_t expected[32], difference = 0;
  struct vcs_zcode_dht_record record;
  if (reason)
    *reason = VCS_ZCODE_DHT_RECORD_OK;
  if (!plan_token ||
      !publication_build(service, spec, &record, expected, false, reason))
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  for (size_t i = 0; i < 32; i++)
    difference |= expected[i] ^ plan_token[i];
  if (difference)
    return VCS_ZCODE_DHT_RECORD_STORE_STALE;
  struct service_publication *publication =
      publication_claim(service, &record);
  if (!publication)
    return VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    memset(publication, 0, sizeof(*publication));
    publication->used = true;
    publication->record = record;
    publication->lifetime_s = record.expiry - record.not_before;
    publication->backoff_s = PUBLICATION_RETRY_MIN_S;
    publication_mark_dirty(service, now.monotonic_s);
    vcs_zcode_dht_service_publication_schedule(service, now);
  }
  return result;
}

bool vcs_zcode_dht_storage_ack_plan_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out)
{
  if (!spec || spec->kind != VCS_ZCODE_DHT_RECORD_STORAGE_ACK)
    return false;
  return publication_build(service, spec, record_out, plan_token, true, NULL);
}

static bool publication_owner_group_is_zero(const uint8_t owner_group[32])
{
  uint8_t any = 0;
  for (size_t i = 0; i < 32; i++) any |= owner_group[i];
  return any == 0;
}

static bool publication_evidence_spec(
    const struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    enum vcs_zcode_dht_record_kind expected,
    struct vcs_zcode_dht_publish_spec *normalized)
{
  if (!service || !spec || !normalized || spec->kind != expected)
    return false;
  *normalized = *spec;
  if (publication_owner_group_is_zero(normalized->owner_group)) {
    static const char domain[] = "zcl.zcode.owner-group.signer-lineage.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, service->delegation.doc.master_pubkey, 32);
    sha3_256_finalize(&sha, normalized->owner_group);
  }
  return true;
}

bool vcs_zcode_dht_source_reproduction_ack_plan_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out)
{
  struct vcs_zcode_dht_publish_spec normalized;
  return publication_evidence_spec(
             service, spec, VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK,
             &normalized) &&
      publication_build(
          service, &normalized, record_out, plan_token, true, NULL);
}

struct storage_ack_plan_apply {
  struct vcs_zcode_dht_service *service;
  const struct vcs_zcode_dht_publish_spec *spec;
  uint8_t *plan_token;
  struct vcs_zcode_dht_record *record_out;
  bool ok;
};

static void storage_ack_plan_apply(void *opaque, bool current)
{
  struct storage_ack_plan_apply *apply = opaque;
  if (current)
    apply->ok = vcs_zcode_dht_storage_ack_plan_verified(
        apply->service, apply->spec, apply->plan_token, apply->record_out);
}

bool vcs_zcode_dht_service_storage_ack_plan(
    struct vcs_zcode_dht_service *service,
    struct vcs_package_store *package_store,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out)
{
  struct vcs_package_possession_receipt receipt;
  if (!spec || spec->kind != VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
      !vcs_package_store_verify_possession_receipt(
          package_store, spec->transport_root, true, &receipt))
    return false;
  if (plan_token)
    memset(plan_token, 0, 32);
  if (record_out)
    memset(record_out, 0, sizeof(*record_out));
  struct storage_ack_plan_apply apply = {
      service, spec, plan_token, record_out, false};
  vcs_package_store_possession_apply_if_current(
      package_store, spec->transport_root, receipt.mutation_generation,
      true, storage_ack_plan_apply, &apply);
  return apply.ok;
}

enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_storage_ack_commit_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out)
{
  uint8_t expected[32], difference = 0;
  struct vcs_zcode_dht_record record;
  if (!spec || spec->kind != VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
      !plan_token ||
      !publication_build(service, spec, &record, expected, true, NULL))
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  for (size_t i = 0; i < 32; i++)
    difference |= expected[i] ^ plan_token[i];
  if (difference)
    return VCS_ZCODE_DHT_RECORD_STORE_STALE;
  struct service_publication *publication =
      publication_claim(service, &record);
  if (!publication)
    return VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    memset(publication, 0, sizeof(*publication));
    publication->used = true;
    publication->possession_current = true;
    publication->renewal_proof_ready = false;
    publication->possession_proof_epoch =
        publication_next_proof_epoch(service);
    publication->record = record;
    publication->lifetime_s = record.expiry - record.not_before;
    publication->backoff_s = PUBLICATION_RETRY_MIN_S;
    publication_mark_dirty(service, now.monotonic_s);
    vcs_zcode_dht_service_publication_schedule(service, now);
  }
  return result;
}

enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_source_reproduction_ack_commit_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out)
{
  uint8_t expected[32], difference = 0;
  struct vcs_zcode_dht_record record;
  struct vcs_zcode_dht_publish_spec normalized;
  if (!plan_token ||
      !publication_evidence_spec(
          service, spec, VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK,
          &normalized) ||
      !publication_build(
          service, &normalized, &record, expected, true, NULL))
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  for (size_t i = 0; i < 32; i++)
    difference |= expected[i] ^ plan_token[i];
  if (difference)
    return VCS_ZCODE_DHT_RECORD_STORE_STALE;
  struct service_publication *publication =
      publication_claim(service, &record);
  if (!publication)
    return VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    memset(publication, 0, sizeof(*publication));
    publication->used = true;
    publication->record = record;
    publication->lifetime_s = record.expiry - record.not_before;
    publication->backoff_s = PUBLICATION_RETRY_MIN_S;
    publication_mark_dirty(service, now.monotonic_s);
    vcs_zcode_dht_service_publication_schedule(service, now);
  }
  return result;
}

struct storage_ack_commit_apply {
  struct vcs_zcode_dht_service *service;
  const struct vcs_zcode_dht_publish_spec *spec;
  const uint8_t *plan_token;
  struct vcs_zcode_dht_time now;
  struct vcs_zcode_dht_record *record_out;
  enum vcs_zcode_dht_record_store_result result;
};

static void storage_ack_commit_apply(void *opaque, bool current)
{
  struct storage_ack_commit_apply *apply = opaque;
  if (current)
    apply->result = vcs_zcode_dht_storage_ack_commit_verified(
        apply->service, apply->spec, apply->plan_token, apply->now,
        apply->record_out);
}

enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_service_storage_ack_commit(
    struct vcs_zcode_dht_service *service,
    struct vcs_package_store *package_store,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out)
{
  struct vcs_package_possession_receipt receipt;
  if (!spec || !vcs_package_store_verify_possession_receipt(
                   package_store, spec->transport_root, true, &receipt))
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  struct storage_ack_commit_apply apply = {
      service, spec, plan_token, now, record_out,
      VCS_ZCODE_DHT_RECORD_STORE_INVALID};
  vcs_package_store_possession_apply_if_current(
      package_store, spec->transport_root, receipt.mutation_generation,
      true, storage_ack_commit_apply, &apply);
  return apply.result;
}

size_t vcs_zcode_dht_service_storage_ack_proof_requests(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_storage_ack_proof_request *out, size_t max)
{
  if (!service || !out || !max)
    return 0;
  size_t count = 0;
  for (size_t i = 0;
       i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS && count < max; i++)
    if (service->publications[i].used &&
        service->publications[i].record.kind ==
            VCS_ZCODE_DHT_RECORD_STORAGE_ACK) {
      struct service_publication *publication = &service->publications[i];
      if (!publication->possession_proof_epoch)
        publication->possession_proof_epoch =
            publication_next_proof_epoch(service);
      if (now.wall_unix >= publication_renew_at(publication) &&
          !publication->renewal_proof_ready) {
        if (!publication->renewal_proof_required)
          publication->possession_proof_epoch =
              publication_next_proof_epoch(service);
        publication->renewal_proof_required = true;
        publication->possession_current = false;
      }
      memcpy(out[count].transport_root,
             publication->record.transport_root, 32);
      out[count].fresh_required =
          publication->renewal_proof_required ||
          !publication->possession_current;
      out[count].proof_epoch = publication->possession_proof_epoch;
      count++;
    }
  return count;
}

void vcs_zcode_dht_service_storage_ack_validation(
    struct vcs_zcode_dht_service *service, const uint8_t transport_root[32],
    uint64_t proof_epoch, bool valid, struct vcs_zcode_dht_time now)
{
  if (!service || !transport_root)
    return;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++) {
    struct service_publication *publication = &service->publications[i];
    if (publication->used &&
        publication->record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
        memcmp(publication->record.transport_root, transport_root, 32) == 0 &&
        publication->possession_proof_epoch == proof_epoch) {
      publication->possession_current = valid;
      if (!valid)
        publication->renewal_proof_ready = false;
      if (valid && publication->renewal_proof_required)
        publication->renewal_proof_ready = true;
      publication_drive(service, publication, now);
    }
  }
}

static void publication_cancel_active(
    struct vcs_zcode_dht_service *service,
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

static uint64_t publication_renew_at(
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
  for (uint32_t i = 0;
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
      memset(operation, 0, sizeof(*operation));
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

static void publication_drive(struct vcs_zcode_dht_service *service,
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
    publication_cancel_active(service, publication);
    memset(publication, 0, sizeof(*publication));
    publication_mark_dirty(service, now.monotonic_s);
    return;
  }
  if (publication->record.kind ==
          VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK &&
      now.wall_unix >= publication->record.expiry) {
    publication_cancel_active(service, publication);
    memset(publication, 0, sizeof(*publication));
    publication_mark_dirty(service, now.monotonic_s);
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
