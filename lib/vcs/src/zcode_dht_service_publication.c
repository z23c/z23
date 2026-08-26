/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Publication planning and commits — signed records, plan tokens,
 * slot claiming, and possession-proof plumbing. The renewal/drive state
 * machine lives in zcode_dht_service_publication_drive.c. */

#include "zcode_dht_service_internal.h"

#include "crypto/sha3.h"
#include "vcs/package_store.h"
#include "vcs/zcode_dht_record_store.h"

#include <string.h>

uint64_t publication_next_proof_epoch(
    struct vcs_zcode_dht_service *service)
{
  service->next_possession_proof_epoch++;
  if (!service->next_possession_proof_epoch)
    service->next_possession_proof_epoch++;
  return service->next_possession_proof_epoch;
}

void publication_mark_dirty(struct vcs_zcode_dht_service *service,
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
 * the table is full of streams this record neither belongs to nor beats —
 * reported as NO_SLOT, because "global-cap" (the record store's 4096 cap)
 * sent the first operator diagnosing this condition to the wrong table. */
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
    return VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    /* The claimed slot may be the same stream's live intention mid-cycle:
     * cancel its lookup and children before overwriting, or those ids
     * leave their owner and the bounded tables they live in never free. */
    publication_cancel_active(service, publication);
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

/* Lock order: this wrapper (and its commit twin below) takes the package
 * store's possession section and calls INTO the service from inside it —
 * the opposite of the composition root, which takes the service lock first.
 * Only tests call these today; a production caller that already holds the
 * service lock must use the _verified entry points instead. */
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
    return VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    publication_cancel_active(service, publication);
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
    return VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_service_record_admit(service, &record, now);
  if (record_out && (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE ||
                     result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT))
    *record_out = record;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    publication_cancel_active(service, publication);
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
