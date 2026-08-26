/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded signed-record operations inside the authenticated DHT. */

#include "zcode_dht_service_internal.h"

#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

bool vcs_zcode_dht_message_is_request(enum vcs_zcode_dht_msg_kind kind)
{
  return kind == VCS_ZCODE_DHT_MSG_FIND_NODE ||
         kind == VCS_ZCODE_DHT_MSG_FIND_RECORD ||
         kind == VCS_ZCODE_DHT_MSG_STORE_RECORD;
}

const uint8_t *vcs_zcode_dht_message_query_id(
    const struct vcs_zcode_dht_msg *message)
{
  switch (message->kind) {
  case VCS_ZCODE_DHT_MSG_FIND_NODE: return message->find_node.query_id;
  case VCS_ZCODE_DHT_MSG_NODES: return message->nodes.query_id;
  case VCS_ZCODE_DHT_MSG_FIND_RECORD: return message->find_record.query_id;
  case VCS_ZCODE_DHT_MSG_RECORDS: return message->records.query_id;
  case VCS_ZCODE_DHT_MSG_STORE_RECORD: return message->store_record.query_id;
  case VCS_ZCODE_DHT_MSG_STORE_RESULT: return message->store_result.query_id;
  }
  return NULL;
}

const struct vcs_zcode_dht_delegation *vcs_zcode_dht_message_delegation(
    const struct vcs_zcode_dht_msg *message)
{
  switch (message->kind) {
  case VCS_ZCODE_DHT_MSG_FIND_NODE: return &message->find_node.delegation;
  case VCS_ZCODE_DHT_MSG_NODES: return &message->nodes.delegation;
  case VCS_ZCODE_DHT_MSG_FIND_RECORD:
    return &message->find_record.delegation;
  case VCS_ZCODE_DHT_MSG_RECORDS: return &message->records.delegation;
  case VCS_ZCODE_DHT_MSG_STORE_RECORD:
    return &message->store_record.delegation;
  case VCS_ZCODE_DHT_MSG_STORE_RESULT:
    return &message->store_result.delegation;
  }
  return NULL;
}

uint64_t vcs_zcode_dht_message_generation(
    const struct vcs_zcode_dht_msg *message)
{
  switch (message->kind) {
  case VCS_ZCODE_DHT_MSG_FIND_NODE:
    return message->find_node.session_generation;
  case VCS_ZCODE_DHT_MSG_NODES: return message->nodes.session_generation;
  case VCS_ZCODE_DHT_MSG_FIND_RECORD:
    return message->find_record.session_generation;
  case VCS_ZCODE_DHT_MSG_RECORDS: return message->records.session_generation;
  case VCS_ZCODE_DHT_MSG_STORE_RECORD:
    return message->store_record.session_generation;
  case VCS_ZCODE_DHT_MSG_STORE_RESULT:
    return message->store_result.session_generation;
  }
  return 0;
}

bool vcs_zcode_dht_response_matches_query(
    enum vcs_zcode_dht_msg_kind message_kind, enum query_kind query_kind)
{
  if (message_kind == VCS_ZCODE_DHT_MSG_NODES)
    return query_kind == QUERY_BOOTSTRAP || query_kind == QUERY_LOOKUP ||
           query_kind == QUERY_PROBE;
  if (message_kind == VCS_ZCODE_DHT_MSG_RECORDS)
    return query_kind == QUERY_RECORD_LOOKUP;
  return message_kind == VCS_ZCODE_DHT_MSG_STORE_RESULT &&
         query_kind == QUERY_RECORD_STORE;
}

static struct service_peer *records_peer_find(
    struct vcs_zcode_dht_service *service, uint64_t peer_id)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (service->peers[i].used && service->peers[i].peer_id == peer_id)
      return &service->peers[i];
  return NULL;
}

struct service_record_operation *vcs_zcode_dht_records_operation_find(
    struct vcs_zcode_dht_service *service, uint64_t id)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++)
    if (service->record_operations[i].used &&
        service->record_operations[i].id == id)
      return &service->record_operations[i];
  return NULL;
}

static bool records_outbound_push(struct vcs_zcode_dht_service *service,
                                  uint64_t peer_id, const uint8_t *wire,
                                  size_t wire_len)
{
  if (!wire || !wire_len || wire_len > VCS_ZCODE_DHT_MAX_FRAME_BYTES ||
      service->outbound_count >= VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND)
    return false;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND; i++)
    if (!service->outbound[i].used) {
      service->outbound[i].used = true;
      service->outbound[i].peer_id = peer_id;
      service->outbound[i].len = wire_len;
      memcpy(service->outbound[i].wire, wire, wire_len);
      service->outbound_count++;
      return true;
    }
  return false;
}

static bool records_query_id(struct vcs_zcode_dht_service *service,
                             const struct service_peer *peer,
                             uint8_t out[16])
{
  uint8_t digest[32];
  struct sha3_256_ctx sha;
  service->serial++;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)"zcl.dht.record.query.v1", 24);
  sha3_256_write(&sha, service->self_id, 32);
  sha3_256_write(&sha, (const uint8_t *)&peer->peer_id, 8);
  sha3_256_write(&sha, (const uint8_t *)&peer->session.generation, 8);
  sha3_256_write(&sha, (const uint8_t *)&service->serial, 8);
  sha3_256_finalize(&sha, digest);
  memcpy(out, digest, 16);
  return true;
}

static bool records_selector_equal(
    const struct vcs_zcode_dht_record_selector *a,
    const struct vcs_zcode_dht_record_selector *b)
{
  return a->kind == b->kind &&
         memcmp(a->namespace_name, b->namespace_name,
                VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES) == 0 &&
         memcmp(a->root, b->root, 32) == 0;
}

static void records_subject(const struct vcs_zcode_dht_record *record,
                            struct vcs_zcode_sovereignty_subject *subject)
{
  memset(subject, 0, sizeof(*subject));
  memcpy(subject->semantic_root, record->semantic_root, 32);
  memcpy(subject->transport_root, record->transport_root, 32);
  memcpy(subject->publisher_zid, record->delegation.doc.master_pubkey, 32);
  memcpy(subject->service_type, record->namespace_name,
         VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
}

bool vcs_zcode_dht_records_policy_allows(
    const struct vcs_zcode_dht_service *service,
    enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_dht_record *record)
{
  struct vcs_zcode_sovereignty_subject subject;
  records_subject(record, &subject);
  return service->policy_decide &&
         service->policy_decide(service->policy_ctx, action, &subject);
}

static struct service_record_operation *records_operation_allocate(
    struct vcs_zcode_dht_service *service,
    enum service_record_operation_kind kind, uint64_t *id_out)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++) {
    struct service_record_operation *operation =
        &service->record_operations[i];
    if (operation->used)
      continue;
    memset(operation, 0, sizeof(*operation));
    operation->used = true;
    operation->kind = kind;
    operation->state = VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
    operation->id = service->next_record_operation_id++;
    if (!operation->id)
      operation->id = service->next_record_operation_id++;
    *id_out = operation->id;
    return operation;
  }
  return NULL;
}

static struct service_query *records_query_allocate(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    enum query_kind kind, uint64_t operation_id,
    struct vcs_zcode_dht_time now)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++) {
    struct service_query *query = &service->queries[i];
    if (query->used)
      continue;
    memset(query, 0, sizeof(*query));
    query->used = true;
    query->kind = kind;
    query->peer_id = peer->peer_id;
    query->generation = peer->session.generation;
    query->deadline_mono =
        now.monotonic_s + VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S;
    query->record_operation_id = operation_id;
    if (!records_query_id(service, peer, query->id)) {
      memset(query, 0, sizeof(*query));
      return NULL;
    }
    return query;
  }
  return NULL;
}

static void fill_find_auth(struct vcs_zcode_dht_msg_find_record *message,
                           const struct vcs_zcode_dht_service *service,
                           const struct service_peer *peer,
                           const struct service_query *query)
{
  message->session_generation = peer->session.generation;
  memcpy(message->sender_node_id, service->self_id, 32);
  memcpy(message->query_id, query->id, 16);
  message->delegation = service->delegation;
}

bool vcs_zcode_dht_service_record_query_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out)
{
  return vcs_zcode_dht_service_record_query_page_begin(
      service, peer_id, selector, 0, now, operation_id_out);
}

bool vcs_zcode_dht_service_record_query_page_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record_selector *selector,
    uint8_t page_offset, struct vcs_zcode_dht_time now,
    uint64_t *operation_id_out)
{
  if (!service || !service->enabled || !selector || !operation_id_out ||
      page_offset >= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
      page_offset % VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0)
    return false;
  *operation_id_out = 0;
  struct service_peer *peer = records_peer_find(service, peer_id);
  if (!peer || !peer->connected || !peer->authenticated)
    return false;
  uint64_t operation_id = 0;
  struct service_record_operation *operation = records_operation_allocate(
      service, SERVICE_RECORD_LOOKUP, &operation_id);
  if (!operation)
    return false;
  operation->selector = *selector;
  operation->page_offset = page_offset;
  struct service_query *query = records_query_allocate(
      service, peer, QUERY_RECORD_LOOKUP, operation_id, now);
  if (!query) {
    memset(operation, 0, sizeof(*operation));
    return false;
  }
  query->record_selector = *selector;
  query->record_page_offset = page_offset;
  struct vcs_zcode_dht_msg_find_record message;
  memset(&message, 0, sizeof(message));
  fill_find_auth(&message, service, peer, query);
  message.selector = *selector;
  message.page_offset = page_offset;
  uint8_t wire[VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES];
  size_t wire_len = 0;
  if (vcs_zcode_dht_msg_serialize_find_record(
          &message, peer->session.transcript_hash, service->online_seed, wire,
          sizeof(wire), &wire_len) != VCS_ZCODE_DHT_OK ||
      !records_outbound_push(service, peer_id, wire, wire_len)) {
    memset(query, 0, sizeof(*query));
    memset(operation, 0, sizeof(*operation));
    return false;
  }
  service->find_record_sent++;
  *operation_id_out = operation_id;
  return true;
}

bool vcs_zcode_dht_service_record_store_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record *record,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out)
{
  if (!service || !service->enabled || !record || !operation_id_out)
    return false;
  *operation_id_out = 0;
  struct service_peer *peer = records_peer_find(service, peer_id);
  if (!peer || !peer->connected || !peer->authenticated)
    return false;
  uint8_t record_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_encode(record, record_wire) !=
          VCS_ZCODE_DHT_RECORD_OK ||
      memcmp(record->network_genesis, service->genesis, 32) != 0)
    return false;
  uint64_t operation_id = 0;
  struct service_record_operation *operation = records_operation_allocate(
      service, SERVICE_RECORD_STORE, &operation_id);
  if (!operation)
    return false;
  struct service_query *query = records_query_allocate(
      service, peer, QUERY_RECORD_STORE, operation_id, now);
  if (!query) {
    memset(operation, 0, sizeof(*operation));
    return false;
  }
  sha3_256(record_wire, sizeof(record_wire), query->record_digest);
  struct vcs_zcode_dht_msg_store_record message;
  memset(&message, 0, sizeof(message));
  message.session_generation = peer->session.generation;
  memcpy(message.sender_node_id, service->self_id, 32);
  memcpy(message.query_id, query->id, 16);
  message.delegation = service->delegation;
  message.record = *record;
  uint8_t wire[VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES];
  size_t wire_len = 0;
  if (vcs_zcode_dht_msg_serialize_store_record(
          &message, peer->session.transcript_hash, service->online_seed, wire,
          sizeof(wire), &wire_len) != VCS_ZCODE_DHT_OK ||
      !records_outbound_push(service, peer_id, wire, wire_len)) {
    memset(query, 0, sizeof(*query));
    memset(operation, 0, sizeof(*operation));
    return false;
  }
  service->store_record_sent++;
  *operation_id_out = operation_id;
  return true;
}

bool vcs_zcode_dht_service_record_operation_poll(
    struct vcs_zcode_dht_service *service, uint64_t operation_id,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_operation_result *out)
{
  if (!service || !out)
    return false;
  vcs_zcode_dht_service_tick(service, now);
  struct service_record_operation *operation =
      vcs_zcode_dht_records_operation_find(service, operation_id);
  if (!operation)
    return false;
  memset(out, 0, sizeof(*out));
  out->state = operation->state;
  out->store_status = operation->store_status;
  if (operation->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING) {
    const uint64_t retention =
        VCS_ZCODE_DHT_RECORD_OPERATION_RESULT_RETENTION_S;
    out->expires_mono = operation->terminal_mono > UINT64_MAX - retention
                            ? UINT64_MAX
                            : operation->terminal_mono + retention;
  }
  out->page_offset = operation->page_offset;
  out->next_offset = operation->next_offset;
  out->record_count = operation->record_count;
  memcpy(out->records, operation->records,
         operation->record_count * sizeof(*operation->records));
  if (operation->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
    memset(operation, 0, sizeof(*operation));
  return true;
}

/* Drop an operation and any query still carrying its id. Both cancel and the
 * terminal sweep need exactly this; a swept operation normally has no live
 * query left, but releasing one that does is cheaper than proving it can't. */
static void records_operation_release(
    struct vcs_zcode_dht_service *service, uint64_t operation_id,
    struct service_record_operation *operation)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (service->queries[i].used &&
        service->queries[i].record_operation_id == operation_id)
      memset(&service->queries[i], 0, sizeof(service->queries[i]));
  memset(operation, 0, sizeof(*operation));
}

bool vcs_zcode_dht_service_record_operation_cancel(
    struct vcs_zcode_dht_service *service, uint64_t operation_id)
{
  if (!service)
    return false;
  struct service_record_operation *operation =
      vcs_zcode_dht_records_operation_find(service, operation_id);
  if (!operation)
    return false;
  records_operation_release(service, operation_id, operation);
  return true;
}

/* A terminal operation holds one of eight slots until its owner collects it.
 * The public API gives every owner the same explicit retention interval;
 * after it, an unpolled result is no longer part of the contract and the slot
 * is reusable. State is the terminal discriminator because zero is a valid
 * monotonic timestamp. Subtraction avoids timestamp-addition overflow and a
 * backwards clock step retains the result until the clock catches up. */
void vcs_zcode_dht_records_sweep(struct vcs_zcode_dht_service *service,
                                 uint64_t now_mono)
{
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS; i++) {
    struct service_record_operation *operation =
        &service->record_operations[i];
    if (operation->used &&
        operation->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING &&
        now_mono >= operation->terminal_mono &&
        now_mono - operation->terminal_mono >=
            VCS_ZCODE_DHT_RECORD_OPERATION_RESULT_RETENTION_S)
      records_operation_release(service, operation->id, operation);
  }
}

/* Reclaim expired rows from the record store on a debounced tick. Water-
 * marked on the service so an idle swarm pays one pass per interval, not
 * one per tick; anything collected marks the store dirty exactly like an
 * admission would, so the next debounced save persists the freed image.
 * The reclaim is a mid-session version of what load() already does —
 * without it, capacity refusals and per-put cost grow with dead history
 * until the next restart. */
void vcs_zcode_dht_records_collect_expired(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now)
{
  if (!service || !service->enabled || !service->record_store)
    return;
  if (now.monotonic_s < service->record_collect_watermark_mono)
    return; /* monotonic arithmetic keeps wall-clock jumps inert */
  if (service->record_collect_watermark_mono &&
      now.monotonic_s - service->record_collect_watermark_mono <
          VCS_ZCODE_DHT_RECORD_COLLECT_INTERVAL_S)
    return;
  service->record_collect_watermark_mono = now.monotonic_s;
  size_t collected =
      vcs_zcode_dht_record_store_collect(service->record_store,
                                         now.wall_unix);
  if (collected == 0)
    return;
  service->records_dirty = true;
  if (!service->persistence_dirty)
    service->dirty_since_mono = now.monotonic_s;
  service->persistence_dirty = true;
  service->persistence_generation++;
}

enum vcs_zcode_dht_record_store_result vcs_zcode_dht_service_record_admit(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record, struct vcs_zcode_dht_time now)
{
  if (!service || !service->enabled || !service->record_store)
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  /* A generic online delegation does not prove that its holder may create
   * namespace governance. Keep the reserved wire kind inert until a
   * master-signed namespace credential supplies that missing authority. */
  if (record && record->kind == VCS_ZCODE_DHT_RECORD_AGENT_SCOPE)
    return VCS_ZCODE_DHT_RECORD_STORE_SCOPE;
  if (!vcs_zcode_dht_records_policy_allows(
          service, VCS_ZCODE_SOVEREIGNTY_STORE, record) ||
      !vcs_zcode_dht_records_policy_allows(
          service, VCS_ZCODE_SOVEREIGNTY_INDEX, record))
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  enum vcs_zcode_dht_record_store_result result =
      vcs_zcode_dht_record_store_put(service->record_store, record,
                                     now.wall_unix);
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED ||
      result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT) {
    service->records_dirty = true;
    if (!service->persistence_dirty)
      service->dirty_since_mono = now.monotonic_s;
    service->persistence_dirty = true;
    service->persistence_generation++;
  }
  return result;
}

static bool reply_records(struct vcs_zcode_dht_service *service,
                          struct service_peer *peer,
                          const struct vcs_zcode_dht_msg_find_record *request,
                          uint64_t now_unix)
{
  struct vcs_zcode_dht_msg_records response;
  memset(&response, 0, sizeof(response));
  response.session_generation = peer->session.generation;
  memcpy(response.sender_node_id, service->self_id, 32);
  memcpy(response.query_id, request->query_id, 16);
  response.delegation = service->delegation;
  response.selector = request->selector;
  response.page_offset = request->page_offset;
  struct vcs_zcode_dht_record discovered[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  struct vcs_zcode_dht_record served[
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT];
  size_t discovered_count = vcs_zcode_dht_service_record_local_query(
      service, now_unix, &request->selector, discovered,
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT);
  if (discovered_count > VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT)
    discovered_count = VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT;
  size_t served_count = 0;
  for (size_t i = 0; i < discovered_count; i++)
    if (vcs_zcode_dht_records_policy_allows(
            service, VCS_ZCODE_SOVEREIGNTY_SERVE, &discovered[i]))
      served[served_count++] = discovered[i];
  if (request->page_offset < served_count) {
    size_t count = served_count - request->page_offset;
    if (count > VCS_ZCODE_DHT_RECORDS_PER_FRAME)
      count = VCS_ZCODE_DHT_RECORDS_PER_FRAME;
    memcpy(response.records, served + request->page_offset,
           count * sizeof(*response.records));
    qsort(response.records, count, sizeof(*response.records),
          vcs_zcode_dht_records_canonical_compare);
    response.record_count = (uint32_t)count;
    if (count == VCS_ZCODE_DHT_RECORDS_PER_FRAME &&
        request->page_offset + count < served_count)
      response.next_offset = (uint8_t)(request->page_offset + count);
  }
  uint8_t wire[VCS_ZCODE_DHT_RECORDS_MAX_WIRE_BYTES];
  size_t wire_len = 0;
  if (vcs_zcode_dht_msg_serialize_records(
          &response, peer->session.transcript_hash, service->online_seed, wire,
          sizeof(wire), &wire_len) != VCS_ZCODE_DHT_OK ||
      !records_outbound_push(service, peer->peer_id, wire, wire_len))
    return false;
  service->records_sent++;
  return true;
}

static enum vcs_zcode_dht_store_status store_status(
    enum vcs_zcode_dht_record_store_result result)
{
  if (result == VCS_ZCODE_DHT_RECORD_STORE_ADDED)
    return VCS_ZCODE_DHT_STORE_STORED;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE)
    return VCS_ZCODE_DHT_STORE_DUPLICATE;
  if (result == VCS_ZCODE_DHT_RECORD_STORE_CONFLICT)
    return VCS_ZCODE_DHT_STORE_CONFLICT;
  return VCS_ZCODE_DHT_STORE_REJECTED;
}

static bool reply_store_result(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    const struct vcs_zcode_dht_msg_store_record *request,
    enum vcs_zcode_dht_store_status status)
{
  uint8_t record_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_encode(&request->record, record_wire) !=
      VCS_ZCODE_DHT_RECORD_OK)
    return false;
  struct vcs_zcode_dht_msg_store_result response;
  memset(&response, 0, sizeof(response));
  response.session_generation = peer->session.generation;
  memcpy(response.sender_node_id, service->self_id, 32);
  memcpy(response.query_id, request->query_id, 16);
  response.delegation = service->delegation;
  response.status = status;
  sha3_256(record_wire, sizeof(record_wire), response.record_digest);
  uint8_t wire[VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES];
  size_t wire_len = 0;
  if (vcs_zcode_dht_msg_serialize_store_result(
          &response, peer->session.transcript_hash, service->online_seed, wire,
          sizeof(wire), &wire_len) != VCS_ZCODE_DHT_OK ||
      !records_outbound_push(service, peer->peer_id, wire, wire_len))
    return false;
  service->store_result_sent++;
  return true;
}

bool vcs_zcode_dht_service_records_handle(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    struct service_query *query, const struct vcs_zcode_dht_msg *message,
    struct vcs_zcode_dht_time now,
    enum vcs_zcode_dht_reject_reason *rejected_out)
{
  if (rejected_out)
    *rejected_out = VCS_ZCODE_DHT_REJECT_CAP;
  if (message->kind == VCS_ZCODE_DHT_MSG_FIND_RECORD) {
    service->find_record_received++;
    return reply_records(service, peer, &message->find_record, now.wall_unix);
  }
  if (message->kind == VCS_ZCODE_DHT_MSG_STORE_RECORD) {
    if (!vcs_zcode_dht_records_policy_allows(
            service, VCS_ZCODE_SOVEREIGNTY_DISCOVER,
            &message->store_record.record)) {
      if (rejected_out)
        *rejected_out = VCS_ZCODE_DHT_REJECT_UNAUTHORIZED;
      return false;
    }
    if (peer->record_admissions >=
        VCS_ZCODE_DHT_SERVICE_MAX_RECORDS_PER_PEER)
      return false;
    peer->record_admissions++;
    enum vcs_zcode_dht_record_store_result admitted =
        vcs_zcode_dht_service_record_admit(service,
                                           &message->store_record.record, now);
    enum vcs_zcode_dht_store_status status = store_status(admitted);
    if (status == VCS_ZCODE_DHT_STORE_REJECTED) {
      if (rejected_out)
        *rejected_out = admitted == VCS_ZCODE_DHT_RECORD_STORE_STALE
                            ? VCS_ZCODE_DHT_REJECT_REPLAY
                            : admitted == VCS_ZCODE_DHT_RECORD_STORE_EXPIRED
                                  ? VCS_ZCODE_DHT_REJECT_EXPIRED
                                  : admitted ==
                                            VCS_ZCODE_DHT_RECORD_STORE_INVALID
                                        ? VCS_ZCODE_DHT_REJECT_POISONED
                                        : admitted ==
                                                  VCS_ZCODE_DHT_RECORD_STORE_SCOPE
                                              ? VCS_ZCODE_DHT_REJECT_UNAUTHORIZED
                                              : VCS_ZCODE_DHT_REJECT_CAP;
      return false;
    }
    service->store_record_received++;
    return reply_store_result(service, peer, &message->store_record, status);
  }
  if (!query)
    return false;
  struct service_record_operation *operation =
      vcs_zcode_dht_records_operation_find(service,
                                            query->record_operation_id);
  if (!operation)
    return false;
  if (message->kind == VCS_ZCODE_DHT_MSG_RECORDS) {
    if (query->kind != QUERY_RECORD_LOOKUP ||
        !records_selector_equal(&query->record_selector,
                                &message->records.selector) ||
        query->record_page_offset != message->records.page_offset) {
      if (rejected_out)
        *rejected_out = VCS_ZCODE_DHT_REJECT_POISONED;
      return false;
    }
    operation->record_count = message->records.record_count;
    operation->page_offset = message->records.page_offset;
    operation->next_offset = message->records.next_offset;
    memcpy(operation->records, message->records.records,
           operation->record_count * sizeof(*operation->records));
    operation->state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    operation->terminal_mono = now.monotonic_s;
    service->records_received++;
    return true;
  }
  if (message->kind == VCS_ZCODE_DHT_MSG_STORE_RESULT) {
    if (query->kind != QUERY_RECORD_STORE ||
        memcmp(query->record_digest, message->store_result.record_digest, 32) !=
            0) {
      if (rejected_out)
        *rejected_out = VCS_ZCODE_DHT_REJECT_POISONED;
      return false;
    }
    operation->store_status = message->store_result.status;
    operation->state = message->store_result.status ==
                               VCS_ZCODE_DHT_STORE_REJECTED
                           ? VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED
                           : VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    operation->terminal_mono = now.monotonic_s;
    service->store_result_received++;
    return true;
  }
  return false;
}

void vcs_zcode_dht_service_record_query_finish(
    struct vcs_zcode_dht_service *service, const struct service_query *query,
    enum query_outcome outcome, struct vcs_zcode_dht_time now)
{
  if (!service || !query ||
      (query->kind != QUERY_RECORD_LOOKUP &&
       query->kind != QUERY_RECORD_STORE) ||
      outcome == QUERY_OUTCOME_RESPONSE)
    return;
  struct service_record_operation *operation =
      vcs_zcode_dht_records_operation_find(service,
                                            query->record_operation_id);
  if (operation) {
    operation->state = outcome == QUERY_OUTCOME_EXPIRED
                           ? VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT
                           : VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED;
    operation->terminal_mono = now.monotonic_s;
  }
}
