/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded canonical persistence for signed ZCODE DHT records. */

#ifndef ZCL_VCS_ZCODE_DHT_RECORD_STORE_H
#define ZCL_VCS_ZCODE_DHT_RECORD_STORE_H

#include "vcs/zcode_dht_record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS 4096u
#define VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT 64u
#define VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_PROVIDER 256u
#define VCS_ZCODE_DHT_RECORD_STORE_MAX_CONFLICTS 8u
#define VCS_ZCODE_DHT_RECORD_STORE_FILE "zcode/dht/records.v1"
#define VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES 80u

enum vcs_zcode_dht_record_store_result {
  VCS_ZCODE_DHT_RECORD_STORE_OK = 0,
  VCS_ZCODE_DHT_RECORD_STORE_ADDED,
  VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE,
  VCS_ZCODE_DHT_RECORD_STORE_CONFLICT,
  VCS_ZCODE_DHT_RECORD_STORE_STALE,
  VCS_ZCODE_DHT_RECORD_STORE_EXPIRED,
  VCS_ZCODE_DHT_RECORD_STORE_INVALID,
  VCS_ZCODE_DHT_RECORD_STORE_ROOT_CAP,
  VCS_ZCODE_DHT_RECORD_STORE_PROVIDER_CAP,
  VCS_ZCODE_DHT_RECORD_STORE_CONFLICT_CAP,
  VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP,
  VCS_ZCODE_DHT_RECORD_STORE_IO,
  VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
  /* Not a record-store condition at all: the service's publication intent
   * table is full of streams this publish neither belongs to nor beats.
   * Distinct from GLOBAL_CAP so an operator reading a refusal is sent to
   * the 16-slot intent table, not the 4096-record store cap. Appended last
   * so the values ahead of it stay stable for any future numeric use. */
  VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT,
  /* The record is well-formed and signature-valid but its signing key holds
   * no live grant in a namespace whose grants already govern it. Distinct
   * from INVALID so an operator reading the refusal mints or renews a
   * grant instead of reshaping the record. Appended last so the values
   * ahead of it stay stable for any future numeric use. */
  VCS_ZCODE_DHT_RECORD_STORE_SCOPE,
};

const char *vcs_zcode_dht_record_store_result_string(
    enum vcs_zcode_dht_record_store_result result);

struct vcs_zcode_dht_record_store;

struct vcs_zcode_dht_record_store *vcs_zcode_dht_record_store_create(
    const uint8_t network_genesis[32]);
struct vcs_zcode_dht_record_store *vcs_zcode_dht_record_store_clone(
    const struct vcs_zcode_dht_record_store *store);
void vcs_zcode_dht_record_store_free(
    struct vcs_zcode_dht_record_store *store);

/* Input must already have passed vcs_zcode_dht_record_parse. Newer sequence
 * replaces older records in the same publisher slot; same-sequence conflicts
 * are retained as signed evidence up to the explicit conflict cap. */
enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_put(
    struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record, uint64_t now_unix);

size_t vcs_zcode_dht_record_store_count(
    const struct vcs_zcode_dht_record_store *store);
size_t vcs_zcode_dht_record_store_query(
    const struct vcs_zcode_dht_record_store *store,
    enum vcs_zcode_dht_record_kind kind, const char *namespace_name,
    const uint8_t root[32], uint64_t now_unix,
    struct vcs_zcode_dht_record *out, size_t out_capacity);

/* Namespace governance snapshot: every live AGENT_SCOPE grant one master
 * key holds in one namespace, regardless of content root (each granted key
 * is its own stream, so a root-filtered query cannot enumerate them).
 * Grants live at `now_unix` the same way store_query windows records.
 * `founder_out` (zeroed when none exists) receives the signing key of the
 * lowest-sequence live grant — the operator key that founded governance;
 * equal sequences resolve by the store's canonical order, so the answer is
 * deterministic for one store state. `granted` collects the granted keys
 * (each grant's transport_root) up to `granted_capacity`. The return value
 * is the TOTAL live grant count, so a caller seeing count > capacity knows
 * the membership list is partial and must fail closed. */
size_t vcs_zcode_dht_record_store_scope_grants(
    const struct vcs_zcode_dht_record_store *store,
    const char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES],
    const uint8_t master_pubkey[32], uint64_t now_unix,
    uint8_t founder_out[32], uint8_t *granted, size_t granted_capacity);
void vcs_zcode_dht_record_store_digest(
    const struct vcs_zcode_dht_record_store *store, uint8_t out[32]);

/* Hash only records that can supersede/conflict with `record`. Publication
 * plan tokens use this narrower snapshot: unrelated DHT gossip must not
 * invalidate an operator's plan, while a concurrent change to the same
 * kind/namespace/root/master/provider stream still does. */
void vcs_zcode_dht_record_store_stream_digest(
    const struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record, uint8_t out[32]);

/* Highest sequence currently held in `record`'s stream (0 when the stream is
 * empty). Publish-plan auto-sequencing derives max+1 from THIS, under the
 * caller's service lock, so two operators renewing the same stream through
 * one node can never both commit the same derived sequence: the second
 * commit's rebuild lands on a different token and refuses STALE. Client-side
 * max+1 derivations raced the store's visibility lag and produced exactly
 * that duplicate-sequence collision (both records conflicted, zero usable). */
uint64_t vcs_zcode_dht_record_store_max_sequence(
    const struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record);

/* Stream identity: same kind, namespace, genesis, provider, delegation
 * master key, and content root (transport for provider records, semantic
 * for pointers). Records of one stream supersede each other by sequence;
 * records of different streams never do. Publication slots key on this so
 * an out-of-band renewal of a live stream replaces its intention instead
 * of leaking a second permanent slot. */
bool vcs_zcode_dht_record_stream_equal(const struct vcs_zcode_dht_record *a,
                                       const struct vcs_zcode_dht_record *b);

/* Save is temp + file fsync + rename + directory fsync, mode 0600. Load
 * verifies the complete image into a temporary store before replacing the
 * destination, so malformed/cross-network/torn images leave memory intact. */
enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_save(
    const struct vcs_zcode_dht_record_store *store, const char *datadir,
    char *error_out, size_t error_capacity);
enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_load(
    struct vcs_zcode_dht_record_store *store, const char *datadir,
    const struct vcs_zcode_dht_record_verify_context *verify,
    char *error_out, size_t error_capacity);

#endif /* ZCL_VCS_ZCODE_DHT_RECORD_STORE_H */
