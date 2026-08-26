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
  /* Not a record-store condition at all: the service's publication intent
   * table is full of streams this publish neither belongs to nor beats.
   * Distinct from GLOBAL_CAP so an operator reading a refusal is sent to
   * the 16-slot intent table, not the 4096-record store cap. */
  VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT,
  VCS_ZCODE_DHT_RECORD_STORE_IO,
  VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
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
