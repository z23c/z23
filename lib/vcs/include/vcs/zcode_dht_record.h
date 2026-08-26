/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical signed discovery and evidence DHT records. */

#ifndef ZCL_VCS_ZCODE_DHT_RECORD_H
#define ZCL_VCS_ZCODE_DHT_RECORD_H

#include "vcs/zcode_dht.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_RECORD_VERSION 1u
#define VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES 32u
#define VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX 31u
#define VCS_ZCODE_DHT_RECORD_SIGNATURE_BYTES 64u
#define VCS_ZCODE_DHT_RECORD_WIRE_BYTES                                  \
  (12u + VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES + 5u * 32u + 3u * 8u +    \
   VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES +                                \
   VCS_ZCODE_DHT_RECORD_SIGNATURE_BYTES)
#define VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS UINT64_C(7200)
#define VCS_ZCODE_DHT_POINTER_MAX_SECONDS UINT64_C(604800)
#define VCS_ZCODE_DHT_STORAGE_ACK_MAX_SECONDS UINT64_C(604800)
#define VCS_ZCODE_DHT_SOURCE_REPRODUCTION_ACK_MAX_SECONDS UINT64_C(604800)
#define VCS_ZCODE_DHT_AGENT_SCOPE_MAX_SECONDS UINT64_C(604800)
#define VCS_ZCODE_DHT_RECORD_SIGNATURE_DOMAIN "zcl.zcode.dht.record.v1"
#define VCS_ZCODE_DHT_RECORD_KEY_DOMAIN "zcl.zcode.dht.record-key.v1"
#define VCS_ZCODE_DHT_RECORD_ID_DOMAIN "zcl.zcode.dht.record-id.v1"

enum vcs_zcode_dht_record_kind {
  VCS_ZCODE_DHT_RECORD_PROVIDER = 1,
  VCS_ZCODE_DHT_RECORD_POINTER = 2,
  VCS_ZCODE_DHT_RECORD_STORAGE_ACK = 3,
  VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK = 4,
  /* Appended last so the values ahead of it stay stable for any future
   * numeric use; older binaries fail closed on the unknown kind byte. */
  VCS_ZCODE_DHT_RECORD_AGENT_SCOPE = 5,
};

enum vcs_zcode_dht_record_error {
  VCS_ZCODE_DHT_RECORD_OK = 0,
  VCS_ZCODE_DHT_RECORD_NULL,
  VCS_ZCODE_DHT_RECORD_SIZE,
  VCS_ZCODE_DHT_RECORD_MAGIC,
  VCS_ZCODE_DHT_RECORD_VERSION_ERROR,
  VCS_ZCODE_DHT_RECORD_KIND,
  VCS_ZCODE_DHT_RECORD_NAMESPACE,
  VCS_ZCODE_DHT_RECORD_ROOT,
  VCS_ZCODE_DHT_RECORD_OWNER_GROUP,
  VCS_ZCODE_DHT_RECORD_SEQUENCE,
  VCS_ZCODE_DHT_RECORD_WINDOW,
  /* The record's own window is well-formed but the loaded delegation does
   * not cover it — a different operator action than reshaping the record:
   * re-delegate with a longer expiry or publish a shorter window. */
  VCS_ZCODE_DHT_RECORD_DELEGATION_WINDOW,
  VCS_ZCODE_DHT_RECORD_NOT_YET_VALID,
  VCS_ZCODE_DHT_RECORD_EXPIRED,
  VCS_ZCODE_DHT_RECORD_DELEGATION,
  VCS_ZCODE_DHT_RECORD_NETWORK,
  VCS_ZCODE_DHT_RECORD_PROVIDER_ID,
  VCS_ZCODE_DHT_RECORD_SIGNER,
  VCS_ZCODE_DHT_RECORD_SIGNATURE,
  VCS_ZCODE_DHT_RECORD_CHAIN,
};

const char *vcs_zcode_dht_record_error_string(
    enum vcs_zcode_dht_record_error error);

/* namespace is canonical lower-case ASCII with a zero tail. PROVIDER and
 * STORAGE_ACK address transport_root directly and require semantic_root=0.
 * POINTER binds semantic_root -> transport_root. SOURCE_REPRODUCTION_ACK
 * binds the re-derived source semantic_root to its complete transport_root.
 * AGENT_SCOPE grants one record-signing key (transport_root) authority to
 * publish inside namespace_name under the grantor's master; semantic_root
 * and owner_group are zero. owner_group is present on both ACK kinds and is
 * explicitly declared diversity, never physical-host or separate-operator
 * proof. */
struct vcs_zcode_dht_record {
  enum vcs_zcode_dht_record_kind kind;
  char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES];
  uint8_t network_genesis[32];
  uint8_t semantic_root[32];
  uint8_t transport_root[32];
  uint8_t provider_node_id[32];
  uint8_t owner_group[32];
  uint64_t sequence;
  uint64_t not_before;
  uint64_t expiry;
  struct vcs_zcode_dht_delegation delegation;
  uint8_t signature[VCS_ZCODE_DHT_RECORD_SIGNATURE_BYTES];
};

struct vcs_zcode_dht_record_verify_context {
  uint8_t network_genesis[32];
  uint64_t now_unix;
  vcs_zcode_dht_chain_verify_fn chain_verify;
  void *chain_ctx;
};

/* Derive the Kademlia routing target for one logical record stream. `root`
 * is semantic_root for POINTER and transport_root for every other kind.
 * The fixed-size canonical namespace prevents alternate encodings from
 * routing the same stream to different responsible nodes. */
bool vcs_zcode_dht_record_key(
    const uint8_t network_genesis[32],
    enum vcs_zcode_dht_record_kind kind,
    const char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES],
    const uint8_t root[32], uint8_t out[32]);

/* Sign a fully populated record with the delegated online seed. The seed's
 * public key must equal delegation.online_pubkey. */
enum vcs_zcode_dht_record_error vcs_zcode_dht_record_sign(
    struct vcs_zcode_dht_record *record, const uint8_t online_seed[32]);

enum vcs_zcode_dht_record_error vcs_zcode_dht_record_encode(
    const struct vcs_zcode_dht_record *record,
    uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES]);

/* Root of the complete canonical signed wire. This is an evidence coordinate,
 * not a routing key: callers must still parse/verify the record before using
 * its claims. The domain includes its trailing NUL byte. */
enum vcs_zcode_dht_record_error vcs_zcode_dht_record_id(
    const struct vcs_zcode_dht_record *record, uint8_t out[32]);

/* Bounds and canonical structure are checked before delegation/signature/chain
 * work. `out` is zero on every rejection. */
enum vcs_zcode_dht_record_error vcs_zcode_dht_record_parse(
    const uint8_t *wire, size_t wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *out);

/* At-rest verification keeps expired signed evidence parseable so a rebuild
 * can prune it rather than treating ordinary expiry as store corruption.
 * Future records still reject. `expired_out` and `out` are zero on failure. */
enum vcs_zcode_dht_record_error vcs_zcode_dht_record_parse_persisted(
    const uint8_t *wire, size_t wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    bool *expired_out, struct vcs_zcode_dht_record *out);

/* True only for two distinct, valid-looking records occupying the same signed
 * sequence slot. Callers retain both as equivocation evidence. */
bool vcs_zcode_dht_record_conflicts(
    const struct vcs_zcode_dht_record *a,
    const struct vcs_zcode_dht_record *b);

/* Sequence is meaningful only inside one kind/namespace/root/master/provider
 * stream. These bounded-set helpers keep equivocation and supersession out of
 * consumer-specific global ordering. */
bool vcs_zcode_dht_record_same_stream(
    const struct vcs_zcode_dht_record *a,
    const struct vcs_zcode_dht_record *b);
bool vcs_zcode_dht_record_conflicted_at(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index);
bool vcs_zcode_dht_record_superseded_at(
    const struct vcs_zcode_dht_record *records, size_t count, size_t index);

#endif /* ZCL_VCS_ZCODE_DHT_RECORD_H */
