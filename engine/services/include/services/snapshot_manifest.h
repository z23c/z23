/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_SNAPSHOT_MANIFEST_H
#define ZCL_SERVICES_SNAPSHOT_MANIFEST_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core/zcl_ids.h"
#include "util/result.h"

struct byte_stream;

enum snapshot_manifest_result {
    SNAPSHOT_MANIFEST_OK = 0,
    SNAPSHOT_MANIFEST_NULL_ARG,
    SNAPSHOT_MANIFEST_TRUNCATED,
    SNAPSHOT_MANIFEST_TRAILING_BYTES,
    SNAPSHOT_MANIFEST_RANGE,
    SNAPSHOT_MANIFEST_STALE_SCHEMA,
    SNAPSHOT_MANIFEST_UNFINAL,
    SNAPSHOT_MANIFEST_WEAK_WORK,
    SNAPSHOT_MANIFEST_NO_MMR,
    SNAPSHOT_MANIFEST_NO_MMB,
    SNAPSHOT_MANIFEST_NOT_AHEAD,
};

struct snapshot_manifest {
    int32_t  height;
    uint8_t  block_hash[32];
    uint8_t  utxo_root[32];
    uint8_t  mmr_root[32];
    uint8_t  mmb_root[32];
    uint8_t  chain_work[32];
    uint64_t num_utxos;
    uint64_t total_bytes;
    uint32_t protocol_version;
    uint32_t snapshot_schema_version;
    int32_t  peer_tip_height;
};

/* zcl_ids.h adoption (additive-only): strongly-typed readers for the raw
 * fields above. Wire layout is UNCHANGED — every field stays a bare
 * int32_t/uint8_t[32] a wire memcpy/parse writes directly; these are
 * read-side aliases only. `mmr_root` has no zcl_ids wrapper (it is distinct
 * from `mmb_root` and no dedicated MMR-root type exists), and `num_utxos` /
 * `protocol_version` / `snapshot_schema_version` / `peer_tip_height` stay
 * their native scalar types on purpose: zcl_byte_count is reserved for byte
 * sizes, not item counts, so wrapping num_utxos with it would be a type
 * lie. A new dedicated wrapper type is the only way to close this gap. */
_Static_assert(sizeof(((struct snapshot_manifest *)0)->block_hash) == sizeof(struct zcl_block_hash),
               "snapshot_manifest.block_hash must stay wire-compatible with zcl_block_hash");
_Static_assert(sizeof(((struct snapshot_manifest *)0)->utxo_root) == sizeof(struct zcl_utxo_root),
               "snapshot_manifest.utxo_root must stay wire-compatible with zcl_utxo_root");
_Static_assert(sizeof(((struct snapshot_manifest *)0)->mmb_root) == sizeof(struct zcl_mmb_root),
               "snapshot_manifest.mmb_root must stay wire-compatible with zcl_mmb_root");
_Static_assert(sizeof(((struct snapshot_manifest *)0)->chain_work) == sizeof(struct zcl_chainwork_be256),
               "snapshot_manifest.chain_work must stay wire-compatible with zcl_chainwork_be256");
_Static_assert(sizeof(((struct snapshot_manifest *)0)->height) == sizeof(struct zcl_height),
               "snapshot_manifest.height must stay wire-compatible with zcl_height");
_Static_assert(sizeof(((struct snapshot_manifest *)0)->total_bytes) == sizeof(struct zcl_byte_count),
               "snapshot_manifest.total_bytes must stay wire-compatible with zcl_byte_count");

static inline struct zcl_height snapshot_manifest_height_id(const struct snapshot_manifest *m)
{
    return (struct zcl_height){ .value = m->height };
}

static inline struct zcl_block_hash snapshot_manifest_block_hash_id(const struct snapshot_manifest *m)
{
    struct zcl_block_hash h;
    memcpy(h.bytes, m->block_hash, 32);
    return h;
}

static inline struct zcl_utxo_root snapshot_manifest_utxo_root_id(const struct snapshot_manifest *m)
{
    struct zcl_utxo_root r;
    memcpy(r.bytes, m->utxo_root, 32);
    return r;
}

static inline struct zcl_mmb_root snapshot_manifest_mmb_root_id(const struct snapshot_manifest *m)
{
    struct zcl_mmb_root r;
    memcpy(r.bytes, m->mmb_root, 32);
    return r;
}

static inline struct zcl_chainwork_be256 snapshot_manifest_chain_work_id(const struct snapshot_manifest *m)
{
    struct zcl_chainwork_be256 w;
    memcpy(w.bytes, m->chain_work, 32);
    return w;
}

static inline struct zcl_byte_count snapshot_manifest_total_bytes_id(const struct snapshot_manifest *m)
{
    return (struct zcl_byte_count){ .value = m->total_bytes };
}

struct zcl_result snapshot_manifest_parse(struct snapshot_manifest *out,
                                struct byte_stream *s,
                                enum snapshot_manifest_result *result);
enum snapshot_manifest_result snapshot_manifest_validate_offer(
    const struct snapshot_manifest *m,
    int32_t our_height);
enum snapshot_manifest_result snapshot_manifest_validate_recovery(
    const struct snapshot_manifest *m,
    int32_t target_height);
const char *snapshot_manifest_result_name(
    enum snapshot_manifest_result result);

#endif /* ZCL_SERVICES_SNAPSHOT_MANIFEST_H */
