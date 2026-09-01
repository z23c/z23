/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_snapshot_loader: runtime mmap+SHA3-verify+iterate over a
 * UTXO snapshot sidecar produced by `zclassic23 --gen-utxo-snapshot`.
 *
 * Sidecar format (see main.c gen_utxo_snapshot_mode for the writer):
 *
 *   Header (104 bytes, all little-endian):
 *     magic[8]      = "ZCLUTXO\x00"
 *     version u32   = 1
 *     reserved u32
 *     height u32    = anchor height (informational)
 *     reserved u32
 *     count u64     = number of vouts (records) that follow
 *     total_supply i64 = sum of all values in sats
 *     anchor_block_hash[32]
 *     sha3_hash[32] = SHA3-256 over the body bytes
 *
 *   Body: `count` records, each:
 *     txid[32], vout u32 LE, value i64 LE,
 *     script_len u32 LE, script[script_len],
 *     height u32 LE, is_coinbase u8
 *
 * The per-record encoding matches utxo_commitment_sha3_compute()
 * so the body sha3 equals the compile-time checkpoint when the
 * sidecar was generated at the anchor height (h=3,056,758).
 */

#ifndef ZCL_CHAIN_UTXO_SNAPSHOT_LOADER_H
#define ZCL_CHAIN_UTXO_SNAPSHOT_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct uss_header {
    uint32_t version;
    uint32_t height;
    uint64_t count;
    int64_t  total_supply;
    uint8_t  anchor_block_hash[32];
    uint8_t  sha3_hash[32];
};

struct uss_record {
    const uint8_t *txid;     /* 32 bytes */
    uint32_t       vout;
    int64_t        value;
    const uint8_t *script;
    uint32_t       script_len;
    uint32_t       height;
    uint8_t        is_coinbase;
};

/* Independently recomputed transparent component of any legacy USS v1-v3
 * import artifact. New producers target zcl.consensus_state_bundle.v1 rather
 * than extending this format again.
 * `sha3_hash` covers ONLY the canonical UTXO records, never a trailing v2/v3
 * shielded section.  This is deliberately distinct from uss_header.sha3_hash,
 * which commits the complete payload and therefore cannot be compared to the
 * compiled UTXO checkpoint once a shielded section is present. */
struct uss_utxo_component {
    uint8_t  sha3_hash[32];
    uint64_t count;
    int64_t  total_supply;
};

struct uss_handle;

/* Open a sidecar file. mmap'd MAP_PRIVATE PROT_READ.
 * On success returns a heap-allocated handle and fills *hdr.
 * Caller frees with uss_close().
 *
 * VERIFY MODE: if `verify_full_sha3` is true, the entire body is
 * SHA3-hashed up front and compared to hdr.sha3_hash. This is
 * essentially mandatory for cold-start trust — the call takes
 * ~200 ms on AVX-512 and binds the body before any UTXO is
 * inserted into the database.
 *
 * If `expected_sha3` is non-NULL, additionally compares the FULL payload
 * digest in hdr.sha3_hash to that buffer. This can bind legacy v1 (whose
 * payload is only UTXOs) to a transparent checkpoint. It must not be used to
 * compare v2/v3 full-payload digests to a transparent-only checkpoint; use
 * uss_utxo_component_compute() for that independent component. */
struct uss_handle *uss_open(const char *path,
                            bool verify_full_sha3,
                            const uint8_t *expected_sha3,
                            struct uss_header *hdr,
                            char *err, size_t err_sz);

void uss_close(struct uss_handle *h);

/* SHA256 of the exact mapped artifact bytes.  Call before uss_close(); this
 * binds header and payload bytes from the same open file description that the
 * loader verified, without reopening a mutable path. */
bool uss_artifact_sha256(const struct uss_handle *h, uint8_t out[32]);

typedef bool (*uss_record_cb)(const struct uss_record *r, void *ctx);

/* Iterate every record. Stops early if cb returns false.
 * Returns count emitted, or -1 on truncation. */
int64_t uss_iter(struct uss_handle *h, uss_record_cb cb, void *ctx);

/* Recompute the transparent component from the decoded record stream using
 * the single canonical UTXO encoder.  Returns false on truncation, malformed
 * coin values/coinbase flags, count drift, or signed supply overflow.  The
 * caller must compare all three outputs to its independently trusted
 * checkpoint; the snapshot header is not treated as that authority. */
bool uss_utxo_component_compute(struct uss_handle *h,
                                struct uss_utxo_component *out,
                                char *err, size_t err_sz);

/* Legacy import format version (1 = UTXO-only, 2 = UTXO + Sapling frontier,
 * 3 = UTXO + shielded section [Sapling + Sprout frontiers + nullifier set]).
 * These encodings remain readable for recovery compatibility but are frozen;
 * none is the canonical complete-state publishing format.
 * 0 on NULL handle. */
uint32_t uss_version(const struct uss_handle *h);

/* Expose the trailing Sapling commitment-tree frontier section, present only in
 * version-2 snapshots. On success sets *blob_out to a pointer INTO the mmap'd
 * file (valid until uss_close) and *len_out to its length, returns true. For a
 * v1 file (no section) or any truncation returns false with *blob_out=NULL,
 * *len_out=0. The blob is the incremental_tree_serialize output for the Sapling
 * tree at the snapshot's seed height; it is already covered by the body SHA3
 * verified at uss_open time. */
bool uss_frontier(struct uss_handle *h, const uint8_t **blob_out,
                  uint32_t *len_out);

/* Expose the v3 SHIELDED section (present only in version-3 snapshots): the
 * Sapling frontier, the Sprout frontier, and the packed nullifier records (each
 * SNAPSHOT_NF_RECORD_BYTES, decode with snapshot_shielded_unpack_nf). All
 * pointers point INTO the mmap'd file (valid until uss_close) and are already
 * covered by the body SHA3 verified at uss_open time. Any out-pointer may be
 * NULL. An empty region yields (NULL,0). Returns false for a v1/v2 file, a NULL
 * handle, or any truncation (with all outputs zeroed). */
bool uss_shielded(struct uss_handle *h,
                  const uint8_t **sapling_out, uint32_t *sapling_len_out,
                  const uint8_t **sprout_out,  uint32_t *sprout_len_out,
                  const uint8_t **nf_out,      uint64_t *nf_count_out);

#endif /* ZCL_CHAIN_UTXO_SNAPSHOT_LOADER_H */
