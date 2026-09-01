/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Merkle Mountain Range (MMR) — append-only authenticated data structure
 * over block hashes. Enables O(log n) inclusion proofs between power nodes.
 *
 * Uses SHA3-256 with domain separation:
 *   Leaf:     SHA3-256(0x00 || block_hash)
 *   Internal: SHA3-256(0x01 || left || right)
 *   Root:     SHA3-256(0x02 || peak_0 || peak_1 || ... || peak_k)
 */

#ifndef ZCL_CHAIN_MMR_H
#define ZCL_CHAIN_MMR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MMR_HASH_SIZE 32
#define MMR_MAX_PEAKS 64  /* supports up to 2^64 leaves */

/* Domain separation tags */
#define MMR_TAG_LEAF     0x00
#define MMR_TAG_INTERNAL 0x01
#define MMR_TAG_ROOT     0x02

struct mmr {
    uint64_t num_leaves;
    uint8_t  peaks[MMR_MAX_PEAKS][MMR_HASH_SIZE];
    uint32_t num_peaks;
};

/* Initialize empty MMR */
void mmr_init(struct mmr *m);

/* Append a block hash as a new leaf. Updates peaks and returns
 * the number of new internal nodes created (for persistence). */
int mmr_append(struct mmr *m, const uint8_t block_hash[32]);

/* Compute the MMR root from current peaks */
void mmr_root(const struct mmr *m, uint8_t out[32]);

/* Hash a leaf (exposed for testing/persistence) */
void mmr_hash_leaf(const uint8_t block_hash[32], uint8_t out[32]);

/* Hash two children into a parent */
void mmr_hash_internal(const uint8_t left[32], const uint8_t right[32],
                       uint8_t out[32]);

/* ── Serialization ─────────────────────────────────────── */

/* Max serialized size: 8 (num_leaves) + 4 (num_peaks) + peaks */
#define MMR_SERIALIZED_MAX (8 + 4 + MMR_MAX_PEAKS * MMR_HASH_SIZE)

size_t mmr_serialize(const struct mmr *m, uint8_t *buf, size_t buflen);
bool mmr_deserialize(struct mmr *m, const uint8_t *buf, size_t len);

/* ── Unified commitment leaf ──────────────────────────── */
/* An auxiliary commitment leaf hashes block data + UTXO state + file chunks
 * at a given height. One leaf every COMMITMENT_INTERVAL blocks. It detects
 * mutation relative to the same supplied MMR root, but ZClassic headers do
 * not commit that root. Therefore it is evidence, not consensus authority:
 *   - block_hash:  names the validated chain location
 *   - utxo_root:   hashes the asserted UTXO set (SHA3 over all UTXOs)
 *   - data_root:   hashes the asserted raw file data (SHA3 over chunk hashes)
 *
 * A new node still needs an explicit assisted trust posture or local
 * full-history verification; MMR root + latest commitment + delta is not
 * sufficient for sovereignty.
 * Energy cost: one SHA3 per commitment (microseconds). */

#define MMR_COMMITMENT_INTERVAL 100  /* ~20 minutes between commits */

struct mmr_commitment {
    int32_t  height;            /* block height of this commitment */
    uint8_t  block_hash[32];    /* block hash at height */
    uint8_t  utxo_root[32];     /* SHA3 of UTXO set at height */
    uint8_t  data_root[32];     /* SHA3 of file chunk hashes up to height */
};

/* Hash a commitment into an MMR leaf.
 * SHA3(0x00 || height || block_hash || utxo_root || data_root) */
void mmr_hash_commitment(const struct mmr_commitment *c, uint8_t out[32]);

/* Append a commitment to the MMR (convenience wrapper) */
int mmr_append_commitment(struct mmr *m, const struct mmr_commitment *c);

#endif
