/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Merkle Mountain Belt (MMB) — O(1) append authenticated data structure
 * over rich block metadata. Enables FlyClient-style probabilistic chain
 * verification with O(log k) proofs for k-th newest item.
 *
 * Based on: "The Merkle Mountain Belt" (Cevallos, Hambrock, Stewart 2025)
 *
 * Uses SHA3-256 with domain separation:
 *   Leaf:     SHA3-256(0x10 || block_hash || height || timestamp || nBits || sapling_root || chain_work || utxo_root)
 *   Internal: SHA3-256(0x11 || left || right)
 *   Root:     SHA3-256(0x14 || peak_0 || peak_1 || ... || peak_k)
 *
 * Key advantage over MMR: O(1) append via lazy merging (max 1 merge per append).
 * Recent items get shorter proofs: O(log k) for k-th newest vs O(log n) always.
 */

#ifndef ZCL_CHAIN_MMB_H
#define ZCL_CHAIN_MMB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MMB_HASH_SIZE     32
#define MMB_MAX_MOUNTAINS 64   /* supports 2^64 leaves */
/* Per-mountain height cap. For any plausible chain,
 * mountain height ≤ ⌈log2(num_leaves)⌉ ≤ 64. The cap bounds the
 * deserialize input (defence in depth for fast-sync/swarm paths
 * hash-binds the blob) and bounds in-memory merges so
 * an unsigned wraparound can never silently corrupt the trust root. */
#define MMB_MAX_HEIGHT    64

/* Domain separation tags — distinct from MMR (0x00-0x02) */
#define MMB_TAG_LEAF      0x10
#define MMB_TAG_INTERNAL  0x11
#define MMB_TAG_ROOT      0x14

/* ── Rich FlyClient leaf (ZIP-221 inspired) ───────────────── */

struct mmb_leaf {
    uint8_t  block_hash[32];     /* PoW-committed block identity */
    uint32_t height;             /* block height */
    uint32_t timestamp;          /* nTime — for difficulty adjustment proofs */
    uint32_t nBits;              /* compact difficulty target */
    uint8_t  sapling_root[32];   /* hashFinalSaplingRoot */
    uint8_t  chain_work[32];     /* cumulative PoW (arith_uint256 LE) */
    /* SHA3-256 root of the full UTXO set as it stood after this block
     * (coins_kv_commitment — the single canonical encoder, byte-identical to
     * zclassicd's gettxoutsetinfo set). Carried ONLY at boundary heights
     * (height % MMR_COMMITMENT_INTERVAL == 0); zero sentinel on the other 99
     * heights. This field is an auxiliary, peer-provided assertion: ZClassic
     * headers do not commit the MMB root or any UTXO root. Folding it into the
     * leaf detects mutation relative to that same auxiliary root, but does not
     * tie peer state to PoW or collapse the circular trust in the offered
     * root. Keep peer snapshots assisted until local full-history promotion. */
    uint8_t  utxo_root[32];
};

#define MMB_LEAF_PREIMAGE_SIZE (32 + 4 + 4 + 4 + 32 + 32 + 32)  /* 140 bytes */

/* Build a leaf from block_index fields. `utxo_root` is the per-height UTXO
 * commitment (32 bytes); pass NULL or all-zeros at non-boundary heights or
 * where the boundary root is not yet known (the sentinel). */
void mmb_leaf_from_block(struct mmb_leaf *leaf,
                         const uint8_t block_hash[32],
                         int32_t height, uint32_t timestamp,
                         uint32_t nBits,
                         const uint8_t sapling_root[32],
                         const uint8_t chain_work[32],
                         const uint8_t utxo_root[32]);

/* ── Mountain (complete binary tree) ──────────────────────── */

struct mmb_mountain {
    uint8_t  peak[MMB_HASH_SIZE];  /* root hash of this mountain */
    uint32_t height;                /* tree height (2^h leaves) */
};

/* ── The MMB structure ────────────────────────────────────── */

struct mmb {
    uint64_t num_leaves;
    struct mmb_mountain mountains[MMB_MAX_MOUNTAINS];
    uint32_t num_mountains;
    uint8_t  root_cache[MMB_HASH_SIZE];
    bool     root_dirty;
};

/* Initialize empty MMB */
void mmb_init(struct mmb *m);

/* Append a rich leaf. O(1) guaranteed: at most 1 merge.
 * Returns the number of merges (0 or 1) on success, or -1 on failure —
 * the mountain count is already at MMB_MAX_MOUNTAINS, or a merge would push
 * a peak past MMB_MAX_HEIGHT (refused to avoid corrupting the root). */
int mmb_append(struct mmb *m, const struct mmb_leaf *leaf);

/* Append a pre-computed leaf hash (from mmb_hash_leaf or leaf store).
 * Same merge logic as mmb_append, skips the hash step. Returns 0 or 1
 * merges on success, or -1 on the same overflow conditions as mmb_append. */
int mmb_append_hash(struct mmb *m, const uint8_t leaf_hash[32]);

/* Compute the MMB root from current peaks.
 * Caches result; subsequent calls without append are O(1). */
void mmb_root(const struct mmb *m, uint8_t out[32]);

/* Hash a rich leaf (exposed for testing/proofs) */
void mmb_hash_leaf(const struct mmb_leaf *leaf, uint8_t out[32]);

/* Hash two children into a parent */
void mmb_hash_internal(const uint8_t left[32], const uint8_t right[32],
                       uint8_t out[32]);

/* ── Serialization ─────────────────────────────────────── */

/* Serialized: version(1) + num_leaves(8) + num_mountains(4) +
 *             mountains[N] × (peak[32] + height[4]) */
#define MMB_SERIALIZED_MAX (1 + 8 + 4 + MMB_MAX_MOUNTAINS * 36)

size_t mmb_serialize(const struct mmb *m, uint8_t *buf, size_t buflen);
bool mmb_deserialize(struct mmb *m, const uint8_t *buf, size_t len);

/* ── Inclusion proofs ──────────────────────────────────── */

struct mmb_proof {
    uint64_t leaf_index;                          /* 0-based leaf index */
    uint8_t  leaf_hash[MMB_HASH_SIZE];            /* SHA3(0x10 || leaf_data) */
    uint8_t  siblings[MMB_MAX_MOUNTAINS][MMB_HASH_SIZE];
    uint32_t num_siblings;
    uint8_t  peaks[MMB_MAX_MOUNTAINS][MMB_HASH_SIZE];
    uint32_t num_peaks;
    uint64_t mmb_size;                            /* packed: low 40 bits = num_leaves, bits 40-63 = lr_bits */
};

/* Generate an inclusion proof for the leaf at `leaf_index` within an MMB
 * of `num_leaves` leaves. `all_leaf_hashes` must be the full ordered
 * array of pre-hashed leaves (mmb_hash_leaf / mmb_append_hash output) —
 * the function replays the exact append+lazy-merge sequence to recover
 * the target's authentication path. On success it fills `proof` with the
 * target leaf hash, the sibling hashes along the path, the left/right
 * orientation at each step, and all peak hashes at proof time (packed
 * into `proof->mmb_size`), then returns true.
 *
 * Precondition: `leaf_index < num_leaves` and both pointers non-NULL;
 * otherwise the reason is logged and false is returned. Cost is O(n)
 * (it rebuilds the whole structure), so this is a prover-side / fast-sync
 * operation, not a per-block hot path.
 *
 * Source: src/mmb.c (mmb_prove). */
bool mmb_prove(const uint8_t (*all_leaf_hashes)[32],
               uint64_t num_leaves,
               uint64_t leaf_index,
               struct mmb_proof *proof);

/* Verify an inclusion proof against an expected MMB root.
 *
 * A true return PROVES that `proof->leaf_hash` is committed under
 * `expected_root`: i.e. folding the leaf hash up through the recorded
 * siblings (using the packed left/right bits) reproduces one of the
 * proof's peaks, AND bagging those peaks
 * (SHA3-256(0x14 || peak_0 || ... || peak_k), or the single peak
 * verbatim) equals `expected_root`. Because every hash is SHA3-256 with
 * domain separation, this is a cryptographic membership proof: only a
 * leaf actually appended to the MMB that produced `expected_root` can
 * pass.
 *
 * It does NOT by itself prove anything about the leaf's *contents* —
 * the caller must independently bind `proof->leaf_hash` to a trusted
 * mmb_hash_leaf(leaf) of the block metadata it expects. Returns false
 * (and logs) on NULL args, zero peaks, a non-matching peak, or a root
 * mismatch.
 *
 * Source: src/mmb.c (mmb_verify). */
bool mmb_verify(const struct mmb_proof *proof,
                const uint8_t expected_root[32]);

#endif
