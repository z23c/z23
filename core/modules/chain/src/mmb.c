/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Merkle Mountain Belt — O(1) append, O(log k) recent proofs.
 * Lazy merging: at most 1 merge per append (no domino cascade). */

#include "chain/mmb.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* The leaf preimage carries the per-height utxo_root as its last 32 bytes.
 * If this assertion fails, mmb_hash_leaf's absorb loop and the binding test
 * have drifted out of sync — every persisted leaf hash would change. */
_Static_assert(MMB_LEAF_PREIMAGE_SIZE == 140,
               "MMB leaf preimage must be 140 bytes (108 metadata + 32 utxo_root)");

/* ── Leaf construction ────────────────────────────────────── */

void mmb_leaf_from_block(struct mmb_leaf *leaf,
                         const uint8_t block_hash[32],
                         int32_t height, uint32_t timestamp,
                         uint32_t nBits,
                         const uint8_t sapling_root[32],
                         const uint8_t chain_work[32],
                         const uint8_t utxo_root[32])
{
    memcpy(leaf->block_hash, block_hash, 32);
    leaf->height = (uint32_t)height;
    leaf->timestamp = timestamp;
    leaf->nBits = nBits;
    if (sapling_root)
        memcpy(leaf->sapling_root, sapling_root, 32);
    else
        memset(leaf->sapling_root, 0, 32);
    if (chain_work)
        memcpy(leaf->chain_work, chain_work, 32);
    else
        memset(leaf->chain_work, 0, 32);
    if (utxo_root)
        memcpy(leaf->utxo_root, utxo_root, 32);
    else
        memset(leaf->utxo_root, 0, 32);
}

/* ── Hashing with domain separation ──────────────────────── */

void mmb_hash_leaf(const struct mmb_leaf *leaf, uint8_t out[32])
{
    /* SHA3-256(0x10 || block_hash || height_LE || timestamp_LE ||
     *          nBits_LE || sapling_root || chain_work || utxo_root)
     * Total preimage: 1 + 140 = 141 bytes. utxo_root is folded LAST so the
     * absorb order matches the documented field layout and the round-trip
     * sensitivity test checks that a height-H boundary leaf's auxiliary
     * utxo_root affects the exact bytes hashed. This is not a ZClassic-header
     * or PoW commitment to the UTXO contents. */
    uint8_t buf[1 + MMB_LEAF_PREIMAGE_SIZE];
    buf[0] = MMB_TAG_LEAF;
    size_t pos = 1;

    memcpy(buf + pos, leaf->block_hash, 32); pos += 32;

    /* Little-endian uint32_t fields */
    buf[pos++] = (uint8_t)(leaf->height);
    buf[pos++] = (uint8_t)(leaf->height >> 8);
    buf[pos++] = (uint8_t)(leaf->height >> 16);
    buf[pos++] = (uint8_t)(leaf->height >> 24);

    buf[pos++] = (uint8_t)(leaf->timestamp);
    buf[pos++] = (uint8_t)(leaf->timestamp >> 8);
    buf[pos++] = (uint8_t)(leaf->timestamp >> 16);
    buf[pos++] = (uint8_t)(leaf->timestamp >> 24);

    buf[pos++] = (uint8_t)(leaf->nBits);
    buf[pos++] = (uint8_t)(leaf->nBits >> 8);
    buf[pos++] = (uint8_t)(leaf->nBits >> 16);
    buf[pos++] = (uint8_t)(leaf->nBits >> 24);

    memcpy(buf + pos, leaf->sapling_root, 32); pos += 32;
    memcpy(buf + pos, leaf->chain_work, 32);   pos += 32;
    memcpy(buf + pos, leaf->utxo_root, 32);    pos += 32;

    sha3_256(buf, 1 + MMB_LEAF_PREIMAGE_SIZE, out);
}

void mmb_hash_internal(const uint8_t left[32], const uint8_t right[32],
                       uint8_t out[32])
{
    uint8_t buf[65];
    buf[0] = MMB_TAG_INTERNAL;
    memcpy(buf + 1, left, 32);
    memcpy(buf + 33, right, 32);
    sha3_256(buf, 65, out);
}

/* ── Core operations ─────────────────────────────────────── */

void mmb_init(struct mmb *m)
{
    memset(m, 0, sizeof(*m));
    m->root_dirty = true;
}

/* Shared merge logic — called after inserting a height-0 mountain.
 * Returns merge count on success, -1 if the height cap would be
 * breached (defence against in-memory corruption that bypassed
 * mmb_deserialize's input cap). */
static int mmb_merge_after_insert(struct mmb *m)
{
    int merges = 0;

    /* First: merge rightmost pair if same height */
    if (m->num_mountains >= 2) {
        uint32_t r = m->num_mountains - 1;
        if (m->mountains[r - 1].height == m->mountains[r].height) {
            if (m->mountains[r - 1].height >= MMB_MAX_HEIGHT)
                LOG_ERR("mmb", "merge: height %u would exceed cap %d (rightmost pair at idx %u) — refusing to corrupt root",
                        m->mountains[r - 1].height, MMB_MAX_HEIGHT, r - 1);
            uint8_t merged[32];
            mmb_hash_internal(m->mountains[r - 1].peak,
                              m->mountains[r].peak, merged);
            memcpy(m->mountains[r - 1].peak, merged, 32);
            m->mountains[r - 1].height++;
            m->num_mountains--;
            merges++;
        }
    }

    /* Second: scan left for one deferred mergeable pair */
    if (m->num_mountains >= 2) {
        for (uint32_t i = m->num_mountains - 1; i >= 1; i--) {
            if (m->mountains[i - 1].height == m->mountains[i].height) {
                if (m->mountains[i - 1].height >= MMB_MAX_HEIGHT)
                    LOG_ERR("mmb", "merge: height %u would exceed cap %d (deferred pair at idx %u) — refusing to corrupt root",
                            m->mountains[i - 1].height, MMB_MAX_HEIGHT, i - 1);
                uint8_t merged[32];
                mmb_hash_internal(m->mountains[i - 1].peak,
                                  m->mountains[i].peak, merged);
                memcpy(m->mountains[i - 1].peak, merged, 32);
                m->mountains[i - 1].height++;
                for (uint32_t j = i; j < m->num_mountains - 1; j++)
                    m->mountains[j] = m->mountains[j + 1];
                m->num_mountains--;
                merges++;
                break;
            }
        }
    }

    return merges;
}

int mmb_append(struct mmb *m, const struct mmb_leaf *leaf)
{
    if (m->num_mountains >= MMB_MAX_MOUNTAINS)
        LOG_ERR("mmb", "append: mountain count at max (%d)", MMB_MAX_MOUNTAINS);

    struct mmb_mountain *mt = &m->mountains[m->num_mountains];
    mmb_hash_leaf(leaf, mt->peak);
    mt->height = 0;
    m->num_mountains++;
    m->num_leaves++;
    m->root_dirty = true;

    return mmb_merge_after_insert(m);
}

int mmb_append_hash(struct mmb *m, const uint8_t leaf_hash[32])
{
    if (m->num_mountains >= MMB_MAX_MOUNTAINS)
        LOG_ERR("mmb", "append_hash: mountain count at max (%d)", MMB_MAX_MOUNTAINS);

    struct mmb_mountain *mt = &m->mountains[m->num_mountains];
    memcpy(mt->peak, leaf_hash, 32);
    mt->height = 0;
    m->num_mountains++;
    m->num_leaves++;
    m->root_dirty = true;

    return mmb_merge_after_insert(m);
}

void mmb_root(const struct mmb *m, uint8_t out[32])
{
    if (m->num_mountains == 0) {
        memset(out, 0, 32);
        return;
    }

    /* Check cache */
    if (!m->root_dirty) {
        memcpy(out, m->root_cache, 32);
        return;
    }

    if (m->num_mountains == 1) {
        memcpy(out, m->mountains[0].peak, 32);
    } else {
        /* Bag all peaks: SHA3(0x14 || peak_0 || ... || peak_k) */
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        uint8_t tag = MMB_TAG_ROOT;
        sha3_256_write(&ctx, &tag, 1);
        for (uint32_t i = 0; i < m->num_mountains; i++)
            sha3_256_write(&ctx, m->mountains[i].peak, 32);
        sha3_256_finalize(&ctx, out);
    }

    /* Update cache (cast away const for caching — safe because
     * root_cache is a mutable cache field) */
    struct mmb *mut = (struct mmb *)m;
    memcpy(mut->root_cache, out, 32);
    mut->root_dirty = false;
}

/* ── Serialization ───────────────────────────────────────── */

size_t mmb_serialize(const struct mmb *m, uint8_t *buf, size_t buflen)
{
    /* version(1) + num_leaves(8) + num_mountains(4) +
     * N × (peak[32] + height[4]) */
    size_t needed = 1 + 8 + 4 + m->num_mountains * 36;
    if (buflen < needed) return 0;

    size_t pos = 0;

    /* Version byte */
    buf[pos++] = 0x01;

    /* num_leaves (LE 64-bit) */
    uint64_t nl = m->num_leaves;
    for (int i = 0; i < 8; i++) { buf[pos++] = (uint8_t)nl; nl >>= 8; }

    /* num_mountains (LE 32-bit) */
    uint32_t nm = m->num_mountains;
    for (int i = 0; i < 4; i++) { buf[pos++] = (uint8_t)nm; nm >>= 8; }

    /* Each mountain: peak[32] + height[4] */
    for (uint32_t i = 0; i < m->num_mountains; i++) {
        memcpy(buf + pos, m->mountains[i].peak, 32); pos += 32;
        uint32_t h = m->mountains[i].height;
        for (int j = 0; j < 4; j++) { buf[pos++] = (uint8_t)h; h >>= 8; }
    }

    return pos;
}

bool mmb_deserialize(struct mmb *m, const uint8_t *buf, size_t len)
{
    mmb_init(m);
    if (len < 13)
        LOG_FAIL("mmb", "deserialize: buffer too short (%zu < 13)", len);

    size_t pos = 0;

    /* Version check */
    if (buf[pos] != 0x01)
        LOG_FAIL("mmb", "deserialize: unsupported version 0x%02x", buf[pos]);
    pos++;

    /* num_leaves */
    m->num_leaves = 0;
    for (int i = 7; i >= 0; i--)
        m->num_leaves = (m->num_leaves << 8) | buf[pos + i];
    pos += 8;

    /* num_mountains */
    uint32_t nm = 0;
    for (int i = 3; i >= 0; i--)
        nm = (nm << 8) | buf[pos + i];
    pos += 4;

    if (nm > MMB_MAX_MOUNTAINS)
        LOG_FAIL("mmb", "deserialize: mountain count %u exceeds max %d", nm, MMB_MAX_MOUNTAINS);
    if (len < pos + nm * 36)
        LOG_FAIL("mmb", "deserialize: buffer too short for %u mountains", nm);

    m->num_mountains = nm;
    for (uint32_t i = 0; i < nm; i++) {
        memcpy(m->mountains[i].peak, buf + pos, 32); pos += 32;
        uint32_t h = 0;
        for (int j = 3; j >= 0; j--)
            h = (h << 8) | buf[pos + j];
        pos += 4;
        if (h > MMB_MAX_HEIGHT) {
            mmb_init(m);
            LOG_FAIL("mmb", "deserialize: mountain[%u] height %u exceeds cap %d",
                     i, h, MMB_MAX_HEIGHT);
        }
        m->mountains[i].height = h;
    }

    m->root_dirty = true;
    return true;
}

/* ── Inclusion proofs ────────────────────────────────────── */

bool mmb_prove(const uint8_t (*all_leaf_hashes)[32],
               uint64_t num_leaves,
               uint64_t leaf_index,
               struct mmb_proof *proof)
{
    if (!all_leaf_hashes || !proof || leaf_index >= num_leaves)
        LOG_FAIL("mmb", "prove: invalid args (hashes=%p, proof=%p, index=%lu/%lu)",
                 (const void *)all_leaf_hashes, (const void *)proof,
                 (unsigned long)leaf_index, (unsigned long)num_leaves);

    memset(proof, 0, sizeof(*proof));
    proof->leaf_index = leaf_index;
    proof->mmb_size = num_leaves;
    memcpy(proof->leaf_hash, all_leaf_hashes[leaf_index], 32);

    /* Rebuild MMB using the same append logic as mmb_append(),
     * tracking the authentication path for the target leaf.
     * We track which stack entry contains the target and record
     * siblings whenever the target participates in a merge. */
    uint8_t stack[MMB_MAX_MOUNTAINS][32];
    uint32_t stack_heights[MMB_MAX_MOUNTAINS];
    uint64_t stack_first[MMB_MAX_MOUNTAINS];
    uint32_t sp = 0;
    int target_sp = -1;
    uint32_t sib_count = 0;

    /* Record left/right bits for verification */
    uint64_t lr_bits = 0; /* bit i: 0 = target is left child, 1 = right */

    for (uint64_t i = 0; i < num_leaves; i++) {
        memcpy(stack[sp], all_leaf_hashes[i], 32);
        stack_heights[sp] = 0;
        stack_first[sp] = i;
        if (i == leaf_index) target_sp = (int)sp;
        sp++;

        /* Rightmost merge */
        if (sp >= 2 && stack_heights[sp - 2] == stack_heights[sp - 1]) {
            uint32_t a = sp - 2, b = sp - 1;
            if (target_sp == (int)b) {
                memcpy(proof->siblings[sib_count], stack[a], 32);
                lr_bits |= (1ULL << sib_count);  /* target is right */
                sib_count++;
                target_sp = (int)a;
            } else if (target_sp == (int)a) {
                memcpy(proof->siblings[sib_count], stack[b], 32);
                /* target is left, bit stays 0 */
                sib_count++;
            }
            uint8_t merged[32];
            mmb_hash_internal(stack[a], stack[b], merged);
            memcpy(stack[a], merged, 32);
            stack_heights[a]++;
            sp--;
        }

        /* Deferred merge: scan left for one more mergeable pair */
        if (sp >= 2) {
            for (uint32_t k = sp - 1; k >= 1; k--) {
                if (stack_heights[k - 1] == stack_heights[k]) {
                    uint32_t a = k - 1, b = k;
                    if (target_sp == (int)b) {
                        memcpy(proof->siblings[sib_count], stack[a], 32);
                        lr_bits |= (1ULL << sib_count);
                        sib_count++;
                        target_sp = (int)a;
                    } else if (target_sp == (int)a) {
                        memcpy(proof->siblings[sib_count], stack[b], 32);
                        sib_count++;
                    }
                    uint8_t merged[32];
                    mmb_hash_internal(stack[a], stack[b], merged);
                    memcpy(stack[a], merged, 32);
                    stack_heights[a]++;
                    /* Shift right */
                    for (uint32_t j = b; j < sp - 1; j++) {
                        stack_heights[j] = stack_heights[j + 1];
                        memcpy(stack[j], stack[j + 1], 32);
                        stack_first[j] = stack_first[j + 1];
                    }
                    sp--;
                    /* Adjust target_sp if it was shifted */
                    if (target_sp > (int)b) target_sp--;
                    break;
                }
            }
        }
    }

    proof->num_siblings = sib_count;

    /* num_leaves < 2^40 and sib_count < 24, so pack both into mmb_size. */
    /* Pack: low 40 bits = num_leaves, bits 40-63 = lr_bits */
    proof->mmb_size = (num_leaves & 0xFFFFFFFFFFULL) |
                      ((lr_bits & 0xFFFFFFULL) << 40);

    /* Record all peaks */
    proof->num_peaks = sp;
    for (uint32_t i = 0; i < sp; i++)
        memcpy(proof->peaks[i], stack[i], 32);

    return true;
}

bool mmb_verify(const struct mmb_proof *proof,
                const uint8_t expected_root[32])
{
    if (!proof || !expected_root)
        LOG_FAIL("mmb", "verify: NULL argument (proof=%p, root=%p)",
                 (const void *)proof, (const void *)expected_root);
    if (proof->num_peaks == 0)
        LOG_FAIL("mmb", "verify: proof has zero peaks");

    /* Unpack lr_bits from mmb_size (low 40 = num_leaves, bits 40+ = lr) */
    uint64_t lr_bits = (proof->mmb_size >> 40) & 0xFFFFFFULL;

    /* Reconstruct target peak from leaf + siblings using lr_bits */
    uint8_t current[32];
    memcpy(current, proof->leaf_hash, 32);

    for (uint32_t i = 0; i < proof->num_siblings; i++) {
        uint8_t merged[32];
        if (lr_bits & (1ULL << i)) {
            /* Target was right child; sibling is left */
            mmb_hash_internal(proof->siblings[i], current, merged);
        } else {
            /* Target was left child; sibling is right */
            mmb_hash_internal(current, proof->siblings[i], merged);
        }
        memcpy(current, merged, 32);
    }

    /* Check if reconstructed hash matches any peak */
    bool peak_found = false;
    for (uint32_t p = 0; p < proof->num_peaks; p++) {
        if (memcmp(current, proof->peaks[p], 32) == 0) {
            peak_found = true;
            break;
        }
    }
    if (!peak_found)
        LOG_FAIL("mmb", "verify: reconstructed hash does not match any peak");

    /* Bag all peaks and verify root */
    uint8_t computed_root[32];
    if (proof->num_peaks == 1) {
        memcpy(computed_root, proof->peaks[0], 32);
    } else {
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        uint8_t tag = MMB_TAG_ROOT;
        sha3_256_write(&ctx, &tag, 1);
        for (uint32_t i = 0; i < proof->num_peaks; i++)
            sha3_256_write(&ctx, proof->peaks[i], 32);
        sha3_256_finalize(&ctx, computed_root);
    }

    return memcmp(computed_root, expected_root, 32) == 0;
}
