/* Copyright (c) 2016 John Tromp, The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Equihash solver — pure C23 port of Tromp's bucket-based Wagner algorithm.
 * Hardcoded for N=192, K=7 with RESTBITS=4. */

#include "crypto/equihash_solver.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* Slot layout: word[0] = tree attr, word[1..] = hash data.
 * Tree packing: (bucket_id << 12) | (slot0 << 6) | slot1 */

static inline uint32_t tree_make(uint32_t bid, uint32_t s0, uint32_t s1)
{
    return (((bid << EH_SLOTBITS) | s0) << EH_SLOTBITS) | s1;
}

static inline uint32_t tree_bid(uint32_t t)
{
    return t >> (2 * EH_SLOTBITS);
}

static inline uint32_t tree_s0(uint32_t t)
{
    return (t >> EH_SLOTBITS) & EH_SLOTMASK;
}

static inline uint32_t tree_s1(uint32_t t)
{
    return t & EH_SLOTMASK;
}

/* Slot access in overlapping heap layout */
static inline uint32_t *slot0_at(const struct eh_solver *s, uint32_t half_r,
                                  uint32_t bid, uint32_t sid)
{
    return s->heap0 + half_r +
           ((size_t)bid * EH_NSLOTS + sid) * EH_SLOT0_WORDS;
}

static inline uint32_t *slot1_at(const struct eh_solver *s, uint32_t half_r,
                                  uint32_t bid, uint32_t sid)
{
    return s->heap1 + half_r +
           ((size_t)bid * EH_NSLOTS + sid) * EH_SLOT1_WORDS;
}

static inline uint8_t *slot_hash_bytes(uint32_t *slot)
{
    return (uint8_t *)(slot + 1);
}

/* Per-round hash sizes for N=192, K=7.
 * hashbits(r) = 192 - (r+1)*24 + 4 */
static const struct {
    uint32_t hashbytes;
    uint32_t hashwords;
    uint32_t byte_off;
} round_info[EH_K + 1] = {
    { 22, 6, 2 },  /* r=0: hashbits=172 */
    { 19, 5, 1 },  /* r=1: hashbits=148 */
    { 16, 4, 0 },  /* r=2: hashbits=124 */
    { 13, 4, 3 },  /* r=3: hashbits=100 */
    { 10, 3, 2 },  /* r=4: hashbits=76  */
    {  7, 2, 1 },  /* r=5: hashbits=52  */
    {  4, 1, 0 },  /* r=6: hashbits=28  */
    {  0, 0, 0 },  /* sentinel          */
};

/* Collision data for tracking xhash slots */
struct collisiondata {
    uint8_t nxhashslots[EH_NRESTS];
    uint8_t xhashslots[EH_NRESTS][EH_XFULL];
    uint8_t *xx;
    uint32_t n0;
    uint32_t n1;
};

static inline void cd_clear(struct collisiondata *cd)
{
    memset(cd->nxhashslots, 0, EH_NRESTS);
}

static inline bool cd_addslot(struct collisiondata *cd, uint32_t s1,
                               uint32_t xh)
{
    cd->n1 = cd->nxhashslots[xh]++;
    if (cd->n1 >= EH_XFULL)
        return false;
    cd->xx = cd->xhashslots[xh];
    cd->xx[cd->n1] = (uint8_t)s1;
    cd->n0 = 0;
    return true;
}

static inline bool cd_next(const struct collisiondata *cd)
{
    return cd->n0 < cd->n1;
}

static inline uint32_t cd_slot(struct collisiondata *cd)
{
    return cd->xx[cd->n0++];
}

/* Extract 20-bit bucket ID from hash bytes.
 * For N=192, DIGITBITS=24, BUCKBITS=20: top 20 bits of 3 bytes. */
static inline uint32_t bucket_from_hash(const uint8_t *ph)
{
    return ((((uint32_t)ph[0] << 8) | ph[1]) << 4) | (ph[2] >> 4);
}

/* Extract 4-bit xhash from slot hash bytes at given byte offset.
 * For N=192, DIGITBITS=24 (multiple of 8): always low nibble. */
static inline uint32_t getxhash(const uint8_t *hash_bytes, uint32_t prevbo)
{
    return hash_bytes[prevbo] & 0xf;
}

/* Extract 20-bit xor-bucket ID from XOR of two hash byte streams.
 * After xhash at prevbo, the next 20 bits are at prevbo+1..prevbo+3. */
static inline uint32_t xorbucketid(const uint8_t *b0, const uint8_t *b1,
                                    uint32_t prevbo)
{
    return ((((uint32_t)((b0[prevbo + 1] ^ b1[prevbo + 1])) << 8)
                      | (b0[prevbo + 2] ^ b1[prevbo + 2])) << 4)
                      | ((b0[prevbo + 3] ^ b1[prevbo + 3]) >> 4);
}

static inline uint32_t eh_min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t getslot(struct eh_solver *s, uint32_t r, uint32_t bid)
{
    return s->nslot_counts[(r & 1) * EH_NBUCKETS + bid]++;
}

static uint32_t getnslots(struct eh_solver *s, uint32_t r, uint32_t bid)
{
    uint32_t *ns = &s->nslot_counts[(r & 1) * EH_NBUCKETS + bid];
    uint32_t n = eh_min(*ns, EH_NSLOTS);
    *ns = 0;
    return n;
}

/* Index reconstruction: walk tree back to leaf indices */
static void listindices0(const struct eh_solver *s, uint32_t r, uint32_t t,
                           uint32_t *indices);
static void listindices1(const struct eh_solver *s, uint32_t r, uint32_t t,
                           uint32_t *indices);

static void orderindices(uint32_t *indices, uint32_t size)
{
    if (indices[0] > indices[size]) {
        for (uint32_t i = 0; i < size; i++) {
            uint32_t tmp = indices[i];
            indices[i] = indices[size + i];
            indices[size + i] = tmp;
        }
    }
}

static void listindices0(const struct eh_solver *s, uint32_t r, uint32_t t,
                           uint32_t *indices)
{
    if (r == 0) {
        *indices = t;
        return;
    }
    r--;
    uint32_t bid = tree_bid(t);
    uint32_t s0 = tree_s0(t);
    uint32_t s1 = tree_s1(t);
    const uint32_t *sl0 = slot1_at(s, r / 2, bid, s0);
    const uint32_t *sl1 = slot1_at(s, r / 2, bid, s1);
    uint32_t size = 1u << r;
    listindices1(s, r, sl0[0], indices);
    listindices1(s, r, sl1[0], indices + size);
    orderindices(indices, size);
}

static void listindices1(const struct eh_solver *s, uint32_t r, uint32_t t,
                           uint32_t *indices)
{
    r--;
    uint32_t bid = tree_bid(t);
    uint32_t s0 = tree_s0(t);
    uint32_t s1 = tree_s1(t);
    const uint32_t *sl0 = slot0_at(s, r / 2, bid, s0);
    const uint32_t *sl1 = slot0_at(s, r / 2, bid, s1);
    uint32_t size = 1u << r;
    listindices0(s, r, sl0[0], indices);
    listindices0(s, r, sl1[0], indices + size);
    orderindices(indices, size);
}

static int compu32(const void *pa, const void *pb)
{
    uint32_t a = *(const uint32_t *)pa;
    uint32_t b = *(const uint32_t *)pb;
    return a < b ? -1 : a == b ? 0 : 1;
}

static void candidate(struct eh_solver *s, uint32_t t)
{
    uint32_t prf[EH_PROOFSIZE];
    /* K=7 is odd, so top-level tree is in slot0 → use listindices1 */
    listindices1(s, EH_K, t, prf);

    /* Check for duplicates */
    uint32_t sorted[EH_PROOFSIZE];
    memcpy(sorted, prf, sizeof(prf));
    qsort(sorted, EH_PROOFSIZE, sizeof(uint32_t), compu32);
    for (uint32_t i = 1; i < EH_PROOFSIZE; i++)
        if (sorted[i] <= sorted[i - 1])
            return;

    uint32_t soli = s->nsols++;
    if (soli < EH_MAXSOLS) {
        listindices1(s, EH_K, t, s->sols[soli]);
    }
}

/* Round 0: generate initial hashes and distribute to buckets */
static void digit0(struct eh_solver *s)
{
    uint8_t hash[EH_HASHOUT];
    struct blake2b_ctx state;
    uint32_t hashbytes = round_info[0].hashbytes;
    uint32_t nextbo = round_info[0].byte_off;

    for (uint32_t block = 0; block < EH_NBLOCKS; block++) {
        state = s->blake_ctx;
        uint32_t leb = block;
        blake2b_update(&state, &leb, sizeof(uint32_t));
        blake2b_final(&state, hash, EH_HASHOUT);

        for (uint32_t i = 0; i < EH_HASHPERBLAKE; i++) {
            const uint8_t *ph = hash + i * EH_N / 8;
            uint32_t bucketid = bucket_from_hash(ph);
            uint32_t slot = getslot(s, 0, bucketid);
            if (slot >= EH_NSLOTS) {
                s->bfull++;
                continue;
            }
            uint32_t *sl = slot0_at(s, 0, bucketid, slot);
            sl[0] = block * EH_HASHPERBLAKE + i;
            memcpy(slot_hash_bytes(sl) + nextbo,
                   ph + EH_N / 8 - hashbytes, hashbytes);
        }
    }
}

/* Odd round: read from slot0 (even), write to slot1 (odd) */
static void digitodd(struct eh_solver *s, uint32_t r)
{
    uint32_t prevhashunits = round_info[r - 1].hashwords;
    uint32_t nexthashunits = round_info[r].hashwords;
    uint32_t dunits = prevhashunits - nexthashunits;
    uint32_t prevbo = round_info[r - 1].byte_off;
    uint32_t half_r_prev = (r - 1) / 2;
    uint32_t half_r_next = r / 2;

    struct collisiondata cd;
    for (uint32_t bucketid = 0; bucketid < EH_NBUCKETS; bucketid++) {
        cd_clear(&cd);
        uint32_t bsize = getnslots(s, r - 1, bucketid);
        for (uint32_t s1 = 0; s1 < bsize; s1++) {
            const uint32_t *pslot1 = slot0_at(s, half_r_prev, bucketid, s1);
            uint32_t xh = getxhash(slot_hash_bytes((uint32_t *)pslot1),
                                    prevbo);
            if (!cd_addslot(&cd, s1, xh)) {
                s->xfull++;
                continue;
            }
            while (cd_next(&cd)) {
                uint32_t s0idx = cd_slot(&cd);
                const uint32_t *pslot0 = slot0_at(s, half_r_prev,
                                                    bucketid, s0idx);
                /* Check for hash equality (would mean duplicate) */
                if (pslot0[prevhashunits] == pslot1[prevhashunits]) {
                    s->hfull++;
                    continue;
                }
                const uint8_t *b0 = slot_hash_bytes((uint32_t *)pslot0);
                const uint8_t *b1 = slot_hash_bytes((uint32_t *)pslot1);
                uint32_t xbid = xorbucketid(b0, b1, prevbo);
                uint32_t xorslot = getslot(s, r, xbid);
                if (xorslot >= EH_NSLOTS) {
                    s->bfull++;
                    continue;
                }
                uint32_t *xs = slot1_at(s, half_r_next, xbid, xorslot);
                xs[0] = tree_make(bucketid, s0idx, s1);
                const uint32_t *h0 = pslot0 + 1;
                const uint32_t *h1 = pslot1 + 1;
                uint32_t *xh_out = xs + 1;
                for (uint32_t j = dunits; j < prevhashunits; j++)
                    xh_out[j - dunits] = h0[j] ^ h1[j];
            }
        }
    }
}

/* Even round: read from slot1 (odd), write to slot0 (even) */
static void digiteven(struct eh_solver *s, uint32_t r)
{
    uint32_t prevhashunits = round_info[r - 1].hashwords;
    uint32_t nexthashunits = round_info[r].hashwords;
    uint32_t dunits = prevhashunits - nexthashunits;
    uint32_t prevbo = round_info[r - 1].byte_off;
    uint32_t half_r_prev = (r - 1) / 2;
    uint32_t half_r_next = r / 2;

    struct collisiondata cd;
    for (uint32_t bucketid = 0; bucketid < EH_NBUCKETS; bucketid++) {
        cd_clear(&cd);
        uint32_t bsize = getnslots(s, r - 1, bucketid);
        for (uint32_t s1 = 0; s1 < bsize; s1++) {
            const uint32_t *pslot1 = slot1_at(s, half_r_prev, bucketid, s1);
            uint32_t xh = getxhash(slot_hash_bytes((uint32_t *)pslot1),
                                    prevbo);
            if (!cd_addslot(&cd, s1, xh)) {
                s->xfull++;
                continue;
            }
            while (cd_next(&cd)) {
                uint32_t s0idx = cd_slot(&cd);
                const uint32_t *pslot0 = slot1_at(s, half_r_prev,
                                                    bucketid, s0idx);
                if (pslot0[prevhashunits] == pslot1[prevhashunits]) {
                    s->hfull++;
                    continue;
                }
                const uint8_t *b0 = slot_hash_bytes((uint32_t *)pslot0);
                const uint8_t *b1 = slot_hash_bytes((uint32_t *)pslot1);
                uint32_t xbid = xorbucketid(b0, b1, prevbo);
                uint32_t xorslot = getslot(s, r, xbid);
                if (xorslot >= EH_NSLOTS) {
                    s->bfull++;
                    continue;
                }
                uint32_t *xs = slot0_at(s, half_r_next, xbid, xorslot);
                xs[0] = tree_make(bucketid, s0idx, s1);
                const uint32_t *h0 = pslot0 + 1;
                const uint32_t *h1 = pslot1 + 1;
                uint32_t *xh_out = xs + 1;
                for (uint32_t j = dunits; j < prevhashunits; j++)
                    xh_out[j - dunits] = h0[j] ^ h1[j];
            }
        }
    }
}

/* Final round K: find complete collisions */
static void digitK(struct eh_solver *s)
{
    uint32_t prevhashunits = round_info[EH_K - 1].hashwords;
    uint32_t prevbo = round_info[EH_K - 1].byte_off;
    uint32_t half_r_prev = (EH_K - 1) / 2;

    struct collisiondata cd;
    for (uint32_t bucketid = 0; bucketid < EH_NBUCKETS; bucketid++) {
        cd_clear(&cd);
        uint32_t bsize = getnslots(s, EH_K - 1, bucketid);
        for (uint32_t s1 = 0; s1 < bsize; s1++) {
            const uint32_t *pslot1 = slot0_at(s, half_r_prev, bucketid, s1);
            uint32_t xh = getxhash(slot_hash_bytes((uint32_t *)pslot1),
                                    prevbo);
            if (!cd_addslot(&cd, s1, xh))
                continue;
            while (cd_next(&cd)) {
                uint32_t s0idx = cd_slot(&cd);
                const uint32_t *pslot0 = slot0_at(s, half_r_prev,
                                                    bucketid, s0idx);
                if (pslot0[prevhashunits] == pslot1[prevhashunits])
                    candidate(s, tree_make(bucketid, s0idx, s1));
            }
        }
    }
}

struct eh_solver *eh_solver_new(void)
{
    struct eh_solver *s = zcl_calloc(1, sizeof(struct eh_solver), "eh_solver");
    if (!s) return NULL;

    size_t heap0_size = (size_t)EH_NBUCKETS * EH_NSLOTS * EH_SLOT0_WORDS;
    size_t heap1_size = (size_t)EH_NBUCKETS * EH_NSLOTS * EH_SLOT1_WORDS;

    s->heap0 = zcl_calloc(heap0_size, sizeof(uint32_t), "eh_heap0");
    s->heap1 = zcl_calloc(heap1_size, sizeof(uint32_t), "eh_heap1");
    s->nslot_counts = zcl_calloc(2 * (size_t)EH_NBUCKETS, sizeof(uint32_t), "eh_nslot_counts");

    if (!s->heap0 || !s->heap1 || !s->nslot_counts) {
        free(s->heap0);
        free(s->heap1);
        free(s->nslot_counts);
        free(s);
        return NULL;
    }
    return s;
}

void eh_solver_free(struct eh_solver *s)
{
    if (!s) return;
    free(s->heap0);
    free(s->heap1);
    free(s->nslot_counts);
    free(s);
}

void eh_solver_set_state(struct eh_solver *s, const struct blake2b_ctx *ctx)
{
    s->blake_ctx = *ctx;
    memset(s->nslot_counts, 0, (size_t)EH_NBUCKETS * sizeof(uint32_t));
    s->nsols = 0;
}

uint32_t eh_solver_run(struct eh_solver *s)
{
    s->xfull = s->bfull = s->hfull = 0;

    digit0(s);

    s->xfull = s->bfull = s->hfull = 0;
    for (uint32_t r = 1; r < EH_K; r++) {
        if (r & 1)
            digitodd(s, r);
        else
            digiteven(s, r);
        s->xfull = s->bfull = s->hfull = 0;
    }

    digitK(s);

    return eh_min(s->nsols, EH_MAXSOLS);
}
