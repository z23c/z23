/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private SLH-DSA parameter table, ADRS, hash and tree interfaces. */
#ifndef ZCL_SLHDSA_INTERNAL_H
#define ZCL_SLHDSA_INTERNAL_H

#include "slhdsa/slhdsa_kat.h"
#include "base/serialize_le.h"

#include <string.h>

enum {
    SLH_MAX_N = 24,
    SLH_MAX_LEN = 51,   /* WOTS+ chains: 2n + 3 */
    SLH_MAX_K = 17,
    SLH_MAX_M = 39,
    SLH_LG_W = 4,
    SLH_W = 16,
    SLH_LEN2 = 3,
    SLH_RATE = 136,     /* SHAKE256 rate in bytes */
    SLH_ADRS_SIZE = 32
};

/* FIPS 205 Table 2 (SHAKE rows) plus derived sizes. */
struct slh_params {
    unsigned n, h, d, hp, a, k, len, m;
    size_t fors_size;   /* k * (a + 1) * n */
    size_t xmss_size;   /* (len + hp) * n */
    size_t sig_size;
};

[[nodiscard]] const struct slh_params *slh_params_get(enum zcl_slhdsa_param param);

/* FIPS 205 Section 4.2 address, SHAKE form (full 32 bytes, big-endian words):
 * 0 layer, 4..15 tree, 16 type, 20 key pair, 24 chain/tree height,
 * 28 hash/tree index. */
struct slh_adrs {
    uint8_t b[SLH_ADRS_SIZE];
};

enum {
    SLH_ADRS_WOTS_HASH = 0,
    SLH_ADRS_WOTS_PK = 1,
    SLH_ADRS_TREE = 2,
    SLH_ADRS_FORS_TREE = 3,
    SLH_ADRS_FORS_ROOTS = 4,
    SLH_ADRS_WOTS_PRF = 5,
    SLH_ADRS_FORS_PRF = 6
};

static inline void slh_adrs_put32(struct slh_adrs *a, unsigned off, uint32_t v)
{
    zcl_write_u32_be(a->b + off, v);
}

static inline uint32_t slh_adrs_get32(const struct slh_adrs *a, unsigned off)
{
    return zcl_read_u32_be(a->b + off);
}

static inline void slh_adrs_set_layer(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 0, v);
}

static inline void slh_adrs_set_tree(struct slh_adrs *a, uint64_t t)
{
    slh_adrs_put32(a, 4, 0);
    slh_adrs_put32(a, 8, (uint32_t)(t >> 32));
    slh_adrs_put32(a, 12, (uint32_t)t);
}

static inline void slh_adrs_set_type(struct slh_adrs *a, uint32_t type)
{
    slh_adrs_put32(a, 16, type);
    memset(a->b + 20, 0, 12);
}

static inline void slh_adrs_set_keypair(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 20, v);
}

static inline uint32_t slh_adrs_keypair(const struct slh_adrs *a)
{
    return slh_adrs_get32(a, 20);
}

static inline void slh_adrs_set_chain(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 24, v);
}

static inline void slh_adrs_set_height(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 24, v);
}

static inline void slh_adrs_set_hash(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 28, v);
}

static inline void slh_adrs_set_index(struct slh_adrs *a, uint32_t v)
{
    slh_adrs_put32(a, 28, v);
}

static inline uint32_t slh_adrs_index(const struct slh_adrs *a)
{
    return slh_adrs_get32(a, 28);
}

/* Incremental SHAKE256 over the public Keccak-f[1600] permutation. */
struct slh_xof {
    uint64_t st[25];
    uint8_t buf[SLH_RATE];
    size_t fill;
};

void slh_xof_init(struct slh_xof *x);
void slh_xof_absorb(struct slh_xof *x, const uint8_t *data, size_t len);
/* Pads, squeezes out_len bytes, and wipes the whole state. */
void slh_xof_finish(struct slh_xof *x, uint8_t *out, size_t out_len);

/* Hashing context: parameters, PK.seed and (for signing) SK.seed. */
struct slh_ctx {
    const struct slh_params *p;
    const uint8_t *pk_seed;
    const uint8_t *sk_seed;
};

/* Two-part message so M' = header || M needs no copy. */
struct slh_msg {
    const uint8_t *head;
    size_t head_len;
    const uint8_t *body;
    size_t body_len;
};

/* F, H and T_l of FIPS 205 Section 11.1: SHAKE256(PK.seed || ADRS || in), n bytes.
 * out may alias in. */
void slh_hash(const struct slh_ctx *c, const struct slh_adrs *a,
              const uint8_t *in, size_t in_len, uint8_t *out);
/* PRF(PK.seed, SK.seed, ADRS). */
void slh_prf(const struct slh_ctx *c, const struct slh_adrs *a, uint8_t *out);
/* PRF_msg(SK.prf, opt_rand, M). */
void slh_prf_msg(const struct slh_params *p, const uint8_t *sk_prf,
                 const uint8_t *opt_rand, const struct slh_msg *m, uint8_t *out);
/* H_msg(R, PK.seed, PK.root, M): m bytes. */
void slh_h_msg(const struct slh_params *p, const uint8_t *r,
               const uint8_t *pk_seed, const uint8_t *pk_root,
               const struct slh_msg *m, uint8_t *out);

/* FIPS 205 Algorithm 4. */
void slh_base_2b(const uint8_t *x, unsigned b, unsigned out_len, uint32_t *out);

/* WOTS+ (Algorithms 5-8). a must be type WOTS_HASH with layer, tree and key
 * pair set. sig has len * n bytes. */
void slh_wots_pkgen(const struct slh_ctx *c, struct slh_adrs *a, uint8_t *pk);
void slh_wots_sign(const struct slh_ctx *c, const uint8_t *m,
                   struct slh_adrs *a, uint8_t *sig);
void slh_wots_pk_from_sig(const struct slh_ctx *c, const uint8_t *sig,
                          const uint8_t *m, struct slh_adrs *a, uint8_t *pk);

/* Climbs an authentication path: a already holds the tree index of the leaf
 * (type TREE or FORS_TREE); node holds the leaf and receives the root. */
void slh_climb(const struct slh_ctx *c, struct slh_adrs *a, uint8_t *node,
               const uint8_t *auth, unsigned levels);

/* XMSS and hypertree (Algorithms 9-13). base holds layer and tree address. */
void slh_xmss_node(const struct slh_ctx *c, uint32_t i, unsigned z,
                   const struct slh_adrs *base, uint8_t *out);
void slh_ht_sign(const struct slh_ctx *c, const uint8_t *m,
                 uint64_t idx_tree, uint32_t idx_leaf, uint8_t *sig_ht);
[[nodiscard]] bool slh_ht_verify(const struct slh_ctx *c, const uint8_t *m,
                                 const uint8_t *sig_ht, uint64_t idx_tree,
                                 uint32_t idx_leaf, const uint8_t *pk_root);

/* FORS (Algorithms 14-17). a is type FORS_TREE with layer, tree, key pair set. */
void slh_fors_sign(const struct slh_ctx *c, const uint8_t *md,
                   struct slh_adrs *a, uint8_t *sig);
void slh_fors_pk_from_sig(const struct slh_ctx *c, const uint8_t *sig,
                          const uint8_t *md, struct slh_adrs *a, uint8_t *pk);

#endif /* ZCL_SLHDSA_INTERNAL_H */
