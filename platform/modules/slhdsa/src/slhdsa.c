/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: SLH-DSA key generation, signing and verification
 * (FIPS 205 Algorithms 18-24). */

#include "slhdsa_internal.h"

#include "base/cleanse.h"

static_assert(ZCL_SLHDSA_MAX_SIGNATURE_SIZE == 16224, "max signature");

/* Splits the H_msg digest into FORS message, tree index and leaf index
 * (Algorithm 19 lines 5-9). */
static void split_digest(const struct slh_params *p, const uint8_t *digest,
                         const uint8_t **md, uint64_t *idx_tree,
                         uint32_t *idx_leaf)
{
    const size_t md_len = ((size_t)p->k * p->a + 7) / 8;
    const size_t tree_len = (p->h - p->hp + 7) / 8;
    const size_t leaf_len = (p->hp + 7) / 8;
    uint64_t tree = 0;
    uint32_t leaf = 0;
    for (size_t i = 0; i < tree_len; i++)
        tree = (tree << 8) | digest[md_len + i];
    for (size_t i = 0; i < leaf_len; i++)
        leaf = (leaf << 8) | digest[md_len + tree_len + i];
    *md = digest;
    *idx_tree = tree & ((UINT64_C(1) << (p->h - p->hp)) - 1);
    *idx_leaf = leaf & ((1u << p->hp) - 1u);
}

static void keygen_core(const struct slh_params *p, const uint8_t *seed,
                        uint8_t *pk, uint8_t *sk)
{
    const unsigned n = p->n;
    struct slh_ctx c = {.p = p, .pk_seed = seed + 2 * n, .sk_seed = seed};
    struct slh_adrs a = {0};
    uint8_t root[SLH_MAX_N];
    slh_adrs_set_layer(&a, p->d - 1);
    slh_xmss_node(&c, 0, p->hp, &a, root);
    memcpy(sk, seed, 3u * n);
    memcpy(sk + 3u * n, root, n);
    memcpy(pk, seed + 2u * n, n);
    memcpy(pk + n, root, n);
}

enum zcl_slhdsa_status zcl_slhdsa_keygen_internal(
    enum zcl_slhdsa_param param, const uint8_t *seed, size_t seed_len,
    uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len)
{
    const struct slh_params *p = slh_params_get(param);
    if (!p || !seed || !pk || !sk)
        return ZCL_SLHDSA_ERR_ARGUMENT;
    if (seed_len != 3u * p->n || pk_len != 2u * p->n || sk_len != 4u * p->n)
        return ZCL_SLHDSA_ERR_LENGTH;
    keygen_core(p, seed, pk, sk);
    return ZCL_SLHDSA_OK;
}

enum zcl_slhdsa_status zcl_slhdsa_keygen(
    enum zcl_slhdsa_param param, zcl_slhdsa_random_fn random, void *random_ctx,
    uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len)
{
    const struct slh_params *p = slh_params_get(param);
    uint8_t seed[3 * SLH_MAX_N];
    enum zcl_slhdsa_status st;
    if (!p || !random || !pk || !sk)
        return ZCL_SLHDSA_ERR_ARGUMENT;
    if (pk_len != 2u * p->n || sk_len != 4u * p->n)
        return ZCL_SLHDSA_ERR_LENGTH;
    if (!random(random_ctx, seed, 3u * p->n)) {
        memory_cleanse(seed, sizeof(seed));
        memory_cleanse(pk, pk_len);
        memory_cleanse(sk, sk_len);
        return ZCL_SLHDSA_ERR_RANDOM;
    }
    st = zcl_slhdsa_keygen_internal(param, seed, 3u * p->n, pk, pk_len, sk,
                                    sk_len);
    memory_cleanse(seed, sizeof(seed));
    return st;
}

static void sign_core(const struct slh_params *p, const uint8_t *sk,
                      const struct slh_msg *m, const uint8_t *opt_rand,
                      uint8_t *sig)
{
    const unsigned n = p->n;
    const struct slh_ctx c = {.p = p, .pk_seed = sk + 2 * n, .sk_seed = sk};
    uint8_t digest[SLH_MAX_M], pk_fors[SLH_MAX_N];
    const uint8_t *md;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    struct slh_adrs a = {0};
    slh_prf_msg(p, sk + n, opt_rand, m, sig);
    slh_h_msg(p, sig, c.pk_seed, sk + 3u * n, m, digest);
    split_digest(p, digest, &md, &idx_tree, &idx_leaf);
    slh_adrs_set_tree(&a, idx_tree);
    slh_adrs_set_type(&a, SLH_ADRS_FORS_TREE);
    slh_adrs_set_keypair(&a, idx_leaf);
    slh_fors_sign(&c, md, &a, sig + n);
    slh_fors_pk_from_sig(&c, sig + n, md, &a, pk_fors);
    slh_ht_sign(&c, pk_fors, idx_tree, idx_leaf, sig + n + p->fors_size);
}

static enum zcl_slhdsa_status sign_checked(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const struct slh_msg *m, const uint8_t *opt_rand, uint8_t *sig,
    size_t sig_len)
{
    const struct slh_params *p = slh_params_get(param);
    if (!p || !sk || !sig || (m->head_len && !m->head) ||
        (m->body_len && !m->body))
        return ZCL_SLHDSA_ERR_ARGUMENT;
    if (sk_len != 4u * p->n || sig_len != p->sig_size)
        return ZCL_SLHDSA_ERR_LENGTH;
    sign_core(p, sk, m, opt_rand ? opt_rand : sk + 2u * p->n, sig);
    return ZCL_SLHDSA_OK;
}

enum zcl_slhdsa_status zcl_slhdsa_sign_internal(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *opt_rand, size_t opt_rand_len, uint8_t *sig, size_t sig_len)
{
    const struct slh_params *p = slh_params_get(param);
    const struct slh_msg m = {.body = msg, .body_len = msg_len};
    if (p && opt_rand_len != (opt_rand ? p->n : 0u))
        return ZCL_SLHDSA_ERR_LENGTH;
    return sign_checked(param, sk, sk_len, &m, opt_rand, sig, sig_len);
}

/* M' = 0x00 || len(ctx) || ctx || M (Algorithm 22 line 5). */
static enum zcl_slhdsa_status sign_external(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *opt_rand, uint8_t *sig, size_t sig_len)
{
    uint8_t head[2 + ZCL_SLHDSA_MAX_CONTEXT_SIZE];
    struct slh_msg m = {.head = head, .head_len = 2 + ctx_len, .body = msg,
                        .body_len = msg_len};
    if (ctx_len > ZCL_SLHDSA_MAX_CONTEXT_SIZE)
        return ZCL_SLHDSA_ERR_CONTEXT;
    if (ctx_len != 0 && !ctx)
        return ZCL_SLHDSA_ERR_ARGUMENT;
    head[0] = 0;
    head[1] = (uint8_t)ctx_len;
    if (ctx_len != 0)
        memcpy(head + 2, ctx, ctx_len);
    return sign_checked(param, sk, sk_len, &m, opt_rand, sig, sig_len);
}

enum zcl_slhdsa_status zcl_slhdsa_sign_deterministic(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    uint8_t *sig, size_t sig_len)
{
    enum zcl_slhdsa_status st = sign_external(param, sk, sk_len, msg, msg_len,
                                              ctx, ctx_len, nullptr, sig,
                                              sig_len);
    if (st != ZCL_SLHDSA_OK && sig)
        memory_cleanse(sig, sig_len);
    return st;
}

enum zcl_slhdsa_status zcl_slhdsa_sign(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    zcl_slhdsa_random_fn random, void *random_ctx, uint8_t *sig, size_t sig_len)
{
    uint8_t opt_rand[SLH_MAX_N];
    const struct slh_params *p = slh_params_get(param);
    enum zcl_slhdsa_status st;
    if (!p || !random || !sig)
        return ZCL_SLHDSA_ERR_ARGUMENT;
    if (!random(random_ctx, opt_rand, p->n)) {
        memory_cleanse(sig, sig_len);
        return ZCL_SLHDSA_ERR_RANDOM;
    }
    st = sign_external(param, sk, sk_len, msg, msg_len, ctx, ctx_len, opt_rand,
                       sig, sig_len);
    if (st != ZCL_SLHDSA_OK)
        memory_cleanse(sig, sig_len);
    return st;
}

static enum zcl_slhdsa_status verify_checked(
    enum zcl_slhdsa_param param, const uint8_t *pk, size_t pk_len,
    const struct slh_msg *m, const uint8_t *sig, size_t sig_len)
{
    const struct slh_params *p = slh_params_get(param);
    uint8_t digest[SLH_MAX_M], pk_fors[SLH_MAX_N];
    const uint8_t *md;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    struct slh_ctx c;
    struct slh_adrs a = {0};
    if (!p || !pk || !sig || (m->head_len && !m->head) ||
        (m->body_len && !m->body))
        return ZCL_SLHDSA_ERR_ARGUMENT;
    if (pk_len != 2u * p->n || sig_len != p->sig_size)
        return ZCL_SLHDSA_ERR_LENGTH;
    c = (struct slh_ctx){.p = p, .pk_seed = pk, .sk_seed = nullptr};
    slh_h_msg(p, sig, pk, pk + p->n, m, digest);
    split_digest(p, digest, &md, &idx_tree, &idx_leaf);
    slh_adrs_set_tree(&a, idx_tree);
    slh_adrs_set_type(&a, SLH_ADRS_FORS_TREE);
    slh_adrs_set_keypair(&a, idx_leaf);
    slh_fors_pk_from_sig(&c, sig + p->n, md, &a, pk_fors);
    return slh_ht_verify(&c, pk_fors, sig + p->n + p->fors_size, idx_tree,
                         idx_leaf, pk + p->n)
               ? ZCL_SLHDSA_OK
               : ZCL_SLHDSA_ERR_VERIFY;
}

enum zcl_slhdsa_status zcl_slhdsa_verify_internal(
    enum zcl_slhdsa_param param, const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
    const struct slh_msg m = {.body = msg, .body_len = msg_len};
    return verify_checked(param, pk, pk_len, &m, sig, sig_len);
}

enum zcl_slhdsa_status zcl_slhdsa_verify(
    enum zcl_slhdsa_param param, const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *sig, size_t sig_len)
{
    uint8_t head[2 + ZCL_SLHDSA_MAX_CONTEXT_SIZE];
    struct slh_msg m = {.head = head, .head_len = 2 + ctx_len, .body = msg,
                        .body_len = msg_len};
    if (ctx_len > ZCL_SLHDSA_MAX_CONTEXT_SIZE)
        return ZCL_SLHDSA_ERR_CONTEXT;
    if (ctx_len != 0 && !ctx)
        return ZCL_SLHDSA_ERR_ARGUMENT;
    head[0] = 0;
    head[1] = (uint8_t)ctx_len;
    if (ctx_len != 0)
        memcpy(head + 2, ctx, ctx_len);
    return verify_checked(param, pk, pk_len, &m, sig, sig_len);
}
