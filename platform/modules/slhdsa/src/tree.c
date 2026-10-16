/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: XMSS trees and the hypertree (FIPS 205 Algorithms 9-13). */

#include "slhdsa_internal.h"

void slh_climb(const struct slh_ctx *c, struct slh_adrs *a, uint8_t *node,
               const uint8_t *auth, unsigned levels)
{
    const unsigned n = c->p->n;
    uint8_t buf[2 * SLH_MAX_N];
    for (unsigned k = 0; k < levels; k++) {
        const uint32_t idx = slh_adrs_index(a);
        const uint8_t *sibling = auth + (size_t)k * n;
        slh_adrs_set_height(a, k + 1);
        slh_adrs_set_index(a, idx >> 1);
        if ((idx & 1u) == 0) {
            memcpy(buf, node, n);
            memcpy(buf + n, sibling, n);
        } else {
            memcpy(buf, sibling, n);
            memcpy(buf + n, node, n);
        }
        slh_hash(c, a, buf, 2u * n, node);
    }
}

void slh_xmss_node(const struct slh_ctx *c, uint32_t i, unsigned z,
                   const struct slh_adrs *base, uint8_t *out)
{
    struct slh_adrs a = *base;
    uint8_t pair[2 * SLH_MAX_N];
    if (z == 0) {
        slh_adrs_set_type(&a, SLH_ADRS_WOTS_HASH);
        slh_adrs_set_keypair(&a, i);
        slh_wots_pkgen(c, &a, out);
        return;
    }
    slh_xmss_node(c, 2 * i, z - 1, base, pair);
    slh_xmss_node(c, 2 * i + 1, z - 1, base, pair + c->p->n);
    slh_adrs_set_type(&a, SLH_ADRS_TREE);
    slh_adrs_set_height(&a, z);
    slh_adrs_set_index(&a, i);
    slh_hash(c, &a, pair, 2u * c->p->n, out);
}

/* Algorithm 10: sig_xmss = WOTS+ signature || authentication path. */
static void xmss_sign(const struct slh_ctx *c, const uint8_t *m, uint32_t idx,
                      const struct slh_adrs *base, uint8_t *sig)
{
    const unsigned n = c->p->n;
    struct slh_adrs a = *base;
    uint8_t *auth = sig + (size_t)c->p->len * n;
    for (unsigned j = 0; j < c->p->hp; j++)
        slh_xmss_node(c, (idx >> j) ^ 1u, j, base, auth + (size_t)j * n);
    slh_adrs_set_type(&a, SLH_ADRS_WOTS_HASH);
    slh_adrs_set_keypair(&a, idx);
    slh_wots_sign(c, m, &a, sig);
}

/* Algorithm 11. out may alias m. */
static void xmss_pk_from_sig(const struct slh_ctx *c, uint32_t idx,
                             const uint8_t *sig, const uint8_t *m,
                             const struct slh_adrs *base, uint8_t *out)
{
    struct slh_adrs a = *base;
    uint8_t node[SLH_MAX_N];
    slh_adrs_set_type(&a, SLH_ADRS_WOTS_HASH);
    slh_adrs_set_keypair(&a, idx);
    slh_wots_pk_from_sig(c, sig, m, &a, node);
    slh_adrs_set_type(&a, SLH_ADRS_TREE);
    slh_adrs_set_index(&a, idx);
    slh_climb(c, &a, node, sig + (size_t)c->p->len * c->p->n, c->p->hp);
    memcpy(out, node, c->p->n);
}

static void layer_adrs(struct slh_adrs *a, unsigned layer, uint64_t tree)
{
    slh_adrs_set_layer(a, layer);
    slh_adrs_set_tree(a, tree);
}

void slh_ht_sign(const struct slh_ctx *c, const uint8_t *m,
                 uint64_t idx_tree, uint32_t idx_leaf, uint8_t *sig_ht)
{
    const struct slh_params *p = c->p;
    struct slh_adrs a = {0};
    uint8_t root[SLH_MAX_N];
    uint8_t *sig = sig_ht;
    layer_adrs(&a, 0, idx_tree);
    xmss_sign(c, m, idx_leaf, &a, sig);
    xmss_pk_from_sig(c, idx_leaf, sig, m, &a, root);
    for (unsigned j = 1; j < p->d; j++) {
        idx_leaf = (uint32_t)(idx_tree & ((UINT64_C(1) << p->hp) - 1));
        idx_tree >>= p->hp;
        layer_adrs(&a, j, idx_tree);
        sig += p->xmss_size;
        xmss_sign(c, root, idx_leaf, &a, sig);
        if (j < p->d - 1)
            xmss_pk_from_sig(c, idx_leaf, sig, root, &a, root);
    }
}

bool slh_ht_verify(const struct slh_ctx *c, const uint8_t *m,
                   const uint8_t *sig_ht, uint64_t idx_tree, uint32_t idx_leaf,
                   const uint8_t *pk_root)
{
    const struct slh_params *p = c->p;
    struct slh_adrs a = {0};
    uint8_t node[SLH_MAX_N];
    layer_adrs(&a, 0, idx_tree);
    xmss_pk_from_sig(c, idx_leaf, sig_ht, m, &a, node);
    for (unsigned j = 1; j < p->d; j++) {
        idx_leaf = (uint32_t)(idx_tree & ((UINT64_C(1) << p->hp) - 1));
        idx_tree >>= p->hp;
        layer_adrs(&a, j, idx_tree);
        xmss_pk_from_sig(c, idx_leaf, sig_ht + (size_t)j * p->xmss_size, node,
                         &a, node);
    }
    return memcmp(node, pk_root, p->n) == 0;
}
