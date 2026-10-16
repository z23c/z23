/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: FORS few-time signatures (FIPS 205 Algorithms 14-17). */

#include "slhdsa_internal.h"

static void fors_sk(const struct slh_ctx *c, const struct slh_adrs *a,
                    uint32_t idx, uint8_t *out)
{
    struct slh_adrs ska = *a;
    slh_adrs_set_type(&ska, SLH_ADRS_FORS_PRF);
    slh_adrs_set_keypair(&ska, slh_adrs_keypair(a));
    slh_adrs_set_index(&ska, idx);
    slh_prf(c, &ska, out);
}

static void fors_node(const struct slh_ctx *c, uint32_t i, unsigned z,
                      struct slh_adrs *a, uint8_t *out)
{
    const unsigned n = c->p->n;
    uint8_t pair[2 * SLH_MAX_N];
    if (z == 0) {
        fors_sk(c, a, i, out);
        slh_adrs_set_height(a, 0);
        slh_adrs_set_index(a, i);
        slh_hash(c, a, out, n, out);
        return;
    }
    fors_node(c, 2 * i, z - 1, a, pair);
    fors_node(c, 2 * i + 1, z - 1, a, pair + n);
    slh_adrs_set_height(a, z);
    slh_adrs_set_index(a, i);
    slh_hash(c, a, pair, 2u * n, out);
}

void slh_fors_sign(const struct slh_ctx *c, const uint8_t *md,
                   struct slh_adrs *a, uint8_t *sig)
{
    const struct slh_params *p = c->p;
    const unsigned n = p->n;
    uint32_t ind[SLH_MAX_K];
    slh_base_2b(md, p->a, p->k, ind);
    for (unsigned i = 0; i < p->k; i++) {
        fors_sk(c, a, (i << p->a) + ind[i], sig);
        sig += n;
        for (unsigned j = 0; j < p->a; j++) {
            const uint32_t s = (ind[i] >> j) ^ 1u;
            fors_node(c, (i << (p->a - j)) + s, j, a, sig);
            sig += n;
        }
    }
}

void slh_fors_pk_from_sig(const struct slh_ctx *c, const uint8_t *sig,
                          const uint8_t *md, struct slh_adrs *a, uint8_t *pk)
{
    const struct slh_params *p = c->p;
    const unsigned n = p->n;
    uint32_t ind[SLH_MAX_K];
    uint8_t roots[SLH_MAX_K * SLH_MAX_N];
    struct slh_adrs ra = *a;
    slh_base_2b(md, p->a, p->k, ind);
    for (unsigned i = 0; i < p->k; i++) {
        uint8_t *node = roots + (size_t)i * n;
        slh_adrs_set_height(a, 0);
        slh_adrs_set_index(a, (i << p->a) + ind[i]);
        slh_hash(c, a, sig, n, node);
        sig += n;
        slh_climb(c, a, node, sig, p->a);
        sig += (size_t)p->a * n;
    }
    slh_adrs_set_type(&ra, SLH_ADRS_FORS_ROOTS);
    slh_adrs_set_keypair(&ra, slh_adrs_keypair(a));
    slh_hash(c, &ra, roots, (size_t)p->k * n, pk);
}
