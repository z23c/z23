/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: WOTS+ one-time signatures (FIPS 205 Algorithms 4-8). */

#include "slhdsa_internal.h"

#include "base/cleanse.h"

void slh_base_2b(const uint8_t *x, unsigned b, unsigned out_len, uint32_t *out)
{
    size_t in = 0;
    unsigned bits = 0;
    uint32_t total = 0;
    for (unsigned o = 0; o < out_len; o++) {
        while (bits < b) {
            total = (total << 8) + x[in++];
            bits += 8;
        }
        bits -= b;
        out[o] = (total >> bits) & ((1u << b) - 1u);
        total &= (1u << bits) - 1u;
    }
}

/* Algorithm 5: advances x in place from step start by steps applications of F. */
static void wots_chain(const struct slh_ctx *c, struct slh_adrs *a, uint8_t *x,
                       unsigned start, unsigned steps)
{
    for (unsigned j = start; j < start + steps; j++) {
        slh_adrs_set_hash(a, j);
        slh_hash(c, a, x, c->p->n, x);
    }
}

/* Message digits plus checksum digits (Algorithms 7 and 8, shared part). */
static void wots_digits(const struct slh_params *p, const uint8_t *m,
                        uint32_t digits[SLH_MAX_LEN])
{
    const unsigned len1 = 2 * p->n;
    uint8_t csum_bytes[2];
    uint32_t csum = 0;
    slh_base_2b(m, SLH_LG_W, len1, digits);
    for (unsigned i = 0; i < len1; i++)
        csum += SLH_W - 1u - digits[i];
    csum <<= (8 - ((SLH_LEN2 * SLH_LG_W) % 8)) % 8;
    csum_bytes[0] = (uint8_t)(csum >> 8);
    csum_bytes[1] = (uint8_t)csum;
    slh_base_2b(csum_bytes, SLH_LG_W, SLH_LEN2, digits + len1);
}

static void wots_sk(const struct slh_ctx *c, const struct slh_adrs *a,
                    unsigned chain, uint8_t *out)
{
    struct slh_adrs ska = *a;
    slh_adrs_set_type(&ska, SLH_ADRS_WOTS_PRF);
    slh_adrs_set_keypair(&ska, slh_adrs_keypair(a));
    slh_adrs_set_chain(&ska, chain);
    slh_prf(c, &ska, out);
}

static void wots_compress(const struct slh_ctx *c, const struct slh_adrs *a,
                          const uint8_t *tmp, uint8_t *pk)
{
    struct slh_adrs pka = *a;
    slh_adrs_set_type(&pka, SLH_ADRS_WOTS_PK);
    slh_adrs_set_keypair(&pka, slh_adrs_keypair(a));
    slh_hash(c, &pka, tmp, (size_t)c->p->len * c->p->n, pk);
}

void slh_wots_pkgen(const struct slh_ctx *c, struct slh_adrs *a, uint8_t *pk)
{
    uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    const unsigned n = c->p->n;
    for (unsigned i = 0; i < c->p->len; i++) {
        wots_sk(c, a, i, tmp + (size_t)i * n);
        slh_adrs_set_chain(a, i);
        wots_chain(c, a, tmp + (size_t)i * n, 0, SLH_W - 1);
    }
    wots_compress(c, a, tmp, pk);
    memory_cleanse(tmp, sizeof(tmp));
}

void slh_wots_sign(const struct slh_ctx *c, const uint8_t *m,
                   struct slh_adrs *a, uint8_t *sig)
{
    uint32_t digits[SLH_MAX_LEN];
    const unsigned n = c->p->n;
    wots_digits(c->p, m, digits);
    for (unsigned i = 0; i < c->p->len; i++) {
        wots_sk(c, a, i, sig + (size_t)i * n);
        slh_adrs_set_chain(a, i);
        wots_chain(c, a, sig + (size_t)i * n, 0, digits[i]);
    }
}

void slh_wots_pk_from_sig(const struct slh_ctx *c, const uint8_t *sig,
                          const uint8_t *m, struct slh_adrs *a, uint8_t *pk)
{
    uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    uint32_t digits[SLH_MAX_LEN];
    const unsigned n = c->p->n;
    wots_digits(c->p, m, digits);
    for (unsigned i = 0; i < c->p->len; i++) {
        memcpy(tmp + (size_t)i * n, sig + (size_t)i * n, n);
        slh_adrs_set_chain(a, i);
        wots_chain(c, a, tmp + (size_t)i * n, digits[i], SLH_W - 1 - digits[i]);
    }
    wots_compress(c, a, tmp, pk);
}
