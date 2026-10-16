/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: SLH-DSA-SHAKE tweakable hashes (FIPS 205 Section 11.1) and the
 * incremental SHAKE256 sponge they run on. */

#include "slhdsa_internal.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

void slh_xof_init(struct slh_xof *x)
{
    memset(x, 0, sizeof(*x));
}

static void xof_permute_block(struct slh_xof *x)
{
    for (unsigned i = 0; i < SLH_RATE / 8; i++)
        x->st[i] ^= zcl_read_u64_le(x->buf + 8 * i);
    sha3_keccakf_scalar(x->st);
    x->fill = 0;
}

void slh_xof_absorb(struct slh_xof *x, const uint8_t *data, size_t len)
{
    while (len != 0) {
        size_t take = SLH_RATE - x->fill;
        if (take > len)
            take = len;
        memcpy(x->buf + x->fill, data, take);
        x->fill += take;
        data += take;
        len -= take;
        if (x->fill == SLH_RATE)
            xof_permute_block(x);
    }
}

void slh_xof_finish(struct slh_xof *x, uint8_t *out, size_t out_len)
{
    uint8_t word[8];
    memset(x->buf + x->fill, 0, SLH_RATE - x->fill);
    x->buf[x->fill] ^= 0x1f;
    x->buf[SLH_RATE - 1] ^= 0x80;
    xof_permute_block(x);
    for (unsigned i = 0; out_len != 0;) {
        zcl_write_u64_le(word, x->st[i++]);
        const size_t take = out_len < 8 ? out_len : 8;
        memcpy(out, word, take);
        out += take;
        out_len -= take;
        if (i == SLH_RATE / 8 && out_len != 0) {
            sha3_keccakf_scalar(x->st);
            i = 0;
        }
    }
    memory_cleanse(x, sizeof(*x));
    memory_cleanse(word, sizeof(word));
}

static void xof_adrs_prefix(struct slh_xof *x, const struct slh_ctx *c,
                            const struct slh_adrs *a)
{
    slh_xof_init(x);
    slh_xof_absorb(x, c->pk_seed, c->p->n);
    slh_xof_absorb(x, a->b, SLH_ADRS_SIZE);
}

void slh_hash(const struct slh_ctx *c, const struct slh_adrs *a,
              const uint8_t *in, size_t in_len, uint8_t *out)
{
    struct slh_xof x;
    xof_adrs_prefix(&x, c, a);
    slh_xof_absorb(&x, in, in_len);
    slh_xof_finish(&x, out, c->p->n);
}

void slh_prf(const struct slh_ctx *c, const struct slh_adrs *a, uint8_t *out)
{
    struct slh_xof x;
    xof_adrs_prefix(&x, c, a);
    slh_xof_absorb(&x, c->sk_seed, c->p->n);
    slh_xof_finish(&x, out, c->p->n);
}

void slh_prf_msg(const struct slh_params *p, const uint8_t *sk_prf,
                 const uint8_t *opt_rand, const struct slh_msg *m, uint8_t *out)
{
    struct slh_xof x;
    slh_xof_init(&x);
    slh_xof_absorb(&x, sk_prf, p->n);
    slh_xof_absorb(&x, opt_rand, p->n);
    slh_xof_absorb(&x, m->head, m->head_len);
    slh_xof_absorb(&x, m->body, m->body_len);
    slh_xof_finish(&x, out, p->n);
}

void slh_h_msg(const struct slh_params *p, const uint8_t *r,
               const uint8_t *pk_seed, const uint8_t *pk_root,
               const struct slh_msg *m, uint8_t *out)
{
    struct slh_xof x;
    slh_xof_init(&x);
    slh_xof_absorb(&x, r, p->n);
    slh_xof_absorb(&x, pk_seed, p->n);
    slh_xof_absorb(&x, pk_root, p->n);
    slh_xof_absorb(&x, m->head, m->head_len);
    slh_xof_absorb(&x, m->body, m->body_len);
    slh_xof_finish(&x, out, p->m);
}
