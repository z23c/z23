/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Zcash PRF functions — pure C23 implementation. */

#include "sapling/prf.h"
#include "sapling/jubjub.h"
#include "crypto/sha256.h"
#include "crypto/blake2b.h"
#include "support/cleanse.h"
#include <string.h>

/* Sprout PRF: SHA256Compress(x || y) with control bits in x[0] */
static void sprout_prf(bool a, bool b, bool c, bool d,
                        const unsigned char *x,
                        const struct uint256 *y,
                        struct uint256 *out)
{
    unsigned char blob[64];
    memcpy(blob, x, 32);
    memcpy(blob + 32, y->data, 32);

    blob[0] &= 0x0F;
    blob[0] |= (a ? (1 << 7) : 0) | (b ? (1 << 6) : 0) |
               (c ? (1 << 5) : 0) | (d ? (1 << 4) : 0);

    struct sha256_ctx hasher;
    sha256_init(&hasher);
    sha256_write(&hasher, blob, 64);
    sha256_finalize_no_padding(&hasher, out->data, 0);
    memory_cleanse(&hasher, sizeof(hasher));
    memory_cleanse(blob, sizeof(blob));
}

static void sprout_prf_addr(const unsigned char *a_sk, unsigned char t,
                             struct uint256 *out)
{
    struct uint256 y;
    memset(y.data, 0, 32);
    y.data[0] = t;
    sprout_prf(true, true, false, false, a_sk, &y, out);
}

void prf_addr_a_pk(const unsigned char *a_sk, struct uint256 *out)
{
    sprout_prf_addr(a_sk, 0, out);
}

void prf_addr_sk_enc(const unsigned char *a_sk, struct uint256 *out)
{
    sprout_prf_addr(a_sk, 1, out);
}

void prf_nf(const unsigned char *a_sk, const struct uint256 *rho,
            struct uint256 *out)
{
    sprout_prf(true, true, true, false, a_sk, rho, out);
}

void prf_pk(const unsigned char *a_sk, size_t i0,
            const struct uint256 *h_sig, struct uint256 *out)
{
    sprout_prf(false, (bool)i0, false, false, a_sk, h_sig, out);
}

void prf_rho(const unsigned char *phi, size_t i0,
             const struct uint256 *h_sig, struct uint256 *out)
{
    sprout_prf(false, (bool)i0, true, false, phi, h_sig, out);
}

/* Sapling PRF_expand: blake2b with personalization "Zcash_ExpandSeed" */
static const unsigned char EXPAND_SEED_PERSONAL[BLAKE2B_PERSONALBYTES] = {
    'Z','c','a','s','h','_','E','x','p','a','n','d','S','e','e','d'
};

void prf_expand(const struct uint256 *sk, unsigned char t,
                unsigned char out[64])
{
    unsigned char blob[33];
    memcpy(blob, sk->data, 32);
    blob[32] = t;

    struct blake2b_ctx state;
    blake2b_init_salt_personal(&state, 64, NULL, 0, NULL,
                               EXPAND_SEED_PERSONAL);
    blake2b_update(&state, blob, 33);
    blake2b_final(&state, out, 64);
    memory_cleanse(&state, sizeof(state));
    memory_cleanse(blob, sizeof(blob));
}

void prf_ask(const struct uint256 *sk, struct uint256 *out)
{
    unsigned char tmp[64];
    prf_expand(sk, 0, tmp);
    jubjub_to_scalar(tmp, out->data);
    memory_cleanse(tmp, sizeof(tmp));
}

void prf_nsk(const struct uint256 *sk, struct uint256 *out)
{
    unsigned char tmp[64];
    prf_expand(sk, 1, tmp);
    jubjub_to_scalar(tmp, out->data);
    memory_cleanse(tmp, sizeof(tmp));
}

void prf_ovk(const struct uint256 *sk, struct uint256 *out)
{
    unsigned char tmp[64];
    prf_expand(sk, 2, tmp);
    memcpy(out->data, tmp, 32);
    memory_cleanse(tmp, sizeof(tmp));
}
