/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Zcash PRF functions — SHA256Compress for Sprout, blake2b for Sapling. */

#ifndef ZCL_SAPLING_PRF_H
#define ZCL_SAPLING_PRF_H

#include "core/uint256.h"
#include <stdbool.h>
#include <stddef.h>

/* Sprout PRFs (SHA256Compress based) */
void prf_addr_a_pk(const unsigned char *a_sk, struct uint256 *out);
void prf_addr_sk_enc(const unsigned char *a_sk, struct uint256 *out);
void prf_nf(const unsigned char *a_sk, const struct uint256 *rho,
            struct uint256 *out);
void prf_pk(const unsigned char *a_sk, size_t i0,
            const struct uint256 *h_sig, struct uint256 *out);
void prf_rho(const unsigned char *phi, size_t i0,
             const struct uint256 *h_sig, struct uint256 *out);

/* Sapling PRFs (blake2b based) */
void prf_expand(const struct uint256 *sk, unsigned char t,
                unsigned char out[64]);
void prf_ask(const struct uint256 *sk, struct uint256 *out);
void prf_nsk(const struct uint256 *sk, struct uint256 *out);
void prf_ovk(const struct uint256 *sk, struct uint256 *out);

#endif
