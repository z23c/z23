/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int64_t CAmount;

#define COIN ((CAmount)100000000)
#define CENT ((CAmount)1000000)
#define MAX_MONEY (21000000 * COIN)

static inline bool MoneyRange(CAmount nValue)
{
    return nValue >= 0 && nValue <= MAX_MONEY;
}

struct fee_rate {
    CAmount satoshis_per_k;
};

static inline void fee_rate_init(struct fee_rate *r)
{
    r->satoshis_per_k = 0;
}

static inline void fee_rate_init_from_fee(struct fee_rate *r, CAmount fee_paid, size_t size)
{
    r->satoshis_per_k = size > 0 ? fee_paid * 1000 / (CAmount)size : 0;
}

static inline CAmount fee_rate_get_fee(const struct fee_rate *r, size_t size)
{
    CAmount fee = r->satoshis_per_k * (CAmount)size / 1000;
    if (fee == 0 && r->satoshis_per_k > 0)
        fee = r->satoshis_per_k;
    return fee;
}

static inline CAmount fee_rate_get_fee_per_k(const struct fee_rate *r)
{
    return fee_rate_get_fee(r, 1000);
}

#endif
