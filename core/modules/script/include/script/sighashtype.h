/* Copyright (c) 2017 Bitcoin ABC developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_SIGHASHTYPE_H
#define ZCL_SCRIPT_SIGHASHTYPE_H

#include <stdbool.h>
#include <stdint.h>

#define SIGHASH_ALL          1
#define SIGHASH_NONE         2
#define SIGHASH_SINGLE       3
#define SIGHASH_ANYONECANPAY 0x80

enum base_sighash_type {
    BASE_SIGHASH_UNSUPPORTED = 0,
    BASE_SIGHASH_ALL = SIGHASH_ALL,
    BASE_SIGHASH_NONE = SIGHASH_NONE,
    BASE_SIGHASH_SINGLE = SIGHASH_SINGLE
};

struct sighash_type {
    uint32_t raw;
};

static inline struct sighash_type sighash_type_default(void)
{
    return (struct sighash_type){ .raw = SIGHASH_ALL };
}

static inline enum base_sighash_type sighash_get_base_type(struct sighash_type s)
{
    return (enum base_sighash_type)(s.raw & 0x1f);
}

static inline bool sighash_is_defined(struct sighash_type s)
{
    uint32_t base = s.raw & ~(uint32_t)SIGHASH_ANYONECANPAY;
    return base >= BASE_SIGHASH_ALL && base <= BASE_SIGHASH_SINGLE;
}

static inline bool sighash_has_anyone_can_pay(struct sighash_type s)
{
    return (s.raw & SIGHASH_ANYONECANPAY) != 0;
}

static inline struct sighash_type sighash_with_anyone_can_pay(struct sighash_type s, bool acp)
{
    return (struct sighash_type){
        .raw = (s.raw & ~(uint32_t)SIGHASH_ANYONECANPAY) |
               (acp ? SIGHASH_ANYONECANPAY : 0)
    };
}

#endif
