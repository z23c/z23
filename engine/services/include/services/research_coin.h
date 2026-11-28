/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coin identity. */
#ifndef ZCL_RESEARCH_COIN_H
#define ZCL_RESEARCH_COIN_H

#include "base/result.h"

#include <stdint.h>

/* Wallet identity for the Ironwood rehearsal descriptor.
 * units is the currency label, NUL-terminated.
 * bip44 is the BIP44 coin type.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_coin_view {
    char units[8];
    uint32_t bip44;
};

struct zcl_result research_coin_read(struct research_coin_view *out);

#endif
