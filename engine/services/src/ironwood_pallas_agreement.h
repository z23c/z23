/* purpose: Isolated synthetic Orchard key-agreement research adapter. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef IRONWOOD_PALLAS_AGREEMENT_H
#define IRONWOOD_PALLAS_AGREEMENT_H
#include <stdint.h>
#include "util/result.h"
/* RESEARCH ONLY: public synthetic inputs; not qualified for wallet secrets.
 * ivk is a nonzero canonical Pallas base-field integer (the final 32 bytes
 * of Orchard raw IVK), epk is a nonidentity Pallas compressed point.
 * On failure out is unchanged. Input/output buffers may alias. */
struct zcl_result ironwood_research_pallas_agree(const uint8_t ivk[32],
    const uint8_t epk[32], uint8_t out[32]);
#endif
