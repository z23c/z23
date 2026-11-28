/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis header fields. */
#ifndef ZCL_RESEARCH_HEADER_H
#define ZCL_RESEARCH_HEADER_H

#include "base/result.h"

#include <stdint.h>

/* Copies the research genesis header: version, time, compact target, parent,
 * final Sapling root, and the 32-byte nonce. Does not select the chain, open
 * a socket, or write a store. On failure the output is left untouched. */
struct research_header {
    int32_t version;
    uint32_t time;
    uint32_t bits;
    unsigned char prev[32];
    unsigned char sapling_root[32];
    unsigned char nonce[32];
};

struct zcl_result research_header_read(struct research_header *out);

#endif
