/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read Ironwood later-upgrade heights and Equihash parameters. */
#ifndef ZCL_RESEARCH_POW_H
#define ZCL_RESEARCH_POW_H

#include "base/result.h"

struct research_pow {
    int bubbles_height;
    int diffadj_height;
    int buttercup_height;
    unsigned equihash_n;
    unsigned equihash_k;
};

/* Copies the research descriptor's Bubbles, DiffAdj, and Buttercup
 * activation heights, plus the Equihash parameters at height. Does not
 * select the chain, open a socket, or write a store. On failure the
 * output is left untouched. */
struct zcl_result research_pow_read(int height, struct research_pow *out);

#endif
