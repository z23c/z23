/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block subsidy. */
#ifndef ZCL_RESEARCH_SUBSIDY_H
#define ZCL_RESEARCH_SUBSIDY_H

#include "base/result.h"

#include <stdint.h>

/* Consensus mint for one Ironwood rehearsal height. subsidy is the maximum
 * coinbase value at that height. The intervals and coinbase_protected flag
 * come from the sealed descriptor. coinbase_protected is 0 when a
 * transparent coinbase is allowed. Does not select the chain or write a
 * store. On failure *out is left untouched. */
struct research_subsidy_view {
    int64_t subsidy;
    int slow_start;
    int pre_halving;
    int post_halving;
    int coinbase_protected;
};

struct zcl_result research_subsidy_read(int height,
                                        struct research_subsidy_view *out);

#endif
