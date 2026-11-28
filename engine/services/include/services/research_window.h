/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood release ballot window. */
#ifndef ZCL_RESEARCH_WINDOW_H
#define ZCL_RESEARCH_WINDOW_H

#include "base/result.h"

#include <stdint.h>

/* Window fields copied from the release manifest. votes is the 95 percent
 * requirement of window. On failure *out is left untouched. */
struct research_window {
    int32_t start;
    int32_t window;
    int32_t votes;
    int32_t slot0_activation;
    int32_t slot1_activation;
};

/* Reads path as a ballot manifest and copies its release window. Uses the
 * sealed Ironwood genesis. Does not select the chain or write a store. */
struct zcl_result research_window_read(const char *path,
                                       struct research_window *out);

#endif
