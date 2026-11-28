/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read Ironwood Overwinter and Sapling activation heights. */
#ifndef ZCL_RESEARCH_SCHEDULE_H
#define ZCL_RESEARCH_SCHEDULE_H

#include "base/result.h"

/* Copies the research descriptor's Overwinter and Sapling activation
 * heights. Does not select the chain, open a socket, or write a store.
 * On failure the outputs are left untouched. */
struct zcl_result research_schedule_read(int *overwinter_height,
                                         int *sapling_height);

#endif
