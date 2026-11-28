/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood selected release activation schedule. */
#ifndef ZCL_RESEARCH_RELEASE_H
#define ZCL_RESEARCH_RELEASE_H

#include "base/result.h"

/* Copies the selected Ironwood release activation heights. Overwinter and
 * Sapling activate at the genesis block. Does not select the chain or change
 * the sealed rehearsal descriptor. On failure the outputs are left untouched. */
struct zcl_result research_release_read(int *overwinter_height,
                                        int *sapling_height);

#endif
