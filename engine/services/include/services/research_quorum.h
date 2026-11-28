/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade quorum. */
#ifndef ZCL_RESEARCH_QUORUM_H
#define ZCL_RESEARCH_QUORUM_H

#include "base/result.h"

/* Block-version quorum for the Ironwood rehearsal descriptor.
 * window is the number of blocks in the majority sample.
 * enforce is how many of those blocks must already be the new version.
 * reject is how many outdated blocks get rejected.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_quorum_view {
    int window;
    int enforce;
    int reject;
};

struct zcl_result research_quorum_read(struct research_quorum_view *out);

#endif
