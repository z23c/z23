/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood address namespace without selecting a chain. */
#ifndef ZCL_RESEARCH_NAMESPACE_H
#define ZCL_RESEARCH_NAMESPACE_H

#include "base/result.h"

#include <stddef.h>

#define RESEARCH_NAMESPACE_HRP_CAP 32
#define RESEARCH_NAMESPACE_HRP_COUNT 4
#define RESEARCH_NAMESPACE_PREFIX_LEN 4

struct research_namespace {
    char hrp[RESEARCH_NAMESPACE_HRP_COUNT][RESEARCH_NAMESPACE_HRP_CAP];
    unsigned char pubkey_prefix[RESEARCH_NAMESPACE_PREFIX_LEN];
};

/* Copies the research descriptor's four Sapling HRPs and the pubkey-address
 * prefix. Does not select the chain, open a socket, or write a store.
 * hrp_cap is the caller buffer width, including the NUL. On failure the
 * output is left untouched. */
struct zcl_result research_namespace_read(struct research_namespace *out,
                                          size_t hrp_cap);

#endif
