/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood listen port, seed count, and payment namespace. */
#ifndef ZCL_RESEARCH_LISTEN_H
#define ZCL_RESEARCH_LISTEN_H

#include "base/result.h"

#include <stddef.h>

/* Copies the research descriptor's listen port, combined seed count, and
 * Sapling payment HRP. Does not select the chain, open a socket, or write
 * a store. On failure the outputs are left untouched. */
struct zcl_result research_listen_read(int *listen_port, size_t *seed_count,
                                       char *payment_hrp, size_t payment_hrp_cap);

#endif
