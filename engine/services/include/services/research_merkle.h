/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis merkle root. */
#ifndef ZCL_RESEARCH_MERKLE_H
#define ZCL_RESEARCH_MERKLE_H

#include "base/result.h"

#include <stddef.h>

/* Copies the research genesis merkle root in wire order. The caller reverses
 * it for display. Does not select the chain, open a socket, or write a
 * store. raw_cap is the byte count of raw. On failure raw is left untouched. */
struct zcl_result research_merkle_read(unsigned char *raw, size_t raw_cap);

#endif
