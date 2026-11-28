/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis block hash. */
#ifndef ZCL_RESEARCH_BLOCKHASH_H
#define ZCL_RESEARCH_BLOCKHASH_H

#include "base/result.h"

#include <stddef.h>

/* Copies the raw double SHA-256 of the research genesis header, including
 * its Equihash solution. The caller reverses it for display. Does not select
 * the chain, open a socket, or write a store. raw_cap is the byte count of
 * raw. On failure raw is left untouched. */
struct zcl_result research_blockhash_read(unsigned char *raw, size_t raw_cap);

#endif
