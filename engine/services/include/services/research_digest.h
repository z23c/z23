/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis block SHA-256. */
#ifndef ZCL_RESEARCH_DIGEST_H
#define ZCL_RESEARCH_DIGEST_H

#include "base/result.h"

#include <stddef.h>

/* Copies one SHA-256 of the research genesis block wire. Does not select
 * the chain, open a socket, or write a store. raw_cap is the byte count
 * of raw. On failure raw is left untouched. */
struct zcl_result research_digest_read(unsigned char *raw, size_t raw_cap);

#endif
