/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Derive the Ironwood message start. */
#ifndef ZCL_RESEARCH_MAGIC_H
#define ZCL_RESEARCH_MAGIC_H

#include "base/result.h"

#include <stddef.h>

/* Copies the first four bytes of SHA3-256 of the published Ironwood
 * transport label, without a trailing NUL. Does not select the chain, open
 * a socket, or write a store. magic_cap is the byte count of magic. On
 * failure magic is left untouched. */
struct zcl_result research_magic_read(unsigned char *magic, size_t magic_cap);

#endif
