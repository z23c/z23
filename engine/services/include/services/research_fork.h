/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Derive the Ironwood release fork identity. */
#ifndef ZCL_RESEARCH_FORK_H
#define ZCL_RESEARCH_FORK_H

#include "base/result.h"

#include <stddef.h>

/* Copies SHA3-256 of the published Ironwood release label, without a
 * trailing NUL. Does not select the chain, open a socket, or write a
 * store. fork_cap is the byte count of fork_id. On failure fork_id is
 * left untouched. */
struct zcl_result research_fork_read(unsigned char *fork_id, size_t fork_cap);

#endif
