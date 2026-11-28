/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood network id and founders-reward count. */
#ifndef ZCL_RESEARCH_NETWORK_H
#define ZCL_RESEARCH_NETWORK_H

#include "base/result.h"

#include <stddef.h>

/* Copies the research descriptor's network id and founders-reward address
 * count. Does not select the chain, open a socket, or write a store.
 * network_id_cap includes the NUL. On failure the outputs are left
 * untouched. */
struct zcl_result research_network_read(char *network_id, size_t network_id_cap,
                                        size_t *founders_count);

#endif
