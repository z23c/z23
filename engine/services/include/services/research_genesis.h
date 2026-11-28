/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis wire length and coinbase message. */
#ifndef ZCL_RESEARCH_GENESIS_H
#define ZCL_RESEARCH_GENESIS_H

#include "base/result.h"

#include <stddef.h>

/* Copies the research descriptor's genesis wire length and the coinbase
 * scriptSig text. Does not select the chain, open a socket, or write a
 * store. message_cap includes the NUL. On failure the outputs are left
 * untouched. */
struct zcl_result research_genesis_read(size_t *wire_len, char *message,
                                        size_t message_cap);

#endif
