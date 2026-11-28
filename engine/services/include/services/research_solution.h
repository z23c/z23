/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis solution length. */
#ifndef ZCL_RESEARCH_SOLUTION_H
#define ZCL_RESEARCH_SOLUTION_H

#include "base/result.h"

/* Reads the one-byte solution length and the transaction count that follows
 * the solution in the research genesis wire. Does not select the chain, open
 * a socket, or write a store. A length of 253 or more is refused. On failure
 * the outputs are left untouched. */
struct zcl_result research_solution_read(unsigned int *solution_len,
                                        unsigned int *tx_count);

#endif
