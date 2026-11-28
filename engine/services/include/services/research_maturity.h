/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coinbase maturity. */
#ifndef ZCL_RESEARCH_MATURITY_H
#define ZCL_RESEARCH_MATURITY_H

#include "base/result.h"

/* Copies the block count a fresh Ironwood coinbase must age before it can
 * fund notes. Does not select the chain or write a store. On failure *blocks
 * is left untouched. */
struct zcl_result research_maturity_read(int *blocks);

#endif
