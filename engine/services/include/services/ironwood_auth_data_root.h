/* purpose: Compute bounded ZIP 244 authorizing-data roots for private blocks. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_AUTH_DATA_ROOT_H
#define ZCL_IRONWOOD_AUTH_DATA_ROOT_H
#include "base/result.h"
#include <stdint.h>
struct block;
/* Ordered pre-v5 transactions use the ZIP 244 all-ff sentinel. Version 6
 * transactions must have a checked model and raw frame. Version 5 and other
 * versions are unsupported. Zero padding completes the tree to a power of
 * two. Output is raw hash bytes and is unchanged on failure.
 * This computes a root only: it authenticates no block or chain-history root,
 * verifies no signatures or proofs, and activates no consensus rule. */
struct zcl_result ironwood_auth_data_root(const struct block *block, uint8_t out[32]);
#endif
