/* purpose: Bind a decoded Ironwood transaction to its retained wire frame. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_CHECKED_WIRE_H
#define ZCL_IRONWOOD_CHECKED_WIRE_H
#include "base/result.h"
#include "primitives/transaction_v6_wire.h"
struct transaction;
/* The returned view borrows tx->v6_wire until the transaction changes.
 * Checks the cached txid and every decoded component used by validation.
 * Bundle authorization and the block's authorizing-data commitment are
 * checked by their respective callers. Failure preserves the output. */
struct zcl_result ironwood_checked_wire(const struct transaction *tx,
    size_t frame_limit, struct v6_wire_view *out);
#endif
