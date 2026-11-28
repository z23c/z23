/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Decode bounded opaque v6 transaction frames from block wire streams.
 */
#ifndef Z23_TRANSACTION_V6_DECODE_H
#define Z23_TRANSACTION_V6_DECODE_H

#include <stdbool.h>
#include <stddef.h>

struct byte_stream;
struct transaction;

/* Return whether the unread stream starts with the v6 version/group header.
 * This is a borrowed lookahead and never advances or modifies the stream. */
bool transaction_v6_decode_is_prefix(const struct byte_stream *s);

/* Parse and store exactly one checked v6 frame, advancing only on success.
 * Transparent and Sapling model fields are populated; Orchard and Ironwood
 * remain checked opaque wire. The txid is the ZIP 229 digest; no proof,
 * signature, or contextual validity is established. The caller supplies
 * its network frame limit. On failure the stream cursor is unchanged and
 * tx is safe to transaction_free. */
bool transaction_v6_decode_prefix(struct transaction *tx, struct byte_stream *s,
                                  size_t max_size);

#endif
