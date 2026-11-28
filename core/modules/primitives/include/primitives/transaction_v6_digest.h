/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Compute ZIP 229 digests from checked v6 transaction views.
 */
#ifndef Z23_TRANSACTION_V6_DIGEST_H
#define Z23_TRANSACTION_V6_DIGEST_H
#include "primitives/transaction_v6_wire.h"
/* Digests are raw ZIP 229 bytes; transaction identifiers may render reversed. */
struct v6_digests {
    uint8_t txid[32], auth[32];
    uint8_t sapling_effect[32], sapling_auth[32];
    uint8_t orchard_effect[32], orchard_auth[32];
    uint8_t ironwood_effect[32], ironwood_auth[32];
    uint8_t header_effect[32], transparent_effect[32];
};
/* View must come from a successful parse and its borrowed bytes stay immutable.
 * Structural inspection only: this does not verify signatures or proofs. */
bool v6_wire_digests(const struct v6_wire_view *, struct v6_digests *);
#endif
