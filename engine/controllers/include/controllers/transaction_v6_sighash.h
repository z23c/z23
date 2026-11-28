/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Compute conditional v6 shielded signature digests. */
#ifndef Z23_CONTROLLER_TRANSACTION_V6_SIGHASH_H
#define Z23_CONTROLLER_TRANSACTION_V6_SIGHASH_H
#include "primitives/transaction_v6_digest.h"
/* Previous outputs are ordered exactly as transparent inputs. Script is raw
 * scriptPubKey bytes without CompactSize. Caller must obtain and authenticate
 * these from the UTXO view; this API does not validate transaction consensus.
 * Amount and script lengths must satisfy MAX_MONEY and MAX_SCRIPT_SIZE.
 * For no inputs or coinbase provide NULL, 0. Output unchanged on failure. */
struct v6_prevout { uint64_t amount; struct v6_span script_pubkey; };
bool v6_shielded_sighash(const struct v6_wire_view *, const struct v6_prevout *,
                         size_t count, uint8_t out[32]);
#endif
