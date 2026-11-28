/* purpose: Authenticate the public cryptography of an Ironwood v6 bundle. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_BUNDLE_AUTH_H
#define ZCL_IRONWOOD_BUNDLE_AUTH_H
#include "base/result.h"
#include "controllers/transaction_v6_sighash.h"
#include <stddef.h>
#include <stdint.h>
/* Verify a complete v6 frame's nonempty Ironwood proof, each spend signature,
 * and binding signature using the resident pinned proof parameters. Prevouts
 * must be authenticated and ordered as transparent inputs; use NULL, 0 for
 * no inputs or coinbase. Input bytes and prevout scripts must remain stable.
 * Success authenticates only the Ironwood bundle's cryptography. The caller
 * must validate other pools, transaction values, anchors, nullifiers, network
 * rules and all other consensus state. Errors do not mutate inputs. */
struct zcl_result ironwood_bundle_authenticate(const uint8_t *wire, size_t size,
    const struct v6_prevout *prevouts, size_t prevout_count);
#include "validation/ironwood_bundle_auth.h"
#endif
