/* purpose: Verify public Ironwood action spend authorization signatures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_SPEND_AUTH_H
#define ZCL_IRONWOOD_SPEND_AUTH_H
#include "base/result.h"
#include <stdint.h>
/* Verify one action using its nonidentity randomized key, 64-byte RedPallas
 * signature and caller-computed 32-byte transaction sighash. This does not
 * validate the transaction or proof. Public data only, variable-time. The
 * binding signature uses a different generator and is outside this API. */
struct zcl_result ironwood_spend_auth_verify(const uint8_t rk[32],
    const uint8_t signature[64], const uint8_t sighash[32]);
#endif
