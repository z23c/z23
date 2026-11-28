/* purpose: Recover public fixture outgoing plaintext from an Ironwood action. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_PUBLIC_OUTGOING_H
#define ZCL_IRONWOOD_PUBLIC_OUTGOING_H
#include "base/result.h"
#include <stdint.h>
/* Inputs are public bytes from a checked action; this does not validate its
 * proof or establish consensus acceptance. Failure leaves out unchanged. */
struct ironwood_public_outgoing_input {
    uint8_t cv[32], cmx[32], epk[32], ciphertext[80];
};
struct ironwood_public_outgoing_plaintext {
    uint8_t pk_d[32], esk[32];
};
struct zcl_result ironwood_public_outgoing_recover(const struct ironwood_public_outgoing_input *input,
    const uint8_t ovk[32], struct ironwood_public_outgoing_plaintext *out);
#endif
