/* purpose: Recover public fixture outgoing plaintext from an Ironwood action. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_public_outgoing.h"
#include "crypto/blake2b.h"
#include "crypto/chacha20poly1305.h"
#include <string.h>

struct zcl_result ironwood_public_outgoing_recover(const struct ironwood_public_outgoing_input *input,
    const uint8_t ovk[32], struct ironwood_public_outgoing_plaintext *out)
{
    static const uint8_t domain[16] = { 'Z', 'c', 'a', 's', 'h', '_', 'O', 'r', 'c', 'h', 'a', 'r', 'd', 'o', 'c', 'k' };
    static const uint8_t nonce[12] = {0};
    if (!input || !ovk || !out) return ZCL_ERR(-1, "Invalid outgoing recovery input");
    struct blake2b_ctx hash;
    uint8_t key[32], plain[64];
    if (blake2b_init_salt_personal(&hash, sizeof key, NULL, 0, NULL, domain) ||
        blake2b_update(&hash, ovk, 32) || blake2b_update(&hash, input->cv, 32) ||
        blake2b_update(&hash, input->cmx, 32) || blake2b_update(&hash, input->epk, 32) ||
        blake2b_final(&hash, key, sizeof key) ||
        !chacha20poly1305_decrypt(input->ciphertext, sizeof input->ciphertext,
                                  NULL, 0, nonce, key, plain)) return ZCL_ERR(-1, "Outgoing recovery authentication failed");
    memcpy(out->pk_d, plain, 32);
    memcpy(out->esk, plain + 32, 32);
    return ZCL_OK;
}
