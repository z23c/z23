/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: known-answer-test-only SLH-DSA internal algorithms. */
#ifndef ZCL_SLHDSA_SLHDSA_KAT_H
#define ZCL_SLHDSA_SLHDSA_KAT_H

/* SLH-DSA internal algorithms for known-answer testing only (FIPS 205
 * Algorithms 18, 19 and 20). The internal signer signs the caller's bytes
 * directly, with no context-string encoding; production code includes
 * slhdsa/slhdsa.h and uses the external interface. The buffer rules of
 * slhdsa/slhdsa.h apply. */

#include "slhdsa/slhdsa.h"

/* slh_keygen_internal: seed is SK.seed || SK.prf || PK.seed (3n bytes). */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_keygen_internal(
    enum zcl_slhdsa_param param, const uint8_t *seed, size_t seed_len,
    uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);

/* slh_sign_internal: opt_rand has n bytes, or is NULL with opt_rand_len 0 for
 * the deterministic variant (opt_rand = PK.seed). */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_sign_internal(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *opt_rand, size_t opt_rand_len,
    uint8_t *sig, size_t sig_len);

/* slh_verify_internal. */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_verify_internal(
    enum zcl_slhdsa_param param, const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

#endif /* ZCL_SLHDSA_SLHDSA_KAT_H */
