/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: public SLH-DSA (FIPS 205) stateless hash-based signature interface. */
#ifndef ZCL_SLHDSA_SLHDSA_H
#define ZCL_SLHDSA_SLHDSA_H

/* SLH-DSA, NIST FIPS 205 (August 2024), SHAKE parameter sets SLH-DSA-SHAKE-128s
 * and SLH-DSA-SHAKE-192s. Security rests only on SHAKE256.
 *
 * This is the "pure" external interface (FIPS 205 Algorithms 22 and 24): the
 * signed message is M' = 0x00 || len(ctx) || ctx || M with a context string of
 * 0..255 bytes. There is no pre-hash (HashSLH-DSA) variant.
 *
 * Randomness: this module never reads an operating-system generator. The
 * hedged signer and key generation take a callback and the caller must supply
 * cryptographically secure random bytes through it. The deterministic signer
 * uses opt_rand = PK.seed as FIPS 205 permits.
 *
 * Every length is checked before any work is done; verification allocates
 * nothing and its stack use does not depend on attacker-chosen lengths. On any
 * failure every non-NULL output buffer is zeroed. Output buffers must not
 * overlap each other or any input. The caller owns the secret key and must
 * wipe it (base/cleanse.h) when it is no longer needed. The internal
 * algorithms are declared in slhdsa/slhdsa_kat.h for known-answer testing. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_slhdsa_param {
    ZCL_SLHDSA_SHAKE_128S = 0,
    ZCL_SLHDSA_SHAKE_192S = 1
};

enum {
    ZCL_SLHDSA_SHAKE_128S_PUBLIC_KEY_SIZE = 32,
    ZCL_SLHDSA_SHAKE_128S_SECRET_KEY_SIZE = 64,
    ZCL_SLHDSA_SHAKE_128S_SIGNATURE_SIZE = 7856,
    ZCL_SLHDSA_SHAKE_128S_RANDOM_SIZE = 16,   /* opt_rand, and n */
    ZCL_SLHDSA_SHAKE_128S_KEYGEN_SEED_SIZE = 48, /* SK.seed || SK.prf || PK.seed */

    ZCL_SLHDSA_SHAKE_192S_PUBLIC_KEY_SIZE = 48,
    ZCL_SLHDSA_SHAKE_192S_SECRET_KEY_SIZE = 96,
    ZCL_SLHDSA_SHAKE_192S_SIGNATURE_SIZE = 16224,
    ZCL_SLHDSA_SHAKE_192S_RANDOM_SIZE = 24,
    ZCL_SLHDSA_SHAKE_192S_KEYGEN_SEED_SIZE = 72,

    ZCL_SLHDSA_MAX_PUBLIC_KEY_SIZE = 48,
    ZCL_SLHDSA_MAX_SECRET_KEY_SIZE = 96,
    ZCL_SLHDSA_MAX_SIGNATURE_SIZE = 16224,
    ZCL_SLHDSA_MAX_RANDOM_SIZE = 24,
    ZCL_SLHDSA_MAX_CONTEXT_SIZE = 255
};

enum zcl_slhdsa_status {
    ZCL_SLHDSA_OK = 0,
    ZCL_SLHDSA_ERR_ARGUMENT,  /* NULL pointer or unknown parameter set */
    ZCL_SLHDSA_ERR_LENGTH,    /* key, signature or seed has the wrong length */
    ZCL_SLHDSA_ERR_CONTEXT,   /* context string longer than 255 bytes */
    ZCL_SLHDSA_ERR_RANDOM,    /* the random callback reported failure */
    ZCL_SLHDSA_ERR_VERIFY     /* well-formed input, signature does not verify */
};

/* Fills out[0..len) with cryptographically secure random bytes and returns
 * true, or returns false on failure. */
typedef bool (*zcl_slhdsa_random_fn)(void *context, uint8_t *out, size_t len);

/* Sizes for a parameter set, or 0 for an unknown one. */
[[nodiscard]] size_t zcl_slhdsa_public_key_size(enum zcl_slhdsa_param param);
[[nodiscard]] size_t zcl_slhdsa_secret_key_size(enum zcl_slhdsa_param param);
[[nodiscard]] size_t zcl_slhdsa_signature_size(enum zcl_slhdsa_param param);

/* FIPS 205 Algorithm 21 (slh_keygen) with seeds drawn from the callback. */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_keygen(
    enum zcl_slhdsa_param param, zcl_slhdsa_random_fn random, void *random_ctx,
    uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);

/* FIPS 205 Algorithm 22 (slh_sign), hedged: opt_rand comes from the callback. */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_sign(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    zcl_slhdsa_random_fn random, void *random_ctx,
    uint8_t *sig, size_t sig_len);

/* FIPS 205 Algorithm 22 (slh_sign), deterministic: opt_rand = PK.seed. */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_sign_deterministic(
    enum zcl_slhdsa_param param, const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    uint8_t *sig, size_t sig_len);

/* FIPS 205 Algorithm 24 (slh_verify). Returns ZCL_SLHDSA_OK only for a valid
 * signature; ZCL_SLHDSA_ERR_VERIFY for a well-formed signature that fails. */
[[nodiscard]] enum zcl_slhdsa_status zcl_slhdsa_verify(
    enum zcl_slhdsa_param param, const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *sig, size_t sig_len);

#endif /* ZCL_SLHDSA_SLHDSA_H */
