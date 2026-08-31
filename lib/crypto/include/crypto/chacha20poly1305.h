/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ChaCha20-Poly1305 AEAD (RFC 7539) — pure C23 implementation.
 * Replaces libsodium crypto_aead_chacha20poly1305_ietf_encrypt/decrypt. */

#ifndef ZCL_CRYPTO_CHACHA20POLY1305_H
#define ZCL_CRYPTO_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define POLY1305_TAG_SIZE 16

void chacha20_block(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12], uint8_t out[64]);

/* Encrypt disjoint buffers or exactly in place. Returns false without writing
 * when len would exhaust the 32-bit IETF ChaCha20 counter space. */
bool chacha20_encrypt(const uint8_t key[32], uint32_t counter,
                       const uint8_t nonce[12],
                       const uint8_t *plaintext, size_t len,
                       uint8_t *ciphertext);

/* Select the four-stream bulk implementation used by chacha20_encrypt().
 * VECTOR4 is arm64 NEON or x86-64 SSE2 and is installed only after a one-time
 * portable-oracle KAT. A request can narrow to PORTABLE but cannot override a
 * failed KAT. AUTO is the production default. The scalar chacha20_block()
 * remains the frozen oracle on every platform. */
enum chacha20_impl {
    CHACHA20_IMPL_AUTO = -1,
    CHACHA20_IMPL_PORTABLE = 0,
    CHACHA20_IMPL_VECTOR4 = 1,
};
int chacha20_select_impl(enum chacha20_impl which);
bool chacha20_vector4_compiled(void);
bool chacha20_vector4_available(void);
const char *chacha20_implementation(void);

void poly1305_mac(const uint8_t *message, size_t len,
                   const uint8_t key[32], uint8_t tag[16]);

bool chacha20poly1305_encrypt(const uint8_t *plaintext, size_t plen,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t nonce[12],
                                const uint8_t key[32],
                                uint8_t *ciphertext);

bool chacha20poly1305_decrypt(const uint8_t *ciphertext, size_t clen,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t nonce[12],
                                const uint8_t key[32],
                                uint8_t *plaintext);

#endif
