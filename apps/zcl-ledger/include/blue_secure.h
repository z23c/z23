/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SECURE_H
#define ZCL_BLUE_SECURE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Ledger Blue installer requires ISO C23"
#endif

typedef struct {
    uint8_t enc_key[16], mac_key[16], enc_iv[16], mac_iv[16];
} blue_secure_channel;

EVP_PKEY *blue_key_generate(void);
int blue_key_public(EVP_PKEY *key, uint8_t output[65]);
int blue_sign(EVP_PKEY *key, const uint8_t *message, size_t length,
              uint8_t *signature, size_t *signature_length);
int blue_verify(const uint8_t public_key[65], const uint8_t *message,
                size_t length, const uint8_t *signature, size_t signature_length);
int blue_ecdh(EVP_PKEY *local, const uint8_t peer[65], uint8_t secret[32]);
int blue_secure_init(blue_secure_channel *channel, const uint8_t secret[32]);
int blue_secure_wrap(blue_secure_channel *channel, const uint8_t *plain,
                     size_t plain_length, uint8_t *output, size_t capacity,
                     size_t *output_length);
int blue_secure_unwrap(blue_secure_channel *channel, const uint8_t *input,
                       size_t input_length, uint8_t *plain, size_t capacity,
                       size_t *plain_length);

#endif
