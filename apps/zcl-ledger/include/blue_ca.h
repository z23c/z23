/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_CA_H
#define ZCL_BLUE_CA_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Ledger Blue CA manager requires ISO C23"
#endif

int blue_ca_generate(const char *path);
EVP_PKEY *blue_ca_load(const char *path);
int blue_ca_sign_digest(EVP_PKEY *key, const uint8_t digest[32],
                        uint8_t signature[73], size_t *signature_length);
int blue_ca_app_hash(uint32_t target, const uint8_t create[21],
                     const uint8_t *code, size_t code_length,
                     const uint8_t *params, size_t params_length,
                     uint8_t digest[32]);

#endif
