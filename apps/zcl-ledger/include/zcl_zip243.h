/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_ZIP243_H
#define ZCL_ZIP243_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZIP-243 digest computation requires ISO C23"
#endif

typedef struct {
    void *context;
    bool (*init)(void *context, const uint8_t personal[16]);
    bool (*update)(void *context, const uint8_t *bytes, size_t length);
    bool (*final)(void *context, uint8_t digest[32]);
} zcl_zip243_hasher;

/* Computes the ZIP-243 SIGHASH_ALL digest for Sapling spend authorization and
 * binding signatures (NOT_AN_INPUT). The caller supplies the consensus branch
 * ID and a streaming personalized BLAKE2b-256 implementation. This function never
 * signs, validates proofs, or determines the active consensus branch. */
int zcl_zip243_shielded_digest(const uint8_t *wire, size_t length,
                                uint32_t branch_id,
                                const zcl_zip243_hasher *hasher,
                                uint8_t digest[32]);

#endif
