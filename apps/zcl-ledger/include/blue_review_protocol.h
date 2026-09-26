/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REVIEW_PROTOCOL_H
#define ZCL_BLUE_REVIEW_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "zcl_tx_review.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue review protocol requires ISO C23"
#endif

enum { ZCL_BLUE_REVIEW_MAX_BYTES = 4096 };

typedef struct {
    uint8_t wire[ZCL_BLUE_REVIEW_MAX_BYTES];
    uint16_t expected;
    uint16_t received;
} blue_review_state;

typedef bool (*blue_review_digest_fn)(const uint8_t *bytes, size_t length,
                                       uint8_t digest[32]);

/* Returns a BOLOS status word. Success response bytes never contain keys or
 * signatures. The caller appends the status word to the APDU reply. */
uint16_t blue_review_handle(blue_review_state *state,
                            const uint8_t *apdu, size_t apdu_length,
                            uint8_t *reply, size_t reply_capacity,
                            size_t *reply_length,
                            blue_review_digest_fn digest);

void blue_review_encode_summary(const zcl_tx_review *review,
                                uint8_t reply[44]);

#endif
