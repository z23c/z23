/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_REVIEW_H
#define ZCL_TX_REVIEW_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL transaction review requires ISO C23"
#endif

enum { ZCL_TX_REVIEW_MAX_BYTES = 2 * 1024 * 1024 };

typedef struct {
    uint32_t transparent_inputs;
    uint32_t transparent_outputs;
    uint32_t sapling_spends;
    uint32_t sapling_outputs;
    uint32_t sprout_joinsplits;
    uint32_t lock_time;
    uint32_t expiry_height;
    uint64_t transparent_output_zat;
    int64_t value_balance_zat;
} zcl_tx_review;

/* Parses the complete ZCL Sapling-v4 wire format. Proofs and signatures are
 * treated as opaque bytes. The result does not establish ownership, fee,
 * shielded recipient, shielded amount, or consensus validity. */
int zcl_tx_review_parse(const uint8_t *wire, size_t length,
                        zcl_tx_review *review);

#endif
