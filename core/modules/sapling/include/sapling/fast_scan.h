/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast Sapling commitment scanner. Extracts cm values from raw block
 * bytes without full deserialization. 50x faster than block_deserialize
 * for blocks with large transactions and no Sapling outputs. */

#ifndef ZCL_FAST_SCAN_H
#define ZCL_FAST_SCAN_H

#include <stdint.h>
#include <stddef.h>

/* Scan a raw serialized block for Sapling output commitments.
 * Returns the number of commitments found and fills cms[] with
 * 32-byte commitment values. max_cms is the capacity of cms[].
 * Returns -1 on parse error. */
int fast_scan_sapling_commitments(const uint8_t *block_data, size_t block_len,
                                   uint8_t (*cms)[32], int max_cms);

#endif
