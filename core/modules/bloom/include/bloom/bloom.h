/* Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_BLOOM_H
#define ZCL_BLOOM_H

#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_BLOOM_FILTER_SIZE 36000
#define MAX_BLOOM_HASH_FUNCS 50

enum bloom_flags {
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3
};

struct bloom_filter {
    unsigned char *data;
    size_t data_size;
    bool is_full;
    bool is_empty;
    unsigned int num_hash_funcs;
    unsigned int tweak;
    unsigned char flags;
};

/* Allocate and size a bloom filter for ~num_elements entries at the target
 * false-positive rate fp_rate. The backing bit-array size is capped at
 * MAX_BLOOM_FILTER_SIZE and the hash-function count at MAX_BLOOM_HASH_FUNCS;
 * tweak perturbs the hash so different filters salt differently. Returns
 * false (and leaves no allocation) only if the bit-array allocation fails. */
bool bloom_filter_init(struct bloom_filter *f, unsigned int num_elements,
                       double fp_rate, unsigned int tweak, unsigned char flags);
/* Release the bit-array and zero data/data_size. Safe to call once after init. */
void bloom_filter_free(struct bloom_filter *f);
/* Set the bits for one element. No-op when the filter is saturated (is_full). */
void bloom_filter_insert(struct bloom_filter *f, const unsigned char *data, size_t len);
/* Probabilistic membership: true if all of the element's bits are set.
 * May report false positives; never false negatives for inserted elements.
 * Returns true when is_full, false when is_empty. */
bool bloom_filter_contains(const struct bloom_filter *f, const unsigned char *data, size_t len);
/* Convenience wrappers that insert/test a 32-byte uint256 as the key. */
void bloom_filter_insert_uint256(struct bloom_filter *f, const struct uint256 *hash);
bool bloom_filter_contains_uint256(const struct bloom_filter *f, const struct uint256 *hash);
/* Zero all bits, keeping the existing sizing and tweak (filter becomes empty). */
void bloom_filter_clear(struct bloom_filter *f);
/* Clear all bits and adopt new_tweak as the hash salt. */
void bloom_filter_reset(struct bloom_filter *f, unsigned int new_tweak);
/* True if the filter's byte size and hash-function count are both within the
 * BIP37 wire limits (MAX_BLOOM_FILTER_SIZE / MAX_BLOOM_HASH_FUNCS). */
bool bloom_filter_is_within_size_constraints(const struct bloom_filter *f);

struct rolling_bloom_filter {
    struct bloom_filter b1;
    struct bloom_filter b2;
    unsigned int bloom_size;
    unsigned int insertions;
};

/* Build a rolling (generational) bloom filter that retains roughly the last
 * num_elements inserts, swapping between two sub-filters so old entries age
 * out instead of accumulating false positives. Each sub-filter is sized for
 * 2*num_elements and a random tweak. Returns false if either sub-filter's
 * allocation fails (any partial allocation is freed first). */
bool rolling_bloom_init(struct rolling_bloom_filter *f, unsigned int num_elements, double fp_rate);
/* Release both sub-filters. */
void rolling_bloom_free(struct rolling_bloom_filter *f);
/* Record one element, rotating the older generation when a window fills. */
void rolling_bloom_insert(struct rolling_bloom_filter *f, const unsigned char *data, size_t len);
/* Probabilistic membership over the retained window; false positives possible. */
bool rolling_bloom_contains(const struct rolling_bloom_filter *f, const unsigned char *data, size_t len);

/* BIP37 gating — returns true only if ZCL_ENABLE_BIP37=1 is set.
 * Default OFF because BIP37 is a known privacy leak (CVE-2014). */
bool bip37_enabled(void);

#endif
