/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_SIGCACHE_H
#define ZCL_SCRIPT_SIGCACHE_H

#include "core/uint256.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define DEFAULT_MAX_SIG_CACHE_SIZE 32
#define SIG_CACHE_MAX_ENTRIES 65536

struct sig_cache {
    struct uint256 nonce;
    struct uint256 entries[SIG_CACHE_MAX_ENTRIES];
    bool occupied[SIG_CACHE_MAX_ENTRIES];
    size_t count;
    zcl_mutex_t mutex;
};

/* Initialize a cache: draw a fresh random `nonce`, clear all slots, init the
 * mutex. The per-instance random nonce keys the entry hash so an attacker
 * cannot precompute colliding entries across nodes — do not replace it with a
 * fixed value. Pairs with sig_cache_destroy (frees the mutex). */
void sig_cache_init(struct sig_cache *cache);
void sig_cache_destroy(struct sig_cache *cache);

/* Compute the cache key for a (sighash, sig, pubkey) triple:
 * SHA256(nonce || hash || pubkey || sig). The nonce makes the key
 * node-private. Read-only on `cache` (mutex not needed). Callers compute the
 * entry, then probe with sig_cache_get / insert with sig_cache_set. */
void sig_cache_compute_entry(const struct sig_cache *cache,
                             struct uint256 *entry,
                             const struct uint256 *hash,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *pubkey, size_t pklen);

/* Membership probe. Returns true iff this exact entry was previously
 * sig_cache_set — meaning "this signature already verified, skip the ECDSA
 * check". SECURITY CONTRACT: a verifier may treat a hit as a validated
 * signature ONLY because an entry is inserted exclusively after a real
 * verification succeeds; never sig_cache_set an unverified entry. The 256-bit
 * key collision probability is negligible, so a false hit cannot forge a sig
 * in practice. Thread-safe (takes the mutex). */
bool sig_cache_get(struct sig_cache *cache, const struct uint256 *entry);

/* Record that `entry` (a verified signature key) is valid. Direct-mapped:
 * the slot is index = first 4 bytes of entry mod SIG_CACHE_MAX_ENTRIES, so a
 * new entry silently EVICTS any prior occupant of that slot (no chaining) —
 * eviction only costs a future re-verification, never correctness. Call ONLY
 * after the underlying signature actually verified. Thread-safe. */
void sig_cache_set(struct sig_cache *cache, const struct uint256 *entry);

/* Remove `entry` if present in its slot (used when an entry must be
 * invalidated). No-op if the slot holds a different/absent entry.
 * Thread-safe. */
void sig_cache_erase(struct sig_cache *cache, const struct uint256 *entry);

#endif
