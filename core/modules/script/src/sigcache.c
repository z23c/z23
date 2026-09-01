/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "script/sigcache.h"
#include "crypto/sha256.h"
#include "core/random.h"
#include <string.h>

void sig_cache_init(struct sig_cache *cache)
{
    GetRandBytes(cache->nonce.data, 32);
    cache->count = 0;
    memset(cache->occupied, 0, sizeof(cache->occupied));
    zcl_mutex_init(&cache->mutex);
}

void sig_cache_destroy(struct sig_cache *cache)
{
    zcl_mutex_destroy(&cache->mutex);
}

void sig_cache_compute_entry(const struct sig_cache *cache,
                             struct uint256 *entry,
                             const struct uint256 *hash,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *pubkey, size_t pklen)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, cache->nonce.data, 32);
    sha256_write(&ctx, hash->data, 32);
    sha256_write(&ctx, pubkey, pklen);
    sha256_write(&ctx, sig, siglen);
    sha256_finalize(&ctx, entry->data);
}

static size_t cache_slot(const struct uint256 *entry)
{
    uint32_t h;
    memcpy(&h, entry->data, 4);
    return h % SIG_CACHE_MAX_ENTRIES;
}

bool sig_cache_get(struct sig_cache *cache, const struct uint256 *entry)
{
    zcl_mutex_lock(&cache->mutex);
    size_t slot = cache_slot(entry);
    bool found = cache->occupied[slot] &&
                 uint256_cmp(&cache->entries[slot], entry) == 0;
    zcl_mutex_unlock(&cache->mutex);
    return found;
}

void sig_cache_set(struct sig_cache *cache, const struct uint256 *entry)
{
    zcl_mutex_lock(&cache->mutex);
    size_t slot = cache_slot(entry);
    if (!cache->occupied[slot])
        cache->count++;
    cache->entries[slot] = *entry;
    cache->occupied[slot] = true;
    zcl_mutex_unlock(&cache->mutex);
}

void sig_cache_erase(struct sig_cache *cache, const struct uint256 *entry)
{
    zcl_mutex_lock(&cache->mutex);
    size_t slot = cache_slot(entry);
    if (cache->occupied[slot] &&
        uint256_cmp(&cache->entries[slot], entry) == 0) {
        cache->occupied[slot] = false;
        cache->count--;
    }
    zcl_mutex_unlock(&cache->mutex);
}

