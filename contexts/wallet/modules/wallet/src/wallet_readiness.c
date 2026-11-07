/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: wallet scan identity and readiness state. */

#include "base/serialize_le.h"
#include "wallet/wallet.h"
#include "sha3/sha3.h"

static void wallet_scan_hash_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, value);
    sha3_256_write(ctx, bytes, sizeof(bytes));
}

static bool wallet_scan_hash_transparent(const struct wallet *w, struct sha3_256_ctx *ctx)
{
    const struct basic_keystore *ks = &w->keystore;
    if (ks->num_keys > MAX_KEYSTORE_KEYS || ks->num_watching > MAX_KEYSTORE_WATCHING ||
        ks->num_scripts > MAX_KEYSTORE_SCRIPTS) return false;
    wallet_scan_hash_u64(ctx, ks->num_keys);
    for (size_t i = 0; i < ks->num_keys; i++) {
        uint8_t used = ks->keys[i].used;
        sha3_256_write(ctx, &used, 1);
        if (used) sha3_256_write(ctx, ks->keys[i].keyid.id.data, 20);
    }
    wallet_scan_hash_u64(ctx, ks->num_watching);
    for (size_t i = 0; i < ks->num_watching; i++) {
        uint8_t used = ks->watching[i].used;
        sha3_256_write(ctx, &used, 1);
        if (used) sha3_256_write(ctx, ks->watching[i].keyid.id.data, 20);
    }
    wallet_scan_hash_u64(ctx, ks->num_scripts);
    for (size_t i = 0; i < ks->num_scripts; i++) {
        const struct script_entry *e = &ks->scripts[i];
        uint8_t used = e->used;
        sha3_256_write(ctx, &used, 1);
        if (!used) continue;
        if (e->redeem_script.size > sizeof(e->redeem_script.data)) return false;
        sha3_256_write(ctx, e->script_id.data, 20);
        wallet_scan_hash_u64(ctx, e->redeem_script.size);
        sha3_256_write(ctx, e->redeem_script.data, e->redeem_script.size);
    }
    return true;
}

static bool wallet_scan_hash_sapling(const struct wallet *w, struct sha3_256_ctx *ctx)
{
    const struct sapling_keystore *ks = &w->sapling_keys;
    if (ks->locked || ks->num_unscannable || ks->num_damaged || ks->num_keys > MAX_SAPLING_KEYS)
        return false;
    wallet_scan_hash_u64(ctx, ks->has_seed);
    wallet_scan_hash_u64(ctx, ks->next_child_index);
    wallet_scan_hash_u64(ctx, ks->num_keys);
    for (size_t i = 0; i < ks->num_keys; i++) {
        const struct sapling_key_entry *e = &ks->keys[i];
        uint8_t used = e->used;
        sha3_256_write(ctx, &used, 1);
        if (!used) continue;
        wallet_scan_hash_u64(ctx, e->child_index);
        sha3_256_write(ctx, e->ivk, 32);
        sha3_256_write(ctx, e->xfvk.fvk.ak, 32);
        sha3_256_write(ctx, e->xfvk.fvk.nk, 32);
    }
    return true;
}

bool wallet_scan_identity_locked(const struct wallet *w, uint8_t digest[32])
{
    if (!w || !digest) return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const uint8_t domain[] = "z23-wallet-scan-identity-v1";
    sha3_256_write(&ctx, domain, sizeof(domain) - 1);
    wallet_scan_hash_u64(&ctx, w->has_master_key);
    wallet_scan_hash_u64(&ctx, w->hd_account);
    wallet_scan_hash_u64(&ctx, w->hd_external_counter);
    wallet_scan_hash_u64(&ctx, w->hd_internal_counter);
    if (!wallet_scan_hash_transparent(w, &ctx) || !wallet_scan_hash_sapling(w, &ctx))
        return false;
    sha3_256_finalize(&ctx, digest);
    return true;
}

bool wallet_scan_identity(struct wallet *w, uint8_t digest[32])
{
    if (!w || !digest || !zcl_mutex_trylock(&w->cs)) return false;
    if (!zcl_mutex_trylock(&w->keystore.cs)) { zcl_mutex_unlock(&w->cs); return false; }
    if (!zcl_mutex_trylock(&w->sapling_keys.cs)) {
        zcl_mutex_unlock(&w->keystore.cs); zcl_mutex_unlock(&w->cs); return false;
    }
    bool ok = wallet_scan_identity_locked(w, digest);
    zcl_mutex_unlock(&w->sapling_keys.cs);
    zcl_mutex_unlock(&w->keystore.cs);
    zcl_mutex_unlock(&w->cs);
    return ok;
}

struct wallet_readiness wallet_readiness_get_locked(const struct wallet *w)
{
    return w->readiness;
}

struct wallet_readiness wallet_readiness_get(const struct wallet *w)
{
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    struct wallet_readiness result = wallet_readiness_get_locked(w);
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return result;
}

bool wallet_readiness_initialize(struct wallet *w, enum wallet_readiness_state state,
                                 bool generation_present, uint64_t generation)
{
    if (!w || (state != WALLET_READINESS_READY && state != WALLET_READINESS_PENDING))
        return false;
    zcl_mutex_lock(&w->cs);
    bool ok = w->readiness.state == WALLET_READINESS_UNKNOWN && w->readiness.epoch == 0;
    if (ok) {
        w->readiness.state = state;
        w->readiness.generation_present = generation_present;
        w->readiness.generation = generation_present ? generation : 0;
        w->readiness.epoch = 1;
    }
    zcl_mutex_unlock(&w->cs);
    return ok;
}

bool wallet_readiness_can_complete_locked(const struct wallet *w, bool generation_present,
                                          uint64_t generation)
{
    return w && w->readiness.state == WALLET_READINESS_PENDING &&
           w->readiness.generation_present == generation_present &&
           (!generation_present || w->readiness.generation == generation) &&
           w->readiness.epoch != UINT64_MAX;
}

void wallet_readiness_complete_locked(struct wallet *w)
{
    w->readiness.state = WALLET_READINESS_READY;
    w->readiness.epoch++;
}

bool wallet_readiness_complete(struct wallet *w, bool generation_present,
                               uint64_t generation)
{
    if (!w) return false;
    zcl_mutex_lock(&w->cs);
    bool ok = wallet_readiness_can_complete_locked(w, generation_present, generation);
    if (ok) wallet_readiness_complete_locked(w);
    zcl_mutex_unlock(&w->cs);
    return ok;
}
