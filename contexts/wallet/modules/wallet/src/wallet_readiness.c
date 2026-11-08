/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: wallet scan identity and readiness state. */

#include "base/serialize_le.h"
#include "wallet/wallet.h"
#include "sha3/sha3.h"
#include "base/cleanse.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

/* The same ordered byte stream defines both the persistent digest and the
 * ephemeral exact comparison. Callers hold wallet, transparent and Sapling locks. */
typedef bool (*wallet_scan_emit_fn)(void *, const void *, size_t);
struct wallet_scan_sink { wallet_scan_emit_fn emit; void *ctx; };

static bool wallet_scan_u64(struct wallet_scan_sink *sink, uint64_t value)
{
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, value);
    return sink->emit(sink->ctx, bytes, sizeof(bytes));
}

static bool wallet_scan_keys(const struct basic_keystore *ks, struct wallet_scan_sink *sink)
{
    if (ks->num_keys > MAX_KEYSTORE_KEYS || !wallet_scan_u64(sink, ks->num_keys)) return false;
    for (size_t i = 0; i < ks->num_keys; i++) {
        uint8_t used = ks->keys[i].used;
        if (!sink->emit(sink->ctx, &used, 1) ||
            (used && !sink->emit(sink->ctx, ks->keys[i].keyid.id.data, 20))) return false;
    }
    if (ks->num_watching > MAX_KEYSTORE_WATCHING || !wallet_scan_u64(sink, ks->num_watching)) return false;
    for (size_t i = 0; i < ks->num_watching; i++) {
        uint8_t used = ks->watching[i].used;
        if (!sink->emit(sink->ctx, &used, 1) ||
            (used && !sink->emit(sink->ctx, ks->watching[i].keyid.id.data, 20))) return false;
    }
    return true;
}
static bool wallet_scan_scripts(const struct basic_keystore *ks, struct wallet_scan_sink *sink)
{
    if (ks->num_scripts > MAX_KEYSTORE_SCRIPTS || !wallet_scan_u64(sink, ks->num_scripts)) return false;
    for (size_t i = 0; i < ks->num_scripts; i++) {
        const struct script_entry *e = &ks->scripts[i];
        uint8_t used = e->used;
        if (!sink->emit(sink->ctx, &used, 1)) return false;
        if (!used) continue;
        if (e->redeem_script.size > sizeof(e->redeem_script.data) ||
            !sink->emit(sink->ctx, e->script_id.data, 20) ||
            !wallet_scan_u64(sink, e->redeem_script.size) ||
            !sink->emit(sink->ctx, e->redeem_script.data, e->redeem_script.size)) return false;
    }
    return true;
}
static bool wallet_scan_transparent(const struct wallet *w, struct wallet_scan_sink *sink)
{
    return wallet_scan_keys(&w->keystore, sink) && wallet_scan_scripts(&w->keystore, sink);
}

static bool wallet_scan_sapling(const struct wallet *w, struct wallet_scan_sink *sink)
{
    const struct sapling_keystore *ks = &w->sapling_keys;
    if (ks->locked || ks->num_unscannable || ks->num_damaged || ks->num_keys > MAX_SAPLING_KEYS ||
        !wallet_scan_u64(sink, ks->has_seed) || !wallet_scan_u64(sink, ks->next_child_index) ||
        !wallet_scan_u64(sink, ks->num_keys)) return false;
    for (size_t i = 0; i < ks->num_keys; i++) {
        const struct sapling_key_entry *e = &ks->keys[i];
        uint8_t used = e->used;
        if (!sink->emit(sink->ctx, &used, 1)) return false;
        if (!used) continue;
        if (!wallet_scan_u64(sink, e->child_index) || !sink->emit(sink->ctx, e->ivk, 32) ||
            !sink->emit(sink->ctx, e->xfvk.fvk.ak, 32) || !sink->emit(sink->ctx, e->xfvk.fvk.nk, 32)) return false;
    }
    return true;
}

static bool wallet_scan_walk(const struct wallet *w, struct wallet_scan_sink *sink)
{
    static const uint8_t domain[] = "z23-wallet-scan-identity-v1";
    return w && sink && sink->emit && sink->emit(sink->ctx, domain, sizeof(domain) - 1) &&
        wallet_scan_u64(sink, w->has_master_key) && wallet_scan_u64(sink, w->hd_account) &&
        wallet_scan_u64(sink, w->hd_external_counter) && wallet_scan_u64(sink, w->hd_internal_counter) &&
        wallet_scan_transparent(w, sink) && wallet_scan_sapling(w, sink);
}

static bool wallet_scan_hash_emit(void *opaque, const void *bytes, size_t size)
{
    sha3_256_write(opaque, bytes, size);
    return true;
}

bool wallet_scan_identity_locked(const struct wallet *w, uint8_t digest[32])
{
    if (!w || !digest) return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    struct wallet_scan_sink sink = {wallet_scan_hash_emit, &ctx};
    if (!wallet_scan_walk(w, &sink)) return false;
    sha3_256_finalize(&ctx, digest);
    return true;
}

struct wallet_scan_snapshot { size_t size; uint8_t bytes[]; };
struct wallet_scan_buffer { uint8_t *bytes; size_t size, pos; };

static bool wallet_scan_count_emit(void *opaque, const void *bytes, size_t size)
{
    size_t *total = opaque;
    (void)bytes;
    if (size > SIZE_MAX - *total) return false;
    *total += size;
    return true;
}
static bool wallet_scan_copy_emit(void *opaque, const void *bytes, size_t size)
{
    struct wallet_scan_buffer *b = opaque;
    if (size > b->size - b->pos) return false;
    memcpy(b->bytes + b->pos, bytes, size);
    b->pos += size;
    return true;
}
static bool wallet_scan_compare_emit(void *opaque, const void *bytes, size_t size)
{
    struct wallet_scan_buffer *b = opaque;
    if (size > b->size - b->pos || memcmp(b->bytes + b->pos, bytes, size)) return false;
    b->pos += size;
    return true;
}

bool wallet_scan_snapshot_capture_locked(const struct wallet *w, const uint8_t expected[32],
                                         struct wallet_scan_snapshot **out)
{
    if (!out) return false;
    *out = NULL;
    if (!w || !expected) return false;
    size_t size = 0;
    struct wallet_scan_sink count = {wallet_scan_count_emit, &size};
    if (!wallet_scan_walk(w, &count) || size > SIZE_MAX - sizeof(struct wallet_scan_snapshot)) return false;
    struct wallet_scan_snapshot *snapshot = zcl_malloc(sizeof(*snapshot) + size, "wallet scan snapshot");
    if (!snapshot) return false;
    snapshot->size = size;
    struct wallet_scan_buffer buffer = {snapshot->bytes, size, 0};
    struct wallet_scan_sink copy = {wallet_scan_copy_emit, &buffer};
    uint8_t digest[32];
    bool ok = wallet_scan_walk(w, &copy) && buffer.pos == size;
    if (ok) {
        sha3_256(snapshot->bytes, size, digest);
        ok = memcmp(digest, expected, sizeof(digest)) == 0;
        memory_cleanse(digest, sizeof(digest));
    }
    if (!ok) { wallet_scan_snapshot_free(snapshot); return false; }
    *out = snapshot;
    return true;
}

bool wallet_scan_snapshot_matches_locked(const struct wallet *w, const struct wallet_scan_snapshot *snapshot)
{
    if (!w || !snapshot) return false;
    struct wallet_scan_buffer buffer = {(uint8_t *)snapshot->bytes, snapshot->size, 0};
    struct wallet_scan_sink compare = {wallet_scan_compare_emit, &buffer};
    return wallet_scan_walk(w, &compare) && buffer.pos == buffer.size;
}

void wallet_scan_snapshot_free(struct wallet_scan_snapshot *snapshot)
{
    if (!snapshot) return;
    size_t size = snapshot->size;
    memory_cleanse(snapshot, sizeof(*snapshot) + size);
    free(snapshot);
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
