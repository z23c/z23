/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "wallet/sapling_keys.h"
#include "core/random.h"
#include "domain/encoding/bech32.h"
#include "encoding/utilstrencodings.h"
#include "sapling/sapling.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>

void sapling_keystore_init(struct sapling_keystore *sks)
{
    zcl_mutex_init(&sks->cs);
    memset(sks->seed, 0, 32);
    sks->has_seed = false;
    sks->next_child_index = 0;
    sks->num_keys = 0;
    memset(sks->keys, 0, sizeof(sks->keys));
}

void sapling_keystore_free(struct sapling_keystore *sks)
{
    memory_cleanse(sks->seed, 32);
    memory_cleanse(&sks->master_xsk, sizeof(sks->master_xsk));
    for (size_t i = 0; i < sks->num_keys; i++) {
        if (sks->keys[i].used)
            memory_cleanse(&sks->keys[i].xsk, sizeof(struct zip32_xsk));
    }
    zcl_mutex_destroy(&sks->cs);
}

bool sapling_keystore_generate_seed(struct sapling_keystore *sks)
{
    zcl_mutex_lock(&sks->cs);
    GetRandBytes(sks->seed, 32);
    sks->has_seed = true;
    zip32_xsk_master(&sks->master_xsk, sks->seed, 32);
    sks->next_child_index = 0;
    zcl_mutex_unlock(&sks->cs);
    return true;
}

bool sapling_keystore_set_seed(struct sapling_keystore *sks,
                                const uint8_t seed[32])
{
    zcl_mutex_lock(&sks->cs);
    memcpy(sks->seed, seed, 32);
    sks->has_seed = true;
    zip32_xsk_master(&sks->master_xsk, sks->seed, 32);
    sks->next_child_index = 0;
    zcl_mutex_unlock(&sks->cs);
    return true;
}

bool sapling_keystore_new_address_transactional(
    struct sapling_keystore *sks,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
    uint8_t pk_d_out[32],
    struct sapling_address_undo *undo_out)
{
    if (undo_out)
        memset(undo_out, 0, sizeof(*undo_out));
    zcl_mutex_lock(&sks->cs);

    bool generated_seed = false;
    if (!sks->has_seed) {
        GetRandBytes(sks->seed, 32);
        sks->has_seed = true;
        zip32_xsk_master(&sks->master_xsk, sks->seed, 32);
        generated_seed = true;
    }

    if (sks->num_keys >= MAX_SAPLING_KEYS) {
        zcl_mutex_unlock(&sks->cs);
        /* Keystore at capacity — tell the caller why new_address() failed. */
        LOG_WARN("sapling_keys",
                 "new_address: keystore full (%d/%d keys)",
                 (int)sks->num_keys, MAX_SAPLING_KEYS);
        return false;
    }

    /* Derive child: m/32'/coin_type'/account'
     * ZClassic uses coin_type = 147 (registered in SLIP-0044) */
    struct zip32_xsk purpose_key, coin_key, account_key;
    zip32_xsk_derive(&purpose_key, &sks->master_xsk,
                     32 | ZIP32_HARDENED_KEY_LIMIT);
    zip32_xsk_derive(&coin_key, &purpose_key,
                     147 | ZIP32_HARDENED_KEY_LIMIT);
    zip32_xsk_derive(&account_key, &coin_key,
                     sks->next_child_index | ZIP32_HARDENED_KEY_LIMIT);

    struct zip32_xfvk xfvk;
    zip32_xsk_to_xfvk(&xfvk, &account_key);

    uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    if (!zip32_xfvk_address(&xfvk, diversifier, pk_d)) {
        memory_cleanse(&purpose_key, sizeof(purpose_key));
        memory_cleanse(&coin_key, sizeof(coin_key));
        memory_cleanse(&account_key, sizeof(account_key));
        zcl_mutex_unlock(&sks->cs);
        return false;
    }

    /* Compute IVK for this key */
    uint8_t ivk[32];
    sapling_crh_ivk(xfvk.fvk.ak, xfvk.fvk.nk, ivk);

    struct sapling_key_entry *entry = &sks->keys[sks->num_keys];
    entry->xsk = account_key;
    entry->xfvk = xfvk;
    memcpy(entry->diversifier, diversifier, ZC_DIVERSIFIER_SIZE);
    memcpy(entry->pk_d, pk_d, 32);
    memcpy(entry->ivk, ivk, 32);
    entry->child_index = sks->next_child_index;
    entry->used = true;
    sks->num_keys++;
    sks->next_child_index++;

    if (undo_out) {
        undo_out->child_index = entry->child_index;
        undo_out->generated_seed = generated_seed;
        undo_out->valid = true;
    }

    memcpy(diversifier_out, diversifier, ZC_DIVERSIFIER_SIZE);
    memcpy(pk_d_out, pk_d, 32);

    memory_cleanse(&purpose_key, sizeof(purpose_key));
    memory_cleanse(&coin_key, sizeof(coin_key));
    memory_cleanse(&account_key, sizeof(account_key));

    zcl_mutex_unlock(&sks->cs);
    return true;
}

bool sapling_keystore_new_address(struct sapling_keystore *sks,
                                   uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
                                   uint8_t pk_d_out[32])
{
    return sapling_keystore_new_address_transactional(
        sks, diversifier_out, pk_d_out, NULL);
}

bool sapling_keystore_rollback_address(
    struct sapling_keystore *sks,
    const struct sapling_address_undo *undo)
{
    if (!sks || !undo || !undo->valid)
        LOG_FAIL("sapling_keys", "rollback_address: invalid arguments/token");

    zcl_mutex_lock(&sks->cs);
    if (sks->num_keys == 0 ||
        sks->next_child_index != undo->child_index + 1) {
        zcl_mutex_unlock(&sks->cs);
        LOG_FAIL("sapling_keys",
                 "rollback_address: child %u is no longer the latest",
                 undo->child_index);
    }
    struct sapling_key_entry *entry = &sks->keys[sks->num_keys - 1];
    if (!entry->used || entry->child_index != undo->child_index) {
        zcl_mutex_unlock(&sks->cs);
        LOG_FAIL("sapling_keys",
                 "rollback_address: latest entry does not match child %u",
                 undo->child_index);
    }

    memory_cleanse(entry, sizeof(*entry));
    sks->num_keys--;
    sks->next_child_index = undo->child_index;
    if (undo->generated_seed && sks->num_keys == 0) {
        memory_cleanse(sks->seed, sizeof(sks->seed));
        memory_cleanse(&sks->master_xsk, sizeof(sks->master_xsk));
        sks->has_seed = false;
        sks->next_child_index = 0;
    }
    zcl_mutex_unlock(&sks->cs);
    return true;
}

bool sapling_encode_payment_address(const uint8_t diversifier[ZC_DIVERSIFIER_SIZE],
                                     const uint8_t pk_d[32],
                                     const char *hrp,
                                     char *out, size_t out_size)
{
    /* Serialize: diversifier(11) || pk_d(32) = 43 bytes */
    uint8_t raw[43];
    memcpy(raw, diversifier, ZC_DIVERSIFIER_SIZE);
    memcpy(raw + ZC_DIVERSIFIER_SIZE, pk_d, 32);

    /* Convert 8-bit to 5-bit for Bech32 */
    uint8_t data5[69]; /* ceil(43 * 8 / 5) = 69 */
    size_t data5_len = 0;
    if (!ConvertBits(8, 5, true, raw, 43, data5, sizeof(data5), &data5_len))
        return false;

    return domain_encoding_bech32_encode(out, out_size, hrp, data5, data5_len);
}

bool sapling_decode_payment_address(const char *str,
                                     uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
                                     uint8_t pk_d_out[32])
{
    char hrp[64];
    uint8_t data5[128];
    size_t data5_len = 0;
    if (!domain_encoding_bech32_decode(hrp, sizeof(hrp), data5, sizeof(data5), &data5_len, str))
        return false;

    uint8_t raw[64];
    size_t raw_len = 0;
    if (!ConvertBits(5, 8, false, data5, data5_len, raw, sizeof(raw), &raw_len))
        return false;

    if (raw_len != 43)
        return false;

    memcpy(diversifier_out, raw, ZC_DIVERSIFIER_SIZE);
    memcpy(pk_d_out, raw + ZC_DIVERSIFIER_SIZE, 32);
    return true;
}

bool sapling_keystore_have_spending_key(const struct sapling_keystore *sks,
                                         const uint8_t ivk[32])
{
    if (!sks || !ivk)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&sks->cs);
    for (size_t i = 0; i < sks->num_keys; i++) {
        if (sks->keys[i].used && memcmp(sks->keys[i].ivk, ivk, 32) == 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
    return false;
}

const struct sapling_key_entry *sapling_keystore_find_by_ivk(
    const struct sapling_keystore *sks, const uint8_t ivk[32])
{
    if (!sks || !ivk)
        return NULL;
    zcl_mutex_lock((zcl_mutex_t *)&sks->cs);
    for (size_t i = 0; i < sks->num_keys; i++) {
        if (sks->keys[i].used && memcmp(sks->keys[i].ivk, ivk, 32) == 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
            return &sks->keys[i];
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
    return NULL;
}

const struct sapling_key_entry *sapling_keystore_find_by_address(
    const struct sapling_keystore *sks,
    const uint8_t diversifier[ZC_DIVERSIFIER_SIZE],
    const uint8_t pk_d[32])
{
    if (!sks || !diversifier || !pk_d)
        return NULL;
    zcl_mutex_lock((zcl_mutex_t *)&sks->cs);
    for (size_t i = 0; i < sks->num_keys; i++) {
        if (sks->keys[i].used &&
            memcmp(sks->keys[i].diversifier, diversifier, ZC_DIVERSIFIER_SIZE) == 0 &&
            memcmp(sks->keys[i].pk_d, pk_d, 32) == 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
            return &sks->keys[i];
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&sks->cs);
    return NULL;
}

bool sapling_keystore_import_xsk(struct sapling_keystore *sks,
                                  const struct zip32_xsk *xsk)
{
    zcl_mutex_lock(&sks->cs);

    if (sks->num_keys >= MAX_SAPLING_KEYS) {
        zcl_mutex_unlock(&sks->cs);
        /* Keystore at capacity — tell the caller why import_xsk() failed. */
        LOG_WARN("sapling_keys",
                 "import_xsk: keystore full (%d/%d keys)",
                 (int)sks->num_keys, MAX_SAPLING_KEYS);
        return false;
    }

    struct zip32_xfvk xfvk;
    zip32_xsk_to_xfvk(&xfvk, xsk);

    uint8_t ivk[32];
    sapling_crh_ivk(xfvk.fvk.ak, xfvk.fvk.nk, ivk);

    /* Check for duplicate */
    for (size_t i = 0; i < sks->num_keys; i++) {
        if (sks->keys[i].used && memcmp(sks->keys[i].ivk, ivk, 32) == 0) {
            zcl_mutex_unlock(&sks->cs);
            return false;
        }
    }

    uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    if (!zip32_xfvk_address(&xfvk, diversifier, pk_d)) {
        zcl_mutex_unlock(&sks->cs);
        return false;
    }

    struct sapling_key_entry *entry = &sks->keys[sks->num_keys];
    entry->xsk = *xsk;
    entry->xfvk = xfvk;
    memcpy(entry->diversifier, diversifier, ZC_DIVERSIFIER_SIZE);
    memcpy(entry->pk_d, pk_d, 32);
    memcpy(entry->ivk, ivk, 32);
    entry->child_index = xsk->child_index;
    entry->used = true;
    sks->num_keys++;

    zcl_mutex_unlock(&sks->cs);
    return true;
}

/* Serialize zip32_xsk to 169 bytes (C++ compatible layout):
 * depth(1) | parentFVKTag(4,LE) | childIndex(4,LE) | chaincode(32) |
 * ask(32) | nsk(32) | ovk(32) | dk(32) */
static void xsk_serialize(const struct zip32_xsk *xsk, uint8_t out[ZIP32_XSK_SERIALIZED_SIZE])
{
    size_t p = 0;
    out[p++] = xsk->depth;
    out[p++] = (xsk->parent_fvk_tag >> 0) & 0xff;
    out[p++] = (xsk->parent_fvk_tag >> 8) & 0xff;
    out[p++] = (xsk->parent_fvk_tag >> 16) & 0xff;
    out[p++] = (xsk->parent_fvk_tag >> 24) & 0xff;
    out[p++] = (xsk->child_index >> 0) & 0xff;
    out[p++] = (xsk->child_index >> 8) & 0xff;
    out[p++] = (xsk->child_index >> 16) & 0xff;
    out[p++] = (xsk->child_index >> 24) & 0xff;
    memcpy(out + p, xsk->chain_code, 32); p += 32;
    memcpy(out + p, xsk->expsk.ask, 32); p += 32;
    memcpy(out + p, xsk->expsk.nsk, 32); p += 32;
    memcpy(out + p, xsk->expsk.ovk, 32); p += 32;
    memcpy(out + p, xsk->dk, 32); p += 32;
    (void)p;
}

static bool xsk_deserialize(const uint8_t in[ZIP32_XSK_SERIALIZED_SIZE],
                             struct zip32_xsk *xsk)
{
    size_t p = 0;
    xsk->depth = in[p++];
    xsk->parent_fvk_tag = (uint32_t)in[p] | ((uint32_t)in[p+1] << 8) |
                           ((uint32_t)in[p+2] << 16) | ((uint32_t)in[p+3] << 24);
    p += 4;
    xsk->child_index = (uint32_t)in[p] | ((uint32_t)in[p+1] << 8) |
                        ((uint32_t)in[p+2] << 16) | ((uint32_t)in[p+3] << 24);
    p += 4;
    memcpy(xsk->chain_code, in + p, 32); p += 32;
    memcpy(xsk->expsk.ask, in + p, 32); p += 32;
    memcpy(xsk->expsk.nsk, in + p, 32); p += 32;
    memcpy(xsk->expsk.ovk, in + p, 32); p += 32;
    memcpy(xsk->dk, in + p, 32); p += 32;
    (void)p;
    return true;
}

bool sapling_encode_extended_spending_key(const struct zip32_xsk *xsk,
                                           const char *hrp,
                                           char *out, size_t out_size)
{
    uint8_t raw[ZIP32_XSK_SERIALIZED_SIZE];
    xsk_serialize(xsk, raw);

    uint8_t data5[272]; /* ceil(169 * 8 / 5) = 271 */
    size_t data5_len = 0;
    if (!ConvertBits(8, 5, true, raw, ZIP32_XSK_SERIALIZED_SIZE,
                     data5, sizeof(data5), &data5_len)) {
        memory_cleanse(raw, sizeof(raw));
        return false;
    }
    memory_cleanse(raw, sizeof(raw));

    bool ok = domain_encoding_bech32_encode(out, out_size, hrp, data5, data5_len);
    memory_cleanse(data5, sizeof(data5));
    return ok;
}

bool sapling_decode_extended_spending_key(const char *str,
                                           struct zip32_xsk *xsk_out)
{
    char hrp[64];
    uint8_t data5[272];
    size_t data5_len = 0;
    if (!domain_encoding_bech32_decode(hrp, sizeof(hrp), data5, sizeof(data5), &data5_len, str))
        return false;

    /* Verify HRP starts with "secret-extended-key-" */
    if (strncmp(hrp, "secret-extended-key-", 20) != 0)
        return false;

    uint8_t raw[256];
    size_t raw_len = 0;
    if (!ConvertBits(5, 8, false, data5, data5_len, raw, sizeof(raw), &raw_len))
        return false;

    if (raw_len != ZIP32_XSK_SERIALIZED_SIZE)
        return false;

    bool ok = xsk_deserialize(raw, xsk_out);
    memory_cleanse(raw, sizeof(raw));
    return ok;
}

/* Serialize zip32_xfvk to 169 bytes:
 * depth(1) | parentFVKTag(4,LE) | childIndex(4,LE) | chaincode(32) |
 * ak(32) | nk(32) | ovk(32) | dk(32) */
static void xfvk_serialize(const struct zip32_xfvk *xfvk,
                             uint8_t out[ZIP32_XFVK_SERIALIZED_SIZE])
{
    size_t p = 0;
    out[p++] = xfvk->depth;
    out[p++] = (xfvk->parent_fvk_tag >> 0) & 0xff;
    out[p++] = (xfvk->parent_fvk_tag >> 8) & 0xff;
    out[p++] = (xfvk->parent_fvk_tag >> 16) & 0xff;
    out[p++] = (xfvk->parent_fvk_tag >> 24) & 0xff;
    out[p++] = (xfvk->child_index >> 0) & 0xff;
    out[p++] = (xfvk->child_index >> 8) & 0xff;
    out[p++] = (xfvk->child_index >> 16) & 0xff;
    out[p++] = (xfvk->child_index >> 24) & 0xff;
    memcpy(out + p, xfvk->chain_code, 32); p += 32;
    memcpy(out + p, xfvk->fvk.ak, 32); p += 32;
    memcpy(out + p, xfvk->fvk.nk, 32); p += 32;
    memcpy(out + p, xfvk->fvk.ovk, 32); p += 32;
    memcpy(out + p, xfvk->dk, 32); p += 32;
    (void)p;
}

static bool xfvk_deserialize(const uint8_t in[ZIP32_XFVK_SERIALIZED_SIZE],
                               struct zip32_xfvk *xfvk)
{
    size_t p = 0;
    xfvk->depth = in[p++];
    xfvk->parent_fvk_tag = (uint32_t)in[p] | ((uint32_t)in[p+1] << 8) |
                             ((uint32_t)in[p+2] << 16) | ((uint32_t)in[p+3] << 24);
    p += 4;
    xfvk->child_index = (uint32_t)in[p] | ((uint32_t)in[p+1] << 8) |
                          ((uint32_t)in[p+2] << 16) | ((uint32_t)in[p+3] << 24);
    p += 4;
    memcpy(xfvk->chain_code, in + p, 32); p += 32;
    memcpy(xfvk->fvk.ak, in + p, 32); p += 32;
    memcpy(xfvk->fvk.nk, in + p, 32); p += 32;
    memcpy(xfvk->fvk.ovk, in + p, 32); p += 32;
    memcpy(xfvk->dk, in + p, 32); p += 32;
    (void)p;
    return true;
}

bool sapling_encode_extended_full_viewing_key(const struct zip32_xfvk *xfvk,
                                               const char *hrp,
                                               char *out, size_t out_size)
{
    uint8_t raw[ZIP32_XFVK_SERIALIZED_SIZE];
    xfvk_serialize(xfvk, raw);

    uint8_t data5[272];
    size_t data5_len = 0;
    if (!ConvertBits(8, 5, true, raw, ZIP32_XFVK_SERIALIZED_SIZE,
                     data5, sizeof(data5), &data5_len)) {
        memory_cleanse(raw, sizeof(raw));
        return false;
    }
    memory_cleanse(raw, sizeof(raw));

    bool ok = domain_encoding_bech32_encode(out, out_size, hrp, data5, data5_len);
    memory_cleanse(data5, sizeof(data5));
    return ok;
}

bool sapling_decode_extended_full_viewing_key(const char *str,
                                               struct zip32_xfvk *xfvk_out)
{
    char hrp[64];
    uint8_t data5[272];
    size_t data5_len = 0;
    if (!domain_encoding_bech32_decode(hrp, sizeof(hrp), data5, sizeof(data5), &data5_len, str))
        return false;

    uint8_t raw[256];
    size_t raw_len = 0;
    if (!ConvertBits(5, 8, false, data5, data5_len, raw, sizeof(raw), &raw_len))
        return false;

    if (raw_len != ZIP32_XFVK_SERIALIZED_SIZE)
        return false;

    return xfvk_deserialize(raw, xfvk_out);
}
