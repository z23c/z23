/* Copyright (c) 2014-2016 The Bitcoin Core developers
 * Copyright (c) 2016-2018 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "keys/key_io.h"
#include "support/cleanse.h"
#include <string.h>

bool encode_destination(const struct tx_destination *dest,
                        const unsigned char *pubkey_prefix, size_t pfx_len,
                        const unsigned char *script_prefix, size_t spfx_len,
                        char *out, size_t outsize)
{
    unsigned char data[64];
    size_t data_len = 0;

    if (dest->type == DEST_KEY_ID) {
        memcpy(data, pubkey_prefix, pfx_len);
        memcpy(data + pfx_len, dest->id.key.id.data, 20);
        data_len = pfx_len + 20;
    } else if (dest->type == DEST_SCRIPT_ID) {
        memcpy(data, script_prefix, spfx_len);
        memcpy(data + spfx_len, dest->id.script.hash.data, 20);
        data_len = spfx_len + 20;
    } else {
        return false;
    }

    size_t out_len;
    return domain_encoding_base58check_encode(data, data_len, out, outsize, &out_len);
}

bool decode_destination(const char *str,
                        const unsigned char *pubkey_prefix, size_t pfx_len,
                        const unsigned char *script_prefix, size_t spfx_len,
                        struct tx_destination *dest)
{
    unsigned char data[64];
    size_t data_len;

    if (!domain_encoding_base58check_decode(str, data, sizeof(data), &data_len))
        return false;

    if (data_len == 20 + pfx_len &&
        memcmp(data, pubkey_prefix, pfx_len) == 0) {
        dest->type = DEST_KEY_ID;
        memcpy(dest->id.key.id.data, data + pfx_len, 20);
        return true;
    }

    if (data_len == 20 + spfx_len &&
        memcmp(data, script_prefix, spfx_len) == 0) {
        dest->type = DEST_SCRIPT_ID;
        memcpy(dest->id.script.hash.data, data + spfx_len, 20);
        return true;
    }

    dest->type = DEST_NONE;
    return false;
}

bool encode_secret(const struct privkey *key,
                   const unsigned char *prefix, size_t pfx_len,
                   char *out, size_t outsize)
{
    unsigned char data[64];
    memcpy(data, prefix, pfx_len);
    memcpy(data + pfx_len, key->vch, 32);
    size_t len = pfx_len + 32;
    if (key->fCompressed) {
        data[len] = 1;
        len++;
    }
    size_t out_len;
    bool ok = domain_encoding_base58check_encode(data, len, out, outsize, &out_len);
    memory_cleanse(data, sizeof(data));
    return ok;
}

bool decode_secret(const char *str,
                   const unsigned char *prefix, size_t pfx_len,
                   struct privkey *key)
{
    unsigned char data[64];
    size_t data_len;

    if (!domain_encoding_base58check_decode(str, data, sizeof(data), &data_len)) {
        memory_cleanse(data, sizeof(data));
        return false;
    }

    if (data_len < pfx_len + 32 ||
        memcmp(data, prefix, pfx_len) != 0) {
        memory_cleanse(data, sizeof(data));
        return false;
    }

    bool compressed = (data_len == pfx_len + 33 &&
                       data[pfx_len + 32] == 1);

    privkey_init(key);
    memcpy(key->vch, data + pfx_len, 32);
    key->fCompressed = compressed;
    /* Range-validate the externally-sourced scalar at the boundary: a
     * WIF whose payload is 0 or >= the secp256k1 group order is not a
     * usable secret key, and letting it through with fValid=true used
     * to carry it all the way to an assert() in privkey_get_pubkey. */
    key->fValid = privkey_range_check(key);
    if (!key->fValid)
        memory_cleanse(key->vch, sizeof(key->vch));

    memory_cleanse(data, sizeof(data));
    return privkey_is_valid(key);
}
