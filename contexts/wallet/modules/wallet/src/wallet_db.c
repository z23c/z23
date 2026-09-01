/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "wallet/wallet_db.h"
#include "core/serialize.h"
#include "support/cleanse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Key prefixes for wallet DB entries */
#define PREFIX_KEY    "key"
#define PREFIX_TX     "tx"
#define PREFIX_BEST   "bestblock"
#define PREFIX_SCANH  "scanheight"
#define PREFIX_ZSEED  "zseed"
#define PREFIX_ZKEY   "zkey"
#define PREFIX_CSCRIPT "cscript"

bool wallet_db_open(struct wallet_db *wdb, const char *path)
{
    memset(wdb, 0, sizeof(*wdb));
    if (!db_wrapper_open(&wdb->db, path, 4 << 20, false, false))
        return false;
    wdb->open = true;
    return true;
}

void wallet_db_close(struct wallet_db *wdb)
{
    if (wdb->open) {
        db_wrapper_close(&wdb->db);
        wdb->open = false;
    }
}

bool wallet_db_read_keys(struct wallet_db *wdb, struct wallet *w)
{
    if (!wdb->open) return false;

    struct db_iterator it;
    db_iter_init(&it, &wdb->db);
    db_iter_seek(&it, PREFIX_KEY, 3);

    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 3 || memcmp(k, PREFIX_KEY, 3) != 0)
            break;

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (vlen < 35) { /* 1 + 1 + 33 minimum */
            db_iter_next(&it);
            continue;
        }

        const unsigned char *vp = (const unsigned char *)v;
        bool compressed = vp[0] != 0;
        unsigned int pk_size = vp[1];
        if (pk_size > PUBLIC_KEY_SIZE || vlen < 2 + pk_size + 32) {
            db_iter_next(&it);
            continue;
        }

        struct pubkey pk;
        pubkey_set(&pk, vp + 2, pk_size);

        struct privkey key;
        privkey_init(&key);
        memcpy(key.vch, vp + 2 + pk_size, 32);
        key.fValid = true;
        key.fCompressed = compressed;

        keystore_add_key(&w->keystore, &key);
        memory_cleanse(key.vch, 32);

        db_iter_next(&it);
    }

    db_iter_free(&it);
    return true;
}

bool wallet_db_read_txs(struct wallet_db *wdb, struct wallet *w)
{
    if (!wdb->open) return false;

    struct db_iterator it;
    db_iter_init(&it, &wdb->db);
    db_iter_seek(&it, PREFIX_TX, 2);

    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 2 || memcmp(k, PREFIX_TX, 2) != 0)
            break;

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (vlen < 45) { /* minimum: 32+8+1+4 */
            db_iter_next(&it);
            continue;
        }

        struct byte_stream s;
        stream_init_from_data(&s, (const unsigned char *)v, vlen);

        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        stream_read_bytes(&s, wtx.hash_block.data, 32);
        stream_read_i64_le(&s, &wtx.time_received);
        unsigned char fm;
        stream_read_bytes(&s, &fm, 1);
        wtx.from_me = fm != 0;
        uint32_t conf;
        stream_read_u32_le(&s, &conf);
        wtx.confirms = (int)conf;

        transaction_init(&wtx.tx);
        if (transaction_deserialize(&wtx.tx, &s)) {
            wtx.used = true;
            wallet_add_to_wallet(w, &wtx);
            /* wallet_add_to_wallet deep-copies the tx; free this orphaned load
             * copy (same leak as the SQLite loader). Failed deserialize already
             * frees internally. */
            transaction_free(&wtx.tx);
        }

        stream_free(&s);
        db_iter_next(&it);
    }

    db_iter_free(&it);
    return true;
}

bool wallet_db_read_scan_height(struct wallet_db *wdb, int *height)
{
    if (!wdb->open) return false;
    char *val = NULL;
    size_t vlen = 0;
    if (!db_read(&wdb->db, PREFIX_SCANH, 10, &val, &vlen))
        return false;
    if (vlen != 4) {
        free(val);
        return false;
    }
    int32_t h;
    memcpy(&h, val, 4);
    *height = h;
    free(val);
    return true;
}

bool wallet_db_read_sapling_seed(struct wallet_db *wdb, uint8_t seed[32])
{
    if (!wdb->open) return false;
    char *val = NULL;
    size_t vlen = 0;
    if (!db_read(&wdb->db, PREFIX_ZSEED, 5, &val, &vlen))
        return false;
    if (vlen != 32) {
        free(val);
        return false;
    }
    memcpy(seed, val, 32);
    free(val);
    return true;
}

bool wallet_db_read_sapling_keys(struct wallet_db *wdb, struct wallet *w)
{
    if (!wdb->open) return false;

    /* Read seed first */
    uint8_t seed[32];
    if (wallet_db_read_sapling_seed(wdb, seed)) {
        sapling_keystore_set_seed(&w->sapling_keys, seed);
        memory_cleanse(seed, 32);
    }

    struct db_iterator it;
    db_iter_init(&it, &wdb->db);
    db_iter_seek(&it, PREFIX_ZKEY, 4);

    size_t expected_vlen = sizeof(struct zip32_xsk) + 11 + 32 + 32;

    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 4 || memcmp(k, PREFIX_ZKEY, 4) != 0)
            break;

        uint32_t child_index = 0;
        if (klen >= 8)
            memcpy(&child_index, k + 4, 4);

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (vlen < expected_vlen) {
            db_iter_next(&it);
            continue;
        }

        const unsigned char *vp = (const unsigned char *)v;
        struct sapling_keystore *sks = &w->sapling_keys;

        if (sks->num_keys < MAX_SAPLING_KEYS) {
            struct sapling_key_entry *entry = &sks->keys[sks->num_keys];
            size_t off = 0;
            memcpy(&entry->xsk, vp + off, sizeof(struct zip32_xsk));
            off += sizeof(struct zip32_xsk);
            memcpy(entry->diversifier, vp + off, 11);
            off += 11;
            memcpy(entry->pk_d, vp + off, 32);
            off += 32;
            memcpy(entry->ivk, vp + off, 32);

            zip32_xsk_to_xfvk(&entry->xfvk, &entry->xsk);
            entry->child_index = child_index;
            entry->used = true;
            sks->num_keys++;

            if (child_index >= sks->next_child_index)
                sks->next_child_index = child_index + 1;
        }

        db_iter_next(&it);
    }

    db_iter_free(&it);
    return true;
}

bool wallet_db_read_scripts(struct wallet_db *wdb, struct wallet *w)
{
    if (!wdb->open) return false;

    struct db_iterator it;
    db_iter_init(&it, &wdb->db);
    db_iter_seek(&it, PREFIX_CSCRIPT, 7);

    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 7 || memcmp(k, PREFIX_CSCRIPT, 7) != 0)
            break;

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (vlen == 0 || vlen > MAX_SCRIPT_SIZE) {
            db_iter_next(&it);
            continue;
        }

        struct script s;
        script_init(&s);
        memcpy(s.data, v, vlen);
        s.size = vlen;
        keystore_add_cscript(&w->keystore, &s);

        db_iter_next(&it);
    }

    db_iter_free(&it);
    return true;
}

