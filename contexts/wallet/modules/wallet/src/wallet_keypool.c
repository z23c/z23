/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: restore and consume durable transparent wallet keypool entries. */

#include "wallet_internal.h"
#include "script/standard.h"
#include <stdint.h>
#include <string.h>

bool wallet_key_pool_restore(struct wallet *w, const struct key_id *keyid,
                             int64_t generation)
{
    if (!w || !keyid || generation < 0 || generation == INT64_MAX)
        return false; /* raw-return-ok:invalid durable row refused */
    zcl_mutex_lock(&w->cs);
    if (!keystore_have_key(&w->keystore, keyid) ||
        w->key_pool_size >= MAX_KEY_POOL) {
        zcl_mutex_unlock(&w->cs);
        return false; /* raw-return-ok:receipt does not name an owned key */
    }
    for (size_t i = 0; i < w->key_pool_size; i++) {
        if (memcmp(w->key_pool[i].keyid.id.data, keyid->id.data,
                   sizeof(keyid->id.data)) == 0 ||
            w->key_pool[i].generation == generation) {
            zcl_mutex_unlock(&w->cs);
            return false; /* raw-return-ok:duplicate durable membership */
        }
    }
    struct wallet_key_pool_entry *entry = &w->key_pool[w->key_pool_size++];
    entry->keyid = *keyid;
    entry->generation = generation;
    entry->persisted = true;
    if (w->next_key_pool_index <= generation)
        w->next_key_pool_index = generation + 1;
    zcl_mutex_unlock(&w->cs);
    return true;
}

void wallet_key_pool_consume_transaction_outputs_locked(
    struct wallet *w, const struct transaction *tx)
{
    /* A crash-recovered prepared transaction may name a change key which was
     * still unused at the crash. Consume it before the pre-relay flush. */
    for (size_t oi = 0; oi < tx->num_vout; oi++) {
        struct tx_destination dest;
        if (!script_extract_destination(&tx->vout[oi].script_pub_key, &dest) ||
            dest.type != DEST_KEY_ID)
            continue;
        for (size_t pi = 0; pi < w->key_pool_size; pi++) {
            if (memcmp(w->key_pool[pi].keyid.id.data, dest.id.key.id.data,
                       sizeof(dest.id.key.id.data)) != 0)
                continue;
            if (pi + 1 < w->key_pool_size)
                w->key_pool[pi] = w->key_pool[w->key_pool_size - 1];
            memset(&w->key_pool[w->key_pool_size - 1], 0,
                   sizeof(w->key_pool[w->key_pool_size - 1]));
            w->key_pool_size--;
            break;
        }
    }
}
