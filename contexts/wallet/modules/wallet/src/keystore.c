/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "wallet/keystore.h"
#include "core/hash.h"
#include "support/cleanse.h"
#include <string.h>

static bool uint160_eq(const struct uint160 *a, const struct uint160 *b)
{
    return memcmp(a->data, b->data, 20) == 0;
}

static bool key_id_eq(const struct key_id *a, const struct key_id *b)
{
    return uint160_eq(&a->id, &b->id);
}

void keystore_init(struct basic_keystore *ks)
{
    zcl_mutex_init(&ks->cs);
    memset(ks->keys, 0, sizeof(ks->keys));
    memset(ks->scripts, 0, sizeof(ks->scripts));
    memset(ks->watching, 0, sizeof(ks->watching));
    ks->num_keys = 0;
    ks->num_scripts = 0;
    ks->num_watching = 0;
}

void keystore_free(struct basic_keystore *ks)
{
    memory_cleanse(ks->keys, sizeof(ks->keys));
    ks->num_keys = 0;
    ks->num_scripts = 0;
    ks->num_watching = 0;
    zcl_mutex_destroy(&ks->cs);
}

void keystore_wipe_private_keys(struct basic_keystore *ks)
{
    if (!ks) return;
    zcl_mutex_lock(&ks->cs);
    /* memory_cleanse every private-key slot then drop the count so a
     * subsequent unlock/reload repopulates from scratch. Scripts and
     * watch-only entries hold no spend secrets and are left intact. */
    memory_cleanse(ks->keys, sizeof(ks->keys));
    ks->num_keys = 0;
    zcl_mutex_unlock(&ks->cs);
}

bool keystore_add_key(struct basic_keystore *ks, const struct privkey *key)
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk))
        return false;

    struct key_id kid = pubkey_get_id(&pk);

    zcl_mutex_lock(&ks->cs);

    for (size_t i = 0; i < ks->num_keys; i++) {
        if (ks->keys[i].used && key_id_eq(&ks->keys[i].keyid, &kid)) {
            ks->keys[i].key = *key;
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }

    if (ks->num_keys >= MAX_KEYSTORE_KEYS) {
        zcl_mutex_unlock(&ks->cs);
        return false;
    }

    struct key_entry *e = &ks->keys[ks->num_keys++];
    e->keyid = kid;
    e->key = *key;
    e->used = true;

    zcl_mutex_unlock(&ks->cs);
    return true;
}

bool keystore_remove_key(struct basic_keystore *ks,
                          const struct key_id *keyid)
{
    if (!ks || !keyid) return false;
    zcl_mutex_lock(&ks->cs);
    for (size_t i = 0; i < ks->num_keys; i++) {
        if (ks->keys[i].used && key_id_eq(&ks->keys[i].keyid, keyid)) {
            memory_cleanse(&ks->keys[i].key, sizeof(ks->keys[i].key));
            ks->keys[i].used = false;
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }
    zcl_mutex_unlock(&ks->cs);
    return false;
}

bool keystore_have_key(const struct basic_keystore *ks,
                        const struct key_id *keyid)
{
    /* Hold ks->cs so the read sees a consistent entry vs add/remove writers
     * (uniform with keystore_get_key / keystore_get_pubkey). */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_keys; i++)
        if (ks->keys[i].used && key_id_eq(&ks->keys[i].keyid, keyid)) {
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_get_key(const struct basic_keystore *ks,
                       const struct key_id *keyid, struct privkey *key_out)
{
    /* Take ks->cs: keystore_remove_key cleanses ks->keys[i].key under the
     * lock and keystore_add_key publishes new entries under it. Reading
     * lock-free races those writers and can copy out a half-written or
     * memory_cleanse()'d (zeroed) private key. const-cast to lock is the
     * established reader pattern in this codebase (e.g. wallet.c:629). */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_keys; i++) {
        if (ks->keys[i].used && key_id_eq(&ks->keys[i].keyid, keyid)) {
            *key_out = ks->keys[i].key;
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_get_pubkey(const struct basic_keystore *ks,
                          const struct key_id *keyid, struct pubkey *pk_out)
{
    /* Same race as keystore_get_key: ks->keys[i].key is read (to derive the
     * pubkey) while writers mutate/cleanse entries under ks->cs. Lock the whole
     * read and unlock on every exit; const-cast follows the reader pattern. */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_keys; i++) {
        if (ks->keys[i].used && key_id_eq(&ks->keys[i].keyid, keyid)) {
            bool ok = privkey_get_pubkey(&ks->keys[i].key, pk_out);
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return ok;
        }
    }

    for (size_t i = 0; i < ks->num_watching; i++) {
        if (ks->watching[i].used && key_id_eq(&ks->watching[i].keyid, keyid)) {
            *pk_out = ks->watching[i].key;
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_add_cscript(struct basic_keystore *ks,
                            const struct script *redeem_script)
{
    struct uint160 id;
    hash160(redeem_script->data, redeem_script->size, id.data);

    zcl_mutex_lock(&ks->cs);

    for (size_t i = 0; i < ks->num_scripts; i++) {
        if (ks->scripts[i].used && uint160_eq(&ks->scripts[i].script_id, &id)) {
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }

    if (ks->num_scripts >= MAX_KEYSTORE_SCRIPTS) {
        zcl_mutex_unlock(&ks->cs);
        return false;
    }

    struct script_entry *e = &ks->scripts[ks->num_scripts++];
    e->script_id = id;
    e->redeem_script = *redeem_script;
    e->used = true;

    zcl_mutex_unlock(&ks->cs);
    return true;
}

bool keystore_have_cscript(const struct basic_keystore *ks,
                             const struct uint160 *script_id)
{
    /* Lock the read: keystore_add_cscript publishes scripts[] entries (and bumps
     * num_scripts) under ks->cs; a lock-free scan can observe a half-published
     * entry or a stale count. const-cast to lock follows the reader pattern
     * (keystore_get_key). */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_scripts; i++)
        if (ks->scripts[i].used && uint160_eq(&ks->scripts[i].script_id, script_id)) {
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_get_cscript(const struct basic_keystore *ks,
                            const struct uint160 *script_id,
                            struct script *script_out)
{
    /* Lock the read+copy: a lock-free copy of redeem_script can tear against
     * keystore_add_cscript's publish under ks->cs. */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_scripts; i++) {
        if (ks->scripts[i].used && uint160_eq(&ks->scripts[i].script_id, script_id)) {
            *script_out = ks->scripts[i].redeem_script;
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_add_watch_only(struct basic_keystore *ks,
                               const struct pubkey *pk)
{
    struct key_id kid = pubkey_get_id(pk);

    zcl_mutex_lock(&ks->cs);

    for (size_t i = 0; i < ks->num_watching; i++) {
        if (ks->watching[i].used && key_id_eq(&ks->watching[i].keyid, &kid)) {
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }

    if (ks->num_watching >= MAX_KEYSTORE_WATCHING) {
        zcl_mutex_unlock(&ks->cs);
        return false;
    }

    struct watching_entry *e = &ks->watching[ks->num_watching++];
    e->keyid = kid;
    e->key = *pk;
    e->used = true;

    zcl_mutex_unlock(&ks->cs);
    return true;
}

bool keystore_add_watch_only_id(struct basic_keystore *ks,
                                  const struct key_id *keyid)
{
    zcl_mutex_lock(&ks->cs);

    for (size_t i = 0; i < ks->num_watching; i++) {
        if (ks->watching[i].used && key_id_eq(&ks->watching[i].keyid, keyid)) {
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }

    if (ks->num_watching >= MAX_KEYSTORE_WATCHING) {
        zcl_mutex_unlock(&ks->cs);
        return false;
    }

    struct watching_entry *e = &ks->watching[ks->num_watching++];
    e->keyid = *keyid;
    memset(&e->key, 0, sizeof(e->key));
    e->used = true;

    zcl_mutex_unlock(&ks->cs);
    return true;
}

bool keystore_have_watch_only(const struct basic_keystore *ks,
                                const struct key_id *keyid)
{
    /* Lock the read: keystore_add_watch_only[_id] publish watching[] entries
     * under ks->cs; a lock-free scan can observe a half-published entry. */
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = 0; i < ks->num_watching; i++)
        if (ks->watching[i].used && key_id_eq(&ks->watching[i].keyid, keyid)) {
            zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
            return true;
        }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return false;
}

bool keystore_remove_watch_only(struct basic_keystore *ks,
                                  const struct key_id *keyid)
{
    zcl_mutex_lock(&ks->cs);
    for (size_t i = 0; i < ks->num_watching; i++) {
        if (ks->watching[i].used && key_id_eq(&ks->watching[i].keyid, keyid)) {
            ks->watching[i].used = false;
            zcl_mutex_unlock(&ks->cs);
            return true;
        }
    }
    zcl_mutex_unlock(&ks->cs);
    return false;
}
