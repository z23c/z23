/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_WALLET_KEYSTORE_H
#define ZCL_WALLET_KEYSTORE_H

#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stddef.h>

#define MAX_KEYSTORE_KEYS 4096
#define MAX_KEYSTORE_SCRIPTS 4096
#define MAX_KEYSTORE_WATCHING 4096

struct key_entry {
    struct key_id keyid;
    struct privkey key;
    bool used;
};

struct script_entry {
    struct uint160 script_id;
    struct script redeem_script;
    bool used;
};

struct watching_entry {
    struct key_id keyid;
    struct pubkey key;
    bool used;
};

struct basic_keystore {
    zcl_mutex_t cs;

    struct key_entry keys[MAX_KEYSTORE_KEYS];
    size_t num_keys;

    struct script_entry scripts[MAX_KEYSTORE_SCRIPTS];
    size_t num_scripts;

    struct watching_entry watching[MAX_KEYSTORE_WATCHING];
    size_t num_watching;
};

/* Zero all entry arrays/counts and initialise ks->cs. Call once before
 * any other keystore op. ks must be non-NULL (not checked). */
void keystore_init(struct basic_keystore *ks);
/* Wipe key material (memory_cleanse over the key array), zero the counts,
 * and destroy ks->cs. Does not free ks itself. ks must be non-NULL
 * (not checked). */
void keystore_free(struct basic_keystore *ks);

/* Derive the key_id from key's pubkey and store the private key under it.
 * If an entry with that key_id already exists its private key is
 * overwritten. Returns true on insert or overwrite; false if the pubkey
 * cannot be derived from key, or the array is full (MAX_KEYSTORE_KEYS).
 * Takes ks->cs. */
bool keystore_add_key(struct basic_keystore *ks, const struct privkey *key);
/* Remove a key by its key_id. Returns true if a matching entry was
 * found and marked unused, false otherwise. Used by controller
 * rollback when persistence fails after keystore mutation. */
bool keystore_remove_key(struct basic_keystore *ks,
                          const struct key_id *keyid);
/* memory_cleanse every resident private key and reset the count to zero,
 * keeping ks initialised (mutex intact). Used by the wallet lock surface
 * (wallet_lock_lock) to make decrypted spend keys non-resident without
 * tearing down the keystore. ks may be NULL (no-op). Takes ks->cs. */
void keystore_wipe_private_keys(struct basic_keystore *ks);
/* Return true if a live private-key entry matches keyid. Read-only,
 * does NOT take ks->cs. */
bool keystore_have_key(const struct basic_keystore *ks,
                        const struct key_id *keyid);
/* Copy the private key matching keyid into *key_out. Returns true and
 * fills key_out on a hit; returns false and leaves key_out untouched on
 * a miss. Read-only, does NOT take ks->cs. */
bool keystore_get_key(const struct basic_keystore *ks,
                       const struct key_id *keyid, struct privkey *key_out);
/* Resolve keyid to a pubkey: derives it from the stored private key if
 * present, else returns a stored watch-only pubkey. Returns true and
 * fills pk_out on a hit; false (pk_out untouched) on a miss or if pubkey
 * derivation fails. Read-only, does NOT take ks->cs. */
bool keystore_get_pubkey(const struct basic_keystore *ks,
                          const struct key_id *keyid, struct pubkey *pk_out);

/* Store a redeem script keyed by its hash160. If that script hash is
 * already present it is a no-op. Returns true on insert or duplicate;
 * false if the array is full (MAX_KEYSTORE_SCRIPTS). Takes ks->cs. */
bool keystore_add_cscript(struct basic_keystore *ks,
                            const struct script *redeem_script);
/* Return true if a live script entry matches script_id. Read-only,
 * does NOT take ks->cs. */
bool keystore_have_cscript(const struct basic_keystore *ks,
                             const struct uint160 *script_id);
/* Copy the redeem script matching script_id into *script_out. Returns
 * true and fills script_out on a hit; false (script_out untouched) on a
 * miss. Read-only, does NOT take ks->cs. */
bool keystore_get_cscript(const struct basic_keystore *ks,
                            const struct uint160 *script_id,
                            struct script *script_out);

/* Add a watch-only entry keyed by pk's key_id, storing the full pubkey.
 * If that key_id is already watched it is a no-op. Returns true on insert
 * or duplicate; false if the array is full (MAX_KEYSTORE_WATCHING).
 * Takes ks->cs. */
bool keystore_add_watch_only(struct basic_keystore *ks,
                               const struct pubkey *pk);
/* Add a watch-only entry by key_id only, with a zeroed pubkey (use when
 * the pubkey is unknown). If that key_id is already watched it is a
 * no-op. Returns true on insert or duplicate; false if the array is full
 * (MAX_KEYSTORE_WATCHING). Takes ks->cs. */
bool keystore_add_watch_only_id(struct basic_keystore *ks,
                                  const struct key_id *keyid);
/* Return true if a live watch-only entry matches keyid. Read-only,
 * does NOT take ks->cs. */
bool keystore_have_watch_only(const struct basic_keystore *ks,
                                const struct key_id *keyid);
/* Mark the watch-only entry matching keyid unused. Returns true if a
 * match was found and cleared, false otherwise. Takes ks->cs. */
bool keystore_remove_watch_only(struct basic_keystore *ks,
                                  const struct key_id *keyid);

#endif
