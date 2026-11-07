/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_WALLET_KEY_H
#define ZCL_DB_MODEL_WALLET_KEY_H

#include "models/database.h"
#include "models/activerecord.h"
#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>

struct pubkey;
struct privkey;

struct db_wallet_key {
    uint8_t pubkey_hash[20];
    uint8_t pubkey[33];
    size_t pubkey_len;
    uint8_t privkey[32];
    bool compressed;
    int64_t created_at;
};

/* Callbacks and validation */
struct ar_callbacks *db_wallet_key_callbacks(void);
struct ar_callbacks *db_sapling_key_callbacks(void);
struct ar_callbacks *db_wallet_script_callbacks(void);
bool db_wallet_key_validate(const struct db_wallet_key *k,
                            struct ar_errors *errors);

/* NOTE: no db_wallet_key_save — the wallet_keys secret column has a
 * single writer, the encryption-aware wallet_sqlite layer
 * (contexts/wallet/modules/wallet/src/wallet_sqlite.c). This model is the read/destroy side
 * for diagnostics and the vault. */

bool db_wallet_key_find(struct node_db *ndb, const uint8_t pubkey_hash[20],
                        struct db_wallet_key *out);
bool db_wallet_key_delete(struct node_db *ndb, const uint8_t pubkey_hash[20]);
bool db_wallet_key_exists(struct node_db *ndb, const uint8_t pubkey_hash[20]);
int db_wallet_key_count(struct node_db *ndb);

/* Copy the first wallet key's 20-byte pubkey_hash into out (LIMIT 1, the
 * same arbitrary "any key" the API wallet panel encodes as the display
 * address). Returns false when the db is closed, no key exists, or the
 * stored hash is not exactly 20 bytes; out is left untouched on false. */
bool db_wallet_key_first_pubkey_hash(struct node_db *ndb, uint8_t out[20]);

/* Load all wallet keys into a callback. Returns count loaded. */
typedef void (*wallet_key_cb)(const struct db_wallet_key *key, void *ctx);
int db_wallet_key_each(struct node_db *ndb, wallet_key_cb cb, void *ctx);

/* Sapling keys */
struct db_sapling_key {
    uint8_t ivk[32];
    uint8_t xsk[169];
    uint8_t xfvk[169];
    uint8_t diversifier[11];
    uint8_t pk_d[32];
    uint32_t child_index;
    char address[128];
};

bool db_sapling_key_validate(const struct db_sapling_key *k,
                              struct ar_errors *errors);
/* NOTE: no db_sapling_key_save — single writer is wallet_sqlite. */
bool db_sapling_key_find_by_ivk(struct node_db *ndb, const uint8_t ivk[32],
                                struct db_sapling_key *out);
int db_sapling_key_count(struct node_db *ndb);

/* Blocks kept below a wallet's birthday tip. */
#define WALLET_BIRTHDAY_MARGIN 100

/* Wallet birthday: the scan floor plus WALLET_BIRTHDAY_MARGIN, and the
 * hash of the block at that floor (the
 * floor block). Every block up to the floor existed when the wallet was made,
 * so none can pay it; the first scan starts at the floor once the active
 * chain reaches it, and only while the active chain holds that exact block
 * (which proves every block below it is unchanged). The birthday need not be
 * on the active chain: the floor block is what is checked. Absent for wallets
 * created before birthdays, for restored wallets and for a create that knows
 * no block at least the margin below any height it proves; those scan from
 * the beginning (a chain above 1000 blocks defers the first boot catch-up,
 * so a restored wallet records a pending retry that only a rescan over the
 * whole range clears). Written once, with the wallet. */
bool db_wallet_birthday_get(struct node_db *ndb, int64_t *height,
                            uint8_t floor_hash[32]);
bool db_wallet_birthday_set(struct node_db *ndb, int64_t height,
                            const uint8_t floor_hash[32]);
/* Refuses when any birthday tuple key exists or cannot be read. */
bool db_wallet_birthday_set_if_absent(struct node_db *ndb, int64_t height,
                                      const uint8_t floor_hash[32]);

enum wallet_birthday_proof_status { WALLET_BIRTHDAY_PROOF_FOUND, WALLET_BIRTHDAY_PROOF_ABSENT,
    WALLET_BIRTHDAY_PROOF_MALFORMED, WALLET_BIRTHDAY_PROOF_ERROR };
bool db_wallet_birthday_set_created(struct node_db *ndb, int64_t height,
                                    const uint8_t hash[32], const uint8_t identity[32]);
enum wallet_birthday_proof_status db_wallet_birthday_proof_get(struct node_db *ndb,
    int64_t *height, uint8_t hash[32], uint8_t identity[32]);

struct wallet_create_pending { uint8_t nonce[32], identity[32], floor_hash[32]; int floor; bool committed; };
bool db_wallet_create_pending_insert(struct node_db *ndb, const struct wallet_create_pending *pending);
enum wallet_birthday_proof_status db_wallet_create_pending_get(struct node_db *ndb, struct wallet_create_pending *out);
bool db_wallet_create_pending_commit(struct node_db *ndb, const struct wallet_create_pending *pending);
bool db_wallet_create_pending_cancel(struct node_db *ndb, const struct wallet_create_pending *pending);

/* Wallet seed (singleton). NOTE: no db_wallet_seed_save — single writer
 * is wallet_sqlite (wallet_sqlite_write_sapling_seed). */
bool db_wallet_seed_load(struct node_db *ndb, uint8_t seed[32],
                         uint32_t *next_child);

/* Redeem scripts */
struct db_wallet_script {
    uint8_t script_hash[20];
    uint8_t *redeem_script;
    size_t script_len;
};

bool db_wallet_script_validate(const struct db_wallet_script *s,
                               struct ar_errors *errors);
bool db_wallet_script_save(struct node_db *ndb, const struct db_wallet_script *s);
bool db_wallet_script_find(struct node_db *ndb, const uint8_t script_hash[20],
                           struct db_wallet_script *out);

/* ── Relationships ─────────────────────────────────────────────── */

/* WalletKey has_many :wallet_utxos */
struct db_wallet_utxo;
int db_wallet_key_utxos(struct node_db *ndb, const uint8_t pubkey_hash[20],
                        struct db_wallet_utxo *out, size_t max);

/* SaplingKey has_many :sapling_notes */
struct db_sapling_note;
int db_sapling_key_notes(struct node_db *ndb, const uint8_t ivk[32],
                         struct db_sapling_note *out, size_t max);

#endif
