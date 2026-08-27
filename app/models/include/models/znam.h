/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_ZNAM_H
#define ZCL_DB_MODEL_ZNAM_H

#include "models/database.h"
#include "models/activerecord.h"
#include "znam/znam.h"
#include <stdbool.h>

/* ActiveRecord models for the ZCL Names (ZNAM) registry.
 *
 * Three tables, three record types:
 *   znam_names         → struct znam_entry
 *   znam_text_records  → struct znam_text_record
 *   znam_addr_records  → struct znam_addr_record
 *
 * The validators enforce the format constraints from the on-chain
 * ZNAM protocol (lokad ID "ZNAM"). Names that fail validation should
 * never have been accepted from OP_RETURN parsing in the first place;
 * the validator here is the last line of defense against corrupted
 * blocks reaching at-rest storage. */

struct znam_entry {
    char name[ZNAM_NAME_MAX + 1];
    char owner_address[64];
    uint8_t target_type;
    char target_value[ZNAM_VALUE_MAX + 1];
    uint8_t reg_txid[32];
    int32_t reg_height;
    uint8_t last_update_txid[32];
    /* Overlay bookkeeping (path A / node.db only): registration term
     * granted at REGISTER (reg_height + ZNAM_REGISTRATION_TERM_BLOCKS) and
     * extended by each RENEW. 0 for rows created before the expiry column
     * existed. Not enforced by resolution today — see znam.h. */
    int32_t expiry_height;
};

/* Text record (ENS TextResolver equivalent) */
struct znam_text_record {
    char name[ZNAM_NAME_MAX + 1];
    char key[ZNAM_TEXT_KEY_MAX + 1];
    char value[ZNAM_TEXT_VAL_MAX + 1];
};

/* Additional address record (ENS AddrResolver equivalent) */
struct znam_addr_record {
    char name[ZNAM_NAME_MAX + 1];
    uint8_t coin_type;    /* ZNAM_TYPE_BTC, etc. */
    char address[ZNAM_VALUE_MAX + 1];
};

struct ar_callbacks *db_znam_entry_callbacks(void);
struct ar_callbacks *db_znam_text_callbacks(void);
struct ar_callbacks *db_znam_addr_callbacks(void);

bool db_znam_entry_validate(const struct znam_entry *entry,
                            struct ar_errors *errors);
bool db_znam_text_validate(const struct znam_text_record *rec,
                           struct ar_errors *errors);
bool db_znam_addr_validate(const struct znam_addr_record *rec,
                           struct ar_errors *errors);

bool db_znam_save(struct node_db *ndb, const struct znam_entry *entry);
bool db_znam_find(struct node_db *ndb, const char *name,
                  struct znam_entry *out);
/* Property-catalog reads keyed by the registration transaction, which is
 * ZNAM's immutable metaverse root.  -1 is a query/integrity error, 0 is a
 * determined miss, 1 is found. */
int db_znam_find_by_reg_txid(struct node_db *ndb, const uint8_t reg_txid[32],
                            struct znam_entry *out);
/* Exact table cardinality.  False is a read failure, distinct from an empty
 * registry. */
bool db_znam_count(struct node_db *ndb, size_t *count_out);
int db_znam_list(struct node_db *ndb, struct znam_entry *out, size_t max);
int db_znam_list_by_owner(struct node_db *ndb, const char *owner,
                          struct znam_entry *out, size_t max);

/* Wallet-wide sweep: every name owned by ANY address this wallet holds,
 * with its registration and expiry heights, ordered by owner then name.
 * "Any address this wallet holds" is wallet_keys (Base58Check-encoded as
 * this chain's P2PKH addresses) plus wallet_watch_only's stored address
 * text — de-duplicated, so a name is never listed twice.
 *
 * Returns the number of entries written (never negative). A wallet that
 * owns no names returns 0 with `out` untouched: owning nothing is an
 * answer, not an error. Bounded by `max`. */
int db_znam_list_wallet_owned(struct node_db *ndb, struct znam_entry *out,
                              size_t max);

/* How many distinct transparent addresses db_znam_list_wallet_owned folds
 * over. 0 for a wallet with no keys — which is why its sweep is empty. */
int db_znam_wallet_address_count(struct node_db *ndb);

/* Text records */
bool db_znam_text_save(struct node_db *ndb, const char *name,
                       const char *key, const char *value);
bool db_znam_text_get(struct node_db *ndb, const char *name,
                      const char *key, char *value_out, size_t max);
int db_znam_text_list(struct node_db *ndb, const char *name,
                      struct znam_text_record *out, size_t max);
/* Uncapped total for one name's text records — the number db_znam_text_list
 * would fold over with no window. -1 only when the store is unreadable. */
int db_znam_text_count(struct node_db *ndb, const char *name);

/* Multi-coin address records */
bool db_znam_addr_save(struct node_db *ndb, const char *name,
                       uint8_t coin_type, const char *address);
bool db_znam_addr_get(struct node_db *ndb, const char *name,
                      uint8_t coin_type, char *addr_out, size_t max);
int db_znam_addr_list(struct node_db *ndb, const char *name,
                      struct znam_addr_record *out, size_t max);
/* Uncapped total for one name's address records. -1 on an unreadable
 * store, mirroring the text count. */
int db_znam_addr_count(struct node_db *ndb, const char *name);

#endif
