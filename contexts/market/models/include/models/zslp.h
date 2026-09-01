/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZSLP token model — tracks SLP tokens and transfers in SQLite. */

#ifndef ZCL_DB_MODEL_ZSLP_H
#define ZCL_DB_MODEL_ZSLP_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    ZSLP_TOKEN_KEY_MAX = 64,
    /* On-chain SLP tickers are unbounded; the longest real ZClassic ticker is
     * 32 bytes. 32 lets the indexer store every on-chain token (the create
     * RPC keeps its own stricter 10-char cap on user input). */
    ZSLP_TICKER_MAX = 32,
    ZSLP_NAME_MAX = 64,
    ZSLP_DOC_URL_MAX = 256,
    ZSLP_ADDRESS_MAX = 128,
    ZSLP_ADDR_HASH_HEX_MAX = 40
};

struct db_zslp_balance {
    char token_id[ZSLP_TOKEN_KEY_MAX + 1];
    char address[ZSLP_ADDRESS_MAX + 1];
    int64_t balance;
};

struct db_zslp_token_info {
    char token_id[ZSLP_TOKEN_KEY_MAX + 1];
    char ticker[ZSLP_TICKER_MAX + 1];
    char name[ZSLP_NAME_MAX + 1];
    int decimals;
    int genesis_height;
    int64_t total_minted;
};

struct db_zslp_transfer_info {
    char txid[65];
    char token_id[ZSLP_TOKEN_KEY_MAX + 1];
    int block_height;
    int tx_type;
    int64_t amount;
    int vout;
    char to_addr_hex[ZSLP_ADDR_HASH_HEX_MAX + 1];
};

/* Lifecycle callbacks */
struct ar_callbacks *db_zslp_token_callbacks(void);
struct ar_callbacks *db_zslp_transfer_callbacks(void);
struct ar_callbacks *db_zslp_balance_callbacks(void);

bool db_zslp_balance_validate(const struct db_zslp_balance *b,
                              struct ar_errors *errors);
bool db_zslp_balance_save(struct node_db *ndb, const struct db_zslp_balance *b);
bool db_zslp_balance_find(struct node_db *ndb, const char *token_id,
                          const char *address, struct db_zslp_balance *out);
bool db_zslp_balance_credit(struct node_db *ndb, const char *token_id,
                            const char *address, int64_t amount);
bool db_zslp_token_validate_key(const char *token_key,
                                struct ar_errors *errors);
bool db_zslp_token_save_key(struct node_db *ndb, const char *token_key,
                            const char *ticker, const char *name,
                            int decimals, const char *document_url,
                            int genesis_height, int64_t initial_quantity);
bool db_zslp_token_find(struct node_db *ndb, const char *token_key,
                        struct db_zslp_token_info *out);
int db_zslp_token_list(struct node_db *ndb,
                       struct db_zslp_token_info *out, size_t max_out);

/* Chain-derived asset-definition reads.  Unlike the generic token helpers
 * above, these exclude application-local alphanumeric token keys and expose
 * only real 32-byte/64-hex GENESIS transaction ids.  lookup returns 1 when
 * found, 0 when absent, and -1 on a database/read error so a read-only
 * projection never reports an I/O failure as an empty asset catalog. */
int db_zslp_asset_lookup(struct node_db *ndb, const uint8_t token_id[32],
                         struct db_zslp_token_info *out);
bool db_zslp_asset_count(struct node_db *ndb, size_t *out);
int db_zslp_asset_list(struct node_db *ndb,
                       struct db_zslp_token_info *out, size_t max_out);
int db_zslp_transfer_list_by_token(struct node_db *ndb, const char *token_key,
                                   struct db_zslp_transfer_info *out,
                                   size_t max_out);
int db_zslp_max_height(struct node_db *ndb);

/* Save a ZSLP token GENESIS record. token_id = genesis txid (internal order). */
bool db_zslp_token_save(struct node_db *ndb, const uint8_t token_id[32],
                         const char *ticker, const char *name,
                         int decimals, const char *document_url,
                         int genesis_height, int64_t initial_quantity);

/* Save a ZSLP transfer (GENESIS, SEND, or MINT output). */
bool db_zslp_transfer_save(struct node_db *ndb, const uint8_t txid[32],
                            int block_height, const uint8_t token_id[32],
                            int tx_type, int64_t amount, int vout,
                            const uint8_t *to_addr); /* NULL if unknown */

/* Wipe all ZSLP data (for re-indexing). */
void db_zslp_clear_all(struct node_db *ndb);

#endif
