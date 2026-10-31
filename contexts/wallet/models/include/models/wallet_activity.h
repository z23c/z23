/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only fact rows for the wallet summary and history commands. Each row
 * is a narrow projection of wallet_sapling_notes, wallet_utxos or
 * wallet_transactions, ordered by (txid, index) so a duplicate row is always
 * adjacent to its twin. No row carries a key or an address. */

#ifndef ZCL_DB_MODEL_WALLET_ACTIVITY_H
#define ZCL_DB_MODEL_WALLET_ACTIVITY_H

#include "models/database.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_wallet_note_fact {
    uint8_t txid[32];
    uint32_t output_index;
    int64_t value;
    uint8_t ivk[32];
    int block_height;       /* 0 while unconfirmed */
    bool spent;
    uint8_t spent_txid[32]; /* valid when spent */
    bool memo_present;      /* any byte other than 0x00 and 0xf6 */
};

struct db_wallet_coin_fact {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    int height;
    bool spent;
    uint8_t spent_txid[32]; /* valid when spent */
    bool coinbase;
};

struct db_wallet_tx_fact {
    uint8_t txid[32];
    int block_height;       /* 0 while unconfirmed */
    int64_t time_received; /* when the wallet recorded it */
    bool from_me;
    int64_t fee;            /* 0 when never recorded */
};

/* Each reader heap-allocates *out (NULL when empty) and returns the row
 * count, or -1 on a closed database, allocation failure or SQL error. The
 * caller frees *out with free(). */
int db_wallet_note_facts_alloc(struct node_db *ndb,
                               struct db_wallet_note_fact **out);
int db_wallet_coin_facts_alloc(struct node_db *ndb,
                               struct db_wallet_coin_fact **out);
int db_wallet_tx_facts_alloc(struct node_db *ndb,
                             struct db_wallet_tx_fact **out);

/* Memo bytes and receiving address of every note one transaction created.
 * Writes at most `max` rows and returns the count; ivk filtering is the
 * caller's job. */
struct db_wallet_note_memo {
    uint32_t output_index;
    uint8_t ivk[32];
    uint8_t memo[512];
    size_t memo_len;
    char address[128];
};
int db_wallet_note_memos_for_tx(struct node_db *ndb, const uint8_t txid[32],
                                struct db_wallet_note_memo *out, size_t max);

#endif /* ZCL_DB_MODEL_WALLET_ACTIVITY_H */
