/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable once-only record of one keyed wallet send.
 *
 * One row per idempotency key, written to node.db before any transaction is
 * built and advanced before the wallet admits it. The row holds only hashes,
 * a state and, once known, the txid. It never holds the key, an address, an
 * amount or a memo: key_hash and digest are SHA3-256 values bound to the
 * caller's key, so a copy of node.db cannot be searched for a payment. */

#ifndef ZCL_MODELS_WALLET_SEND_ONCE_H
#define ZCL_MODELS_WALLET_SEND_ONCE_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

/* Retention. A key must outlive any window in which an app can repeat a
 * request: committed rows are kept 90 days, rows that never reached a known
 * outcome are kept 365 days so the answer stays outcome_unknown rather than
 * becoming a fresh send. The table is capped; at the cap a new keyed send is
 * refused instead of forgetting an older key. */
#define WALLET_SEND_ONCE_COMMITTED_RETAIN_SEC (90LL * 86400LL)
#define WALLET_SEND_ONCE_UNRESOLVED_RETAIN_SEC (365LL * 86400LL)
#define WALLET_SEND_ONCE_MAX_ROWS 100000

enum wallet_send_once_state {
    WALLET_SEND_ONCE_STARTED = 1,   /* recorded; nothing built yet */
    WALLET_SEND_ONCE_BUILT = 2,     /* txid known, about to be admitted */
    WALLET_SEND_ONCE_COMMITTED = 3  /* admitted and durable in the wallet */
};

struct wallet_send_once_row {
    uint8_t key_hash[32];
    uint8_t digest[32];
    enum wallet_send_once_state state;
    bool has_txid;
    uint8_t txid[32];
    int64_t created_at;
    int64_t updated_at;
};

struct ar_callbacks *db_wallet_send_once_callbacks(void);
bool db_wallet_send_once_validate(const struct wallet_send_once_row *row,
                                  struct ar_errors *errors);
/* Insert a new row; false when the key already exists or the write failed. */
bool db_wallet_send_once_insert(struct node_db *ndb,
                                const struct wallet_send_once_row *row);
bool db_wallet_send_once_find(struct node_db *ndb, const uint8_t key_hash[32],
                              struct wallet_send_once_row *out);
/* Advance a row to a later state; a row never moves backwards. */
bool db_wallet_send_once_advance(struct node_db *ndb,
                                 const uint8_t key_hash[32],
                                 enum wallet_send_once_state state,
                                 const uint8_t *txid, int64_t now);
/* Release a key that provably built nothing. Never removes a committed row. */
bool db_wallet_send_once_release(struct node_db *ndb,
                                 const uint8_t key_hash[32]);
int db_wallet_send_once_count(struct node_db *ndb);
/* Delete rows older than their retention. */
bool db_wallet_send_once_prune(struct node_db *ndb, int64_t now);
/* The connection's PRAGMA synchronous level (0 OFF, 1 NORMAL, 2 FULL), -1 on error. */
int db_wallet_send_once_sync_level(struct node_db *ndb);

#endif
