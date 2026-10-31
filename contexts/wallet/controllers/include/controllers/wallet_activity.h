/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.wallet.summary and core.wallet.history: the pure aggregation over
 * wallet fact rows (wallet_activity.c) and the node RPC handlers and JSON
 * rendering on top of it (wallet_activity_rpc.c). Both are read-only and use
 * only viewing keys: they never touch a spending key. */

#ifndef ZCL_CONTROLLERS_WALLET_ACTIVITY_H
#define ZCL_CONTROLLERS_WALLET_ACTIVITY_H

#include "models/wallet_activity.h"
#include "rpc/server.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* Confirmations a shielded note needs before it is spendable. A note the
 * wallet received from elsewhere needs WALLET_CONF_RECEIVED; a note created
 * by a transaction that spends a wallet note or coin is the wallet's own
 * change and needs WALLET_CONF_CHANGE. */
#define WALLET_CONF_RECEIVED 10
#define WALLET_CONF_CHANGE 3
/* Same maturity rule as db_wallet_utxo_spendable_balance: a coinbase output
 * counts once its height is at most tip - WALLET_COINBASE_MATURITY. */
#define WALLET_COINBASE_MATURITY 100

#define WALLET_HISTORY_DEFAULT_LIMIT 10
#define WALLET_HISTORY_MAX_LIMIT 16

struct wallet_summary {
    int64_t spendable;       /* confirmed, unspent shielded notes */
    int64_t pending;         /* unspent shielded notes below threshold */
    int pending_count;
    int pending_min_confs_needed; /* smallest remaining; 0 when none */
    int64_t sending;         /* wallet funds spent by an unconfirmed tx */
    int64_t public_confirmed;
    int64_t immature;
};

/* Sum the wallet's holdings. Only notes whose ivk appears in `ivks` count; a
 * repeated ivk and a repeated note row each count once. */
void wallet_summary_accumulate(const struct db_wallet_note_fact *notes,
                               size_t nn,
                               const struct db_wallet_coin_fact *coins,
                               size_t nc,
                               const struct db_wallet_tx_fact *txs, size_t nt,
                               const uint8_t (*ivks)[32], size_t nk, int tip,
                               struct wallet_summary *out);

enum wallet_direction {
    WALLET_DIR_RECEIVED,
    WALLET_DIR_SENT,
    WALLET_DIR_INTERNAL,
    WALLET_DIR_UNKNOWN, /* outgoing, but the split cannot be recovered */
};

struct wallet_history_entry {
    uint8_t txid[32];
    int height;              /* 0 while pending */
    int confirmations;
    int64_t time;            /* 0 when unknown */
    enum wallet_direction direction;
    bool private_kind;       /* any shielded note involved */
    int64_t net;             /* signed change to the wallet's balance */
    bool amount_known;
    int64_t amount;          /* received, or value sent to others; 0 internal */
    bool fee_known;
    int64_t fee;
    bool memo_present;
};

/* Build every history entry, newest first (pending first, then descending
 * height, ties by txid). Returns the count or -1; free *out with free(). */
int wallet_history_build(const struct db_wallet_note_fact *notes, size_t nn,
                         const struct db_wallet_coin_fact *coins, size_t nc,
                         const struct db_wallet_tx_fact *txs, size_t nt,
                         const uint8_t (*ivks)[32], size_t nk, int tip,
                         struct wallet_history_entry **out);

struct wallet_history_cursor {
    bool set;
    int key;                 /* height, or INT32_MAX while pending */
    uint8_t txid[32];
};

/* Cursor text is "<height|p>:<64 hex>" naming the last entry of a page. */
bool wallet_history_cursor_parse(const char *text,
                                 struct wallet_history_cursor *out);
void wallet_history_cursor_format(const struct wallet_history_entry *e,
                                  char *out, size_t cap);
/* Index of the first entry strictly after the cursor. */
size_t wallet_history_page_start(const struct wallet_history_entry *e,
                                 size_t n,
                                 const struct wallet_history_cursor *cur);

/* Node state the summary reports beside the amounts. */
struct wallet_chain_view {
    int tip_height;
    int header_height;
    int peer_best_height;
    int scanned_through;
    bool locked;
    bool encrypted;
    size_t shielded_keys;
};

void wallet_summary_to_json(const struct wallet_summary *s,
                            const struct wallet_chain_view *v,
                            bool send_allowed, const char *send_reason,
                            struct json_value *out);
void wallet_history_entry_to_json(const struct wallet_history_entry *e,
                                  struct json_value *out);

/* The one place the summary asks whether the wallet may send. */
bool wallet_send_gate(char *reason, size_t cap);

bool rpc_walletsummary(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_wallethistory(const struct json_value *params, bool help,
                       struct json_value *result);
struct sapling_keystore;
bool wallet_latest_shielded_address(const struct sapling_keystore *ks,
                                    const char *hrp, char *out, size_t cap);
bool rpc_walletlatestaddress(const struct json_value *params, bool help,
                             struct json_value *result);
void register_wallet_activity_rpc_commands(struct rpc_table *t);

#endif /* ZCL_CONTROLLERS_WALLET_ACTIVITY_H */
