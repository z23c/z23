/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.wallet.summary and core.wallet.history: the pure aggregation over
 * wallet fact rows (wallet_activity.c) and the node RPC handlers and JSON
 * rendering on top of it (wallet_shielded_activity_rpc.c). Both are read-only and use
 * only viewing keys: they never touch a spending key. */

#ifndef ZCL_CONTROLLERS_WALLET_ACTIVITY_H
#define ZCL_CONTROLLERS_WALLET_ACTIVITY_H

#include "models/wallet_activity.h"
#include "rpc/server.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct wallet_rpc_context;
struct db_sapling_note;

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
    /* The most one send can spend now: a send draws on one key and takes at
     * most WALLET_SEND_MAX_NOTES inputs, largest first, so this is the largest
     * per-key sum of that many confirmed, unspent shielded notes past their
     * threshold with an unspent nullifier on the chain and a witness at the
     * authoritative tip. The notes are exactly those wallet_note_classify
     * calls spendable, which z_sendmany uses to select its inputs. */
    int64_t spendable;
    /* Every such note summed across every key, with no per-send cap. */
    int64_t spendable_total;
    int64_t pending;         /* unspent shielded notes below threshold */
    int pending_count;
    int pending_min_confs_needed; /* smallest remaining; 0 when none */
    /* Confirmed notes send would refuse for now: a missing or stale witness,
     * or a spent set that could not be read. */
    int64_t unready;
    int unready_notes;
    /* Notes whose nullifier the chain already holds; they count nowhere. */
    int reconciling_notes;
    int64_t sending;         /* wallet funds spent by an unconfirmed tx */
    int64_t public_confirmed;
    int64_t immature;
};

enum wallet_note_class {
    WALLET_NOTE_RECONCILING, /* the chain already spent it */
    WALLET_NOTE_PENDING,     /* below its confirmation threshold */
    WALLET_NOTE_SPENDABLE,
    WALLET_NOTE_UNREADY,     /* confirmed, but chain or witness not ready */
};

/* The one rule for what a shielded note is worth to a send: WALLET_CONF_CHANGE
 * confirmations for a note a wallet transaction created by spending, else
 * WALLET_CONF_RECEIVED; spendable also needs the nullifier unspent on the
 * chain and a current witness. `spenders` is wallet_note_spenders output.
 * *short_by is the confirmations still missing when pending, else 0. */
enum wallet_note_class wallet_note_classify(
    const struct db_wallet_note_fact *n, const uint8_t (*spenders)[32],
    size_t ns, int tip, int *short_by);
bool wallet_note_is_spendable(const struct db_wallet_note_fact *n,
                              const uint8_t (*spenders)[32], size_t ns,
                              int tip);
/* Sorted txids of every transaction that spent a wallet note or coin; NULL
 * when it cannot be allocated. Free with free(). */
uint8_t (*wallet_note_spenders(const struct db_wallet_note_fact *notes,
                               size_t nn,
                               const struct db_wallet_coin_fact *coins,
                               size_t nc, const uint8_t (*ivks)[32], size_t nk,
                               size_t *count))[32];

/* The notes z_sendmany selects from: up to `cap` of one key's unspent notes,
 * largest first, that wallet_note_is_spendable accepts and that have at least
 * `min_conf` confirmations (an extra floor, never a bypass). Filtering comes
 * before the cap. Returns the count, or -1 when the wallet state cannot be
 * read. */
int wallet_send_spendable_notes(struct wallet_rpc_context *ctx,
                                const uint8_t ivk[32], int min_conf,
                                struct db_sapling_note *out, int cap);

/* Sum the wallet's holdings. Only notes whose ivk appears in `ivks` count; a
 * repeated ivk and a repeated note row each count once. A note's chain and
 * witness fields must be filled; an unchecked note is never spendable.
 * False, with *out zeroed, when the working set cannot be allocated: the
 * amounts are then unknown, not zero. */
bool wallet_summary_accumulate(const struct db_wallet_note_fact *notes,
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
    bool private_kind;       /* fully_shielded is 1 */
    /* 1 when every input and output of the transaction is shielded, 0 when
     * any is transparent, -1 when the wallet cannot tell. */
    int fully_shielded;
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

struct wallet_history_page_key {
    bool set;
    int key;                 /* height, or INT32_MAX while pending */
    uint8_t txid[32];
};

/* Cursor text is "<height|p>:<64 hex>" naming the last entry of a page. */
bool wallet_history_cursor_parse(const char *text,
                                 struct wallet_history_page_key *out);
void wallet_history_cursor_format(const struct wallet_history_entry *e,
                                  char *out, size_t cap);
/* Index of the first entry strictly after the cursor. */
size_t wallet_history_page_start(const struct wallet_history_entry *e,
                                 size_t n,
                                 const struct wallet_history_page_key *cur);

/* A block or header newer than this many seconds shows the chain moving. */
#define WALLET_CHAIN_FRESH_SECONDS 600

/* True when this node saw its tip or best header advance within
 * WALLET_CHAIN_FRESH_SECONDS, `age_ms` being the node's own monotonic age of
 * that observation (node_health_snapshot.chain_progress_age_ms). Negative
 * means none was seen, which is never fresh. Block timestamps and the wall
 * clock play no part. */
bool wallet_chain_fresh(int64_t age_ms);

/* The most notes one send spends, and so the most the summary counts per key. */
#define WALLET_SEND_MAX_NOTES 256

/* Node state the summary reports beside the amounts. */
struct wallet_chain_view {
    int tip_height;          /* > 0: a command with no tip fails instead */
    int header_height;       /* 0 when the node knows no header */
    int peer_best_height;    /* 0 or less when no peer reports a height */
    size_t peer_count;       /* peers past the handshake; 0 when offline */
    bool chain_fresh;        /* wallet_chain_fresh: the chain moved lately */
    int scanned_through;     /* < 0 when unknown */
    bool locked;
    bool encrypted;
    size_t shielded_keys;
    /* False when the viewing keys were not loaded (a locked wallet that
     * kept none), so no shielded amount can be read. */
    bool shielded_known;
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
