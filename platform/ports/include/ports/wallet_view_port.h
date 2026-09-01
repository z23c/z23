/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_view_port — storage interface for the wallet "view" projection
 * (the receive-address list and the held-token summary the explorer /
 * wallet UI render).
 *
 * This is a read-ONLY, NON-CONSENSUS projection. It reads the wallet key
 * tables and the ZSLP token/transfer indices to produce two small,
 * bounded lists. wallet_view_projection.c is the only domain logic;
 * everything below this interface is storage.
 *
 * The seam exists so the service never names sqlite. The two methods
 * here capture exactly the queries the service issues:
 *
 *   list_receive_addresses(out,max)  the sapling receive-address list
 *                                    ("SELECT address FROM
 *                                     wallet_sapling_keys ...")
 *   list_held_tokens(out,max)        the top-10 held-token summary
 *                                    (the zslp_tokens JOIN zslp_transfers
 *                                     aggregate)
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem.
 *
 * Threading: the live adapter wraps a single sqlite3* opened by boot.
 * Both methods are read-only and run on request threads; sqlite's own
 * locking serializes them against the wallet writer.
 */

#ifndef ZCL_PORTS_WALLET_VIEW_PORT_H
#define ZCL_PORTS_WALLET_VIEW_PORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* One wallet receive address. Mirrors struct wv_receive_address in
 * services/wallet_view_projection.h field-for-field; declared here so
 * the port has no dependency on the service header. */
struct wallet_view_receive_address {
    char address[128];
};

/* One held-token summary row. Mirrors struct wv_held_token. */
struct wallet_view_held_token {
    char token_id[65];
    char ticker[16];
    int  decimals;
};

/* ── Page-projection row types ────────────────────────────────
 * The rows the wallet view PAGES (dashboard / coins / history /
 * node / shield) read. Each mirrors exactly the column list and
 * order of each SELECT, so the rendered HTML stays byte-identical.
 * The adapter is the only place
 * that names sqlite for these; controllers reach them through the
 * service wrappers in services/wallet_view_projection.h. */

/* One held-token detail row (coins page): token_id + ticker + name +
 * decimals + summed balance. Distinct from wallet_view_held_token
 * (dashboard summary) because the coins page also needs the name and
 * the raw balance for full-precision display. */
struct wallet_view_token_balance {
    char    token_id[65];   /* hex(token_id) */
    char    ticker[64];
    char    name[128];
    int     decimals;
    int64_t balance;        /* SUM(amount), zatoshi-equivalent base units */
};

/* One unspent wallet UTXO (coins page). */
struct wallet_view_coin {
    char    txid[65];       /* hex(txid), upper-hex */
    int     vout;
    int64_t value;
    int     height;
    char    type[16];       /* "Coinbase" | "Standard" */
};

/* One grouped shielded-note row (coins page note table). */
struct wallet_view_note_group {
    int64_t value;
    char    address[256];
    int     count;
    int     min_height;
    int     max_height;
};

/* One ledger/transaction row (dashboard recent + history list). The
 * column list matches both queries' shared prefix; history adds a fee
 * column which the dashboard query omits (fee is 0 for the dashboard). */
struct wallet_view_ledger_row {
    char    txid[65];       /* hex(txid) */
    int     height;
    int64_t block_time;
    int     from_me;
    int64_t fee;
    int64_t wallet_output;  /* received / change to our wallet */
    int64_t wallet_input;   /* spent from our wallet by this tx */
};

/* One unspent shielded note (dashboard recent + history note list). */
struct wallet_view_note_row {
    int64_t value;
    int     height;
    char    address[256];
    int64_t block_time;     /* 0 when not joined to blocks */
};

/* One connected-peer row (node page peer table). */
struct wallet_view_peer_row {
    char    addr[128];
    char    subver[128];
    int     starting_height;
    int     inbound;
};

/* One wallet UTXO output for a single tx (tx-detail page). */
struct wallet_view_tx_output {
    int     vout;
    int64_t value;
};

/* Header fields for a single wallet transaction (tx-detail lookup). */
struct wallet_view_tx_header {
    int     block_height;
    int     from_me;
    int64_t fee;
    int64_t block_time;
};

struct wallet_view_port {
    void *self;

    /* Project the wallet's sapling receive addresses into the
     * caller-owned `out` buffer in stable (rowid) order. Returns the
     * number of rows written (<= max). Returns 0 on storage error,
     * empty wallet, or bad args. */
    int (*list_receive_addresses)(void *self,
                                  struct wallet_view_receive_address *out,
                                  size_t max);

    /* Project the top-10 held-token summary (tokens with a positive
     * net balance to a wallet key) into the caller-owned `out` buffer,
     * highest balance first. Returns the number of rows written
     * (<= max). Returns 0 on storage error, no holdings, or bad args. */
    int (*list_held_tokens)(void *self,
                            struct wallet_view_held_token *out,
                            size_t max);

    /* Dashboard token cards: top-5 held tokens (ticker + decimals +
     * balance). Returns rows written (<= max). */
    int (*list_token_cards)(void *self,
                            struct wallet_view_token_balance *out,
                            size_t max);

    /* Coins page token table: top-50 held tokens with name. */
    int (*list_token_balances)(void *self,
                               struct wallet_view_token_balance *out,
                               size_t max);

    /* Coins page: unspent wallet UTXOs, highest value first. */
    int (*list_unspent_coins)(void *self,
                              struct wallet_view_coin *out,
                              size_t max);

    /* Coins page: grouped unspent shielded notes, highest value first. */
    int (*list_note_groups)(void *self,
                            struct wallet_view_note_group *out,
                            size_t max);

    /* Dashboard recent + history list: wallet transactions ordered by
     * height DESC. `limit`/`offset` page the result; `restrict_mode`,
     * `from_me`, `search_hex` are the history filter params (pass
     * restrict_mode=0 / from_me=0 / search_hex=NULL for the unfiltered
     * dashboard query). When `with_filter` is false the simpler
     * dashboard query (no fee, no filter) is used. */
    int (*list_ledger_rows)(void *self,
                            struct wallet_view_ledger_row *out, size_t max,
                            bool with_filter, int restrict_mode, int from_me,
                            const char *search_hex, int limit, int offset);

    /* Dashboard recent + history: count of transactions matching the
     * history filter. Returns the count (0 on error / bad args). */
    int (*count_ledger_rows)(void *self, int restrict_mode, int from_me,
                             const char *search_hex);

    /* Dashboard recent + history: unspent shielded notes, height DESC.
     * `with_block_time` joins blocks for the timestamp (history) vs not
     * (dashboard). `limit` caps the result. */
    int (*list_recent_notes)(void *self,
                             struct wallet_view_note_row *out, size_t max,
                             bool with_block_time, int limit);

    /* Node page: connected peers, starting_height DESC, up to `max`. */
    int (*list_peers)(void *self,
                      struct wallet_view_peer_row *out, size_t max);

    /* Shield confirm: first sapling destination address (rowid order).
     * Writes into `out` (size `outmax`); returns true if a non-empty
     * address was found. */
    bool (*first_sapling_address)(void *self, char *out, size_t outmax);

    /* Tx detail: look up a single wallet transaction by upper-hex txid.
     * Fills `*out` and returns true if found. */
    bool (*lookup_tx_header)(void *self, const char *upper_txid,
                             struct wallet_view_tx_header *out);

    /* Tx detail: wallet UTXO outputs for `upper_txid`, vout order. */
    int (*list_tx_outputs)(void *self, const char *upper_txid,
                           struct wallet_view_tx_output *out, size_t max);
};

#endif /* ZCL_PORTS_WALLET_VIEW_PORT_H */
