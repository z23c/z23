/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_WALLET_VIEW_PROJECTION_H
#define ZCL_SERVICES_WALLET_VIEW_PROJECTION_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sqlite3.h>

#include "ports/wallet_view_port.h"

struct wv_receive_address {
    char address[128];
};

struct wv_held_token {
    char token_id[65];
    char ticker[16];
    int decimals;
};

int wv_list_receive_addresses(sqlite3 *db, struct wv_receive_address *out,
                              size_t max);
int wv_list_held_tokens(sqlite3 *db, struct wv_held_token *out, size_t max);

/* ── Page projections ─────────────────────────────────────────
 * Thin service wrappers over the wallet_view_port page methods. Each
 * binds the default sqlite adapter to `db` and drives the port, so the
 * wallet_view PAGE controllers reach storage without naming sqlite. The
 * row types are the port's own (no layout duplication). */

int wv_list_token_cards(sqlite3 *db,
                        struct wallet_view_token_balance *out, size_t max);
int wv_list_token_balances(sqlite3 *db,
                           struct wallet_view_token_balance *out, size_t max);
int wv_list_unspent_coins(sqlite3 *db,
                          struct wallet_view_coin *out, size_t max);
int wv_list_note_groups(sqlite3 *db,
                        struct wallet_view_note_group *out, size_t max);
int wv_list_ledger_rows(sqlite3 *db,
                        struct wallet_view_ledger_row *out, size_t max,
                        bool with_filter, int restrict_mode, int from_me,
                        const char *search_hex, int limit, int offset);
int wv_count_ledger_rows(sqlite3 *db, int restrict_mode, int from_me,
                         const char *search_hex);
int wv_list_recent_notes(sqlite3 *db,
                         struct wallet_view_note_row *out, size_t max,
                         bool with_block_time, int limit);
int wv_list_peers(sqlite3 *db,
                  struct wallet_view_peer_row *out, size_t max);
bool wv_first_sapling_address(sqlite3 *db, char *out, size_t outmax);
bool wv_lookup_tx_header(sqlite3 *db, const char *upper_txid,
                         struct wallet_view_tx_header *out);
int wv_list_tx_outputs(sqlite3 *db, const char *upper_txid,
                       struct wallet_view_tx_output *out, size_t max);

#endif /* ZCL_SERVICES_WALLET_VIEW_PROJECTION_H */
