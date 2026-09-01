/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:count-of-rows-projected — both public functions
// (wv_list_receive_addresses / wv_list_held_tokens) return int = the
// number of rows written into the caller's out-array, which IS the
// payload. An empty wallet legitimately returns 0; a prepare failure also
// returns 0 because there are simply no rows to project. The read-only
// projection has no mutating decision and nothing to carry beyond the
// count. Wrapping it in zcl_result would discard the row count.
//
// Storage is reached ONLY through wallet_view_port — the raw sqlite
// queries live in the sqlite adapter. This file is pure domain logic:
// it binds the default sqlite adapter and drives the port. The public
// functions still accept a sqlite3* so callers (wallet_view controllers,
// tests) are unchanged.

#include "services/wallet_view_projection.h"

#include "adapters/outbound/persistence/wallet_view_sqlite.h"
#include "ports/wallet_view_port.h"

#include <stddef.h>

/* struct wv_receive_address / struct wv_held_token (public service types)
 * and the port row types are deliberately kept layout-identical so the
 * port can fill the caller's buffer in one shot with no per-row copy.
 * These asserts fail the build if either drifts. */
_Static_assert(sizeof(struct wv_receive_address) ==
                   sizeof(struct wallet_view_receive_address),
               "wv_receive_address size must match port row");
_Static_assert(offsetof(struct wv_receive_address, address) ==
                   offsetof(struct wallet_view_receive_address, address),
               "wv_receive_address layout must match port row");
_Static_assert(sizeof(struct wv_held_token) ==
                   sizeof(struct wallet_view_held_token),
               "wv_held_token size must match port row");
_Static_assert(offsetof(struct wv_held_token, token_id) ==
                       offsetof(struct wallet_view_held_token, token_id) &&
                   offsetof(struct wv_held_token, ticker) ==
                       offsetof(struct wallet_view_held_token, ticker) &&
                   offsetof(struct wv_held_token, decimals) ==
                       offsetof(struct wallet_view_held_token, decimals),
               "wv_held_token layout must match port row");

int wv_list_receive_addresses(sqlite3 *db, struct wv_receive_address *out,
                              size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    /* Layout-identical to struct wallet_view_receive_address (asserted
     * above); project directly into the caller's buffer. */
    return port.list_receive_addresses(
        port.self, (struct wallet_view_receive_address *)out, max);
}

int wv_list_held_tokens(sqlite3 *db, struct wv_held_token *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    /* Layout-identical to struct wallet_view_held_token (asserted above). */
    return port.list_held_tokens(
        port.self, (struct wallet_view_held_token *)out, max);
}

/* ── Page projection wrappers ─────────────────────────────────
 * Each binds the sqlite adapter and forwards to the port. The wallet
 * view PAGE controllers call these instead of touching sqlite. */

int wv_list_token_cards(sqlite3 *db,
                        struct wallet_view_token_balance *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_token_cards(port.self, out, max);
}

int wv_list_token_balances(sqlite3 *db,
                           struct wallet_view_token_balance *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_token_balances(port.self, out, max);
}

int wv_list_unspent_coins(sqlite3 *db,
                          struct wallet_view_coin *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_unspent_coins(port.self, out, max);
}

int wv_list_note_groups(sqlite3 *db,
                        struct wallet_view_note_group *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_note_groups(port.self, out, max);
}

int wv_list_ledger_rows(sqlite3 *db,
                        struct wallet_view_ledger_row *out, size_t max,
                        bool with_filter, int restrict_mode, int from_me,
                        const char *search_hex, int limit, int offset)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_ledger_rows(port.self, out, max, with_filter,
                                 restrict_mode, from_me, search_hex,
                                 limit, offset);
}

int wv_count_ledger_rows(sqlite3 *db, int restrict_mode, int from_me,
                         const char *search_hex)
{
    if (!db)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.count_ledger_rows(port.self, restrict_mode, from_me,
                                  search_hex);
}

int wv_list_recent_notes(sqlite3 *db,
                         struct wallet_view_note_row *out, size_t max,
                         bool with_block_time, int limit)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_recent_notes(port.self, out, max, with_block_time,
                                  limit);
}

int wv_list_peers(sqlite3 *db,
                  struct wallet_view_peer_row *out, size_t max)
{
    if (!db || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_peers(port.self, out, max);
}

bool wv_first_sapling_address(sqlite3 *db, char *out, size_t outmax)
{
    if (!db || !out || outmax == 0)
        return false;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return false;  // raw-return-ok:bind-only-fails-on-null-db-already-checked-above
    return port.first_sapling_address(port.self, out, outmax);
}

bool wv_lookup_tx_header(sqlite3 *db, const char *upper_txid,
                         struct wallet_view_tx_header *out)
{
    if (!db || !upper_txid || !out)
        return false;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return false;  // raw-return-ok:bind-only-fails-on-null-db-already-checked-above
    return port.lookup_tx_header(port.self, upper_txid, out);
}

int wv_list_tx_outputs(sqlite3 *db, const char *upper_txid,
                       struct wallet_view_tx_output *out, size_t max)
{
    if (!db || !upper_txid || !out || max == 0)
        return 0;
    struct wallet_view_port port;
    if (!wallet_view_sqlite_bind(db, &port))
        return 0;
    return port.list_tx_outputs(port.self, upper_txid, out, max);
}
