/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet coins-page view (/wallet/coins). The controller fetches the
 * unspent UTXOs, grouped shielded notes, and held tokens via the
 * wallet_view port, then delegates each section's HTML assembly here.
 * Controllers must not build views. */

#ifndef ZCL_VIEWS_WALLET_VIEW_COINS_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_COINS_VIEW_H

#include "ports/wallet_view_port.h"

#include <stddef.h>
#include <stdint.h>

/* Build the transparent UTXO table rows into `out` (size `outmax`) from
 * `coins` (`n` rows). `tip` is the chain tip for confirmation counts.
 * Writes the running totals to `*out_total` / `*out_count`. Returns
 * bytes written (NUL-terminated). */
size_t wv_render_coin_rows(char *out, size_t outmax,
                           const struct wallet_view_coin *coins, int n,
                           int tip, int64_t *out_total, int *out_count);

/* Build the shielded-notes <tr> rows into `out` (size `outmax`) from
 * `groups` (`n` rows). Returns bytes written (NUL-terminated). */
size_t wv_render_note_rows(char *out, size_t outmax,
                           const struct wallet_view_note_group *groups, int n);

/* Build the token-table <tr> rows into `out` (size `outmax`) from
 * `tokens` (`n` rows). Returns bytes written (NUL-terminated). */
size_t wv_render_token_rows(char *out, size_t outmax,
                            const struct wallet_view_token_balance *tokens,
                            int n);

#endif /* ZCL_VIEWS_WALLET_VIEW_COINS_VIEW_H */
