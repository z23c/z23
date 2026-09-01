/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet dashboard-page view (/wallet). The controller fetches the
 * token-card summary, the recent ledger rows, and the recent shielded
 * notes via the wallet_view port, then delegates the HTML assembly for
 * the "Tokens" card and the "Recent transactions" list here. Controllers
 * must not build views. */

#ifndef ZCL_VIEWS_WALLET_VIEW_DASHBOARD_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_DASHBOARD_VIEW_H

#include "ports/wallet_view_port.h"

#include <stddef.h>
#include <stdint.h>

/* Build the dashboard "Tokens" card into `out` (size `outmax`) from the
 * top-5 held tokens `tokens` (`n` rows). Emits nothing when `n` == 0 (no
 * positive-balance token). Returns bytes written (NUL-terminated). */
size_t wv_render_dashboard_tokens(char *out, size_t outmax,
                                  const struct wallet_view_token_balance *tokens,
                                  int n);

/* Build the dashboard "Recent transactions" list into `out` (size
 * `outmax`). `rows` are the recent ledger rows (`n_rows`), `notes` are
 * the recent unspent shielded notes (`n_notes`); both are shown until 5
 * entries total are rendered. `tip` and `total_balance` drive the
 * confirmation context and the empty-state message. Returns bytes
 * written (NUL-terminated). */
size_t wv_render_dashboard_recent(char *out, size_t outmax,
                                  const struct wallet_view_ledger_row *rows,
                                  int n_rows,
                                  const struct wallet_view_note_row *notes,
                                  int n_notes,
                                  int tip, int64_t total_balance);

#endif /* ZCL_VIEWS_WALLET_VIEW_DASHBOARD_VIEW_H */
