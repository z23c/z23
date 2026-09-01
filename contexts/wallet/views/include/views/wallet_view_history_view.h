/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet history-page view (/wallet/history). The controller parses the
 * page/filter/search, fetches the matching ledger rows and shielded
 * notes via the wallet_view port, and delegates the per-row HTML
 * assembly here. Controllers must not build views. */

#ifndef ZCL_VIEWS_WALLET_VIEW_HISTORY_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_HISTORY_VIEW_H

#include "ports/wallet_view_port.h"

#include <stddef.h>
#include <stdint.h>

/* Append the history timeline cards (one per ledger row in `rows`,
 * `n` of them) to the response buffer `r` (size `max`) at `*off`,
 * advancing `*off`. `tip` drives confirmation counts. */
void wv_render_history_cards(uint8_t *r, size_t max, size_t *off,
                             const struct wallet_view_ledger_row *rows, int n,
                             int tip);

/* Append the "Shielded Notes" section (header + one row per note in
 * `notes`, `n` of them) to `r` at `*off`. Emits nothing if `n` == 0. */
void wv_render_history_notes(uint8_t *r, size_t max, size_t *off,
                             const struct wallet_view_note_row *notes, int n);

/* Build the tx-detail "Wallet Outputs" section into `out` (size
 * `outmax`) from `outs` (`n` rows). Emits nothing (empty string) when
 * `n` == 0. Returns bytes written (NUL-terminated). */
size_t wv_render_tx_outputs(char *out, size_t outmax,
                            const struct wallet_view_tx_output *outs, int n);

#endif /* ZCL_VIEWS_WALLET_VIEW_HISTORY_VIEW_H */
