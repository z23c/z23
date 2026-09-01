/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view controller — HTML dashboard for the GTK browser.
 * All data from SQLite. No RPC. No ports.
 *
 * Routes:
 *   GET /wallet              Dashboard (balance, peers, height)
 *   GET /wallet/send         Send form
 *   GET /wallet/receive      Receive address + QR placeholder
 *   GET /wallet/history      Transaction history
 *   GET /wallet/addresses    All wallet addresses
 *   GET /wallet/coins        Coin analysis (UTXO breakdown) */

#ifndef ZCL_CONTROLLERS_WALLET_VIEW_H
#define ZCL_CONTROLLERS_WALLET_VIEW_H

#include <stdint.h>
#include <stddef.h>

/* Initialize with datadir for SQLite access */
void wallet_view_init(const char *datadir);

/* Enable zclassicd sync (call after GUI starts, not during tests) */
void wallet_view_enable_sync(void);

/* Handle a wallet view request. Returns HTTP response bytes. */
size_t wallet_view_handle_request(const char *method, const char *path,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *response, size_t response_max);

#endif
