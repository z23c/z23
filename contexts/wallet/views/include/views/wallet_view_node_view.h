/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet node-page view — the peer table for /wallet/node. The
 * controller fetches the peer rows via the wallet_view port, packs them
 * into the struct below, and delegates the HTML assembly here. */

#ifndef ZCL_VIEWS_WALLET_VIEW_NODE_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_NODE_VIEW_H

#include "ports/wallet_view_port.h"

#include <stddef.h>

/* Render the node-page peer table into the caller-owned `out` buffer
 * (size `outmax`). `peers` is the fetched peer rows (`n` of them, may be
 * 0 → "Connecting to network..." row). Returns bytes written. */
size_t wv_render_peer_table(char *out, size_t outmax,
                            const struct wallet_view_peer_row *peers, int n);

#endif /* ZCL_VIEWS_WALLET_VIEW_NODE_VIEW_H */
