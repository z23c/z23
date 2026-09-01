/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet shield-page view — the "nothing to shield" panel for
 * /wallet/shield when the transparent balance is dust. The controller
 * decides which panel to show and fetches the balances; this view owns
 * the inline HTML. */

#ifndef ZCL_VIEWS_WALLET_VIEW_SHIELD_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_SHIELD_VIEW_H

#include <stddef.h>
#include <stdint.h>

/* Append the "Nothing to shield" panel (breadcrumb + body) to the
 * response buffer `r` (size `max`) starting at `*off`. Advances `*off`. */
void wv_render_shield_nothing(uint8_t *r, size_t max, size_t *off);

#endif /* ZCL_VIEWS_WALLET_VIEW_SHIELD_VIEW_H */
