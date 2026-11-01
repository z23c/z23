/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_KEEPER_H
#define ZAPP_WALLET_SEND_KEEPER_H
#include "wallet_send_screen.h"

/* Keeps a payment's flow across the destruction and re-creation of the activity. A flow that is authenticating,
 * committing, or holds an outcome the owner has not yet closed is retired, never destroyed, when the activity goes;
 * the next activity adopts it, so it shows that flow's progress or outcome and cannot start a second payment beside it.
 * A retired flow is unbound from the destroyed activity's window at once and bound to the new one on adoption, before it
 * is drawn: it never reaches a window that may be gone and never draws on one that is not protected.
 * Nothing here logs or touches Android. */

struct wsk_host {
    void *ctx;
    struct wss *(*make)(void *ctx);   /* a new screen over fresh ops, or NULL */
    void (*pause)(void *ctx);         /* waits a short while between lock attempts; may be NULL */
    /* Binds an adopted flow to the new activity's window: calls wss_rebind with that window's protections. Until it
     * has, the flow is hidden. May be NULL only where there is no window. */
    void (*bind)(void *ctx, struct wss *screen);
};
#define WSK_DETACH_STEPS 12

struct wsk {
    struct wsk_host host;
    struct wss *screen;    /* the flow the activity shows */
    struct wss *retired;   /* a flow kept for the next activity */
    bool reshow;           /* the adopted flow must be shown at once */
};

void wsk_init(struct wsk *k, const struct wsk_host *host);
/* Adopts the retired flow if there is one (reshow is set), otherwise makes a new screen. False when there is none. */
bool wsk_attach(struct wsk *k);
/* The activity is going away: retires a flow with progress or an unclosed outcome, otherwise waits a short while for
 * the wallet to lock and destroys it; a screen that is still locking is retired. */
void wsk_detach(struct wsk *k);
/* Ticks the retired flow while the wallet may be open. */
void wsk_tick(struct wsk *k);
/* True while a retired flow may hold the wallet open. */
bool wsk_owes(struct wsk *k);

#endif
