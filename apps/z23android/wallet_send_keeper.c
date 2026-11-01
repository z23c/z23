/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send_keeper.h"

void wsk_init(struct wsk *k, const struct wsk_host *host)
{
    *k = (struct wsk){.host = *host};
}

/* A flow whose progress or outcome the owner has not closed: authenticating, building, handed to the node, done, already paid, or
 * ended with an unknown result. Destroying it would hide what happened to the payment. */
static bool held(struct wss *s)
{
    struct wss_view v;
    if (wss_closed(s)) return false;
    wss_view(s, &v);
    return v.state == WS_AUTH || v.state == WS_COMMIT || v.state == WS_BROADCAST || v.state == WS_DONE || v.state == WS_PAID || v.check_history;
}

bool wsk_attach(struct wsk *k)
{
    if (k->screen) return false;
    if (k->retired) {
        k->screen = k->retired;
        k->retired = NULL;
        k->reshow = true;
        if (k->host.bind) k->host.bind(k->host.ctx, k->screen);
        return true;
    }
    k->screen = k->host.make(k->host.ctx);
    return k->screen != NULL;
}

void wsk_detach(struct wsk *k)
{
    if (!k->screen) return;
    for (int i = 0; i < WSK_DETACH_STEPS && !held(k->screen); ++i) {
        if (wss_destroy(k->screen)) { k->screen = NULL; return; }
        wss_on_tick(k->screen);
        if (k->host.pause) k->host.pause(k->host.ctx);
    }
    wss_unbind(k->screen);
    k->retired = k->screen;
    k->screen = NULL;
}

void wsk_tick(struct wsk *k)
{
    if (k->retired && wss_exposed(k->retired)) wss_on_tick(k->retired);
}

bool wsk_owes(struct wsk *k)
{
    return k->retired && wss_exposed(k->retired);
}
