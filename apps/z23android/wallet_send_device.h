/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_DEVICE_H
#define ZAPP_WALLET_SEND_DEVICE_H
#include "device_key.h"
#include "wallet_send_screen.h"

/* The device side of a send: the typed wss_device_ops over the device key. Every payment opens the wrapped wallet
 * secret with ZAPP_DEVKEY_PURPOSE_PAYMENT, so the owner is asked under the prompt that authorises a payment and never
 * under the one that unlocks the wallet. One call, one prompt: nothing here remembers an authentication.
 *
 * The call blocks while the system prompt is up, so it runs only on the screen's worker, and `ops` must give the
 * keystore operations bound to the calling thread (a JVM-attached worker with the activity). */
struct wsd {
    void *ctx;
    /* Fills ops for the calling thread; false when the thread has no JVM or no activity. */
    bool (*ops)(void *ctx, struct zapp_devkey_ops *out);
    char blob[512];   /* the wrapped wallet secret, in the app's private files */
};

/* The blob of the wallet secret under the app files directory. */
bool wsd_init(struct wsd *device, void *ctx, bool (*ops)(void *ctx, struct zapp_devkey_ops *out), const char *files);
void wsd_ops(struct wsd *device, struct wss_device_ops *ops);

#endif
