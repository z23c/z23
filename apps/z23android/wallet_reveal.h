/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_REVEAL_H
#define ZAPP_WALLET_REVEAL_H
#include "wallet_screens.h"
#include "wallet_send_screen.h"

/* Shows the private balance of a locked wallet for a short window. The owner taps Show private balance on Funds; the
 * device key asks for the screen lock, the node unlocks for WRV_WINDOW_SECONDS, and Funds reads the summary again. The
 * wallet is locked again when the window ends, when the owner leaves the wallet screens or the app is hidden, and again
 * on every tick while a lock is owed.
 *
 * The unlock is the send flow's: wss_unlock_node (device unwrap, unlock request on standard input, cleansed buffers) and
 * the node's lock call. A payment in flight (busy) is never locked under: when one runs, this view stops asking for a
 * lock and the send flow, which holds its own unlock, locks the wallet when it ends. Nothing here reads or keeps an
 * amount. The device key, the node and the host come in through the typed interfaces of the send screen, which the
 * tests fake. This file logs nothing. */

#define WRV_WINDOW_SECONDS 120u

/* wrv_state reports enum wallet_reveal (wallet_screens.h): WALLET_REVEAL_NONE when there is nothing to say, WALLET_REVEAL_OPEN
 * while this view has unlocked the wallet and not yet seen it locked again, and otherwise the reason the last tap left
 * the wallet locked. */

struct wrv_deps {
    struct wss_node_ops node;       /* unlock and lock */
    struct wss_device_ops device;   /* unwrap */
    struct wss_host_ops host;       /* now_ms, spawn and redraw */
    bool (*busy)(void *ctx);        /* a payment is in flight: the wallet is not locked under it; must not call this view */
    void *busy_ctx;
};

struct wrv;
struct wrv *wrv_create(const struct wrv_deps *deps);
/* Wipes and frees. False, and nothing freed, while wrv_owes. */
bool wrv_destroy(struct wrv *view);

/* The owner tapped Show private balance. Starts the prompt on a worker. False, with nothing started, while a prompt or
 * a window is open or a lock is owed; with a payment in flight it starts nothing and the state becomes WALLET_REVEAL_SENDING. */
bool wrv_begin(struct wrv *view);
/* The owner left the wallet screens or the app was hidden: closes the window and, if the wallet may be open, locks it
 * on a worker. A prompt that is still up is cancelled: its answer opens nothing. */
void wrv_end(struct wrv *view);
/* Call about every two seconds: ends the window when it is over and asks again for a lock that is owed. */
void wrv_tick(struct wrv *view);
enum wallet_reveal wrv_state(struct wrv *view);
/* True while a prompt, a window, a lock or a worker is outstanding: ticks must continue. */
bool wrv_owes(struct wrv *view);
/* True when the passphrase and the unlock request hold no byte: proof that every path cleansed them. */
bool wrv_secrets_clear(struct wrv *view);

/* The one view of the app, bound to the activity's node, device key and worker thread by wallet_send_ui.c, which also
 * ticks it with the send flow and counts it in zapp_send_ui_owes. The wallet screens reach it through their environment. */
bool zapp_reveal_start(void);
enum wallet_reveal zapp_reveal_state(void);
void zapp_reveal_end(void);

#endif
