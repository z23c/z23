/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_reveal.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct wrv {
    pthread_mutex_t lock;
    struct wrv_deps d;
    enum wallet_reveal result; /* what Funds is told while no prompt or window is open */
    bool asking;           /* the prompt or the unlock call of the current ticket is running */
    bool open;             /* the window runs until deadline_ms */
    bool owed;             /* the wallet may be unlocked by this view and is not yet known to be locked */
    bool worker;           /* a worker job is running; at most one at a time */
    unsigned ticket;       /* changes when a tap begins and when the view ends, so an old answer is told apart */
    uint64_t deadline_ms;
    struct wss_unlock_buf buf;
};

static uint64_t now_ms(const struct wrv *w)
{
    return w->d.host.now_ms ? w->d.host.now_ms(w->d.host.ctx) : 0;
}
static bool busy(const struct wrv *w)
{
    return w->d.busy && w->d.busy(w->d.busy_ctx);
}
static void redraw(const struct wrv *w)
{
    if (w->d.host.redraw) w->d.host.redraw(w->d.host.ctx);
}

struct wrv *wrv_create(const struct wrv_deps *deps)
{
    struct wrv *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (pthread_mutex_init(&w->lock, NULL) != 0) { free(w); return NULL; }
    w->d = *deps;
    return w;
}

bool wrv_owes(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    bool owes = w->asking || w->open || w->owed || w->worker;
    pthread_mutex_unlock(&w->lock);
    return owes;
}

bool wrv_secrets_clear(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    bool clear = wss_unlock_buf_clear(&w->buf);
    pthread_mutex_unlock(&w->lock);
    return clear;
}

bool wrv_destroy(struct wrv *w)
{
    if (!w) return true;
    if (wrv_owes(w)) return false;
    wss_unlock_cleanse(&w->buf);
    pthread_mutex_destroy(&w->lock);
    free(w);
    return true;
}

enum wallet_reveal wrv_state(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    enum wallet_reveal state = w->asking ? WALLET_REVEAL_ASKING : (w->open || w->owed) ? WALLET_REVEAL_OPEN : w->result;
    pthread_mutex_unlock(&w->lock);
    return state;
}

/* ---- locking ---- */

/* On the worker: one lock call when one is owed. A payment in flight holds the wallet open under its own unlock and locks
 * it when it ends, so nothing is locked under it and the debt is dropped. A failed call stays owed for the next tick. */
static void lock_job(void *arg)
{
    struct wrv *w = arg;
    pthread_mutex_lock(&w->lock);
    bool owed = w->owed;
    pthread_mutex_unlock(&w->lock);
    bool held = owed && busy(w);
    bool locked = owed && !held && w->d.node.lock(w->d.node.ctx);
    pthread_mutex_lock(&w->lock);
    if (held || locked) w->owed = false;
    w->worker = false;
    pthread_mutex_unlock(&w->lock);
    redraw(w);
}

/* Starts lock_job if a lock is owed and nothing else runs. Called without the lock. */
static void lock_if_owed(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    bool start = w->owed && !w->open && !w->asking && !w->worker;
    if (start) w->worker = true;
    pthread_mutex_unlock(&w->lock);
    if (!start) return;
    if (w->d.host.spawn && w->d.host.spawn(w->d.host.ctx, lock_job, w)) return;
    pthread_mutex_lock(&w->lock);
    w->worker = false;
    pthread_mutex_unlock(&w->lock);
}

/* ---- the prompt ---- */

struct asked { struct wrv *w; unsigned ticket; };

/* Asked once the owner has authenticated, just before the unlock request: the tap must still be the current one and no
 * payment may be in flight. From here the wallet may be open, so a lock is owed. */
static bool still_wanted(void *arg)
{
    struct asked *a = arg;
    struct wrv *w = a->w;
    pthread_mutex_lock(&w->lock);
    bool wanted = w->asking && w->ticket == a->ticket && !busy(w);
    if (wanted) w->owed = true;
    pthread_mutex_unlock(&w->lock);
    return wanted;
}

static enum wallet_reveal failure_of(const struct wrv *w, const struct wss_unlock_result *r)
{
    if (r->key == WSS_KEY_DECLINED) return WALLET_REVEAL_CANCELLED;
    if (r->key == WSS_KEY_NO_SCREEN_LOCK) return WALLET_REVEAL_NO_SCREEN_LOCK;
    if (r->key == WSS_KEY_GONE) return WALLET_REVEAL_KEY_GONE;
    if (r->key == WSS_KEY_OK && !r->sent && busy(w)) return WALLET_REVEAL_SENDING;
    return WALLET_REVEAL_FAILED;
}

static void unlock_job(void *arg)
{
    struct wrv *w = arg;
    pthread_mutex_lock(&w->lock);
    struct asked asked = {w, w->ticket};
    pthread_mutex_unlock(&w->lock);
    struct wss_unlock_result r =
        wss_unlock_node(&w->d.device, &w->d.node, &w->buf, WRV_WINDOW_SECONDS, still_wanted, &asked);
    uint64_t at = now_ms(w);
    pthread_mutex_lock(&w->lock);
    bool current = w->asking && w->ticket == asked.ticket;
    if (current) {
        w->asking = false;
        w->open = r.ok;
        w->deadline_ms = at + (uint64_t)WRV_WINDOW_SECONDS * 1000u;
        w->result = r.ok ? WALLET_REVEAL_NONE : failure_of(w, &r);
    }
    w->worker = false;
    pthread_mutex_unlock(&w->lock);
    redraw(w);
    /* An unlock whose tap was cancelled meanwhile, or that the node did not confirm, leaves the wallet possibly open. */
    lock_if_owed(w);
}

bool wrv_begin(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    bool free_to_ask = !w->asking && !w->open && !w->owed && !w->worker;
    bool sending = free_to_ask && busy(w);
    if (free_to_ask && !sending) {
        w->asking = w->worker = true;
        w->result = WALLET_REVEAL_NONE;
        ++w->ticket;
    }
    if (sending) w->result = WALLET_REVEAL_SENDING;
    pthread_mutex_unlock(&w->lock);
    if (!free_to_ask || sending) {
        if (sending) redraw(w);
        return false;
    }
    if (w->d.host.spawn && w->d.host.spawn(w->d.host.ctx, unlock_job, w)) return true;
    pthread_mutex_lock(&w->lock);
    w->asking = w->worker = false;
    w->result = WALLET_REVEAL_FAILED;
    pthread_mutex_unlock(&w->lock);
    redraw(w);
    return false;
}

void wrv_end(struct wrv *w)
{
    pthread_mutex_lock(&w->lock);
    w->asking = w->open = false;
    w->result = WALLET_REVEAL_NONE;
    ++w->ticket;
    pthread_mutex_unlock(&w->lock);
    lock_if_owed(w);
}

void wrv_tick(struct wrv *w)
{
    uint64_t at = now_ms(w);
    pthread_mutex_lock(&w->lock);
    bool over = w->open && at >= w->deadline_ms;
    if (over) w->open = false;
    pthread_mutex_unlock(&w->lock);
    if (over) redraw(w);
    lock_if_owed(w);
}
