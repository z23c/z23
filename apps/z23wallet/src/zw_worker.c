/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the read worker. It owns the socket, cookie and auth header; the
 * UI enqueues coalesced jobs and drains results after a window wake. The
 * worker never touches UI state and never sleeps on its own schedule. It
 * publishes its phase (locate/connect/send/recv) for the UI's watchdog. */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "zw.h"

#define RESULT_CAP 64

struct zw_worker {
    pthread_t thread;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct gui_window *win;
    struct zw_rpc *rpc;
    uint32_t pending; /* bitmask of queries */
    uint32_t gens[ZW_Q_COUNT];
    struct zw_result *ring;
    size_t head, count;
    struct zw_cancel *cancel;
    atomic_int port;
    bool stop, busy, started, reset_auth;
};

static void push_result(struct zw_worker *w, struct zw_result *r)
{
    if (w->count == RESULT_CAP) { /* drop the oldest; the model only needs fresh data */
        zw_result_release(&w->ring[w->head]);
        w->head = (w->head + 1) % RESULT_CAP;
        w->count--;
    }
    w->ring[(w->head + w->count) % RESULT_CAP] = *r;
    r->bal = NULL; /* ownership moved into the ring */
    w->count++;
}

static enum zw_query next_job(struct zw_worker *w)
{
    enum zw_query q = ZW_Q_CHAIN;
    while (!(w->pending & (1u << q))) q++;
    w->pending &= ~(1u << q);
    return q;
}

static void *worker_main(void *arg)
{
    struct zw_worker *w = arg;
    struct zw_result *res = zcl_malloc(sizeof(*res), "zw_result");
    if (!res) {
        zw_log("read worker: out of memory; no node data will arrive");
        return NULL;
    }
    pthread_mutex_lock(&w->mu);
    for (;;) {
        while (!w->stop && !w->pending) pthread_cond_wait(&w->cv, &w->mu);
        if (w->stop) break;
        enum zw_query q = next_job(w);
        uint32_t gen = w->gens[q];
        w->busy = true;
        if (w->reset_auth) { /* applied here, by the only thread that touches rpc */
            w->rpc->ep.valid = false;
            w->rpc->z23_refused = false;
            w->reset_auth = false;
        }
        pthread_mutex_unlock(&w->mu);
        memset(res, 0, sizeof(*res));
        res->generation = gen;
        (void)zw_query_run(w->rpc, q, res);
        atomic_store(&w->port, (int)w->rpc->ep.port);
        pthread_mutex_lock(&w->mu);
        push_result(w, res);
        w->busy = false;
        pthread_mutex_unlock(&w->mu);
        gui_window_wake(w->win);
        pthread_mutex_lock(&w->mu);
    }
    pthread_mutex_unlock(&w->mu);
    free(res);
    return NULL;
}

struct zw_worker *zw_worker_start(struct gui_window *win, const struct zw_options *o)
{
    struct zw_worker *w = zcl_calloc(1, sizeof(*w), "zw_worker");
    if (!w) return NULL;
    w->ring = zcl_calloc(RESULT_CAP, sizeof(*w->ring), "zw_results");
    w->rpc = zcl_calloc(1, sizeof(*w->rpc), "zw_rpc");
    if (!w->ring || !w->rpc) goto fail;
    w->cancel = zw_cancel_new();
    if (!w->cancel) goto fail;
    w->rpc->opt = o;
    w->rpc->cancel = w->cancel;
    w->win = win;
    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
    if (pthread_create(&w->thread, NULL, worker_main, w) != 0) {
        zw_log("cannot start the read worker thread");
        goto fail;
    }
    w->started = true;
    return w;
fail:
    zw_cancel_free(w->cancel);
    free(w->ring);
    free(w->rpc);
    free(w);
    return NULL;
}

bool zw_worker_enqueue(struct zw_worker *w, enum zw_query q, uint32_t generation)
{
    pthread_mutex_lock(&w->mu);
    bool coalesced = (w->pending & (1u << q)) != 0;
    w->pending |= 1u << q;
    w->gens[q] = generation;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);
    return !coalesced;
}

size_t zw_worker_drain(struct zw_worker *w, struct zw_result *out, size_t cap)
{
    pthread_mutex_lock(&w->mu);
    size_t n = w->count < cap ? w->count : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = w->ring[(w->head + i) % RESULT_CAP];
        w->ring[(w->head + i) % RESULT_CAP].bal = NULL;
    }
    w->head = (w->head + n) % RESULT_CAP;
    w->count -= n;
    pthread_mutex_unlock(&w->mu);
    return n;
}

bool zw_worker_busy(struct zw_worker *w)
{
    pthread_mutex_lock(&w->mu);
    bool b = w->busy || w->pending || w->count;
    pthread_mutex_unlock(&w->mu);
    return b;
}

int zw_worker_phase(struct zw_worker *w) { return atomic_load(&w->rpc->phase); }

uint16_t zw_worker_port(struct zw_worker *w) { return (uint16_t)atomic_load(&w->port); }

void zw_watchdog_line(int phase, uint16_t port, char *buf, size_t cap)
{
    snprintf(buf, cap, "worker: no reply after 6 s (phase=%s, 127.0.0.1:%u)", zw_phase_name(phase),
             (unsigned)port);
}

void zw_worker_reset_auth(struct zw_worker *w)
{
    pthread_mutex_lock(&w->mu);
    w->reset_auth = true; /* the next job locates and re-reads the credentials */
    pthread_mutex_unlock(&w->mu);
}

void zw_worker_stop(struct zw_worker *w)
{
    if (!w) return;
    pthread_mutex_lock(&w->mu);
    w->stop = true;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
    /* A request in flight is aborted by shutting its socket down, so the join below
     * is bounded by one loopback connect, not by the node. Only after the join may
     * the caller free the window the worker wakes. */
    zw_cancel_fire(w->cancel);
    pthread_join(w->thread, NULL);
    for (size_t i = 0; i < w->count; i++) zw_result_release(&w->ring[(w->head + i) % RESULT_CAP]);
    zw_endpoint_wipe(&w->rpc->ep);
    zw_cancel_free(w->cancel);
    free(w->ring);
    free(w->rpc);
    free(w);
}
