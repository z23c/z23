/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Single owner of accepted RPC sockets while they wait for a worker. */

#include "httpserver_queue.h"

#include "platform/time_compat.h"
#include "rpc/httpserver.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#define RPC_HTTP_QUEUE_CAP 64
#define RPC_HTTP_QUEUE_WAIT_MS_DEFAULT 10000

/* Every admitted connection has exactly one owner: listener, this queue,
 * worker, or ws_events after an explicit transfer. The queue surrenders dead
 * and stale entries before claiming saturation, so its depth cannot become a
 * lifetime ratchet behind wedged workers. */
static struct rpc_conn g_client_queue[RPC_HTTP_QUEUE_CAP];
static size_t g_client_queue_head = 0;
static size_t g_client_queue_tail = 0;
static size_t g_client_queue_count = 0;
static pthread_mutex_t g_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_client_queue_cond = PTHREAD_COND_INITIALIZER;
static int g_client_queue_wait_ms = RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
static size_t g_client_queue_peak = 0;
static uint64_t g_client_admitted = 0;
static uint64_t g_client_reclaimed_hangup = 0;
static uint64_t g_client_reclaimed_stale = 0;
static uint64_t g_client_rejected_busy = 0;

static struct rpc_conn queue_pop_locked(void)
{
    struct rpc_conn conn = { .fd = PLATFORM_SOCKET_INVALID, .ssl = NULL,
                             .admitted_us = 0 };
    if (g_client_queue_count > 0) {
        conn = g_client_queue[g_client_queue_head];
        g_client_queue_head =
            (g_client_queue_head + 1) % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count--;
    }
    return conn;
}

static size_t queue_reclaim_locked(int64_t now_us)
{
    struct rpc_conn kept[RPC_HTTP_QUEUE_CAP];
    size_t nkept = 0;
    size_t reclaimed = 0;
    int64_t wait_us = (int64_t)g_client_queue_wait_ms * 1000;

    for (size_t i = 0; i < g_client_queue_count; i++) {
        struct rpc_conn conn =
            g_client_queue[(g_client_queue_head + i) % RPC_HTTP_QUEUE_CAP];
        if (rpc_conn_peer_gone(&conn)) {
            g_client_reclaimed_hangup++;
            rpc_conn_discard(&conn);
            reclaimed++;
            continue;
        }
        if (wait_us > 0 && now_us - conn.admitted_us >= wait_us) {
            g_client_reclaimed_stale++;
            rpc_conn_discard(&conn);
            reclaimed++;
            continue;
        }
        kept[nkept++] = conn;
    }

    if (reclaimed > 0) {
        for (size_t i = 0; i < nkept; i++)
            g_client_queue[i] = kept[i];
        g_client_queue_head = 0;
        g_client_queue_tail = nkept % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count = nkept;
    }
    return reclaimed;
}

bool rpc_http_queue_admit(struct rpc_conn conn)
{
    bool admitted = false;
    size_t reclaimed = 0;

    pthread_mutex_lock(&g_client_queue_mutex);
    if (g_client_queue_count >= RPC_HTTP_QUEUE_CAP)
        reclaimed = queue_reclaim_locked(platform_time_monotonic_us());

    if (g_client_queue_count < RPC_HTTP_QUEUE_CAP) {
        conn.admitted_us = platform_time_monotonic_us();
        g_client_queue[g_client_queue_tail] = conn;
        g_client_queue_tail =
            (g_client_queue_tail + 1) % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count++;
        if (g_client_queue_count > g_client_queue_peak)
            g_client_queue_peak = g_client_queue_count;
        g_client_admitted++;
        admitted = true;
        pthread_cond_signal(&g_client_queue_cond);
    } else {
        g_client_rejected_busy++;
    }
    pthread_mutex_unlock(&g_client_queue_mutex);

    if (reclaimed > 0) {
        fprintf(stderr,  // obs-ok:helper-context-logged
                "RPC server: admission queue was full; reclaimed %zu "
                "abandoned connection(s)\n", reclaimed);
    }
    return admitted;
}

struct rpc_conn rpc_http_queue_take_wait(const _Atomic bool *running)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue_count == 0 && atomic_load(running)) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 2;
        pthread_cond_timedwait(&g_client_queue_cond, &g_client_queue_mutex,
                               &deadline);
    }
    struct rpc_conn conn = queue_pop_locked();
    pthread_mutex_unlock(&g_client_queue_mutex);
    return conn;
}

void rpc_http_queue_wake(void)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    pthread_cond_broadcast(&g_client_queue_cond);
    pthread_mutex_unlock(&g_client_queue_mutex);
}

void rpc_http_queue_drain(void)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue_count > 0) {
        struct rpc_conn conn = queue_pop_locked();
        rpc_conn_discard(&conn);
    }
    g_client_queue_head = 0;
    g_client_queue_tail = 0;
    pthread_mutex_unlock(&g_client_queue_mutex);
}

void rpc_http_queue_start(int wait_ms)
{
    rpc_http_queue_drain();
    pthread_mutex_lock(&g_client_queue_mutex);
    g_client_queue_peak = 0;
    g_client_admitted = 0;
    g_client_reclaimed_hangup = 0;
    g_client_reclaimed_stale = 0;
    g_client_rejected_busy = 0;
    g_client_queue_wait_ms = wait_ms >= 0 ? wait_ms
                                          : RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
    pthread_mutex_unlock(&g_client_queue_mutex);
}

bool rpc_http_test_queue_admit(platform_socket_t fd)
{
    struct rpc_conn conn = { .fd = fd, .ssl = NULL, .admitted_us = 0 };
    return rpc_http_queue_admit(conn);
}

platform_socket_t rpc_http_test_queue_take(void)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    struct rpc_conn conn = queue_pop_locked();
    pthread_mutex_unlock(&g_client_queue_mutex);
    return conn.fd;
}

void rpc_http_test_queue_reset(int wait_ms)
{
    rpc_http_queue_start(wait_ms);
}

void rpc_http_test_queue_stats(struct rpc_http_queue_stats *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_client_queue_mutex);
    out->capacity = RPC_HTTP_QUEUE_CAP;
    out->depth = g_client_queue_count;
    out->peak_depth = g_client_queue_peak;
    out->admitted = g_client_admitted;
    out->reclaimed_hangup = g_client_reclaimed_hangup;
    out->reclaimed_stale = g_client_reclaimed_stale;
    out->rejected_busy = g_client_rejected_busy;
    pthread_mutex_unlock(&g_client_queue_mutex);
}
