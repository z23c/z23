/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "node_watch.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct watch {
    struct node_watch_ops ops;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    pthread_t thread;
    bool stop;
};

static pthread_mutex_t registry = PTHREAD_MUTEX_INITIALIZER;
static struct watch *current;

/* Waits one interval; false when the watch was stopped meanwhile. */
static bool wait_interval(struct watch *w)
{
    struct timespec until;
    clock_gettime(CLOCK_MONOTONIC, &until);
    until.tv_sec += w->ops.interval_ms / 1000;
    until.tv_nsec += (long)(w->ops.interval_ms % 1000) * 1000000L;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&w->mutex);
    int rc = 0;
    while (!w->stop && rc != ETIMEDOUT) rc = pthread_cond_timedwait(&w->changed, &w->mutex, &until);
    bool running = !w->stop;
    pthread_mutex_unlock(&w->mutex);
    return running;
}
/* True when the node is gone, the watch was not stopped meanwhile, and gone() handled it. */
static bool tick(struct watch *w)
{
    if (w->ops.alive(w->ops.context)) return false;
    pthread_mutex_lock(&w->mutex);
    bool stopped = w->stop;
    pthread_mutex_unlock(&w->mutex);
    return !stopped && w->ops.gone(w->ops.context);
}
static void *watch_thread(void *argument)
{
    struct watch *w = argument;
    while (wait_interval(w)) {
        if (tick(w)) break;
    }
    return NULL;
}
static void stop_locked(void)
{
    struct watch *w = current;
    if (!w) return;
    pthread_mutex_lock(&w->mutex); w->stop = true; pthread_cond_signal(&w->changed); pthread_mutex_unlock(&w->mutex);
    pthread_join(w->thread, NULL);
    pthread_cond_destroy(&w->changed); pthread_mutex_destroy(&w->mutex);
    free(w); current = NULL;
}
static bool init_watch(struct watch *w, const struct node_watch_ops *ops)
{
    pthread_condattr_t attr;
    w->ops = *ops;
    if (pthread_mutex_init(&w->mutex, NULL)) return false;
    if (pthread_condattr_init(&attr)) { pthread_mutex_destroy(&w->mutex); return false; }
    bool ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0 && pthread_cond_init(&w->changed, &attr) == 0;
    pthread_condattr_destroy(&attr);
    if (!ok) pthread_mutex_destroy(&w->mutex);
    return ok;
}
bool zapp_node_watch_start(const struct node_watch_ops *ops)
{
    if (!ops || !ops->alive || !ops->gone || !ops->interval_ms) return false;
    struct watch *w = calloc(1, sizeof(*w));
    if (!w) return false;
    if (!init_watch(w, ops)) { free(w); return false; }
    pthread_mutex_lock(&registry);
    stop_locked();
    bool ok = pthread_create(&w->thread, NULL, watch_thread, w) == 0;
    if (ok) current = w;
    else { pthread_cond_destroy(&w->changed); pthread_mutex_destroy(&w->mutex); free(w); }
    pthread_mutex_unlock(&registry);
    return ok;
}
void zapp_node_watch_stop(void)
{
    pthread_mutex_lock(&registry);
    stop_locked();
    pthread_mutex_unlock(&registry);
}
