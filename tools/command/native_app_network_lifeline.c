/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Stop one private worker when its owner dies or its deadline expires. */
#include "command/native_app_network_lifeline.h"
#if !defined(_WIN32)
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/thread_registry.h"
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
static void *an_lifeline_watch(void *context)
{
    struct app_network_lifeline *g = context;
    while (!atomic_load_explicit(&g->stop, memory_order_acquire)) {
        int64_t now = platform_time_monotonic_ms();
        if ((uint64_t)getppid() != g->parent || now <= 0 || now < g->last || now >= g->deadline) _exit(124);
        g->last = now;
        platform_sleep_ms(25); /* real-clock: bounded worker lifeline poll */
    }
    return NULL;
}
static bool an_lifeline_start(struct app_network_lifeline *g, uint64_t parent, unsigned timeout_ms, unsigned cap_ms)
{
    if (!g || parent <= 1 || !timeout_ms || timeout_ms > cap_ms) return false;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || now > INT64_MAX - (int64_t)timeout_ms ||
        !os_proc_bind_parent_death(SIGKILL, parent)) return false;
    g->parent = parent; g->deadline = now + (int64_t)timeout_ms; g->last = now; atomic_init(&g->stop, false);
    return thread_registry_spawn("app-network-lifeline", an_lifeline_watch, g, &g->thread) == 0;
}
bool app_network_lifeline_start(struct app_network_lifeline *g, uint64_t parent, unsigned timeout_ms)
{ return an_lifeline_start(g, parent, timeout_ms, 135000u); }
bool app_host_lifeline_start(struct app_network_lifeline *g, uint64_t parent, unsigned timeout_ms)
{ return an_lifeline_start(g, parent, timeout_ms, 86405000u); }
bool app_network_lifeline_stop(struct app_network_lifeline *g)
{
    if (!g) return false;
    atomic_store_explicit(&g->stop, true, memory_order_release);
    int rc; do { rc = pthread_join(g->thread, NULL); } while (rc == EINTR);
    return rc == 0;
}
#else
typedef int app_network_lifeline_unavailable;
#endif
