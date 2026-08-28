/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Defer HTTPS activation until initial block download completes. */

#include "net/https_server.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static char g_deferred_cert[1024];
static char g_deferred_key[1024];
static char g_deferred_host[256];
static _Atomic bool g_deferred_pending = false;

void https_deferred_set(const char *cert, const char *key, const char *hostname)
{
    strncpy(g_deferred_cert, cert, sizeof(g_deferred_cert) - 1);
    g_deferred_cert[sizeof(g_deferred_cert) - 1] = '\0';
    strncpy(g_deferred_key, key, sizeof(g_deferred_key) - 1);
    g_deferred_key[sizeof(g_deferred_key) - 1] = '\0';
    if (hostname && hostname[0])
        snprintf(g_deferred_host, sizeof(g_deferred_host), "%s", hostname);
    else
        g_deferred_host[0] = '\0';
    atomic_store(&g_deferred_pending, true);
    printf("HTTPS: deferred start queued (will start when synced)\n");
}

bool https_deferred_pending(void)
{
    return atomic_load(&g_deferred_pending);
}

void https_deferred_check(void)
{
    if (atomic_load(&g_deferred_pending) && !https_server_is_running()) {
        atomic_store(&g_deferred_pending, false);
        printf("HTTPS: starting deferred server (node synced)\n");
        https_server_start(g_deferred_cert, g_deferred_key,
                           g_deferred_host[0] ? g_deferred_host : NULL);
    }
}
