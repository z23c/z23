/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Deferred HTTPS start owned by the engine. The engine holds the configured
 * HTTPS and HTTP ports, so the deferred start replays those ports (core's
 * https_deferred_set/check start on the default 8443/8080 and lose them). */

#include "services/https_deferred_start.h"
#include "net/https_server.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define DEFERRED_TAG "https_deferred_start"

static char g_deferred_cert[1024];
static char g_deferred_key[1024];
static char g_deferred_host[256];
static int g_deferred_https_port;
static int g_deferred_http_port;
static _Atomic bool g_deferred_pending = false;

static https_deferred_start_fn g_starter = NULL;

static bool port_in_range(int port)
{
    return port >= 1 && port <= 65535;
}

static struct zcl_result refuse_logged(struct zcl_result refusal)
{
    LOG_ERROR(DEFERRED_TAG, "%s", refusal.message);
    return refusal;
}

static bool start_with_stored_ports(const char *cert, const char *key,
                                    const char *host, int https_port,
                                    int http_port)
{
    if (g_starter)
        return g_starter(cert, key, host, https_port, http_port);
    return https_server_start_on_port(cert, key, host, https_port, http_port);
}

struct zcl_result https_deferred_start_set(const char *cert_path,
                                           const char *key_path,
                                           const char *hostname,
                                           int https_port, int http_port)
{
    if (!cert_path || !key_path)
        return refuse_logged(ZCL_ERR(-1, "deferred HTTPS start refused: "
                                     "cert_path and key_path must be set"));
    if (!port_in_range(https_port) || !port_in_range(http_port))
        return refuse_logged(ZCL_ERR(-1, "deferred HTTPS start refused: "
                                     "https_port and http_port must be in "
                                     "1..65535 (https=%d http=%d)",
                                     https_port, http_port));
    if (strlen(cert_path) >= sizeof(g_deferred_cert) ||
        strlen(key_path) >= sizeof(g_deferred_key) ||
        (hostname && strlen(hostname) >= sizeof(g_deferred_host)))
        return refuse_logged(ZCL_ERR(-1, "deferred HTTPS start refused: "
                                     "cert and key paths must be under %zu "
                                     "bytes and the hostname under %zu",
                                     sizeof(g_deferred_cert),
                                     sizeof(g_deferred_host)));
    snprintf(g_deferred_cert, sizeof(g_deferred_cert), "%s", cert_path);
    snprintf(g_deferred_key, sizeof(g_deferred_key), "%s", key_path);
    snprintf(g_deferred_host, sizeof(g_deferred_host), "%s",
             hostname ? hostname : "");
    g_deferred_https_port = https_port;
    g_deferred_http_port = http_port;
    atomic_store(&g_deferred_pending, true);
    printf("HTTPS: deferred start queued (will start when synced)\n");
    return ZCL_OK;
}

struct zcl_result https_deferred_start_pending(bool *pending)
{
    if (!pending)
        return ZCL_ERR(-1, "deferred HTTPS start pending query needs a "
                       "non-NULL out pointer");
    *pending = atomic_load(&g_deferred_pending);
    return ZCL_OK;
}

void https_deferred_start_check(void)
{
    if (!atomic_load(&g_deferred_pending) || https_server_is_running())
        return;
    atomic_store(&g_deferred_pending, false);
    printf("HTTPS: starting deferred server (node synced)\n");
    if (!start_with_stored_ports(g_deferred_cert, g_deferred_key,
                                 g_deferred_host[0] ? g_deferred_host : NULL,
                                 g_deferred_https_port,
                                 g_deferred_http_port)) {
        LOG_ERROR(DEFERRED_TAG, "deferred HTTPS start failed on port %d",
                  g_deferred_https_port);
    }
}

#ifdef ZCL_TESTING
void https_deferred_start_set_starter_for_testing(https_deferred_start_fn fn)
{
    g_starter = fn;
}
#endif
