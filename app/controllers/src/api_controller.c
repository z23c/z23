/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * REST API controller — fast JSON API for the block explorer.
 * Serves /api routes. All RPC calls happen in a background thread;
 * HTTPS handler threads only serve from cache (api_rpc_call crashes
 * when called from HTTPS handler threads). */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "rpc/zclassicd_port.h" /* ZCLASSICD_RPC_DEFAULT_PORT */
#include "controllers/api_controller.h"
#include "controllers/explorer_internal.h"
#include "encoding/utilstrencodings.h"
#include "controllers/file_controller.h"
#include "net/snapshot_sync_contract.h"
#include "services/zslp_service.h"
#include "controllers/blockchain_controller.h"
#include "controllers/game_controller.h"
#include "controllers/name_controller.h"
#include "controllers/file_market_controller.h"
#include "controllers/swap_controller.h"
#include "controllers/messaging_controller.h"
#include "controllers/health_controller.h"
#include "services/node_health_service.h"
#include "chain/mmb.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "views/format_helpers.h"
#include "views/explorer_factoids_view.h"
#include "event/event.h"
#include "net/download.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "sapling/incremental_merkle_tree.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/block.h"
#include "models/file_service.h"
#include "models/hodl_wave.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "models/zslp.h"
#include "json/json.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <sqlite3.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "api_controller_internal.h"

/* ── State ────────────────────────────────────────────────── */

/* struct api_context defined in api_controller_internal.h */

/* struct api_rpc_backend defined in api_controller_internal.h */

struct api_context g_api_ctx = {0};
/* Credentials start absent: boot fills them from the node's .cookie or
 * rpcuser/rpcpassword config, and api_rpc_call refuses to fire when
 * they are still absent — no invented fallback pair. */
struct api_rpc_backend g_api_rpc = {
    .port = ZCLASSICD_RPC_DEFAULT_PORT,
};
pthread_mutex_t g_api_worker_generation_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef ZCL_TESTING
static api_test_rpc_call_fn g_api_test_rpc_call;

void api_test_set_rpc_call(api_test_rpc_call_fn fn)
{
    g_api_test_rpc_call = fn;
}
#endif

/* ── Background cache ─────────────────────────────────────── */

#define API_BLOCKS_CACHE_SIZE 131072   /* 128KB */
#define API_STATS_CACHE_SIZE  16384    /* 16KB  */
#define API_SUPPLY_CACHE_SIZE 4096     /* 4KB   */
#define API_HODL_CACHE_SIZE   8192     /* 8KB   */

static char   g_api_blocks_cache[API_BLOCKS_CACHE_SIZE];
static size_t g_api_blocks_cache_len = 0;

static char   g_api_stats_cache[API_STATS_CACHE_SIZE];
static size_t g_api_stats_cache_len = 0;

static char   g_api_supply_cache[API_SUPPLY_CACHE_SIZE];
static size_t g_api_supply_cache_len = 0;
static char   g_api_supply_legacy_cache[API_SUPPLY_CACHE_SIZE];
static size_t g_api_supply_legacy_cache_len = 0;

static char   g_api_hodl_cache[API_HODL_CACHE_SIZE];
static size_t g_api_hodl_cache_len = 0;
static int64_t g_api_hodl_cache_height = -1;

#define API_DEEP_STATS_CACHE_SIZE 65536  /* 64KB */
static char   g_api_deep_stats_cache[API_DEEP_STATS_CACHE_SIZE];
static size_t g_api_deep_stats_cache_len = 0;

_Atomic int g_api_cache_thread_running = 0;
static bool g_api_cache_thread_active = false;
static pthread_mutex_t g_api_cache_lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_api_cache_lifecycle_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_api_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* #13: the cache-refresh thread's supervisor liveness contract lives in
 * api_controller_cache_liveness.c (split out for E1 file-size ceiling) —
 * api_cache_register_supervisor / api_cache_supervisor_tick /
 * api_cache_supervisor_quiesce declared in api_controller_internal.h. */

static bool api_response_cacheable(const uint8_t *buf, size_t len);
static int64_t api_response_height(const uint8_t *buf, size_t len);

void api_set_state(struct main_state *ms, struct tx_mempool *mp,
                    struct coins_view_cache *coins_tip,
                    struct node_db *ndb, const char *datadir)
{
    g_api_ctx.main_state = ms;
    g_api_ctx.mempool = mp;
    g_api_ctx.coins_tip = coins_tip;
    g_api_ctx.node_db = ndb;
    g_api_ctx.datadir = datadir;
}

void api_set_rpc_backend(const char *rpc_user, const char *rpc_pass,
                          int rpc_port)
{
    if (rpc_user)
        snprintf(g_api_rpc.user, sizeof(g_api_rpc.user), "%s", rpc_user);
    if (rpc_pass)
        snprintf(g_api_rpc.pass, sizeof(g_api_rpc.pass), "%s", rpc_pass);
    if (rpc_port > 0)
        g_api_rpc.port = rpc_port;
}

/* ── RPC call to local zclassicd ─────────────────────────── */
/* ONLY called from the background cache thread, never from
 * HTTPS handler threads (socket ops crash in that context). */

int api_rpc_call(const char *method, const char *params_json,
                     char *out, size_t outmax)
{
#ifdef ZCL_TESTING
    if (g_api_test_rpc_call)
        return g_api_test_rpc_call(method, params_json, out, outmax);
#endif

    /* Credentials absent (no .cookie, no conf pair at boot): send
     * nothing rather than guessable basic-auth. */
    if (!g_api_rpc.user[0] || !g_api_rpc.pass[0])
        LOG_ERR("api",
                "api_rpc_call(%s): no node credentials configured; "
                "not dialing", method);

    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("api", "api_rpc_call(%s): socket() failed", method);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)g_api_rpc.port);

    (void)platform_socket_set_receive_timeout(fd, 10000);
    (void)platform_socket_set_send_timeout(fd, 10000);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        platform_socket_close(fd);
        LOG_ERR("api", "api_rpc_call(%s): connect to port %d failed", method, g_api_rpc.port);
    }

    char body[4096];
    int blen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);

    /* Base64 encode auth: the shared encoder in encoding/utilstrencodings.h
     * uses the same alphabet and '=' padding this call site used to inline. */
    char auth_plain[256];
    snprintf(auth_plain, sizeof(auth_plain), "%s:%s",
             g_api_rpc.user, g_api_rpc.pass);
    char auth_b64[512];
    EncodeBase64((const unsigned char *)auth_plain, strlen(auth_plain),
                 auth_b64, sizeof(auth_b64));

    char req[8192];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        auth_b64, blen, body);

    if (rlen <= 0 || (size_t)rlen >= sizeof(req) ||
        !platform_socket_send_all(fd, req, (size_t)rlen)) {
        platform_socket_close(fd);
        LOG_ERR("api", "api_rpc_call(%s): write failed (len=%d)", method,
                rlen);
    }

    size_t total = 0;
    while (total < outmax - 1) {
        int r = platform_socket_receive(fd, out + total,
                                        outmax - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    out[total] = '\0';
    platform_socket_close(fd);

    /* Skip HTTP headers */
    char *body_start = strstr(out, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        size_t body_len = total - (size_t)(body_start - out);
        memmove(out, body_start, body_len);
        out[body_len] = '\0';
        return (int)body_len;
    }
    return (int)total;
}

/* JSON extraction and validation: delegated to shared format_helpers.
 * Call sites use zcl_json_int/zcl_json_real (return-value wrappers with the
 * -1 int / 0.0 real defaults) and zcl_json_extract_str directly. */

/* Validate address/param is safe to embed in JSON (alphanumeric only).
 * Prevents JSON injection via crafted params. */
bool api_is_json_safe_param(const char *s, size_t maxlen)
{
    if (!s || !*s) return false;
    for (size_t i = 0; s[i] && i < maxlen; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c)) return false;
    }
    return true;
}

/* ── HTTP response helpers ───────────────────────────────── */

/* SECURITY_HEADERS + JSON_*_HEADERS macros live in
 * api_controller_internal.h so all api_controller_*.c siblings
 * share a single source of truth. */

static size_t cors_preflight(uint8_t *r, size_t max)
{
    return (size_t)snprintf((char *)r, max,
        "HTTP/1.1 204 No Content\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Access-Control-Max-Age: 86400\r\n"
        "Connection: close\r\n\r\n");
}

size_t api_json_error(uint8_t *r, size_t max, const char *headers,
                          const char *message)
{
    if (!r || max == 0)
        return 0;

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", ZCL_REST_ERROR_SCHEMA);
    json_push_kv_str(&body, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(&body, "error", message ? message : "error");

    const char *h = headers ? headers : "";
    size_t hlen = strlen(h);

    if (hlen >= max) {
        memcpy(r, h, max - 1);
        r[max - 1] = '\0';
        json_free(&body);
        return max - 1;
    }

    memcpy(r, h, hlen);
    size_t avail = max - hlen;
    size_t need = json_write(&body, (char *)r + hlen, avail);
    json_free(&body);
    size_t actual_blen = need < avail ? need : (avail ? avail - 1 : 0);
    return hlen + actual_blen;
}

size_t api_json_status(uint8_t *r, size_t max, const char *status,
                       const struct json_value *body)
{
    if (!r || max == 0 || !body)
        return 0;

    size_t blen = json_write(body, NULL, 0);
    char headers[256];
    int hn = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n\r\n",
        status ? status : "200 OK", blen);
    if (hn < 0 || (size_t)hn >= sizeof(headers))
        return 0;

    size_t hlen = (size_t)hn;
    if (blen > SIZE_MAX - hlen || hlen + blen > max) {
        LOG_WARN("api", "api_json_ok: response too large body=%zu max=%zu",
                 blen, max);
        return api_json_error(r, max, JSON_500_HEADERS,
                              "Response too large");
    }

    memcpy(r, headers, hlen);
    json_write(body, (char *)r + hlen, max - hlen);
    return hlen + blen;
}

size_t api_json_ok(uint8_t *r, size_t max, const struct json_value *body)
{
    return api_json_status(r, max, "200 OK", body);
}

/* ── Compute functions (called ONLY from background thread) ── */

static void *api_cache_refresh_thread(void *arg)
{
    (void)arg;

    /* Wait for RPC server to start, but let shutdown/test isolation interrupt
     * the startup delay instead of retaining borrowed state for five seconds. */
    for (int s = 0; s < 5 && g_api_cache_thread_running; s++)
        sleep(1);

    printf("API cache: background refresh thread started\n");
    fflush(stdout);

    int iteration = 0;
    while (g_api_cache_thread_running) {
        api_cache_supervisor_tick();

        /* Refresh /api/blocks every 30 seconds */
        if (iteration % 3 == 0) {
            uint8_t *tmp = zcl_malloc(API_BLOCKS_CACHE_SIZE, "api_blocks_tmp");
            if (tmp) {
                size_t len = compute_blocks(tmp, API_BLOCKS_CACHE_SIZE);
                if (len > 0 && len < API_BLOCKS_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_blocks_cache, tmp, len);
                    g_api_blocks_cache_len = len;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
        }

        /* Refresh /api/stats every 60 seconds */
        if (iteration % 6 == 0) {
            uint8_t *tmp = zcl_malloc(API_STATS_CACHE_SIZE, "api_stats_tmp");
            if (tmp) {
                size_t len = compute_stats(tmp, API_STATS_CACHE_SIZE);
                if (len > 0 && len < API_STATS_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_stats_cache, tmp, len);
                    g_api_stats_cache_len = len;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
        }

        /* Refresh /api/supply every 60 seconds */
        if (iteration % 6 == 0) {
            uint8_t *tmp = zcl_malloc(API_SUPPLY_CACHE_SIZE, "api_supply_tmp");
            if (tmp) {
                size_t len = compute_supply(tmp, API_SUPPLY_CACHE_SIZE);
                if (len > 0 && len < API_SUPPLY_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_supply_cache, tmp, len);
                    g_api_supply_cache_len = len;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
            tmp = zcl_malloc(API_SUPPLY_CACHE_SIZE, "api_supply_legacy_tmp");
            if (tmp) {
                size_t len = compute_supply_legacy(tmp, API_SUPPLY_CACHE_SIZE);
                if (len > 0 && len < API_SUPPLY_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_supply_legacy_cache, tmp, len);
                    g_api_supply_legacy_cache_len = len;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
        }

        /* Refresh /api/hodl every 60 seconds */
        if (iteration % 6 == 0) {
            uint8_t *tmp = zcl_malloc(API_HODL_CACHE_SIZE, "api_hodl_tmp");
            if (tmp) {
                size_t len = compute_hodl_cache_refresh(
                    tmp, API_HODL_CACHE_SIZE);
                if (len > 0 && len < API_HODL_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    int64_t height = api_response_height(tmp, len);
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_hodl_cache, tmp, len);
                    g_api_hodl_cache_len = len;
                    g_api_hodl_cache_height = height;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
        }

        /* Refresh /api/stats/deep every 300 seconds (30 iterations) */
        if (iteration % 30 == 0) {
            uint8_t *tmp = zcl_malloc(API_DEEP_STATS_CACHE_SIZE, "api_deep_stats_tmp");
            if (tmp) {
                size_t len = compute_deep_stats_cache_refresh(
                    tmp, API_DEEP_STATS_CACHE_SIZE);
                if (len > 0 && len < API_DEEP_STATS_CACHE_SIZE &&
                    api_response_cacheable(tmp, len)) {
                    pthread_mutex_lock(&g_api_cache_mutex);
                    memcpy(g_api_deep_stats_cache, tmp, len);
                    g_api_deep_stats_cache_len = len;
                    pthread_mutex_unlock(&g_api_cache_mutex);
                }
                free(tmp);
            }
        }

        if (iteration == 0)
            printf("API cache: initial refresh complete (blocks=%zu stats=%zu supply=%zu hodl=%zu)\n",
                   g_api_blocks_cache_len, g_api_stats_cache_len,
                   g_api_supply_cache_len, g_api_hodl_cache_len);

        iteration++;
        /* Sleep 10 seconds between iterations; blocks refresh every 3rd (30s),
         * stats/supply/hodl every 6th (60s) */
        for (int s = 0; s < 10 && g_api_cache_thread_running; s++)
            sleep(1);
    }

    printf("API cache: background refresh thread stopped\n");
    fflush(stdout);
    pthread_mutex_lock(&g_api_cache_lifecycle_mutex);
    g_api_cache_thread_active = false;
    pthread_cond_broadcast(&g_api_cache_lifecycle_cond);
    pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
    return NULL;
}

bool api_start_detached_thread(pthread_t *thread_out,
                               void *(*entry)(void *),
                               void *arg)
{
    pthread_attr_t attr;
    bool ok = false;

    if (!thread_out || !entry)
        LOG_FAIL("api", "start_detached_thread: NULL thread_out or entry");
    if (pthread_attr_init(&attr) != 0)
        LOG_FAIL("api", "start_detached_thread: pthread_attr_init failed");
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
        goto cleanup;
    if (pthread_attr_setstacksize(&attr, 2 * 1024 * 1024) != 0)
        goto cleanup;
    /* raw-pthread-ok: detached-helper-wrapper (custom stack via pthread_attr) */
    if (pthread_create(thread_out, &attr, entry, arg) != 0)
        goto cleanup;
    ok = true;

cleanup:
    pthread_attr_destroy(&attr);
    return ok;
}

static bool ensure_cache_thread(void)
{
    pthread_t t;

    pthread_mutex_lock(&g_api_worker_generation_mutex);
    pthread_mutex_lock(&g_api_cache_lifecycle_mutex);
    if (g_api_cache_thread_active) {
        pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
        pthread_mutex_unlock(&g_api_worker_generation_mutex);
        return true;
    }
    atomic_store(&g_api_cache_thread_running, 1);
    g_api_cache_thread_active = true;
    api_cache_register_supervisor();
    if (!api_start_detached_thread(&t, api_cache_refresh_thread, NULL)) {
        atomic_store(&g_api_cache_thread_running, 0);
        g_api_cache_thread_active = false;
        pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
        pthread_mutex_unlock(&g_api_worker_generation_mutex);
        LOG_FAIL("api", "ensure_cache_thread: failed to start cache refresh thread");
    }
    pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
    pthread_mutex_unlock(&g_api_worker_generation_mutex);
    return true;
}

static bool api_response_cacheable(const uint8_t *buf, size_t len)
{
    if (!buf || len == 0)
        return false;
    const char *s = (const char *)buf;
    if (strstr(s, "HTTP/1.1 200 OK") != s)
        return false;
    if (strstr(s, "{\"error\":") || strstr(s, "\"error\":\""))
        return false;
    return true;
}

static int64_t api_response_height(const uint8_t *buf, size_t len)
{
    if (!buf || len == 0)
        LOG_RETURN(-1, "api", "api_response_height: empty response");
    return zcl_json_int((const char *)buf, "height");
}

void api_start_cache(void)
{
    if (!ensure_cache_thread())
        LOG_WARN("controller", "API cache: failed to start background thread");
}

void api_stop_cache(void)
{
    pthread_mutex_lock(&g_api_worker_generation_mutex);
    api_cache_supervisor_quiesce();
    pthread_mutex_lock(&g_api_cache_lifecycle_mutex);
    atomic_store(&g_api_cache_thread_running, 0);
    while (g_api_cache_thread_active)
        pthread_cond_wait(&g_api_cache_lifecycle_cond,
                          &g_api_cache_lifecycle_mutex);
    pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
    api_lookup_stop();
    pthread_mutex_unlock(&g_api_worker_generation_mutex);
}

#ifdef ZCL_TESTING
bool api_test_stop_background_workers(void)
{
    api_stop_cache();
    pthread_mutex_lock(&g_api_cache_lifecycle_mutex);
    bool cache_stopped = !g_api_cache_thread_active;
    pthread_mutex_unlock(&g_api_cache_lifecycle_mutex);
    return cache_stopped && !api_lookup_test_worker_alive();
}
#endif

/* ── Serve from cache helpers ────────────────────────────── */

/* `cache_len` is read under g_api_cache_mutex in the same hold as the
 * memcpy — the refresh thread updates buffer+len together under the
 * mutex, so a by-value len read outside the lock can be stale (a
 * larger old len against a newer shorter buffer serves garbage). */
static size_t serve_from_cache(const char *cache, const size_t *cache_len,
                                uint8_t *r, size_t max)
{
    pthread_mutex_lock(&g_api_cache_mutex);
    size_t len = *cache_len;
    if (len == 0) {
        pthread_mutex_unlock(&g_api_cache_mutex);
        return api_json_error(r, max, JSON_503_HEADERS,
                          "Cached data unavailable");
    }
    size_t copy = len < max ? len : max;
    memcpy(r, cache, copy);
    pthread_mutex_unlock(&g_api_cache_mutex);
    return copy;
}

static size_t serve_hodl_fresh(uint8_t *r, size_t max)
{
    int64_t current_height = api_hodl_current_tip_height();

    pthread_mutex_lock(&g_api_cache_mutex);
    size_t len = g_api_hodl_cache_len;
    int64_t cache_height = g_api_hodl_cache_height;
    if (len > 0 && (current_height < 0 || cache_height >= current_height)) {
        size_t copy = len < max ? len : max;
        memcpy(r, g_api_hodl_cache, copy);
        pthread_mutex_unlock(&g_api_cache_mutex);
        return copy;
    }
    pthread_mutex_unlock(&g_api_cache_mutex);

    uint8_t *tmp = zcl_malloc(API_HODL_CACHE_SIZE, "api_hodl_fresh_tmp");
    if (!tmp)
        return api_json_error(r, max, JSON_500_HEADERS, "Out of memory");

    len = compute_hodl(tmp, API_HODL_CACHE_SIZE);
    if (len > 0 && len < API_HODL_CACHE_SIZE &&
        api_response_cacheable(tmp, len)) {
        int64_t height = api_response_height(tmp, len);
        pthread_mutex_lock(&g_api_cache_mutex);
        memcpy(g_api_hodl_cache, tmp, len);
        g_api_hodl_cache_len = len;
        g_api_hodl_cache_height = height;
        pthread_mutex_unlock(&g_api_cache_mutex);

        size_t copy = len < max ? len : max;
        memcpy(r, tmp, copy);
        free(tmp);
        return copy;
    }

    free(tmp);
    return api_json_error(r, max, JSON_503_HEADERS,
                          "HODL data unavailable");
}

bool api_route_is_operator_private(const char *path)
{
    return api_route_registry_is_private(path);
}

size_t api_route_blocks(uint8_t *response, size_t response_max)
{
    return serve_from_cache(g_api_blocks_cache, &g_api_blocks_cache_len,
                            response, response_max);
}

size_t api_route_stats(uint8_t *response, size_t response_max)
{
    return serve_from_cache(g_api_stats_cache, &g_api_stats_cache_len,
                            response, response_max);
}

size_t api_route_deep_stats(uint8_t *response, size_t response_max)
{
    return serve_from_cache(g_api_deep_stats_cache, &g_api_deep_stats_cache_len,
                            response, response_max);
}

size_t api_route_supply(uint8_t *response, size_t response_max)
{
    return serve_from_cache(g_api_supply_cache, &g_api_supply_cache_len,
                            response, response_max);
}

size_t api_route_supply_legacy(uint8_t *response, size_t response_max)
{
    return serve_from_cache(g_api_supply_legacy_cache,
                            &g_api_supply_legacy_cache_len,
                            response, response_max);
}

#ifdef ZCL_TESTING
void api_test_seed_supply_caches(const char *canonical,
                                 const char *legacy)
{
    pthread_mutex_lock(&g_api_cache_mutex);

    g_api_supply_cache_len = 0;
    if (canonical) {
        size_t len = strlen(canonical);
        if (len < sizeof(g_api_supply_cache)) {
            memcpy(g_api_supply_cache, canonical, len);
            g_api_supply_cache_len = len;
        }
    }

    g_api_supply_legacy_cache_len = 0;
    if (legacy) {
        size_t len = strlen(legacy);
        if (len < sizeof(g_api_supply_legacy_cache)) {
            memcpy(g_api_supply_legacy_cache, legacy, len);
            g_api_supply_legacy_cache_len = len;
        }
    }

    pthread_mutex_unlock(&g_api_cache_mutex);
}
#endif

size_t api_route_hodl(uint8_t *response, size_t response_max)
{
    return serve_hodl_fresh(response, response_max);
}

size_t api_route_factoids(uint8_t *response, size_t response_max)
{
    if (!g_api_ctx.datadir)
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "No datadir");
    int64_t served_tip = api_hodl_current_tip_height();
    return explorer_factoids_build_json_for_served_tip(
        response, response_max, g_api_ctx.datadir, served_tip);
}

/* ── Main router ─────────────────────────────────────────── */
/* IMPORTANT: This function is called from HTTPS handler threads.
 * It must NEVER call api_rpc_call directly. All data comes from
 * background caches or the lookup thread.
 *
 * SECURITY INVARIANT: this router never sees HTTP headers or peer
 * identity, so it cannot authenticate anyone. ANY transport that
 * forwards /api traffic here (the clearnet TLS listener, any future
 * ingress) MUST apply the operator-private gate
 * (api_route_is_operator_private) listener-side BEFORE dispatching.
 * The onion service exposes no /api; wallet_gui calls in-process and
 * is trusted. */

size_t api_handle_request(const char *method, const char *path,
                           const uint8_t *body, size_t body_len,
                           uint8_t *response, size_t response_max)
{
    (void)body; (void)body_len;
    if (!method || !path || !response || response_max == 0) return 0;

    /* Start background cache thread on first request */
    if (!ensure_cache_thread()) {
        return api_json_error(response, response_max, JSON_503_HEADERS,
                          "API cache unavailable");
    }

    /* Handle CORS preflight */
    if (strcmp(method, "OPTIONS") == 0)
        return cors_preflight(response, response_max);

    /* Only GET requests */
    if (strcmp(method, "GET") != 0)
        return api_json_error(response, response_max,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n",
            "Method not allowed");

    /* Strip trailing slash */
    char clean_path[512];
    snprintf(clean_path, sizeof(clean_path), "%s", path);
    size_t plen = strlen(clean_path);
    if (plen > 1 && clean_path[plen - 1] == '/')
        clean_path[plen - 1] = '\0';

    char route_path_buf[512];
    char requested_version[32];
    if (api_path_has_unsupported_version(clean_path, requested_version,
                                         sizeof(requested_version)))
        return api_serve_unsupported_version(requested_version, response,
                                             response_max);

    /* Compatibility exception: legacy /api/supply is a raw numeric feed used
     * by old callers, while /api/v1/supply is the canonical REST resource. */
    if (strcmp(clean_path, "/api/supply") == 0)
        return api_route_supply_legacy(response, response_max);

    const char *route_path =
        api_canonical_route_path(clean_path, route_path_buf,
                                 sizeof(route_path_buf));

    const struct api_resource_route *route =
        api_resource_route_find(method, route_path);
    if (route)
        return route->handler(response, response_max);

    bool handled = false;
    size_t dynamic = api_resource_route_dispatch_dynamic(
        method, route_path, response, response_max, &handled);
    if (handled)
        return dynamic;

    return api_json_error(response, response_max, JSON_404_HEADERS,
                      "Unknown API endpoint");
}
