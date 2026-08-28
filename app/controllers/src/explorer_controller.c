/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block explorer controller — comprehensive blockchain explorer served
 * over Tor .onion. Supports blocks, transactions (transparent + shielded),
 * ZSLP tokens, and address lookups. */

#include "platform/time_compat.h"
#include "controllers/explorer_controller.h"
#include "controllers/api_controller.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "core/serialize.h"
#include "keys/key_io.h"
#include "models/block.h"
#include "models/database.h"
#include "models/hodl_wave.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "zslp/slp.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "views/explorer_factoids_view.h"
#include "views/explorer_stats_view.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/socket.h>
#include "platform/socket_compat.h"
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <math.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "controllers/explorer_internal.h"
#include "util/template.h"
#include "views/wallet_templates_gen.h"
#include "views/site_css.h"
#include "views/explorer_main_view.h"
#include "views/format_helpers.h"
#include "explorer_controller_internal.h"

/* struct explorer_context defined in explorer_controller_internal.h */

struct explorer_rpc_backend {
    char user[128];
    char pass[128];
    int proxy_port;
};

/* struct explorer_assets defined in explorer_controller_internal.h */

static struct explorer_context g_explorer_ctx = {0};
/* Credentials start absent: boot fills them from the node's .cookie or
 * rpcuser/rpcpassword config; the call path refuses to fire without
 * them — no invented fallback pair. */
static struct explorer_rpc_backend g_explorer_rpc = {
    .proxy_port = 8023,
};
static struct explorer_assets g_explorer_assets = {0};

static bool explorer_join_path(char *out, size_t out_size,
                               const char *directory, const char *leaf)
{
    int written = snprintf(out, out_size, "%s/%s", directory, leaf);
    return written >= 0 && (size_t)written < out_size;
}

struct explorer_context *explorer_ctx(void)
{
    return &g_explorer_ctx;
}

static struct explorer_rpc_backend *explorer_rpc(void)
{
    return &g_explorer_rpc;
}

struct explorer_assets *explorer_assets(void)
{
    return &g_explorer_assets;
}

/* Transitional aliases while this large controller is moved over in slices. */
/* ── Template system ───────────────────────────────────────── */

void ensure_explorer_dir(void)
{
    struct explorer_context *ctx = explorer_ctx();
    struct explorer_assets *assets = explorer_assets();
    if (!ctx->datadir) return;
    if (!explorer_join_path(assets->explorer_dir,
                            sizeof(assets->explorer_dir), ctx->datadir,
                            "explorer")) {
        assets->explorer_dir[0] = '\0';
        return;
    }
    mkdir(assets->explorer_dir, 0755);
}

static void write_default_file(const char *filename, const char *content)
{
    struct explorer_assets *assets = explorer_assets();
    char path[1200];
    if (!explorer_join_path(path, sizeof(path), assets->explorer_dir,
                            filename))
        return;
    /* Only write if file doesn't exist — don't overwrite customizations */
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return; }
    f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
        printf("Explorer: wrote default %s\n", path);
    }
}

void load_css(void)
{
    struct explorer_assets *assets = explorer_assets();
    char path[1200];
    const char *override_path = getenv("ZCL_EXPLORER_CSS_FILE");
    bool default_path_valid = explorer_join_path(
        path, sizeof(path), assets->explorer_dir, "style.css");

    if (override_path && override_path[0]) {
        FILE *f = fopen(override_path, "r");
        if (f) {
            assets->css_len = fread(assets->css_cache, 1,
                                    sizeof(assets->css_cache) - 1, f);
            assets->css_cache[assets->css_len] = '\0';
            fclose(f);
            return;
        }
        LOG_WARN("explorer", "CSS override unavailable: %s", override_path);
    } else if (default_path_valid && getenv("ZCL_EXPLORER_CSS_LIVE")) {
        FILE *f = fopen(path, "r");
        if (f) {
            assets->css_len = fread(assets->css_cache, 1,
                                    sizeof(assets->css_cache) - 1, f);
            assets->css_cache[assets->css_len] = '\0';
            fclose(f);
            return;
        }
    }

    assets->css_len = strlen(site_css);
    if (assets->css_len >= sizeof(assets->css_cache))
        assets->css_len = sizeof(assets->css_cache) - 1;
    memcpy(assets->css_cache, site_css, assets->css_len);
    assets->css_cache[assets->css_len] = '\0';
}

static void init_default_templates(void)
{
    ensure_explorer_dir();
    write_default_file("style.css", site_css);
    load_css();
}

/* compute threads forward-declared in explorer_controller_internal.h */
/* g_stats_computing defined in explorer_controller_pages.c */
/* g_tokens_computing defined in explorer_controller_pages.c */
/* g_factoids_computing defined in explorer_controller_pages.c */
static _Atomic int g_prewarm_started;

bool explorer_start_detached_thread(pthread_t *thread_out,
                                           void *(*entry)(void *),
                                           void *arg,
                                           size_t stack_size)
{
    pthread_attr_t attr;
    bool ok = false;

    if (!thread_out || !entry)
        LOG_FAIL("explorer", "explorer_start_detached_thread: NULL thread_out or entry");
    if (pthread_attr_init(&attr) != 0)
        LOG_FAIL("explorer", "explorer_start_detached_thread: pthread_attr_init failed");
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
        goto cleanup;
    if (stack_size > 0 && pthread_attr_setstacksize(&attr, stack_size) != 0)
        goto cleanup;
    /* raw-pthread-ok: detached-helper-wrapper (custom stack via pthread_attr) */
    if (pthread_create(thread_out, &attr, entry, arg) != 0)
        goto cleanup;
    ok = true;

cleanup:
    pthread_attr_destroy(&attr);
    return ok;
}

bool explorer_start_once(_Atomic int *flag,
                                void *(*entry)(void *),
                                const char *name)
{
    int expected = 0;
    pthread_t t;

    if (!flag || !entry)
        LOG_FAIL("explorer", "explorer_start_once: NULL flag or entry for %s", name ? name : "unknown");
    if (!atomic_compare_exchange_strong(flag, &expected, 1))
        return expected == 1;
    if (!explorer_start_detached_thread(&t, entry, NULL, 2 * 1024 * 1024)) {
        atomic_store(flag, 0);
        LOG_FAIL("explorer", "Explorer: failed to start %s thread", name ? name : "unknown");
    }
    return true;
}

static void prewarm_caches(void)
{
    /* Delay 5 seconds to let RPC server start */
    sleep(5);

    printf("Explorer: pre-warming stats cache...\n");
    fflush(stdout);
    explorer_start_once(&g_stats_computing, stats_compute_thread,
                        "stats_compute");

    printf("Explorer: pre-warming tokens cache...\n");
    fflush(stdout);
    explorer_start_once(&g_tokens_computing, tokens_compute_thread,
                        "tokens_compute");

    printf("Explorer: pre-warming factoids cache...\n");
    fflush(stdout);
    explorer_start_once(&g_factoids_computing, factoids_compute_thread,
                        "factoids_compute");
}

static void *prewarm_thread(void *arg)
{
    (void)arg;
    prewarm_caches();
    return NULL;
}

void explorer_set_state(struct main_state *ms, struct tx_mempool *mp,
                         struct coins_view_cache *coins_tip,
                         struct node_db *ndb, const char *datadir)
{
    struct explorer_context *ctx = explorer_ctx();
    ctx->main_state = ms;
    ctx->mempool = mp;
    ctx->coins_tip = coins_tip;
    ctx->node_db = ndb;
    ctx->datadir = datadir;
    init_default_templates();

    /* Pre-warm caches in background after startup */
    int chain_tip_h = ms ? active_chain_height(&ms->chain_active) : 0;
    int best_header = (ms && ms->pindex_best_header) ?
        ms->pindex_best_header->nHeight : chain_tip_h;
    if (best_header - chain_tip_h > 1000) {
        printf("Explorer prewarm deferred during IBD "
               "(chain=%d, headers=%d, behind=%d)\n",
               chain_tip_h, best_header, best_header - chain_tip_h);
        return;
    }
    explorer_start_once(&g_prewarm_started, prewarm_thread, "prewarm");
}

/* ── RPC proxy to local zclassicd ─────────────────────────── */

int rpc_call(const char *method, const char *params_json,
	                     char *out, size_t outmax)
{
    if (!out || outmax == 0)
        LOG_ERR("explorer", "rpc_call(%s): invalid output buffer", method);
    out[0] = '\0';

    /* Credentials absent at call time: send nothing rather than
     * guessable basic-auth. */
    if (!explorer_rpc()->user[0] || !explorer_rpc()->pass[0])
        LOG_ERR("explorer",
                "rpc_call(%s): no node credentials configured; not "
                "dialing", method);

    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                 true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("explorer", "rpc_call(%s): socket() failed", method);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)explorer_rpc()->proxy_port);

    platform_socket_set_receive_timeout(fd, 5000);
    platform_socket_set_send_timeout(fd, 5000);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        platform_socket_close(fd);
        LOG_ERR("explorer", "rpc_call(%s): connect to port %d failed", method, explorer_rpc()->proxy_port);
    }

    char body[4096];
    int blen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);
    if (blen < 0 || (size_t)blen >= sizeof(body)) {
        platform_socket_close(fd);
        LOG_ERR("explorer", "rpc_call(%s): request body too large (%d bytes)", method, blen);
    }

    /* Base64 encode auth (simple inline for user:pass) */
    char auth_plain[256];
    int auth_len = snprintf(auth_plain, sizeof(auth_plain), "%s:%s",
                            explorer_rpc()->user, explorer_rpc()->pass);
    if (auth_len < 0 || (size_t)auth_len >= sizeof(auth_plain)) {
        platform_socket_close(fd);
        LOG_ERR("explorer", "rpc_call(%s): credentials exceed local limit",
                method);
    }
    /* Simple base64 */
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char auth_b64[512];
    size_t alen = (size_t)auth_len, bo = 0;
    for (size_t i = 0; i < alen; i += 3) {
        uint32_t n = ((uint32_t)(uint8_t)auth_plain[i]) << 16;
        if (i + 1 < alen) n |= ((uint32_t)(uint8_t)auth_plain[i+1]) << 8;
        if (i + 2 < alen) n |= (uint32_t)(uint8_t)auth_plain[i+2];
        auth_b64[bo++] = b64[(n >> 18) & 63];
        auth_b64[bo++] = b64[(n >> 12) & 63];
        auth_b64[bo++] = (i + 1 < alen) ? b64[(n >> 6) & 63] : '=';
        auth_b64[bo++] = (i + 2 < alen) ? b64[n & 63] : '=';
    }
    auth_b64[bo] = '\0';

    char req[8192];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        auth_b64, blen, body);
    if (rlen < 0 || (size_t)rlen >= sizeof(req)) {
        platform_socket_close(fd);
        LOG_ERR("explorer", "rpc_call(%s): request too large (%d bytes)", method, rlen);
    }

    if (!platform_socket_send_all(fd, req, (size_t)rlen)) {
        platform_socket_close(fd);
        LOG_ERR("explorer", "rpc_call(%s): write failed", method);
    }

    /* Read response */
    size_t total = 0;
    while (total < outmax - 1) {
        ptrdiff_t r = platform_socket_receive(fd, out + total,
                                              outmax - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    out[total] = '\0';
    platform_socket_close(fd);

    /* Skip HTTP headers — find \r\n\r\n */
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

/* JSON extraction: use shared zcl_json_int/zcl_json_real (return-value
 * wrappers with the -1 int / 0.0 real defaults) and zcl_json_extract_str
 * directly, all from format_helpers.h. */

void explorer_set_rpc(const char *user, const char *pass, int port)
{
    struct explorer_rpc_backend *rpc = explorer_rpc();
    if (user) snprintf(rpc->user, sizeof(rpc->user), "%s", user);
    if (pass) snprintf(rpc->pass, sizeof(rpc->pass), "%s", pass);
    if (port > 0) rpc->proxy_port = port;
}

static int native_chain_height(void)
{
    struct explorer_context *ctx = explorer_ctx();
    if (ctx->main_state)
        return active_chain_height(&ctx->main_state->chain_active);
    /* Fallback: query SQLite when running without full node (e.g. GTK browser).
     * The raw read lives in the block model (db_block_max_height_any_status). */
    if (ctx->node_db && ctx->node_db->db)
        return db_block_max_height_any_status(ctx->node_db);
    LOG_ERR("explorer", "native_chain_height: no main_state or node_db available");
}

bool use_rpc_proxy(void)
{
    /* Use RPC/SQLite proxy when no main_state (standalone browser)
     * or when chain height is not available */
    if (!explorer_ctx()->main_state) return true;
    return native_chain_height() < 1;
}

/* ── Helpers ──────────────────────────────────────────────── */

/* html_escape provided by util/template.h (included above) */

/* difficulty_from_bits() / difficulty_from_index() in chain/pow.h */
#include "chain/pow.h"

bool explorer_param_is_printable_ascii(const char *s)
{
    if (!s) return false;
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c < 32 || c > 126)
            return false;
    }
    return true;
}

void format_time(char *buf, size_t max, uint32_t t)
{
    zcl_format_time(buf, max, (int64_t)t);
}

void format_time_ago(char *buf, size_t max, uint32_t t)
{
    time_t now = platform_time_wall_time_t();
    int64_t diff = (int64_t)now - (int64_t)t;
    if (diff < 0) diff = 0;
    if (diff < 60)
        snprintf(buf, max, "%"PRId64"s ago", diff);
    else if (diff < 3600)
        snprintf(buf, max, "%"PRId64"m ago", diff / 60);
    else if (diff < 86400)
        snprintf(buf, max, "%"PRId64"h ago", diff / 3600);
    else
        snprintf(buf, max, "%"PRId64"d ago", diff / 86400);
}

/* Encode a tx_destination to a t-address string */
bool addr_encode(char *out, size_t outmax,
                         const struct tx_destination *dest)
{
    const struct chain_params *cp = chain_params_get();
    if (!cp) LOG_FAIL("explorer", "addr_encode: chain_params_get returned NULL");
    size_t pk_len = 0, sh_len = 0;
    const unsigned char *pk_pfx = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sh_pfx = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sh_len);
    return encode_destination(dest, pk_pfx, pk_len, sh_pfx, sh_len, out, outmax);
}

bool addr_decode(const char *str, struct tx_destination *dest)
{
    const struct chain_params *cp = chain_params_get();
    if (!cp) LOG_FAIL("explorer", "addr_decode: chain_params_get returned NULL");
    size_t pk_len = 0, sh_len = 0;
    const unsigned char *pk_pfx = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sh_pfx = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sh_len);
    return decode_destination(str, pk_pfx, pk_len, sh_pfx, sh_len, dest);
}

/* ── Macros from explorer_internal.h ──────────────────────── */
/* EXPLORER_HEADER, EXPLORER_NAV, EXPLORER_FOOTER, and APPEND
 * are all defined in controllers/explorer_internal.h (single source
 * of truth for all explorer pages). */

/* ── Main Request Handler ─────────────────────────────────── */

struct explorer_shortcut_route {
    const char *shortcut;
    const char *canonical;
};

static const struct explorer_shortcut_route g_explorer_shortcuts[] = {
    { "/stats", "/explorer/stats" },
    { "/stats/", "/explorer/stats" },
    { "/tokens", "/explorer/tokens" },
    { "/tokens/", "/explorer/tokens" },
    { "/hodl", "/explorer/hodl" },
    { "/hodl/", "/explorer/hodl" },
    { "/events", "/explorer/events" },
    { "/events/", "/explorer/events" },
    { "/factoids", "/explorer/factoids" },
    { "/factoids/", "/explorer/factoids" },
    { "/names", "/explorer/names" },
    { "/names/", "/explorer/names" },
    { "/network", "/explorer/network" },
    { "/network/", "/explorer/network" },
    { "/market", "/explorer/market" },
    { "/market/", "/explorer/market" },
    { "/swaps", "/explorer/swaps" },
    { "/swaps/", "/explorer/swaps" },
    { "/messages", "/explorer/messages" },
    { "/messages/", "/explorer/messages" },
};

const char *explorer_canonical_shortcut(const char *path)
{
    if (!path)
        return NULL;
    for (size_t i = 0; i < sizeof(g_explorer_shortcuts) /
                           sizeof(g_explorer_shortcuts[0]); i++) {
        if (strcmp(path, g_explorer_shortcuts[i].shortcut) == 0)
            return g_explorer_shortcuts[i].canonical;
    }
    return NULL;
}

static size_t explorer_redirect(uint8_t *response, size_t response_max,
                                const char *location)
{
    if (!response || !location)
        return 0;
    int n = snprintf((char *)response, response_max,
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Connection: close\r\n\r\n",
        location);
    if (n < 0)
        return 0;
    return (size_t)n < response_max ? (size_t)n : response_max;
}

size_t explorer_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max)
{
    (void)body; (void)body_len;
    if (!path || !response) return 0;

    /* Delegate /api/ routes to the REST API controller */
    if (strncmp(path, "/api/", 5) == 0 || strcmp(path, "/api") == 0) {
        return api_handle_request(method, path, body, body_len,
                                   response, response_max);
    }

    const char *canonical = explorer_canonical_shortcut(path);
    if (canonical)
        return explorer_redirect(response, response_max, canonical);

    (void)method;

    if (strcmp(path, "/explorer/style.css") == 0)
        return serve_css(response, response_max);

    if (strcmp(path, "/explorer/favicon.png") == 0 ||
        strcmp(path, "/favicon.ico") == 0) {
        struct explorer_context *ctx = explorer_ctx();
        if (!ctx->datadir) return 0; /* no datadir → no favicon to serve */
        char fpath[1200];
        snprintf(fpath, sizeof(fpath), "%s/explorer/favicon.png", ctx->datadir);
        FILE *f = fopen(fpath, "rb");
        if (f) {
            size_t off = 0;
            int n = snprintf((char *)response, response_max,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/png\r\n"
                "Cache-Control: public, max-age=86400\r\n"
                "Connection: close\r\n\r\n");
            if (n > 0) off = (size_t)n;
            off += fread(response + off, 1, response_max - off, f);
            fclose(f);
            return off;
        }
        return 0;
    }

    if (strcmp(path, "/explorer") == 0 || strcmp(path, "/explorer/") == 0 ||
        strncmp(path, "/explorer?", 10) == 0 || strncmp(path, "/explorer/?", 11) == 0) {
        int page = 0;
        const char *pp = strstr(path, "page=");
        if (pp) page = atoi(pp + 5);
        if (page < 0) page = 0;
        return serve_dashboard_with_page(response, response_max, page);
    }

    if (strcmp(path, "/explorer/stats") == 0 || strcmp(path, "/explorer/stats/") == 0)
        return serve_stats(response, response_max);

    if (strcmp(path, "/explorer/tokens") == 0 || strcmp(path, "/explorer/tokens/") == 0)
        return serve_tokens(response, response_max);

    if (strncmp(path, "/explorer/token/", 16) == 0)
        return serve_token_detail(path + 16, response, response_max);

    if (strcmp(path, "/explorer/hodl") == 0 || strcmp(path, "/explorer/hodl/") == 0)
        return serve_hodl(response, response_max);

    if (strcmp(path, "/explorer/events") == 0 || strcmp(path, "/explorer/events/") == 0)
        return serve_events(response, response_max);

    if (strcmp(path, "/explorer/factoids") == 0 || strcmp(path, "/explorer/factoids/") == 0)
        return serve_factoids(response, response_max);

    if (strcmp(path, "/explorer/names") == 0 || strcmp(path, "/explorer/names/") == 0)
        return serve_names(response, response_max);

    if (strcmp(path, "/explorer/network") == 0 || strcmp(path, "/explorer/network/") == 0)
        return serve_network(response, response_max);

    if (strcmp(path, "/explorer/market") == 0 || strcmp(path, "/explorer/market/") == 0)
        return serve_market(response, response_max);

    if (strcmp(path, "/explorer/swaps") == 0 || strcmp(path, "/explorer/swaps/") == 0)
        return serve_swaps(response, response_max);

    if (strcmp(path, "/explorer/messages") == 0 || strcmp(path, "/explorer/messages/") == 0)
        return serve_messages(response, response_max);

    if (strncmp(path, "/explorer/block/", 16) == 0)
        return serve_block(path + 16, response, response_max);

    if (strncmp(path, "/explorer/tx/", 13) == 0)
        return serve_tx(path + 13, response, response_max);

    if (strncmp(path, "/explorer/address/", 18) == 0)
        return serve_address(path + 18, response, response_max);

    if (strncmp(path, "/explorer/search", 16) == 0) {
        const char *q = strstr(path, "q=");
        return serve_search(q ? q + 2 : "", response, response_max);
    }

    /* Wallet — self-contained HTML+CSS+JS, fetches /api/wallet.
     * HTML assembly lives in app/views/src/explorer_main_view.c. */
    if (strcmp(path, "/wallet") == 0 || strcmp(path, "/wallet/") == 0)
        return explorer_view_wallet_page(response, response_max);

    return 0; /* unhandled → caller returns 404 */
}
