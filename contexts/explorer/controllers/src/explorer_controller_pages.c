/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Explorer secondary-page CONTROLLER: thin parse-delegate glue for
 * stats, tokens, factoids, hodl, events, names, market, swaps, messages,
 * css. The page assembly (HTML/SVG/JSON) lives in the view shape:
 *   contexts/explorer/views/src/explorer_stats_view.c
 *   contexts/explorer/views/src/explorer_factoids_view.c
 *   contexts/explorer/views/src/explorer_pages_view.c
 * This file retains only the request dispatch, the in-RAM page cache, and the
 * background compute-thread orchestration used by the prewarm pipeline.
 * See explorer_controller_internal.h for shared declarations. */

#include "platform/time_compat.h"
#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "explorer_controller_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "models/hodl_wave.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "services/hodl_history_service.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/template.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "views/format_helpers.h"
#include "views/explorer_stats_view.h"
#include "views/explorer_factoids_view.h"
#include "views/explorer_pages_view.h"
#include "views/explorer_pages_loading_view.h"
#include "views/wallet_templates_gen.h"
#include "zslp/slp.h"

#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Once-flags driving compute-thread spawning. Referenced from
 * explorer_controller.c's prewarm pipeline via the extern declarations
 * in explorer_controller_internal.h. */
_Atomic int g_stats_computing = 0;
_Atomic int g_tokens_computing = 0;
_Atomic int g_factoids_computing = 0;

/* Stats page — computed in background thread, served from cache */
#define STATS_CACHE_SIZE (1024 * 1024) /* 1MB for comprehensive stats */
static char g_stats_cache[STATS_CACHE_SIZE] = "";
/* Published with release AFTER the bytes are written and read with acquire in
 * serve_stats(), so a request thread never observes a nonzero length before
 * g_stats_cache holds the matching bytes. */
static _Atomic size_t g_stats_cache_len = 0;
static _Atomic int64_t g_stats_cache_height = 0;

static int64_t explorer_page_cap_to_served_tip(int64_t index_tip)
{
    if (index_tip < 0)
        return index_tip;
    if (!reducer_frontier_provable_tip_is_published())
        return 0;

    int32_t served_tip = reducer_frontier_provable_tip_cached();
    if (served_tip >= 0 && index_tip > served_tip)
        return served_tip;
    return index_tip;
}

static int64_t explorer_page_index_tip_height(const char *datadir)
{
    sqlite3 *db = NULL;
    int64_t block_tip;
    int64_t utxo_tip;

    if (!datadir || !explorer_open_readonly_db(datadir, &db))
        LOG_RETURN(-1, "explorer",
                   "explorer_page_index_tip_height: open db failed");
    block_tip = sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
    utxo_tip = sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM utxos");
    sqlite3_close(db);
    return block_tip > utxo_tip ? block_tip : utxo_tip;
}

static int64_t explorer_page_served_tip_height(const char *datadir,
                                               int64_t *index_tip_out)
{
    int64_t index_tip = explorer_page_index_tip_height(datadir);
    if (index_tip_out)
        *index_tip_out = index_tip;
    return explorer_page_cap_to_served_tip(index_tip);
}

/* ── Disk cache helpers (survive restarts) ────────────────── */

static void stats_cache_save(size_t len)
{
    struct explorer_assets *assets = explorer_assets();
    if (!assets->explorer_dir[0]) ensure_explorer_dir();
    if (!assets->explorer_dir[0] || len == 0) return;
    char path[1200];
    snprintf(path, sizeof(path), "%s/stats.cache", assets->explorer_dir);
    FILE *f = fopen(path, "w");
    if (f) { fwrite(g_stats_cache, 1, len, f); fclose(f); }
}

static size_t stats_cache_load(void)
{
    struct explorer_assets *assets = explorer_assets();
    if (!assets->explorer_dir[0]) ensure_explorer_dir();
    if (!assets->explorer_dir[0]) return 0;
    char path[1200];
    snprintf(path, sizeof(path), "%s/stats.cache", assets->explorer_dir);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t len = fread(g_stats_cache, 1, sizeof(g_stats_cache) - 1, f);
    fclose(f);
    g_stats_cache[len] = '\0';
    return len;
}

/* serve_loading_placeholder() and the page renderers (tokens, token detail,
 * hodl, events, names, market, swaps, messages) live in
 * contexts/explorer/views/src/explorer_pages_view.c. The controller parses and delegates;
 * views render. */

void *stats_compute_thread(void *arg)
{
    (void)arg;
    struct explorer_context *ctx = explorer_ctx();
    int64_t start_index_tip = -1;
    int64_t start_tip =
        explorer_page_served_tip_height(ctx->datadir, &start_index_tip);
    if (start_index_tip >= 0 && start_tip >= 0 && start_index_tip > start_tip) {
        printf("Stats background: deferred until served frontier catches "
               "index (served=%lld index=%lld)\n",
               (long long)start_tip, (long long)start_index_tip);
        fflush(stdout);
        g_stats_computing = 0;
        return NULL;
    }
    /* Load previous cache from disk for instant serving while recomputing */
    if (g_stats_cache_len == 0) {
        size_t disk_len = stats_cache_load();
        if (disk_len > 0) {
            /* Release: the loaded bytes above must be visible before a
             * reader can observe this nonzero length. */
            atomic_store_explicit(&g_stats_cache_len, disk_len, memory_order_release);
            printf("Stats: loaded %zu bytes from disk cache (instant)\n", disk_len);
            fflush(stdout);
        }
    }
    printf("Stats background: computing comprehensive stats...\n");
    fflush(stdout);
    /* Compute fresh into a temp buffer so we don't blank the disk-loaded cache */
    char *tmp = zcl_malloc(STATS_CACHE_SIZE, "stats_cache_tmp");
    if (!tmp) { g_stats_computing = 0; LOG_NULL("explorer", "stats_compute_thread: malloc(%d) failed", STATS_CACHE_SIZE); }
    size_t len = explorer_stats_build((uint8_t *)tmp, STATS_CACHE_SIZE, ctx->datadir);
    if (len > 0) {
        int64_t end_index_tip = -1;
        int64_t end_tip =
            explorer_page_served_tip_height(ctx->datadir, &end_index_tip);
        bool stable = start_index_tip >= 0 && end_index_tip >= 0 &&
                      start_index_tip == end_index_tip &&
                      end_tip >= 0 && end_index_tip <= end_tip;
        if (stable) {
            memcpy(g_stats_cache, tmp, len);
            /* Release: publish the length only after the bytes are in place, pairing
             * with the acquire-load in serve_stats(). */
            atomic_store_explicit(&g_stats_cache_height, end_tip,
                                  memory_order_release);
            atomic_store_explicit(&g_stats_cache_len, len, memory_order_release);
            stats_cache_save(len);
        } else {
            printf("Stats background: discarded unstable build "
                   "(start_index=%lld end_index=%lld served=%lld)\n",
                   (long long)start_index_tip, (long long)end_index_tip,
                   (long long)end_tip);
            fflush(stdout);
        }
    }
    free(tmp);
    g_stats_computing = 0;
    return NULL;
}

/* (stats_query_int64, stats_query_double, stats_tab_css, and stats body
 * moved to explorer_stats.c — see explorer_stats_build()) */

size_t serve_stats(uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    int64_t index_tip = -1;
    int64_t tip = explorer_page_served_tip_height(ctx->datadir, &index_tip);
    /* Return cached version if available. Acquire-load pairs with the release
     * store in stats_compute_thread(): once we read a nonzero length, the
     * matching g_stats_cache bytes are guaranteed visible. */
    size_t cached = atomic_load_explicit(&g_stats_cache_len, memory_order_acquire);
    int64_t cache_height =
        atomic_load_explicit(&g_stats_cache_height, memory_order_acquire);
    if (cached > 0) {
        if (tip > 0 && cache_height > 0 && cache_height < tip)
            explorer_start_once(&g_stats_computing, stats_compute_thread,
                                "stats_compute");
        size_t copy = cached < max ? cached : max;
        memcpy(r, g_stats_cache, copy);
        return copy;
    }
    if (index_tip >= 0 && tip >= 0 && index_tip > tip)
        return explorer_view_loading_placeholder(r, max,
            "Statistics Index Warming",
            "#33ff99", "Charts are being computed from blockchain data.");

    /* Not cached yet — trigger background computation if not running */
    explorer_start_once(&g_stats_computing, stats_compute_thread,
                        "stats_compute");
    return explorer_view_loading_placeholder(r, max,
        "Statistics Index Warming",
        "#33ff99", "Charts are being computed from blockchain data.");
}

/* ── Factoids Page ────────────────────────────────────────── */

#define FACTOIDS_CACHE_SIZE (1024 * 1024)  /* 1MB — 17 sections with SHA3 */
#define FACTOIDS_CACHE_HASH_MAX 80
static char g_factoids_cache[FACTOIDS_CACHE_SIZE] = "";
/* Published with release after the bytes are in place and read with acquire in
 * serve_factoids() (same contract as g_stats_cache_len). */
static _Atomic size_t g_factoids_cache_len = 0;
static _Atomic int64_t g_factoids_cache_height = 0;
static pthread_mutex_t g_factoids_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_factoids_cache_hash[FACTOIDS_CACHE_HASH_MAX] = "";

static bool factoids_block_hash_at(const char *datadir, int64_t height,
                                   char out[FACTOIDS_CACHE_HASH_MAX])
{
    sqlite3 *db = NULL;
    char sql[160];

    if (out)
        out[0] = '\0';
    if (!datadir || height < 0 || !out ||
        !explorer_open_readonly_db(datadir, &db))
        return false;

    snprintf(sql, sizeof(sql),
             "SELECT hex(hash) FROM blocks WHERE height=%" PRId64, height);
    bool ok = sql_query_text(db, sql, out, FACTOIDS_CACHE_HASH_MAX);
    sqlite3_close(db);
    return ok && out[0] != '\0';
}

#ifdef ZCL_TESTING
static void factoids_cache_clear(void)
{
    pthread_mutex_lock(&g_factoids_cache_lock);
    g_factoids_cache[0] = '\0';
    g_factoids_cache_hash[0] = '\0';
    atomic_store_explicit(&g_factoids_cache_height, 0, memory_order_release);
    atomic_store_explicit(&g_factoids_cache_len, 0, memory_order_release);
    pthread_mutex_unlock(&g_factoids_cache_lock);
}
#endif

static void factoids_cache_publish(const char *data, size_t len,
                                   int64_t height, const char *hash)
{
    if (!data || len == 0 || len >= FACTOIDS_CACHE_SIZE || height <= 0 ||
        !hash || !hash[0])
        return;

    pthread_mutex_lock(&g_factoids_cache_lock);
    memcpy(g_factoids_cache, data, len);
    g_factoids_cache[len] = '\0';
    snprintf(g_factoids_cache_hash, sizeof(g_factoids_cache_hash), "%s", hash);
    atomic_store_explicit(&g_factoids_cache_height, height,
                          memory_order_release);
    atomic_store_explicit(&g_factoids_cache_len, len, memory_order_release);
    pthread_mutex_unlock(&g_factoids_cache_lock);
}

static size_t factoids_cache_copy_if_valid(const char *datadir, int64_t tip,
                                           uint8_t *r, size_t max,
                                           bool *behind_tip_out)
{
    size_t cached;
    int64_t cache_height;
    char cache_hash[FACTOIDS_CACHE_HASH_MAX];
    char live_hash[FACTOIDS_CACHE_HASH_MAX];

    if (behind_tip_out)
        *behind_tip_out = false;
    if (!r || max == 0)
        return 0;

    pthread_mutex_lock(&g_factoids_cache_lock);
    cached = atomic_load_explicit(&g_factoids_cache_len, memory_order_acquire);
    cache_height =
        atomic_load_explicit(&g_factoids_cache_height, memory_order_acquire);
    snprintf(cache_hash, sizeof(cache_hash), "%s", g_factoids_cache_hash);
    pthread_mutex_unlock(&g_factoids_cache_lock);

    if (cached == 0 || cache_height <= 0 || !cache_hash[0])
        return 0;
    if (tip > 0 && cache_height > tip)
        return 0;
    if (!factoids_block_hash_at(datadir, cache_height, live_hash) ||
        strcmp(cache_hash, live_hash) != 0)
        return 0;

    pthread_mutex_lock(&g_factoids_cache_lock);
    size_t current_len =
        atomic_load_explicit(&g_factoids_cache_len, memory_order_acquire);
    int64_t current_height =
        atomic_load_explicit(&g_factoids_cache_height, memory_order_acquire);
    bool same_entry = current_len == cached && current_height == cache_height &&
                      strcmp(g_factoids_cache_hash, cache_hash) == 0;
    size_t copy = 0;
    if (same_entry) {
        copy = cached < max ? cached : max;
        memcpy(r, g_factoids_cache, copy);
    }
    pthread_mutex_unlock(&g_factoids_cache_lock);

    if (copy > 0 && behind_tip_out && tip > 0 && cache_height < tip)
        *behind_tip_out = true;
    return copy;
}

void *factoids_compute_thread(void *arg)
{
    (void)arg;
    struct explorer_context *ctx = explorer_ctx();
    int64_t start_index_tip = -1;
    int64_t start_tip =
        explorer_page_served_tip_height(ctx->datadir, &start_index_tip);
    char start_hash[FACTOIDS_CACHE_HASH_MAX];
    if (start_tip <= 0) {
        printf("Factoids background: deferred until served frontier is known "
               "(served=%lld index=%lld)\n",
               (long long)start_tip, (long long)start_index_tip);
        fflush(stdout);
        g_factoids_computing = 0;
        return NULL;
    }
    if (!factoids_block_hash_at(ctx->datadir, start_tip, start_hash)) {
        printf("Factoids background: deferred until served tip hash is indexed "
               "(served=%lld index=%lld)\n",
               (long long)start_tip, (long long)start_index_tip);
        fflush(stdout);
        g_factoids_computing = 0;
        return NULL;
    }
    printf("Factoids background: computing historian data...\n");
    fflush(stdout);
    /* Build into a temp buffer so request threads never read a half-written
     * g_factoids_cache: explorer_factoids_build() APPENDs ~17 sections
     * incrementally while serve_factoids() concurrently memcpy()s the live
     * buffer. Publish with a single memcpy + release store (matches stats). */
    char *tmp = zcl_malloc(FACTOIDS_CACHE_SIZE, "factoids_cache_tmp");
    if (!tmp) {
        g_factoids_computing = 0;
        LOG_NULL("explorer", "factoids_compute_thread: malloc(%d) failed", FACTOIDS_CACHE_SIZE);
    }
    size_t len = explorer_factoids_build_for_served_tip(
        (uint8_t *)tmp, FACTOIDS_CACHE_SIZE, ctx->datadir, start_tip);
    if (len > 0) {
        int64_t end_index_tip = -1;
        int64_t end_tip =
            explorer_page_served_tip_height(ctx->datadir, &end_index_tip);
        char end_hash[FACTOIDS_CACHE_HASH_MAX];
        bool publishable =
            end_tip >= start_tip &&
            factoids_block_hash_at(ctx->datadir, start_tip, end_hash) &&
            strcmp(start_hash, end_hash) == 0;
        if (publishable) {
            factoids_cache_publish(tmp, len, start_tip, start_hash);
        } else {
            printf("Factoids background: discarded unpublished build "
                   "(served_start=%lld start_index=%lld end_index=%lld "
                   "served_end=%lld)\n",
                   (long long)start_tip,
                   (long long)start_index_tip, (long long)end_index_tip,
                   (long long)end_tip);
            fflush(stdout);
        }
    }
    free(tmp);
    g_factoids_computing = 0;
    return NULL;
}

size_t serve_factoids(uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    int64_t index_tip = -1;
    int64_t tip = explorer_page_served_tip_height(ctx->datadir, &index_tip);
    /* Return cached version if available. Acquire-load pairs with the release
     * store in factoids_compute_thread(): a nonzero length guarantees the
     * matching g_factoids_cache bytes are visible. */
    bool cached_behind_tip = false;
    size_t copied = factoids_cache_copy_if_valid(ctx->datadir, tip, r, max,
                                                 &cached_behind_tip);
    if (copied > 0) {
        if (cached_behind_tip) {
            explorer_start_once(&g_factoids_computing, factoids_compute_thread,
                                "factoids_compute");
        }
        return copied;
    }
    if (index_tip >= 0 && tip >= 0 && index_tip > tip)
        return explorer_view_loading_placeholder(r, max,
            "Factoids Index Warming",
            "#33ff99", "Historian data is being computed from blockchain.");

    /* Not cached yet -- trigger background computation */
    explorer_start_once(&g_factoids_computing, factoids_compute_thread,
                        "factoids_compute");
    return explorer_view_loading_placeholder(r, max,
        "Factoids Index Warming",
        "#33ff99", "Historian data is being computed from blockchain.");
}

#ifdef ZCL_TESTING
void explorer_test_set_datadir(const char *datadir)
{
    explorer_ctx()->datadir = datadir;
}

void explorer_test_reset_factoids_cache(void)
{
    factoids_cache_clear();
    atomic_store_explicit(&g_factoids_computing, 0, memory_order_release);
}

bool explorer_test_compute_factoids_cache_now(void)
{
    atomic_store_explicit(&g_factoids_computing, 1, memory_order_release);
    factoids_compute_thread(NULL);
    return atomic_load_explicit(&g_factoids_cache_len,
                                memory_order_acquire) > 0;
}

bool explorer_test_factoids_compute_active(void)
{
    return atomic_load_explicit(&g_factoids_computing,
                                memory_order_acquire) != 0;
}
#endif

/* ── ZSLP Tokens Page ─────────────────────────────────────── */

/* Tokens page cache — precomputed in background. Published with release after
 * the bytes are in place and read with acquire in serve_tokens() (same publish
 * contract as g_stats_cache_len / g_factoids_cache_len). */
static char g_tokens_cache[131072] = "";
static _Atomic size_t g_tokens_cache_len = 0;

void *tokens_compute_thread(void *arg)
{
    (void)arg;
    struct explorer_context *ctx = explorer_ctx();
    printf("Tokens background: computing...\n");
    fflush(stdout);

    uint8_t *r = zcl_malloc(131072, "tokens_html_buf");
    if (!r) {
        g_tokens_computing = 0;
        LOG_NULL("explorer", "tokens_compute_thread: malloc(131072) failed");
    }

    /* Delegate page assembly to the view (app/views). */
    size_t off = explorer_view_tokens(ctx->datadir, r, 131072);

    /* Cache result */
    if (off > 0 && off < sizeof(g_tokens_cache)) {
        memcpy(g_tokens_cache, r, off);
        /* Release: publish the length only after the bytes are in place,
         * pairing with the acquire-load in serve_tokens(). */
        atomic_store_explicit(&g_tokens_cache_len, off, memory_order_release);
    }
    free(r);
    g_tokens_computing = 0;
    printf("Tokens background: cached %zu bytes\n", g_tokens_cache_len);
    fflush(stdout);
    return NULL;
}

size_t serve_tokens(uint8_t *r, size_t max)
{
    size_t cached = atomic_load_explicit(&g_tokens_cache_len, memory_order_acquire);
    if (cached > 0) {
        size_t copy = cached < max ? cached : max;
        memcpy(r, g_tokens_cache, copy);
        return copy;
    }
    /* Trigger the background compute. Call explorer_start_once directly —
     * do NOT pre-set g_tokens_computing=1 first, or its compare_exchange(0→1)
     * fails and the thread never starts, wedging the page on "Loading"
     * forever. */
    explorer_start_once(&g_tokens_computing, tokens_compute_thread,
                        "tokens_compute");
    return explorer_view_tokens_loading(r, max);
}

/* ── ZSLP Token Detail Page ────────────────────────────────── */

size_t serve_token_detail(const char *token_id_hex, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    return explorer_view_token_detail(token_id_hex, ctx->datadir, r, max);
}

/* ── HODL Wave Page ────────────────────────────────────────── */

size_t serve_hodl(uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    return explorer_view_hodl(ctx->datadir, r, max);
}


/* ── CSS Stylesheet ───────────────────────────────────────── */

size_t serve_css(uint8_t *r, size_t max)
{
    struct explorer_assets *assets = explorer_assets();
    /* Reload each request so explicit CSS overrides are live-editable. */
    load_css();
    size_t off = 0;
    int n = snprintf((char *)r, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/css; charset=utf-8\r\n"
        "Cache-Control: public, max-age=60\r\n"
        "Connection: close\r\n\r\n");
    if (n > 0) off = (size_t)n;
    if (off < max) {
        size_t room = max - off;
        size_t copy_len = assets->css_len < room ? assets->css_len : room;
        memcpy(r + off, assets->css_cache, copy_len);
        off += copy_len;
    }
    return off;
}

/* ── Event Log Page ───────────────────────────────────────── */

size_t serve_events(uint8_t *r, size_t max)
{
    return explorer_view_events(r, max);
}

/* ── Names Page ──────────────────────────────────────────── */

size_t serve_names(uint8_t *r, size_t max)
{
    return explorer_view_names(r, max);
}

/* ── Network Page ────────────────────────────────────────── */

size_t serve_network(uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    return explorer_view_network(ctx->datadir, r, max);
}

/* ── Market Page ─────────────────────────────────────────── */

size_t serve_market(uint8_t *r, size_t max)
{
    return explorer_view_market(r, max);
}

/* ── Swaps Page ──────────────────────────────────────────── */

size_t serve_swaps(uint8_t *r, size_t max)
{
    return explorer_view_swaps(r, max);
}

/* ── Messages Page ───────────────────────────────────────── */

size_t serve_messages(uint8_t *r, size_t max)
{
    return explorer_view_messages(r, max);
}
