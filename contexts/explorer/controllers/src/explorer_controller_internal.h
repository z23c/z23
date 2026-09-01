/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the explorer controller.
 *
 * The public surface lives in controllers/explorer_controller.h. This
 * header is private to engine/controllers/src/explorer_controller*.c and
 * declares helpers that needed to become non-static so the explorer
 * controller could be split across multiple files. Do not include from
 * outside engine/controllers/src/.
 *
 * NOTE: this is distinct from the inline-helper header
 * controllers/explorer_internal.h (which is shared with explorer_stats.c
 * and explorer_factoids.c); that one holds chart/SQL inlines. This one
 * threads the original explorer_controller.c statics across the new
 * block/tx/address/pages siblings. */

#ifndef ZCL_APP_CONTROLLERS_SRC_EXPLORER_CONTROLLER_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_EXPLORER_CONTROLLER_INTERNAL_H

#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "models/database.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Shared controller context (defined in explorer_controller.c) ── */

struct explorer_context {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
    const char *datadir;
};

struct explorer_context *explorer_ctx(void);

/* ── RPC proxy helpers (defined in explorer_controller.c) ── */

int rpc_call(const char *method, const char *params_json,
             char *out, size_t outmax);
bool use_rpc_proxy(void);

/* ── Formatting helpers (defined in explorer_controller.c) ──
 * Block difficulty: use difficulty_from_index() from chain/pow.h. */

bool explorer_param_is_printable_ascii(const char *s);
void format_time(char *buf, size_t max, uint32_t t);
void format_time_ago(char *buf, size_t max, uint32_t t);
bool addr_encode(char *out, size_t outmax,
                 const struct tx_destination *dest);
bool addr_decode(const char *str, struct tx_destination *dest);

/* ── Detached-thread plumbing (defined in explorer_controller.c) ── */

bool explorer_start_detached_thread(pthread_t *thread_out,
                                    void *(*entry)(void *),
                                    void *arg,
                                    size_t stack_size);
bool explorer_start_once(_Atomic int *flag,
                         void *(*entry)(void *),
                         const char *name);

/* ── Filesystem-backed explorer assets (defined in
 * explorer_controller.c). Used by pages.c for cache files + CSS. */

struct explorer_assets {
    char explorer_dir[1024];
    char css_cache[32768];
    size_t css_len;
};

struct explorer_assets *explorer_assets(void);
void ensure_explorer_dir(void);
void load_css(void);

/* ── Serve handlers (defined in sibling files) ── */

/* explorer_controller_block.c */
size_t serve_block(const char *param, uint8_t *r, size_t max);

/* explorer_controller_tx.c */
size_t serve_tx(const char *param, uint8_t *r, size_t max);

/* explorer_controller_address.c */
size_t serve_address(const char *param, uint8_t *r, size_t max);
size_t serve_search(const char *query, uint8_t *r, size_t max);

/* Dashboard fallback used by serve_search. Defined in
 * explorer_controller.c. Renamed from the original static
 * `serve_dashboard` to avoid the symbol collision with
 * wallet_view_dashboard.c that the file-split exposed. */
size_t explorer_serve_dashboard(uint8_t *r, size_t max);

/* explorer_controller_dashboard.c — dashboard rendering (RPC proxy +
 * native modes). explorer_handle_request routes /explorer here. */
size_t serve_dashboard_with_page(uint8_t *r, size_t max, int page);

/* explorer_controller_pages.c */
size_t serve_stats(uint8_t *r, size_t max);
size_t serve_factoids(uint8_t *r, size_t max);
size_t serve_tokens(uint8_t *r, size_t max);
size_t serve_token_detail(const char *token_id_hex, uint8_t *r, size_t max);
size_t serve_hodl(uint8_t *r, size_t max);
size_t serve_css(uint8_t *r, size_t max);
size_t serve_events(uint8_t *r, size_t max);
size_t serve_names(uint8_t *r, size_t max);
size_t serve_network(uint8_t *r, size_t max);
size_t serve_market(uint8_t *r, size_t max);
size_t serve_swaps(uint8_t *r, size_t max);
size_t serve_messages(uint8_t *r, size_t max);

/* Detached compute threads (defined in explorer_controller_pages.c) — used
 * by explorer_controller.c's prewarm pipeline. */
void *stats_compute_thread(void *arg);
void *tokens_compute_thread(void *arg);
void *factoids_compute_thread(void *arg);

/* Once-flags driving compute-thread spawning. Defined in
 * explorer_controller_pages.c (where the threads live); referenced
 * from explorer_controller.c's prewarm. */
extern _Atomic int g_stats_computing;
extern _Atomic int g_tokens_computing;
extern _Atomic int g_factoids_computing;

#endif
