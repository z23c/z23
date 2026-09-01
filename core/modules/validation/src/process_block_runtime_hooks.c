/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime callback bridges for process_block.
 *
 * Validation owns the consensus decisions; boot owns service wakeups and
 * durable tip publication. This file is the narrow, mutex-protected boundary
 * between those worlds so process_block_core.c can stay focused on selection
 * and tip state transitions. */

#include <pthread.h>
#include <stdatomic.h>

#include "process_block_internal.h"

/* Active block-index database, published by the composition root once the
 * tree is open. Defined here rather than in boot.c so that config/ stays
 * strictly above lib/: boot assigns it, validation and the app-side readers
 * consume it. */
struct block_tree_db *g_active_block_tree = NULL;

static _Atomic process_block_activation_controller_fn g_activation_controller;

void process_block_set_activation_controller(
    process_block_activation_controller_fn fn)
{
    atomic_store_explicit(&g_activation_controller, fn, memory_order_release);
}

struct chain_activation_controller *process_block_activation_controller(void)
{
    process_block_activation_controller_fn fn =
        atomic_load_explicit(&g_activation_controller, memory_order_acquire);
    return fn ? fn() : NULL;
}

static pthread_mutex_t g_gap_fill_kick_lock = PTHREAD_MUTEX_INITIALIZER;
static process_block_gap_fill_kick_fn g_gap_fill_kick;
static void *g_gap_fill_kick_ctx;
static pthread_mutex_t g_tip_publication_lock = PTHREAD_MUTEX_INITIALIZER;
static process_block_commit_tip_fn g_commit_tip_hook;
static process_block_clear_tip_fn g_clear_tip_hook;
static void *g_tip_publication_ctx;

void process_block_set_gap_fill_kick(process_block_gap_fill_kick_fn fn,
                                     void *ctx)
{
    pthread_mutex_lock(&g_gap_fill_kick_lock);
    g_gap_fill_kick = fn;
    g_gap_fill_kick_ctx = ctx;
    pthread_mutex_unlock(&g_gap_fill_kick_lock);
}

void process_block_kick_gap_fill(void)
{
    process_block_gap_fill_kick_fn fn;
    void *ctx;

    pthread_mutex_lock(&g_gap_fill_kick_lock);
    fn = g_gap_fill_kick;
    ctx = g_gap_fill_kick_ctx;
    pthread_mutex_unlock(&g_gap_fill_kick_lock);

    if (fn)
        fn(ctx);
}

void process_block_set_tip_publication_hooks(
    process_block_commit_tip_fn commit_tip,
    process_block_clear_tip_fn clear_tip,
    void *ctx)
{
    pthread_mutex_lock(&g_tip_publication_lock);
    g_commit_tip_hook = commit_tip;
    g_clear_tip_hook = clear_tip;
    g_tip_publication_ctx = ctx;
    pthread_mutex_unlock(&g_tip_publication_lock);
}

enum process_block_tip_publish_result process_block_publish_tip(
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    bool persist_coins_best,
    const struct process_block_tip_evidence *verified)
{
    process_block_commit_tip_fn fn;
    void *ctx;

    pthread_mutex_lock(&g_tip_publication_lock);
    fn = g_commit_tip_hook;
    ctx = g_tip_publication_ctx;
    pthread_mutex_unlock(&g_tip_publication_lock);

    if (!fn)
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED;
    return fn(ctx, ms, coins_tip, new_tip, reason, update_header_tip,
              persist_coins_best, verified);
}

enum process_block_tip_publish_result process_block_clear_tip(
    struct main_state *ms,
    const char *reason)
{
    process_block_clear_tip_fn fn;
    void *ctx;

    pthread_mutex_lock(&g_tip_publication_lock);
    fn = g_clear_tip_hook;
    ctx = g_tip_publication_ctx;
    pthread_mutex_unlock(&g_tip_publication_lock);

    if (!fn)
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED;
    return fn(ctx, ms, reason);
}

const char *process_block_tip_publish_result_name(
    enum process_block_tip_publish_result result)
{
    switch (result) {
    case PROCESS_BLOCK_TIP_PUBLISH_OK:
        return "ok";
    case PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED:
        return "not_initialized";
    case PROCESS_BLOCK_TIP_PUBLISH_REJECTED_DB_BUSY:
        return "db_busy";
    case PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST:
        return "persist";
    case PROCESS_BLOCK_TIP_PUBLISH_REJECTED:
    default:
        return "rejected";
    }
}
