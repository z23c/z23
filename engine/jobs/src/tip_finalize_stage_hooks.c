/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage dependency-injection hooks. The finalize stage lives in
 * app/jobs but must reach facts owned by higher layers (the live UTXO count
 * for supply audits; the boot-cursor reorg clamp in config/) without a
 * backward include. Boot binds these setters after the owning subsystems open;
 * the stage invokes them through the accessors below. Split from
 * tip_finalize_stage.c along the file-size ceiling seam — the DI plumbing is a
 * separable concern from the finalize algorithm, and new hooks (e.g. the
 * segment sealer) land here rather than growing the stage TU. */

#include "jobs/tip_finalize_stage.h"
#include "jobs/tip_finalize_stage_hooks.h"

#include <pthread.h>
#include <stddef.h>

static pthread_mutex_t g_hooks_lock = PTHREAD_MUTEX_INITIALIZER;
static tip_finalize_utxo_count_fn g_utxo_counter = NULL;
static void *g_utxo_counter_user = NULL;
static tip_finalize_reorg_clamp_fn g_reorg_clamp = NULL;
static void *g_reorg_clamp_user = NULL;

void tip_finalize_stage_set_utxo_counter(tip_finalize_utxo_count_fn fn, void *user)
{
    pthread_mutex_lock(&g_hooks_lock);
    g_utxo_counter = fn;
    g_utxo_counter_user = user;
    pthread_mutex_unlock(&g_hooks_lock);
}

void tip_finalize_stage_set_reorg_clamp(tip_finalize_reorg_clamp_fn fn,
                                        void *user)
{
    pthread_mutex_lock(&g_hooks_lock);
    g_reorg_clamp = fn;
    g_reorg_clamp_user = user;
    pthread_mutex_unlock(&g_hooks_lock);
}

bool tip_finalize_hooks_count_utxos(int height_after, int64_t *out_count)
{
    pthread_mutex_lock(&g_hooks_lock);
    tip_finalize_utxo_count_fn fn = g_utxo_counter;
    void *user = g_utxo_counter_user;
    pthread_mutex_unlock(&g_hooks_lock);
    if (!fn) {
        *out_count = -1;
        return true;
    }
    return fn(height_after, out_count, user);
}

void tip_finalize_hooks_reorg_clamp(int fork_height)
{
    pthread_mutex_lock(&g_hooks_lock);
    tip_finalize_reorg_clamp_fn fn = g_reorg_clamp;
    void *user = g_reorg_clamp_user;
    pthread_mutex_unlock(&g_hooks_lock);
    if (fn)
        fn(fork_height, user);
}

void tip_finalize_hooks_reset(void)
{
    pthread_mutex_lock(&g_hooks_lock);
    g_utxo_counter = NULL;
    g_utxo_counter_user = NULL;
    g_reorg_clamp = NULL;
    g_reorg_clamp_user = NULL;
    pthread_mutex_unlock(&g_hooks_lock);
}
