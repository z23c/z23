/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/block_height_census.h"

#include "chain/chain.h"
#include "platform/time_compat.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define CENSUS_CAP 32
/* A census older than this is rebuilt even when nothing visible changed, which
 * bounds how long a block whose `nHeight` was assigned just after its map
 * insertion can stay unseen. */
#define CENSUS_MAX_AGE_SECS 30

struct census {
    const struct block_map *map;
    const struct block_map_entry *buckets;
    size_t capacity;
    size_t size;
    const struct block_index *tip;
    const struct block_index *best_header;
    int height;
    int64_t born;
    size_t n;
    bool valid;
    struct block_index *items[CENSUS_CAP];
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define CENSUS_SLOTS 4
static struct census g_census[CENSUS_SLOTS];
static unsigned g_next_slot;
static unsigned long g_scans;

static int64_t mono_secs(void)
{
    return platform_time_monotonic_ms() / 1000;
}

static bool census_current(const struct census *c, struct main_state *ms,
                           int height, const struct block_index *tip)
{
    const struct block_map *m = &ms->map_block_index;
    return c->valid && c->map == m && c->buckets == m->buckets &&
           c->capacity == m->capacity && c->size == block_map_count(m) &&
           c->tip == tip && c->best_header == ms->pindex_best_header &&
           c->height == height &&
           mono_secs() - c->born < CENSUS_MAX_AGE_SECS;
}

/* Gather every block at `height`. Returns false when the height holds more
 * blocks than the census stores (the caller scans instead). The map size is
 * recorded before the walk so an insertion during it forces the next call to
 * rescan. */
static bool census_fill(struct census *c, struct main_state *ms, int height,
                        const struct block_index *tip)
{
    c->valid = false;
    c->map = &ms->map_block_index;
    c->buckets = c->map->buckets;
    c->capacity = c->map->capacity;
    c->size = block_map_count(c->map);
    c->tip = tip;
    c->best_header = ms->pindex_best_header;
    c->height = height;
    c->born = mono_secs();
    c->n = 0;
    g_scans++;

    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(c->map, &iter, NULL, &p)) {
        if (!p || p->nHeight != height)
            continue;
        if (c->n == CENSUS_CAP)
            return false;
        c->items[c->n++] = p;
    }
    c->valid = true;
    return true;
}

static struct block_index *scan_find(struct main_state *ms, int height,
                                     block_height_pred_fn pred, void *ctx)
{
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (p && p->nHeight == height && pred(p, ctx))
            return p;
    }
    return NULL;
}

struct block_index *block_height_find(struct main_state *ms, int height,
                                      block_height_pred_fn pred, void *ctx)
{
    if (!ms || !pred)
        return NULL;
    const struct block_index *tip = active_chain_tip(&ms->chain_active);

    struct block_index *found = NULL;
    pthread_mutex_lock(&g_mu);
    struct census *c = NULL;
    for (int i = 0; i < CENSUS_SLOTS && !c; i++)
        if (census_current(&g_census[i], ms, height, tip))
            c = &g_census[i];
    if (!c) {
        c = &g_census[g_next_slot++ % CENSUS_SLOTS];
        if (!census_fill(c, ms, height, tip))
            c = NULL;
    }
    for (size_t i = 0; c && i < c->n && !found; i++)
        if (pred(c->items[i], ctx))
            found = c->items[i];
    pthread_mutex_unlock(&g_mu);
    return c ? found : scan_find(ms, height, pred, ctx);
}

#ifdef ZCL_TESTING
unsigned long block_height_census_test_scans(void)
{
    pthread_mutex_lock(&g_mu);
    unsigned long n = g_scans;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void block_height_census_test_reset(void)
{
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < CENSUS_SLOTS; i++)
        g_census[i].valid = false;
    g_scans = 0;
    pthread_mutex_unlock(&g_mu);
}
#endif
