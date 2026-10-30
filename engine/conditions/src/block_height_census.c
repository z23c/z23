/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: per-height block census that lets self-heal conditions find blocks
 * at tip+1 without scanning the whole block map on every poll. */

#include "conditions/block_height_census.h"

#include "chain/chain.h"
#include "platform/time_compat.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define CENSUS_CAP 32
/* A census older than this is rebuilt even when nothing visible changed.
 * `nHeight` is written after map insertion and rewritten by header relinks
 * and height repair (in sealed core/ and in many engine files), so there is
 * no single write site to count. A block that gains height H after the census
 * was taken therefore stays unseen for at most this long; a block that loses
 * height H is dropped at once by the live `nHeight` re-check in
 * block_height_find(). */
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
    bool overflow; /* more than CENSUS_CAP blocks: scan, do not store */
    struct block_index *items[CENSUS_CAP];
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define CENSUS_SLOTS 4
static struct census g_census[CENSUS_SLOTS];
static unsigned g_next_slot;
static unsigned long g_scans;

#ifdef ZCL_TESTING
static int64_t (*g_test_clock)(void);
#endif

static int64_t mono_secs(void)
{
#ifdef ZCL_TESTING
    if (g_test_clock)
        return g_test_clock();
#endif
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

/* Gather every block at `height`. A height holding more blocks than the census
 * stores is recorded as an overflow marker, valid until the map size changes,
 * so the caller scans once per call instead of twice. The map size is
 * recorded before the walk so an insertion during it forces the next call to
 * rescan. */
static void census_fill(struct census *c, struct main_state *ms, int height,
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
    c->overflow = false;
    g_scans++;

    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(c->map, &iter, NULL, &p)) {
        if (!p || p->nHeight != height)
            continue;
        if (c->n == CENSUS_CAP) {
            c->overflow = true;
            break;
        }
        c->items[c->n++] = p;
    }
    c->valid = true;
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
        census_fill(c, ms, height, tip);
    }
    bool scan = c->overflow;
    for (size_t i = 0; !scan && i < c->n && !found; i++) {
        /* Live re-check: a relink or height repair may have moved the block. */
        if (c->items[i]->nHeight == height && pred(c->items[i], ctx))
            found = c->items[i];
    }
    pthread_mutex_unlock(&g_mu);
    return scan ? scan_find(ms, height, pred, ctx) : found;
}

#ifdef ZCL_TESTING
unsigned long block_height_census_test_scans(void)
{
    pthread_mutex_lock(&g_mu);
    unsigned long n = g_scans;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void block_height_census_test_set_clock(int64_t (*fn)(void))
{
    pthread_mutex_lock(&g_mu);
    g_test_clock = fn;
    pthread_mutex_unlock(&g_mu);
}

void block_height_census_test_reset(void)
{
    pthread_mutex_lock(&g_mu);
    g_test_clock = NULL;
    for (int i = 0; i < CENSUS_SLOTS; i++)
        g_census[i].valid = false;
    g_scans = 0;
    pthread_mutex_unlock(&g_mu);
}
#endif
