/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Hold and persist the FlySync island-anchor fact; see
 * services/island_anchor.h for the contract. */

#include "services/island_anchor.h"

#include "chain/chain.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define IA_SUBSYS "flysync"
#define IA_FACT_KEY "flysync.island_anchor.v1"
#define IA_STATE_KEY "flysync.island_state"
#define IA_FACT_LEN (4 + 32 + 32 + 4 + 32)

static pthread_mutex_t g_ia_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_ia_set = false;
static struct island_anchor g_ia;   /* guarded by g_ia_lock */

static bool ia_valid(const struct island_anchor *a)
{
    return a && a->root_height > 0 &&
           a->rung_height == a->root_height + ISLAND_ANCHOR_WINDOW - 1 &&
           !uint256_is_null(&a->root_hash) &&
           !uint256_is_null(&a->rung_hash) &&
           !arith_uint256_is_zero(&a->root_work);
}

bool island_anchor_register(const struct island_anchor *a)
{
    if (!ia_valid(a)) {
        LOG_WARN(IA_SUBSYS, "island anchor refused: malformed fact");
        return false;
    }
    pthread_mutex_lock(&g_ia_lock);
    g_ia = *a;
    atomic_store(&g_ia_set, true);
    pthread_mutex_unlock(&g_ia_lock);
    LOG_INFO(IA_SUBSYS,
             "island anchor registered: root h=%d, rung h=%d",
             a->root_height, a->rung_height);
    return true;
}

void island_anchor_unregister(void)
{
    pthread_mutex_lock(&g_ia_lock);
    atomic_store(&g_ia_set, false);
    memset(&g_ia, 0, sizeof(g_ia));
    pthread_mutex_unlock(&g_ia_lock);
}

bool island_anchor_registered(void)
{
    return atomic_load(&g_ia_set);
}

bool island_anchor_get(struct island_anchor *out)
{
    if (!out || !atomic_load(&g_ia_set))
        return false;
    pthread_mutex_lock(&g_ia_lock);
    bool have = atomic_load(&g_ia_set);
    if (have)
        *out = g_ia;
    pthread_mutex_unlock(&g_ia_lock);
    return have;
}

bool island_anchor_is_root(const struct block_index *bi)
{
    struct island_anchor a;
    if (!bi || !bi->phashBlock || !island_anchor_get(&a))
        return false;
    return bi->nHeight == a.root_height &&
           uint256_eq(bi->phashBlock, &a.root_hash);
}

bool island_anchor_seed_root_work(struct block_index *bi)
{
    struct island_anchor a;
    if (!bi || bi->pprev || !bi->phashBlock || !island_anchor_get(&a))
        return false;
    if (bi->nHeight != a.root_height || !uint256_eq(bi->phashBlock, &a.root_hash))
        return false;
    bi->nChainWork = a.root_work;
    return true;
}

bool island_anchor_refuses_fork_at(int32_t fork_height)
{
    struct island_anchor a;
    return island_anchor_get(&a) && fork_height < a.rung_height;
}

void island_anchor_work_from_be(struct arith_uint256 *out,
                                const uint8_t be[32])
{
    for (int limb = 0; limb < ARITH_UINT256_WIDTH; limb++) {
        int at = 28 - 4 * limb;
        out->pn[limb] = ((uint32_t)be[at] << 24) | ((uint32_t)be[at + 1] << 16) |
                        ((uint32_t)be[at + 2] << 8) | (uint32_t)be[at + 3];
    }
}

static void ia_put32(uint8_t *p, int32_t v)
{
    uint32_t u = (uint32_t)v;
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(u >> (8 * i));
}

static int32_t ia_get32(const uint8_t *p)
{
    uint32_t u = 0;
    for (int i = 0; i < 4; i++)
        u |= (uint32_t)p[i] << (8 * i);
    return (int32_t)u;
}

static void ia_encode(const struct island_anchor *a, uint8_t out[IA_FACT_LEN])
{
    ia_put32(out, a->root_height);
    memcpy(out + 4, a->root_hash.data, 32);
    for (int l = 0; l < ARITH_UINT256_WIDTH; l++)
        ia_put32(out + 36 + 4 * l, (int32_t)a->root_work.pn[l]);
    ia_put32(out + 68, a->rung_height);
    memcpy(out + 72, a->rung_hash.data, 32);
}

static void ia_decode(const uint8_t in[IA_FACT_LEN], struct island_anchor *a)
{
    memset(a, 0, sizeof(*a));
    a->root_height = ia_get32(in);
    memcpy(a->root_hash.data, in + 4, 32);
    for (int l = 0; l < ARITH_UINT256_WIDTH; l++)
        a->root_work.pn[l] = (uint32_t)ia_get32(in + 36 + 4 * l);
    a->rung_height = ia_get32(in + 68);
    memcpy(a->rung_hash.data, in + 72, 32);
}

static bool ia_state_save(struct sqlite3 *db, enum island_anchor_state st)
{
    uint8_t v = (uint8_t)st;
    return progress_meta_set(db, IA_STATE_KEY, &v, 1);
}

bool island_anchor_save(struct sqlite3 *db, const struct island_anchor *a)
{
    if (!db || !ia_valid(a)) {
        LOG_WARN(IA_SUBSYS, "island anchor save refused: %s",
                 db ? "malformed fact" : "progress store not open");
        return false;
    }
    uint8_t buf[IA_FACT_LEN];
    ia_encode(a, buf);
    if (!progress_meta_table_ensure(db) ||
        !progress_meta_set(db, IA_FACT_KEY, buf, sizeof(buf)) ||
        !ia_state_save(db, ISLAND_ANCHOR_STATE_SEEDED)) {
        LOG_WARN(IA_SUBSYS, "island anchor save failed (root h=%d)",
                 a->root_height);
        return false;
    }
    return true;
}

bool island_anchor_load(struct sqlite3 *db, struct island_anchor *out,
                        bool *found)
{
    if (found)
        *found = false;
    if (!db || !out)
        return false;
    uint8_t buf[IA_FACT_LEN];
    size_t len = 0;
    bool have = false;
    if (!progress_meta_get_blob_exact(db, IA_FACT_KEY, buf, sizeof(buf),
                                      &len, &have))
        return false;
    if (!have)
        return true;
    if (len != sizeof(buf)) {
        LOG_WARN(IA_SUBSYS, "island anchor fact has length %zu, want %d",
                 len, IA_FACT_LEN);
        return false;
    }
    ia_decode(buf, out);
    if (found)
        *found = true;
    return true;
}

enum island_anchor_state island_anchor_state_load(struct sqlite3 *db)
{
    uint8_t v = 0;
    size_t len = 0;
    bool have = false;
    if (!db || !progress_meta_get(db, IA_STATE_KEY, &v, 1, &len, &have))
        return ISLAND_ANCHOR_STATE_NONE;
    if (!have || len != 1) {
        /* save() writes the fact before the state: a fact without a state is
         * a seed interrupted between the two writes, and the fact stands. */
        struct island_anchor a;
        bool found = false;
        return island_anchor_load(db, &a, &found) && found && ia_valid(&a)
                   ? ISLAND_ANCHOR_STATE_SEEDED
                   : ISLAND_ANCHOR_STATE_NONE;
    }
    if (v == ISLAND_ANCHOR_STATE_SEEDED || v == ISLAND_ANCHOR_STATE_FELL_BACK)
        return (enum island_anchor_state)v;
    return ISLAND_ANCHOR_STATE_NONE;
}

bool island_anchor_note_fallback(struct sqlite3 *db, const char *why)
{
    island_anchor_unregister();
    bool ok = db && progress_meta_table_ensure(db) &&
              ia_state_save(db, ISLAND_ANCHOR_STATE_FELL_BACK);
    LOG_WARN(IA_SUBSYS,
             "FlySync falls back to normal sync: %s (state %s)",
             why ? why : "unspecified", ok ? "recorded" : "NOT recorded");
    return ok;
}

bool island_anchor_boot_register(struct sqlite3 *db)
{
    if (island_anchor_state_load(db) != ISLAND_ANCHOR_STATE_SEEDED)
        return false;
    struct island_anchor a;
    bool found = false;
    if (!island_anchor_load(db, &a, &found) || !found) {
        LOG_WARN(IA_SUBSYS,
                 "island state is SEEDED but the anchor fact is unreadable; "
                 "the island is not registered");
        return false;
    }
    return island_anchor_register(&a);
}
