/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Hold and persist the FlySync island-anchor fact; see
 * services/island_anchor.h for the contract. */

#include "services/island_anchor.h"

#include "base/serialize_le.h"
#include "chain/chain.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

#define IA_SUBSYS "flysync"
#define IA_FACT_KEY "flysync.island_anchor.v1"
#define IA_STATE_KEY "flysync.island_state"
#define IA_HOLD_KEY "flysync.hold_since"
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
    for (int limb = 0; limb < ARITH_UINT256_WIDTH; limb++)
        out->pn[limb] = zcl_read_u32_be(be + 28 - 4 * limb);
}

static void ia_encode(const struct island_anchor *a, uint8_t out[IA_FACT_LEN])
{
    zcl_write_i32_le(out, a->root_height);
    memcpy(out + 4, a->root_hash.data, 32);
    for (int l = 0; l < ARITH_UINT256_WIDTH; l++)
        zcl_write_u32_le(out + 36 + 4 * l, a->root_work.pn[l]);
    zcl_write_i32_le(out + 68, a->rung_height);
    memcpy(out + 72, a->rung_hash.data, 32);
}

static void ia_decode(const uint8_t in[IA_FACT_LEN], struct island_anchor *a)
{
    memset(a, 0, sizeof(*a));
    a->root_height = zcl_read_i32_le(in);
    memcpy(a->root_hash.data, in + 4, 32);
    for (int l = 0; l < ARITH_UINT256_WIDTH; l++)
        a->root_work.pn[l] = zcl_read_u32_le(in + 36 + 4 * l);
    a->rung_height = zcl_read_i32_le(in + 68);
    memcpy(a->rung_hash.data, in + 72, 32);
}

static bool ia_exec(struct sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK)
        LOG_WARN(IA_SUBSYS, "island anchor %s failed: %s", sql,
                 err ? err : sqlite3_errstr(rc));
    sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool ia_state_save(struct sqlite3 *db, enum island_anchor_state st)
{
    uint8_t v = (uint8_t)st;
    return progress_meta_set(db, IA_STATE_KEY, &v, 1);
}

struct zcl_result island_anchor_save(struct sqlite3 *db,
                                     const struct island_anchor *a)
{
    if (!db || !ia_valid(a))
        return ZCL_ERR(-1, "island anchor save refused: %s",
                       db ? "malformed fact" : "progress store not open");
    uint8_t buf[IA_FACT_LEN];
    ia_encode(a, buf);
    if (!progress_meta_table_ensure(db))
        return ZCL_ERR(-2, "island anchor save failed: progress_meta table "
                       "not ensured (root h=%d)", a->root_height);
    /* The fact and its SEEDED state commit together: never one without the
     * other. */
    uint8_t st = (uint8_t)ISLAND_ANCHOR_STATE_SEEDED;
    progress_store_tx_lock();
    bool begun = ia_exec(db, "BEGIN IMMEDIATE");
    bool wrote = begun &&
                 progress_meta_set_in_tx(db, IA_FACT_KEY, buf, sizeof(buf)) &&
                 progress_meta_set_in_tx(db, IA_STATE_KEY, &st, 1);
    bool committed = wrote && ia_exec(db, "COMMIT");
    if (begun && !committed)
        (void)ia_exec(db, "ROLLBACK");
    progress_store_tx_unlock();
    if (!committed)
        return ZCL_ERR(-3, "island anchor save failed: the fact and its state "
                       "did not commit (root h=%d)", a->root_height);
    return ZCL_OK;
}

/* Retire the fact once its rows have rejoined the chain (fall-back only). */
struct zcl_result island_anchor_retire(struct sqlite3 *db)
{
    if (island_anchor_state_load(db) != ISLAND_ANCHOR_STATE_FELL_BACK)
        return ZCL_ERR(-1, "island fact not retired: state is not FELL_BACK");
    if (!progress_meta_delete(db, IA_FACT_KEY))
        return ZCL_ERR(-2, "island fact not retired: progress_meta delete "
                       "failed");
    LOG_INFO(IA_SUBSYS, "fallen-back island rejoined the chain; fact retired");
    return ZCL_OK;
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
    if (!have || len != 1)
        return ISLAND_ANCHOR_STATE_NONE;   /* save() writes both or neither */
    if (v == ISLAND_ANCHOR_STATE_SEEDED || v == ISLAND_ANCHOR_STATE_FELL_BACK ||
        v == ISLAND_ANCHOR_STATE_INSTALLED)
        return (enum island_anchor_state)v;
    return ISLAND_ANCHOR_STATE_NONE;
}

struct zcl_result island_anchor_note_installed(struct sqlite3 *db)
{
    enum island_anchor_state st = island_anchor_state_load(db);
    if (st == ISLAND_ANCHOR_STATE_INSTALLED)
        return ZCL_OK;
    if (st != ISLAND_ANCHOR_STATE_SEEDED)
        return ZCL_ERR(-1, "island install not recorded: state is %d, not "
                       "SEEDED", (int)st);
    if (!ia_state_save(db, ISLAND_ANCHOR_STATE_INSTALLED))
        return ZCL_ERR(-2, "island install not recorded: progress_meta write "
                       "failed");
    LOG_INFO(IA_SUBSYS, "island state INSTALLED recorded");
    return ZCL_OK;
}

bool island_anchor_hold_recorded(struct sqlite3 *db)
{
    uint8_t buf[8];
    size_t len = 0;
    bool have = false;
    return db && progress_meta_get(db, IA_HOLD_KEY, buf, sizeof(buf), &len,
                                   &have) && have && len == sizeof(buf);
}

struct zcl_result island_anchor_hold_since(struct sqlite3 *db, int64_t now_s,
                                           int64_t *since_s)
{
    if (since_s)
        *since_s = now_s;
    if (!db || !since_s)
        return ZCL_ERR(-1, "FlySync hold start not read: progress store not "
                       "open");
    uint8_t buf[8];
    size_t len = 0;
    bool have = false;
    if (!progress_meta_table_ensure(db) ||
        !progress_meta_get(db, IA_HOLD_KEY, buf, sizeof(buf), &len, &have))
        return ZCL_ERR(-2, "FlySync hold start not read from progress_meta");
    if (have && len == sizeof(buf)) {
        *since_s = (int64_t)zcl_read_u64_le(buf);
        return ZCL_OK;
    }
    zcl_write_u64_le(buf, (uint64_t)now_s);
    if (!progress_meta_set(db, IA_HOLD_KEY, buf, sizeof(buf)))
        return ZCL_ERR(-3, "FlySync hold start not written to progress_meta");
    return ZCL_OK;
}

struct zcl_result island_anchor_note_fallback(struct sqlite3 *db,
                                              const char *why)
{
    if (island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_INSTALLED)
        return ZCL_ERR(-2, "FlySync fall-back refused: the rung bundle is "
                       "installed (%s)", why ? why : "unspecified");
    island_anchor_unregister();
    bool ok = db && progress_meta_table_ensure(db) &&
              ia_state_save(db, ISLAND_ANCHOR_STATE_FELL_BACK);
    LOG_WARN(IA_SUBSYS,
             "FlySync falls back to normal sync: %s (state %s)",
             why ? why : "unspecified", ok ? "recorded" : "NOT recorded");
    if (!ok)
        return ZCL_ERR(-1, "FlySync fall-back state not recorded (%s)",
                       db ? "progress_meta write failed"
                          : "progress store not open");
    return ZCL_OK;
}

bool island_anchor_boot_register(struct sqlite3 *db)
{
    enum island_anchor_state st = island_anchor_state_load(db);
    if (st != ISLAND_ANCHOR_STATE_SEEDED && st != ISLAND_ANCHOR_STATE_INSTALLED)
        return false;
    struct island_anchor a;
    bool found = false;
    if (!island_anchor_load(db, &a, &found) || !found) {
        LOG_WARN(IA_SUBSYS,
                 "island state is %s but the anchor fact is unreadable; "
                 "the island is not registered",
                 st == ISLAND_ANCHOR_STATE_INSTALLED ? "INSTALLED" : "SEEDED");
        return false;
    }
    return island_anchor_register(&a);
}
