/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Hold and persist the FlySync island-anchor fact; see
 * services/island_anchor.h for the contract. */

// one-result-type-ok:zcl-result-plus-pure-predicates — every fallible export
// (register, the progress_meta loads, save, retire, the state notes, the hold
// count) returns struct zcl_result with a typed island_anchor_err code; the
// bool exports left (registered, get, is_root, seed_root_work,
// refuses_fork_at) are total in-memory predicates over the registered fact,
// called per entry on the block-index load and reorg paths.

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
#define IA_HOLD_KEY "flysync.hold_boots"
#define IA_ROWS_KEY "flysync.island_rows.v1"
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

struct zcl_result island_anchor_register(const struct island_anchor *a)
{
    if (!ia_valid(a))
        return ZCL_ERR(ISLAND_ANCHOR_ERR_INVALID, "island anchor refused: "
                       "malformed fact");
    pthread_mutex_lock(&g_ia_lock);
    g_ia = *a;
    atomic_store(&g_ia_set, true);
    pthread_mutex_unlock(&g_ia_lock);
    LOG_INFO(IA_SUBSYS,
             "island anchor registered: root h=%d, rung h=%d",
             a->root_height, a->rung_height);
    return ZCL_OK;
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

static bool ia_rows_match(const struct island_anchor *a,
                          const struct island_anchor_rows *rows)
{
    return rows &&
           uint256_eq(&rows->hash[0], &a->root_hash) &&
           uint256_eq(&rows->hash[ISLAND_ANCHOR_WINDOW - 1], &a->rung_hash);
}

struct zcl_result island_anchor_save(struct sqlite3 *db,
                                     const struct island_anchor *a,
                                     const struct island_anchor_rows *rows)
{
    if (!db || !ia_valid(a) || !ia_rows_match(a, rows))
        return ZCL_ERR(-1, "island anchor save refused: %s",
                       !db ? "progress store not open" :
                       !ia_valid(a) ? "malformed fact" :
                       "row list does not run from the root to the rung");
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
                 progress_meta_set_in_tx(db, IA_ROWS_KEY, rows->hash,
                                         sizeof(rows->hash)) &&
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
    if (!progress_meta_delete(db, IA_FACT_KEY) ||
        !progress_meta_delete(db, IA_ROWS_KEY))
        return ZCL_ERR(-2, "island fact not retired: progress_meta delete "
                       "failed");
    LOG_INFO(IA_SUBSYS, "fallen-back island rejoined the chain; fact retired");
    return ZCL_OK;
}

/* Read one exact-length progress_meta blob: OK with *found false when absent,
 * UNREADABLE when the read fails, MALFORMED when the length is wrong. */
static struct zcl_result ia_blob_load(struct sqlite3 *db, const char *key,
                                      void *buf, size_t want, bool *found)
{
    bool have = false;
    size_t len = 0;
    *found = false;
    if (!db)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_UNREADABLE, "%s not read: progress "
                       "store not open", key);
    if (!progress_meta_get_blob_exact(db, key, buf, want, &len, &have))
        return ZCL_ERR(ISLAND_ANCHOR_ERR_UNREADABLE, "%s not read: "
                       "progress_meta read failed", key);
    if (have && len != want)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_MALFORMED, "%s has length %zu, want "
                       "%zu", key, len, want);
    *found = have;
    return ZCL_OK;
}

struct zcl_result island_anchor_load(struct sqlite3 *db,
                                     struct island_anchor *out, bool *found)
{
    bool have = false;
    if (found)
        *found = false;
    if (!out)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_INVALID, "island fact not loaded: no "
                       "output");
    uint8_t buf[IA_FACT_LEN];
    struct zcl_result r = ia_blob_load(db, IA_FACT_KEY, buf, sizeof(buf),
                                       &have);
    if (r.ok && have)
        ia_decode(buf, out);
    if (found)
        *found = r.ok && have;
    return r;
}

struct zcl_result island_anchor_rows_load(struct sqlite3 *db,
                                          struct island_anchor_rows *out,
                                          bool *found)
{
    bool have = false;
    if (found)
        *found = false;
    if (!out)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_INVALID, "island rows not loaded: no "
                       "output");
    struct zcl_result r = ia_blob_load(db, IA_ROWS_KEY, out->hash,
                                       sizeof(out->hash), &have);
    if (found)
        *found = r.ok && have;
    return r;
}

enum island_anchor_state island_anchor_state_load(struct sqlite3 *db)
{
    uint8_t v = 0;
    size_t len = 0;
    bool have = false;
    /* A failed read or a malformed value is UNREADABLE, never NONE: NONE
     * means "never a FlySync datadir", and a SEEDED island misread as fresh
     * could be written FELL_BACK for good. No progress store holds no state
     * at all (and nothing durable can be written to it). */
    if (!db)
        return ISLAND_ANCHOR_STATE_NONE;
    if (!progress_meta_get(db, IA_STATE_KEY, &v, 1, &len, &have)) {
        LOG_WARN(IA_SUBSYS, "island state unreadable: progress_meta read "
                 "failed");
        return ISLAND_ANCHOR_STATE_UNREADABLE;
    }
    if (!have)
        return ISLAND_ANCHOR_STATE_NONE;   /* save() writes both or neither */
    if (len == 1 && (v == ISLAND_ANCHOR_STATE_SEEDED ||
                     v == ISLAND_ANCHOR_STATE_FELL_BACK ||
                     v == ISLAND_ANCHOR_STATE_INSTALLED))
        return (enum island_anchor_state)v;
    LOG_WARN(IA_SUBSYS, "island state malformed (length %zu, value %u)", len,
             (unsigned)v);
    return ISLAND_ANCHOR_STATE_UNREADABLE;
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

struct zcl_result island_anchor_hold_recorded(struct sqlite3 *db, bool *held)
{
    uint8_t buf[8];
    size_t len = 0;
    bool have = false;
    if (!held)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_INVALID, "hold count not read: no "
                       "output");
    *held = false;
    if (!db)
        return ZCL_OK;   /* no progress store holds no hold (as state NONE) */
    if (!progress_meta_get(db, IA_HOLD_KEY, buf, sizeof(buf), &len, &have))
        return ZCL_ERR(ISLAND_ANCHOR_ERR_UNREADABLE, "FlySync hold count not "
                       "read: progress_meta read failed");
    *held = have && len == sizeof(buf);
    return ZCL_OK;
}

struct zcl_result island_anchor_hold_boot(struct sqlite3 *db, uint64_t *boots)
{
    if (boots)
        *boots = 0;
    if (!db || !boots)
        return ZCL_ERR(-1, "FlySync held boot not counted: progress store not "
                       "open");
    uint8_t buf[8];
    size_t len = 0;
    bool have = false;
    if (!progress_meta_table_ensure(db) ||
        !progress_meta_get(db, IA_HOLD_KEY, buf, sizeof(buf), &len, &have))
        return ZCL_ERR(-2, "FlySync held boots not read from progress_meta");
    uint64_t n = (have && len == sizeof(buf)) ? zcl_read_u64_le(buf) : 0;
    zcl_write_u64_le(buf, n + 1);
    if (!progress_meta_set(db, IA_HOLD_KEY, buf, sizeof(buf)))
        return ZCL_ERR(-3, "FlySync held boot not written to progress_meta");
    *boots = n + 1;
    return ZCL_OK;
}

struct zcl_result island_anchor_note_fallback(struct sqlite3 *db,
                                              const char *why)
{
    enum island_anchor_state st = island_anchor_state_load(db);
    if (st == ISLAND_ANCHOR_STATE_INSTALLED)
        return ZCL_ERR(-2, "FlySync fall-back refused: the rung bundle is "
                       "installed (%s)", why ? why : "unspecified");
    if (st == ISLAND_ANCHOR_STATE_UNREADABLE)
        return ZCL_ERR(-3, "FlySync fall-back refused: the island state is "
                       "unreadable, so it may be installed (%s)",
                       why ? why : "unspecified");
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

struct zcl_result island_anchor_boot_register(struct sqlite3 *db,
                                              bool *registered)
{
    if (registered)
        *registered = false;
    enum island_anchor_state st = island_anchor_state_load(db);
    if (st == ISLAND_ANCHOR_STATE_UNREADABLE)
        return ZCL_ERR(ISLAND_ANCHOR_ERR_UNREADABLE, "island state unreadable; "
                       "the island is not registered");
    if (st != ISLAND_ANCHOR_STATE_SEEDED && st != ISLAND_ANCHOR_STATE_INSTALLED)
        return ZCL_OK;
    struct island_anchor a;
    bool found = false;
    struct zcl_result r = island_anchor_load(db, &a, &found);
    if (r.ok && !found)
        r = ZCL_ERR(ISLAND_ANCHOR_ERR_MALFORMED, "the anchor fact is missing");
    if (r.ok)
        r = island_anchor_register(&a);
    if (!r.ok)
        return ZCL_ERR(r.code, "island state is %s but %s; the island is not "
                       "registered",
                       st == ISLAND_ANCHOR_STATE_INSTALLED ? "INSTALLED"
                                                           : "SEEDED",
                       r.message);
    if (registered)
        *registered = true;
    return ZCL_OK;
}
