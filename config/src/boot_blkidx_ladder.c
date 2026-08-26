/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: The block-index load ladder, folded out of config/src/boot.c
 * app_init into a const rung table. Each rung is { name, applicable, load,
 * post }; the driver iterates them in the SAME order the old hand-written
 * if/else chain ran, fires each applicable rung's load (+ optional post), and
 * bumps that rung's fire counter. The loader functions themselves are
 * unchanged — this file only owns the dispatch shape + the flat_union_tainted
 * guard (now a first-class context field) + the fire-counter dump_state entry.
 * Split out of boot.c for the E1 file-size ceiling (same seam pattern as
 * config/src/boot_legacy_import.c). */

#include "config/boot_blkidx_ladder.h"

#include "config/boot.h"                     /* app_context, boot_dispatch_blocks_table_hydrate */
#include "services/block_index_loader.h"     /* load_block_index* / rebuild / save_block_index_flat */
#include "storage/block_index_projection.h"  /* verified bound-delta preflight */
#include "models/block.h"                     /* db_block, db_block_find_by_height, db_block_max_height */
#include "controllers/sync_controller.h"      /* node_db_sync_get_tip_height / _hash */
#include "validation/main_state.h"            /* struct main_state, map_block_index */
#include "validation/chainstate.h"            /* block_index, block_map_find */
#include "chain/chain.h"                       /* struct uint256, block_index fields */
#include "event/event.h"                       /* event_emitf, EV_BOOT_BLOCK_INDEX */
#include "platform/time_compat.h"              /* platform_time_wall_time_t */
#include "json/json.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Rungs ──────────────────────────────────────────────────────────
 * Each rung keeps the EXACT applicability condition + action of the inline
 * ladder it replaces. `applicable` decides whether the rung runs at all;
 * `load` performs the (unchanged) loader call and folds the result into the
 * shared context; `post` runs after a successful applicability match (used
 * only by the LevelDB rung's flat_union_tainted-guarded flat re-save).
 * Ordering is authoritative and MUST match the original chain. */

/* Rung 0 — projection-as-authority rebuild (-rebuildfromlog).
 * Original guard: `ctx->boot_from_log && rebuild(...,1000,true).ok`. When it
 * accepts, rebuilt_from_log latches and every later rung is suppressed; on a
 * non-accept it falls through to the legacy loaders so a sparse/empty
 * projection never bricks boot. */
static bool rung_from_log_applicable(const struct boot_blkidx_load_ctx *c)
{
    return c->ctx->boot_from_log;
}
static bool rung_from_log_load(struct boot_blkidx_load_ctx *c)
{
    if (boot_try_rebuild_block_index_from_projection(
            c->st, c->params, 1000, /*publish_tip=*/true).ok) {
        c->rebuilt_from_log = true;
        c->loaded = true;
        return true;
    }
    return false;
}

/* Rung 1 — flat file (mmap, <2s). Unconditionally sets `loaded` from the
 * flat load result when the projection path did not win. */
static bool rung_flat_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log;
}
static bool rung_flat_load(struct boot_blkidx_load_ctx *c)
{
    c->loaded = load_block_index_flat(c->ctx->datadir, c->st).ok;
    return c->loaded;
}

/* Rung 2 — SQLite block_index cache. */
static bool rung_sqlite_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log && !c->loaded && c->ndb->open;
}
static bool rung_sqlite_load(struct boot_blkidx_load_ctx *c)
{
    c->loaded = load_block_index_sqlite(c->ndb, c->st).ok;
    return c->loaded;
}

/* Rung 3 — kill-9 recovery: a node SIGKILL'd with no clean shutdown never
 * wrote the flat/SQLite caches, so the legacy loaders above yield an
 * empty/genesis-only map. Rebuild PURELY from the durable per-block
 * block_index_projection, publish_tip=false (the coins/UTXO authority owns
 * the tip; the guarded forward seed advances it). Fires ONLY when the legacy
 * loaders came back empty (map.size<=1) — never reached on a real
 * multi-million-entry boot. */
static bool rung_kill9_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log && c->st->map_block_index.size <= 1;
}
static bool rung_kill9_load(struct boot_blkidx_load_ctx *c)
{
    if (boot_try_rebuild_block_index_from_projection(
            c->st, c->params, 1, /*publish_tip=*/false).ok) {
        c->loaded = true;
        return true;
    }
    return false;
}

/* Rung 4 — flat-union taint check (no load; a validation gate). If the loaded
 * flat file has far fewer entries than the chain (stale), drop `loaded` to
 * fall through to LevelDB. If the persisted sync tip hash maps to the WRONG
 * height in the loaded map, the flat is a corrupt union: drop `loaded` AND set
 * flat_union_tainted so the LevelDB rung's mid-boot flat re-save is suppressed
 * (persisting the union would launder the poison record into every future
 * boot — otherwise a height-0 stub can survive across boots).
 * The heal happens later this boot; the shutdown save persists
 * the healed map. */
static bool rung_taint_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log && c->loaded && c->ndb->open;
}
static bool rung_taint_load(struct boot_blkidx_load_ctx *c)
{
    int64_t db_height = node_db_sync_get_tip_height(c->ndb);
    if (db_height < 0)
        db_height = db_block_max_height(c->ndb);
    size_t flat_count = c->st->map_block_index.size;
    if (db_height > 0 && (int64_t)flat_count < db_height - 1000) {
        printf("Block index flat: stale (%zu entries vs chain height %lld)"
               " — reloading from LevelDB\n",
               flat_count, (long long)db_height);
        fflush(stdout);
        c->loaded = false;  /* fall through to LevelDB */
    }

    /* Consistency check: the persisted sync projection cursor must exist in
     * the loaded flat block index AT THE CORRECT HEIGHT. Use
     * node_state sync_projection_tip_hash/height first: the blocks table can
     * lag by a block after crash recovery or catchup flushing. */
    if (c->loaded && db_height > 0) {
        uint8_t tip_hash_raw[32];
        bool have_tip_hash = node_db_sync_get_tip_hash(c->ndb, tip_hash_raw);
        if (have_tip_hash) {
            struct uint256 tip_hash;
            memcpy(tip_hash.data, tip_hash_raw, 32);
            struct block_index *flat_tip =
                block_map_find(&c->st->map_block_index, &tip_hash);
            if (!flat_tip || (int64_t)flat_tip->nHeight != db_height) {
                bool absent_and_journaled = !flat_tip &&
                    db_height <= INT32_MAX &&
                    block_index_projection_bound_covers_tip(
                        block_index_projection_singleton(), c->ctx->datadir,
                        tip_hash_raw, (int32_t)db_height);
                if (absent_and_journaled) {
                    printf("Block index flat: authenticated snapshot predates "
                           "SQLite tip %lld; verified projection delta covers "
                           "the tip\n", (long long)db_height);
                } else {
                    fprintf(stderr,
                        "Block index flat: tip hash maps to wrong "
                        "height (%d vs SQLite %lld). Corrupt flat "
                        "file — reloading from SQLite.\n",
                        flat_tip ? flat_tip->nHeight : -1,
                        (long long)db_height);
                    c->loaded = false;
                    c->flat_union_tainted = true;
                }
            }
        } else {
            struct db_block tip_blk;
            if (db_block_find_by_height(c->ndb, (int)db_height, &tip_blk)) {
                struct uint256 tip_hash;
                memcpy(tip_hash.data, tip_blk.hash, 32);
                struct block_index *flat_tip =
                    block_map_find(&c->st->map_block_index, &tip_hash);
                if (!flat_tip || (int64_t)flat_tip->nHeight != db_height) {
                    bool absent_and_journaled = !flat_tip &&
                        db_height <= INT32_MAX &&
                        block_index_projection_bound_covers_tip(
                            block_index_projection_singleton(),
                            c->ctx->datadir, tip_blk.hash,
                            (int32_t)db_height);
                    if (absent_and_journaled) {
                        printf("Block index flat: authenticated snapshot "
                               "predates SQLite tip %lld; verified projection "
                               "delta covers the tip\n",
                               (long long)db_height);
                    } else {
                        fprintf(stderr,
                            "Block index flat: tip hash maps to wrong "
                            "height (%d vs SQLite %lld). Corrupt flat "
                            "file — reloading from SQLite.\n",
                            flat_tip ? flat_tip->nHeight : -1,
                            (long long)db_height);
                        c->loaded = false;
                        c->flat_union_tainted = true;
                    }
                }
            }
        }
    }
    return false;
}

/* Rung 5 — hydrate the map from the node.db `blocks` table (the
 * --importblockindex CLI's sink). Dispatch fires on blocks-table-vs-map-size,
 * NOT on `!loaded` alone, so a small STALE map from an earlier rung never
 * blocks it. Contract: boot_dispatch_blocks_table_hydrate
 * (config/src/boot_legacy_import.c). */
static bool rung_blocks_hydrate_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log;
}
static bool rung_blocks_hydrate_load(struct boot_blkidx_load_ctx *c)
{
    if (boot_dispatch_blocks_table_hydrate(c->ndb, c->st)) {
        c->loaded = true;
        return true;
    }
    return false;
}

/* Rung 6 — LevelDB (our block-tree). Last-resort full load; post = the
 * flat_union_tainted-guarded mid-boot flat re-save. */
static bool rung_leveldb_applicable(const struct boot_blkidx_load_ctx *c)
{
    return !c->rebuilt_from_log && !c->loaded;
}
static bool rung_leveldb_load(struct boot_blkidx_load_ctx *c)
{
    int64_t t_idx_start = (int64_t)platform_time_wall_time_t();
    printf("Loading block index from LevelDB...\n");
    if (!load_block_index(c->st, c->params, c->block_tree,
                          c->block_tree_open).ok) {
        fprintf(stderr, "Warning: Failed to load block index\n");
    }
    int64_t t_idx_elapsed = (int64_t)platform_time_wall_time_t() - t_idx_start;
    printf("Block index loaded: %zu entries in %llds\n",
           c->st->map_block_index.size, (long long)t_idx_elapsed);
    event_emitf(EV_BOOT_BLOCK_INDEX, 0, "loaded entries=%zu elapsed=%llds",
                c->st->map_block_index.size, (long long)t_idx_elapsed);
    return true;
}
static void rung_leveldb_post(struct boot_blkidx_load_ctx *c)
{
    /* Save flat file for next restart — UNLESS the map is a union with a
     * corrupt flat load (flat_union_tainted): the poison record is still in
     * RAM here, and persisting it now re-infects every future boot. The
     * shutdown save runs after the projection topup + height repair heal it. */
    if (c->st->map_block_index.size > 1000) {
        if (c->flat_union_tainted)
            printf("Block index flat: skipping mid-boot re-save of "
                   "the corrupt-flat union — the healed map is "
                   "persisted at shutdown\n");
        else
            save_block_index_flat(c->ctx->datadir, c->st);
    }
}

/* ── Rung table ─────────────────────────────────────────────────────── */

struct boot_blkidx_rung {
    const char *name;
    bool (*applicable)(const struct boot_blkidx_load_ctx *c);
    bool (*load)(struct boot_blkidx_load_ctx *c);
    void (*post)(struct boot_blkidx_load_ctx *c);
};

static const struct boot_blkidx_rung k_blkidx_rungs[] = {
    { "rebuild_from_log", rung_from_log_applicable,       rung_from_log_load,       NULL },
    { "flat",            rung_flat_applicable,            rung_flat_load,           NULL },
    { "sqlite",          rung_sqlite_applicable,          rung_sqlite_load,         NULL },
    { "kill9_projection", rung_kill9_applicable,          rung_kill9_load,          NULL },
    { "flat_union_taint_check", rung_taint_applicable,    rung_taint_load,          NULL },
    { "blocks_table_hydrate", rung_blocks_hydrate_applicable, rung_blocks_hydrate_load, NULL },
    { "leveldb",         rung_leveldb_applicable,         rung_leveldb_load,        rung_leveldb_post },
};
#define BOOT_BLKIDX_RUNG_COUNT \
    (sizeof(k_blkidx_rungs) / sizeof(k_blkidx_rungs[0]))

/* Per-rung cumulative fire counters (a rung "fires" when it is applicable and
 * its load runs). Touched by the boot thread (driver) and read by the
 * diagnostics thread (dumper) — atomics, per CLAUDE.md "Adding state
 * introspection". */
static _Atomic uint64_t g_rung_fires[BOOT_BLKIDX_RUNG_COUNT];
/* Last-run outcome flags (single-writer: the boot thread). */
static _Atomic bool g_last_rebuilt_from_log;
static _Atomic bool g_last_loaded;
static _Atomic bool g_last_flat_union_tainted;

void boot_blkidx_run_ladder(struct boot_blkidx_load_ctx *c)
{
    if (!c)
        return;
    for (size_t i = 0; i < BOOT_BLKIDX_RUNG_COUNT; i++) {
        const struct boot_blkidx_rung *r = &k_blkidx_rungs[i];
        if (r->applicable && !r->applicable(c))
            continue;
        atomic_fetch_add_explicit(&g_rung_fires[i], 1, memory_order_relaxed);
        if (r->load)
            (void)r->load(c);
        if (r->post)
            r->post(c);
    }
    atomic_store_explicit(&g_last_rebuilt_from_log, c->rebuilt_from_log,
                          memory_order_relaxed);
    atomic_store_explicit(&g_last_loaded, c->loaded, memory_order_relaxed);
    atomic_store_explicit(&g_last_flat_union_tainted, c->flat_union_tainted,
                          memory_order_relaxed);
}

bool boot_blkidx_rungs_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    uint64_t total = 0;
    for (size_t i = 0; i < BOOT_BLKIDX_RUNG_COUNT; i++) {
        uint64_t n = atomic_load_explicit(&g_rung_fires[i],
                                          memory_order_relaxed);
        total += n;
        json_push_kv_int(out, k_blkidx_rungs[i].name, (int64_t)n);
    }
    json_push_kv_int(out, "total_rung_fires", (int64_t)total);
    json_push_kv_bool(out, "last_rebuilt_from_log",
                      atomic_load_explicit(&g_last_rebuilt_from_log,
                                           memory_order_relaxed));
    json_push_kv_bool(out, "last_loaded",
                      atomic_load_explicit(&g_last_loaded,
                                           memory_order_relaxed));
    json_push_kv_bool(out, "last_flat_union_tainted",
                      atomic_load_explicit(&g_last_flat_union_tainted,
                                           memory_order_relaxed));
    return true;
}
