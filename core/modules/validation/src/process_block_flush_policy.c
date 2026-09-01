/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Flush policy + coins/Sapling persistence helpers for process_block.
 *
 * Contents:
 *   - g_flush_policy + tunable setter
 *   - g_coins_sqlite_ptr, g_sapling_tree_for_flush, g_sapling_ckpt_path
 *   - sapling_tree_persist_once
 *   - ZCL_TESTING hooks */

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "storage/node_db_runtime.h"
#include "validation/process_block.h"
#include "validation/main_logic.h"
#include "validation/connect_block.h"
#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/coins_view_sqlite.h"
#include "util/log_macros.h"

#include "process_block_internal.h"

/* `g_sapling_tree_rebuilding` is defined in engine/controllers/sync_controller.c
 * and declared in controllers/sync_controller.h (outside ZCL_TESTING),
 * but lib/ shouldn't pull the full controller header in. Mirror the
 * local-extern pattern already used in
 * engine/controllers/src/blockchain_controller_chain.c. Real fix is to
 * promote the global into a lib/-owned header — out of scope. */
extern _Atomic bool g_sapling_tree_rebuilding;

/* ── Flush policy ────────────────────────────────────────────
 * Controls when the in-memory UTXO cache writes to LevelDB.
 * Batching multiple blocks into one LevelDB write improves
 * throughput during IBD by 10-50x.
 *
 * Short-term (hot) layer: coins_view_cache accumulates changes.
 * Long-term (cold) layer: LevelDB receives batched writes.
 * The batch_block_interval controls how many blocks accumulate
 * before flushing — the bridge between the two layers. */
struct flush_policy {
    int64_t interval_secs;     /* max seconds between flushes (default 3600) */
    size_t  max_entries;       /* flush if cache exceeds this (default 500000) */
    int     block_interval;    /* flush every N blocks; 0 = disabled (default) */
};

static struct flush_policy g_flush_policy = {
    .interval_secs  = 3600,
    .max_entries    = 500000,
    .block_interval = 0,
};

static _Atomic int64_t g_blocks_since_sapling_save = 0;
static _Atomic int g_sapling_persist_fail_count = 0;
static _Atomic int g_sapling_persist_test_force_fail = 0;

/* SQLite handle for persisting UTXO commitment alongside flushes.
 * Set by boot.c via set_coins_sqlite_for_commitment(). */
static struct coins_view_sqlite *g_coins_sqlite_ptr = NULL;

void set_coins_sqlite_for_commitment(struct coins_view_sqlite *cvs)
{
    g_coins_sqlite_ptr = cvs;
}

/* Accessor used by core.c (process_block_get_coins_sqlite). */
struct coins_view_sqlite *process_block_coins_sqlite_ptr(void)
{
    return g_coins_sqlite_ptr;
}

/* Sapling tree pointer for persistence during flush.
 * Set by boot.c after loading tree from node_state. */
static struct incremental_merkle_tree *g_sapling_tree_for_flush = NULL;

void set_sapling_tree_for_flush(struct incremental_merkle_tree *tree)
{
    g_sapling_tree_for_flush = tree;
}

/* ── Flat-file sapling checkpoint ───────────────────────
 *
 * Optional path set by boot.c once datadir is known. When populated
 * and the sapling tree pointer above is also set, every
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL blocks we flush a self-contained
 * checkpoint to `<datadir>/sapling_tree_ckpt.dat`. Boot.c loads this
 * file before the node_state-backed rebuild path fires, so a healthy
 * checkpoint skips the 2.6M-block replay entirely.
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL is declared in
 * validation/process_block.h (exported, see below). */
static char g_sapling_ckpt_path[512] = {0};

void set_sapling_checkpoint_datadir(const char *datadir)
{
    if (!datadir || datadir[0] == '\0') {
        g_sapling_ckpt_path[0] = '\0';
        return;
    }
    int n = snprintf(g_sapling_ckpt_path, sizeof(g_sapling_ckpt_path),
                     "%s/sapling_tree_ckpt.dat", datadir);
    if (n < 0 || (size_t)n >= sizeof(g_sapling_ckpt_path))
        g_sapling_ckpt_path[0] = '\0';
}

const char *sapling_checkpoint_path(void)
{
    return g_sapling_ckpt_path[0] ? g_sapling_ckpt_path : NULL;
}

/* ── Flat-file checkpoint write wiring + diagnostics ─────────────
 *
 * The load/resume side already existed; this is the previously-missing
 * periodic WRITE. `g_blocks_since_flat_ckpt` counts note() calls; every
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL calls (or on `force`) the current tree
 * is serialized to the flat file keyed by {height, block_hash, root}.
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL itself is declared in
 * validation/process_block.h (exported so callers reasoning about the
 * checkpoint cadence — e.g. the reducer-cursor hook in
 * services/sapling_checkpoint_hook.c — never duplicate the magic number). */
static _Atomic int64_t g_blocks_since_flat_ckpt = 0;
static _Atomic int64_t g_ckpt_last_write_height = -1;
static _Atomic int64_t g_ckpt_writes = 0;
static _Atomic int64_t g_ckpt_write_fails = 0;
static _Atomic int64_t g_ckpt_last_load_height = -1;
static _Atomic int     g_ckpt_last_load_result = SAPLING_CKPT_LOAD_NONE;
static char            g_ckpt_last_load_detail[32] = {0};

bool sapling_tree_flat_checkpoint_note(
    const struct incremental_merkle_tree *tree, int64_t height,
    const uint8_t block_hash[32], bool force)
{
    if (!tree || g_sapling_ckpt_path[0] == '\0')
        return false;

    /* Bind to the reducer fold cursor: never stamp a checkpoint at a
     * height the reducer has not itself provably applied. coins_applied_
     * height is co-committed in the SAME transaction as every utxo_apply
     * cursor move (storage/coins_kv.h), so deriving from it here has no
     * cross-stage lag and is the exact "reducer fold cursor" every
     * verify-then-trust consumer of this file needs (the empty-frontier
     * healer's tier1 in-window check, and boot.c's own coins-applied
     * comparison endpoint). Checked BEFORE the interval/force logic below
     * and regardless of `force`, so a fast projection lane racing ahead of
     * utxo_apply (node_db_catchup_service is not gated on proof
     * validation) can never clobber a previously-good in-window checkpoint
     * with one that is no longer trustworthy. Fails OPEN when the frontier
     * cannot be derived (legacy/pre-migration datadir, or a hermetic
     * caller with no progress_store open) — unchanged prior behavior. */
    int32_t coins_best_h = -1;
    if (reducer_frontier_derive_coins_best_now(&coins_best_h, NULL, NULL) &&
        height > (int64_t)coins_best_h) {
        LOG_INFO("sapling_tree",
                 "flat_checkpoint_note: refusing h=%lld ahead of reducer "
                 "applied frontier h=%d — checkpoint stays bound to the "
                 "fold cursor, not the caller's own pace",
                 (long long)height, coins_best_h);
        return false;
    }

    int64_t since = atomic_fetch_add(&g_blocks_since_flat_ckpt, 1) + 1;
    if (!force && since < SAPLING_CHECKPOINT_BLOCK_INTERVAL)
        return false;
    atomic_store(&g_blocks_since_flat_ckpt, 0);

    bool ok = sapling_tree_flush_checkpoint(tree, height, block_hash,
                                            g_sapling_ckpt_path);
    if (ok) {
        atomic_store(&g_ckpt_last_write_height, height);
        atomic_fetch_add(&g_ckpt_writes, 1);
    } else {
        atomic_fetch_add(&g_ckpt_write_fails, 1);
        LOG_WARN("sapling_tree",
                 "flat_checkpoint_note: write failed at h=%lld path=%s",
                 (long long)height, g_sapling_ckpt_path);
    }
    return ok;
}

void sapling_ckpt_record_load(enum sapling_ckpt_load_result result,
                              int64_t height, const char *detail)
{
    atomic_store(&g_ckpt_last_load_height, height);
    atomic_store(&g_ckpt_last_load_result, (int)result);
    if (detail) {
        snprintf(g_ckpt_last_load_detail, sizeof(g_ckpt_last_load_detail),
                 "%s", detail);
    } else {
        g_ckpt_last_load_detail[0] = '\0';
    }
}

void sapling_ckpt_get_stats(struct sapling_ckpt_stats *out)
{
    if (!out) return;
    out->last_write_height = atomic_load(&g_ckpt_last_write_height);
    out->writes = atomic_load(&g_ckpt_writes);
    out->write_fails = atomic_load(&g_ckpt_write_fails);
    out->last_load_height = atomic_load(&g_ckpt_last_load_height);
    out->last_load_result = atomic_load(&g_ckpt_last_load_result);
    snprintf(out->last_load_detail, sizeof(out->last_load_detail), "%s",
             g_ckpt_last_load_detail);
    snprintf(out->path, sizeof(out->path), "%s", g_sapling_ckpt_path);
}

bool sapling_tree_persist_once(void)
{
    struct node_db *ndb = process_block_node_db_internal();
    if (!node_db_runtime_handle_open(ndb) || !g_sapling_tree_for_flush)
        return false;

    struct byte_stream ts;
    stream_init(&ts, 4096);
    bool serialized = incremental_tree_serialize(g_sapling_tree_for_flush, &ts);
    if (!serialized) {
        stream_free(&ts);
        return false;
    }

    bool persist_ok;
    int force_fail = atomic_fetch_sub(&g_sapling_persist_test_force_fail, 1);
    if (force_fail > 0) {
        persist_ok = false;
    } else {
        persist_ok = node_db_runtime_state_set(
            ndb, "sapling_tree", ts.data, ts.size);
        atomic_store(&g_sapling_persist_test_force_fail, 0);
    }
    stream_free(&ts);

    if (!persist_ok) {
        int fails = atomic_fetch_add(&g_sapling_persist_fail_count, 1) + 1;
        event_emitf(EV_SAPLING_PERSIST_FAIL, 0, "fails=%d", fails);
        if (fails >= 3) {
            atomic_store(&g_sapling_tree_rebuilding, true);
            atomic_store(&g_sapling_persist_fail_count, 0);
            return false;
        }
        return true;
    }

    atomic_store(&g_sapling_persist_fail_count, 0);
    g_blocks_since_sapling_save = 0;
    return true;
}

void set_flush_policy(int64_t interval_secs, size_t max_entries,
                      int block_interval)
{
    g_flush_policy.interval_secs = interval_secs;
    g_flush_policy.max_entries = max_entries;
    g_flush_policy.block_interval = block_interval;
    printf("flush_policy: interval=%llds max_entries=%zu block_interval=%d\n",
           (long long)interval_secs, max_entries, block_interval);
}

#ifdef ZCL_TESTING
void process_block_test_fail_next_sapling_persists(int n)
{
    atomic_store(&g_sapling_persist_test_force_fail, n);
}

bool process_block_test_persist_sapling_tree(bool force)
{
    (void)force;
    return sapling_tree_persist_once();
}
#endif
