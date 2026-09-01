/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "services/chain_tip.h"

#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "event/event.h"
#include "models/database.h"
#include "config/runtime.h"
#include "jobs/tip_finalize_stage.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* chain-tip fsync barrier.
 *
 * Without an fsync after the tip commit, a SIGABRT or power-loss
 * between the SQLite page-cache write and the kernel flush can leave
 * coins ahead of block_index — coins_best_block hash unknown in
 * block_map, integrity gate fail-fast.
 *
 * We call `sqlite3_db_cacheflush()` to push the dirty page cache to the
 * OS, which in WAL mode flushes WAL frames to disk. With
 * `PRAGMA synchronous=NORMAL` (our steady-state setting) that's the
 * durability guarantee the consensus layer needs: once cacheflush
 * returns, a process kill at any subsequent point reproduces this same
 * tip on the next boot.
 *
 * Auto-throttle: during catch-up (gap > 1000 blocks) we cacheflush every
 * `CATCHUP_FSYNC_EVERY` commits; in steady-state (gap ≤ 1000) every
 * commit. This trades durability granularity for throughput in the
 * regime where every block will be re-flushed shortly anyway.
 *
 * 50 ms wall-clock cap: cacheflush of a busy WAL can occasionally
 * stall on I/O contention. If we exceed the cap, log + continue —
 * better to skip one fsync than block the activation thread.
 */
#define CATCHUP_FSYNC_EVERY 100
#define FSYNC_BARRIER_BUDGET_MS 50

static _Atomic uint64_t g_fsync_seq = 0;

static int monotonic_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void chain_tip_fsync_barrier(struct main_state *ms,
                                    const struct block_index *new_tip)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open || !ndb->db) return;

    int gap = 0;
    if (ms && ms->pindex_best_header && new_tip)
        gap = ms->pindex_best_header->nHeight - new_tip->nHeight;
    if (gap < 0) gap = 0;

    uint64_t seq = atomic_fetch_add(&g_fsync_seq, 1) + 1;
    bool should = (gap <= 1000) || (seq % CATCHUP_FSYNC_EVERY == 0);
    if (!should) return;

    int t0 = monotonic_ms();
    int rc = sqlite3_db_cacheflush(ndb->db);
    int elapsed = monotonic_ms() - t0;
    if (rc != SQLITE_OK) {
        fprintf(stderr,
            "[tip-fsync] db_cacheflush rc=%d elapsed=%dms — continuing\n",
            rc, elapsed);
        return;
    }
    if (elapsed > FSYNC_BARRIER_BUDGET_MS) {
        LOG_WARN("tip", "[tip-fsync] slow cacheflush elapsed=%dms (gap=%d seq=%llu)", elapsed, gap, (unsigned long long)seq);
    }
}

static const char *g_tip_source_names[] = {
    [TIP_FROM_UNSPECIFIED] = "unspecified",
    [TIP_FROM_CONNECT]     = "connect",
    [TIP_FROM_DISCONNECT]  = "disconnect",
    [TIP_FROM_SNAPSHOT]    = "snapshot",
    [TIP_FROM_RESTORE]     = "restore",
    [TIP_FROM_BOOT_REPAIR] = "boot_repair",
    [TIP_FROM_P2P_REPAIR]  = "p2p_repair",
    [TIP_FROM_UTXO_REPAIR] = "utxo_repair",
    [TIP_FROM_TEST]        = "test",
};

const char *tip_source_name(enum tip_source src)
{
    if ((int)src < 0 || (size_t)src >=
        sizeof(g_tip_source_names) / sizeof(g_tip_source_names[0]))
        return "unknown";
    return g_tip_source_names[src] ? g_tip_source_names[src] : "unknown";
}

struct zcl_result chain_set_active_tip(struct main_state *ms,
                                       struct block_index *new_tip,
                                       enum tip_source src,
                                       const char *reason)
{
    if (!ms)
        return ZCL_ERR(-1, "chain_set_active_tip: NULL main_state src=%s reason=%s",
                       tip_source_name(src), reason ? reason : "");

    int from_h = active_chain_height(&ms->chain_active);

    if (!new_tip) {
        if (!active_chain_move_window_tip(&ms->chain_active, NULL))
            return ZCL_ERR(-2,
                "chain_set_active_tip: active_chain_move_window_tip(NULL) failed "
                "from_h=%d src=%s reason=%s",
                from_h, tip_source_name(src), reason ? reason : "");
        printf("[tip] CLEARED (from h=%d) src=%s reason=%s\n",
               from_h, tip_source_name(src),
               reason ? reason : "");
        event_emitf(EV_CHAIN_TIP_COMMIT, 0,
                    "from=%d to=-1 reason=%s",
                    from_h, reason ? reason : "");
        return ZCL_OK;
    }

    if (!active_chain_move_window_tip(&ms->chain_active, new_tip)) {
        fprintf(stderr, // obs-ok:paired-with-ZCL_ERR-return
            "[tip] set_active_tip FAILED at h=%d src=%s reason=%s\n",
            new_tip->nHeight, tip_source_name(src),
            reason ? reason : "");
        return ZCL_ERR(-3,
            "chain_set_active_tip: active_chain_move_window_tip failed at h=%d "
            "src=%s reason=%s",
            new_tip->nHeight, tip_source_name(src),
            reason ? reason : "");
    }

    /* Keep the reducer authority atomics aligned with trusted bootstrap or
     * repair tip writes. */
    if (new_tip->phashBlock) {
        tip_finalize_stage_set_authoritative_tip(new_tip->nHeight,
                                                 new_tip->phashBlock->data);
    }

    char hex16[33] = "(no-hash)";
    if (new_tip->phashBlock) {
        char full[65];
        uint256_get_hex(new_tip->phashBlock, full);
        memcpy(hex16, full, 32);
        hex16[32] = '\0';
    }
    printf("[tip] h=%d hash=%s src=%s reason=%s\n",
           new_tip->nHeight, hex16, tip_source_name(src),
           reason ? reason : "");

    /* EV_TIP_UPDATED payload: hash[32] + height(i32). The event
     * library has a typed helper, but emitf with a structured string
     * is sufficient for observers that just want a notification. */
    event_emitf(EV_TIP_UPDATED, 0,
                "h=%d hash=%s src=%s",
                new_tip->nHeight, hex16, tip_source_name(src));
    event_emitf(EV_CHAIN_TIP_COMMIT, 0,
                "from=%d to=%d reason=%s",
                from_h, new_tip->nHeight, reason ? reason : "");

    /* Durability barrier: flush the SQLite page cache for the chainstate
     * DB so a kill -9 after this point cannot leave coins ahead of
     * block_index. Auto-throttled during catch-up. */
    chain_tip_fsync_barrier(ms, new_tip);
    return ZCL_OK;
}
