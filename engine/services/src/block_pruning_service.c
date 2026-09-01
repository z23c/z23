// one-result-type-ok:json-dump-bool — E2 (one way out): the sole remaining
// Dump-state export: block_pruning_dump_state_json.
// dumper. The dump convention (CLAUDE.md "Adding state introspection")
// mandates a bool return (false = couldn't populate), not struct zcl_result;
// every other fallible surface in this file already returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Pruning Service — see header for design rationale.
 *
 * Implementation
 * --------------
 * Each pruning pass walks the active chain from height 0 upward,
 * collecting which blk*.dat file numbers contain only blocks that
 * are deep enough to prune (deeper than chain_height - keep_blocks).
 *
 * A file is prunable when the highest block it contains is below
 * the prune cutoff. We scan the chain to find the maximum height
 * stored in each file number, then delete files whose max height
 * is below the cutoff.
 *
 * After deleting a file, we walk the chain again and clear
 * BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO on every block_index that
 * referenced the deleted file.
 */

#include "platform/time_compat.h"
#include "services/block_pruning_service.h"

#include "chain/chain.h"
#include "event/event.h"
#include "json/json.h"
#include "supervisors/domains.h"
#include "sync/sync_state.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

/* ── Global instance pointer ───────────────────────────────── */

struct block_pruning_service *g_block_pruning = NULL;

static struct liveness_contract g_prune_contract;
static _Atomic supervisor_child_id g_prune_supervisor_id =
    SUPERVISOR_INVALID_ID;

/* Maximum file number we'll ever scan. blk files are 0..99998,
 * and 255 is the special sync file (never pruned). */
#define MAX_FILE_NUM 100000

/* Track the max height stored in each blk file. We use a
 * dynamically allocated array sized to the highest file number
 * actually seen. */
struct file_height_map {
    int *max_height;   /* max_height[file_num] = highest block height in that file */
    int  capacity;     /* number of slots allocated */
};

static bool file_height_map_init(struct file_height_map *m, int cap)
{
    if (cap <= 0) cap = 64;
    m->max_height = zcl_malloc((size_t)cap * sizeof(int), "prune_file_map");
    if (!m->max_height)
        return false;
    m->capacity = cap;
    for (int i = 0; i < cap; i++)
        m->max_height[i] = -1;
    return true;
}

static bool file_height_map_ensure(struct file_height_map *m, int file_num)
{
    if (file_num < m->capacity)
        return true;
    int new_cap = m->capacity * 2;
    if (new_cap <= file_num) new_cap = file_num + 16;
    int *p = zcl_realloc(m->max_height, (size_t)new_cap * sizeof(int), "prune_file_map");
    if (!p)
        return false;
    for (int i = m->capacity; i < new_cap; i++)
        p[i] = -1;
    m->max_height = p;
    m->capacity = new_cap;
    return true;
}

static void file_height_map_free(struct file_height_map *m)
{
    free(m->max_height);
    m->max_height = NULL;
    m->capacity = 0;
}

static void file_height_map_record(struct file_height_map *m,
                                   int file_num, int height)
{
    if (file_num < 0 || file_num >= MAX_FILE_NUM) return;
    if (!file_height_map_ensure(m, file_num)) return;
    if (height > m->max_height[file_num])
        m->max_height[file_num] = height;
}

static int64_t block_pruning_progress_marker(
    const struct block_pruning_service *svc)
{
    if (!svc) return 0;
    return atomic_load(&svc->blocks_pruned);
}

static int64_t block_pruning_deadline_secs(
    const struct block_pruning_service *svc)
{
    int tick = svc && svc->tick_seconds > 0
        ? svc->tick_seconds
        : BLOCK_PRUNING_DEFAULT_TICK_SECONDS;
    return (int64_t)tick * 3 + 30;
}

static void block_pruning_supervisor_heartbeat(
    struct block_pruning_service *svc)
{
    supervisor_child_id id = atomic_load(&g_prune_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_progress(id, block_pruning_progress_marker(svc));
    supervisor_tick(id);
}

static void block_pruning_on_stall(struct liveness_contract *c)
{
    struct block_pruning_service *svc =
        c ? (struct block_pruning_service *)c->ctx : NULL;
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int64_t blocks = svc ? atomic_load(&svc->blocks_pruned) : 0;
    int64_t files = svc ? atomic_load(&svc->files_pruned) : 0;
    int64_t bytes = svc ? atomic_load(&svc->bytes_reclaimed) : 0;
    LOG_WARN("prune",
             "[prune] supervisor stall reason=%s blocks=%lld files=%lld bytes=%lld",
             reason, (long long)blocks, (long long)files, (long long)bytes);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "source=chain.block_pruning decision=worker_stall "
                "reason=%s blocks=%lld files=%lld bytes=%lld",
                reason, (long long)blocks, (long long)files,
                (long long)bytes);
}

static struct zcl_result block_pruning_register_supervisor(
    struct block_pruning_service *svc)
{
    if (!svc)
        return ZCL_ERR(-1, "block_pruning: supervisor register: null svc");
    if (!supervisor_start())
        return ZCL_ERR(-2, "block_pruning: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_prune_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        g_prune_contract.ctx = svc;
        supervisor_set_period(id, 0);
        supervisor_set_deadline(id, block_pruning_deadline_secs(svc));
        supervisor_set_progress_max_quiet(id, 0);
        block_pruning_supervisor_heartbeat(svc);
        return ZCL_OK;
    }

    liveness_contract_init(&g_prune_contract, "chain.block_pruning");
    atomic_store(&g_prune_contract.period_secs, 0);
    atomic_store(&g_prune_contract.deadline_secs,
                 block_pruning_deadline_secs(svc));
    atomic_store(&g_prune_contract.progress_max_quiet_us, 0);
    g_prune_contract.ctx = svc;
    g_prune_contract.on_tick = NULL;
    g_prune_contract.on_stall = block_pruning_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_prune_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-3, "block_pruning: supervisor_register failed");
    atomic_store(&g_prune_supervisor_id, id);
    block_pruning_supervisor_heartbeat(svc);
    return ZCL_OK;
}

/* Get file size, returns 0 on error. */
static int64_t file_size_or_zero(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (int64_t)st.st_size;
}

/* ── Core pruning logic ────────────────────────────────────── */

/* Shared prune-below-height core for both entry points: run_once's
 * keep_blocks-depth cadence and prune_sealed_range's segment-gated cadence.
 * `prune_below` is the exclusive height boundary — a file is prunable only
 * when the highest block it contains is strictly below it. */
static int block_pruning_run_below(struct block_pruning_service *svc,
                                   int chain_height, int prune_below)
{
    if (prune_below <= 0)
        return 0;  /* nothing old enough yet */

    /* Phase 1: Build map of file_num → max block height. */
    struct file_height_map fmap;
    if (!file_height_map_init(&fmap, 64))
        return 0;

    int lowest_have = chain_height;
    for (int h = 0; h <= chain_height; h++) {
        struct block_index *bi = active_chain_at(&svc->ms->chain_active, h);
        if (!bi) continue;
        if (!(bi->nStatus & BLOCK_HAVE_DATA)) continue;

        int fn = bi->nFile;
        if (fn == 255) continue;  /* never prune sync file */
        if (fn == 0)   continue;  /* never prune file 0 (genesis) */

        file_height_map_record(&fmap, fn, h);
        if (h < lowest_have) lowest_have = h;
    }
    atomic_store(&svc->lowest_have_data, lowest_have);

    /* Phase 2: Delete files where max_height < prune_below. */
    int files_pruned_this_pass = 0;
    for (int fn = 1; fn < fmap.capacity; fn++) {
        if (fmap.max_height[fn] < 0)   continue;  /* no blocks in this file */
        if (fmap.max_height[fn] >= prune_below) continue;  /* too recent */

        /* Delete blk file */
        char blk_path[512], rev_path[512];
        struct disk_block_pos pos = { .nFile = fn, .nPos = 0 };
        get_block_pos_filename(blk_path, sizeof(blk_path), svc->datadir, &pos, "blk");
        get_block_pos_filename(rev_path, sizeof(rev_path), svc->datadir, &pos, "rev");

        int64_t blk_sz = file_size_or_zero(blk_path);
        int64_t rev_sz = file_size_or_zero(rev_path);

        /* Invalidate the file cache and delete under lock to prevent
         * concurrent readers from hitting a deleted file → SIGSEGV.
         * Uses the `_while_locked` variant because the public
         * `disk_block_io_close_cache` re-enters the same NORMAL
         * mutex and would self-deadlock. */
        disk_block_io_lock();
        disk_block_io_close_cache_while_locked();
        bool blk_ok = (unlink(blk_path) == 0 || errno == ENOENT);
        bool rev_ok = (unlink(rev_path) == 0 || errno == ENOENT);
        disk_block_io_unlock();

        if (!blk_ok) {
            LOG_WARN("prune", "[prune] %s:%d %s(): failed to delete %s: %s", __FILE__, __LINE__, __func__, blk_path, strerror(errno));
            continue;
        }

        int64_t freed = blk_sz + (rev_ok ? rev_sz : 0);
        files_pruned_this_pass++;
        atomic_fetch_add(&svc->files_pruned, rev_ok ? 2 : 1);
        atomic_fetch_add(&svc->bytes_reclaimed, freed);

        /* Phase 3: Clear BLOCK_HAVE_DATA/UNDO flags on affected blocks. */
        int blocks_cleared = 0;
        for (int h = 0; h <= chain_height; h++) {
            struct block_index *bi = active_chain_at(&svc->ms->chain_active, h);
            if (!bi) continue;
            if (bi->nFile != fn) continue;
            if (bi->nStatus & BLOCK_HAVE_DATA) {
                bi->nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
                blocks_cleared++;
            }
            if (bi->nStatus & BLOCK_HAVE_UNDO)
                bi->nStatus &= ~(unsigned int)BLOCK_HAVE_UNDO;
        }
        atomic_fetch_add(&svc->blocks_pruned, blocks_cleared);

        event_emitf(EV_BLOCK_PRUNING_DONE, 0,
                    "file=%d max_height=%d freed=%lld blocks=%d",
                    fn, fmap.max_height[fn], (long long)freed, blocks_cleared);
        printf("[prune] deleted blk%05d.dat (max_h=%d, freed=%lld bytes, %d blocks)\n",
               fn, fmap.max_height[fn], (long long)freed, blocks_cleared);
    }

    /* Update lowest_have_data after pruning */
    lowest_have = chain_height;
    for (int h = 0; h <= chain_height; h++) {
        struct block_index *bi = active_chain_at(&svc->ms->chain_active, h);
        if (!bi) continue;
        if (bi->nStatus & BLOCK_HAVE_DATA) {
            lowest_have = h;
            break;
        }
    }
    atomic_store(&svc->lowest_have_data, lowest_have);

    file_height_map_free(&fmap);
    return files_pruned_this_pass;
}

int block_pruning_run_once(struct block_pruning_service *svc)
{
    if (!svc || !svc->ms || !svc->datadir)
        return 0;

    int chain_height = active_chain_height(&svc->ms->chain_active);
    atomic_store(&svc->lowest_have_data, chain_height);
    if (chain_height < svc->keep_blocks)
        return 0;  /* chain too short to prune anything */

    int prune_below = chain_height - svc->keep_blocks;
    return block_pruning_run_below(svc, chain_height, prune_below);
}

int block_pruning_prune_sealed_range(struct block_pruning_service *svc,
                                     uint32_t sealed_verified_top_excl)
{
    if (!svc || !svc->ms || !svc->datadir)
        return 0;

    int chain_height = active_chain_height(&svc->ms->chain_active);

    /* Never prune above the caller's just-sealed+verified boundary, and never
     * beyond what keep_blocks already permits — the intersection of both
     * floors is the only height range this call is allowed to touch. */
    int prune_below = sealed_verified_top_excl > (uint32_t)INT32_MAX
        ? INT32_MAX : (int)sealed_verified_top_excl;
    int keep_floor = chain_height - svc->keep_blocks;
    if (keep_floor < prune_below)
        prune_below = keep_floor;

    return block_pruning_run_below(svc, chain_height, prune_below);
}

/* ── Background thread ─────────────────────────────────────── */

static void *block_pruning_thread(void *arg)
{
    struct block_pruning_service *svc = arg;
    atomic_store(&svc->state, BLOCK_PRUNING_RUNNING);

    /* Signal the starter that we're live. */
    pthread_mutex_lock(&svc->ready_mutex);
    svc->ready = true;
    pthread_cond_signal(&svc->ready_cond);
    pthread_mutex_unlock(&svc->ready_mutex);

    while (!atomic_load(&svc->stop_requested)) {
        /* Only prune when fully synced */
        enum sync_state ss = sync_get_state();
        if (ss == SYNC_AT_TIP) {
            block_pruning_run_once(svc);
        }
        block_pruning_supervisor_heartbeat(svc);

        /* Interruptible sleep: 500ms ticks */
        int total_ms = svc->tick_seconds * 1000;
        int slept = 0;
        while (slept < total_ms) {
            if (atomic_load(&svc->stop_requested)) break;
            platform_sleep_ms(500);
            slept += 500;
        }
    }

    atomic_store(&svc->state, BLOCK_PRUNING_STOPPED);
    return NULL;
}

/* ── Public API ────────────────────────────────────────────── */

void block_pruning_init(struct block_pruning_service *svc,
                        struct main_state *ms,
                        const char *datadir)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->datadir = datadir;
    svc->thread_started = false;
    svc->ready = false;
    pthread_mutex_init(&svc->ready_mutex, NULL);
    pthread_cond_init(&svc->ready_cond, NULL);
    atomic_store(&svc->stop_requested, false);
    atomic_store(&svc->state, BLOCK_PRUNING_IDLE);
    atomic_store(&svc->files_pruned, 0);
    atomic_store(&svc->blocks_pruned, 0);
    atomic_store(&svc->bytes_reclaimed, 0);
    atomic_store(&svc->lowest_have_data, 0);

    /* Read retention depth from env */
    int keep = BLOCK_PRUNING_DEFAULT_KEEP_BLOCKS;
    const char *env = getenv("ZCL_PRUNE_KEEP_BLOCKS");
    if (env) {
        int v = atoi(env);
        if (v >= BLOCK_PRUNING_MIN_KEEP_BLOCKS)
            keep = v;
        else
            LOG_INFO("prune", "[prune] ZCL_PRUNE_KEEP_BLOCKS=%s too low " "(min %d), using default %d", env, BLOCK_PRUNING_MIN_KEEP_BLOCKS, BLOCK_PRUNING_DEFAULT_KEEP_BLOCKS);
    }
    svc->keep_blocks = keep;

    /* Tick interval — default 5 min */
    svc->tick_seconds = BLOCK_PRUNING_DEFAULT_TICK_SECONDS;
}

struct zcl_result block_pruning_start(struct block_pruning_service *svc)
{
    if (!svc || !svc->ms || !svc->datadir)
        return ZCL_ERR(-1, "block_pruning: start: null svc, ms, or datadir");
    if (svc->thread_started)
        return ZCL_ERR(-2, "block_pruning: start: thread already running");

    atomic_store(&svc->stop_requested, false);
    svc->ready = false;
    if (thread_registry_spawn("zcl_block_prune", block_pruning_thread, svc,
                                  &svc->thread) != 0)
        return ZCL_ERR(-3, "block_pruning: failed to create thread: %s",
                       strerror(errno));
    svc->thread_started = true;

    /* Wait for thread to confirm it's running — no sleeps, no races.
     * Bounded so we don't block app_init indefinitely if the pruning
     * thread hangs before its ready-signal (e.g., stuck in
     * thread_registry init or a downstream malloc). 30 s is generous
     * for what is normally a sub-millisecond handshake; longer is
     * almost certainly a deadlock. */
    pthread_mutex_lock(&svc->ready_mutex);
    bool ready_ok = true;
    while (!svc->ready) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 30;
        int rc = pthread_cond_timedwait(&svc->ready_cond,
                                        &svc->ready_mutex, &deadline);
        if (rc == ETIMEDOUT && !svc->ready) {
            ready_ok = false;
            break;
        }
    }
    pthread_mutex_unlock(&svc->ready_mutex);

    if (!ready_ok) {
        /* Signal stop and retain ownership. A stage watchdog may terminate a
         * genuinely wedged process, but startup must not discard a live
         * worker and later free its service state. */
        atomic_store(&svc->stop_requested, true);
        pthread_join(svc->thread, NULL);
        svc->thread_started = false;
        return ZCL_ERR(-4,
            "block_pruning: thread did not signal ready within 30 s — aborted start");
    }

    struct zcl_result sup_r = block_pruning_register_supervisor(svc);
    if (!sup_r.ok) {
        atomic_store(&svc->stop_requested, true);
        pthread_join(svc->thread, NULL);
        svc->thread_started = false;
        return sup_r;
    }

    printf("[prune] started — keep_blocks=%d tick=%ds\n",
           svc->keep_blocks, svc->tick_seconds);
    return ZCL_OK;
}

void block_pruning_stop(struct block_pruning_service *svc)
{
    if (!svc || !svc->thread_started) return;
    supervisor_child_id id = atomic_load(&g_prune_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    atomic_store(&svc->stop_requested, true);
    pthread_join(svc->thread, NULL);
    svc->thread_started = false;
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_prune_supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
    pthread_mutex_destroy(&svc->ready_mutex);
    pthread_cond_destroy(&svc->ready_cond);
    printf("[prune] stopped\n");
}

void block_pruning_get_status(const struct block_pruning_service *svc,
                              struct block_pruning_status *out)
{
    memset(out, 0, sizeof(*out));
    if (!svc) return;
    out->state           = atomic_load(&svc->state);
    out->files_pruned    = atomic_load(&svc->files_pruned);
    out->blocks_pruned   = atomic_load(&svc->blocks_pruned);
    out->bytes_reclaimed = atomic_load(&svc->bytes_reclaimed);
    out->lowest_have_data = atomic_load(&svc->lowest_have_data);
    out->keep_blocks     = svc->keep_blocks;
    if (svc->ms)
        out->chain_height = active_chain_height(&svc->ms->chain_active);
}

/* See CLAUDE.md "Adding state introspection". Reads g_block_pruning
 * which is set by boot once init has run; returns a `running:false`
 * stub otherwise. Reentrant-safe via the atomic snapshot helper. */
bool block_pruning_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    if (!g_block_pruning) {
        json_push_kv_bool(out, "running", false);
        return true;
    }
    struct block_pruning_status s = {0};
    block_pruning_get_status(g_block_pruning, &s);
    json_push_kv_bool(out, "running", g_block_pruning->thread_started);
    json_push_kv_int(out, "state", s.state);
    json_push_kv_int(out, "files_pruned", s.files_pruned);
    json_push_kv_int(out, "blocks_pruned", s.blocks_pruned);
    json_push_kv_int(out, "bytes_reclaimed", s.bytes_reclaimed);
    json_push_kv_int(out, "lowest_have_data", s.lowest_have_data);
    json_push_kv_int(out, "keep_blocks", s.keep_blocks);
    json_push_kv_int(out, "chain_height", s.chain_height);
    return true;
}
