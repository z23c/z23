/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sv_lookahead — implementation. See jobs/sv_lookahead.h.
 *
 * Same shape as pv_lookahead: ordinary lock-free chain readers, one verdict
 * ring under g_mu, and a drive that never waits on the pool. Simpler on
 * purpose: a height the pool cannot verify (unreadable body, internal_error)
 * is skipped, not retried; the drive verifies it inline exactly as today. */

#include "jobs/sv_lookahead.h"

#include "jobs/created_outputs_index.h"
#include "script_validate_stage_internal.h"

#include "platform/time_compat.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SVLA_MAX_WORKERS 4
#define SVLA_FULL_POLL_MS 5     /* window full: the drive frees a slot soon */
#define SVLA_IDLE_POLL_MS 50    /* chain end or bodies not yet persisted */

struct svla_slot {
    int32_t height;             /* -1 = empty */
    struct uint256 hash;
    uint32_t flags;
    uint32_t branch_id;
    struct script_verify_summary s;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct svla_slot g_slots[SV_LOOKAHEAD_WINDOW];
static pthread_t g_threads[SVLA_MAX_WORKERS];
static bool      g_thread_started[SVLA_MAX_WORKERS];
static int       g_n_threads = 0;
static bool      g_running = false;     /* under g_mu */
static bool      g_stop = false;        /* under g_mu */
static int64_t   g_next_claim = 0;      /* under g_mu */
static int64_t   g_last_cursor = 0;     /* under g_mu; a rewind means reorg */
static _Atomic uint64_t g_populated = 0;   /* written under g_mu */
static _Atomic bool g_running_fast = false;   /* lock-free take() fast path */
static _Atomic uint64_t g_hit_total = 0;
static _Atomic uint64_t g_miss_total = 0;
static _Atomic uint64_t g_verified_total = 0;
static _Atomic uint64_t g_skipped_total = 0;

/* Pool configuration: written in sv_lookahead_start before any worker spawns,
 * immutable until sv_lookahead_stop has joined them. */
static struct main_state *g_ms = NULL;
static char g_datadir[2048] = {0};
static script_validate_reader_fn g_reader = NULL;
static void *g_reader_user = NULL;
static script_validate_prevout_fn g_prevout = NULL;
static void *g_prevout_user = NULL;
static sv_lookahead_limit_fn g_limit = NULL;

static struct liveness_contract g_pool_contract;
static _Atomic int g_pool_child_id = SUPERVISOR_INVALID_ID;

enum svla_attempt {
    SVLA_STORED,      /* verdict cached */
    SVLA_PAST_CHAIN,  /* no block at this height yet: hold the claim */
    SVLA_SKIP,        /* not cacheable; the drive verifies inline */
};

/* g_mu held; released for the sleep. Workers poll the lock-free cursor, so a
 * consume needs no wake-up and the drive never signals the pool. */
static void svla_poll_wait_locked(int ms)
{
    pthread_mutex_unlock(&g_mu);
    platform_sleep_ms(ms);
    pthread_mutex_lock(&g_mu);
}

/* g_mu NOT held. Cache the verdict for the key unless an identical one is
 * already stored. */
static void svla_store(int32_t h, const struct uint256 *hash, uint32_t flags,
                       uint32_t branch_id, const struct script_verify_summary *s)
{
    pthread_mutex_lock(&g_mu);
    struct svla_slot *slot = &g_slots[(uint32_t)h % SV_LOOKAHEAD_WINDOW];
    bool same = slot->height == h &&
                memcmp(slot->hash.data, hash->data, 32) == 0 &&
                slot->flags == flags && slot->branch_id == branch_id;
    if (!same) {
        if (slot->height < 0)
            atomic_fetch_add(&g_populated, 1);
        slot->height = h;
        slot->hash = *hash;
        slot->flags = flags;
        slot->branch_id = branch_id;
        slot->s = *s;
    }
    pthread_mutex_unlock(&g_mu);
}

/* Read the body the index names and confirm it is that block: a torn or
 * misdirected read must never be verified under another block's hash. */
static bool svla_read_body(struct block *blk, const struct block_index *bi,
                           const struct uint256 *hash)
{
    bool got = g_reader
        ? g_reader(blk, bi, g_datadir, g_reader_user)
        : read_block_from_disk_index_pread(blk, bi, g_datadir);
    if (!got)
        return false;
    struct uint256 actual;
    block_header_get_hash(&blk->header, &actual);
    return memcmp(actual.data, hash->data, 32) == 0;
}

/* The workers share the drive's SQLite connection; the bounded-read and
 * coins_kv statement caches are per thread and keyed by the global batch
 * generation, so finalize them after every height instead of holding a
 * prepared statement on a worker across drive batches or past shutdown. */
static void svla_release_thread_caches(void)
{
    created_outputs_index_batch_reset();
    script_validate_prevout_batch_reset();
}

static enum svla_attempt svla_verify_height(int32_t h)
{
    struct block_index *bi = active_chain_at(&g_ms->chain_active, h);
    if (!bi)
        return SVLA_PAST_CHAIN;
    if (!(block_index_status_load(bi) & BLOCK_HAVE_DATA) || !bi->phashBlock)
        return SVLA_SKIP;
    struct uint256 hash = *bi->phashBlock;   /* value snapshot before reading */

    struct block blk;
    block_init(&blk);
    if (!svla_read_body(&blk, bi, &hash)) {
        block_free(&blk);
        atomic_fetch_add(&g_skipped_total, 1);
        return SVLA_SKIP;
    }
    uint32_t flags, branch_id;
    script_verify_params_for_height(h, &flags, &branch_id);
    struct script_verify_summary s;
    script_verify_block(&blk, h, g_prevout, g_prevout_user, NULL, NULL,
                        /*parallel=*/false, &s);
    block_free(&blk);
    svla_release_thread_caches();
    atomic_fetch_add(&g_verified_total, 1);

    /* No verdict (unresolved prevout, undecodable body, out of memory): never
     * cached, so the stage's hold path always runs inline. */
    if (!s.ok && s.internal_error) {
        atomic_fetch_add(&g_skipped_total, 1);
        return SVLA_SKIP;
    }
    svla_store(h, &hash, flags, branch_id, &s);
    return SVLA_STORED;
}

/* g_mu held. Fold the observed cursor into the claim state and return the
 * exclusive end of the claimable range: the window, clamped to the persisted
 * bodies. A backward cursor (reorg) pulls the claim back; slots are left alone
 * because take() rejects an abandoned branch's slot on the hash compare. */
static int64_t svla_claim_end_locked(int64_t cursor)
{
    if (cursor < g_last_cursor)
        g_next_claim = cursor;
    g_last_cursor = cursor;
    if (g_next_claim < cursor)
        g_next_claim = cursor;
    int64_t end = cursor + SV_LOOKAHEAD_WINDOW;
    uint64_t lim = g_limit ? g_limit() : 0;
    if (lim < (uint64_t)end)
        end = (int64_t)lim;
    return end > INT32_MAX ? INT32_MAX : end;
}

static void svla_worker_beat(int child)
{
    if (child == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(child);
    supervisor_progress(child, (int64_t)atomic_load(&g_verified_total));
}

static void *svla_worker_entry(void *arg)
{
    (void)arg;
    int child = atomic_load(&g_pool_child_id);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_alive(child);
    pthread_mutex_lock(&g_mu);
    while (!g_stop) {
        svla_worker_beat(child);
        int64_t cursor = (int64_t)script_validate_stage_cursor();
        int64_t end = svla_claim_end_locked(cursor);
        int64_t h = g_next_claim;
        if (h >= end) {
            svla_poll_wait_locked(h >= cursor + SV_LOOKAHEAD_WINDOW
                                      ? SVLA_FULL_POLL_MS : SVLA_IDLE_POLL_MS);
            continue;
        }
        g_next_claim = h + 1;
        if (g_slots[(uint64_t)h % SV_LOOKAHEAD_WINDOW].height == (int32_t)h)
            continue;                    /* already verified this height */
        pthread_mutex_unlock(&g_mu);
        enum svla_attempt r = svla_verify_height((int32_t)h);
        pthread_mutex_lock(&g_mu);
        if (r == SVLA_PAST_CHAIN) {      /* hold the claim at the chain end */
            if (g_next_claim > h)
                g_next_claim = h;
            svla_poll_wait_locked(SVLA_IDLE_POLL_MS);
        }
    }
    pthread_mutex_unlock(&g_mu);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_exited(child);
    svla_release_thread_caches();
    thread_registry_unregister_self();
    return NULL;
}

static void svla_reset_locked(void)
{
    for (size_t i = 0; i < SV_LOOKAHEAD_WINDOW; i++)
        g_slots[i].height = -1;
    atomic_store(&g_populated, (uint64_t)0);
    g_next_claim = 0;
    g_last_cursor = 0;
    g_stop = false;
    g_ms = NULL;
    g_datadir[0] = '\0';
    g_reader = NULL;
    g_reader_user = NULL;
    g_prevout = NULL;
    g_prevout_user = NULL;
    g_limit = NULL;
}

static int svla_worker_count(void)
{
    int n = GetNumCores() - 2;
    if (n > SVLA_MAX_WORKERS)
        n = SVLA_MAX_WORKERS;
    return n < 1 ? 1 : n;
}

/* Join the supervisor liveness tree BEFORE spawning workers so the first worker
 * already sees a valid child id. Heartbeat-only: a full window or the chain end
 * legitimately produces no new verdicts, which is not a stall. */
static void svla_register_supervisor(void)
{
    liveness_contract_init(&g_pool_contract, "sv_lookahead");
    g_pool_contract.deadline_secs = 10;
    supervisor_domains_init();
    supervisor_child_id cid =
        supervisor_register_in_domain(g_chain_sup, &g_pool_contract);
    atomic_store(&g_pool_child_id, cid);
    if (cid == SUPERVISOR_INVALID_ID) {
        LOG_WARN("sv_lookahead",
                 "[sv_lookahead] supervisor registry full; pool runs "
                 "unsupervised (workers still join on stop)");
        return;
    }
    supervisor_set_progress_exempt(
        cid, "idle by design at the chain end or with a full window");
}

static void svla_unregister_supervisor(void)
{
    supervisor_unregister(atomic_load(&g_pool_child_id));
    atomic_store(&g_pool_child_id, SUPERVISOR_INVALID_ID);
}

/* Spawn n workers; on a failed spawn join the started ones and report false. */
static bool svla_spawn_workers(int n)
{
    memset(g_thread_started, 0, sizeof(g_thread_started));
    for (int i = 0; i < n; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sv.lookahead.%d", i);
        // thread-supervision-ok:bounded-worker-pool joined in sv_lookahead_stop; idle-polls the cursor, verifies a bounded lookahead window
        int rc = thread_registry_spawn(name, svla_worker_entry, NULL,
                                       &g_threads[i]);
        if (rc == 0) {
            g_thread_started[i] = true;
            continue;
        }
        LOG_WARN("sv_lookahead",
                 "[sv_lookahead] worker %d spawn failed rc=%d; stopping "
                 "pool, the stage verifies inline", i, rc);
        pthread_mutex_lock(&g_mu);
        g_stop = true;
        pthread_mutex_unlock(&g_mu);
        for (int j = 0; j < i; j++)
            pthread_join(g_threads[j], NULL);
        return false;
    }
    return true;
}

bool sv_lookahead_start(struct main_state *ms, const char *datadir,
                        script_validate_reader_fn reader, void *reader_user,
                        script_validate_prevout_fn prevout, void *prevout_user,
                        sv_lookahead_limit_fn limit)
{
    if (!ms || !prevout || !limit)
        LOG_FAIL("sv_lookahead", "[sv_lookahead] start: missing argument");

    pthread_mutex_lock(&g_mu);
    if (g_running) {
        pthread_mutex_unlock(&g_mu);
        LOG_FAIL("sv_lookahead", "[sv_lookahead] start: already running");
    }
    svla_reset_locked();
    g_ms = ms;
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
    g_reader = reader;
    g_reader_user = reader_user;
    g_prevout = prevout;
    g_prevout_user = prevout_user;
    g_limit = limit;
    g_next_claim = (int64_t)script_validate_stage_cursor();
    atomic_store(&g_hit_total, (uint64_t)0);
    atomic_store(&g_miss_total, (uint64_t)0);
    atomic_store(&g_verified_total, (uint64_t)0);
    atomic_store(&g_skipped_total, (uint64_t)0);
    pthread_mutex_unlock(&g_mu);

    svla_register_supervisor();
    int n = svla_worker_count();
    if (!svla_spawn_workers(n)) {
        svla_unregister_supervisor();
        pthread_mutex_lock(&g_mu);
        svla_reset_locked();
        pthread_mutex_unlock(&g_mu);
        return false;
    }
    pthread_mutex_lock(&g_mu);
    g_n_threads = n;
    g_running = true;
    atomic_store_explicit(&g_running_fast, true, memory_order_release);
    pthread_mutex_unlock(&g_mu);
    LOG_INFO("sv_lookahead",
             "[sv_lookahead] started %d script pre-verification workers "
             "(window=%d)", n, SV_LOOKAHEAD_WINDOW);
    return true;
}

void sv_lookahead_stop(void)
{
    pthread_mutex_lock(&g_mu);
    bool was_running = g_running;
    if (was_running) {
        g_stop = true;
        g_running = false;
        atomic_store_explicit(&g_running_fast, false, memory_order_release);
    }
    int n = g_n_threads;
    pthread_mutex_unlock(&g_mu);
    if (!was_running)
        return;
    for (int i = 0; i < n; i++) {
        if (g_thread_started[i]) {
            pthread_join(g_threads[i], NULL);
            g_thread_started[i] = false;
        }
    }
    svla_unregister_supervisor();
    pthread_mutex_lock(&g_mu);
    g_n_threads = 0;
    svla_reset_locked();
    pthread_mutex_unlock(&g_mu);
    LOG_INFO("sv_lookahead", "[sv_lookahead] stopped (hits=%llu misses=%llu)",
             (unsigned long long)atomic_load(&g_hit_total),
             (unsigned long long)atomic_load(&g_miss_total));
}

bool sv_lookahead_take(int height, const struct uint256 *block_hash,
                       uint32_t flags, uint32_t branch_id,
                       script_validate_prevout_fn prevout, void *prevout_user,
                       struct script_verify_summary *out)
{
    if (!atomic_load_explicit(&g_running_fast, memory_order_acquire))
        return false; // raw-return-ok:a not-running pool is a designed cache miss, not an error
    if (height < 0 || !block_hash || !out)
        return false;

    bool hit = false;
    pthread_mutex_lock(&g_mu);
    if (g_running && prevout == g_prevout && prevout_user == g_prevout_user) {
        struct svla_slot *slot =
            &g_slots[(uint32_t)height % SV_LOOKAHEAD_WINDOW];
        hit = slot->height == height &&
              memcmp(slot->hash.data, block_hash->data, 32) == 0 &&
              slot->flags == flags && slot->branch_id == branch_id;
        if (hit) {
            *out = slot->s;
            slot->height = -1;
            atomic_fetch_sub(&g_populated, 1);
        }
        atomic_fetch_add(hit ? &g_hit_total : &g_miss_total, 1);
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

uint64_t sv_lookahead_hit_total(void)      { return atomic_load(&g_hit_total); }
uint64_t sv_lookahead_miss_total(void)     { return atomic_load(&g_miss_total); }
uint64_t sv_lookahead_verified_total(void) { return atomic_load(&g_verified_total); }
uint64_t sv_lookahead_skipped_total(void)  { return atomic_load(&g_skipped_total); }

uint64_t sv_lookahead_populated(void)
{
    return atomic_load(&g_populated);
}
