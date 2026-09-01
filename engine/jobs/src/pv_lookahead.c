/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * pv_lookahead — implementation. See jobs/pv_lookahead.h.
 *
 * Workers are ordinary lock-free chain readers (the same active_chain_at +
 * pread pattern bg_validation runs concurrently with the fold); the only
 * shared mutable state is the verdict ring under g_mu. The drive never waits
 * on the pool — a miss falls back to the inline verify — so there is no
 * drive/worker deadlock by construction. */

#include "jobs/pv_lookahead.h"

#include "jobs/proof_validate_verify.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/bn254.h"
#include "sapling/params_init.h"
#include "storage/disk_block_io.h"
#include "json/json.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define PVLA_MAX_WORKERS 16
#define PVLA_RETRY_WAIT_MS 20

struct pvla_slot {
    int32_t height;                 /* -1 = empty */
    struct uint256 hash;
    struct pv_lookahead_verdict v;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;
static struct pvla_slot g_slots[PV_LOOKAHEAD_WINDOW];
static pthread_t g_threads[PVLA_MAX_WORKERS];
static bool      g_thread_started[PVLA_MAX_WORKERS];
static int       g_n_threads = 0;
static bool      g_running = false;      /* under g_mu */
static bool      g_stop = false;         /* under g_mu */
static int64_t   g_next_claim = 0;       /* under g_mu */
static uint64_t  g_populated = 0;        /* under g_mu */
/* Lowest height this sweep skipped because its body had not landed yet, or -1.
 * The offline -mint-anchor fold never needs this: every body is already on
 * disk, so a PVLA_HEIGHT_GAP there is permanent and skipping it forever is
 * right. On the live/replay path body_persist writes bodies CONCURRENTLY, so
 * the same gap is transient — without a re-sweep the workers claim the whole
 * window before the bodies arrive, skip every height, and the hit rate stays
 * pinned at zero for the rest of the run. Under g_mu. */
static int64_t   g_lowest_gap = -1;      /* under g_mu */
/* Last drive cursor observed, so a rewind (reorg) is distinguishable from
 * ordinary forward motion. Under g_mu. */
static int64_t   g_last_cursor = 0;      /* under g_mu */
static _Atomic bool g_running_fast = false;   /* lock-free take() fast path */
static _Atomic uint64_t g_hit_total = 0;
static _Atomic uint64_t g_miss_total = 0;
/* Monotonic count of verdicts the workers have PRODUCED (each PVLA_STORED),
 * plus the pool start wall-clock, so the witness reports a pre-verify
 * throughput independent of the drive's consume rate. */
static _Atomic uint64_t g_verified_total = 0;
static _Atomic int64_t  g_start_us = 0;

/* Liveness-tree presence: one child contract for the whole pool. Each worker
 * heartbeats it every loop iteration (workers wake at least every
 * PVLA_RETRY_WAIT_MS even when idle-blocked), so a wedged pool surfaces on the
 * supervisor tree; progress_marker tracks g_verified_total so a live-but-
 * making-no-progress pool is distinguishable from a healthy idle one. The pool
 * is fold-adjacent, so it stays TEMPORARY (never auto-restarted mid-fold) —
 * a dead worker just yields cache misses the drive resolves inline. */
static struct liveness_contract g_pool_contract;
static _Atomic int g_pool_child_id = SUPERVISOR_INVALID_ID;

/* Pool configuration — written in pv_lookahead_start before any worker spawns,
 * immutable until pv_lookahead_stop has joined them. */
static struct main_state *g_ms = NULL;
static char g_datadir[2048] = {0};
static stage_block_reader_fn g_reader = NULL;
static void *g_reader_user = NULL;
static proof_validate_tx_verify_fn g_verifier = NULL;
static void *g_verifier_user = NULL;

/* Success-counter deltas of the serial reduce; mirrors the stage's
 * add_success_counters classification exactly (pinned by the pv_lookahead
 * differential test asserting counter equality serial vs pool). */
struct pvla_deltas {
    uint64_t spends, outputs, groth16, phgr13, binding;
};

static void pvla_success_cb(const struct transaction *tx,
                            const struct proof_validate_tx_report *r,
                            void *user)
{
    struct pvla_deltas *d = user;
    d->spends += (uint64_t)r->sapling_spends_total;
    d->outputs += (uint64_t)r->sapling_outputs_total;
    for (size_t i = 0; tx && i < tx->num_joinsplit; i++) {
        if (tx->v_joinsplit[i].use_groth)
            d->groth16++;
        else
            d->phgr13++;
    }
    if (tx && (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0))
        d->binding++;
}

/* g_mu held. Bounded wait so workers re-check the (lock-free) drive cursor
 * even when no take() broadcast arrives. */
static void pvla_timed_wait_locked(int ms)
{
    struct timespec until;
    if (platform_time_realtime_timespec(&until) != 0)
        return;
    until.tv_nsec += (long)ms * 1000000L;
    if (until.tv_nsec >= 1000000000L) {
        until.tv_sec += 1;
        until.tv_nsec -= 1000000000L;
    }
    (void)pthread_cond_timedwait(&g_cv, &g_mu, &until);
}

enum pvla_attempt {
    PVLA_STORED,   /* verdict cached (or an identical one already was) */
    /* This height's block/header/body is unavailable.  It is safe to scan
     * later heights: proof verification is a pure function of the selected
     * block bytes + verifier, and the serial drive still owns the missing
     * height.  When the drive reaches it, a cache miss verifies inline. */
    PVLA_HEIGHT_GAP,
    /* The verifier is globally unavailable (currently: canonical Sapling
     * parameters are still loading).  Later shielded heights would have the
     * same precondition, so retain the old hold-and-retry behavior instead of
     * burning the complete lookahead window as misses. */
    PVLA_GLOBAL_RETRY,
    PVLA_SKIP,     /* internal_error — never cached; the drive resolves inline */
};

static enum pvla_attempt pvla_verify_height(int32_t h)
{
    struct block_index *bi = active_chain_at(&g_ms->chain_active, h);
    if (!bi || !(block_index_status_load(bi) & BLOCK_HAVE_DATA) ||
        !bi->phashBlock)
        return PVLA_HEIGHT_GAP;
    struct uint256 hash = *bi->phashBlock;   /* value snapshot before reading */

    struct block blk;
    block_init(&blk);
    bool got = g_reader
        ? g_reader(&blk, bi, g_datadir, g_reader_user)
        : read_block_from_disk_index_pread(&blk, bi, g_datadir);
    if (!got) {
        block_free(&blk);
        return PVLA_HEIGHT_GAP;
    }
    /* Mirror the stage's Sapling-params wait gate: a shielded block before the
     * keys finish loading is a global transient hold there, so it is a global
     * retry here.  Later shielded heights share that unavailable verifier. */
    if (!g_verifier && proof_verify_block_has_shielded_proofs(&blk) &&
        !sapling_params_loaded()) {
        block_free(&blk);
        return PVLA_GLOBAL_RETRY;
    }

    struct pvla_deltas d = {0};
    struct proof_verify_summary s;
    proof_verify_block(&blk, h, g_verifier, g_verifier_user,
                       /*parallel=*/false, pvla_success_cb, NULL, &d, &s);
    block_free(&blk);

    if (!s.ok && s.internal_error)
        return PVLA_SKIP;

    pthread_mutex_lock(&g_mu);
    struct pvla_slot *slot = &g_slots[(uint32_t)h % PV_LOOKAHEAD_WINDOW];
    if (!(slot->height == h &&
          memcmp(slot->hash.data, hash.data, 32) == 0)) {
        if (slot->height < 0)
            g_populated++;
        slot->height = h;
        slot->hash = hash;
        slot->v.ok = s.ok;
        slot->v.sapling_spends_total = s.sapling_spends_total;
        slot->v.sapling_outputs_total = s.sapling_outputs_total;
        slot->v.sprout_joinsplits_total = s.sprout_joinsplits_total;
        slot->v.first_failure_txid = s.first_failure_txid;
        slot->v.first_failure_proof_type = s.first_failure_proof_type;
        slot->v.spends_verified = d.spends;
        slot->v.outputs_verified = d.outputs;
        slot->v.sprout_groth16_verified = d.groth16;
        slot->v.sprout_phgr13_verified = d.phgr13;
        slot->v.binding_sig_verified = d.binding;
        atomic_fetch_add(&g_verified_total, 1);
    }
    pthread_mutex_unlock(&g_mu);
    return PVLA_STORED;
}

static void *pvla_worker_entry(void *arg)
{
    (void)arg;
    int child = atomic_load(&g_pool_child_id);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_alive(child);
    pthread_mutex_lock(&g_mu);
    while (!g_stop) {
        if (child != SUPERVISOR_INVALID_ID) {
            supervisor_tick(child);
            supervisor_progress(child,
                                (int64_t)atomic_load(&g_verified_total));
        }
        int64_t cursor = (int64_t)proof_validate_stage_cursor();
        /* Rewind (reorg): the drive moved BACKWARD, which the offline fold never
         * does. Pull the claim back so the workers do not sit stranded above
         * cursor + WINDOW until the drive climbs again. Liveness only — the
         * slots are left alone deliberately: take() rejects an abandoned
         * branch's slot on the block-hash compare, and heights below the fork
         * keep verdicts that are still exactly right. */
        if (cursor < g_last_cursor) {
            g_next_claim = cursor;
            g_lowest_gap = -1;
        }
        g_last_cursor = cursor;
        if (g_next_claim < cursor)
            g_next_claim = cursor;
        int64_t h = g_next_claim;
        if (h >= cursor + PV_LOOKAHEAD_WINDOW || h > INT32_MAX) {
            /* Window exhausted. Re-sweep from the lowest height we skipped for
             * a not-yet-written body: on the live path those bodies land while
             * we scan. Bounded — the reclaim happens at most once per
             * PVLA_RETRY_WAIT_MS, never in a hot loop, and heights above the
             * gap keep the verdicts they already earned. A permanently missing
             * height still costs only one cheap failed claim per sweep
             * (active_chain_at / BLOCK_HAVE_DATA, no pread), so the
             * "never block forever on a missing height" property above holds. */
            if (g_lowest_gap >= cursor && g_lowest_gap < g_next_claim)
                g_next_claim = g_lowest_gap;
            g_lowest_gap = -1;
            pvla_timed_wait_locked(PVLA_RETRY_WAIT_MS);
            continue;
        }
        struct pvla_slot *slot = &g_slots[(uint64_t)h % PV_LOOKAHEAD_WINDOW];
        g_next_claim = h + 1;
        if (slot->height == (int32_t)h)
            continue;                    /* already verified this height */
        pthread_mutex_unlock(&g_mu);

        enum pvla_attempt r = pvla_verify_height((int32_t)h);

        pthread_mutex_lock(&g_mu);
        if (r == PVLA_HEIGHT_GAP &&
            (g_lowest_gap < 0 || h < g_lowest_gap))
            g_lowest_gap = h;
        if (r == PVLA_GLOBAL_RETRY) {
            /* Hold the height: pull the claim cursor back so it is retried
             * (by this or any worker) once the global verifier precondition
             * clears. A concurrent duplicate re-verify of an in-flight sibling
             * height is idempotent (verdicts are pure) — only transiently
             * wasteful, never wrong. */
            if (g_next_claim > h)
                g_next_claim = h;
            pvla_timed_wait_locked(PVLA_RETRY_WAIT_MS);
        }
    }
    pthread_mutex_unlock(&g_mu);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_exited(child);
    thread_registry_unregister_self();
    return NULL;
}

static void pvla_reset_locked(void)
{
    for (size_t i = 0; i < PV_LOOKAHEAD_WINDOW; i++)
        g_slots[i].height = -1;
    g_populated = 0;
    g_next_claim = 0;
    g_lowest_gap = -1;
    g_last_cursor = 0;
    g_stop = false;
    g_ms = NULL;
    g_datadir[0] = '\0';
    g_reader = NULL;
    g_reader_user = NULL;
    g_verifier = NULL;
    g_verifier_user = NULL;
}

static int pvla_worker_count(void)
{
    int n = GetNumCores() - 2;
    if (n > 8) n = 8;
    const char *env = getenv("ZCL_PV_WORKERS");
    if (env && env[0]) {
        long v = strtol(env, NULL, 10);
        if (v >= 1 && v <= PVLA_MAX_WORKERS)
            n = (int)v;
        else
            LOG_WARN("pv_lookahead",
                     "[pv_lookahead] ignoring ZCL_PV_WORKERS=%s (want 1..%d)",
                     env, PVLA_MAX_WORKERS);
    }
    if (n < 1) n = 1;
    return n;
}

bool pv_lookahead_start(struct main_state *ms, const char *datadir,
                        stage_block_reader_fn reader, void *reader_user,
                        proof_validate_tx_verify_fn verifier,
                        void *verifier_user)
{
    if (!ms)
        LOG_FAIL("pv_lookahead", "[pv_lookahead] start: NULL main_state");

    pthread_mutex_lock(&g_mu);
    if (g_running) {
        pthread_mutex_unlock(&g_mu);
        LOG_FAIL("pv_lookahead", "[pv_lookahead] start: already running");
    }
    pvla_reset_locked();
    g_ms = ms;
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
    g_reader = reader;
    g_reader_user = reader_user;
    g_verifier = verifier;
    g_verifier_user = verifier_user;
    g_next_claim = (int64_t)proof_validate_stage_cursor();
    atomic_store(&g_hit_total, (uint64_t)0);
    atomic_store(&g_miss_total, (uint64_t)0);
    atomic_store(&g_verified_total, (uint64_t)0);
    atomic_store(&g_start_us, platform_time_monotonic_us());
    pthread_mutex_unlock(&g_mu);

    /* Join the supervisor liveness tree BEFORE spawning workers so the first
     * worker to enter its loop already sees a valid child id. Heartbeat-only
     * (no progress-quiet gate): a full window legitimately produces no new
     * verdicts while the drive drains, which is not a stall. TEMPORARY policy,
     * no on_respawn — worker_state is observational; a dead worker degrades to
     * inline verifies, never a respawn mid-fold. */
    liveness_contract_init(&g_pool_contract, "mint.pv_lookahead");
    g_pool_contract.deadline_secs = 10;
    supervisor_domains_init();
    supervisor_child_id cid =
        supervisor_register_in_domain(g_chain_sup, &g_pool_contract);
    atomic_store(&g_pool_child_id, cid);
    if (cid == SUPERVISOR_INVALID_ID)
        LOG_WARN("pv_lookahead",
                 "[pv_lookahead] supervisor registry full — pool runs "
                 "unsupervised (workers still join on stop)");

    /* Warm the bn254 Frobenius constant table (lazy static, bn254.c) on THIS
     * thread so no worker races its first-use initialization. */
    struct bn_fq12 one, warmed;
    bn_fq12_one(&one);
    bn_fq12_frobenius_map(&warmed, &one, 1);

    int n = pvla_worker_count();
    memset(g_thread_started, 0, sizeof(g_thread_started));
    for (int i = 0; i < n; i++) {
        char name[32];
        snprintf(name, sizeof(name), "pv.lookahead.%d", i);
        // thread-supervision-ok:bounded-worker-pool joined in pv_lookahead_stop; idle-blocked on g_cv, verifies bounded lookahead window
        int rc = thread_registry_spawn(name, pvla_worker_entry, NULL,
                                       &g_threads[i]);
        if (rc != 0) {
            LOG_WARN("pv_lookahead",
                     "[pv_lookahead] worker %d spawn failed rc=%d — "
                     "stopping pool; the fold verifies inline", i, rc);
            pthread_mutex_lock(&g_mu);
            g_stop = true;
            pthread_cond_broadcast(&g_cv);
            pthread_mutex_unlock(&g_mu);
            for (int j = 0; j < i; j++)
                if (g_thread_started[j])
                    pthread_join(g_threads[j], NULL);
            supervisor_unregister(atomic_load(&g_pool_child_id));
            atomic_store(&g_pool_child_id, SUPERVISOR_INVALID_ID);
            pthread_mutex_lock(&g_mu);
            pvla_reset_locked();
            pthread_mutex_unlock(&g_mu);
            return false;
        }
        g_thread_started[i] = true;
    }
    pthread_mutex_lock(&g_mu);
    g_n_threads = n;
    g_running = true;
    atomic_store_explicit(&g_running_fast, true, memory_order_release);
    pthread_mutex_unlock(&g_mu);
    LOG_INFO("pv_lookahead",
             "[pv_lookahead] started %d proof pre-verification workers "
             "(window=%d)", n, PV_LOOKAHEAD_WINDOW);
    return true;
}

void pv_lookahead_stop(void)
{
    pthread_mutex_lock(&g_mu);
    bool was_running = g_running;
    if (was_running) {
        g_stop = true;
        g_running = false;
        atomic_store_explicit(&g_running_fast, false, memory_order_release);
        pthread_cond_broadcast(&g_cv);
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
    supervisor_unregister(atomic_load(&g_pool_child_id));
    atomic_store(&g_pool_child_id, SUPERVISOR_INVALID_ID);
    pthread_mutex_lock(&g_mu);
    g_n_threads = 0;
    pvla_reset_locked();
    pthread_mutex_unlock(&g_mu);
    LOG_INFO("pv_lookahead",
             "[pv_lookahead] stopped (hits=%llu misses=%llu)",
             (unsigned long long)atomic_load(&g_hit_total),
             (unsigned long long)atomic_load(&g_miss_total));
}

bool pv_lookahead_take(int height, const struct uint256 *block_hash,
                       proof_validate_tx_verify_fn verifier,
                       void *verifier_user,
                       struct pv_lookahead_verdict *out)
{
    /* Live-path fast exit: one relaxed-ish load when the pool never started. */
    if (!atomic_load_explicit(&g_running_fast, memory_order_acquire))
        return false; // raw-return-ok:a not-running pool is a designed cache miss, not an error
    if (height < 0 || !block_hash || !out)
        return false;

    bool hit = false;
    pthread_mutex_lock(&g_mu);
    if (g_running && verifier == g_verifier &&
        verifier_user == g_verifier_user) {
        struct pvla_slot *slot =
            &g_slots[(uint32_t)height % PV_LOOKAHEAD_WINDOW];
        if (slot->height == height &&
            memcmp(slot->hash.data, block_hash->data, 32) == 0) {
            *out = slot->v;
            slot->height = -1;
            if (g_populated > 0)
                g_populated--;
            hit = true;
        }
        if (hit)
            atomic_fetch_add(&g_hit_total, 1);
        else
            atomic_fetch_add(&g_miss_total, 1);
        /* The drive is about to advance its cursor: wake window-waiters. */
        pthread_cond_broadcast(&g_cv);
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

uint64_t pv_lookahead_hit_total(void)  { return atomic_load(&g_hit_total); }
uint64_t pv_lookahead_miss_total(void) { return atomic_load(&g_miss_total); }

uint64_t pv_lookahead_populated(void)
{
    pthread_mutex_lock(&g_mu);
    uint64_t n = g_populated;
    pthread_mutex_unlock(&g_mu);
    return n;
}

bool pv_lookahead_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("pv_lookahead", "dump_state_json: NULL out");
    json_set_object(out);

    bool running = atomic_load_explicit(&g_running_fast, memory_order_acquire);
    uint64_t hits = atomic_load(&g_hit_total);
    uint64_t misses = atomic_load(&g_miss_total);
    uint64_t produced = atomic_load(&g_verified_total);
    int64_t start_us = atomic_load(&g_start_us);

    pthread_mutex_lock(&g_mu);
    int workers = g_n_threads;
    uint64_t queue_depth = g_populated;    /* verdicts warmed, not yet consumed */
    pthread_mutex_unlock(&g_mu);

    json_push_kv_bool(out, "running", running);
    json_push_kv_int(out, "workers", (int64_t)workers);
    json_push_kv_int(out, "window", (int64_t)PV_LOOKAHEAD_WINDOW);
    json_push_kv_int(out, "queue_depth", (int64_t)queue_depth);
    json_push_kv_int(out, "cache_hits", (int64_t)hits);
    json_push_kv_int(out, "cache_misses", (int64_t)misses);
    json_push_kv_int(out, "verdicts_produced", (int64_t)produced);

    uint64_t consumed = hits + misses;
    double hit_rate = consumed > 0 ? (double)hits / (double)consumed : 0.0;
    json_push_kv_real(out, "hit_rate", hit_rate);

    /* Pre-verify throughput: verdicts the workers produced per elapsed second
     * since the pool started (a healthy pool outruns the drive's consume rate,
     * so queue_depth stays near the window). Zero when not started. */
    double blk_per_sec = 0.0;
    if (running && start_us > 0) {
        int64_t now_us = platform_time_monotonic_us();
        int64_t elapsed_us = now_us - start_us;
        if (elapsed_us > 0)
            blk_per_sec = (double)produced * 1000000.0 / (double)elapsed_us;
    }
    json_push_kv_real(out, "throughput_blk_per_sec", blk_per_sec);

    int child = atomic_load(&g_pool_child_id);
    json_push_kv_bool(out, "supervised", child != SUPERVISOR_INVALID_ID);
    json_push_kv_int(out, "supervisor_child_id", (int64_t)child);
    return true;
}
