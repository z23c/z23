/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * legacy_mirror_sync_parity_trend — bounded trend-history write for the
 * mirror's consensus-parity comparisons (see models/parity_sample.h). Split
 * out of legacy_mirror_sync_service.c to keep that file under the E1
 * file-size ceiling; shares g_lms via legacy_mirror_sync_internal.h exactly
 * like every other TU in this service.
 *
 * Called from lms_cache_comparison() for EVERY comparison outcome the
 * mirror's comparator can land in: a clean agreeing sample, a same-height
 * hash disagreement, an unreachable-oracle sample, and the "no common
 * height available yet" sample. This turns the mirror's ad-hoc
 * rpc-unreachable / hash-disagreement blockers (which only ever fire
 * transiently and can go unnoticed for days — see
 * engine/conditions/src/parity_slo_breach.c) into a trendable time series. */
// one-result-type-ok:best-effort-trend-write — lms_record_parity_sample is a
// best-effort, fire-and-forget history write (observational trend data,
// never a correctness dependency); failures are logged via LOG_WARN, not
// returned, matching every other best-effort persistence write in this
// codebase (e.g. network_monitor.c's nm_sample_once).

#include "legacy_mirror_sync_internal.h"

#include "config/db_service.h"
#include "config/runtime.h"
#include "models/parity_sample.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

/* Bounded retention for the parity_samples trend table. Every comparison
 * outcome writes one row; capped to the newest N so the table cannot grow
 * unbounded on a long-running node. 10k rows at the default 3s tick cadence
 * covers several hours of dense history — comfortably longer than the
 * parity_slo_breach detector's sustained-window thresholds. */
#define PARITY_SAMPLE_RETAIN_ROWS 10000

/* Prune cadence: the retention DELETE runs once per this many saved samples,
 * not on every sample. At the 3s tick that is about every 5 minutes, so the
 * table can overshoot the retention bound by at most this many rows. */
#define PARITY_SAMPLE_PRUNE_EVERY 100

/* Minimum seconds between two failure log lines from the db worker. */
#define PARITY_SAMPLE_LOG_INTERVAL_SECS 60

static atomic_uint_fast64_t g_ps_enqueued;
static atomic_uint_fast64_t g_ps_dropped;
static atomic_uint_fast64_t g_ps_saved;
static atomic_uint_fast64_t g_ps_pruned;
static atomic_uint_fast64_t g_ps_since_prune;
static atomic_int_fast64_t g_ps_last_log;
static atomic_int g_ps_prune_every = PARITY_SAMPLE_PRUNE_EVERY;
static atomic_int g_ps_retain = PARITY_SAMPLE_RETAIN_ROWS;
static atomic_uintptr_t g_ps_last_worker;

static bool ps_log_allowed(void)
{
    int64_t now = (int64_t)platform_time_wall_unix();
    int64_t last = atomic_load(&g_ps_last_log);
    if (last != 0 && now - last < PARITY_SAMPLE_LOG_INTERVAL_SECS)
        return false;
    return atomic_compare_exchange_strong(&g_ps_last_log, &last, now);
}

/* Runs on the db worker, never on the comparison tick. Keeps the
 * ActiveRecord save lifecycle (db_parity_sample_save) intact. */
static bool ps_write(struct node_db *ndb, void *ctx)
{
    const struct db_parity_sample *s = ctx;
    atomic_store(&g_ps_last_worker, (uintptr_t)pthread_self());
    if (!db_parity_sample_save(ndb, s)) {
        if (ps_log_allowed())
            LOG_WARN("legacy_mirror", "parity sample save failed (height=%lld)",
                     (long long)s->heights_equal_at);
        return false;
    }
    atomic_fetch_add(&g_ps_saved, 1);
    int every = atomic_load(&g_ps_prune_every);
    if (every < 1)
        every = 1;
    if (atomic_fetch_add(&g_ps_since_prune, 1) + 1 >= (uint64_t)every) {
        atomic_store(&g_ps_since_prune, 0);
        if (db_parity_sample_prune(ndb, atomic_load(&g_ps_retain))) {
            atomic_fetch_add(&g_ps_pruned, 1);
        } else if (ps_log_allowed()) {
            LOG_WARN("legacy_mirror", "parity sample prune failed");
        }
    }
    return true;
}

static void ps_free(void *ctx)
{
    free(ctx); /* raw-alloc-ok:paired-with-zcl_malloc-in-lms_record_parity_sample */
}

/* Best-effort trend write, enqueued on the db worker so the comparison tick
 * never waits on a WAL fsync. A missing db service (e.g. unit tests that
 * never wire the runtime db service) is a silent no-op. A full queue drops
 * the sample and counts it: this is observational history, never a
 * correctness dependency. */
void lms_record_parity_sample(int height, bool known, bool agree)
{
    struct db_service *svc = app_runtime_db_service();
    if (!svc || !db_service_is_started(svc))
        return;

    struct db_parity_sample *s = zcl_malloc(sizeof(*s), "lms.parity_sample");
    if (!s) {
        atomic_fetch_add(&g_ps_dropped, 1);
        return;
    }
    *s = (struct db_parity_sample){
        .ts = (int64_t)platform_time_wall_unix(),
        .our_height = atomic_load(&g_lms.local_height),
        .oracle_height = atomic_load(&g_lms.legacy_height),
        .heights_equal_at = height,
        .hash_equal = (known && agree) ? 1 : 0,
        .oracle_reachable = atomic_load(&g_lms.reachable) ? 1 : 0,
    };
    /* Ownership of `s` transfers on every path. */
    if (db_service_enqueue_write(svc, ps_write, s, ps_free))
        atomic_fetch_add(&g_ps_enqueued, 1);
    else
        atomic_fetch_add(&g_ps_dropped, 1);
}

void lms_parity_sample_get_stats(struct lms_parity_sample_stats *out)
{
    if (!out)
        return;
    out->enqueued = atomic_load(&g_ps_enqueued);
    out->dropped = atomic_load(&g_ps_dropped);
    out->saved = atomic_load(&g_ps_saved);
    out->pruned = atomic_load(&g_ps_pruned);
}

bool lms_parity_sample_last_write_on_thread(pthread_t t)
{
    return atomic_load(&g_ps_last_worker) == (uintptr_t)t;
}

void lms_parity_sample_test_reset(int prune_every, int retain)
{
    atomic_store(&g_ps_enqueued, 0);
    atomic_store(&g_ps_dropped, 0);
    atomic_store(&g_ps_saved, 0);
    atomic_store(&g_ps_pruned, 0);
    atomic_store(&g_ps_since_prune, 0);
    atomic_store(&g_ps_last_worker, 0);
    atomic_store(&g_ps_prune_every,
                 prune_every > 0 ? prune_every : PARITY_SAMPLE_PRUNE_EVERY);
    atomic_store(&g_ps_retain,
                 retain > 0 ? retain : PARITY_SAMPLE_RETAIN_ROWS);
}
