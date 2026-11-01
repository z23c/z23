/* Copyright 2026 Rhett Creighton - Apache License 2.0
// supervisor-ok:bounded-one-shot-maintenance — the only thread is a one-shot evidence maintenance run, joined before the next run and by chain_evidence_maintain_quiesce; the requester never waits on it beyond a deadline, and a stuck run only reports PENDING
 *
 * Off-thread chain-evidence maintenance for the health collector.
 *
 * The health collector (zcl_health_sweep ring, the sd-watchdog collect tick,
 * RPC status calls) used to bind its controller with the mutating
 * chain_evidence_controller_init (state load, boot reconcile) and drain the
 * reducer's pending finalized tip inline.  Both touch node.db, whose shared
 * connection mutex an ingest statement can hold for a long time, so a
 * collector queued behind a stalled disk read stalled the whole sweep ring and
 * the sweep-liveness the systemd watchdog gate reads.
 *
 * The maintenance (init + reconcile + drain) now runs on ONE helper thread;
 * the collector only requests a run and waits a bounded time for it.
 *
 *   - Work is unchanged: the same init and drain run, with the same lock
 *     order, so the boot reconcile and the pending-tip persistence still
 *     happen whenever node.db is reachable.
 *   - A run that does not finish inside the wait reports PENDING; the
 *     collector marks the tick stale/unavailable instead of claiming fresh
 *     evidence.  The run keeps going on the helper thread and, once node.db
 *     frees up, completes on its own.
 *   - No lost tip: the pending slot is cleared only after a successful
 *     persist (chain_evidence_drain_pending_tip), so a failed or still-running
 *     attempt leaves it pending for the next request.
 *   - No duplicate write: record_finalized_tip skips the write when the
 *     persisted evidence already names the tip, and at most one run is in
 *     flight at a time.
 *   - DONE means a run that STARTED after this request finished; a request
 *     that finds an older run still in flight only waits and reports PENDING,
 *     and the next request starts a fresh run. */

#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"

#include "util/thread_registry.h"

#include <pthread.h>
#include <stdbool.h>
#include <time.h>

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static bool g_inflight;
static bool g_have_tid;
static pthread_t g_tid;
static struct node_db *g_ndb;
static struct chain_state_repository *g_csr;

static void *maintenance_main(void *arg)
{
    (void)arg;
    struct chain_evidence_controller cec;
    chain_evidence_controller_init(&cec, g_ndb, g_csr);
    (void)chain_evidence_drain_pending_tip(&cec);
    pthread_mutex_lock(&g_mu);
    g_inflight = false;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

/* Wait (g_mu held) until the in-flight run ends or wait_ms passes. */
static bool wait_idle_locked(int wait_ms)
{
    struct timespec dl;
    if (clock_gettime(CLOCK_REALTIME, &dl) != 0) // platform-ok: pthread_cond_timedwait takes an absolute CLOCK_REALTIME deadline
        return !g_inflight;
    dl.tv_sec += wait_ms / 1000;
    dl.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) {
        dl.tv_sec += 1;
        dl.tv_nsec -= 1000000000L;
    }
    int rc = 0;
    while (g_inflight && rc == 0)
        rc = pthread_cond_timedwait(&g_cv, &g_mu, &dl);
    return !g_inflight;
}

enum cec_maint_result chain_evidence_maintain_bounded(
    struct node_db *ndb, struct chain_state_repository *csr, int wait_ms)
{
    enum cec_maint_result result = CEC_MAINT_PENDING;
    pthread_mutex_lock(&g_mu);
    if (g_inflight) {
        (void)wait_idle_locked(wait_ms); /* older run: never claimed as DONE */
        pthread_mutex_unlock(&g_mu);
        return CEC_MAINT_PENDING;
    }
    if (g_have_tid) {
        pthread_join(g_tid, NULL); /* finished: g_inflight was cleared */
        g_have_tid = false;
    }
    g_ndb = ndb;
    g_csr = csr;
    g_inflight = true;
    // thread-supervision-ok:bounded one-shot maintenance run; the tid is joined before the next run and by chain_evidence_maintain_quiesce, and the requester never waits on it beyond wait_ms
    if (thread_registry_spawn("zcl_cec_maint", maintenance_main, NULL,
                              &g_tid) != 0) {
        g_inflight = false;
        pthread_mutex_unlock(&g_mu);
        return CEC_MAINT_PENDING;
    }
    g_have_tid = true;
    if (wait_idle_locked(wait_ms))
        result = CEC_MAINT_DONE;
    pthread_mutex_unlock(&g_mu);
    return result;
}

void chain_evidence_maintain_quiesce(void)
{
    pthread_mutex_lock(&g_mu);
    while (g_inflight)
        pthread_cond_wait(&g_cv, &g_mu);
    if (g_have_tid) {
        pthread_join(g_tid, NULL);
        g_have_tid = false;
    }
    pthread_mutex_unlock(&g_mu);
}
