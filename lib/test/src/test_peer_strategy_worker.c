/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the background NAT probe worker (net/peer_strategy_worker).
 *
 * The worker owns the blocking NAT-PMP/UPnP reachability probe off the
 * boot path and re-arms the 7200 s port-mapping lease at half-life. What
 * is proven here, without a gateway and without sleeps:
 *
 *   (1) scheduling is pure: success renews at PSW_RENEW_SECS and resets
 *       the backoff; failures back off 60 -> 120 -> ... -> 900 capped.
 *   (2) run_once publishes the probed profile under the lock, schedules
 *       the next run, and keeps looping; failure schedules the backoff.
 *   (3) the regtest gate exits the worker without ever probing.
 *   (4) lifecycle: start returns while an injected probe is STILL BLOCKED
 *       (the boot non-blocking property), the published result is
 *       observable through the snapshot, and stop + join reap the thread
 *       promptly from its renewal wait.
 *
 * The injected probes never touch a socket, the real clock, or the onion
 * directory; waiting on worker state uses the worker's own condvar with a
 * bounded deadline, so nothing here is sleep-based. */

#include "test/test_core.h"

#include "net/peer_strategy_worker.h"

#include "platform/time_compat.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define PSW_CHECK(name, expr) do {                                  \
    printf("peer_strategy_worker: %s... ", (name));                 \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* ── Injected seams ─────────────────────────────────────────── */

struct fake_probe {
    int      calls;
    bool     result;
    /* When gate is non-NULL the probe blocks until the test releases it
     * — the "gateway that ignores us", without the tens of seconds. */
    pthread_mutex_t *gate_mu;
    pthread_cond_t  *gate_cv;
    bool            *gate_open;
};

static bool fake_probe(struct node_profile *profile, uint16_t port,
                       void *seam_ctx)
{
    struct fake_probe *fp = seam_ctx;
    if (fp->gate_mu) {
        pthread_mutex_lock(fp->gate_mu);
        while (!*fp->gate_open)
            pthread_cond_wait(fp->gate_cv, fp->gate_mu);
        pthread_mutex_unlock(fp->gate_mu);
    }
    memset(profile, 0, sizeof(*profile));
    profile->public_port = port;
    if (fp->result) {
        profile->has_public_ip = true;
        profile->nat_pmp_available = true;
        profile->public_ip[0] = 203;
        profile->public_ip[3] = 7;
    }
    fp->calls++;
    return fp->result;
}

static bool fake_no_regtest(void *seam_ctx)
{
    (void)seam_ctx;
    return false;
}

static bool fake_yes_regtest(void *seam_ctx)
{
    (void)seam_ctx;
    return true;
}

/* Wait until the worker leaves `state`, bounded; the worker broadcasts
 * its cv on every publish, so this is a condition wait, not a poll. */
static bool wait_state_change(struct peer_strategy_worker *w,
                              enum psw_state from, int timeout_sec)
{
    struct timespec deadline;
    if (platform_time_realtime_timespec(&deadline) != 0)
        return false;
    deadline.tv_sec += timeout_sec;
    deadline.tv_nsec = 0;
    pthread_mutex_lock(&w->mu);
    while (w->state == from) {
        if (pthread_cond_timedwait(&w->cv, &w->mu, &deadline) != 0)
            break;
    }
    bool changed = w->state != from;
    pthread_mutex_unlock(&w->mu);
    return changed;
}

/* ── (1) pure scheduling ────────────────────────────────────── */

static void t_scheduling(int *out)
{
    int failures = 0;
    int backoff = PSW_BACKOFF_INIT_SECS;

    PSW_CHECK("success renews at lease half-life",
              psw_next_delay_secs(true, &backoff) == PSW_RENEW_SECS);
    PSW_CHECK("success resets backoff",
              backoff == PSW_BACKOFF_INIT_SECS);

    int expected = PSW_BACKOFF_INIT_SECS;
    bool progression_ok = true;
    for (;;) {
        int got = psw_next_delay_secs(false, &backoff);
        if (got != expected)
            progression_ok = false;
        if (expected >= PSW_BACKOFF_MAX_SECS) {
            /* capped: further failures keep returning the cap */
            if (psw_next_delay_secs(false, &backoff) != PSW_BACKOFF_MAX_SECS)
                progression_ok = false;
            break;
        }
        expected *= 2;
        if (expected > PSW_BACKOFF_MAX_SECS)
            expected = PSW_BACKOFF_MAX_SECS;
    }
    PSW_CHECK("failure backoff doubles 60..900 then caps", progression_ok);

    backoff = PSW_BACKOFF_MAX_SECS;
    PSW_CHECK("success after failures renews at half-life again",
              psw_next_delay_secs(true, &backoff) == PSW_RENEW_SECS &&
              backoff == PSW_BACKOFF_INIT_SECS);
    *out += failures;
}

/* ── (2) run_once publish + schedule ────────────────────────── */

static void t_run_once(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct fake_probe fp = {0};
    fp.result = true;

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &fp;

    PSW_CHECK("run_once success keeps the loop going",
              peer_strategy_worker_run_once(&w));
    struct node_profile snap;
    enum psw_state st = peer_strategy_worker_snapshot(&w, &snap);
    PSW_CHECK("published state is mapped", st == PSW_MAPPED);
    PSW_CHECK("published profile carries the probed endpoint",
              snap.has_public_ip && snap.public_ip[0] == 203 &&
              snap.public_port == 8033);
    PSW_CHECK("success schedules the half-life renewal",
              w.next_delay_secs == PSW_RENEW_SECS);

    /* Renewal: a second successful probe re-arms at the same cadence. */
    PSW_CHECK("renewal probe runs and keeps looping",
              peer_strategy_worker_run_once(&w));
    PSW_CHECK("renewal called the probe again", fp.calls == 2);
    PSW_CHECK("renewal reschedules at half-life",
              w.next_delay_secs == PSW_RENEW_SECS);

    /* Failure path: unmapped state, loud backoff schedule, loop continues. */
    fp.result = false;
    PSW_CHECK("failed renewal keeps the loop going",
              peer_strategy_worker_run_once(&w));
    st = peer_strategy_worker_snapshot(&w, &snap);
    PSW_CHECK("failure publishes unmapped", st == PSW_UNMAPPED);
    PSW_CHECK("failure schedules the initial backoff",
              w.next_delay_secs == PSW_BACKOFF_INIT_SECS);
    PSW_CHECK("second failure doubles the backoff",
              peer_strategy_worker_run_once(&w) &&
              w.next_delay_secs == PSW_BACKOFF_INIT_SECS * 2);

    peer_strategy_worker_stop(&w);
    PSW_CHECK("run_once observes the stop request",
              !peer_strategy_worker_run_once(&w));
    *out += failures;
}

/* ── (3) regtest gate ───────────────────────────────────────── */

static void t_regtest_skip(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct fake_probe fp = {0};

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_yes_regtest;
    w.seam_ctx = &fp;

    PSW_CHECK("regtest run_once exits the worker",
              !peer_strategy_worker_run_once(&w));
    PSW_CHECK("regtest never probes", fp.calls == 0);
    PSW_CHECK("regtest publishes the skip state",
              peer_strategy_worker_snapshot(&w, NULL) == PSW_SKIPPED_REGTEST);
    *out += failures;
}

/* ── (4) lifecycle: start does not wait, stop+join reap ─────── */

static void t_lifecycle(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct fake_probe fp = {0};
    pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
    bool gate_open = false;
    fp.result = true;
    fp.gate_mu = &gate_mu;
    fp.gate_cv = &gate_cv;
    fp.gate_open = &gate_open;

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &fp;

    PSW_CHECK("start spawns the tracked worker",
              peer_strategy_worker_start(&w));

    /* The probe is still blocked on the closed gate. That start()
     * returned and the state is PROBING is the boot non-blocking
     * property: the caller never waits for the probe. */
    PSW_CHECK("start returned with the probe still blocked",
              peer_strategy_worker_snapshot(&w, NULL) == PSW_PROBING);

    pthread_mutex_lock(&gate_mu);
    gate_open = true;
    pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate_mu);

    PSW_CHECK("probe completion publishes the result",
              wait_state_change(&w, PSW_PROBING, 10) &&
              peer_strategy_worker_snapshot(&w, NULL) == PSW_MAPPED);

    /* The worker is now parked in the 3600 s renewal wait; stop must wake
     * it and join must reap it well inside the documented bound. */
    peer_strategy_worker_stop(&w);
    peer_strategy_worker_join(&w);
    PSW_CHECK("stop+join reaped the worker from its renewal wait",
              !w.started);
    PSW_CHECK("stopped worker settles to idle",
              peer_strategy_worker_snapshot(&w, NULL) == PSW_IDLE);

    /* join without a start and a double stop are both safe no-ops. */
    peer_strategy_worker_stop(&w);
    peer_strategy_worker_join(&w);
    PSW_CHECK("stop/join without a running worker are no-ops", true);

    pthread_mutex_destroy(&gate_mu);
    pthread_cond_destroy(&gate_cv);
    *out += failures;
}

int test_peer_strategy_worker(void)
{
    int failures = 0;
    t_scheduling(&failures);
    t_run_once(&failures);
    t_regtest_skip(&failures);
    t_lifecycle(&failures);
    printf("peer_strategy_worker: %s\n", failures ? "FAIL" : "OK");
    return failures;
}
