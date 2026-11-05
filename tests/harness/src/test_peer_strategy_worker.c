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

#include "chain/chainparams.h"
#include "platform/time_compat.h"
#include "util/log_json.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
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

/* ── (5) names, null guards, defaults ───────────────────────── */

static void t_names_and_null_guards(int *out)
{
    int failures = 0;

    PSW_CHECK("state names: idle/probing",
              strcmp(psw_state_name(PSW_IDLE), "idle") == 0 &&
              strcmp(psw_state_name(PSW_PROBING), "probing") == 0);
    PSW_CHECK("state names: mapped/unmapped",
              strcmp(psw_state_name(PSW_MAPPED), "mapped") == 0 &&
              strcmp(psw_state_name(PSW_UNMAPPED), "unmapped") == 0);
    PSW_CHECK("state names: skipped_regtest and unknown",
              strcmp(psw_state_name(PSW_SKIPPED_REGTEST),
                     "skipped_regtest") == 0 &&
              strcmp(psw_state_name((enum psw_state)99), "unknown") == 0);

    PSW_CHECK("next_delay with a null backoff refuses with -1",
              psw_next_delay_secs(true, NULL) == -1 &&
              psw_next_delay_secs(false, NULL) == -1);
    PSW_CHECK("run_once and start refuse a null worker",
              !peer_strategy_worker_run_once(NULL) &&
              !peer_strategy_worker_start(NULL));
    PSW_CHECK("snapshot of a null worker reports idle",
              peer_strategy_worker_snapshot(NULL, NULL) == PSW_IDLE);

    peer_strategy_worker_init(NULL, 1);
    peer_strategy_worker_stop(NULL);
    peer_strategy_worker_join(NULL);
    PSW_CHECK("null init/stop/join are safe no-ops", true);

    struct peer_strategy_worker w;
    peer_strategy_worker_init(&w, 8033);
    PSW_CHECK("init leaves an idle, unscheduled worker",
              w.state == PSW_IDLE && w.next_delay_secs == 0 &&
              w.backoff_secs == PSW_BACKOFF_INIT_SECS &&
              w.listen_port == 8033 && !w.started && !w.stop);
    *out += failures;
}

static void t_default_regtest_gate(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    peer_strategy_worker_init(&w, 8033);

    chain_params_select(CHAIN_MAIN);
    PSW_CHECK("default regtest gate is closed on mainnet params",
              !w.regtest_fn(NULL));
    chain_params_select(CHAIN_REGTEST);
    PSW_CHECK("default regtest gate opens on regtest params",
              w.regtest_fn(NULL));
    chain_params_select(CHAIN_MAIN);
    *out += failures;
}

/* ── (6) completion record and stop-during-probe ────────────── */

static struct {
    int n;
    enum log_json_level level;
    char fields[256];
} g_cap;

static void cap_hook(enum log_json_level level, const char *event,
                     const char *fields)
{
    if (strcmp(event, "nat_probe_complete") != 0)
        return;
    g_cap.n++;
    g_cap.level = level;
    snprintf(g_cap.fields, sizeof(g_cap.fields), "%s", fields);
}

/* seam_ctx points at a bool: the probe result. A success carries four
 * distinct IP octets and Tor, so a swapped index shows in the record. */
static bool ip_probe(struct node_profile *p, uint16_t port, void *seam_ctx)
{
    bool ok = *(bool *)seam_ctx;
    memset(p, 0, sizeof(*p));
    p->public_port = port;
    if (ok) {
        p->has_public_ip = true;
        p->tor_available = true;
        p->public_ip[0] = 198;
        p->public_ip[1] = 51;
        p->public_ip[2] = 100;
        p->public_ip[3] = 7;
    }
    return ok;
}

static void t_completion_record(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    bool probe_ok = true;

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = ip_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &probe_ok;
    memset(&g_cap, 0, sizeof(g_cap));
    log_json_set_mirror(cap_hook);

    (void)peer_strategy_worker_run_once(&w);
    PSW_CHECK("success record: info level, all four octets, tor, renewal",
              g_cap.n == 1 && g_cap.level == LOG_JSON_INFO &&
              strcmp(g_cap.fields,
                     "\"state\":\"mapped\",\"clearnet\":\"198.51.100.7\","
                     "\"tor\":true,\"next_probe_s\":3600") == 0);

    probe_ok = false;
    (void)peer_strategy_worker_run_once(&w);
    PSW_CHECK("failure record: warn level, empty clearnet, backoff",
              g_cap.n == 2 && g_cap.level == LOG_JSON_WARN &&
              strcmp(g_cap.fields,
                     "\"state\":\"unmapped\",\"clearnet\":\"\","
                     "\"tor\":false,\"next_probe_s\":60") == 0);
    log_json_set_mirror(NULL);
    *out += failures;
}

static bool stopping_probe(struct node_profile *p, uint16_t port,
                           void *seam_ctx)
{
    memset(p, 0, sizeof(*p));
    p->public_port = port;
    peer_strategy_worker_stop(seam_ctx);
    return true;
}

static void t_stop_during_probe(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = stopping_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &w;

    PSW_CHECK("a stop requested mid-probe ends the loop after publishing",
              !peer_strategy_worker_run_once(&w));
    PSW_CHECK("the interrupted probe's result was still published",
              peer_strategy_worker_snapshot(&w, NULL) == PSW_MAPPED);
    *out += failures;
}

/* ── (7) the condvar is broadcast on every publish ──────────── */

struct waiter {
    struct peer_strategy_worker *w;
    atomic_bool ready;
    bool woken;
};

/* Holds w->mu from before `ready` until pthread_cond_timedwait releases it,
 * so once the test has taken and dropped the mutex this thread is waiting.
 * woken is true only when a broadcast (not the 20 s bound) ended the wait. */
static void *waiter_main(void *arg)
{
    struct waiter *wt = arg;
    struct peer_strategy_worker *w = wt->w;
    struct timespec deadline;
    int rc = 0;

    platform_time_realtime_timespec(&deadline);
    deadline.tv_sec += 20;
    pthread_mutex_lock(&w->mu);
    atomic_store(&wt->ready, true);
    while (w->state == PSW_IDLE && rc == 0)
        rc = pthread_cond_timedwait(&w->cv, &w->mu, &deadline);
    wt->woken = rc == 0 && w->state != PSW_IDLE;
    pthread_mutex_unlock(&w->mu);
    return NULL;
}

/* Run one run_once step with a waiter parked on the worker's condvar. */
static bool publish_wakes_waiter(struct peer_strategy_worker *w)
{
    struct waiter wt = { .w = w, .woken = false };
    pthread_t tid;
    atomic_init(&wt.ready, false);
    if (pthread_create(&tid, NULL, waiter_main, &wt) != 0)
        return false;
    while (!atomic_load(&wt.ready))
        sched_yield();
    pthread_mutex_lock(&w->mu);
    pthread_mutex_unlock(&w->mu);
    (void)peer_strategy_worker_run_once(w);
    pthread_join(tid, NULL);
    return wt.woken;
}

static void t_publish_broadcasts(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct fake_probe fp = {0};
    fp.result = true;

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_yes_regtest;
    w.seam_ctx = &fp;
    PSW_CHECK("the regtest skip wakes a waiter on the condvar",
              publish_wakes_waiter(&w));

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &fp;
    PSW_CHECK("a published probe result wakes a waiter on the condvar",
              publish_wakes_waiter(&w));
    *out += failures;
}

/* ── (8) the thread shell ───────────────────────────────────── */

struct count_ctx {
    atomic_int calls;
};

static bool count_probe(struct node_profile *p, uint16_t port, void *seam_ctx)
{
    struct count_ctx *c = seam_ctx;
    memset(p, 0, sizeof(*p));
    p->public_port = port;
    atomic_fetch_add(&c->calls, 1);
    return true;
}

static void t_wait_survives_wakeups(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct count_ctx cc;
    atomic_init(&cc.calls, 0);

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = count_probe;
    w.regtest_fn = fake_no_regtest;
    w.seam_ctx = &cc;

    PSW_CHECK("worker starts", peer_strategy_worker_start(&w));
    PSW_CHECK("worker records that it started", w.started);
    PSW_CHECK("first probe publishes",
              wait_state_change(&w, PSW_PROBING, 10) &&
              peer_strategy_worker_snapshot(&w, NULL) == PSW_MAPPED);

    /* Wakeups that are not a stop must not end the renewal wait: the next
     * probe is an hour away. A worker that treated them as a deadline would
     * re-probe at once (or, if the wait returned early, exit). */
    for (int i = 0; i < 2000; i++) {
        pthread_mutex_lock(&w.mu);
        pthread_cond_broadcast(&w.cv);
        pthread_mutex_unlock(&w.mu);
        sched_yield();
    }
    PSW_CHECK("non-stop wakeups neither re-probe nor end the worker",
              atomic_load(&cc.calls) == 1 &&
              peer_strategy_worker_snapshot(&w, NULL) == PSW_MAPPED);

    pthread_t tid_before = w.tid;
    PSW_CHECK("a second start on a running worker is a no-op success",
              peer_strategy_worker_start(&w) &&
              pthread_equal(w.tid, tid_before) &&
              peer_strategy_worker_snapshot(&w, NULL) == PSW_MAPPED);

    peer_strategy_worker_stop(&w);
    peer_strategy_worker_join(&w);
    PSW_CHECK("join clears started and the worker settles idle",
              !w.started &&
              peer_strategy_worker_snapshot(&w, NULL) == PSW_IDLE &&
              atomic_load(&cc.calls) == 1);
    *out += failures;
}

static void t_regtest_thread_exit(int *out)
{
    int failures = 0;
    struct peer_strategy_worker w;
    struct fake_probe fp = {0};

    peer_strategy_worker_init(&w, 8033);
    w.probe_fn = fake_probe;
    w.regtest_fn = fake_yes_regtest;
    w.seam_ctx = &fp;

    PSW_CHECK("regtest worker starts", peer_strategy_worker_start(&w));
    PSW_CHECK("regtest worker reports the skip",
              wait_state_change(&w, PSW_PROBING, 10));
    peer_strategy_worker_join(&w);
    PSW_CHECK("the exited regtest worker keeps its skipped state",
              peer_strategy_worker_snapshot(&w, NULL) ==
                  PSW_SKIPPED_REGTEST && !w.started && fp.calls == 0);
    *out += failures;
}

int test_peer_strategy_worker(void)
{
    int failures = 0;
    t_scheduling(&failures);
    t_run_once(&failures);
    t_regtest_skip(&failures);
    t_lifecycle(&failures);
    t_names_and_null_guards(&failures);
    t_default_regtest_gate(&failures);
    t_completion_record(&failures);
    t_stop_during_probe(&failures);
    t_publish_broadcasts(&failures);
    t_wait_survives_wakeups(&failures);
    t_regtest_thread_exit(&failures);
    printf("peer_strategy_worker: %s\n", failures ? "FAIL" : "OK");
    return failures;
}
