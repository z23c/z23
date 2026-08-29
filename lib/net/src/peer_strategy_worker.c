/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background NAT/reachability probe worker — see the header for the
 * contract. This TU owns the thread shell and the publish/schedule
 * decision; the probe itself stays in peer_strategy.c. */

// supervisor-ok:bounded-nat-probe — single joined worker, no resident service

#define _GNU_SOURCE  /* pthread_timedjoin_np (platform_thread_join_until) */
#include "net/peer_strategy_worker.h"

#include "chain/chainparams.h"
#include "platform/thread_compat.h"
#include "platform/time_compat.h"
#include "util/log_json.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ── Default (production) seams ─────────────────────────────── */

static bool psw_real_probe(struct node_profile *profile, uint16_t port,
                           void *seam_ctx)
{
    (void)seam_ctx;
    return peer_strategy_discover_self(profile, port);
}

static bool psw_real_regtest(void *seam_ctx)
{
    (void)seam_ctx;
    const struct chain_params *cp = chain_params_get();
    return cp && cp->fMineBlocksOnDemand;
}

/* ── Init / pure scheduling ─────────────────────────────────── */

void peer_strategy_worker_init(struct peer_strategy_worker *w,
                               uint16_t listen_port)
{
    if (!w) {
        LOG_ERROR("net", "peer_strategy_worker_init: null worker");
        return;
    }

    memset(w, 0, sizeof(*w));
    w->listen_port = listen_port;
    w->probe_fn = psw_real_probe;
    w->regtest_fn = psw_real_regtest;
    w->state = PSW_IDLE;
    w->backoff_secs = PSW_BACKOFF_INIT_SECS;
    w->next_delay_secs = 0;
    int rc = pthread_mutex_init(&w->mu, NULL);
    if (rc != 0) {
        LOG_ERROR("net", "nat probe worker mutex init failed rc=%d", rc);
        return;
    }
    rc = pthread_cond_init(&w->cv, NULL);
    if (rc != 0) {
        LOG_ERROR("net", "nat probe worker cond init failed rc=%d", rc);
        return;
    }
}

const char *psw_state_name(enum psw_state s)
{
    switch (s) {
    case PSW_IDLE:            return "idle";
    case PSW_PROBING:         return "probing";
    case PSW_MAPPED:          return "mapped";
    case PSW_UNMAPPED:        return "unmapped";
    case PSW_SKIPPED_REGTEST: return "skipped_regtest";
    }
    return "unknown";
}

int psw_next_delay_secs(bool probe_ok, int *backoff_secs)
{
    if (!backoff_secs)
        LOG_ERR("net", "psw_next_delay_secs: null backoff");

    if (probe_ok) {
        *backoff_secs = PSW_BACKOFF_INIT_SECS;
        return PSW_RENEW_SECS;
    }
    int delay = *backoff_secs;
    if (delay < PSW_BACKOFF_INIT_SECS)
        delay = PSW_BACKOFF_INIT_SECS;
    int next = delay * 2;
    *backoff_secs = next > PSW_BACKOFF_MAX_SECS ? PSW_BACKOFF_MAX_SECS : next;
    return delay;
}

/* ── One probe + publish + schedule step ────────────────────── */

bool peer_strategy_worker_run_once(struct peer_strategy_worker *w)
{
    if (!w)
        LOG_FAIL("net", "peer_strategy_worker_run_once: null worker");

    pthread_mutex_lock(&w->mu);
    bool stop = w->stop;
    pthread_mutex_unlock(&w->mu);
    if (stop)
        return false;

    /* Regtest is a local connect-only chain: no mapping, no discovery, no
     * renewal. discover_self carries the same gate; the worker checks it
     * first so it can EXIT instead of bouncing through the failure
     * backoff forever. */
    if (w->regtest_fn(w->seam_ctx)) {
        pthread_mutex_lock(&w->mu);
        w->state = PSW_SKIPPED_REGTEST;
        pthread_cond_broadcast(&w->cv);
        pthread_mutex_unlock(&w->mu);
        LOG_INFO("net", "nat probe worker: regtest, port mapping skipped");
        return false;
    }

    struct node_profile p;
    bool ok = w->probe_fn(&p, w->listen_port, w->seam_ctx);

    int delay;
    pthread_mutex_lock(&w->mu);
    w->profile = p;
    w->state = ok ? PSW_MAPPED : PSW_UNMAPPED;
    delay = psw_next_delay_secs(ok, &w->backoff_secs);
    w->next_delay_secs = delay;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);

    /* Structured completion record — the async successor of the boot-time
     * "Reachability:" line. */
    char ip_str[24] = "";
    if (p.has_public_ip)
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 p.public_ip[0], p.public_ip[1], p.public_ip[2],
                 p.public_ip[3]);
    log_jsonf(ok ? LOG_JSON_INFO : LOG_JSON_WARN, "nat_probe_complete",
              "\"state\":\"%s\",\"clearnet\":\"%s\",\"tor\":%s,"
              "\"next_probe_s\":%d",
              psw_state_name(ok ? PSW_MAPPED : PSW_UNMAPPED), ip_str,
              p.tor_available ? "true" : "false", delay);
    if (!ok)
        LOG_WARN("net",
                 "nat probe/renewal failed (no public endpoint reached); "
                 "node keeps serving, retry in %ds", delay);

    pthread_mutex_lock(&w->mu);
    stop = w->stop;
    pthread_mutex_unlock(&w->mu);
    return !stop;
}

/* ── Thread shell ───────────────────────────────────────────── */

static void *psw_main(void *arg)
{
    struct peer_strategy_worker *w = arg;

    for (;;) {
        if (!peer_strategy_worker_run_once(w))
            break;

        /* Interruptible renewal wait: stop() broadcasts and we wake at
         * once; otherwise the condvar deadline IS the next probe time. */
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        pthread_mutex_lock(&w->mu);
        deadline.tv_sec += w->next_delay_secs;
        while (!w->stop) {
            int rc = pthread_cond_timedwait(&w->cv, &w->mu, &deadline);
            if (rc == ETIMEDOUT)
                break;
            if (rc != 0) {
                /* Spurious-free condvar error: log and fall through to a
                 * bounded re-check rather than spinning silently. */
                LOG_WARN("net", "nat probe worker cond wait rc=%d", rc);
                break;
            }
        }
        bool stop = w->stop;
        pthread_mutex_unlock(&w->mu);
        if (stop)
            break;
    }

    pthread_mutex_lock(&w->mu);
    if (w->state == PSW_PROBING || w->state == PSW_MAPPED ||
        w->state == PSW_UNMAPPED)
        w->state = PSW_IDLE;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
    return NULL;
}

bool peer_strategy_worker_start(struct peer_strategy_worker *w)
{
    if (!w)
        LOG_FAIL("net", "peer_strategy_worker_start: null worker");
    if (w->started)
        return true;

    pthread_mutex_lock(&w->mu);
    w->stop = false;
    w->state = PSW_PROBING;
    pthread_mutex_unlock(&w->mu);

    /* Non-NULL out_tid: caller-owned join (join ownership transfers to this
     * module; peer_strategy_worker_join reaps). The registry remains the
     * shutdown fallback while it is live. */
    // thread-supervision-ok: bounded joined probe worker, stopped+joined at shutdown
    int rc = thread_registry_spawn("zcl_nat_probe", psw_main, w, &w->tid);
    if (rc != 0) {
        pthread_mutex_lock(&w->mu);
        w->state = PSW_IDLE;
        pthread_mutex_unlock(&w->mu);
        LOG_WARN("net", "nat probe worker spawn failed rc=%d; "
                        "port mapping and reachability discovery unavailable "
                        "this boot", rc);
        return false;
    }
    w->started = true;
    return true;
}

void peer_strategy_worker_stop(struct peer_strategy_worker *w)
{
    if (!w) {
        LOG_ERROR("net", "peer_strategy_worker_stop: null worker");
        return;
    }
    pthread_mutex_lock(&w->mu);
    w->stop = true;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
}

void peer_strategy_worker_join(struct peer_strategy_worker *w)
{
    if (!w || !w->started)
        return;

    struct timespec deadline;
    platform_time_realtime_timespec(&deadline);
    deadline.tv_sec += PSW_JOIN_TIMEOUT_SECS;
    int rc = platform_thread_join_until(w->tid, NULL, &deadline);
    if (rc != 0) {
        /* The in-flight probe is socket-timeout bounded (~25 s worst case),
         * so this is a loud straggler note, then the unconditional join —
         * ownership is never abandoned. */
        fprintf(stderr, // obs-ok:shutdown-join-straggler-note
                "[shutdown] nat probe worker join did not complete within "
                "%ds (rc=%d); waiting out the in-flight probe\n",
                PSW_JOIN_TIMEOUT_SECS, rc);
        pthread_join(w->tid, NULL);
    }
    w->started = false;
}

enum psw_state
peer_strategy_worker_snapshot(struct peer_strategy_worker *w,
                              struct node_profile *out)
{
    if (!w)
        LOG_RETURN(PSW_IDLE, "net",
                   "peer_strategy_worker_snapshot: null worker");

    pthread_mutex_lock(&w->mu);
    enum psw_state s = w->state;
    if (out)
        *out = w->profile;
    pthread_mutex_unlock(&w->mu);
    return s;
}
