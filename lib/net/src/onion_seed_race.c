/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: concurrent first-usable onion-seed fetch. The blocking Tor
 * fetch cannot be cancelled, so a loser is joined only by waiting out
 * its own timeout into a discarded result.
 *
 * ── Thread ownership and the supervisor contract ───────────────────────
 *
 * Every worker is spawned through thread_registry_spawn() with a non-NULL
 * out_tid, which transfers join ownership to this module: the tid is
 * recorded in the race's join handle and onion_seed_race_join_wait()
 * pthread_join()s it. Nothing here is ever detached. A worker therefore
 * cannot outlive the caller's join, and thread_registry's shutdown sweep
 * can name it if it does hang.
 *
 * The racer is still on the supervisor liveness tree, as a ROOT child
 * ("zcl_onion_seed_race" — lib/net cannot include the app-side
 * supervisors/domains.h without a lib-layering violation, see
 * util/thread_liveness.h). It registers LIVENESS-ONLY: deadline_secs = 0
 * and progress_quiet_us = 0. That is not a weakened contract, it is the
 * only honest one available here, for two reasons a reader should not have
 * to rediscover:
 *
 *   1. The racer is event-driven, not periodic. It runs during onion
 *      bootstrap and is then legitimately silent for the entire life of a
 *      healthy node. A heartbeat deadline or a progress-quiet gate would
 *      name a stall blocker on every node that simply found its peers.
 *
 *   2. A worker's whole body is ONE uninterruptible blocking call. It
 *      cannot beat a cadence mid-fetch even in principle, so a cadence is
 *      not a thing this module can promise. What bounds a worker is the
 *      caller's timeout_secs, enforced inside the fetch primitive.
 *
 * What the tree does get is real: the child is PRESENT (so
 * `z23 dumpstate supervisor` shows the racer exists), and its progress
 * marker is a monotonic count of seed fetches that have COMPLETED since
 * boot — advanced by each worker as it returns, so an operator watching a
 * frozen marker alongside a non-zero in-flight count is looking at a
 * genuinely wedged Tor fetch. */

#include "net/onion_seed_race.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Root liveness child for the racer as a whole — see the header comment
 * for why both stall gates are disabled. Registered lazily (idempotent) on
 * the first race so a build that never bootstraps over Tor does not carry
 * a child that can never beat. */
static struct thread_liveness_child g_race_liveness = {
    .id = SUPERVISOR_INVALID_ID
};
/* Seed fetches completed since boot. Monotonic; the child's progress
 * marker. */
static _Atomic long long g_race_fetches_done;

struct onion_seed_race_join {
    _Atomic int in_flight;
    /* Written only by the thread running the race, read only by that same
     * thread in join_wait — the workers never touch these. */
    size_t cap;
    size_t n;
    size_t joined;
    pthread_t tid[];
};

struct onion_seed_race_wave {
    _Atomic int refs;
    _Atomic int in_flight;
    _Atomic int winner_claimed;
    _Atomic int winner_ready;
    struct onion_fetch_result winner;
    size_t winner_index;
    onion_seed_fetch_fn fetch;
    void *fetch_ctx;
    int timeout_secs;
    struct onion_seed_race_join *join;
};

enum { ONION_SEED_RACE_HOST_CAP = 68 };

struct onion_seed_race_worker {
    struct onion_seed_race_wave *wave;
    char host[ONION_SEED_RACE_HOST_CAP];
    size_t index;
};

static void onion_seed_race_beat(void)
{
    thread_liveness_beat(&g_race_liveness,
                         (int64_t)atomic_load_explicit(&g_race_fetches_done,
                                                       memory_order_relaxed));
}

static void onion_seed_race_wave_release(struct onion_seed_race_wave *wave)
{
    if (!wave)
        return;
    if (atomic_fetch_sub_explicit(&wave->refs, 1, memory_order_acq_rel) != 1)
        return;
    if (wave->winner.body)
        free(wave->winner.body);
    free(wave);
}

static void *onion_seed_race_worker(void *arg)
{
    struct onion_seed_race_worker *w = arg;
    struct onion_seed_race_wave *wave = w->wave;
    struct onion_fetch_result result;
    memset(&result, 0, sizeof(result));

    int rc = wave->fetch(w->host, "/directory.json", &result,
                         wave->timeout_secs, wave->fetch_ctx);
    bool usable = (rc == 0 && result.status == 200 && result.body != NULL);
    if (usable) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(&wave->winner_claimed,
                                                    &expected, 1,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire)) {
            atomic_store_explicit(&wave->winner.complete,
                                  atomic_load_explicit(&result.complete,
                                                       memory_order_relaxed),
                                  memory_order_relaxed);
            wave->winner.status = result.status;
            wave->winner.body = result.body;
            wave->winner.body_len = result.body_len;
            wave->winner_index = w->index;
            result.body = NULL;
            atomic_store_explicit(&wave->winner_ready, 1, memory_order_release);
        }
    }
    if (result.body)
        free(result.body);
    /* One completed fetch — the supervisor's progress marker, published
     * before the in-flight counters drop so a reader that sees in_flight
     * fall has already seen the work it accounted for. */
    (void)atomic_fetch_add_explicit(&g_race_fetches_done, 1,
                                    memory_order_acq_rel);
    onion_seed_race_beat();
    if (wave->join)
        atomic_fetch_sub_explicit(&wave->join->in_flight, 1,
                                  memory_order_acq_rel);
    atomic_fetch_sub_explicit(&wave->in_flight, 1, memory_order_acq_rel);
    onion_seed_race_wave_release(wave);
    free(w);
    return NULL;
}

static int onion_seed_race_start_worker(struct onion_seed_race_wave *wave,
                                        const char *host, size_t index)
{
    if (!wave || !wave->join || !host || !host[0])
        return -1;
    struct onion_seed_race_join *join = wave->join;
    if (join->n >= join->cap) {
        LOG_ERROR("net", "onion seed race worker slots exhausted (%zu)",
                  join->cap);
        return -1;
    }
    size_t host_len = strlen(host);
    if (host_len >= ONION_SEED_RACE_HOST_CAP) {
        LOG_ERROR("net", "onion seed race host too long (%zu)", host_len);
        return -1;
    }

    struct onion_seed_race_worker *w =
        zcl_malloc(sizeof(*w), "onion_seed_race_worker");
    if (!w) {
        LOG_ERROR("net", "onion seed race worker allocation failed");
        return -1;
    }
    memset(w, 0, sizeof(*w));
    memcpy(w->host, host, host_len + 1u);
    w->index = index;
    w->wave = wave;

    atomic_fetch_add_explicit(&wave->refs, 1, memory_order_acq_rel);
    atomic_fetch_add_explicit(&wave->in_flight, 1, memory_order_acq_rel);
    atomic_fetch_add_explicit(&join->in_flight, 1, memory_order_acq_rel);

    /* Joinable, caller-owned: the non-NULL out_tid hands join ownership to
     * this module, and join->tid[] is where onion_seed_race_join_wait()
     * finds it. Nothing here is detached. */
    pthread_t tid;
    int rc = thread_registry_spawn("zcl_seed_race", onion_seed_race_worker,
                                   w, &tid);
    if (rc != 0) {
        atomic_fetch_sub_explicit(&join->in_flight, 1, memory_order_acq_rel);
        atomic_fetch_sub_explicit(&wave->in_flight, 1, memory_order_acq_rel);
        onion_seed_race_wave_release(wave);
        free(w);
        LOG_ERROR("net", "onion seed race spawn failed: rc=%d", rc);
        return -1;
    }
    join->tid[join->n++] = tid;
    return 0;
}

int onion_seed_race_first_usable(const char *const *hosts,
                                 size_t n,
                                 onion_seed_fetch_fn fetch,
                                 void *fetch_ctx,
                                 int timeout_secs,
                                 const _Atomic bool *stop,
                                 struct onion_fetch_result *winner,
                                 size_t *winner_index,
                                 struct onion_seed_race_join **join_out)
{
    if (winner)
        memset(winner, 0, sizeof(*winner));
    if (winner_index)
        *winner_index = (size_t)-1;
    if (join_out)
        *join_out = NULL;

    if (!hosts || !fetch || !winner || !winner_index || !join_out)
        LOG_ERR("net", "onion seed race missing required argument");
    if (n == 0)
        return -1;

    (void)thread_liveness_register(&g_race_liveness, "zcl_onion_seed_race",
                                   0, 0);
    onion_seed_race_beat();

    struct onion_seed_race_join *join =
        zcl_calloc(1, sizeof(*join) + n * sizeof(pthread_t),
                   "onion_seed_race_join");
    if (!join)
        LOG_ERR("net", "onion seed race join allocation failed");
    atomic_init(&join->in_flight, 0);
    join->cap = n;
    join->n = 0;
    join->joined = 0;
    *join_out = join;

    struct onion_seed_race_wave *wave =
        zcl_calloc(1, sizeof(*wave), "onion_seed_race_wave");
    if (!wave) {
        *join_out = NULL;
        free(join);
        LOG_ERR("net", "onion seed race wave allocation failed");
    }
    atomic_init(&wave->refs, 1);
    atomic_init(&wave->in_flight, 0);
    atomic_init(&wave->winner_claimed, 0);
    atomic_init(&wave->winner_ready, 0);
    wave->fetch = fetch;
    wave->fetch_ctx = fetch_ctx;
    wave->timeout_secs = timeout_secs;
    wave->join = join;

    size_t next = 0;
    while (next < n && next < (size_t)ONION_SEED_RACE_MAX_INFLIGHT) {
        (void)onion_seed_race_start_worker(wave, hosts[next], next);
        next++;
    }

    for (;;) {
        if (atomic_load_explicit(&wave->winner_ready, memory_order_acquire))
            break;
        if (stop && atomic_load_explicit(stop, memory_order_acquire))
            break;

        int inflight = atomic_load_explicit(&wave->in_flight,
                                            memory_order_acquire);
        if (inflight == 0) {
            while (next < n &&
                   (size_t)atomic_load_explicit(&wave->in_flight,
                                                memory_order_acquire) <
                       (size_t)ONION_SEED_RACE_MAX_INFLIGHT) {
                (void)onion_seed_race_start_worker(wave, hosts[next], next);
                next++;
            }
            if (atomic_load_explicit(&wave->in_flight,
                                     memory_order_acquire) == 0 &&
                next >= n)
                break;
        } else if (next < n &&
                   (size_t)inflight < (size_t)ONION_SEED_RACE_MAX_INFLIGHT) {
            (void)onion_seed_race_start_worker(wave, hosts[next], next);
            next++;
            continue;
        }
        onion_seed_race_beat();
        platform_sleep_ms(10);
    }

    int rc = -1;
    if (atomic_load_explicit(&wave->winner_ready, memory_order_acquire)) {
        atomic_store_explicit(&winner->complete,
                              atomic_load_explicit(&wave->winner.complete,
                                                   memory_order_relaxed),
                              memory_order_relaxed);
        winner->status = wave->winner.status;
        winner->body = wave->winner.body;
        winner->body_len = wave->winner.body_len;
        wave->winner.body = NULL;
        *winner_index = wave->winner_index;
        rc = 0;
    }

    onion_seed_race_wave_release(wave);
    return rc;
}

void onion_seed_race_join_wait(struct onion_seed_race_join *join)
{
    if (!join)
        return;
    while (join->joined < join->n) {
        (void)pthread_join(join->tid[join->joined], NULL);
        join->joined++;
        onion_seed_race_beat();
    }
}

void onion_seed_race_join_free(struct onion_seed_race_join *join)
{
    if (!join)
        return;
    /* Idempotent: a caller that already joined falls straight through, and
     * one that forgot cannot free a live worker's state. */
    onion_seed_race_join_wait(join);
    free(join);
}

int onion_seed_race_join_in_flight(const struct onion_seed_race_join *join)
{
    if (!join)
        return 0;
    return atomic_load_explicit(&join->in_flight, memory_order_acquire);
}
