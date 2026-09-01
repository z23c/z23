/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_status_frontdoor — Program O2 proof.
 *
 * The old `z23 status` front door made TWELVE sequential RPC calls, some
 * of which recomputed H* under progress_store_tx_lock — so a `status` issued
 * while the reducer owned that lock queued behind the fold and the whole
 * observability front door went dark exactly when the node was busiest.
 *
 * The rewrite composes the body from lock-free / trylock-guarded in-process
 * snapshot sources (status_frontdoor_dump_state_json). This test PROVES the
 * composition never blocks behind progress_store_tx_lock: a writer thread grabs
 * that lock and holds it, and on the main thread we call the composition and
 * assert it RETURNS — fully populated, with labeled-stale fields — while the
 * writer still holds the lock, in a small fraction of the writer's hold time. A
 * regression that reintroduced a blocking read would instead complete only when
 * the writer's ceiling released, tripping the latency bound below (it cannot
 * hang forever: the holder auto-releases at its ceiling). */

#include "controllers/status_frontdoor.h"
#include "controllers/status_native_helpers.h"
#include "jobs/reducer_frontier.h"
#include "storage/progress_store.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Writer contention parameters. The holder keeps progress_store_tx_lock for up
 * to HOLD_CEILING_US unless released sooner; the composition must complete in
 * well under that (COMPLETE_BOUND_US) to prove it never waited for the lock. */
#define HOLD_CEILING_US   4000000  /* 4 s hard ceiling — no infinite hang */
#define COMPLETE_BOUND_US 1000000  /* 1 s: >> real (µs) cost, << the 4 s hold */
#define ACQUIRE_WAIT_US   2000000  /* wait up to 2 s for the writer to acquire */

struct hold_ctx {
    _Atomic bool acquired;
    _Atomic bool release;
};

static void tiny_sleep_us(int64_t us)
{
    struct timespec ts = { .tv_sec = us / 1000000,
                           .tv_nsec = (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

static void *lock_holder_main(void *arg)
{
    struct hold_ctx *c = arg;
    progress_store_tx_lock();
    atomic_store(&c->acquired, true);
    int64_t start = platform_time_monotonic_us();
    /* Hold until the main thread releases us OR the safety ceiling elapses, so
     * a genuine regression fails loudly on the latency bound rather than
     * deadlocking the whole test group forever. */
    while (!atomic_load(&c->release) &&
           platform_time_monotonic_us() - start < HOLD_CEILING_US)
        tiny_sleep_us(1000);
    progress_store_tx_unlock();
    return NULL;
}

/* Assert the composed body carries the load-bearing labeled members. Returns
 * the number of failed checks. */
static int check_body_shape(const struct json_value *body, const char *ctx)
{
    int fails = 0;
#define REQ(cond, what)                                                    \
    do {                                                                   \
        if (!(cond)) {                                                      \
            printf("  FAIL [%s]: missing/invalid %s\n", ctx, what);        \
            fails++;                                                        \
        }                                                                  \
    } while (0)

    const struct json_value *height = json_get(body, "height");
    REQ(height && height->type == JSON_INT, "height");
    const struct json_value *tip = json_get(body, "provable_tip");
    REQ(tip && tip->type == JSON_INT, "provable_tip");
    const struct json_value *pub = json_get(body, "provable_tip_published");
    REQ(pub && pub->type == JSON_BOOL, "provable_tip_published");
    const struct json_value *floor = json_get(body, "reducer_floor");
    REQ(floor && floor->type == JSON_INT, "reducer_floor");

    const struct json_value *conn = json_get(body, "connections");
    REQ(conn && conn->type == JSON_OBJ, "connections");
    if (conn && conn->type == JSON_OBJ) {
        const struct json_value *stale = json_get(conn, "stale");
        REQ(stale && stale->type == JSON_BOOL, "connections.stale");
        const struct json_value *reason = json_get(conn, "warning_reason");
        REQ(reason && reason->type == JSON_STR, "connections.warning_reason");
    }

    const struct json_value *blockers = json_get(body, "blockers");
    REQ(blockers && blockers->type == JSON_OBJ, "blockers");
    const struct json_value *active = json_get(body, "active_blocker_count");
    REQ(active && active->type == JSON_INT, "active_blocker_count");

    const struct json_value *degraded = json_get(body, "degraded");
    REQ(degraded && degraded->type == JSON_ARR, "degraded[]");
    const struct json_value *fresh = json_get(body, "all_members_fresh");
    REQ(fresh && fresh->type == JSON_BOOL, "all_members_fresh");
#undef REQ
    return fails;
}

static int test_basic_shape(void)
{
    int failures = 0;
    printf("status_frontdoor: composes a labeled body... ");
    struct json_value body;
    json_init(&body);
    bool ok = status_frontdoor_dump_state_json(&body, NULL);
    if (!ok) {
        printf("FAIL (dump returned false)\n");
        json_free(&body);
        return 1;
    }
    failures += check_body_shape(&body, "basic");
    json_free(&body);
    if (failures == 0)
        printf("OK\n");
    return failures;
}

static int test_completes_under_held_lock(void)
{
    int failures = 0;
    printf("status_frontdoor: composes while a writer holds "
           "progress_store_tx_lock... ");

    /* Warm the self-anchor / floor cache OUTSIDE the timed section, exactly as
     * production does at boot, so the timed composition is the steady-state
     * lock-free read path (the first call does a one-shot datadir probe, never
     * the progress lock). */
    (void)reducer_frontier_floor();

    struct hold_ctx ctx = { 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, lock_holder_main, &ctx) != 0) {
        printf("FAIL (pthread_create)\n");
        return 1;
    }

    /* Wait until the writer actually owns the lock. */
    int64_t waited = 0;
    while (!atomic_load(&ctx.acquired) && waited < ACQUIRE_WAIT_US) {
        tiny_sleep_us(1000);
        waited += 1000;
    }
    if (!atomic_load(&ctx.acquired)) {
        printf("FAIL (writer never acquired the lock)\n");
        atomic_store(&ctx.release, true);
        pthread_join(th, NULL);
        return 1;
    }

    struct json_value body;
    json_init(&body);
    int64_t t0 = platform_time_monotonic_us();
    bool ok = status_frontdoor_dump_state_json(&body, NULL);
    int64_t elapsed = platform_time_monotonic_us() - t0;

    /* The decisive assertions: the composition returned while the writer STILL
     * holds the lock (release is still false), and it did so far faster than
     * the writer's hold ceiling — it never waited for the lock. */
    bool still_held = !atomic_load(&ctx.release);
    if (!ok) { printf("FAIL (dump returned false under load)\n"); failures++; }
    if (!still_held) {
        printf("FAIL (writer released before the call returned — "
               "cannot attribute non-blocking)\n");
        failures++;
    }
    if (elapsed >= COMPLETE_BOUND_US) {
        printf("FAIL (composition took %lldus >= %dus bound — it blocked "
               "behind the held lock)\n",
               (long long)elapsed, COMPLETE_BOUND_US);
        failures++;
    }
    failures += check_body_shape(&body, "under-load");

    atomic_store(&ctx.release, true);
    pthread_join(th, NULL);
    json_free(&body);
    if (failures == 0)
        printf("OK (%lldus under a held writer lock)\n", (long long)elapsed);
    return failures;
}

static int test_peer_survey_counts_sync_states_as_ready(void)
{
    static const char *const operational[] = {
        "handshake_complete", "active", "syncing_headers",
        "syncing_blocks", "snapshot_serving", "snapshot_receiving",
    };
    static const char *const terminal[] = {
        "connected", "stale", "disconnecting", "banned",
    };
    struct json_value peers = {0};
    struct peer_survey survey;

    printf("status_frontdoor: peer survey keeps sync states relay-ready... ");
    json_set_array(&peers);
    for (size_t i = 0; i < sizeof(operational) / sizeof(operational[0]); i++) {
        struct json_value peer = {0};
        json_set_object(&peer);
        json_push_kv_str(&peer, "state", operational[i]);
        json_push_back(&peers, &peer);
        json_free(&peer);
    }
    for (size_t i = 0; i < sizeof(terminal) / sizeof(terminal[0]); i++) {
        struct json_value peer = {0};
        json_set_object(&peer);
        json_push_kv_str(&peer, "state", terminal[i]);
        json_push_back(&peers, &peer);
        json_free(&peer);
    }

    status_peer_survey(&peers, &survey);
    json_free(&peers);
    if (!survey.ready_known || survey.ready != 6) {
        printf("FAIL (ready_known=%d ready=%d want=6)\n",
               survey.ready_known, survey.ready);
        return 1;
    }
    printf("OK\n");
    return 0;
}

int test_status_frontdoor(void);
int test_status_frontdoor(void)
{
    printf("\n=== status_frontdoor (Program O2 single-round-trip status) ===\n");
    int failures = 0;
    failures += test_basic_shape();
    failures += test_completes_under_held_lock();
    failures += test_peer_survey_counts_sync_states_as_ready();
    return failures;
}
