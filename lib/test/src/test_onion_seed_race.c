/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_seed_race — a dead or slow onion seed must not delay a live
 * one. The production race starts concurrent fetches and returns the first
 * usable 200-body without waiting for the rest.
 *
 * The blocking Tor fetch cannot be cancelled, so the proof is a
 * relationship, not a wall-clock budget: after the race returns the fast
 * door, the slow fetch is still in flight. A duration assertion would
 * pass on an SSD and fail on a 7200rpm box; in_flight > 0 after return
 * does not. */

#include "test/test_core.h"

#include "net/onion_seed_race.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RACE_CHECK(name, expr) do {                         \
    printf("onion_seed_race: %s... ", (name));              \
    if (expr) printf("OK\n");                               \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

struct race_stub {
    const char *slow_host;
    const char *live_host;
    const char *reject_host;
    _Atomic int slow_may_finish;
    _Atomic int slow_started;
};

static int race_stub_fill_live(struct onion_fetch_result *result,
                               const char *onion)
{
    size_t n = strlen(onion);
    result->body = zcl_malloc(n + 1u, "onion_seed_race_test_body");
    if (!result->body) {
        atomic_store(&result->complete, -1);
        return -1;
    }
    memcpy(result->body, onion, n + 1u);
    result->body_len = n;
    result->status = 200;
    atomic_store(&result->complete, 1);
    return 0;
}

static int race_stub_fetch(const char *onion, const char *path,
                           struct onion_fetch_result *result,
                           int timeout_secs, void *ctx)
{
    (void)path;
    (void)timeout_secs;
    if (result)
        memset(result, 0, sizeof(*result));
    if (!onion || !result) {
        if (result)
            atomic_store(&result->complete, -1);
        return -1;
    }

    struct race_stub *stub = ctx;
    if (!stub) {
        atomic_store(&result->complete, -1);
        return -1;
    }

    if (stub->slow_host && strcmp(onion, stub->slow_host) == 0) {
        atomic_store(&stub->slow_started, 1);
        while (atomic_load(&stub->slow_may_finish) == 0)
            platform_sleep_ms(10);
        atomic_store(&result->complete, -1);
        return -1;
    }
    if (stub->reject_host && strcmp(onion, stub->reject_host) == 0) {
        result->status = 404;
        atomic_store(&result->complete, -1);
        return -1;
    }
    if (stub->live_host && strcmp(onion, stub->live_host) == 0)
        return race_stub_fill_live(result, onion);

    /* Two-live case: any host that is not slow/reject is usable. */
    return race_stub_fill_live(result, onion);
}

static void race_stub_init(struct race_stub *stub, const char *slow,
                           const char *live, const char *reject)
{
    memset(stub, 0, sizeof(*stub));
    stub->slow_host = slow;
    stub->live_host = live;
    stub->reject_host = reject;
    atomic_init(&stub->slow_may_finish, 0);
    atomic_init(&stub->slow_started, 0);
}

static int check_slow_does_not_delay_live(const char *first, const char *second,
                                          const char *slow, const char *live)
{
    int failures = 0;
    struct race_stub stub;
    race_stub_init(&stub, slow, live, NULL);

    const char *hosts[2] = { first, second };
    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    size_t winner_index = (size_t)-1;
    struct onion_seed_race_join *join = NULL;

    int rc = onion_seed_race_first_usable(hosts, 2, race_stub_fetch, &stub,
                                          60, NULL, &winner, &winner_index,
                                          &join);

    RACE_CHECK("race returned success", rc == 0);
    RACE_CHECK("winner index names the live seed",
               winner_index < 2 && strcmp(hosts[winner_index], live) == 0);
    RACE_CHECK("winner body is the live seed's answer",
               winner.body && winner.status == 200 &&
               strcmp((const char *)winner.body, live) == 0);
    RACE_CHECK("slow fetch is still in flight after the live answer",
               onion_seed_race_join_in_flight(join) > 0);
    RACE_CHECK("slow fetch was not released by the race",
               atomic_load(&stub.slow_may_finish) == 0);

    atomic_store(&stub.slow_may_finish, 1);
    onion_seed_race_join_wait(join);
    onion_seed_race_join_free(join);
    free(winner.body);
    return failures;
}

static int check_reject_is_not_usable(void)
{
    int failures = 0;
    struct race_stub stub;
    race_stub_init(&stub, NULL, "live.onion", "dead.onion");

    const char *hosts[2] = { "dead.onion", "live.onion" };
    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    size_t winner_index = (size_t)-1;
    struct onion_seed_race_join *join = NULL;

    int rc = onion_seed_race_first_usable(hosts, 2, race_stub_fetch, &stub,
                                          60, NULL, &winner, &winner_index,
                                          &join);

    RACE_CHECK("a 404 is not a usable door", rc == 0 && winner_index == 1);
    RACE_CHECK("the 200 body is the live seed",
               winner.body &&
               strcmp((const char *)winner.body, "live.onion") == 0);

    onion_seed_race_join_wait(join);
    onion_seed_race_join_free(join);
    free(winner.body);
    return failures;
}

static int check_either_live_seed_is_acceptable(void)
{
    int failures = 0;
    struct race_stub stub;
    race_stub_init(&stub, NULL, NULL, NULL);

    const char *hosts[2] = { "alpha.onion", "beta.onion" };
    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    size_t winner_index = (size_t)-1;
    struct onion_seed_race_join *join = NULL;

    int rc = onion_seed_race_first_usable(hosts, 2, race_stub_fetch, &stub,
                                          60, NULL, &winner, &winner_index,
                                          &join);

    bool known_winner = winner_index < 2 && winner.body &&
        strcmp((const char *)winner.body, hosts[winner_index]) == 0;
    RACE_CHECK("either live seed's answer is accepted",
               rc == 0 && known_winner);

    onion_seed_race_join_wait(join);
    onion_seed_race_join_free(join);
    free(winner.body);
    return failures;
}

static int check_all_dead(void)
{
    int failures = 0;
    struct race_stub stub;
    race_stub_init(&stub, NULL, NULL, "dead.onion");

    const char *hosts[2] = { "dead.onion", "dead.onion" };
    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    size_t winner_index = (size_t)-1;
    struct onion_seed_race_join *join = NULL;

    int rc = onion_seed_race_first_usable(hosts, 2, race_stub_fetch, &stub,
                                          60, NULL, &winner, &winner_index,
                                          &join);

    RACE_CHECK("all-dead race fails", rc < 0);
    RACE_CHECK("all-dead race leaves no body", winner.body == NULL);
    RACE_CHECK("all-dead race leaves winner_index unset",
               winner_index == (size_t)-1);

    onion_seed_race_join_wait(join);
    onion_seed_race_join_free(join);
    return failures;
}

static int check_empty_and_null(void)
{
    int failures = 0;
    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    winner.status = 7;
    size_t winner_index = 3;
    struct onion_seed_race_join *join = (struct onion_seed_race_join *)1;

    int rc = onion_seed_race_first_usable(NULL, 1, race_stub_fetch, NULL,
                                          60, NULL, &winner, &winner_index,
                                          &join);
    RACE_CHECK("NULL hosts fails", rc < 0);
    RACE_CHECK("NULL hosts still assigns winner", winner.status == 0 &&
               winner.body == NULL);
    RACE_CHECK("NULL hosts still assigns winner_index",
               winner_index == (size_t)-1);
    RACE_CHECK("NULL hosts still assigns join_out", join == NULL);

    const char *hosts[1] = { "x.onion" };
    memset(&winner, 0, sizeof(winner));
    winner.status = 7;
    winner_index = 3;
    join = (struct onion_seed_race_join *)1;
    rc = onion_seed_race_first_usable(hosts, 0, race_stub_fetch, NULL,
                                      60, NULL, &winner, &winner_index,
                                      &join);
    RACE_CHECK("empty list fails", rc < 0);
    RACE_CHECK("empty list assigns winner_index",
               winner_index == (size_t)-1);
    RACE_CHECK("empty list assigns join_out", join == NULL);
    return failures;
}

int test_onion_seed_race(void)
{
    int failures = 0;

    printf("\n=== onion seed race ===\n");
    failures += check_slow_does_not_delay_live("slow.onion", "live.onion",
                                               "slow.onion", "live.onion");
    failures += check_slow_does_not_delay_live("live.onion", "slow.onion",
                                               "slow.onion", "live.onion");
    failures += check_reject_is_not_usable();
    failures += check_either_live_seed_is_acceptable();
    failures += check_all_dead();
    failures += check_empty_and_null();

    printf("=== onion seed race: %d failure(s) ===\n", failures);
    return failures;
}
