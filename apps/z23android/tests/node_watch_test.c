/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* The hidden-app decision: the foreground service stops once the node has exited, and stops
 * watching when the service is stopped first. */
#include "../node_watch.h"
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static int failures;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "node_watch_test: %s:%d: %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static atomic_bool node_up, hold_alive;
static void pause_ms(long ms);
static atomic_int gone_calls, checks;
static bool alive(void *context) { (void)context; atomic_fetch_add(&checks, 1);
    while (atomic_load(&hold_alive)) pause_ms(1);
    return atomic_load(&node_up);
}
static atomic_int gone_failures;
static atomic_bool ended;
/* A failed attach leaves `ended` false and asks for a retry. */
static bool gone(void *context)
{
    (void)context; atomic_fetch_add(&gone_calls, 1);
    if (atomic_load(&gone_failures) > 0) { atomic_fetch_sub(&gone_failures, 1); return false; }
    atomic_store(&ended, true);
    return true;
}
static const struct node_watch_ops ops = { alive, gone, NULL, 10 };

static void pause_ms(long ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}
static void reset(bool up)
{
    atomic_store(&node_up, up); atomic_store(&gone_calls, 0); atomic_store(&checks, 0);
    atomic_store(&gone_failures, 0); atomic_store(&ended, false); atomic_store(&hold_alive, false);
}

static void test_node_exits_while_watching(void)
{
    reset(true);
    CHECK(zapp_node_watch_start(&ops));
    pause_ms(60);
    CHECK(atomic_load(&checks) > 0 && atomic_load(&gone_calls) == 0);
    atomic_store(&node_up, false);
    for (int i = 0; i < 200 && !atomic_load(&gone_calls); ++i) pause_ms(10);
    CHECK(atomic_load(&gone_calls) == 1);
    pause_ms(60);
    CHECK(atomic_load(&gone_calls) == 1);
    zapp_node_watch_stop();
}
static void test_stop_before_exit(void)
{
    reset(true);
    CHECK(zapp_node_watch_start(&ops));
    pause_ms(40);
    zapp_node_watch_stop();
    int seen = atomic_load(&checks);
    atomic_store(&node_up, false);
    pause_ms(80);
    CHECK(atomic_load(&gone_calls) == 0 && atomic_load(&checks) == seen);
}
static void test_restart_replaces(void)
{
    reset(true);
    CHECK(zapp_node_watch_start(&ops) && zapp_node_watch_start(&ops));
    atomic_store(&node_up, false);
    for (int i = 0; i < 200 && !atomic_load(&gone_calls); ++i) pause_ms(10);
    pause_ms(60);
    CHECK(atomic_load(&gone_calls) == 1);
    zapp_node_watch_stop();
    zapp_node_watch_stop();
}
static void *stop_thread(void *unused) { (void)unused; zapp_node_watch_stop(); return NULL; }
/* A stop that lands while a tick is inside alive() must suppress gone(). */
static void test_stop_races_tick(void)
{
    pthread_t stopper;
    reset(true);
    atomic_store(&hold_alive, true);
    CHECK(zapp_node_watch_start(&ops));
    for (int i = 0; i < 200 && !atomic_load(&checks); ++i) pause_ms(5);
    atomic_store(&node_up, false);
    CHECK(pthread_create(&stopper, NULL, stop_thread, NULL) == 0);
    pause_ms(60);
    atomic_store(&hold_alive, false);
    pthread_join(stopper, NULL);
    pause_ms(40);
    CHECK(atomic_load(&gone_calls) == 0 && !atomic_load(&ended));
}
/* A gone() that could not stop the service (failed attach) leaves ended false and is retried. */
static void test_failed_gone_retries(void)
{
    reset(false);
    atomic_store(&gone_failures, 1000000);
    CHECK(zapp_node_watch_start(&ops));
    for (int i = 0; i < 400 && atomic_load(&gone_calls) < 3; ++i) pause_ms(5);
    CHECK(atomic_load(&gone_calls) >= 3 && !atomic_load(&ended));
    atomic_store(&gone_failures, 0);
    for (int i = 0; i < 400 && !atomic_load(&ended); ++i) pause_ms(5);
    CHECK(atomic_load(&ended));
    int calls = atomic_load(&gone_calls);
    pause_ms(60);
    CHECK(atomic_load(&gone_calls) == calls);
    zapp_node_watch_stop();
}
static void test_rejects_bad_ops(void)
{
    struct node_watch_ops bad = ops;
    bad.interval_ms = 0;
    CHECK(!zapp_node_watch_start(&bad) && !zapp_node_watch_start(NULL));
}
int main(void)
{
    test_node_exits_while_watching(); test_stop_before_exit(); test_restart_replaces(); test_stop_races_tick(); test_failed_gone_retries();
    test_rejects_bad_ops();
    if (failures) { fprintf(stderr, "node_watch_test: %d failure(s)\n", failures); return 1; }
    puts("node_watch_test: ok");
    return 0;
}
