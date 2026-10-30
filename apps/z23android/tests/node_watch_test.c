/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* The hidden-app decision: the foreground service stops once the node has exited, and stops
 * watching when the service is stopped first. */
#include "../node_watch.h"
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

static int failures;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "node_watch_test: %s:%d: %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static atomic_bool node_up;
static atomic_int gone_calls, checks;
static bool alive(void *context) { (void)context; atomic_fetch_add(&checks, 1); return atomic_load(&node_up); }
static void gone(void *context) { (void)context; atomic_fetch_add(&gone_calls, 1); }
static const struct node_watch_ops ops = { alive, gone, NULL, 10 };

static void pause_ms(long ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}
static void reset(bool up) { atomic_store(&node_up, up); atomic_store(&gone_calls, 0); atomic_store(&checks, 0); }

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
static void test_rejects_bad_ops(void)
{
    struct node_watch_ops bad = ops;
    bad.interval_ms = 0;
    CHECK(!zapp_node_watch_start(&bad) && !zapp_node_watch_start(NULL));
}
int main(void)
{
    test_node_exits_while_watching(); test_stop_before_exit(); test_restart_replaces(); test_rejects_bad_ops();
    if (failures) { fprintf(stderr, "node_watch_test: %d failure(s)\n", failures); return 1; }
    puts("node_watch_test: ok");
    return 0;
}
