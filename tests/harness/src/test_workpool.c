/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for platform/modules/util/workpool.{h,c} — thread pool for parallel work. */

#include "test/test_core.h"
#include "platform/time_compat.h"
#include "util/workpool.h"
#include <unistd.h>

/* ── Simple work functions for testing ─────────────────────── */

static bool wp_always_true(void *item)  { (void)item; return true; }
static bool wp_always_false(void *item) { (void)item; return false; }

static _Atomic int g_wp_counter;

static bool wp_increment(void *item)
{
    (void)item;
    g_wp_counter++;
    return true;
}

static bool wp_square(void *item)
{
    int *val = (int *)item;
    *val = (*val) * (*val);
    return true;
}

static bool wp_reject_negative(void *item)
{
    int *val = (int *)item;
    return *val >= 0;
}

static bool wp_busy_work(void *item)
{
    volatile int *val = (volatile int *)item;
    volatile int sum = 0;
    for (int i = 0; i < 10000; i++)
        sum += i;
    *val = (int)sum;
    return true;
}

/* ── Per-test functions to avoid label conflicts ─────────── */

static int t_wp_init_destroy(void)
{
    int failures = 0;
    printf("workpool: init and destroy... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 64, wp_always_true));
    ASSERT(workpool_num_threads(&wp) == 4);
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_auto_threads(void)
{
    int failures = 0;
    printf("workpool: auto thread count... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 0, 64, wp_always_true));
    ASSERT(workpool_num_threads(&wp) >= 1);
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_reject_null_fn(void)
{
    int failures = 0;
    printf("workpool: reject NULL fn... ");
    struct workpool wp;
    ASSERT(!workpool_init(&wp, 2, 64, NULL));
    PASS();
    _test_next: return failures;
}

static int t_wp_reject_zero_cap(void)
{
    int failures = 0;
    printf("workpool: reject zero capacity... ");
    struct workpool wp;
    ASSERT(!workpool_init(&wp, 2, 0, wp_always_true));
    PASS();
    _test_next: return failures;
}

static int t_wp_single_item(void)
{
    int failures = 0;
    printf("workpool: single item... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 2, 64, wp_always_true));
    int dummy = 42;
    void *items[1] = { &dummy };
    ASSERT(workpool_run(&wp, items, 1));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_all_succeed(void)
{
    int failures = 0;
    printf("workpool: all succeed (100 items)... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 256, wp_always_true));
    int data[100];
    void *items[100];
    for (int i = 0; i < 100; i++) { data[i] = i; items[i] = &data[i]; }
    ASSERT(workpool_run(&wp, items, 100));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_failure_propagation(void)
{
    int failures = 0;
    printf("workpool: failure propagation... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 64, wp_always_false));
    int dummy = 0;
    void *items[1] = { &dummy };
    ASSERT(!workpool_run(&wp, items, 1));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_mixed_pass_fail(void)
{
    int failures = 0;
    printf("workpool: mixed pass/fail... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 256, wp_reject_negative));
    int data[20];
    void *items[20];
    for (int i = 0; i < 20; i++) { data[i] = i; items[i] = &data[i]; }
    data[10] = -1;
    ASSERT(!workpool_run(&wp, items, 20));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_all_processed(void)
{
    int failures = 0;
    printf("workpool: all 200 items processed... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 256, wp_increment));
    g_wp_counter = 0;
    int data[200];
    void *items[200];
    for (int i = 0; i < 200; i++) { data[i] = i; items[i] = &data[i]; }
    ASSERT(workpool_run(&wp, items, 200));
    ASSERT_EQ(g_wp_counter, 200);
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_data_modification(void)
{
    int failures = 0;
    printf("workpool: data modification (square)... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 256, wp_square));
    int data[10];
    void *items[10];
    for (int i = 0; i < 10; i++) { data[i] = i + 1; items[i] = &data[i]; }
    ASSERT(workpool_run(&wp, items, 10));
    for (int i = 0; i < 10; i++) ASSERT_EQ(data[i], (i+1)*(i+1));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_multiple_batches(void)
{
    int failures = 0;
    printf("workpool: multiple batches... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 4, 256, wp_increment));
    g_wp_counter = 0;
    for (int batch = 0; batch < 5; batch++) {
        int data[50];
        void *items[50];
        for (int i = 0; i < 50; i++) { data[i] = i; items[i] = &data[i]; }
        ASSERT(workpool_run(&wp, items, 50));
    }
    ASSERT_EQ(g_wp_counter, 250);
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_single_thread(void)
{
    int failures = 0;
    printf("workpool: single thread... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 1, 64, wp_square));
    ASSERT_EQ(workpool_num_threads(&wp), 1);
    int data[5] = {2, 3, 4, 5, 6};
    void *items[5];
    for (int i = 0; i < 5; i++) items[i] = &data[i];
    ASSERT(workpool_run(&wp, items, 5));
    ASSERT_EQ(data[0], 4);
    ASSERT_EQ(data[1], 9);
    ASSERT_EQ(data[2], 16);
    ASSERT_EQ(data[3], 25);
    ASSERT_EQ(data[4], 36);
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_parallel_speedup(void)
{
    int failures = 0;
    printf("workpool: parallel speedup... ");

    int data[512];
    void *items[512];
    for (int i = 0; i < 512; i++) { data[i] = 0; items[i] = &data[i]; }

    struct workpool wp1;
    ASSERT(workpool_init(&wp1, 1, 1024, wp_busy_work));
    int64_t t1s = platform_time_monotonic_us();
    ASSERT(workpool_run(&wp1, items, 512));
    int64_t t1e = platform_time_monotonic_us();
    long t1 = (long)(t1e - t1s);
    workpool_destroy(&wp1);

    for (int i = 0; i < 512; i++) data[i] = 0;

    struct workpool wpm;
    ASSERT(workpool_init(&wpm, 4, 1024, wp_busy_work));
    int64_t tms = platform_time_monotonic_us();
    ASSERT(workpool_run(&wpm, items, 512));
    int64_t tme = platform_time_monotonic_us();
    long tm = (long)(tme - tms);
    workpool_destroy(&wpm);

    printf("[1T=%ldus 4T=%ldus ratio=%.1fx] ",
           t1, tm, t1 > 0 ? (double)t1 / (double)tm : 0);
    /* This group runs inside the fork-parallel suite, so the host may already
     * be saturated by other CPU-heavy groups. Keep the diagnostic ratio, but
     * only fail if the multi-thread path is clearly pathological. */
    ASSERT(tm < t1 * 4);
    PASS();
    _test_next: return failures;
}

static int t_wp_empty_batch(void)
{
    int failures = 0;
    printf("workpool: empty batch... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 2, 64, wp_always_true));
    ASSERT(workpool_run(&wp, NULL, 0));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

static int t_wp_reset_after_failure(void)
{
    int failures = 0;
    printf("workpool: reset after failure... ");
    struct workpool wp;
    ASSERT(workpool_init(&wp, 2, 64, wp_reject_negative));
    int neg = -1;
    void *bad[1] = { &neg };
    ASSERT(!workpool_run(&wp, bad, 1));
    int pos = 42;
    void *good[1] = { &pos };
    ASSERT(workpool_run(&wp, good, 1));
    workpool_destroy(&wp);
    PASS();
    _test_next: return failures;
}

int test_workpool(void)
{
    int failures = 0;
    printf("\n=== Workpool Tests ===\n");

    failures += t_wp_init_destroy();
    failures += t_wp_auto_threads();
    failures += t_wp_reject_null_fn();
    failures += t_wp_reject_zero_cap();
    failures += t_wp_single_item();
    failures += t_wp_all_succeed();
    failures += t_wp_failure_propagation();
    failures += t_wp_mixed_pass_fail();
    failures += t_wp_all_processed();
    failures += t_wp_data_modification();
    failures += t_wp_multiple_batches();
    failures += t_wp_single_thread();
    failures += t_wp_parallel_speedup();
    failures += t_wp_empty_batch();
    failures += t_wp_reset_after_failure();

    printf("Workpool: %d failures\n", failures);
    return failures;
}
