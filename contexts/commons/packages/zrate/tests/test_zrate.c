/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: regression tests for token-bucket and sliding-window rate limiting.
 */
#include "zrate/zrate.h"
#include <math.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_bucket_basic(void)
{
    zrate_bucket b;
    zrate_bucket_init(&b, 10.0, 1.0, 0); /* 10 tokens, 1/s */

    CHECK(zrate_bucket_peek(&b, 0) == 10.0);
    CHECK(zrate_bucket_take(&b, 5.0, 0));
    CHECK(zrate_bucket_peek(&b, 0) == 5.0);
    CHECK(zrate_bucket_take(&b, 5.0, 0));
    CHECK(zrate_bucket_peek(&b, 0) == 0.0);
    CHECK(!zrate_bucket_take(&b, 0.5, 0)); /* empty */

    /* Refill: 1 token/sec -> after 3s, 3 tokens. */
    CHECK(zrate_bucket_take(&b, 3.0, 3000));
    CHECK(zrate_bucket_peek(&b, 3000) == 0.0);

    /* Refill capped at capacity. */
    CHECK(zrate_bucket_peek(&b, 100000) == 10.0);

    /* Fractional consumption. */
    zrate_bucket_init(&b, 2.0, 4.0, 0);
    CHECK(zrate_bucket_take(&b, 0.5, 0));
    CHECK(zrate_bucket_peek(&b, 0) == 1.5);
    CHECK(zrate_bucket_take(&b, 1.5, 0));
    CHECK(!zrate_bucket_take(&b, 0.01, 0));

    /* Backwards clock is ignored (no negative refill). */
    zrate_bucket_init(&b, 1.0, 1.0, 1000);
    CHECK(zrate_bucket_take(&b, 1.0, 1000));
    CHECK(!zrate_bucket_take(&b, 1.0, 500)); /* earlier time: no refill */

    /* NULL / negative safety. */
    CHECK(!zrate_bucket_take(NULL, 1.0, 0));
    zrate_bucket_init(NULL, 1, 1, 0);
    CHECK(!zrate_bucket_take(&b, -1.0, 0));
}

static void test_bucket_wait(void)
{
    zrate_bucket b;
    zrate_bucket_init(&b, 10.0, 2.0, 0); /* 2 tokens/sec */

    CHECK(zrate_bucket_wait_ms(&b, 5.0, 0) == 0);    /* available */
    CHECK(zrate_bucket_take(&b, 10.0, 0));
    /* Need 4 tokens at 2/s -> 2000 ms. */
    CHECK(zrate_bucket_wait_ms(&b, 4.0, 0) == 2000);
    /* After 1000 ms: 2 tokens refilled, need 2 more -> 1000 ms. */
    CHECK(zrate_bucket_wait_ms(&b, 4.0, 1000) == 1000);
    /* Impossible: exceeds capacity. */
    CHECK(zrate_bucket_wait_ms(&b, 11.0, 0) == UINT64_MAX);
    /* Zero rate with insufficient tokens: never. */
    zrate_bucket_init(&b, 1.0, 0.0, 0);
    CHECK(zrate_bucket_take(&b, 1.0, 0));
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == UINT64_MAX);
    /* No refill is needed when the bucket already has enough tokens. */
    zrate_bucket_init(&b, 5.0, 0.0, 0);
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == 0);
    CHECK(zrate_bucket_wait_ms(&b, 5.0, 0) == 0);
    CHECK(zrate_bucket_wait_ms(&b, 0.0, 0) == 0);
    CHECK(zrate_bucket_wait_ms(&b, 6.0, 0) == UINT64_MAX);
    CHECK(zrate_bucket_peek(&b, 0) == 5.0); /* wait must not spend */
    CHECK(zrate_bucket_take(&b, 5.0, 0));
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == UINT64_MAX);
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 100000) == UINT64_MAX);
    CHECK(zrate_bucket_wait_ms(&b, 0.0, 100000) == 0);
    CHECK(zrate_bucket_peek(&b, 100000) == 0.0);
    CHECK(zrate_bucket_take(&b, 0.0, 100000));
    CHECK(!zrate_bucket_take(&b, 1.0, 100000));
    CHECK(zrate_bucket_wait_ms(NULL, 1.0, 0) == UINT64_MAX);
    /* Init normalizes a negative refill rate to zero. */
    zrate_bucket_init(&b, 5.0, -1.0, 0);
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == 0);
    CHECK(zrate_bucket_take(&b, 5.0, 0));
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == UINT64_MAX);
    /* Positive-rate fractional waits still round up, never down. */
    zrate_bucket_init(&b, 5.0, 3.0, 0);
    CHECK(zrate_bucket_take(&b, 5.0, 0));
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 0) == 334);
    CHECK(zrate_bucket_wait_ms(&b, 0.001, 0) == 1);
    CHECK(zrate_bucket_wait_ms(&b, 1.0, 334) == 0);
}

static void test_window_basic(void)
{
    uint64_t events[3];
    zrate_window w;
    zrate_window_init(&w, events, 3, 1000); /* 3 per second */

    CHECK(zrate_window_count(&w, 0) == 0);
    CHECK(zrate_window_hit(&w, 0));
    CHECK(zrate_window_hit(&w, 100));
    CHECK(zrate_window_hit(&w, 500));
    CHECK(zrate_window_count(&w, 500) == 3);
    CHECK(!zrate_window_hit(&w, 999));  /* full */

    /* At t=1000 the t=0 event expires. */
    CHECK(zrate_window_count(&w, 1000) == 2);
    CHECK(zrate_window_hit(&w, 1000));

    /* By t=1501 only the t=1000 event is still inside. */
    CHECK(zrate_window_count(&w, 1501) == 1);
    CHECK(zrate_window_count(&w, 2000) == 0);
}

static void test_window_wait_and_wrap(void)
{
    uint64_t events[2];
    zrate_window w;
    zrate_window_init(&w, events, 2, 100); /* 2 per 100ms */

    CHECK(zrate_window_hit(&w, 0));
    CHECK(zrate_window_hit(&w, 50));
    CHECK(zrate_window_wait_ms(&w, 50) == 50);  /* t=0 expires at t=100 */
    CHECK(zrate_window_wait_ms(&w, 99) == 1);
    CHECK(zrate_window_wait_ms(&w, 100) == 0);  /* room again */
    CHECK(zrate_window_hit(&w, 100));

    /* Wrap: many cycles of fill/expire stay exact. */
    for (uint64_t t = 200; t < 100000; t += 100) {
        CHECK(zrate_window_count(&w, t) <= 2);
        while (zrate_window_hit(&w, t)) { /* fill to limit */ }
        CHECK(zrate_window_count(&w, t) == 2);
    }

    /* Degenerate inputs. */
    zrate_window bad;
    zrate_window_init(&bad, NULL, 2, 100);
    CHECK(!zrate_window_hit(&bad, 0));
    zrate_window_init(&bad, events, 0, 100);
    CHECK(!zrate_window_hit(&bad, 0));
    zrate_window_init(NULL, events, 2, 100);
    CHECK(zrate_window_count(NULL, 0) == 0);
}

static void test_disabled_window_wait(void)
{
    uint64_t events[1] = {77};
    const struct { uint64_t *events; uint32_t limit; uint64_t now; int count; } rows[] = {
        {NULL, 0, 0, 0},
        {events, 0, UINT64_MAX, 0},
        {NULL, 1, 0, 0},
        {NULL, 1, 0, 1},
        {events, 0, UINT64_MAX, 1}
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        zrate_window w;
        zrate_window_init(&w, rows[i].events, rows[i].limit, 100);
        w.count = (uint32_t)rows[i].count;
        fprintf(stderr, "disabled window row %zu\n", i);
        if (rows[i].count) {
            CHECK(zrate_window_count(&w, rows[i].now) == 0 &&
                  zrate_window_wait_ms(&w, rows[i].now) == UINT64_MAX);
        } else {
            CHECK(zrate_window_wait_ms(&w, rows[i].now) == UINT64_MAX);
        }
    }
}

static void test_invalid_bucket_numbers(void)
{
    const double bad[] = {NAN, INFINITY, -INFINITY, -1.0};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        zrate_bucket b;
        zrate_bucket_init(&b, 2, 1, 0);
        CHECK(!zrate_bucket_take(&b, bad[i], 1000));
        CHECK(b.tokens == 2 && b.last_ms == 0);
        CHECK(zrate_bucket_wait_ms(&b, bad[i], 1000) == UINT64_MAX);
        CHECK(b.tokens == 2 && b.last_ms == 0);
        CHECK(zrate_bucket_take(&b, 2, 0));
        CHECK(!zrate_bucket_take(&b, 1, 0));
        CHECK(zrate_bucket_wait_ms(&b, 1, 0) == 1000);
        zrate_bucket_init(&b, bad[i], 1, 0);
        CHECK(b.capacity == 0 && b.tokens == 0);
        CHECK(!zrate_bucket_take(&b, 1, 0));
        zrate_bucket_init(&b, 2, bad[i], 0);
        CHECK(b.rate_per_sec == 0);
        CHECK(zrate_bucket_take(&b, 2, 0));
        CHECK(zrate_bucket_peek(&b, 1000) == 0);
        CHECK(zrate_bucket_wait_ms(&b, 1, 1000) == UINT64_MAX);
    }
}

static void test_cli(void);

int main(void)
{
    test_cli();
    test_invalid_bucket_numbers();
    test_disabled_window_wait();
    test_bucket_basic();
    test_bucket_wait();
    test_window_basic();
    test_window_wait_and_wrap();
    puts("test_zrate: all groups passed (bucket wait window wrap)");
    return 0;
}

static FILE *cli_sink, *cli_failed_stream;
static size_t cli_flushes, cli_writes, cli_fail_at;
static FILE *real_stdout(void) { return stdout; }
static FILE *cli_output(void)
{
    if (++cli_writes >= cli_fail_at && cli_fail_at) cli_sink = cli_failed_stream;
    return cli_sink;
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_output(), __VA_ARGS__)
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef printf
#undef stdout
#define stdout real_stdout()

static int cli_invoke(FILE *sink, int argc, char **args)
{
    cli_sink = sink;
    cli_flushes = cli_writes = 0;
    errno = ERANGE;
    int rc = embedded_cli_main(argc, args);
    cli_sink = stdout;
    return rc;
}
static void cli_case(int argc, char **args, int status, const char *want)
{
    FILE *sink = tmpfile();
    CHECK(sink != NULL);
    CHECK(cli_invoke(sink, argc, args) == status);
    if (!*want) CHECK(cli_flushes == 0);
    char got[1024];
    rewind(sink);
    size_t n = fread(got, 1, sizeof got, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(got, want, n));
    CHECK(fclose(sink) == 0);
}
static void cli_bad_parameters(void)
{
    const char *bad_uint[] = {"", " \t", "-1", "1junk", "1 ", "0x1",
        "18446744073709551616", "-18446744073709551615"};
    for (size_t i = 0; i < sizeof bad_uint / sizeof bad_uint[0]; i++) {
        char *limit[] = {"zrate", "window", (char *)bad_uint[i], "1", "0", NULL};
        char *interval[] = {"zrate", "window", "1", (char *)bad_uint[i], "0", NULL};
        char *time[] = {"zrate", "window", "1", "1", (char *)bad_uint[i], NULL};
        cli_case(5, limit, 2, "");
        cli_case(5, interval, 2, "");
        cli_case(5, time, 2, "");
    }
    const char *limits[] = {"0", "1025", "4294967296", "4294967297"};
    for (size_t i = 0; i < sizeof limits / sizeof limits[0]; i++) {
        char *args[] = {"zrate", "window", (char *)limits[i], "1", "0", NULL};
        cli_case(5, args, 2, "");
    }
    const char *bad_double[] = {"", " ", "junk", "1junk", "1 ", "1e9999", "1e-9999"};
    for (size_t i = 0; i < sizeof bad_double / sizeof bad_double[0]; i++) {
        char *capacity[] = {"zrate", "bucket", (char *)bad_double[i], "1", "0:1", NULL};
        char *rate[] = {"zrate", "bucket", "1", (char *)bad_double[i], "0:1", NULL};
        cli_case(5, capacity, 2, "");
        cli_case(5, rate, 2, "");
    }
}
static void cli_bad_events(void)
{
    const char *bad[] = {"", "1", ":1", " :1", "0:", "0: ", "0:1:2", "0:1x",
        "0x:1", "1x:1", "-1:1", "18446744073709551616:1", "0:1e9999", "0:1e-9999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char *args[] = {"zrate", "bucket", "10", "1", (char *)bad[i], NULL};
        cli_case(5, args, 2, "");
    }
    char *late[] = {"zrate", "bucket", "10", "1", "0:1", "0:bad", NULL};
    cli_case(6, late, 2, "0 ok (left 9.000)\n");
    char *window[] = {"zrate", "window", "1", "10", "0", "bad", NULL};
    cli_case(6, window, 2, "0 ok (1/1)\n");
}
static void cli_normal(void)
{
    char *bucket[] = {"zrate", "bucket", "0x1.4p3", " +2", "-0:1.5", "0:10", "1000:2", NULL};
    cli_case(7, bucket, 1, "0 ok (left 8.500)\n0 deny (wait 750 ms)\n1000 ok (left 8.000)\n");
    char *window[] = {"zrate", "window", " +1", "1000", "-0", "0", "1000", "500", NULL};
    cli_case(8, window, 1, "0 ok (1/1)\n0 deny (wait 1000 ms)\n1000 ok (1/1)\n500 ok (1/1)\n");
    char *zero[] = {"zrate", "window", "1024", "-0", " +0", "0", NULL};
    cli_case(6, zero, 0, "0 ok (0/1024)\n0 ok (0/1024)\n");
    char *maximum[] = {"zrate", "window", "1", "18446744073709551615", "18446744073709551615", NULL};
    cli_case(5, maximum, 0, "18446744073709551615 ok (1/1)\n");
    char *empty_bucket[] = {"zrate", "bucket", "10", "1", NULL};
    char *empty_window[] = {"zrate", "window", "1", "0", NULL};
    cli_case(4, empty_bucket, 0, "");
    cli_case(4, empty_window, 0, "");
    char *usage[] = {"zrate", "unknown", "1", "1", NULL};
    cli_case(4, usage, 2, "");
}
static void cli_nonfinite(void)
{
    const char *values[] = {"-1", "nan", "inf", "-inf"};
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        char *capacity[] = {"zrate", "bucket", (char *)values[i], "1", "0:1", NULL};
        cli_case(5, capacity, 1, "0 deny (wait 18446744073709551615 ms)\n");
        char *rate[] = {"zrate", "bucket", "1", (char *)values[i], "0:1", "1000:1", NULL};
        cli_case(6, rate, 1, "0 ok (left 0.000)\n1000 deny (wait 18446744073709551615 ms)\n");
        char event[64];
        snprintf(event, sizeof event, "0:%s", values[i]);
        char *request[] = {"zrate", "bucket", "1", "1", event, NULL};
        cli_case(5, request, 1, "0 deny (wait 18446744073709551615 ms)\n");
    }
}
static void cli_output_failure(char **args, int argc, size_t target, bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = tmpfile();
    FILE *bad = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL && bad != NULL);
    char buffer[4096];
    if (buffered) CHECK(setvbuf(bad, buffer, _IOFBF, sizeof buffer) == 0);
    cli_fail_at = target;
    cli_failed_stream = bad;
    CHECK(cli_invoke(sink, argc, args) == 2 && ferror(bad));
    cli_fail_at = 0;
    cli_failed_stream = NULL;
    CHECK(fclose(sink) == 0);
    (void)fclose(bad);
}
static void cli_failed_sinks(void)
{
    char *bucket[] = {"zrate", "bucket", "1", "0", "0:1", "0:1", "bad", NULL};
    char *window[] = {"zrate", "window", "1", "10", "0", "0", "bad", NULL};
    for (size_t target = 1; target <= 2; target++) {
        cli_output_failure(bucket, 6, target, false);
        cli_output_failure(window, 6, target, false);
#ifdef __linux__
        cli_output_failure(bucket, 6, target, true);
        cli_output_failure(window, 6, target, true);
        cli_output_failure(bucket, 7, target, true);
        cli_output_failure(window, 7, target, true);
#endif
    }
}
static void test_cli(void)
{
    cli_bad_parameters();
    cli_bad_events();
    cli_normal();
    cli_nonfinite();
    cli_failed_sinks();
}
