#include "zrate/zrate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
    test_bucket_basic();
    test_bucket_wait();
    test_window_basic();
    test_window_wait_and_wrap();
    puts("test_zrate: all groups passed (bucket wait window wrap)");
    return 0;
}
