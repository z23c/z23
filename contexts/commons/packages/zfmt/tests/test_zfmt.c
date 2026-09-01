#include "zfmt/zfmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void expect(zfmt *f, const char *want)
{
    if (!zfmt_ok(f) || strcmp(zfmt_cstr(f), want) != 0) {
        fprintf(stderr, "FAIL: got \"%s\" (ok=%d), want \"%s\"\n",
                zfmt_cstr(f), zfmt_ok(f), want);
        exit(1);
    }
}

static void test_strings(void)
{
    char buf[64];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);
    CHECK(zfmt_ok(&f));
    CHECK(strcmp(zfmt_cstr(&f), "") == 0);

    CHECK(zfmt_str(&f, "hello"));
    CHECK(zfmt_char(&f, ' '));
    CHECK(zfmt_span(&f, "world!!!", 5));
    expect(&f, "hello world");
    CHECK(zfmt_len(&f) == 11);

    zfmt_reset(&f);
    expect(&f, "");
    CHECK(zfmt_str(&f, "again"));
    expect(&f, "again");

    /* NULL safety. */
    CHECK(!zfmt_str(&f, NULL));
    CHECK(!zfmt_ok(&f));
    zfmt_reset(&f);
    CHECK(!zfmt_span(&f, NULL, 3));
    CHECK(!zfmt_ok(&f));            /* sticky */
    zfmt_reset(&f);
    CHECK(zfmt_span(&f, NULL, 0)); /* zero-length NULL span is fine */
    zfmt_init(NULL, buf, sizeof buf); /* no crash */
    zfmt_init(&f, NULL, 0);
    CHECK(!zfmt_ok(&f));
    CHECK(!zfmt_str(&f, "x"));
    CHECK(strcmp(zfmt_cstr(&f), "") == 0);
}

static void test_integers(void)
{
    char buf[64];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);

    CHECK(zfmt_u64(&f, 0));
    expect(&f, "0");
    zfmt_reset(&f);
    CHECK(zfmt_u64(&f, 18446744073709551615ull));
    expect(&f, "18446744073709551615");
    zfmt_reset(&f);
    CHECK(zfmt_i64(&f, -9223372036854775807ll - 1));
    expect(&f, "-9223372036854775808");
    zfmt_reset(&f);
    CHECK(zfmt_i64(&f, 9223372036854775807ll));
    expect(&f, "9223372036854775807");
    zfmt_reset(&f);
    CHECK(zfmt_i64(&f, -42));
    expect(&f, "-42");
    zfmt_reset(&f);
    CHECK(zfmt_hex64(&f, 0xdeadbeefcafeull));
    expect(&f, "0000deadbeefcafe");
    zfmt_reset(&f);
    CHECK(zfmt_u64_pad(&f, 42, 5));
    expect(&f, "00042");
    zfmt_reset(&f);
    CHECK(zfmt_u64_pad(&f, 123456, 3)); /* width smaller than digits */
    expect(&f, "123456");
    zfmt_reset(&f);
    CHECK(zfmt_u64_pad(&f, 0, 4));
    expect(&f, "0000");
}

static void test_double(void)
{
    char buf[64];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);

    CHECK(zfmt_double(&f, 0.0, 2));
    expect(&f, "0.00");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 1.5, 1));
    expect(&f, "1.5");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, -3.25, 2));
    expect(&f, "-3.25");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 0.999, 2)); /* rounds half up */
    expect(&f, "1.00");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 42.0, 0));
    expect(&f, "42");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 0.1 + 0.2, 3));
    expect(&f, "0.300");
}

static void test_overflow(void)
{
    char buf[8]; /* holds 7 chars + NUL */
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);

    CHECK(zfmt_str(&f, "1234567"));   /* exact fit */
    expect(&f, "1234567");
    zfmt_reset(&f);

    CHECK(!zfmt_str(&f, "12345678")); /* one too many */
    CHECK(!zfmt_ok(&f));
    CHECK(zfmt_len(&f) == 7);          /* truncated, valid string */

    /* Sticky: further appends refused. */
    CHECK(!zfmt_char(&f, 'x'));
    CHECK(zfmt_len(&f) == 7);

    /* Reset clears the stickiness. */
    zfmt_reset(&f);
    CHECK(zfmt_ok(&f));
    CHECK(zfmt_str(&f, "ok"));
    expect(&f, "ok");

    /* Long numbers overflow cleanly too. */
    char tiny[4];
    zfmt_init(&f, tiny, sizeof tiny);
    CHECK(!zfmt_u64(&f, 1000000));
    CHECK(!zfmt_ok(&f));
    CHECK(zfmt_len(&f) == 3);
}

static void test_repeat_and_compose(void)
{
    char buf[128];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);

    CHECK(zfmt_repeat(&f, '=', 5));
    expect(&f, "=====");

    /* Compose a realistic line. */
    zfmt_reset(&f);
    zfmt_str(&f, "height=");
    zfmt_u64(&f, 3203194);
    zfmt_str(&f, " root=0x");
    zfmt_hex64(&f, 0x30ec0538ull);
    zfmt_str(&f, " t=");
    zfmt_double(&f, 6.25, 2);
    zfmt_str(&f, "s");
    expect(&f, "height=3203194 root=0x0000000030ec0538 t=6.25s");
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_fuzz_vs_snprintf(void)
{
    for (int i = 0; i < 20000; i++) {
        uint64_t uv = rng_next();
        /* Vary magnitude. */
        uv >>= rng_next() % 64;
        char want[32], buf[32];
        snprintf(want, sizeof want, "%llu", (unsigned long long)uv);
        zfmt f;
        zfmt_init(&f, buf, sizeof buf);
        CHECK(zfmt_u64(&f, uv));
        CHECK(strcmp(buf, want) == 0);

        int64_t sv = (int64_t)uv;
        snprintf(want, sizeof want, "%lld", (long long)sv);
        zfmt_init(&f, buf, sizeof buf);
        CHECK(zfmt_i64(&f, sv));
        CHECK(strcmp(buf, want) == 0);

        snprintf(want, sizeof want, "%016llx", (unsigned long long)uv);
        zfmt_init(&f, buf, sizeof buf);
        CHECK(zfmt_hex64(&f, uv));
        CHECK(strcmp(buf, want) == 0);
    }
    /* INT64_MIN/MAX corners. */
    char want[32], buf[32];
    zfmt f;
    snprintf(want, sizeof want, "%lld", (long long)INT64_MIN);
    zfmt_init(&f, buf, sizeof buf);
    CHECK(zfmt_i64(&f, INT64_MIN));
    CHECK(strcmp(buf, want) == 0);
}

int main(void)
{
    test_strings();
    test_integers();
    test_double();
    test_overflow();
    test_repeat_and_compose();
    test_fuzz_vs_snprintf();
    puts("test_zfmt: all groups passed (strings ints double overflow compose fuzz)");
    return 0;
}
