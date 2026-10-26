/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: formatter regression tests including scaled floating-point bounds.
 */
#include "zfmt/zfmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

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

static void test_double_scaled_range(void)
{
    char buf[64];
    zfmt f;
    zfmt_init(&f, buf, sizeof buf);
    /* Magnitude passes the old 2^53 guard but scaling exceeds uint64_t. */
    CHECK(zfmt_double(&f, 1e15, 9));
    expect(&f, "huge");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, -1e15, 9));
    expect(&f, "huge");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 1e15, 99)); /* precision still clamps to nine */
    expect(&f, "huge");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 0x1p64 / 1e9, 9)); /* exact rounded upper bound */
    expect(&f, "huge");

    /* Preserve representable large results rather than lowering all ranges. */
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 1e15, 0));
    expect(&f, "1000000000000000");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 1e9, 9));
    expect(&f, "1000000000.000000000");
    zfmt_reset(&f);
    CHECK(zfmt_double(&f, 0x1p53, 1));
    expect(&f, "9007199254740992.0");

    char tiny[4];
    zfmt_init(&f, tiny, sizeof tiny);
    CHECK(!zfmt_double(&f, 1e15, 9));
    CHECK(strcmp(tiny, "hug") == 0 && zfmt_len(&f) == 3);
    CHECK(!zfmt_ok(&f));
    CHECK(!zfmt_char(&f, 'x')); /* fallback obeys normal sticky overflow */
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

static void test_cli(void);

int main(void)
{
    test_cli();
    test_strings();
    test_integers();
    test_double();
    test_double_scaled_range();
    test_overflow();
    test_repeat_and_compose();
    test_fuzz_vs_snprintf();
    puts("test_zfmt: all groups passed (strings ints double overflow compose fuzz)");
    return 0;
}

static FILE *cli_sink;
static size_t cli_flushes;
static FILE *real_stdout(void) { return stdout; }
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdout
#define stdout cli_sink
#define puts(text) fprintf(cli_sink, "%s\n", (text))
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef puts
#undef stdout
#define stdout real_stdout()

static int cli_invoke(FILE *sink, int argc, char **args)
{
    cli_sink = sink;
    cli_flushes = 0;
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
    if (!*want) { CHECK(cli_flushes == 0); }
    char got[256];
    rewind(sink);
    size_t n = fread(got, 1, sizeof got, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(got, want, n));
    CHECK(fclose(sink) == 0);
}
static void cli_unsigned_errors(void)
{
    char negative[64], overflow[64];
    snprintf(negative, sizeof negative, "-%llu", ULLONG_MAX);
    snprintf(overflow, sizeof overflow, "%llu0", ULLONG_MAX);
    const char *bad[] = {"", " \t", "junk", "1x", "1 ", "-1", negative, overflow};
    const char *commands[] = {"u64", "hex", "pad"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        for (size_t c = 0; c < sizeof commands / sizeof commands[0]; c++) {
            char *args[] = {"zfmt", (char *)commands[c], (char *)bad[i], "1", NULL};
            cli_case(4, args, 2, "");
        }
        char *template[] = {"zfmt", "template", "Ada", (char *)bad[i], NULL};
        cli_case(4, template, 2, "");
    }
}
static void cli_option_errors(void)
{
    char overflow[64];
    snprintf(overflow, sizeof overflow, "%u0", UINT_MAX);
    const char *bad[] = {"", " ", "junk", "1x", "1 ", "-1", "4294967296", "4294967297", overflow};
    const char *commands[] = {"pad", "double"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        for (size_t c = 0; c < 2; c++) {
            char *args[] = {"zfmt", (char *)commands[c], "1", (char *)bad[i], NULL};
            cli_case(4, args, 2, "");
        }
    }
}
static void cli_signed_double_errors(void)
{
    char high[64], low[64];
    snprintf(high, sizeof high, "%lld0", (long long)INT64_MAX);
    snprintf(low, sizeof low, "%lld0", (long long)INT64_MIN);
    const char *signed_bad[] = {"", " ", "junk", "1x", "1 ", high, low};
    for (size_t i = 0; i < sizeof signed_bad / sizeof signed_bad[0]; i++) {
        char *args[] = {"zfmt", "i64", (char *)signed_bad[i], NULL};
        cli_case(3, args, 2, "");
    }
    const char *double_bad[] = {"", " ", "junk", "1x", "1 ", "1e9999", "1e-9999"};
    for (size_t i = 0; i < sizeof double_bad / sizeof double_bad[0]; i++) {
        char *args[] = {"zfmt", "double", (char *)double_bad[i], "1", NULL};
        cli_case(4, args, 2, "");
    }
}
static void cli_normal(void)
{
    char maximum[64], minimum[64], option[64];
    snprintf(maximum, sizeof maximum, "%llu", (unsigned long long)UINT64_MAX);
    snprintf(minimum, sizeof minimum, "%lld", (long long)INT64_MIN);
    snprintf(option, sizeof option, "%u", UINT_MAX);
    char maxwant[80], minwant[80];
    snprintf(maxwant, sizeof maxwant, "%s\n", maximum);
    snprintf(minwant, sizeof minwant, "%s\n", minimum);
    char *u64[] = {"zfmt", "u64", maximum, "ignored", NULL};
    cli_case(4, u64, 0, maxwant);
    char *i64[] = {"zfmt", "i64", minimum, NULL};
    cli_case(3, i64, 0, minwant);
    char signed_max[64], signed_want[80];
    snprintf(signed_max, sizeof signed_max, "%lld", (long long)INT64_MAX);
    snprintf(signed_want, sizeof signed_want, "%s\n", signed_max);
    i64[2] = signed_max;
    cli_case(3, i64, 0, signed_want);
    char *hex[] = {"zfmt", "hex", " \t+42", NULL};
    cli_case(3, hex, 0, "000000000000002a\n");
    char *zero[] = {"zfmt", "u64", "-0", NULL};
    cli_case(3, zero, 0, "0\n");
    char *pad[] = {"zfmt", "pad", "7", option, NULL};
    char padding[66];
    memset(padding, '0', 63); memcpy(padding + 63, "7\n", 3);
    cli_case(4, pad, 0, padding);
    char *precision[] = {"zfmt", "double", "0x1.4p1", option, NULL};
    cli_case(4, precision, 0, "2.500000000\n");
    char *zero_width[] = {"zfmt", "pad", "7", "-0", NULL};
    cli_case(4, zero_width, 0, "7\n");
    char *zero_precision[] = {"zfmt", "double", "2", "-0", NULL};
    cli_case(4, zero_precision, 0, "2\n");
    char *negative[] = {"zfmt", "double", "-2.5", " \t+2", NULL};
    cli_case(4, negative, 0, "-2.50\n");
    char *template[] = {"zfmt", "template", "Ada", " \t+7", NULL};
    cli_case(4, template, 0, "hello Ada, count=7\n");
}
static void cli_special_doubles(void)
{
    const char *values[] = {"nan", "inf", "-inf"};
    const char *wants[] = {"nan\n", "inf\n", "-inf\n"};
    for (size_t i = 0; i < 3; i++) {
        char *args[] = {"zfmt", "double", (char *)values[i], "2", NULL};
        cli_case(4, args, 0, wants[i]);
    }
}
static void cli_output_failure(const char *command, bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
    char *args[] = {"zfmt", (char *)command, "1", "2", NULL};
    CHECK(cli_invoke(sink, 4, args) == 1 && ferror(sink));
    (void)fclose(sink);
}
static void cli_no_output(void)
{
    char large[256];
    memset(large, 'a', sizeof large - 1); large[sizeof large - 1] = 0;
    char *truncated[] = {"zfmt", "template", large, "1", NULL};
    cli_case(4, truncated, 1, "");
    char *missing[] = {"zfmt", "pad", "1", NULL};
    cli_case(3, missing, 2, "");
    char *unknown[] = {"zfmt", "unknown", "1", NULL};
    cli_case(3, unknown, 2, "");
}
static void test_cli(void)
{
    cli_unsigned_errors();
    cli_option_errors();
    cli_signed_double_errors();
    cli_normal();
    cli_special_doubles();
    cli_no_output();
    const char *commands[] = {"u64", "i64", "hex", "pad", "double", "template"};
    for (size_t i = 0; i < 6; i++) {
        cli_output_failure(commands[i], false);
#ifdef __linux__
        cli_output_failure(commands[i], true);
#endif
    }
}
