/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: regression tests for human-readable byte and duration formatting and parsing.
 */
#include "zhuman/zhuman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *cli_real_stderr(void) { return stderr; }
static FILE *cli_out, *cli_err;
#undef stderr
#define stderr cli_err
#define printf(...) fprintf(cli_out, __VA_ARGS__)
#define puts(s) (fputs((s), cli_out) == EOF ? EOF : fputc('\n', cli_out))
#define main zhuman_cli_main
#include "../app/main.c"
#undef main
#undef puts
#undef printf
#undef stderr
#define stderr cli_real_stderr()

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void expect_iec(uint64_t bytes, const char *want)
{
    char out[32];
    CHECK(zhuman_format_bytes_iec(bytes, out, sizeof out) == ZHUMAN_OK);
    if (strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL iec(%llu): got \"%s\", want \"%s\"\n",
                (unsigned long long)bytes, out, want);
        exit(1);
    }
}

static void expect_si(uint64_t bytes, const char *want)
{
    char out[32];
    CHECK(zhuman_format_bytes_si(bytes, out, sizeof out) == ZHUMAN_OK);
    if (strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL si(%llu): got \"%s\", want \"%s\"\n",
                (unsigned long long)bytes, out, want);
        exit(1);
    }
}

static void expect_parse_bytes(const char *s, uint64_t want)
{
    uint64_t v = 0;
    CHECK(zhuman_parse_bytes(s, &v) == ZHUMAN_OK);
    if (v != want) {
        fprintf(stderr, "FAIL parse_bytes(\"%s\"): got %llu, want %llu\n",
                s, (unsigned long long)v, (unsigned long long)want);
        exit(1);
    }
}

static void test_format_bytes(void)
{
    expect_iec(0, "0 B");
    expect_iec(512, "512 B");
    expect_iec(1023, "1023 B");
    expect_iec(1024, "1 KiB");
    expect_iec(1536, "1.5 KiB");
    expect_iec(2048, "2 KiB");
    expect_iec(1048576, "1 MiB");
    expect_iec(1073741824, "1 GiB");
    expect_iec(1610612736, "1.5 GiB");
    expect_iec(1ull << 60, "1 EiB");
    expect_iec(UINT64_MAX, "15.9 EiB"); /* truncates toward zero */

    expect_si(0, "0 B");
    expect_si(999, "999 B");
    expect_si(1000, "1 kB");
    expect_si(1500, "1.5 kB");
    expect_si(1000000, "1 MB");
    expect_si(1500000, "1.5 MB");
    expect_si(1000000000000ull, "1 TB");

    /* Small buffer rejected without overflow. */
    char tiny[4];
    CHECK(zhuman_format_bytes_iec(1024, tiny, sizeof tiny) == ZHUMAN_ERR_SMALL);
    CHECK(zhuman_format_bytes_iec(0, NULL, 10) == ZHUMAN_ERR_NULL);
    CHECK(zhuman_format_bytes_iec(0, tiny, 0) == ZHUMAN_ERR_NULL);
}

static void test_parse_bytes(void)
{
    expect_parse_bytes("0", 0);
    expect_parse_bytes("512", 512);
    expect_parse_bytes("512 B", 512);
    expect_parse_bytes("512B", 512);
    expect_parse_bytes("1024", 1024);
    expect_parse_bytes("1 KiB", 1024);
    expect_parse_bytes("1KiB", 1024);
    expect_parse_bytes("1.5 KiB", 1536);
    expect_parse_bytes("1.9 KiB", 1945); /* truncates toward zero */
    expect_parse_bytes("2 MiB", 2ull << 20);
    expect_parse_bytes("1 GiB", 1ull << 30);
    expect_parse_bytes("1 kB", 1000);
    expect_parse_bytes("1.5 MB", 1500000);
    expect_parse_bytes("1 TB", 1000000000000ull);
    expect_parse_bytes("1 EiB", 1ull << 60);
    /* A representable whole part may overflow when its fraction is added. */
    uint64_t limit_value = 123;
    CHECK(zhuman_parse_bytes("18.5 EB", &limit_value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(limit_value == 123);
    CHECK(zhuman_parse_bytes("18.9 EB", &limit_value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(limit_value == 123);
    CHECK(zhuman_parse_bytes("18.4 EB", &limit_value) == ZHUMAN_OK);
    CHECK(limit_value == UINT64_C(18400000000000000000));
    CHECK(zhuman_parse_bytes("15.9 EiB", &limit_value) == ZHUMAN_OK);
    CHECK(limit_value == 15 * (UINT64_C(1) << 60) +
                         9 * (UINT64_C(1) << 60) / 10);

    /* Case-insensitive. */
    expect_parse_bytes("1 kib", 1024);
    expect_parse_bytes("1 KIB", 1024);
    expect_parse_bytes("1 mib", 1ull << 20);

    /* Errors. */
    uint64_t v;
    CHECK(zhuman_parse_bytes("", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("   ", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("abc", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("1 XB", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("1.5.2 KiB", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("1.25 KiB", &v) == ZHUMAN_ERR_FORMAT); /* >1 dp */
    CHECK(zhuman_parse_bytes("1 KiB extra", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_bytes("999 EiB", &v) == ZHUMAN_ERR_OVERFLOW);
    CHECK(zhuman_parse_bytes(NULL, &v) == ZHUMAN_ERR_NULL);
    CHECK(zhuman_parse_bytes("1", NULL) == ZHUMAN_ERR_NULL);

    /* Round trip through the formatter for exact values. */
    uint64_t vals[] = {0, 1, 512, 1024, 2048, 1048576, 1610612736, 1ull << 60};
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        char buf[32];
        CHECK(zhuman_format_bytes_iec(vals[i], buf, sizeof buf) == ZHUMAN_OK);
        uint64_t back;
        CHECK(zhuman_parse_bytes(buf, &back) == ZHUMAN_OK);
        CHECK(back == vals[i]);
    }
}

static void expect_duration(uint64_t ms, const char *want)
{
    char out[64];
    CHECK(zhuman_format_duration(ms, out, sizeof out) == ZHUMAN_OK);
    if (strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL duration(%llu): got \"%s\", want \"%s\"\n",
                (unsigned long long)ms, out, want);
        exit(1);
    }
}

static void expect_parse_duration(const char *s, uint64_t want)
{
    uint64_t v = 0;
    CHECK(zhuman_parse_duration(s, &v) == ZHUMAN_OK);
    if (v != want) {
        fprintf(stderr, "FAIL parse_duration(\"%s\"): got %llu, want %llu\n",
                s, (unsigned long long)v, (unsigned long long)want);
        exit(1);
    }
}

static void test_duration(void)
{
    expect_duration(0, "0 ms");
    expect_duration(1, "0.001s");
    expect_duration(250, "0.250s");
    expect_duration(1000, "1s");
    expect_duration(1500, "1.500s");
    expect_duration(60000, "1m");
    expect_duration(90000, "1m 30s");
    expect_duration(3600000, "1h");
    expect_duration(3661001, "1h 1m 1.001s");
    expect_duration(86400000, "1d");
    expect_duration(90061000, "1d 1h 1m 1s");

    expect_parse_duration("0 ms", 0);
    expect_parse_duration("1s", 1000);
    expect_parse_duration("250ms", 250);
    expect_parse_duration("90m", 5400000);
    expect_parse_duration("1h30m", 5400000);
    expect_parse_duration("1h 30m", 5400000);
    expect_parse_duration("1d 2h 3m 4.567s", 93784567);
    expect_parse_duration("1.5s", 1500);
    expect_parse_duration("2s 500ms", 2500);

    /* A zero-valued fraction still violates non-second unit grammar. */
    uint64_t unchanged = 123;
    CHECK(zhuman_parse_duration("1.0m", &unchanged) == ZHUMAN_ERR_FORMAT);
    CHECK(unchanged == 123);
    CHECK(zhuman_parse_duration("1.0001h", &unchanged) == ZHUMAN_ERR_FORMAT);
    CHECK(unchanged == 123);
    CHECK(zhuman_parse_duration("1.0d", &unchanged) == ZHUMAN_ERR_FORMAT);
    CHECK(unchanged == 123);
    CHECK(zhuman_parse_duration("1.0ms", &unchanged) == ZHUMAN_ERR_FORMAT);
    CHECK(unchanged == 123);
    CHECK(zhuman_parse_duration("1s 2.0001m", &unchanged) == ZHUMAN_ERR_FORMAT);
    CHECK(unchanged == 123); /* no partial total is published */
    CHECK(zhuman_parse_duration("1.0s", &unchanged) == ZHUMAN_OK);
    CHECK(unchanged == 1000);
    CHECK(zhuman_parse_duration("1.0001s", &unchanged) == ZHUMAN_OK);
    CHECK(unchanged == 1000); /* preserve sub-millisecond truncation */

    /* Errors: repeats, fractions on non-second units, junk. */
    uint64_t v;
    CHECK(zhuman_parse_duration("", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_duration("1x", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_duration("1m 2m", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_duration("1.5m", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_duration("ms", &v) == ZHUMAN_ERR_FORMAT);
    CHECK(zhuman_parse_duration("999999999999999999999999d", &v) == ZHUMAN_ERR_OVERFLOW);
    CHECK(zhuman_parse_duration(NULL, &v) == ZHUMAN_ERR_NULL);

    /* Round trip. */
    uint64_t ms_vals[] = {0, 1, 999, 1000, 61000, 3661001, 90061000, 86400000000ull};
    for (size_t i = 0; i < sizeof ms_vals / sizeof ms_vals[0]; i++) {
        char buf[64];
        CHECK(zhuman_format_duration(ms_vals[i], buf, sizeof buf) == ZHUMAN_OK);
        uint64_t back;
        CHECK(zhuman_parse_duration(buf, &back) == ZHUMAN_OK);
        CHECK(back == ms_vals[i]);
    }

    /* Small buffer rejected. */
    char tiny[3];
    CHECK(zhuman_format_duration(60000, tiny, sizeof tiny) == ZHUMAN_ERR_SMALL);
}

static void test_err_str(void)
{
    CHECK(strcmp(zhuman_err_str(ZHUMAN_OK), "ok") == 0);
    CHECK(strstr(zhuman_err_str(ZHUMAN_ERR_FORMAT), "format") != NULL);
    CHECK(zhuman_err_str((zhuman_err)999) != NULL);
}

static void test_uint64_decimal_bounds(void)
{
    expect_parse_bytes("18446744073709551615 B", UINT64_MAX);
    expect_parse_bytes("18446744073709551615", UINT64_MAX);
    expect_parse_bytes("18446744073709551614 B", UINT64_MAX - 1);
    expect_parse_duration("18446744073709551615ms", UINT64_MAX);
    expect_parse_duration("18446744073709551614ms", UINT64_MAX - 1);

    uint64_t value = 123;
    CHECK(zhuman_parse_bytes("18446744073709551616 B", &value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(value == 123);
    CHECK(zhuman_parse_duration("18446744073709551616ms", &value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(value == 123);
    /* Decimal accumulation can fit while subsequent unit scaling cannot. */
    CHECK(zhuman_parse_bytes("18446744073709551615 KiB", &value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(value == 123);
    CHECK(zhuman_parse_duration("18446744073709551615s", &value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(value == 123);
    /* Distinct valid components must still respect the total bound. */
    CHECK(zhuman_parse_duration("1s 18446744073709551615ms", &value) == ZHUMAN_ERR_OVERFLOW);
    CHECK(value == 123);
    expect_parse_duration("1s 18446744073709550615ms", UINT64_MAX);
}

static bool cli_text(FILE *f, const char *expected)
{
    rewind(f);
    char buf[256];
    size_t n = fread(buf, 1, sizeof buf, f);
    return !ferror(f) && n == strlen(expected) && memcmp(buf, expected, n) == 0;
}

static bool cli_case(int argc, char **argv, int status, const char *out,
                     const char *err)
{
    cli_out = tmpfile(); cli_err = tmpfile();
    if (!cli_out || !cli_err) {
        if (cli_out) fclose(cli_out);
        if (cli_err) fclose(cli_err);
        return false;
    }
    int actual = zhuman_cli_main(argc, argv);
    bool ok = actual == status && cli_text(cli_out, out) && cli_text(cli_err, err);
    if (fclose(cli_out) != 0) ok = false;
    if (fclose(cli_err) != 0) ok = false;
    return ok;
}

static void test_cli_numeric(void)
{
    const char *usage_text = "usage: zhuman bytes [--si] <n>\n"
        "       zhuman parse-bytes <s>\n       zhuman duration <ms>\n"
        "       zhuman parse-duration <s>\n";
    char *invalid[] = {"", " ", "-1", " -0", "18446744073709551616", "1x"};
    for (size_t mode = 0; mode < 3; mode++) {
        for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
            char *args[] = {"zhuman", mode == 2 ? "duration" : "bytes",
                            mode == 1 ? "--si" : invalid[i], invalid[i], NULL};
            CHECK(cli_case(mode == 1 ? 4 : 3, args, 2, "", usage_text));
        }
        char expected[128], formatted[96];
        zhuman_err e = mode == 2 ? zhuman_format_duration(UINT64_MAX, formatted, sizeof formatted)
            : mode == 1 ? zhuman_format_bytes_si(UINT64_MAX, formatted, sizeof formatted)
                        : zhuman_format_bytes_iec(UINT64_MAX, formatted, sizeof formatted);
        CHECK(e == ZHUMAN_OK);
        snprintf(expected, sizeof expected, "%s\n", formatted);
        char *max[] = {"zhuman", mode == 2 ? "duration" : "bytes",
                       mode == 1 ? "--si" : " +18446744073709551615",
                       " +18446744073709551615", NULL};
        CHECK(cli_case(mode == 1 ? 4 : 3, max, 0, expected, ""));
        char *zero[] = {"zhuman", mode == 2 ? "duration" : "bytes",
                        mode == 1 ? "--si" : "0", "0", NULL};
        CHECK(cli_case(mode == 1 ? 4 : 3, zero, 0,
                       mode == 2 ? "0 ms\n" : "0 B\n", ""));
    }
}

int main(void)
{
    test_cli_numeric();
    test_format_bytes();
    test_parse_bytes();
    test_duration();
    test_uint64_decimal_bounds();
    test_err_str();
    puts("test_zhuman: all groups passed (fmtbytes parsebytes duration errstr)");
    return 0;
}
