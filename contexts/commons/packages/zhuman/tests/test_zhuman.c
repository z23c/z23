#include "zhuman/zhuman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
    test_format_bytes();
    test_parse_bytes();
    test_duration();
    test_err_str();
    puts("test_zhuman: all groups passed (fmtbytes parsebytes duration errstr)");
    return 0;
}
