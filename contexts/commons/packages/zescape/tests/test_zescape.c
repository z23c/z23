#include "zescape/zescape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void expect_escape(const void *in, size_t len, const char *want)
{
    char buf[512];
    size_t n = 0;
    CHECK(zescape_escape(in, len, buf, sizeof buf, &n) == ZESCAPE_OK);
    CHECK(n == strlen(want));
    CHECK(memcmp(buf, want, n) == 0);
}

static void expect_unescape(const char *in, const void *want, size_t want_len)
{
    uint8_t buf[512];
    size_t n = 0, pos = 0;
    CHECK(zescape_unescape(in, strlen(in), buf, sizeof buf, &n, &pos) == ZESCAPE_OK);
    CHECK(n == want_len);
    CHECK(want_len == 0 || memcmp(buf, want, n) == 0);
}

static void test_escape_basics(void)
{
    expect_escape("", 0, "");
    expect_escape("hello", 5, "hello");
    expect_escape("a\nb", 3, "a\\nb");
    expect_escape("tab\there", 8, "tab\\there");
    expect_escape("q\"q", 3, "q\\\"q");
    expect_escape("b\\b", 3, "b\\\\b");
    expect_escape("\r", 1, "\\r");
    /* NUL and other control bytes -> \xNN. */
    expect_escape("\0", 1, "\\x00");
    expect_escape("\x1b", 1, "\\x1b");
    expect_escape("\x7f", 1, "\\x7f");
    expect_escape("\xff", 1, "\\xff");
    expect_escape("\x01", 1, "\\x01");
    /* DEL boundary: 0x7e printable, 0x7f escaped. */
    expect_escape("~", 1, "~");
    expect_escape(" ", 1, " ");

    CHECK(zescape_escaped_max(3) == 12);
}

static void test_escape_small_buffer(void)
{
    char buf[4];
    size_t n = 0;
    /* "a\xff" needs 1 + 4 = 5. */
    CHECK(zescape_escape("a\xff", 2, buf, sizeof buf, &n) == ZESCAPE_ERR_SMALL);
    CHECK(n == 5);
    /* Exact fit works. */
    char exact[5];
    CHECK(zescape_escape("a\xff", 2, exact, sizeof exact, &n) == ZESCAPE_OK);
    CHECK(n == 5 && memcmp(exact, "a\\xff", 5) == 0);
    /* NULL handling. */
    CHECK(zescape_escape(NULL, 1, exact, 5, &n) == ZESCAPE_ERR_NULL);
    CHECK(zescape_escape("a", 1, NULL, 5, &n) == ZESCAPE_ERR_NULL);
    CHECK(zescape_escape("a", 1, exact, 5, NULL) == ZESCAPE_ERR_NULL);
}

static void test_unescape_basics(void)
{
    expect_unescape("", "", 0);
    expect_unescape("hello", "hello", 5);
    expect_unescape("a\\nb", "a\nb", 3);
    expect_unescape("\\t\\\\\\\"", "\t\\\"", 3);
    expect_unescape("\\x41\\x42", "AB", 2);
    expect_unescape("\\x00", "\0", 1);
    expect_unescape("\\xff", "\xff", 1);
    expect_unescape("\\xFF", "\xff", 1);   /* uppercase hex */
    expect_unescape("\\0", "\0", 1);
    expect_unescape("\\a\\b\\f\\v\\r", "\a\b\f\v\r", 5);
    expect_unescape("\\'", "'", 1);
}

static void test_unescape_errors(void)
{
    uint8_t buf[64];
    size_t n, pos;

    /* Unknown letter. */
    CHECK(zescape_unescape("a\\qb", 4, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_BAD_ESCAPE);
    CHECK(pos == 1);

    /* Trailing backslash. */
    CHECK(zescape_unescape("abc\\", 4, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_TRUNCATED);
    CHECK(pos == 3);

    /* \x truncated: "\x4" and "\x" at end. */
    CHECK(zescape_unescape("\\x4", 3, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_TRUNCATED);
    CHECK(pos == 0);
    CHECK(zescape_unescape("\\x", 2, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_TRUNCATED);

    /* Bad hex digits, position points at the digit. */
    CHECK(zescape_unescape("\\xg1", 4, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_BAD_HEX);
    CHECK(pos == 2);
    CHECK(zescape_unescape("\\x1g", 4, buf, sizeof buf, &n, &pos)
          == ZESCAPE_ERR_BAD_HEX);
    CHECK(pos == 3);

    /* Output capacity. */
    CHECK(zescape_unescape("abcdef", 6, buf, 3, &n, &pos)
          == ZESCAPE_ERR_SMALL);
    CHECK(zescape_unescape("\\x41\\x42", 8, buf, 1, &n, &pos)
          == ZESCAPE_ERR_SMALL);

    /* NULL handling. */
    CHECK(zescape_unescape(NULL, 1, buf, 4, &n, &pos) == ZESCAPE_ERR_NULL);
    CHECK(zescape_unescape("a", 1, NULL, 4, &n, &pos) == ZESCAPE_ERR_NULL);
    CHECK(zescape_unescape("a", 1, buf, 4, NULL, &pos) == ZESCAPE_ERR_NULL);
}

static uint64_t rng_state = 0x2545f4914f6cdd1dull;
static uint32_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static void test_roundtrip_fuzz(void)
{
    /* Every byte value individually. */
    for (int v = 0; v < 256; v++) {
        uint8_t b = (uint8_t)v;
        char esc[8];
        size_t en = 0;
        CHECK(zescape_escape(&b, 1, esc, sizeof esc, &en) == ZESCAPE_OK);
        uint8_t back[8];
        size_t bn = 0;
        CHECK(zescape_unescape(esc, en, back, sizeof back, &bn, NULL) == ZESCAPE_OK);
        CHECK(bn == 1 && back[0] == b);
    }

    /* Random buffers survive escape -> unescape. */
    for (int iter = 0; iter < 5000; iter++) {
        size_t len = (size_t)(rng_next() % 65u);
        uint8_t bin[64];
        for (size_t i = 0; i < len; i++) bin[i] = (uint8_t)rng_next();

        char esc[64 * 4];
        size_t en = 0;
        CHECK(zescape_escape(bin, len, esc, sizeof esc, &en) == ZESCAPE_OK);
        CHECK(en == zescape_escaped_max(len) || en <= zescape_escaped_max(len));

        uint8_t back[64];
        size_t bn = 0;
        CHECK(zescape_unescape(esc, en, back, sizeof back, &bn, NULL) == ZESCAPE_OK);
        CHECK(bn == len);
        CHECK(len == 0 || memcmp(bin, back, len) == 0);
    }
}

static void test_err_str(void)
{
    CHECK(strcmp(zescape_err_str(ZESCAPE_OK), "ok") == 0);
    CHECK(strstr(zescape_err_str(ZESCAPE_ERR_BAD_HEX), "hex") != NULL);
    CHECK(zescape_err_str((zescape_err)999) != NULL);
}

int main(void)
{
    test_escape_basics();
    test_escape_small_buffer();
    test_unescape_basics();
    test_unescape_errors();
    test_roundtrip_fuzz();
    test_err_str();
    puts("test_zescape: all groups passed (escape small unescape errors fuzz errstr)");
    return 0;
}
