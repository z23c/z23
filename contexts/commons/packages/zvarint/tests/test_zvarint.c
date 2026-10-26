#include "zvarint/zvarint.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ISO C stdio faults, scoped to the embedded CLI; test diagnostics stay real. */
int test_cli_printf(const char *format, ...);
int test_cli_fprintf(FILE *stream, const char *format, ...);
int test_cli_putchar(int c);
int test_cli_fflush(FILE *stream);
int test_cli_fclose(FILE *stream);
int test_cli_ferror(FILE *stream);
#define printf test_cli_printf
#define fprintf test_cli_fprintf
#define putchar test_cli_putchar
#define fflush test_cli_fflush
#define fclose test_cli_fclose
#define ferror test_cli_ferror
#define main zvarint_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef fprintf
#undef putchar
#undef fflush
#undef fclose
#undef ferror

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

enum { IO_NONE, IO_WRITE, IO_PUTCHAR, IO_FLUSH, IO_CLOSE };
static int io_failure, io_stream;
static int io_errors[2], io_closes[2], io_flushes[2];
static char io_text[2][512];
static size_t io_used[2];

static int io_index(FILE *stream)
{
    CHECK(stream == stdout || stream == stderr);
    return stream == stderr;
}

static void io_reset(int failure, int stream)
{
    io_failure = failure;
    io_stream = stream;
    memset(io_errors, 0, sizeof io_errors);
    memset(io_closes, 0, sizeof io_closes);
    memset(io_flushes, 0, sizeof io_flushes);
    memset(io_text, 0, sizeof io_text);
    memset(io_used, 0, sizeof io_used);
}

static int io_print(FILE *stream, const char *format, va_list ap)
{
    int index = io_index(stream);
    CHECK(io_closes[index] == 0);
    if (io_failure == IO_WRITE && io_stream == index) {
        io_errors[index] = 1;
        return -1;
    }
    size_t space = sizeof io_text[index] - io_used[index];
    int n = vsnprintf(io_text[index] + io_used[index], space, format, ap);
    CHECK(n >= 0);
    CHECK((size_t)n < space);
    io_used[index] += (size_t)n;
    return n;
}

int test_cli_printf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = io_print(stdout, format, ap);
    va_end(ap);
    return n;
}

int test_cli_fprintf(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = io_print(stream, format, ap);
    va_end(ap);
    return n;
}

int test_cli_putchar(int c)
{
    CHECK(io_closes[0] == 0);
    if (io_failure == IO_PUTCHAR && io_stream == 0) {
        io_errors[0] = 1;
        return EOF;
    }
    CHECK(io_used[0] < sizeof io_text[0] - 1);
    io_text[0][io_used[0]++] = (char)c;
    io_text[0][io_used[0]] = '\0';
    return (unsigned char)c;
}

int test_cli_fflush(FILE *stream)
{
    int index = io_index(stream);
    CHECK(io_closes[index] == 0);
    ++io_flushes[index];
    /* A failed earlier write need not make a subsequent flush fail. */
    return io_failure == IO_FLUSH && io_stream == index ? EOF : 0;
}

int test_cli_fclose(FILE *stream)
{
    int index = io_index(stream);
    CHECK(io_closes[index] == 0);
    ++io_closes[index];
    return io_failure == IO_CLOSE && io_stream == index ? EOF : 0;
}

int test_cli_ferror(FILE *stream)
{
    int index = io_index(stream);
    CHECK(io_closes[index] == 0);
    return io_errors[index];
}

static void test_known_vectors(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n = 0;

    /* LEB128 reference values. */
    CHECK(zvarint_encode_u64(0, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x00);

    CHECK(zvarint_encode_u64(1, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x01);

    CHECK(zvarint_encode_u64(127, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x7f);

    CHECK(zvarint_encode_u64(128, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 2 && buf[0] == 0x80 && buf[1] == 0x01);

    CHECK(zvarint_encode_u64(624485, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 3 && buf[0] == 0xe5 && buf[1] == 0x8e && buf[2] == 0x26);

    CHECK(zvarint_encode_u64(UINT64_MAX, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10 && buf[0] == 0xff && buf[9] == 0x01);

    /* Length helpers agree with encoding. */
    CHECK(zvarint_len_u64(0) == 1);
    CHECK(zvarint_len_u64(127) == 1);
    CHECK(zvarint_len_u64(128) == 2);
    CHECK(zvarint_len_u64(UINT64_MAX) == 10);
}

static void test_zigzag(void)
{
    CHECK(zvarint_zigzag_encode(0) == 0);
    CHECK(zvarint_zigzag_encode(-1) == 1);
    CHECK(zvarint_zigzag_encode(1) == 2);
    CHECK(zvarint_zigzag_encode(-2) == 3);
    CHECK(zvarint_zigzag_encode(2) == 4);
    CHECK(zvarint_zigzag_encode(INT64_MAX) == UINT64_MAX - 1);
    CHECK(zvarint_zigzag_encode(INT64_MIN) == UINT64_MAX);

    CHECK(zvarint_zigzag_decode(0) == 0);
    CHECK(zvarint_zigzag_decode(1) == -1);
    CHECK(zvarint_zigzag_decode(2) == 1);
    CHECK(zvarint_zigzag_decode(3) == -2);
    CHECK(zvarint_zigzag_decode(UINT64_MAX) == INT64_MIN);

    /* int64 extremes round trip through the wire format. */
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n, c;
    int64_t s;
    CHECK(zvarint_encode_i64(INT64_MIN, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10);
    CHECK(zvarint_decode_i64(buf, n, &s, &c, 1) == ZVARINT_OK);
    CHECK(s == INT64_MIN && c == 10);
    CHECK(zvarint_encode_i64(INT64_MAX, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10);
    CHECK(zvarint_decode_i64(buf, n, &s, &c, 1) == ZVARINT_OK);
    CHECK(s == INT64_MAX);
}

static void test_errors(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    uint64_t v;
    size_t c;

    /* Truncated: continuation bit set, buffer ends. */
    const uint8_t trunc[] = {0x80};
    CHECK(zvarint_decode_u64(trunc, sizeof trunc, &v, &c, 0)
          == ZVARINT_ERR_TRUNCATED);

    /* Overflow: 11 continuation bytes. */
    const uint8_t over[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01};
    CHECK(zvarint_decode_u64(over, sizeof over, &v, &c, 0)
          == ZVARINT_ERR_OVERFLOW);

    /* Overflow: 10th byte carries more than one payload bit. */
    const uint8_t over2[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02};
    CHECK(zvarint_decode_u64(over2, sizeof over2, &v, &c, 0)
          == ZVARINT_ERR_OVERFLOW);

    /* 10th byte exactly 0x01 is legal (UINT64_MAX). */
    const uint8_t max[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01};
    CHECK(zvarint_decode_u64(max, sizeof max, &v, &c, 0) == ZVARINT_OK);
    CHECK(v == UINT64_MAX && c == 10);

    /* Non-canonical: 0x80 0x00 means zero in two bytes. */
    const uint8_t noncanon[] = {0x80, 0x00};
    CHECK(zvarint_decode_u64(noncanon, 2, &v, &c, 0) == ZVARINT_OK);
    CHECK(v == 0 && c == 2);
    CHECK(zvarint_decode_u64(noncanon, 2, &v, &c, 1)
          == ZVARINT_ERR_NONCANONICAL);

    /* NULL arguments. */
    CHECK(zvarint_decode_u64(NULL, 1, &v, &c, 0) == ZVARINT_ERR_NULL);
    CHECK(zvarint_decode_u64(buf, 1, NULL, &c, 0) == ZVARINT_ERR_NULL);
    CHECK(zvarint_encode_u64(1, NULL, 10, NULL) == ZVARINT_ERR_NULL);

    /* Output capacity too small. */
    CHECK(zvarint_encode_u64(128, buf, 1, NULL) == ZVARINT_ERR_TRUNCATED);

    /* Trailing bytes after a varint are fine; consumed points past it. */
    const uint8_t seq[] = {0x01, 0x02, 0x03};
    CHECK(zvarint_decode_u64(seq, 3, &v, &c, 1) == ZVARINT_OK);
    CHECK(v == 1 && c == 1);
}

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_roundtrip(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n, c;

    /* Boundary values: every 7-bit group edge. */
    for (int shift = 0; shift < 64; shift++) {
        uint64_t base = (shift == 63) ? UINT64_MAX : ((1ull << shift) - 1);
        for (int d = -1; d <= 1; d++) {
            uint64_t v = base + (uint64_t)d;
            if (d < 0 && base == 0) continue;
            CHECK(zvarint_encode_u64(v, buf, sizeof buf, &n) == ZVARINT_OK);
            CHECK(n == zvarint_len_u64(v));
            uint64_t back;
            CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
            CHECK(back == v && c == n);
            /* Own encoding is always canonical under strict mode. */
            CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
        }
    }

    /* Random unsigned. */
    for (int i = 0; i < 20000; i++) {
        uint64_t v = rng_next();
        /* Vary magnitude so small values get exercised too. */
        v >>= (rng_next() % 64);
        CHECK(zvarint_encode_u64(v, buf, sizeof buf, &n) == ZVARINT_OK);
        uint64_t back;
        CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
        CHECK(back == v && c == n);
    }

    /* Random signed. */
    for (int i = 0; i < 20000; i++) {
        int64_t s = (int64_t)rng_next();
        s >>= (int)(rng_next() % 63);
        CHECK(zvarint_encode_i64(s, buf, sizeof buf, &n) == ZVARINT_OK);
        CHECK(n == zvarint_len_i64(s));
        int64_t back;
        CHECK(zvarint_decode_i64(buf, n, &back, &c, 1) == ZVARINT_OK);
        CHECK(back == s && c == n);
    }
}

static void test_err_str(void)
{
    CHECK(strcmp(zvarint_err_str(ZVARINT_OK), "ok") == 0);
    CHECK(strstr(zvarint_err_str(ZVARINT_ERR_TRUNCATED), "mid-varint") != NULL);
    CHECK(zvarint_err_str((zvarint_err)999) != NULL);
}

static void test_cli_decimal_refusal(void)
{
    static const struct { char *mode; char *number; } cases[] = {
        {"enc", "18446744073709551616"},
        {"encs", "9223372036854775808"},
        {"encs", "-9223372036854775809"},
        {"enc", ""}, {"encs", ""},
        {"enc", "-1"}, {"enc", " -1"}
    };
    size_t accepted = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        char *args[] = {"zvarint", cases[i].mode, cases[i].number, NULL};
        io_reset(IO_NONE, 0);
        int status = zvarint_cli_main(3, args);
        if (status == 0) {
            fprintf(stderr, "accepted invalid decimal: %s [%s]\n",
                    cases[i].mode, cases[i].number);
            ++accepted;
        }
    }
    CHECK(accepted == 0);
}

/* Compatibility controls, not additional defect claims. */
static void test_cli_decimal_controls(void)
{
    static const struct { char *mode; char *number; int valid; } cases[] = {
        {"enc", "18446744073709551614", 1},
        {"enc", "18446744073709551615", 1},
        {"encs", "9223372036854775806", 1},
        {"encs", "9223372036854775807", 1},
        {"encs", "-9223372036854775808", 1},
        {"encs", "-9223372036854775807", 1},
        {"enc", "0", 1}, {"encs", "0", 1},
        {"enc", " +1", 1}, {"encs", " -1", 1},
        {"enc", "12x", 0}, {"encs", "+", 0}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        char *args[] = {"zvarint", cases[i].mode, cases[i].number, NULL};
        io_reset(IO_NONE, 0);
        errno = ERANGE;
        CHECK((zvarint_cli_main(3, args) == 0) == cases[i].valid);
    }
}

static void test_cli_output_failures(void)
{
    static const struct {
        char *mode, *input;
        int failure, stream;
        const char *name;
    } cases[] = {
        {"enc", "42", IO_WRITE, 0, "enc stdout write"},
        {"encs", "-1", IO_WRITE, 0, "encs stdout write"},
        {"dec", "2a", IO_WRITE, 0, "dec stdout write"},
        {"decs", "01", IO_WRITE, 0, "decs stdout write"},
        {"enc", "42", IO_PUTCHAR, 0, "stdout newline write"},
        {"enc", "42", IO_FLUSH, 0, "stdout flush"},
        {"enc", "42", IO_CLOSE, 0, "stdout close"},
        {"enc", "42", IO_FLUSH, 1, "stderr flush"},
        {"enc", "42", IO_CLOSE, 1, "stderr close"}
    };
    size_t missed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        char *args[] = {"zvarint", cases[i].mode, cases[i].input, NULL};
        io_reset(cases[i].failure, cases[i].stream);
        if (zvarint_cli_main(3, args) == 0) {
            fprintf(stderr, "ignored output failure: %s\n", cases[i].name);
            ++missed;
        } else {
            CHECK(io_closes[0] == 1 && io_closes[1] == 1);
        }
    }
    CHECK(missed == 0);
}

/* Output and diagnostic controls: these are not additional defect claims. */
static void test_cli_output_controls(void)
{
    static const struct { char *mode, *input; const char *output; } cases[] = {
        {"enc", "42", "2a\n"}, {"encs", "-1", "01\n"},
        {"dec", "2a", "42\n"}, {"decs", "01", "-1\n"}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        char *args[] = {"zvarint", cases[i].mode, cases[i].input, NULL};
        io_reset(IO_NONE, 0);
        CHECK(zvarint_cli_main(3, args) == 0);
        CHECK(strcmp(io_text[0], cases[i].output) == 0);
        CHECK(io_flushes[0] == 1 && io_flushes[1] == 1);
        CHECK(io_closes[0] == 1 && io_closes[1] == 1);
    }
    char *bad[] = {"zvarint", "dec", "0g", NULL};
    io_reset(IO_WRITE, 1);
    CHECK(zvarint_cli_main(3, bad) != 0);
    CHECK(io_errors[1] != 0);
    CHECK(io_closes[0] == 1 && io_closes[1] == 1);
}

static void test_cli_argument_count(void)
{
    char *decode_modes[] = {"dec", "decs"};
    for (size_t i = 0; i < sizeof decode_modes / sizeof decode_modes[0]; ++i) {
        char *args[] = {"zvarint", decode_modes[i], "00", "not-hex", NULL};
        io_reset(IO_NONE, 0);
        CHECK(zvarint_cli_main(4, args) == 2);
        CHECK(io_text[0][0] == '\0');
        CHECK(strstr(io_text[1], "usage:") != NULL);
    }
    char *encode_modes[] = {"enc", "encs"};
    const char *expected[] = {"00\n01\n", "00\n02\n"};
    for (size_t i = 0; i < sizeof encode_modes / sizeof encode_modes[0]; ++i) {
        char *args[] = {"zvarint", encode_modes[i], "0", "1", NULL};
        io_reset(IO_NONE, 0);
        CHECK(zvarint_cli_main(4, args) == 0);
        CHECK(strcmp(io_text[0], expected[i]) == 0);
    }
}

int main(void)
{
    test_known_vectors();
    test_zigzag();
    test_errors();
    test_roundtrip();
    test_err_str();
    test_cli_decimal_refusal();
    test_cli_decimal_controls();
    test_cli_output_failures();
    test_cli_output_controls();
    test_cli_argument_count();
    puts("test_zvarint: all groups passed (vectors zigzag errors roundtrip errstr cli)");
    return 0;
}
