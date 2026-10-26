/* zu256 tests: identities, edge cases, and differential vectors
 * cross-checked against Python's arbitrary-precision integers. */
#include "zu256/zu256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

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
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define puts(text) fprintf(cli_sink, "%s\n", (text))
#define fflush cli_flush
#define main zu256_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef puts
#undef fflush
#undef stdout
#define stdout real_stdout()

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

static bool eq(zu256256 a, zu256256 b) { return zu256_cmp(a, b) == 0; }

#include "vectors.h"

static void test_identities(void)
{
    CHECK(zu256_is_zero(ZU256256_ZERO));
    CHECK(!zu256_is_zero(ZU256256_ONE));
    CHECK(eq(zu256_add(ZU256256_ZERO, ZU256256_ONE, NULL),
             ZU256256_ONE));
    bool ovf = false;
    zu256256 w = zu256_add(ZU256256_MAX, ZU256256_ONE, &ovf);
    CHECK(ovf && zu256_is_zero(w)); /* wraps mod 2^256 */
    bool udf = false;
    w = zu256_sub(ZU256256_ZERO, ZU256256_ONE, &udf);
    CHECK(udf && eq(w, ZU256256_MAX));

    /* cmp ordering */
    zu256256 a = { { 0, 0, 1, 0 } };
    zu256256 b = { { UINT64_MAX, UINT64_MAX, 0, 0 } };
    CHECK(zu256_cmp(a, b) > 0);
    CHECK(zu256_cmp(b, a) < 0);
    CHECK(zu256_cmp(a, a) == 0);

    /* bitlen */
    CHECK(zu256_bitlen(ZU256256_ZERO) == 0);
    CHECK(zu256_bitlen(ZU256256_ONE) == 1);
    CHECK(zu256_bitlen(ZU256256_MAX) == 256);
    zu256256 top = { { 0, 0, 0, 0x8000000000000000ull } };
    CHECK(zu256_bitlen(top) == 256);

    /* div by zero fails closed */
    zu256256 q = ZU256256_MAX, r = ZU256256_MAX;
    CHECK(!zu256_divmod(ZU256256_ONE, ZU256256_ZERO, &q, &r));
    CHECK(eq(q, ZU256256_MAX) && eq(r, ZU256256_MAX));
}

static void test_arith_vectors(void)
{
    for (size_t i = 0; i < sizeof BVEC / sizeof *BVEC; i++) {
        const struct bvec *v = &BVEC[i];
        bool ovf = !v->sovf, udf = !v->duvf, movf = !v->movf;
        zu256256 s = zu256_add(v->a, v->b, &ovf);
        zu256256 d = zu256_sub(v->a, v->b, &udf);
        zu256256 p = zu256_mul(v->a, v->b, &movf);
        CHECK(eq(s, v->sum));
        CHECK(eq(d, v->diff));
        CHECK(eq(p, v->prod));
        CHECK(ovf == !!v->sovf);
        CHECK(udf == !!v->duvf);
        CHECK(movf == !!v->movf);
        zu256256 q, r;
        CHECK(zu256_divmod(v->a, v->b, &q, &r));
        CHECK(eq(q, v->q) && eq(r, v->r));
        /* invariant: a == q*b + r (no wrap in these vectors) */
        bool o1, o2;
        zu256256 recomposed = zu256_add(zu256_mul(q, v->b, &o1), r, &o2);
        CHECK(!o1 && !o2 && eq(recomposed, v->a));
    }
}

static void test_shift_vectors(void)
{
    for (size_t i = 0; i < sizeof SVEC / sizeof *SVEC; i++) {
        const struct svec *v = &SVEC[i];
        CHECK(eq(zu256_shl(v->a, v->n), v->shl));
        CHECK(eq(zu256_shr(v->a, v->n), v->shr));
    }
    /* shift by exactly 256 and beyond yields zero */
    CHECK(zu256_is_zero(zu256_shl(ZU256256_MAX, 256)));
    CHECK(zu256_is_zero(zu256_shr(ZU256256_MAX, 300)));
    /* bit access agrees with limbs */
    for (unsigned n = 0; n < 256; n++) {
        CHECK(zu256_bit(ZU256256_MAX, n));
    }
    CHECK(!zu256_bit(ZU256256_ZERO, 128));
    CHECK(!zu256_bit(ZU256256_MAX, 256));
}

static void test_be32(void)
{
    uint8_t buf[32];
    zu256_to_be32(ZU256256_MAX, buf);
    for (int i = 0; i < 32; i++) {
        CHECK(buf[i] == 0xFF);
    }
    CHECK(eq(zu256_from_be32(buf), ZU256256_MAX));
    memset(buf, 0, sizeof buf);
    buf[31] = 1;
    CHECK(eq(zu256_from_be32(buf), ZU256256_ONE));
    /* round trip on vectors */
    for (size_t i = 0; i < sizeof BVEC / sizeof *BVEC; i++) {
        zu256_to_be32(BVEC[i].a, buf);
        CHECK(eq(zu256_from_be32(buf), BVEC[i].a));
    }
}

static void test_hex(void)
{
    char h[65];
    zu256_to_hex(ZU256256_MAX, h);
    CHECK(strcmp(h,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") == 0);
    zu256256 v;
    CHECK(zu256_from_hex(h, &v) && eq(v, ZU256256_MAX));
    CHECK(zu256_from_hex("0x1A", &v) && eq(v, zu256_from_u64(26)));
    CHECK(zu256_from_hex("0", &v) && zu256_is_zero(v));
    CHECK(!zu256_from_hex("", &v));
    CHECK(!zu256_from_hex("zz", &v));
    /* 65 digits overflow */
    CHECK(!zu256_from_hex(
        "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &v));
    /* round trip */
    for (size_t i = 0; i < sizeof BVEC / sizeof *BVEC; i++) {
        zu256_to_hex(BVEC[i].a, h);
        CHECK(zu256_from_hex(h, &v) && eq(v, BVEC[i].a));
    }
}

static void test_dec(void)
{
    char buf[80];
    CHECK(zu256_to_dec(ZU256256_MAX, buf, sizeof buf));
    CHECK(strcmp(buf,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935") == 0);
    CHECK(zu256_to_dec(ZU256256_ZERO, buf, sizeof buf));
    CHECK(strcmp(buf, "0") == 0);
    /* buffer too small */
    CHECK(!zu256_to_dec(ZU256256_MAX, buf, 10));
    zu256256 v;
    CHECK(zu256_from_dec("0", &v) && zu256_is_zero(v));
    CHECK(!zu256_from_dec("", &v));
    CHECK(!zu256_from_dec("12a3", &v));
    /* max parses; max+1 overflows */
    CHECK(zu256_from_dec(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935", &v));
    CHECK(eq(v, ZU256256_MAX));
    CHECK(!zu256_from_dec(
        "115792089237316195423570985008687907853269984665640564039457584007913129639936", &v));
    for (size_t i = 0; i < sizeof DVEC / sizeof *DVEC; i++) {
        CHECK(zu256_from_dec(DVEC[i].dec, &v));
        CHECK(eq(v, DVEC[i].a));
        CHECK(zu256_to_dec(DVEC[i].a, buf, sizeof buf));
        CHECK(strcmp(buf, DVEC[i].dec) == 0);
    }
}

static void test_cli_rejects_unknown_operations(void)
{
    const char *ops[] = {"addjunk", "subtract", "multiply", "divide", "modulo"};
    unsigned failures = 0;
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        char *args[] = {"zu256", (char *)ops[i], "8", "2", NULL};
        int rc = zu256_cli_main(4, args);
        fprintf(stderr, "unknown_op_row=%zu op=%s result=%s\n", i, ops[i],
                rc == 2 ? "PASS" : "FAIL");
        if (rc != 2) failures++;
    }
    CHECK(failures == 0);
}

static int cli_shift_case(char *mode, char *operand, const char *count,
                           int status, const char *want, bool stale_errno)
{
    FILE *output = tmpfile();
    if (!output) return 1;
    cli_sink = output;
    char *args[] = {"zu256", mode, operand, (char *)count, NULL};
    errno = stale_errno ? ERANGE : 0;
    int bad = zu256_cli_main(4, args) != status;
    cli_sink = stdout;
    rewind(output);
    char got[128];
    size_t n = fread(got, 1, sizeof got, output);
    if (ferror(output) || n != strlen(want) || memcmp(got, want, n) != 0) bad = 1;
    if (fclose(output) != 0) bad = 1;
    return bad;
}

static void test_cli_shift_counts(void)
{
    char maximum[3 * sizeof(unsigned long long) + 1];
    snprintf(maximum, sizeof maximum, "%llu", ULLONG_MAX);
    const struct { const char *text; unsigned shift; } counts[] = {
        {"0", 0}, {"1", 1}, {"255", 255}, {"256", 256}, {"257", 256},
        {"4294967296", 256}, {"4294967297", 256}, {maximum, 256},
        {"+1", 1}, {" \t1", 1}, {"-0", 0}, {" \t-0", 0}
    };
    char high[] = "0x8000000000000000000000000000000000000000000000000000000000000000";
    for (int right = 0; right < 2; right++) {
        zu256256 operand;
        CHECK(parse(right ? high : "1", &operand));
        for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
            zu256256 want = right ? zu256_shr(operand, counts[i].shift)
                                  : zu256_shl(operand, counts[i].shift);
            char hex[65], text[68];
            zu256_to_hex(want, hex);
            snprintf(text, sizeof text, "0x%s\n", hex);
            CHECK(cli_shift_case(right ? "shr" : "shl", right ? high : "1",
                  counts[i].text, 0, text, false) == 0);
        }
    }
    const char *bad[] = {"", " ", "-1", " -2", "1junk", "1 ",
                         "184467440737095516160", "-18446744073709551615"};
    for (int right = 0; right < 2; right++) {
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            CHECK(cli_shift_case(right ? "shr" : "shl", "1", bad[i], 2, "", false) == 0);
        }
    }
    char hex[65], want[68];
    zu256_to_hex(zu256_from_u64(2), hex);
    snprintf(want, sizeof want, "0x%s\n", hex);
    CHECK(cli_shift_case("shl", "1", "1", 0, want, true) == 0);
}

static void test_cli_output(void);

int main(void)
{
    cli_sink = stdout;
    test_cli_output();
    test_cli_shift_counts();
    test_cli_rejects_unknown_operations();
    test_identities();
    test_arith_vectors();
    test_shift_vectors();
    test_be32();
    test_hex();
    test_dec();
    puts("test_zu256: all groups passed (ids arith shift be32 hex dec)");
    return 0;
}

static const struct output_row {
    const char *op, *a, *b, *decimal;
} output_rows[] = {
    {"dec", "42", NULL, "42"}, {"hex", "42", NULL, "42"},
    {"add", "40", "2", "42"}, {"sub", "44", "2", "42"},
    {"mul", "21", "2", "42"}, {"div", "84", "2", "42"},
    {"mod", "85", "43", "42"}, {"shl", "21", "1", "42"},
    {"shr", "84", "1", "42"}
};
static int output_invoke(FILE *sink, const char *op, const char *a, const char *b)
{
    char *args[] = {"zu256", (char *)op, (char *)a, (char *)b, NULL};
    cli_sink = sink;
    cli_flushes = 0;
    int rc = zu256_cli_main(b ? 4 : (a ? 3 : 2), args);
    cli_sink = stdout;
    return rc;
}
static void output_normal(const struct output_row *row)
{
    FILE *sink = tmpfile();
    CHECK(sink != NULL);
    CHECK(output_invoke(sink, row->op, row->a, row->b) == 0);
    char want[80], got[80];
    if (!strcmp(row->op, "dec")) snprintf(want, sizeof want, "%s\n", row->decimal);
    else {
        zu256256 value;
        CHECK(zu256_from_dec(row->decimal, &value));
        char hex[65];
        zu256_to_hex(value, hex);
        snprintf(want, sizeof want, "0x%s\n", hex);
    }
    rewind(sink);
    size_t n = fread(got, 1, sizeof got, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(got, want, n));
    CHECK(fclose(sink) == 0);
}
static void output_failure(const struct output_row *row, bool buffered)
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
    CHECK(output_invoke(sink, row->op, row->a, row->b) == 1);
    CHECK(ferror(sink));
    (void)fclose(sink);
}
static void output_unused(void)
{
    const struct { const char *op, *a, *b; int rc; } rows[] = {
        {"hex", NULL, NULL, 2}, {"hex", "garbage!", NULL, 2},
        {"add", "1", NULL, 2}, {"add", "1", "garbage!", 2},
        {"shl", "1", "bad", 2}, {"unknown", "1", "2", 2},
        {"div", "1", "0", 1}, {"mod", "1", "0", 1}
    };
#ifdef _WIN32
    FILE *sink = fopen("NUL", "r");
#else
    FILE *sink = fopen("/dev/null", "r");
#endif
    CHECK(sink != NULL);
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        CHECK(output_invoke(sink, rows[i].op, rows[i].a, rows[i].b) == rows[i].rc);
        CHECK(cli_flushes == 0 && !ferror(sink));
    }
    CHECK(fclose(sink) == 0);
}
static void test_cli_output(void)
{
    for (size_t i = 0; i < sizeof output_rows / sizeof output_rows[0]; i++) {
        output_normal(&output_rows[i]);
        output_failure(&output_rows[i], false);
#ifdef __linux__
        output_failure(&output_rows[i], true);
#endif
    }
    output_unused();
}
