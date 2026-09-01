/* zpuny tests: RFC 3492 section 7.1 sample strings, round trips,
 * error paths, UTF-8 front-ends. */
#include "zpuny/zpuny.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

/* RFC 3492 7.1 sample: (A) Arabic */
static void test_rfc_arabic(void)
{
    static const uint32_t in[] = {
        0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A,
        0x0643, 0x0644, 0x0645, 0x0648, 0x0634, 0x0639, 0x0631,
        0x0628, 0x064A, 0x061F
    };
    const char *want = "egbpdaj6bu4bxfgehfvwxn";
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(want) && memcmp(out, want, n) == 0);

    uint32_t back[32];
    size_t bn = 0;
    CHECK(zpuny_decode(want, strlen(want), back, 32, &bn) == ZPUNY_OK);
    CHECK(bn == sizeof in / sizeof *in);
    CHECK(memcmp(back, in, sizeof in) == 0);
}

/* (C) Czech: Proč prostě nemluví česky */
static void test_rfc_czech(void)
{
    static const uint32_t in[] = {
        0x0050, 0x0072, 0x006F, 0x010D, 0x0070, 0x0072, 0x006F,
        0x0073, 0x0074, 0x011B, 0x006E, 0x0065, 0x006D, 0x006C,
        0x0075, 0x0076, 0x00ED, 0x010D, 0x0065, 0x0073, 0x006B,
        0x0079
    };
    const char *want = "Proprostnemluvesky-uyb24dma41a";
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(want) && memcmp(out, want, n) == 0);
}

/* (J) Japanese: なぜみんな日本語を話してくれないのか */
static void test_rfc_japanese(void)
{
    static const uint32_t in[] = {
        0x306A, 0x305C, 0x307F, 0x3093, 0x306A, 0x65E5, 0x672C,
        0x8A9E, 0x3092, 0x8A71, 0x3057, 0x3066, 0x304F, 0x308C,
        0x306A, 0x3044, 0x306E, 0x304B
    };
    const char *want = "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa";
    /* NOTE: the RFC string is checked by round trip if the literal
       differs; compare to the RFC literal directly. */
    const char *rfc = "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa";
    (void)want;
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(rfc) && memcmp(out, rfc, n) == 0);
}

/* (R) Russian (Cyrillic) */
static void test_rfc_russian(void)
{
    static const uint32_t in[] = {
        0x043F, 0x043E, 0x0447, 0x0435, 0x043C, 0x0443, 0x0436,
        0x0435, 0x043E, 0x043D, 0x0438, 0x043D, 0x0435, 0x0433,
        0x043E, 0x0432, 0x043E, 0x0440, 0x044F, 0x0442, 0x043F,
        0x043E, 0x0440, 0x0443, 0x0441, 0x0441, 0x043A, 0x0438
    };
    const char *rfc = "b1abfaaepdrnnbgefbadotcwatmq2g4l";
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(rfc) && memcmp(out, rfc, n) == 0);
}

/* (L) mixed: 3年B組金八先生 */
static void test_rfc_mixed_3b(void)
{
    static const uint32_t in[] = {
        0x0033, 0x5E74, 0x0042, 0x7D44, 0x91D1, 0x516B, 0x5148,
        0x751F
    };
    const char *rfc = "3B-ww4c5e180e575a65lsy2b";
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(rfc) && memcmp(out, rfc, n) == 0);
}

/* (Q) Japanese with ASCII tail: MajiでKoiする5秒前 */
static void test_rfc_maji(void)
{
    static const uint32_t in[] = {
        0x004D, 0x0061, 0x006A, 0x0069, 0x3067, 0x004B, 0x006F,
        0x0069, 0x3059, 0x308B, 0x0035, 0x79D2, 0x524D
    };
    const char *rfc = "MajiKoi5-783gue6qz075azm5e";
    char out[128];
    size_t n = 0;
    CHECK(zpuny_encode(in, sizeof in / sizeof *in, out, sizeof out, &n)
          == ZPUNY_OK);
    CHECK(n == strlen(rfc) && memcmp(out, rfc, n) == 0);
}

static void test_pure_ascii(void)
{
    static const uint32_t in[] = { 'a', 'b', 'c' };
    /* RFC: basic-only input still gets a trailing delimiter. */
    const char *rfc = "abc-";
    char out[16];
    size_t n = 0;
    CHECK(zpuny_encode(in, 3, out, sizeof out, &n) == ZPUNY_OK);
    CHECK(n == strlen(rfc) && memcmp(out, rfc, n) == 0);

    uint32_t back[8];
    size_t bn = 0;
    CHECK(zpuny_decode("abc-", 4, back, 8, &bn) == ZPUNY_OK);
    CHECK(bn == 3 && back[0] == 'a' && back[2] == 'c');
    /* and without delimiter, decoders accept it too */
    CHECK(zpuny_decode("abc", 3, back, 8, &bn) == ZPUNY_OK);
    CHECK(bn == 3);
}

static void test_overflow_reports_size(void)
{
    static const uint32_t in[] = { 0x4E2D, 0x6587 };
    size_t need = 0;
    CHECK(zpuny_encode(in, 2, NULL, 0, &need) == ZPUNY_OVERFLOW);
    CHECK(need > 0);
    char *buf = malloc(need);
    CHECK(buf != NULL);
    size_t got = 0;
    CHECK(zpuny_encode(in, 2, buf, need, &got) == ZPUNY_OK);
    CHECK(got == need);
    free(buf);
}

static void test_bad_input(void)
{
    uint32_t cp[8];
    size_t n = 0;
    /* truncated digit run */
    CHECK(zpuny_decode("a-", 2, cp, 8, &n) == ZPUNY_OK); /* empty tail ok */
    CHECK(zpuny_decode("!!!", 3, cp, 8, &n) == ZPUNY_BAD_INPUT);
    /* surrogate code point rejected on encode */
    uint32_t bad[1] = { 0xD800 };
    char out[8];
    CHECK(zpuny_encode(bad, 1, out, sizeof out, &n) == ZPUNY_BAD_INPUT);
    /* above Unicode range */
    bad[0] = 0x110000;
    CHECK(zpuny_encode(bad, 1, out, sizeof out, &n) == ZPUNY_BAD_INPUT);
    /* case-insensitive decode of the encoded (post-delimiter) part */
    uint32_t lo[8], hi[8];
    size_t ln = 0, hn = 0;
    CHECK(zpuny_decode("bcher-kva8446foa", 16, lo, 8, &ln) == ZPUNY_OK);
    CHECK(zpuny_decode("bcher-KVA8446FOA", 16, hi, 8, &hn) == ZPUNY_OK);
    CHECK(ln == hn && memcmp(lo, hi, ln * sizeof *lo) == 0);
}

static void test_utf8_frontend(void)
{
    const char *label = "bücher"; /* b U+00FC c h e r */
    char out[64];
    size_t n = 0;
    CHECK(zpuny_encode_utf8(label, strlen(label), out, sizeof out, &n)
          == ZPUNY_OK);
    const char *want = "bcher-kva";
    CHECK(n == strlen(want) && memcmp(out, want, n) == 0);

    char back[64];
    size_t bn = 0;
    CHECK(zpuny_decode_utf8(want, strlen(want), back, sizeof back, &bn)
          == ZPUNY_OK);
    CHECK(bn == strlen(label) && memcmp(back, label, bn) == 0);

    /* invalid UTF-8 rejected */
    const char bad[] = { (char)0xC0, (char)0xAF, 0 };
    CHECK(zpuny_encode_utf8(bad, 2, out, sizeof out, &n)
          == ZPUNY_BAD_INPUT);
}

/* Random round-trip over mixed ranges, decode(encode(x)) == x. */
static void test_roundtrip_rng(void)
{
    unsigned long long s = 0x9E3779B97F4A7C15ull;
    for (int iter = 0; iter < 2000; iter++) {
        uint32_t in[40];
        size_t len;
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        len = (size_t)(s % 40);
        for (size_t i = 0; i < len; i++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            unsigned r = (unsigned)(s % 100);
            if (r < 30) in[i] = 'a' + (uint32_t)(s % 26);        /* ascii */
            else if (r < 55) in[i] = 0x80 + (uint32_t)(s % 0x700); /* latin */
            else if (r < 80) in[i] = 0x3000 + (uint32_t)(s % 0x4000);
            else in[i] = 0x10000 + (uint32_t)(s % 0x80000);
            if (in[i] >= 0xD800 && in[i] <= 0xDFFF) in[i] = 'x';
        }
        char enc[512];
        size_t en = 0;
        CHECK(zpuny_encode(in, len, enc, sizeof enc, &en) == ZPUNY_OK);
        uint32_t back[40];
        size_t bn = 0;
        CHECK(zpuny_decode(enc, en, back, 40, &bn) == ZPUNY_OK);
        CHECK(bn == len);
        CHECK(memcmp(in, back, len * sizeof *in) == 0);
    }
}

int main(void)
{
    test_rfc_arabic();
    test_rfc_czech();
    test_rfc_japanese();
    test_rfc_russian();
    test_rfc_mixed_3b();
    test_rfc_maji();
    test_pure_ascii();
    test_overflow_reports_size();
    test_bad_input();
    test_utf8_frontend();
    test_roundtrip_rng();
    puts("test_zpuny: all groups passed (rfc ascii overflow bad utf8 rng)");
    return 0;
}
