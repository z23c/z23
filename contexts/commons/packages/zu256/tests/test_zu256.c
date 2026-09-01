/* zu256 tests: identities, edge cases, and differential vectors
 * cross-checked against Python's arbitrary-precision integers. */
#include "zu256/zu256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
    test_identities();
    test_arith_vectors();
    test_shift_vectors();
    test_be32();
    test_hex();
    test_dec();
    puts("test_zu256: all groups passed (ids arith shift be32 hex dec)");
    return 0;
}
