/* zhkdf tests — RFC 5869 appendix A SHA-256 test cases. */
#include "zhkdf/zhkdf.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    while (s[0] && s[1]) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static int eq_hex(const uint8_t *buf, size_t len, const char *hex)
{
    uint8_t want[256];
    size_t n = unhex(hex, want);
    return n == len && memcmp(buf, want, len) == 0;
}

/* RFC 5869 test case 1: basic SHA-256, salt and info present. */
static void test_case1(void)
{
    uint8_t ikm[22];
    uint8_t prk[ZHKDF_SHA256_PRK_LEN];
    uint8_t okm[42];

    memset(ikm, 0x0b, sizeof ikm);
    check(zhkdf_sha256_extract("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
                               13, ikm, sizeof ikm, prk) == 0, "c1 extract rc");
    check(eq_hex(prk, sizeof prk,
                 "077709362c2e32df0ddc3f0dc47bba63"
                 "90b6c73bb50f9c3122ec844ad7c2b3e5"), "c1 prk");
    check(zhkdf_sha256_expand(prk, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
                              10, okm, sizeof okm) == 0, "c1 expand rc");
    check(eq_hex(okm, sizeof okm,
                 "3cb25f25faacd57a90434f64d0362f2a"
                 "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865"), "c1 okm");
}

/* RFC 5869 test case 2: longer inputs, 82-byte OKM. */
static void test_case2(void)
{
    uint8_t ikm[80], salt[80], info[80];
    uint8_t prk[ZHKDF_SHA256_PRK_LEN];
    uint8_t okm[82];

    for (size_t i = 0; i < 80; i++) {
        ikm[i] = (uint8_t)i;          /* 00..4f */
        salt[i] = (uint8_t)(0x60 + i); /* 60..af */
        info[i] = (uint8_t)(0xb0 + i); /* b0..ff */
    }
    check(zhkdf_sha256_extract(salt, sizeof salt, ikm, sizeof ikm, prk) == 0,
          "c2 extract rc");
    check(eq_hex(prk, sizeof prk,
                 "06a6b88c5853361a06104c9ceb35b45c"
                 "ef760014904671014a193f40c15fc244"), "c2 prk");
    check(zhkdf_sha256_expand(prk, info, sizeof info, okm, sizeof okm) == 0,
          "c2 expand rc");
    check(eq_hex(okm, sizeof okm,
                 "b11e398dc80327a1c8e7f78c596a4934"
                 "4f012eda2d4efad8a050cc4c19afa97c"
                 "59045a99cac7827271cb41c65e590e09"
                 "da3275600c2f09b8367793a9aca3db71"
                 "cc30c58179ec3e87c14c01d5c1f3434f"
                 "1d87"), "c2 okm");
}

/* RFC 5869 test case 3: empty salt and empty info. */
static void test_case3(void)
{
    uint8_t ikm[22];
    uint8_t prk[ZHKDF_SHA256_PRK_LEN];
    uint8_t okm[42];

    memset(ikm, 0x0b, sizeof ikm);
    check(zhkdf_sha256_extract(NULL, 0, ikm, sizeof ikm, prk) == 0,
          "c3 extract rc");
    check(eq_hex(prk, sizeof prk,
                 "19ef24a32c717b167f33a91d6f648bdf"
                 "96596776afdb6377ac434c1c293ccb04"), "c3 prk");
    check(zhkdf_sha256_expand(prk, NULL, 0, okm, sizeof okm) == 0,
          "c3 expand rc");
    check(eq_hex(okm, sizeof okm,
                 "8da4e775a563c18f715f802a063c5a31"
                 "b8a11f5c5ee1879ec3454e5f3c738d2d"
                 "9d201395faa4b61a96c8"), "c3 okm");
}

/* Empty-string salt (non-NULL, zero length) must behave as NULL salt. */
static void test_zero_salt_equiv(void)
{
    uint8_t ikm[22];
    uint8_t a[ZHKDF_SHA256_PRK_LEN], b[ZHKDF_SHA256_PRK_LEN];

    memset(ikm, 0x0b, sizeof ikm);
    check(zhkdf_sha256_extract(NULL, 0, ikm, sizeof ikm, a) == 0, "zs rc a");
    check(zhkdf_sha256_extract("", 0, ikm, sizeof ikm, b) == 0, "zs rc b");
    check(memcmp(a, b, sizeof a) == 0, "zs equal");
}

static void test_oneshot_matches_split(void)
{
    uint8_t ikm[22];
    uint8_t prk[ZHKDF_SHA256_PRK_LEN];
    uint8_t split[42], oneshot[42];

    memset(ikm, 0x0b, sizeof ikm);
    check(zhkdf_sha256_extract(NULL, 0, ikm, sizeof ikm, prk) == 0, "os ext");
    check(zhkdf_sha256_expand(prk, NULL, 0, split, sizeof split) == 0,
          "os exp");
    check(zhkdf_sha256(NULL, 0, ikm, sizeof ikm, NULL, 0,
                       oneshot, sizeof oneshot) == 0, "os one rc");
    check(memcmp(split, oneshot, sizeof split) == 0, "os equal");
}

static void test_max_len_and_errors(void)
{
    static uint8_t big[ZHKDF_SHA256_MAX_OKM_LEN];
    static uint8_t over[ZHKDF_SHA256_MAX_OKM_LEN + 1];
    uint8_t prk[ZHKDF_SHA256_PRK_LEN] = {0};
    uint8_t byte;

    check(zhkdf_sha256_expand(prk, NULL, 0, big, sizeof big) == 0,
          "max len ok");
    check(zhkdf_sha256_expand(prk, NULL, 0, over, sizeof over) == -1,
          "over max rejected");
    check(zhkdf_sha256_expand(prk, NULL, 0, &byte, 0) == -1,
          "zero len rejected");
    check(zhkdf_sha256_expand(NULL, NULL, 0, &byte, 1) == -1,
          "null prk rejected");
    check(zhkdf_sha256_expand(prk, NULL, 0, NULL, 1) == -1,
          "null okm rejected");
    check(zhkdf_sha256_extract(NULL, 0, NULL, 1, prk) == -1,
          "null ikm rejected");
}

int main(void)
{
    test_case1();
    test_case2();
    test_case3();
    test_zero_salt_equiv();
    test_oneshot_matches_split();
    test_max_len_and_errors();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zhkdf: all tests passed");
    return 0;
}
