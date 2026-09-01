/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Known-answer tests for core/modules/crypto/src/hkdf_sha256.c against the RFC 5869
 * Appendix A SHA-256 vectors (cases 1, 2, 3), plus a structural check that the
 * two-output Noise HKDF2 helper equals Extract-then-Expand(64, info="") split
 * into halves. HKDF is a pure deterministic function, so every assertion pins
 * an exact byte output — any regression in extract, the T(i) chaining, or the
 * counter byte changes the OKM and fails the test. */

#include "test/test_core.h"
#include "crypto/hkdf_sha256.h"

/* Decode `hex` (2*n chars) into out[n]. Returns n. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = hex; p[0] && p[1] && n < cap; p += 2) {
        unsigned v; sscanf(p, "%2x", &v); out[n++] = (uint8_t)v;
    }
    return n;
}

/* Lowercase-hex-encode buf[n] and compare against expected. */
static bool okm_is(const uint8_t *buf, size_t n, const char *expected)
{
    char hex[512];
    for (size_t i = 0; i < n && i * 2 + 2 < sizeof(hex); i++)
        snprintf(hex + i * 2, 3, "%02x", buf[i]);
    return strcmp(hex, expected) == 0;
}

/* RFC 5869 Appendix A — the three SHA-256 test cases + the Noise HKDF2 helper. */
int test_hkdf_sha256_rfc5869(void)
{
    int failures = 0;

    TEST_CASE("hkdf-sha256 RFC 5869 A.1/A.2/A.3 + Noise HKDF2") {
        uint8_t ikm[128], salt[128], info[128], prk[32], okm[128];
        size_t il, sl, fl;

        /* ── A.1: basic ── */
        il = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof(ikm));
        sl = unhex("000102030405060708090a0b0c", salt, sizeof(salt));
        fl = unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
        hkdf_sha256_extract(salt, sl, ikm, il, prk);
        ASSERT(okm_is(prk, 32,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"));
        ASSERT(hkdf_sha256_expand(prk, info, fl, okm, 42));
        ASSERT(okm_is(okm, 42,
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"));
        /* one-shot must match the two-step */
        ASSERT(hkdf_sha256(salt, sl, ikm, il, info, fl, okm, 42));
        ASSERT(okm_is(okm, 42,
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"));

        /* ── A.2: longer inputs (multi-block expand) ── */
        for (int i = 0; i < 80; i++) ikm[i] = (uint8_t)i;              /* 0x00..0x4f */
        for (int i = 0; i < 80; i++) salt[i] = (uint8_t)(0x60 + i);    /* 0x60..0xaf */
        for (int i = 0; i < 80; i++) info[i] = (uint8_t)(0xb0 + i);    /* 0xb0..0xff */
        hkdf_sha256_extract(salt, 80, ikm, 80, prk);
        ASSERT(okm_is(prk, 32,
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244"));
        ASSERT(hkdf_sha256_expand(prk, info, 80, okm, 82));
        ASSERT(okm_is(okm, 82,
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"));

        /* ── A.3: zero-length salt and info ── */
        il = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof(ikm));
        hkdf_sha256_extract(NULL, 0, ikm, il, prk);
        ASSERT(okm_is(prk, 32,
            "19ef24a32c717b167f33a91d6f648bdf"
            "96596776afdb6377ac434c1c293ccb04"));
        ASSERT(hkdf_sha256_expand(prk, NULL, 0, okm, 42));
        ASSERT(okm_is(okm, 42,
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"));

        /* ── Noise HKDF2 == Expand(Extract(salt,ikm), "")[0..64] split ── */
        uint8_t o1[32], o2[32], full[64];
        uint8_t nsalt[32]; memset(nsalt, 0x42, sizeof(nsalt));
        uint8_t nikm[32];  memset(nikm, 0x17, sizeof(nikm));
        hkdf_sha256_2(nsalt, sizeof(nsalt), nikm, sizeof(nikm), o1, o2);
        hkdf_sha256_extract(nsalt, sizeof(nsalt), nikm, sizeof(nikm), prk);
        ASSERT(hkdf_sha256_expand(prk, NULL, 0, full, 64));
        ASSERT(memcmp(o1, full, 32) == 0);
        ASSERT(memcmp(o2, full + 32, 32) == 0);
        /* empty-ikm variant (Split path) must also be well-defined + stable */
        uint8_t s1[32], s2[32], s1b[32], s2b[32];
        hkdf_sha256_2(nsalt, sizeof(nsalt), NULL, 0, s1, s2);
        hkdf_sha256_2(nsalt, sizeof(nsalt), NULL, 0, s1b, s2b);
        ASSERT(memcmp(s1, s1b, 32) == 0 && memcmp(s2, s2b, 32) == 0);
        ASSERT(memcmp(s1, s2, 32) != 0);
    } TEST_END

    return failures;
}
