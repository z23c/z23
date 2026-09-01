#include "zsha256/zsha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void hex_of(const uint8_t *d, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static void expect_sha(const void *msg, size_t len, const char *want_hex)
{
    uint8_t d[ZSHA256_DIGEST_LEN];
    char got[2 * ZSHA256_DIGEST_LEN + 1];
    zsha256(msg, len, d);
    hex_of(d, ZSHA256_DIGEST_LEN, got);
    if (strcmp(got, want_hex) != 0) {
        fprintf(stderr, "FAIL sha256 mismatch:\n  got  %s\n  want %s\n",
                got, want_hex);
        exit(1);
    }
    char hx[ZSHA256_HEX_LEN];
    zsha256_hex(msg, len, hx);
    CHECK(strcmp(hx, want_hex) == 0);
    CHECK(strlen(hx) == 64);
}

static void expect_hmac(const void *key, size_t klen,
                        const void *msg, size_t mlen,
                        const char *want_hex)
{
    uint8_t d[ZSHA256_DIGEST_LEN];
    char got[2 * ZSHA256_DIGEST_LEN + 1];
    zsha256_hmac(key, klen, msg, mlen, d);
    hex_of(d, ZSHA256_DIGEST_LEN, got);
    if (strcmp(got, want_hex) != 0) {
        fprintf(stderr, "FAIL hmac mismatch:\n  got  %s\n  want %s\n",
                got, want_hex);
        exit(1);
    }
}

static void test_sha_vectors(void)
{
    /* FIPS 180-4 / well-known vectors. */
    expect_sha("", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_sha("abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect_sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* One million 'a' (FIPS 180-4 example). */
    {
        char *big = malloc(1000000);
        CHECK(big != NULL);
        memset(big, 'a', 1000000);
        expect_sha(big, 1000000,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        free(big);
    }

    /* Padding-edge lengths, cross-checked against Python hashlib. */
    {
        char m[120];
        memset(m, 'x', sizeof m);
        expect_sha(m, 55,
            "d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072");
        expect_sha(m, 56,
            "04c26261370ee7541549d16dee320c723e3fd14671e66a099afe0a377c16888e");
        expect_sha(m, 64,
            "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c");
        expect_sha(m, 119,
            "000b48d4edf0fa7bee3c6236ecd2785baa5db4eeb8bb54341b029e0d9fa5fb0c");
        expect_sha(m, 120,
            "13f05a0b594787f5ecd315edc96141bd3243203d1b7d4f0836f37308b276ba98");
    }
}

static void test_hmac_vectors(void)
{
    /* RFC 4231 test cases 1, 2, 3. */
    uint8_t key20[20], dd50[50];
    memset(key20, 0x0b, sizeof key20);
    memset(dd50, 0xdd, sizeof dd50);
    expect_hmac(key20, 20, "Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    expect_hmac("Jefe", 4, "what do ya want for nothing?", 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    memset(key20, 0xaa, sizeof key20);
    expect_hmac(key20, 20, dd50, 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* Key longer than the block size (hashed down first). */
    {
        char k[100];
        memset(k, 'k', sizeof k);
        expect_hmac(k, 100, "data", 4,
            "09380ee4b802da2363bc96e8e0d133ba275458ea8ddbc564f986fc12b31f8cb1");
    }
    /* Empty key and message. */
    expect_hmac(NULL, 0, NULL, 0,
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

static void test_incremental(void)
{
    /* Split updates must match the one-shot result, at every split. */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t len = strlen(msg);
    uint8_t want[ZSHA256_DIGEST_LEN];
    zsha256(msg, len, want);

    for (size_t split = 0; split <= len; split++) {
        zsha256_ctx ctx;
        uint8_t got[ZSHA256_DIGEST_LEN];
        zsha256_init(&ctx);
        zsha256_update(&ctx, msg, split);
        zsha256_update(&ctx, msg + split, len - split);
        zsha256_final(&ctx, got);
        CHECK(zsha256_compare(want, got) == 0);
    }

    /* Byte-at-a-time. */
    {
        zsha256_ctx ctx;
        uint8_t got[ZSHA256_DIGEST_LEN];
        zsha256_init(&ctx);
        for (size_t i = 0; i < len; i++)
            zsha256_update(&ctx, msg + i, 1);
        zsha256_final(&ctx, got);
        CHECK(zsha256_compare(want, got) == 0);
    }

    /* HMAC incremental, all splits. */
    {
        uint8_t hwant[ZSHA256_DIGEST_LEN];
        zsha256_hmac("key", 3, msg, len, hwant);
        for (size_t split = 0; split <= len; split++) {
            zsha256_hmac_ctx hctx;
            uint8_t got[ZSHA256_DIGEST_LEN];
            zsha256_hmac_init(&hctx, "key", 3);
            zsha256_hmac_update(&hctx, msg, split);
            zsha256_hmac_update(&hctx, msg + split, len - split);
            zsha256_hmac_final(&hctx, got);
            CHECK(zsha256_compare(hwant, got) == 0);
        }
    }
}

static void test_compare_and_robustness(void)
{
    uint8_t a[ZSHA256_DIGEST_LEN], b[ZSHA256_DIGEST_LEN];
    zsha256("x", 1, a);
    zsha256("x", 1, b);
    CHECK(zsha256_compare(a, b) == 0);
    b[31] ^= 0x01;
    CHECK(zsha256_compare(a, b) != 0);
    CHECK(zsha256_compare(NULL, NULL) == 0);
    CHECK(zsha256_compare(a, NULL) != 0);

    /* NULL-tolerant entry points. */
    zsha256_update(NULL, "x", 1);            /* no ctx: no-op */
    zsha256_ctx ctx;
    zsha256_init(&ctx);
    zsha256_update(&ctx, NULL, 0);           /* zero len: fine */
    zsha256_update(&ctx, NULL, 5);           /* NULL data: no-op */
    uint8_t d[ZSHA256_DIGEST_LEN];
    zsha256_final(&ctx, d);
    expect_sha("", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    zsha256_init(NULL);                      /* no crash */
    zsha256_final(NULL, d);                  /* no crash */
    zsha256_hmac_init(NULL, "k", 1);         /* no crash */
    zsha256_hmac_update(NULL, "x", 1);       /* no crash */
    zsha256_hmac_final(NULL, d);             /* no crash */
}

static uint64_t rng_state = 0x6a09e667f3bcc908ull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_randomized_consistency(void)
{
    /* Random buffers: incremental (random chunking) equals one-shot,
     * and hashing twice is stable. */
    for (int iter = 0; iter < 200; iter++) {
        size_t len = (size_t)(rng_next() % 1025u);
        uint8_t buf[1024];
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rng_next();

        uint8_t a[ZSHA256_DIGEST_LEN], b[ZSHA256_DIGEST_LEN];
        zsha256(buf, len, a);
        zsha256(buf, len, b);
        CHECK(zsha256_compare(a, b) == 0);

        zsha256_ctx ctx;
        uint8_t c[ZSHA256_DIGEST_LEN];
        zsha256_init(&ctx);
        size_t off = 0;
        while (off < len) {
            size_t chunk = (size_t)(rng_next() % 70u) + 1;
            if (chunk > len - off) chunk = len - off;
            zsha256_update(&ctx, buf + off, chunk);
            off += chunk;
        }
        zsha256_final(&ctx, c);
        CHECK(zsha256_compare(a, c) == 0);
    }
}

int main(void)
{
    test_sha_vectors();
    test_hmac_vectors();
    test_incremental();
    test_compare_and_robustness();
    test_randomized_consistency();
    puts("test_zsha256: all groups passed (vectors hmac incremental compare fuzz)");
    return 0;
}
