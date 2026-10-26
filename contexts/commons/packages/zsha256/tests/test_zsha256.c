#include "zsha256/zsha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *cli_source, *cli_sink;
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define main zsha256_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef stdout
#undef stdin

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

static void test_empty_updates_and_failure_state(void)
{
    const size_t lengths[] = {0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129};
    const size_t key_lengths[] = {0, 1, 63, 64, 65, 128};
    uint8_t data[129], key[128];
    memset(data, 'x', sizeof data);
    memset(key, 'k', sizeof key);
    for (size_t n = 0; n < sizeof lengths / sizeof lengths[0]; ++n) {
        size_t len = lengths[n];
        uint8_t want[ZSHA256_DIGEST_LEN], got[ZSHA256_DIGEST_LEN];
        zsha256(data, len, want);
        for (size_t split = 0; split <= len; ++split) {
            zsha256_ctx ctx = {0};
            unsigned char saved[sizeof ctx];
            zsha256_init(&ctx);
            zsha256_update(&ctx, data, split);
            memcpy(saved, &ctx, sizeof ctx);
            zsha256_update(&ctx, NULL, 0);
            zsha256_update(&ctx, data, 0);
            CHECK(memcmp(saved, &ctx, sizeof ctx) == 0);
            zsha256_update(&ctx, NULL, 1);
            zsha256_update(&ctx, NULL, SIZE_MAX);
            zsha256_final(&ctx, NULL);
            CHECK(memcmp(saved, &ctx, sizeof ctx) == 0);
            zsha256_update(&ctx, data + split, len - split);
            zsha256_update(&ctx, NULL, 0);
            zsha256_final(&ctx, got);
            CHECK(memcmp(want, got, sizeof got) == 0);
        }
        for (size_t k = 0; k < sizeof key_lengths / sizeof key_lengths[0]; ++k) {
            zsha256_hmac(key, key_lengths[k], data, len, want);
            for (size_t split = 0; split <= len; ++split) {
                zsha256_hmac_ctx ctx = {0};
                unsigned char saved[sizeof ctx];
                zsha256_hmac_init(&ctx, key, key_lengths[k]);
                zsha256_hmac_update(&ctx, data, split);
                memcpy(saved, &ctx, sizeof ctx);
                zsha256_hmac_update(&ctx, NULL, 0);
                zsha256_hmac_update(&ctx, NULL, SIZE_MAX);
                zsha256_hmac_final(&ctx, NULL);
                CHECK(memcmp(saved, &ctx, sizeof ctx) == 0);
                zsha256_hmac_update(&ctx, data + split, len - split);
                zsha256_hmac_update(&ctx, NULL, 0);
                zsha256_hmac_final(&ctx, got);
                CHECK(memcmp(want, got, sizeof got) == 0);
            }
        }
    }
}

static int cli_check(bool hmac, bool dash, FILE *output, int status)
{
    FILE *source = tmpfile();
    if (!source) return 1;
    if (fputs("abc", source) < 0 || fflush(source) != 0) {
        fclose(source);
        return 1;
    }
    rewind(source);
    cli_source = source;
    cli_sink = output;
    char *hash_args[] = {"zsha256", "-", NULL};
    char *hmac_args[] = {"zsha256", "--hmac", "key", "-", NULL};
    int rc = zsha256_cli_main((hmac ? 3 : 1) + (dash ? 1 : 0),
                              hmac ? hmac_args : hash_args);
    return fclose(source) != 0 || rc != status;
}

static void test_cli_output(void)
{
    const char *digests[] = {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab"};
    for (int hmac = 0; hmac < 2; hmac++) {
        for (int dash = 0; dash < 2; dash++) {
            FILE *output = tmpfile();
            CHECK(output != NULL);
            CHECK(cli_check(hmac, dash, output, 0) == 0);
            rewind(output);
            char got[80], want[80];
            snprintf(want, sizeof want, "%s  -\n", digests[hmac]);
            CHECK(fgets(got, sizeof got, output) != NULL);
            CHECK(strcmp(got, want) == 0 && fgetc(output) == EOF);
            CHECK(fclose(output) == 0);
#if defined(_WIN32)
            output = fopen("NUL", "r");
#else
            output = fopen("/dev/null", "r");
#endif
            CHECK(output != NULL);
            CHECK(cli_check(hmac, dash, output, 1) == 0);
            CHECK(fclose(output) == 0);
#if defined(__linux__)
            output = fopen("/dev/full", "w");
            CHECK(output != NULL);
            char buffer[4096];
            CHECK(setvbuf(output, buffer, _IOFBF, sizeof buffer) == 0);
            CHECK(cli_check(hmac, dash, output, 1) == 0);
            (void)fclose(output);
#endif
        }
    }
}

static void test_cli_files(void)
{
#if defined(_WIN32)
    char *path = "NUL";
#else
    char *path = "/dev/null";
#endif
    for (int hmac = 0; hmac < 2; hmac++) {
        char *hash_args[] = {"zsha256", path, path, NULL};
        char *hmac_args[] = {"zsha256", "--hmac", "key", path, path, NULL};
        uint8_t digest[ZSHA256_DIGEST_LEN];
        if (hmac) zsha256_hmac("key", 3, "", 0, digest);
        else zsha256("", 0, digest);
        char hex[65], want[160], got[160];
        hex_of(digest, sizeof digest, hex);
        snprintf(want, sizeof want, "%s  %s\n", hex, path);
        for (int count = 1; count <= 2; count++) {
            cli_sink = tmpfile();
            CHECK(cli_sink != NULL);
            CHECK(zsha256_cli_main((hmac ? 3 : 1) + count,
                                  hmac ? hmac_args : hash_args) == 0);
            rewind(cli_sink);
            for (int i = 0; i < count; i++) {
                CHECK(fgets(got, sizeof got, cli_sink) != NULL);
                CHECK(strcmp(got, want) == 0);
            }
            CHECK(fgetc(cli_sink) == EOF);
            CHECK(fclose(cli_sink) == 0);
            cli_sink = fopen(path, "r");
            CHECK(cli_sink != NULL);
            CHECK(zsha256_cli_main((hmac ? 3 : 1) + count,
                                  hmac ? hmac_args : hash_args) == 1);
            CHECK(fclose(cli_sink) == 0);
        }
    }
}

int main(void)
{
    test_cli_output();
    test_cli_files();
    test_sha_vectors();
    test_hmac_vectors();
    test_incremental();
    test_empty_updates_and_failure_state();
    test_compare_and_robustness();
    test_randomized_consistency();
    puts("test_zsha256: all groups passed (vectors hmac incremental compare fuzz)");
    return 0;
}
