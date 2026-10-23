/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Crypto hash tests: SHA-256, SHA-512, SHA-1, RIPEMD-160, HMAC-SHA256,
 * BLAKE2b, Hash256, Hash160, X25519 (RFC 7748). */

#include "test/test_core.h"
#include "crypto/sha1.h"
#include "crypto/hmac_sha256.h"
#include "crypto/pbkdf2_sha256.h"
#include "crypto/blake2b.h"
#include "core/hash.h"
#include "crypto/ed25519.h"
#include "crypto/curve25519.h"
#include "crypto/x25519_safe.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

/* X25519 vectors. Every hex string is copied verbatim from the published
 * source named beside it; none is recalled. */
struct x25519_vector {
    const char *scalar;
    const char *u;
    const char *out;
};

/* RFC 7748 Section 5.2, scalar multiplication test vectors 1 and 2. */
static const struct x25519_vector k_rfc7748_vectors[] = {
    {
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    },
    {
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    },
};

/* RFC 7748 Section 6.1: Alice and Bob keys and the shared secret K. */
static const char k_dh_alice_priv[] =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char k_dh_alice_pub[] =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char k_dh_bob_priv[] =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char k_dh_bob_pub[] =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char k_dh_shared[] =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/* Low-order u-coordinates: the 7-entry blocklist of libsodium
 * src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
 * (has_small_order). Covers orders 1, 2, 4 and 8 and the non-canonical
 * encodings p-1, p and p+1 for p = 2^255-19. The two order-8 entries were
 * cross-checked against their decimal values in the same comments. */
static const char *const k_x25519_small_order_u[] = {
    "0000000000000000000000000000000000000000000000000000000000000000", /* 0, order 4 */
    "0100000000000000000000000000000000000000000000000000000000000000", /* 1, order 1 */
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", /* order 8 */
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", /* order 8 */
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p-1, order 2 */
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p, non-canonical 0 */
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p+1, non-canonical 1 */
};

static bool x25519_bytes_zero(const uint8_t *b, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= b[i];
    return acc == 0;
}

/* RFC 7748 Section 5.2: each vector through curve25519_scalarmult and
 * x25519_safe (the two agree on a non-zero, contributory result). */
static int x25519_check_rfc7748_vectors(void)
{
    int failures = 0;
    uint8_t scalar[32], u[32], got[32];
    for (size_t i = 0; i < sizeof k_rfc7748_vectors / sizeof k_rfc7748_vectors[0]; i++) {
        const struct x25519_vector *v = &k_rfc7748_vectors[i];
        test_hex_to_bytes(v->scalar, scalar, 32);
        test_hex_to_bytes(v->u, u, 32);
        printf("X25519 RFC 7748 Section 5.2 vector %zu (scalarmult)... ", i + 1);
        if (!curve25519_scalarmult(got, scalar, u)) {
            printf("FAIL (scalarmult returned false)\n");
            failures++;
            continue;
        }
        failures += check_hex(got, 32, v->out);
        printf("X25519 RFC 7748 Section 5.2 vector %zu (x25519_safe)... ", i + 1);
        if (!x25519_safe(got, scalar, u)) {
            printf("FAIL (x25519_safe rejected a usable point)\n");
            failures++;
            continue;
        }
        failures += check_hex(got, 32, v->out);
    }
    return failures;
}

/* RFC 7748 Section 5.2 iterated test: starting from k = u = 9, each step is
 * (k, u) = (X25519(k, u), k). Checked after 1 and after 1,000 iterations. */
static int x25519_check_iterated(void)
{
    static const struct {
        int iters;
        const char *want;
    } rows[] = {
        /* RFC 7748 Section 5.2, after one iteration. */
        { 1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" },
        /* RFC 7748 Section 5.2, after 1,000 iterations. */
        { 1000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51" },
    };
    int failures = 0;
    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++) {
        uint8_t k[32] = {9}, u[32] = {9}, next[32];
        bool ok = true;
        for (int i = 0; ok && i < rows[r].iters; i++) {
            ok = curve25519_scalarmult(next, k, u);
            memcpy(u, k, 32);
            memcpy(k, next, 32);
        }
        printf("X25519 RFC 7748 Section 5.2 iterated, %d iteration(s)... ", rows[r].iters);
        if (!ok) {
            printf("FAIL (scalarmult returned false)\n");
            failures++;
            continue;
        }
        failures += check_hex(k, 32, rows[r].want);
    }
    return failures;
}

/* RFC 7748 Section 6.1: public keys are X25519(priv, 9); both sides derive K. */
static int x25519_check_dh_keys(uint8_t a[32], uint8_t b[32], uint8_t pa[32], uint8_t pb[32])
{
    int failures = 0;
    test_hex_to_bytes(k_dh_alice_priv, a, 32);
    test_hex_to_bytes(k_dh_bob_priv, b, 32);
    printf("X25519 RFC 7748 Section 6.1 Alice public key... ");
    if (!curve25519_scalarmult_base(pa, a)) failures++;
    failures += check_hex(pa, 32, k_dh_alice_pub);
    printf("X25519 RFC 7748 Section 6.1 Bob public key... ");
    if (!curve25519_scalarmult_base(pb, b)) failures++;
    failures += check_hex(pb, 32, k_dh_bob_pub);
    return failures;
}

static int x25519_check_dh_example(void)
{
    uint8_t a[32], b[32], pa[32], pb[32], shared[32];
    int failures = x25519_check_dh_keys(a, b, pa, pb);

    printf("X25519 RFC 7748 Section 6.1 shared secret (Alice side)... ");
    if (!x25519_safe(shared, a, pb)) failures++;
    failures += check_hex(shared, 32, k_dh_shared);

    printf("X25519 RFC 7748 Section 6.1 shared secret (Bob side)... ");
    if (!x25519_safe(shared, b, pa)) failures++;
    failures += check_hex(shared, 32, k_dh_shared);
    return failures;
}

/* One low-order u-coordinate: x25519_safe must refuse it and zeroize its
 * output. The raw curve25519_scalarmult returns true (it documents no
 * low-order rejection) and yields the all-zero secret that the guard catches. */
static int x25519_check_small_order_one(const char *u_hex, size_t index)
{
    uint8_t scalar[32], u[32], raw[32], safe[32];
    test_hex_to_bytes(k_dh_alice_priv, scalar, 32);
    test_hex_to_bytes(u_hex, u, 32);
    printf("X25519 small-order u[%zu] raw scalarmult... ", index);
    bool raw_ok = curve25519_scalarmult(raw, scalar, u);
    if (!raw_ok || !x25519_bytes_zero(raw, 32)) {
        printf("FAIL (raw result %s, zero=%d)\n", raw_ok ? "true" : "false",
               x25519_bytes_zero(raw, 32));
        return 1;
    }
    printf("OK\n");
    printf("X25519 small-order u[%zu] refused by x25519_safe... ", index);
    memset(safe, 0xa5, sizeof safe);
    if (x25519_safe(safe, scalar, u) || !x25519_bytes_zero(safe, 32)) {
        printf("FAIL (accepted or left non-zero output)\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int x25519_check_all_small_order(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof k_x25519_small_order_u / sizeof k_x25519_small_order_u[0]; i++)
        failures += x25519_check_small_order_one(k_x25519_small_order_u[i], i);
    return failures;
}

int test_crypto(void)
{
    int failures = 0;
    unsigned char hash[64];

    printf("SHA-256(\"\")... ");
    struct sha256_ctx sha256;
    sha256_init(&sha256);
    sha256_finalize(&sha256, hash);
    failures += check_hex(hash, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    printf("SHA-256(\"abc\")... ");
    sha256_init(&sha256);
    sha256_write(&sha256, (const unsigned char *)"abc", 3);
    sha256_finalize(&sha256, hash);
    failures += check_hex(hash, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    printf("SHA-512(\"\")... ");
    struct sha512_ctx sha512;
    sha512_init(&sha512);
    sha512_finalize(&sha512, hash);
    failures += check_hex(hash, 64, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    printf("SHA-512(\"abc\")... ");
    sha512_init(&sha512);
    sha512_write(&sha512, (const unsigned char *)"abc", 3);
    sha512_finalize(&sha512, hash);
    failures += check_hex(hash, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    printf("SHA-1(\"abc\")... ");
    struct sha1_ctx sha1;
    sha1_init(&sha1);
    sha1_write(&sha1, (const unsigned char *)"abc", 3);
    sha1_finalize(&sha1, hash);
    failures += check_hex(hash, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");

    printf("RIPEMD-160(\"abc\")... ");
    struct ripemd160_ctx rmd;
    ripemd160_init(&rmd);
    ripemd160_write(&rmd, (const unsigned char *)"abc", 3);
    ripemd160_finalize(&rmd, hash);
    failures += check_hex(hash, 20, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

    printf("HMAC-SHA256(\"\",\"\")... ");
    struct hmac_sha256_ctx hmac256;
    hmac_sha256_init(&hmac256, (const unsigned char *)"", 0);
    hmac_sha256_finalize(&hmac256, hash);
    failures += check_hex(hash, 32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");

    printf("BLAKE2b-256(\"\")... ");
    blake2b(hash, 32, NULL, 0, NULL, 0);
    failures += check_hex(hash, 32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");

    printf("BLAKE2b-256(\"abc\")... ");
    blake2b(hash, 32, "abc", 3, NULL, 0);
    failures += check_hex(hash, 32, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");

    printf("Hash256(\"\")... ");
    hash256(NULL, 0, hash);
    failures += check_hex(hash, 32, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

    printf("Hash160(\"\")... ");
    hash160(NULL, 0, hash);
    failures += check_hex(hash, 20, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");

    printf("SHA-256 self-test (%s)... ", sha256_implementation());
    if (sha256_selftest()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* Stress test: SHA-256 1MB of data — verify both paths agree */
    printf("SHA-256 1MB stress test... ");
    {
        unsigned char *big = zcl_malloc(1024 * 1024, "test_hash_buf");
        for (int i = 0; i < 1024 * 1024; i++)
            big[i] = (unsigned char)(i * 137 + 73);

        unsigned char h1[32], h2[32];

        struct sha256_ctx c1;
        sha256_init(&c1);
        sha256_write(&c1, big, 1024 * 1024);
        sha256_finalize(&c1, h1);

        /* Second pass — must match */
        struct sha256_ctx c2;
        sha256_init(&c2);
        sha256_write(&c2, big, 1024 * 1024);
        sha256_finalize(&c2, h2);

        free(big);

        if (memcmp(h1, h2, 32) == 0) printf("OK\n");
        else { printf("FAIL (non-deterministic)\n"); failures++; }
    }

    /* Ed25519 signature verification — RFC 8032 test vectors */
    printf("Ed25519 verify (RFC 8032 Test 1, empty msg)... ");
    {
        uint8_t pk[32], sig[64];
        test_hex_to_bytes("d75a980182b10ab7d54bfed3c964073a"
                          "0ee172f3daa62325af021a68f707511a", pk, 32);
        test_hex_to_bytes("e5564300c360ac729086e2cc806e828a"
                          "84877f1eb8e5d974d873e06522490155"
                          "5fb8821590a33bacc61e39701cf9b46b"
                          "d25bf5f0595bbe24655141438e7a100b", sig, 64);
        bool ok = ed25519_verify(sig, NULL, 0, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Ed25519 verify (RFC 8032 Test 2, msg=0x72)... ");
    {
        uint8_t pk[32], sig[64], msg[1] = {0x72};
        test_hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc"
                          "9c982ccf2ec4968cc0cd55f12af4660c", pk, 32);
        test_hex_to_bytes("92a009a9f0d4cab8720e820b5f642540"
                          "a2b27b5416503f8fb3762223ebdb69da"
                          "085ac1e43e15996e458f3613d0f11d8c"
                          "387b2eaeb4302aeeb00d291612bb0c00", sig, 64);
        bool ok = ed25519_verify(sig, msg, 1, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Ed25519 verify (msg=\"test\")... ");
    {
        uint8_t pk[32], sig[64];
        test_hex_to_bytes("3b6a27bcceb6a42d62a3a8d02a6f0d73"
                          "653215771de243a63ac048a18b59da29", pk, 32);
        test_hex_to_bytes("9653710561c3169b7a9577a01955169d"
                          "ef183fb3ae282e05bec624826e255b0c"
                          "3eede3ecfe054fb5a40efeaef040afaa"
                          "45220ccd7bf8413ba531f24f3f869209", sig, 64);
        bool ok = ed25519_verify(sig, (const uint8_t *)"test", 4, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Ed25519 verify rejects bad signature... ");
    {
        uint8_t pk[32], sig[64];
        test_hex_to_bytes("d75a980182b10ab7d54bfed3c964073a"
                          "0ee172f3daa62325af021a68f707511a", pk, 32);
        test_hex_to_bytes("e5564300c360ac729086e2cc806e828a"
                          "84877f1eb8e5d974d873e06522490155"
                          "5fb8821590a33bacc61e39701cf9b46b"
                          "d25bf5f0595bbe24655141438e7a100b", sig, 64);
        sig[0] ^= 1;
        bool ok = !ed25519_verify(sig, NULL, 0, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Ed25519 verify rejects null public key... ");
    {
        uint8_t pk[32] = {0};
        uint8_t sig[64] = {0};
        bool ok = !ed25519_verify(sig, NULL, 0, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* AGENT-3 non-canonical S (S >= L) must be rejected per
     * RFC 8032 §5.1.7 and Zcash consensus. Take a valid RFC 8032 vector
     * and overwrite S with the Ed25519 group order L itself — numerically
     * valid 32-byte LE but out of canonical range. Old code skipped this
     * and could split consensus with zcashd on malleable sigs. */
    printf("Ed25519 verify rejects non-canonical S >= L ... ");
    {
        uint8_t pk[32], sig[64];
        test_hex_to_bytes("d75a980182b10ab7d54bfed3c964073a"
                          "0ee172f3daa62325af021a68f707511a", pk, 32);
        test_hex_to_bytes("e5564300c360ac729086e2cc806e828a"
                          "84877f1eb8e5d974d873e06522490155"
                          "5fb8821590a33bacc61e39701cf9b46b"
                          "d25bf5f0595bbe24655141438e7a100b", sig, 64);

        /* Replace S (sig[32..63]) with L (group order, 32 LE bytes). */
        static const uint8_t L_LE[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        };
        memcpy(sig + 32, L_LE, 32);
        bool ok = !ed25519_verify(sig, NULL, 0, pk);
        if (ok) printf("OK\n");
        else { printf("FAIL (accepted S == L)\n"); failures++; }
    }

    /* PBKDF2-HMAC-SHA256 RFC 6070 test vectors. */
    printf("PBKDF2-HMAC-SHA256 RFC 6070 c=1 dkLen=32... ");
    {
        uint8_t dk[32];
        pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                            (const uint8_t *)"salt", 4,
                            1, dk, 32);
        failures += check_hex(dk, 32,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

    printf("PBKDF2-HMAC-SHA256 RFC 6070 c=2 dkLen=32... ");
    {
        uint8_t dk[32];
        pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                            (const uint8_t *)"salt", 4,
                            2, dk, 32);
        failures += check_hex(dk, 32,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    }

    printf("PBKDF2-HMAC-SHA256 RFC 6070 c=4096 dkLen=32... ");
    {
        uint8_t dk[32];
        pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                            (const uint8_t *)"salt", 4,
                            4096, dk, 32);
        failures += check_hex(dk, 32,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    printf("PBKDF2-HMAC-SHA256 RFC 6070 c=4096 dkLen=40 (multi-block)... ");
    {
        uint8_t dk[40];
        pbkdf2_hmac_sha256(
            (const uint8_t *)"passwordPASSWORDpassword", 24,
            (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
            4096, dk, 40);
        failures += check_hex(dk, 40,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
    }

    /* X25519 — RFC 7748 vectors, iterated test, Diffie-Hellman example,
     * and refusal of the low-order blocklist. */
    failures += x25519_check_rfc7748_vectors();
    failures += x25519_check_iterated();
    failures += x25519_check_dh_example();
    failures += x25519_check_all_small_order();

    /* Benchmark: SHA-256 throughput */
    printf("SHA-256 benchmark (%s)... ", sha256_implementation());
    {
        unsigned char block[64];
        memset(block, 0x42, 64);
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        int64_t t1 = platform_time_monotonic_us();
        int iters = 1000000;
        struct sha256_ctx bench;
        for (int i = 0; i < iters; i++) {
            sha256_init(&bench);
            sha256_write(&bench, block, 64);
            sha256_finalize(&bench, (unsigned char *)state);
        }
        int64_t t2 = platform_time_monotonic_us();
        double elapsed = (double)(t2 - t1) / 1e6;
        double mbs = (double)iters * 64.0 / elapsed / 1e6;
        printf("OK (%.0f MB/s, %d hashes in %.3fs)\n", mbs, iters, elapsed);
    }

    return failures;
}
