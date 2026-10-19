/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "sha3/shake_wrap.h"
#include "crypto/sha256.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

struct wrap_vector { unsigned mode; size_t index, ad_len, plaintext_len; const char *digest; };
#include "test_shake_wrap_vectors.h"
static void wrap_test_key(uint8_t key[SHAKE_WRAP_KEY_SIZE])
{
    for (size_t i = 0; i < SHAKE_WRAP_KEY_SIZE; ++i) key[i] = (uint8_t)i;
}
static bool wrap_vector_record(const struct wrap_vector *vector,
    struct shake_wrap_state *sender, struct shake_wrap_state *receiver)
{
    uint8_t ad[4096], plaintext[4096], ciphertext[4160], output[4096], sentinel[4096];
    for (size_t i = 0; i < sizeof(ad); ++i) {
        ad[i] = (uint8_t)(i * 7 + vector->index + 1);
        plaintext[i] = (uint8_t)(i * 13 + vector->index + 3);
    }
    if (!shake_wrap_seal(sender, ad, vector->ad_len, plaintext, vector->plaintext_len,
        ciphertext, sizeof(ciphertext))) return false;
    struct sha256_ctx digest;
    uint8_t bytes[32]; char hex[65];
    sha256_init(&digest);
    sha256_write(&digest, ciphertext, vector->plaintext_len + SHAKE_WRAP_TAG_SIZE);
    sha256_finalize(&digest, bytes); zcl_hex_encode(bytes, sizeof(bytes), hex);
    if (strcmp(hex, vector->digest)) {
        fprintf(stderr, "Wrap oracle mismatch mode=%u index=%zu AD=%zu P=%zu actual=%s\n",
            vector->mode, vector->index, vector->ad_len, vector->plaintext_len, hex);
        return false;
    }
    struct shake_wrap_state before = *receiver;
    memset(output, 0xa5, sizeof(output)); memcpy(sentinel, output, sizeof(output));
    ciphertext[vector->plaintext_len + SHAKE_WRAP_TAG_SIZE - 1] ^= 1;
    bool rejected = !shake_wrap_open(receiver, ad, vector->ad_len, ciphertext,
        vector->plaintext_len + SHAKE_WRAP_TAG_SIZE, output, sizeof(output));
    if (!rejected || memcmp(receiver, &before, sizeof(before)) ||
        memcmp(output, sentinel, sizeof(output))) return false;
    ciphertext[vector->plaintext_len + SHAKE_WRAP_TAG_SIZE - 1] ^= 1;
    if (!shake_wrap_open(receiver, ad, vector->ad_len, ciphertext,
        vector->plaintext_len + SHAKE_WRAP_TAG_SIZE, output, sizeof(output))) return false;
    return !memcmp(output, plaintext, vector->plaintext_len) && !memcmp(sender, receiver, sizeof(*sender));
}
static int wrap_oracle_vectors(void)
{
    int failures = 0;
    uint8_t key[SHAKE_WRAP_KEY_SIZE]; wrap_test_key(key);
    struct shake_wrap_state sender = {0}, receiver = {0};
    TEST_CASE("SHAKE256-Wrap: independent 392 fresh and chained oracle records with authenticated continuation") {
        ASSERT_EQ(sizeof(wrap_vectors) / sizeof(wrap_vectors[0]), 392);
        for (size_t i = 0; i < sizeof(wrap_vectors) / sizeof(wrap_vectors[0]); ++i) {
            const struct wrap_vector *vector = &wrap_vectors[i];
            if (!vector->mode || !vector->index) {
                ASSERT(shake_wrap_init(&sender, key));
                ASSERT(shake_wrap_init(&receiver, key));
            }
            ASSERT(wrap_vector_record(vector, &sender, &receiver));
        }
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver);
    return failures;
}
/* Snapshot complete state/output, not merely an ok flag or plaintext prefix. */
static bool wrap_refuses_unchanged(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t length)
{
    struct shake_wrap_state before = *state;
    uint8_t output[4096], sentinel[4096];
    memset(output, 0x6d, sizeof(output)); memcpy(sentinel, output, sizeof(output));
    bool ok = shake_wrap_open(state, ad, ad_len, ciphertext, length, output, sizeof(output));
    return !ok && !memcmp(state, &before, sizeof(before)) && !memcmp(output, sentinel, sizeof(output));
}
static int wrap_authentication_refusals(void)
{
    int failures = 0;
    uint8_t key[32], ad[129], plaintext[257], ciphertext[321];
    wrap_test_key(key); memset(ad, 0x17, sizeof(ad)); memset(plaintext, 0x29, sizeof(plaintext));
    struct shake_wrap_state sender = {0}, receiver = {0}, wrong_key = {0};
    TEST_CASE("SHAKE256-Wrap: key, AD, ciphertext, every tag byte and record geometry refuse before release") {
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&receiver, key));
        ASSERT(shake_wrap_seal(&sender, ad, sizeof(ad), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext)));
        key[0] ^= 1; ASSERT(shake_wrap_init(&wrong_key, key));
        ASSERT(wrap_refuses_unchanged(&wrong_key, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
        ad[128] ^= 1; ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext))); ad[128] ^= 1;
        ciphertext[128] ^= 1; ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext))); ciphertext[128] ^= 1;
        for (size_t i = sizeof(plaintext); i < sizeof(ciphertext); ++i) {
            ciphertext[i] ^= 1;
            ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
            ciphertext[i] ^= 1;
        }
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad) - 1, ciphertext, sizeof(ciphertext)));
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext) - 1));
        uint8_t output[257];
        ASSERT(shake_wrap_open(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext), output, sizeof(output)));
        ASSERT(!memcmp(output, plaintext, sizeof(output)));
        /* A record cannot authenticate again in the advanced chaining state. */
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver); shake_wrap_destroy(&wrong_key);
    return failures;
}
struct wrap_invalid_case { const uint8_t *ad; size_t ad_len; const uint8_t *input; size_t input_len; uint8_t *output; size_t capacity; };
static int wrap_seal_bounds(void)
{
    int failures = 0;
    uint8_t key[32], input[4097], ad[4097], output[4160];
    wrap_test_key(key); memset(input, 0x21, sizeof(input)); memset(ad, 0x43, sizeof(ad)); memset(output, 0x65, sizeof(output));
    struct shake_wrap_state state = {0};
    TEST_CASE("SHAKE256-Wrap: seal bounds, NULLs and every storage overlap preserve all caller bytes") {
        ASSERT(shake_wrap_init(&state, key));
        struct shake_wrap_state before = state;
        const struct wrap_invalid_case cases[] = {
            {ad, 1, input, 4097, output, sizeof(output)}, {ad, 4097, input, 1, output, sizeof(output)},
            {NULL, 1, input, 1, output, sizeof(output)}, {ad, 1, NULL, 1, output, sizeof(output)},
            {ad, 1, input, 1, NULL, 65}, {ad, 1, input, 1, output, 64},
            {ad, 1, input, 1, output, SIZE_MAX}, {ad, 1, input, 1, input, sizeof(input)},
            {ad, 1, input, 1, ad, sizeof(ad)}, {input, 1, input, 1, output, sizeof(output)},
            {state.bytes, 1, input, 1, output, sizeof(output)}, {ad, 1, state.bytes, 1, output, sizeof(output)},
            {ad, 1, input, 1, state.bytes, sizeof(state.bytes)},
        };
        uint8_t saved_input[4097], saved_ad[4097], saved_output[4160];
        memcpy(saved_input, input, sizeof(input)); memcpy(saved_ad, ad, sizeof(ad)); memcpy(saved_output, output, sizeof(output));
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const struct wrap_invalid_case *c = &cases[i];
            ASSERT(!shake_wrap_seal(&state, c->ad, c->ad_len, c->input, c->input_len, c->output, c->capacity));
            ASSERT(!memcmp(&state, &before, sizeof(state)));
            ASSERT(!memcmp(input, saved_input, sizeof(input))); ASSERT(!memcmp(ad, saved_ad, sizeof(ad)));
            ASSERT(!memcmp(output, saved_output, sizeof(output)));
        }
        ASSERT(!shake_wrap_init(&state, state.bytes)); ASSERT(!memcmp(&state, &before, sizeof(state)));
        ASSERT(!shake_wrap_init(&state, NULL)); ASSERT(!memcmp(&state, &before, sizeof(state)));
        ASSERT(!shake_wrap_init(NULL, key));
        uint8_t shared[256], saved_shared[256];
        memset(shared, 0x87, sizeof(shared)); memcpy(saved_shared, shared, sizeof(shared));
        /* Written output would end at 65; the capacity overlaps AD at 160. */
        ASSERT(!shake_wrap_seal(&state, shared + 160, 1, input, 1, shared, 192));
        ASSERT(!memcmp(shared, saved_shared, sizeof(shared)));
        ASSERT(!memcmp(&state, &before, sizeof(state)));
    } TEST_END
    shake_wrap_destroy(&state);
    return failures;
}
static int wrap_open_bounds(void)
{
    int failures = 0;
    uint8_t key[32], plaintext[128], ad[128], ciphertext[192], output[128];
    wrap_test_key(key); memset(plaintext, 0x21, sizeof(plaintext)); memset(ad, 0x43, sizeof(ad)); memset(output, 0x65, sizeof(output));
    struct shake_wrap_state sender = {0}, state = {0};
    TEST_CASE("SHAKE256-Wrap: open bounds and aliases refuse without changing ciphertext, AD, output or state") {
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&state, key));
        ASSERT(shake_wrap_seal(&sender, ad, sizeof(ad), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext)));
        const struct wrap_invalid_case cases[] = {
            {ad, sizeof(ad), ciphertext, 63, output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, 4161, output, sizeof(output)},
            {ad, 4097, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {NULL, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), NULL, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), NULL, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), output, sizeof(output) - 1},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), ciphertext, sizeof(ciphertext)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), ad, sizeof(ad)},
            {ciphertext, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {state.bytes, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), state.bytes, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), state.bytes, sizeof(state.bytes)},
        };
        struct shake_wrap_state before = state;
        uint8_t saved_c[192], saved_ad[128], saved_output[128];
        memcpy(saved_c, ciphertext, sizeof(ciphertext)); memcpy(saved_ad, ad, sizeof(ad)); memcpy(saved_output, output, sizeof(output));
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const struct wrap_invalid_case *c = &cases[i];
            ASSERT(!shake_wrap_open(&state, c->ad, c->ad_len, c->input, c->input_len, c->output, c->capacity));
            ASSERT(!memcmp(&state, &before, sizeof(state))); ASSERT(!memcmp(ciphertext, saved_c, sizeof(ciphertext)));
            ASSERT(!memcmp(ad, saved_ad, sizeof(ad))); ASSERT(!memcmp(output, saved_output, sizeof(output)));
        }
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&state);
    return failures;
}
static int wrap_empty_and_destroy(void)
{
    int failures = 0;
    uint8_t key[32], ciphertext[64]; wrap_test_key(key);
    struct shake_wrap_state sender = {0}, receiver = {0}, zero = {0};
    TEST_CASE("SHAKE256-Wrap: explicit empty spans authenticate and destroy wipes the complete state") {
        ASSERT(!shake_wrap_seal(&sender, NULL, 0, NULL, 0, ciphertext, sizeof(ciphertext)));
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&receiver, key));
        ASSERT(shake_wrap_seal(&sender, NULL, 0, NULL, 0, ciphertext, sizeof(ciphertext)));
        ASSERT(shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&sender, &receiver, sizeof(sender)));
        shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver); shake_wrap_destroy(NULL);
        ASSERT(!memcmp(&sender, &zero, sizeof(sender))); ASSERT(!memcmp(&receiver, &zero, sizeof(receiver)));
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(shake_wrap_init(&receiver, key));
        receiver.offset = 65;
        struct shake_wrap_state corrupted = receiver;
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&receiver, &corrupted, sizeof(receiver)));
        receiver.offset = 0; receiver.initialized ^= 1;
        corrupted = receiver;
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&receiver, &corrupted, sizeof(receiver)));
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver);
    return failures;
}
/* Reference: the byte-wise Wrap and the original loop Keccak-f, kept only here
 * so the optimized library path is compared against an independent copy. */
static uint64_t ref_rotl(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static void ref_keccakf(uint64_t st[25])
{
    static const uint64_t rc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};
    static const int rot[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8,
        25, 43, 62, 18, 39, 61, 20, 44};
    static const int pil[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13,
        12, 2, 20, 14, 22, 9, 6, 1};
    for (int r = 0; r < 24; ++r) {
        uint64_t bc[5], t;
        for (int i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ ref_rotl(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; ++i) {
            uint64_t next = st[pil[i]]; st[pil[i]] = ref_rotl(t, rot[i]); t = next;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) bc[i] = st[j + i];
            for (int i = 0; i < 5; ++i) st[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
        }
        st[0] ^= rc[r];
    }
}
static void ref_permute(uint8_t bytes[200])
{
    uint64_t lanes[25] = {0};
    for (size_t i = 0; i < 200; ++i) lanes[i / 8] |= (uint64_t)bytes[i] << (8 * (i % 8));
    ref_keccakf(lanes);
    for (size_t i = 0; i < 200; ++i) bytes[i] = (uint8_t)(lanes[i / 8] >> (8 * (i % 8)));
}
struct ref_wrap { uint8_t bytes[200]; uint32_t offset; };
static void ref_duplex(struct ref_wrap *s, const uint8_t *in, size_t len, unsigned domain)
{
    memset(s->bytes, 0, 128);
    if (len) memcpy(s->bytes, in, len);
    if (len < 128) s->bytes[len] = 1;
    unsigned leading = domain < 2 ? 1u : 4u;
    s->bytes[128] ^= (uint8_t)(domain + leading * (len == 128 ? 2u : 1u));
    s->bytes[135] ^= 0x9fu;
    ref_permute(s->bytes);
    s->offset = 0;
}
static void ref_extract(struct ref_wrap *s, const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; ++i) out[i] = s->bytes[s->offset + i] ^ in[i];
    s->offset += (uint32_t)len;
}
static void ref_seal(struct ref_wrap *s, const uint8_t *ad, size_t ad_len,
    const uint8_t *pt, size_t len, uint8_t *out)
{
    while (ad_len > 128) { ref_duplex(s, ad, 128, 5); ad += 128; ad_len -= 128; }
    if (!len) {
        ref_duplex(s, ad, ad_len, 7);
    } else {
        size_t limit = 64;
        if (ad_len) { ref_duplex(s, ad, ad_len, 5); limit = 128; }
        size_t block = len < limit ? len : limit;
        ref_extract(s, pt, out, block);
        size_t pos = block;
        while (pos < len) {
            ref_duplex(s, out + pos - block, block, 4);
            block = len - pos; if (block > 128) block = 128;
            ref_extract(s, pt + pos, out + pos, block);
            pos += block;
        }
        ref_duplex(s, out + pos - block, block, 6);
    }
    memcpy(out + len, s->bytes, 64);
    s->offset = 64;
}
static uint64_t diff_next(uint64_t *x)
{
    uint64_t z = (*x += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}
static void diff_fill(uint64_t *rng, uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(diff_next(rng) >> 24);
}
static int wrap_differential(void)
{
    int failures = 0;
    static uint8_t ad[4096], pt[4096], got[4160], want[4160], back[4096];
    TEST_CASE("SHAKE256-Wrap: 1000 random geometries match the byte-wise reference, seal and open") {
        uint64_t rng = UINT64_C(0x5a32334b454343ff);
        bool all_equal = true;
        for (unsigned iter = 0; iter < 1000 && all_equal; ++iter) {
            uint8_t key[SHAKE_WRAP_KEY_SIZE];
            diff_fill(&rng, key, sizeof(key));
            struct shake_wrap_state seal_state, open_state;
            struct ref_wrap ref = {{0}, 0};
            all_equal = shake_wrap_init(&seal_state, key) && shake_wrap_init(&open_state, key);
            ref_duplex(&ref, key, sizeof(key), 1);
            for (unsigned rec = 0; rec < 2 && all_equal; ++rec) {
                size_t len = (size_t)(diff_next(&rng) % 4097);
                size_t ad_len = (diff_next(&rng) & 3) == 0 ? (size_t)(diff_next(&rng) % 4097)
                    : (size_t)(diff_next(&rng) % 200);
                if (iter < 40) len = (size_t)iter * 129 % 4097;
                diff_fill(&rng, ad, ad_len); diff_fill(&rng, pt, len);
                ref_seal(&ref, ad, ad_len, pt, len, want);
                all_equal = shake_wrap_seal(&seal_state, ad, ad_len, pt, len, got, sizeof(got)) &&
                    !memcmp(got, want, len + 64) &&
                    shake_wrap_open(&open_state, ad, ad_len, got, len + 64, back, sizeof(back)) &&
                    !memcmp(back, pt, len) &&
                    !memcmp(seal_state.bytes, ref.bytes, 200) && seal_state.offset == ref.offset &&
                    !memcmp(&seal_state, &open_state, sizeof(seal_state));
            }
            if (!all_equal) fprintf(stderr, "Wrap differential mismatch at iteration %u\n", iter);
        }
        ASSERT(all_equal);
    } TEST_END
    return failures;
}
int test_shake_wrap(void);
int test_shake_wrap(void)
{
    int failures = wrap_oracle_vectors();
    failures += wrap_authentication_refusals(); failures += wrap_seal_bounds();
    failures += wrap_open_bounds(); failures += wrap_empty_and_destroy();
    failures += wrap_differential();
    return failures;
}
