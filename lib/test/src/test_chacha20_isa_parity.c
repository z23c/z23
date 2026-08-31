/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Differential oracle for the paired ChaCha20 four-block tier: arm64 NEON
 * and x86-64 SSE2 must remain byte-identical to the portable block function.
 * AUTO deliberately remains portable until physical caller-shaped benchmark
 * receipts justify a separate per-architecture promotion. */

/* ACCEL-ORACLE: lib/crypto/src/chacha20poly1305.c */

#define _POSIX_C_SOURCE 200809L

#include "crypto/chacha20poly1305.h"
#include "platform/clock.h"

#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t chacha_rng = UINT64_C(0x243f6a8885a308d3);

static uint64_t chacha_rng_next(void)
{
    uint64_t x = chacha_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    chacha_rng = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

static void chacha_rng_fill(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(chacha_rng_next() >> 17);
}

static uint64_t chacha_now_ns(void)
{
    int64_t now = clock_now_monotonic_ns();
    return now > 0 ? (uint64_t)now : 0;
}

struct chacha_once_probe {
    _Atomic unsigned *ready;
    _Atomic bool *start;
    bool available;
};

static void *chacha_once_probe_main(void *arg)
{
    struct chacha_once_probe *probe = arg;
    atomic_fetch_add_explicit(probe->ready, 1u, memory_order_release);
    while (!atomic_load_explicit(probe->start, memory_order_acquire))
        sched_yield();
    probe->available = chacha20_vector4_available();
    return NULL;
}

static int parity_case(const uint8_t key[32], const uint8_t nonce[12],
                       uint32_t counter, const uint8_t *plain, size_t len)
{
    uint8_t ref[4096], got[4096], inplace[4096];
    if (len > sizeof ref) return 1;
    chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
    if (!chacha20_encrypt(key, counter, nonce, plain, len, ref)) return 1;
    chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
    if (!chacha20_encrypt(key, counter, nonce, plain, len, got)) return 1;
    memcpy(inplace, plain, len);
    if (!chacha20_encrypt(key, counter, nonce, inplace, len, inplace)) return 1;
    return memcmp(ref, got, len) != 0 || memcmp(ref, inplace, len) != 0;
}

#define CHACHA_CALLER_MAX_PLAIN 65520u
#define CHACHA_CALLER_MAX_AAD      85u
static uint8_t chacha_caller_plain[CHACHA_CALLER_MAX_PLAIN];
static uint8_t chacha_caller_sealed[CHACHA_CALLER_MAX_PLAIN +
                                    POLY1305_TAG_SIZE];
static uint8_t chacha_caller_opened[CHACHA_CALLER_MAX_PLAIN];
static uint8_t chacha_caller_aad[CHACHA_CALLER_MAX_AAD];

static bool bytes_are(const uint8_t *bytes, size_t len, uint8_t value)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != value) return false;
    return true;
}

static int caller_open_case(const uint8_t key[32], const uint8_t nonce[12],
                            size_t plen, size_t aad_len)
{
    for (size_t i = 0; i < plen; i++)
        chacha_caller_plain[i] = (uint8_t)(i * 131u + 17u);
    for (size_t i = 0; i < aad_len; i++)
        chacha_caller_aad[i] = (uint8_t)(i * 47u + 11u);
    chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
    if (!chacha20poly1305_encrypt(
            chacha_caller_plain, plen, chacha_caller_aad, aad_len,
            nonce, key, chacha_caller_sealed))
        return 1;

    const enum chacha20_impl impls[2] = {
        CHACHA20_IMPL_PORTABLE, CHACHA20_IMPL_VECTOR4 };
    for (size_t tier = 0; tier < 2; tier++) {
        (void)chacha20_select_impl(impls[tier]);
        memset(chacha_caller_opened, 0xa5, plen);
        if (!chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened) ||
            memcmp(chacha_caller_opened, chacha_caller_plain, plen) != 0)
            return 1;

        const size_t mutation_offsets[2] = {plen / 2u, plen};
        for (size_t mutation = 0; mutation < 2; mutation++) {
            size_t offset = mutation_offsets[mutation];
            chacha_caller_sealed[offset] ^= 1u;
            memset(chacha_caller_opened, 0xa5, plen);
            bool accepted = chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened);
            chacha_caller_sealed[offset] ^= 1u;
            if (accepted ||
                !bytes_are(chacha_caller_opened, plen, 0xa5))
                return 1;
        }
        if (aad_len > 0) {
            chacha_caller_aad[0] ^= 1u;
            memset(chacha_caller_opened, 0xa5, plen);
            bool accepted = chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened);
            chacha_caller_aad[0] ^= 1u;
            if (accepted ||
                !bytes_are(chacha_caller_opened, plen, 0xa5))
                return 1;
        }
    }
    return 0;
}

int test_chacha20_isa_parity(void)
{
    printf("\n=== chacha20_isa_parity (portable vs four-block differential oracle) ===\n");
    int failures = 0;
    uint8_t key[32], nonce[12], plain[4096];
    chacha_rng_fill(key, sizeof key);
    chacha_rng_fill(nonce, sizeof nonce);
    chacha_rng_fill(plain, sizeof plain);

    printf("chacha20_isa_parity: concurrent first KAT callers converge... ");
    {
        enum { NPROBES = 16 };
        pthread_t threads[NPROBES];
        struct chacha_once_probe probes[NPROBES];
        _Atomic unsigned ready = 0;
        _Atomic bool start = false;
        int created = 0;
        for (int i = 0; i < NPROBES; i++) {
            probes[i] = (struct chacha_once_probe){
                .ready = &ready, .start = &start, .available = false };
            if (pthread_create(&threads[i], NULL, chacha_once_probe_main,
                               &probes[i]) != 0)
                break;
            created++;
        }
        while (atomic_load_explicit(&ready, memory_order_acquire) <
               (unsigned)created)
            sched_yield();
        atomic_store_explicit(&start, true, memory_order_release);
        bool converged = created == NPROBES;
        for (int i = 0; i < created; i++) {
            if (pthread_join(threads[i], NULL) != 0)
                converged = false;
        }
        for (int i = 1; i < created; i++)
            if (probes[i].available != probes[0].available)
                converged = false;
#if defined(__aarch64__) || defined(__x86_64__) || defined(_M_X64)
        if (created == 0 || !probes[0].available)
            converged = false;
#endif
        if (converged) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chacha20_isa_parity: compiled=%s KAT-usable=%s AUTO=%s\n",
           chacha20_vector4_compiled() ? "yes" : "no",
           chacha20_vector4_available() ? "yes" : "no",
           chacha20_select_impl(CHACHA20_IMPL_AUTO) == CHACHA20_IMPL_VECTOR4
               ? "vector4" : "portable");
#if defined(__aarch64__) || defined(__x86_64__) || defined(_M_X64)
    if (!chacha20_vector4_compiled() ||
        !chacha20_vector4_available()) {
        printf("chacha20_isa_parity: mandatory-ABI vector tier unavailable... FAIL\n");
        failures++;
    }
#endif
    if (chacha20_select_impl(CHACHA20_IMPL_AUTO) != CHACHA20_IMPL_PORTABLE ||
        chacha20_auto_uses_vector4() ||
        strcmp(chacha20_implementation(), "portable C") != 0) {
        printf("chacha20_isa_parity: AUTO promoted without benchmark receipt... FAIL\n");
        failures++;
    }

    printf("chacha20_isa_parity: complete RFC 7539 block vector... ");
    {
        static const uint8_t kat_nonce[12] = {
            0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00 };
        static const uint8_t want[64] = {
            0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
            0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
            0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
            0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e };
        uint8_t kat_key[32], got[64];
        for (size_t i = 0; i < sizeof kat_key; i++) kat_key[i] = (uint8_t)i;
        chacha20_block(kat_key, 1u, kat_nonce, got);
        if (memcmp(got, want, sizeof want) == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chacha20_isa_parity: every length 0..1024, out-of-place + in-place... ");
    {
        int diffs = 0;
        for (size_t len = 0; len <= 1024; len++)
            diffs += parity_case(key, nonce, 7u, plain, len);
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: randomized parity x2000 (0..4096 bytes)... ");
    {
        int diffs = 0;
        for (int trial = 0; trial < 2000; trial++) {
            size_t len = (size_t)(chacha_rng_next() % 4097u);
            chacha_rng_fill(plain, len);
            diffs += parity_case(key, nonce,
                                 (uint32_t)chacha_rng_next() & UINT32_C(0x00ffffff),
                                 plain, len);
        }
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: counter exhaustion refuses before output... ");
    {
        uint8_t out[193], before[193];
        memset(out, 0x5a, sizeof out); memcpy(before, out, sizeof out);
        chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
        bool max64 = chacha20_encrypt(key, UINT32_MAX, nonce, plain, 64, out);
        memset(out, 0x5a, sizeof out);
        bool max65 = chacha20_encrypt(key, UINT32_MAX, nonce, plain, 65, out);
        bool unchanged65 = memcmp(out, before, sizeof out) == 0;
        memset(out, 0x5a, sizeof out);
        bool near192 = chacha20_encrypt(key, UINT32_MAX - 2u, nonce,
                                        plain, 192, out);
        memset(out, 0x5a, sizeof out);
        bool near193 = chacha20_encrypt(key, UINT32_MAX - 2u, nonce,
                                        plain, 193, out);
        bool unchanged193 = memcmp(out, before, sizeof out) == 0;
        if (max64 && !max65 && unchanged65 && near192 && !near193 && unchanged193)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chacha20_isa_parity: complete AEAD parity at caller boundaries... ");
    {
        static const size_t lens[] = {0,1,7,15,16,17,63,64,65,255,256,257,
                                      564,585,1536,2048,4096};
        uint8_t ref[4096 + 16], got[4096 + 16], opened[4096];
        int diffs = 0;
        for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            size_t len = lens[i];
            chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
            bool a = chacha20poly1305_encrypt(plain, len, plain, 17, nonce,
                                               key, ref);
            chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
            bool b = chacha20poly1305_encrypt(plain, len, plain, 17, nonce,
                                               key, got);
            bool c = b && chacha20poly1305_decrypt(got, len + 16, plain, 17,
                                                    nonce, key, opened);
            if (!a || !b || !c || memcmp(ref, got, len + 16) != 0 ||
                memcmp(opened, plain, len) != 0) diffs++;
        }
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: caller-shaped opens authenticate before output... ");
    {
        static const struct { size_t plen, aad_len; } shapes[] = {
            {564u, 0u}, {1536u, 7u}, {65520u, 85u},
        };
        int diffs = 0;
        for (size_t i = 0; i < sizeof shapes / sizeof shapes[0]; i++)
            diffs += caller_open_case(key, nonce, shapes[i].plen,
                                      shapes[i].aad_len);
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: reported benchmark (not a promotion gate)... ");
    {
        static uint8_t bench_in[65520], bench_out[65520];
        chacha_rng_fill(bench_in, sizeof bench_in);
        uint64_t ns[2];
        const enum chacha20_impl impl[2] = {
            CHACHA20_IMPL_PORTABLE, CHACHA20_IMPL_VECTOR4 };
        for (int pass = 0; pass < 2; pass++) {
            chacha20_select_impl(impl[pass]);
            uint64_t start = chacha_now_ns();
            for (int i = 0; i < 256; i++)
                if (!chacha20_encrypt(key, 1u, nonce, bench_in,
                                      sizeof bench_in, bench_out)) failures++;
            ns[pass] = chacha_now_ns() - start;
        }
        printf("portable=%llu ns vector4=%llu ns speedup=%.2fx\n",
               (unsigned long long)ns[0], (unsigned long long)ns[1],
               ns[1] ? (double)ns[0] / (double)ns[1] : 0.0);
    }

    chacha20_select_impl(CHACHA20_IMPL_AUTO);
    printf("chacha20_isa_parity: %d failure(s)\n", failures);
    return failures;
}
