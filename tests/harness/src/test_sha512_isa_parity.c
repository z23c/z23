/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: core/modules/crypto/src/sha512.c
 *
 * Differential oracle for portable SHA-512 and the arm64 FEAT_SHA512 tier.
 * The hardware transform is reachable only when the OS advertises it and its
 * compression state agrees with portable C. This group independently proves
 * reachability, published vectors, padding boundaries, randomized/chunked
 * parity, and comparator teeth. */

#define _POSIX_C_SOURCE 200809L

#include "crypto/sha512.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#endif

static uint64_t sha512_rng_state = 0xd1b54a32d192ed03ULL;

static uint64_t sha512_rng_next(void)
{
    uint64_t x = sha512_rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    sha512_rng_state = x;
    return x * 0x2545f4914f6cdd1dULL;
}

static void sha512_rng_fill(unsigned char *out, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        out[i] = (unsigned char)(sha512_rng_next() >> 17);
}

static void sha512_oneshot(const unsigned char *in, size_t len,
                           unsigned char out[SHA512_OUTPUT_SIZE])
{
    struct sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_write(&ctx, in, len);
    sha512_finalize(&ctx, out);
}

static int sha512_hex(const char *hex, unsigned char *out, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        unsigned value = 0;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return -1;
        out[i] = (unsigned char)value;
    }
    return 0;
}

static bool sha512_host_has_hardware(void)
{
#if defined(__aarch64__) && defined(__APPLE__)
    static const char *const names[] = {
        "hw.optional.arm.FEAT_SHA512",
        "hw.optional.armv8_2_sha512",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        int value = 0;
        size_t len = sizeof(value);
        if (sysctlbyname(names[i], &value, &len, NULL, 0) == 0 &&
            len == sizeof(value) && value == 1)
            return true;
    }
#endif
    return false;
}

int test_sha512_isa_parity(void)
{
    int failures = 0;
    const bool host_hardware = sha512_host_has_hardware();
    const int selected = sha512_select_impl(SHA512_IMPL_ARM);
    const bool tier_available = selected == SHA512_IMPL_ARM;

    printf("\n=== sha512_isa_parity (portable vs ARM FEAT_SHA512) ===\n");
    printf("sha512_isa_parity: host advertises FEAT_SHA512... %s\n",
           host_hardware ? "YES" : "no");
    printf("sha512_isa_parity: node selects.................. %s\n",
           sha512_implementation());
    printf("sha512_isa_parity: hardware reachable when advertised... ");
    if (!host_hardware) {
        printf("not applicable\n");
    } else if (tier_available &&
               strstr(sha512_implementation(), "hardware") != NULL) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    static const struct {
        const char *message;
        size_t len;
        const char *digest;
    } kats[] = {
        { "", 0,
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { "abc", 3,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
    };

    printf("sha512_isa_parity: published KATs through both tiers... ");
    int kat_failures = 0;
    for (int pass = 0; pass < 2; ++pass) {
        sha512_select_impl(pass == 0 ? SHA512_IMPL_PORTABLE
                                     : SHA512_IMPL_ARM);
        for (size_t i = 0; i < sizeof(kats) / sizeof(kats[0]); ++i) {
            unsigned char got[SHA512_OUTPUT_SIZE];
            unsigned char want[SHA512_OUTPUT_SIZE];
            if (sha512_hex(kats[i].digest, want, sizeof(want)) != 0) {
                kat_failures++;
                continue;
            }
            sha512_oneshot((const unsigned char *)kats[i].message,
                           kats[i].len, got);
            if (memcmp(got, want, sizeof(got)) != 0)
                kat_failures++;
        }
    }
    if (kat_failures == 0)
        printf("OK\n");
    else {
        printf("FAIL (%d)\n", kat_failures);
        failures++;
    }

    printf("sha512_isa_parity: every length 0..1024... ");
    int diff_failures = 0;
    unsigned char *buffer = malloc(8193);
    if (buffer == NULL) {
        printf("allocation FAIL\n");
        failures++;
    } else {
        for (size_t len = 0; len <= 1024; ++len) {
            unsigned char portable[SHA512_OUTPUT_SIZE];
            unsigned char hardware[SHA512_OUTPUT_SIZE];
            sha512_rng_fill(buffer, len);
            sha512_select_impl(SHA512_IMPL_PORTABLE);
            sha512_oneshot(buffer, len, portable);
            sha512_select_impl(SHA512_IMPL_ARM);
            sha512_oneshot(buffer, len, hardware);
            if (memcmp(portable, hardware, sizeof(portable)) != 0)
                diff_failures++;
        }
        if (diff_failures == 0)
            printf("OK\n");
        else {
            printf("FAIL (%d)\n", diff_failures);
            failures++;
        }

        printf("sha512_isa_parity: randomized + chunked parity x5000... ");
        diff_failures = 0;
        for (int trial = 0; trial < 5000; ++trial) {
            size_t len = (size_t)(sha512_rng_next() % 8193);
            unsigned char portable[SHA512_OUTPUT_SIZE];
            unsigned char hardware[SHA512_OUTPUT_SIZE];
            sha512_rng_fill(buffer, len);

            sha512_select_impl(SHA512_IMPL_PORTABLE);
            sha512_oneshot(buffer, len, portable);

            sha512_select_impl(SHA512_IMPL_ARM);
            struct sha512_ctx ctx;
            sha512_init(&ctx);
            size_t off = 0;
            while (off < len) {
                size_t part = (size_t)(sha512_rng_next() % 193) + 1;
                if (part > len - off)
                    part = len - off;
                sha512_write(&ctx, buffer + off, part);
                off += part;
            }
            sha512_finalize(&ctx, hardware);
            if (memcmp(portable, hardware, sizeof(portable)) != 0)
                diff_failures++;
        }
        if (diff_failures == 0)
            printf("OK\n");
        else {
            printf("FAIL (%d)\n", diff_failures);
            failures++;
        }
        free(buffer);
    }

    printf("sha512_isa_parity: comparator teeth... ");
    {
        unsigned char want[SHA512_OUTPUT_SIZE];
        unsigned char good[SHA512_OUTPUT_SIZE];
        unsigned char bad[SHA512_OUTPUT_SIZE];
        unsigned char message[3] = {'a', 'b', 'c'};
        (void)sha512_hex(kats[1].digest, want, sizeof(want));
        sha512_select_impl(SHA512_IMPL_ARM);
        sha512_oneshot(message, sizeof(message), good);
        message[2] ^= 1;
        sha512_oneshot(message, sizeof(message), bad);
        if (memcmp(good, want, sizeof(good)) == 0 &&
            memcmp(bad, want, sizeof(bad)) != 0) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("sha512_isa_parity: boot KAT path... ");
    sha512_select_impl(SHA512_IMPL_AUTO);
    if (sha512_selftest())
        printf("OK (%s)\n", sha512_implementation());
    else {
        printf("FAIL\n");
        failures++;
    }

    printf("sha512_isa_parity: %d failure(s)\n", failures);
    return failures;
}
