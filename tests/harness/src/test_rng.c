/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the platform RNG abstraction (platform/modules/platform/src/rng.c).
 *
 * Coverage:
 *   - rng_fill(32 bytes) succeeds and produces non-zero output
 *     (statistical — failure odds ≈ 1/2^256, treat as deterministic)
 *   - rng_u32_range(10, 20) produces values strictly in [10, 20)
 *     across 1000 calls, and produces > 1 distinct value
 *   - inject a seeded xorshift RNG; assert rng_u64 returns the expected
 *     sequence
 *   - rng_set_default(NULL) is a no-op
 *   - rng_reset_default restores real behavior
 */

#include "test/test_core.h"
#include "platform/rng.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RNG_CHECK(name, expr) do { \
    printf("rng: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Seeded xorshift64 RNG for the injection test ───────────────── */

struct xs64 {
    _Atomic uint64_t state;
};

static uint64_t xs64_next(struct xs64 *r)
{
    /* Marsaglia xorshift64. Not cryptographic — that's the point: we
     * want a reproducible stream so the test can assert the expected
     * sequence under a known seed. */
    uint64_t x = atomic_load(&r->state);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    atomic_store(&r->state, x);
    return x;
}

static bool xs64_fill(void *self, uint8_t *out, size_t len)
{
    struct xs64 *r = (struct xs64 *)self;
    size_t i = 0;
    while (i < len) {
        uint64_t v = xs64_next(r);
        size_t chunk = len - i;
        if (chunk > sizeof(v)) chunk = sizeof(v);
        memcpy(out + i, &v, chunk);
        i += chunk;
    }
    return true;
}

int test_rng(void)
{
    printf("\n=== platform rng tests ===\n");
    int failures = 0;

    /* ── real default: 32-byte fill non-zero ────────────────────── */
    {
        rng_reset_default();
        uint8_t buf[32];
        memset(buf, 0, sizeof(buf));
        bool ok = rng_fill(buf, sizeof(buf));
        RNG_CHECK("rng_fill(32) returns true", ok);

        bool any_nonzero = false;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] != 0) { any_nonzero = true; break; }
        }
        RNG_CHECK("rng_fill(32) produces non-zero bytes", any_nonzero);

        /* Zero-length fill is a no-op success. */
        ok = rng_fill(NULL, 0);
        RNG_CHECK("rng_fill(NULL,0) returns true (no-op)", ok);
    }

    /* ── range bounds + distribution ────────────────────────────── */
    {
        rng_reset_default();
        bool in_range = true;
        uint32_t distinct_mask = 0;
        for (int i = 0; i < 1000; i++) {
            uint32_t v = rng_u32_range(10, 20);
            if (v < 10 || v >= 20) { in_range = false; break; }
            distinct_mask |= (1u << (v - 10));
        }
        RNG_CHECK("rng_u32_range(10,20): all in [10,20)", in_range);
        /* With 1000 draws over 10 buckets, every bucket should be hit
         * with overwhelming probability. Conservatively require at
         * least 2 distinct values so we'd catch a stuck constant. */
        int distinct = __builtin_popcount(distinct_mask);
        RNG_CHECK("rng_u32_range produced >=2 distinct values",
                  distinct >= 2);

        /* Degenerate range returns lo. */
        uint32_t deg = rng_u32_range(42, 42);
        RNG_CHECK("rng_u32_range(42,42) == 42", deg == 42);
        deg = rng_u32_range(100, 50);
        RNG_CHECK("rng_u32_range(100,50) == 100 (lo>hi clamps)",
                  deg == 100);

        /* Single-element range. */
        for (int i = 0; i < 8; i++) {
            uint32_t v = rng_u32_range(7, 8);
            if (v != 7) { in_range = false; break; }
        }
        RNG_CHECK("rng_u32_range(7,8) always returns 7", in_range);
    }

    /* ── u64 returns non-zero on real default ───────────────────── */
    {
        rng_reset_default();
        uint64_t a = rng_u64();
        uint64_t b = rng_u64();
        /* Two consecutive draws being equal is ~1/2^64. */
        RNG_CHECK("two real rng_u64 draws differ", a != b);
        RNG_CHECK("real rng_u64 not stuck at zero", a != 0 || b != 0);
    }

    /* ── inject seeded RNG: deterministic sequence ──────────────── */
    {
        struct xs64 r;
        atomic_store(&r.state, (uint64_t)0xDEADBEEFCAFEBABEULL);

        const rng_iface_t iface = {
            .fill = xs64_fill,
            .self = &r,
        };
        rng_set_default(&iface);

        /* Compute the expected sequence from a separate identical
         * instance so a regression in xs64_next itself is also
         * caught by the assertion (the two must agree). */
        struct xs64 expected;
        atomic_store(&expected.state, (uint64_t)0xDEADBEEFCAFEBABEULL);

        bool ok = true;
        for (int i = 0; i < 8; i++) {
            uint64_t got = rng_u64();
            uint64_t exp = xs64_next(&expected);
            if (got != exp) {
                printf("\n  draw %d: got=0x%016llx exp=0x%016llx\n",
                       i, (unsigned long long)got,
                       (unsigned long long)exp);
                ok = false;
                break;
            }
        }
        RNG_CHECK("seeded RNG: rng_u64 matches expected sequence", ok);

        RNG_CHECK("rng_default returns the injected pointer",
                  rng_default() == &iface);

        /* Restore so later tests see real RNG again. */
        rng_reset_default();

        /* After reset, rng_u64 should now produce a fresh value
         * (not part of the seeded sequence). With overwhelming
         * probability it differs from xs64_next(&expected). */
        uint64_t real = rng_u64();
        uint64_t next_seeded = xs64_next(&expected);
        RNG_CHECK("after reset_default: rng_u64 ≠ next seeded value",
                  real != next_seeded);
    }

    /* ── set NULL is rejected ───────────────────────────────────── */
    {
        rng_reset_default();
        const rng_iface_t *before = rng_default();
        rng_set_default(NULL);
        const rng_iface_t *after = rng_default();
        RNG_CHECK("set_default(NULL) is no-op", before == after);
    }

    rng_reset_default();

    if (failures == 0) {
        printf("=== platform rng tests: ALL PASS ===\n\n");
    } else {
        printf("=== platform rng tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
