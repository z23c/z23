/* zprng tests — reference vectors plus statistical sanity checks. */
#include "zprng/zprng.h"

#include <math.h>
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

/* SplitMix64(42) first three outputs, reference values. */
static void test_splitmix_vectors(void)
{
    static const uint64_t want[3] = {
        UINT64_C(0xbdd732262feb6e95),
        UINT64_C(0x28efe333b266f103),
        UINT64_C(0x47526757130f9f52)
    };
    zsplitmix64 sm;

    zsplitmix64_init(&sm, 42);
    for (int i = 0; i < 3; i++)
        check(zsplitmix64_next(&sm) == want[i], "splitmix vector");
}

/* xoshiro256** seeded via SplitMix64(42), reference values. */
static void test_xoshiro_vectors(void)
{
    static const uint64_t want[3] = {
        UINT64_C(0x15780b2e0c2ec716),
        UINT64_C(0x6104d9866d113a7e),
        UINT64_C(0xae17533239e499a1)
    };
    zxoshiro256ss rng;

    zxoshiro256ss_init(&rng, 42);
    for (int i = 0; i < 3; i++)
        check(zxoshiro256ss_next(&rng) == want[i], "xoshiro vector");
}

static void test_determinism(void)
{
    zxoshiro256ss a, b;

    zxoshiro256ss_init(&a, 7);
    zxoshiro256ss_init(&b, 7);
    for (int i = 0; i < 100; i++)
        if (zxoshiro256ss_next(&a) != zxoshiro256ss_next(&b)) {
            check(0, "determinism");
            return;
        }
    check(1, "determinism");

    zxoshiro256ss_init(&a, 7);
    zxoshiro256ss_init(&b, 8);
    check(zxoshiro256ss_next(&a) != zxoshiro256ss_next(&b),
          "different seeds differ");
}

static void test_below_bounds(void)
{
    zxoshiro256ss rng;
    int seen[10] = {0};
    unsigned long total = 0;

    zxoshiro256ss_init(&rng, 99);
    check(zxoshiro256ss_below(&rng, 0) == 0, "below 0 is 0");
    for (int i = 0; i < 100000; i++) {
        uint64_t v = zxoshiro256ss_below(&rng, 10);
        if (v >= 10) {
            check(0, "below in range");
            return;
        }
        seen[v]++;
        total++;
    }
    /* Every bucket hit at least 5000 times in 100k draws; a biased or
     * broken generator misses buckets entirely. */
    for (int i = 0; i < 10; i++)
        if (seen[i] < 5000) {
            check(0, "below bucket coverage");
            return;
        }
    check(total == 100000, "below count");
}

static void test_double_range(void)
{
    zxoshiro256ss rng;

    zxoshiro256ss_init(&rng, 5);
    for (int i = 0; i < 10000; i++) {
        double d = zxoshiro256ss_double(&rng);
        if (!(d >= 0.0 && d < 1.0)) {
            check(0, "double range");
            return;
        }
    }
    check(1, "double range");
}

static void test_shuffle(void)
{
    unsigned deck[52];
    unsigned long long seen_mask_lo = 0;
    zxoshiro256ss rng;

    for (unsigned i = 0; i < 52; i++)
        deck[i] = i;
    zxoshiro256ss_init(&rng, 1234);
    zxoshiro256ss_shuffle(&rng, deck, 52, sizeof deck[0]);
    for (unsigned i = 0; i < 52; i++) {
        if (deck[i] >= 52) {
            check(0, "shuffle keeps elements");
            return;
        }
        seen_mask_lo |= 1ull << deck[i];
    }
    check(seen_mask_lo == 0xfffffffffffffull, "shuffle is permutation");
}

static void test_shuffle_odd_sizes(void)
{
    char bytes[3] = {'x', 'y', 'z'};
    zxoshiro256ss rng;

    zxoshiro256ss_init(&rng, 1);
    zxoshiro256ss_shuffle(&rng, bytes, 3, 1);
    /* All three original bytes survive regardless of order. */
    check((bytes[0] == 'x' || bytes[1] == 'x' || bytes[2] == 'x') &&
              (bytes[0] == 'y' || bytes[1] == 'y' || bytes[2] == 'y') &&
              (bytes[0] == 'z' || bytes[1] == 'z' || bytes[2] == 'z'),
          "shuffle char permutation");
    /* Degenerate inputs are no-ops. */
    zxoshiro256ss_shuffle(&rng, NULL, 5, 1);
    zxoshiro256ss_shuffle(&rng, bytes, 1, 1);
    zxoshiro256ss_shuffle(&rng, bytes, 3, 0);
    check(1, "shuffle degenerate no-op");
}

int main(void)
{
    test_splitmix_vectors();
    test_xoshiro_vectors();
    test_determinism();
    test_below_bounds();
    test_double_range();
    test_shuffle();
    test_shuffle_odd_sizes();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zprng: all tests passed");
    return 0;
}
