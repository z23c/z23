/* zprng tests — reference vectors plus statistical sanity checks. */
#include "zprng/zprng.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static FILE *cli_sink;
static size_t cli_next_calls, cli_flushes;
static FILE *real_stdout(void) { return stdout; }
static uint64_t cli_next(zxoshiro256ss *rng)
{
    cli_next_calls++;
    return zxoshiro256ss_next(rng);
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define fflush cli_flush
#define zxoshiro256ss_next cli_next
#define main zprng_cli_main
#include "../app/main.c"
#undef main
#undef zxoshiro256ss_next
#undef fflush
#undef printf
#undef stdout
#define stdout real_stdout()

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

static void test_shuffle_large_items(void)
{
    const size_t sizes[] = {257, 512, 513};
    for (size_t row = 0; row < sizeof sizes / sizeof sizes[0]; row++) {
        size_t size = sizes[row];
        unsigned char actual[3 * 513 + 2], expected[sizeof actual];
        memset(actual, 0xa5, sizeof actual);
        for (size_t i = 0; i < 3; i++)
            for (size_t j = 0; j < size; j++)
                actual[1 + i * size + j] = (unsigned char)(i * 67 + j);
        memcpy(expected, actual, sizeof actual);
        zxoshiro256ss rng, reference;
        zxoshiro256ss_init(&rng, 1234);
        reference = rng;
        for (size_t i = 2; i > 0; i--) {
            size_t k = (size_t)zxoshiro256ss_below(&reference, i + 1);
            for (size_t j = 0; j < size; j++) {
                unsigned char byte = expected[1 + i * size + j];
                expected[1 + i * size + j] = expected[1 + k * size + j];
                expected[1 + k * size + j] = byte;
            }
        }
        zxoshiro256ss_shuffle(&rng, actual + 1, 3, size);
        int ok = memcmp(actual, expected, sizeof actual) == 0 &&
                 memcmp(&rng, &reference, sizeof rng) == 0;
        fprintf(stderr, "large_shuffle_row=%zu size=%zu result=%s\n", row,
                size, ok ? "PASS" : "FAIL");
        check(ok, "shuffle handles large items with bounded swaps");
    }
}

static void test_shuffle_size_overflow(void)
{
    unsigned char bytes[4] = {1, 2, 3, 4};
    const unsigned char expected[4] = {1, 2, 3, 4};
    zxoshiro256ss rng, original;
    zxoshiro256ss_init(&rng, 1234);
    original = rng;
    /* Impossible span: reject its arithmetic before deriving pointers. */
    zxoshiro256ss_shuffle(&rng, bytes, SIZE_MAX / 2 + 1, 2);
    int ok = memcmp(bytes, expected, sizeof bytes) == 0 &&
             memcmp(&rng, &original, sizeof rng) == 0;
    fprintf(stderr, "shuffle_size_overflow_row=0 result=%s\n", ok ? "PASS" : "FAIL");
    check(ok, "overflowing shuffle span leaves buffer and generator unchanged");
}

static void test_cli_rejects_invalid_arguments(void)
{
    const char *seed_rows[] = {"", "-1", "18446744073709551616", "seed"};
    for (size_t i = 0; i < sizeof seed_rows / sizeof seed_rows[0]; i++) {
        char *args[] = {"zprng", (char *)seed_rows[i], "0", NULL};
        cli_next_calls = cli_flushes = 0;
        int ok = zprng_cli_main(3, args) == 2;
        check(cli_next_calls == 0 && cli_flushes == 0, "bad seed leaves output untouched");
        fprintf(stderr, "prng_seed_row=%zu result=%s\n", i, ok ? "PASS" : "FAIL");
        check(ok, "demo rejects invalid seed");
    }
    const char *count_rows[] = {"", "count"};
    for (size_t i = 0; i < sizeof count_rows / sizeof count_rows[0]; i++) {
        char *args[] = {"zprng", "42", (char *)count_rows[i], NULL};
        cli_next_calls = cli_flushes = 0;
        int ok = zprng_cli_main(3, args) == 2;
        check(cli_next_calls == 0 && cli_flushes == 0, "bad count leaves output untouched");
        fprintf(stderr, "prng_count_row=%zu result=%s\n", i, ok ? "PASS" : "FAIL");
        check(ok, "demo rejects invalid count");
    }
}

static void test_cli_output(void);

int main(void)
{
    cli_sink = stdout;
    test_cli_output();
    test_cli_rejects_invalid_arguments();
    test_shuffle_size_overflow();
    test_shuffle_large_items();
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

static FILE *required_stream(FILE *stream)
{
    if (!stream) { fprintf(stderr, "zprng CLI fixture setup failed\n"); exit(2); }
    return stream;
}
static int cli_invoke(FILE *sink, int argc, char **args)
{
    cli_sink = sink;
    cli_next_calls = cli_flushes = 0;
    int rc = zprng_cli_main(argc, args);
    cli_sink = stdout;
    return rc;
}
static void cli_expected(char *out, size_t cap, uint64_t seed, size_t count)
{
    zxoshiro256ss rng;
    zxoshiro256ss_init(&rng, seed);
    size_t used = 0;
    for (size_t i = 0; i < count; i++) {
        int n = snprintf(out + used, cap - used, "%llu\n",
                         (unsigned long long)zxoshiro256ss_next(&rng));
        if (n < 0 || (size_t)n >= cap - used) exit(2);
        used += (size_t)n;
    }
    out[used] = '\0';
}
static void cli_normal(int argc, char **args, uint64_t seed, size_t count)
{
    FILE *sink = required_stream(tmpfile());
    check(cli_invoke(sink, argc, args) == 0, "normal CLI status");
    check(cli_next_calls == count, "normal CLI draws exact count");
    if (!count) check(cli_flushes == 0, "zero CLI does not flush output");
    char want[256], got[256];
    cli_expected(want, sizeof want, seed, count);
    rewind(sink);
    size_t n = fread(got, 1, sizeof got, sink);
    check(!ferror(sink) && n == strlen(want) && !memcmp(got, want, n), "exact CLI output");
    check(fclose(sink) == 0, "normal CLI close");
}
static void cli_failed_output(bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
    char buffer[4096];
    if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
    char *args[] = {"zprng", "42", "5", NULL};
    check(cli_invoke(sink, 3, args) == 1, "CLI refuses failed output");
    check(ferror(sink) != 0, "CLI observes stream failure");
    check(cli_next_calls == (buffered ? 5u : 1u), "CLI stops draws after immediate write failure");
    (void)fclose(sink);
}
static void test_cli_output(void)
{
    char *defaults[] = {"zprng", NULL};
    cli_normal(1, defaults, 42, 5);
    char *seed[] = {"zprng", "7", NULL};
    cli_normal(2, seed, 7, 5);
    char *explicit[] = {"zprng", "42", "3", "ignored", NULL};
    cli_normal(4, explicit, 42, 3);
    char *zero[] = {"zprng", "42", "0", NULL};
    cli_normal(3, zero, 42, 0);
    cli_failed_output(false);
#ifdef __linux__
    cli_failed_output(true);
#endif
}
