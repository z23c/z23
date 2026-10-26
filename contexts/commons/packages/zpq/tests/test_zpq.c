#include "zpq/zpq.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static int cmp_int_ptr(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    long va = *(const long *)a, vb = *(const long *)b;
    return (va > vb) - (va < vb);
}

static void test_basic(void)
{
    long vals[] = {5, 1, 9, 3, 7, 2, 8};
    zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(pq != NULL);
    CHECK(zpq_len(pq) == 0);
    CHECK(zpq_peek(pq) == NULL);
    CHECK(zpq_pop(pq) == NULL);

    for (size_t i = 0; i < 7; i++) CHECK(zpq_push(pq, &vals[i]));
    CHECK(zpq_len(pq) == 7);
    CHECK(*(long *)zpq_peek(pq) == 1);

    long prev = -1;
    while (zpq_len(pq) > 0) {
        long v = *(long *)zpq_pop(pq);
        CHECK(v > prev);
        prev = v;
    }
    CHECK(prev == 9);
    zpq_destroy(pq);
    zpq_destroy(NULL);

    /* NULL tolerance. */
    CHECK(zpq_len(NULL) == 0);
    CHECK(zpq_peek(NULL) == NULL);
    CHECK(!zpq_push(NULL, &vals[0]));
    CHECK(zpq_pop(NULL) == NULL);
    CHECK(zpq_replace(NULL, &vals[0]) == NULL);
    CHECK(zpq_create(NULL, NULL, (zpq_alloc){0}) == NULL);
}

static void test_from_and_replace(void)
{
    long vals[] = {42, 17, 99, 3, 55, 8, 71, 23};
    void *items[8];
    for (int i = 0; i < 8; i++) items[i] = &vals[i];

    zpq *pq = zpq_from(items, 8, cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(pq != NULL);
    CHECK(zpq_len(pq) == 8);
    CHECK(*(long *)zpq_peek(pq) == 3);

    /* Replace the minimum. */
    long newv = 100;
    CHECK(*(long *)zpq_replace(pq, &newv) == 3);
    CHECK(*(long *)zpq_peek(pq) == 8);
    CHECK(zpq_len(pq) == 8);

    /* Drain must be sorted. */
    long prev = -1;
    size_t n = 0;
    void *p;
    while ((p = zpq_pop(pq)) != NULL) {
        long v = *(long *)p;
        CHECK(v > prev);
        prev = v;
        n++;
    }
    CHECK(n == 8 && prev == 100);
    zpq_destroy(pq);

    CHECK(zpq_from(NULL, 1, cmp_int_ptr, NULL, (zpq_alloc){0}) == NULL);

    /* Empty-from. */
    zpq *e = zpq_from(NULL, 0, cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(e != NULL && zpq_len(e) == 0);
    zpq_destroy(e);
}

/* Counting allocator with a failure switch. */
struct test_alloc {
    size_t mallocs, frees;
    size_t fail_after;
};
static void *ta_malloc(void *ctx, size_t size)
{
    struct test_alloc *t = ctx;
    if (t->mallocs >= t->fail_after) return NULL;
    t->mallocs++;
    return malloc(size);
}
static void ta_free(void *ctx, void *ptr)
{
    struct test_alloc *t = ctx;
    if (ptr) t->frees++;
    free(ptr);
}

static void test_alloc_failure(void)
{
    long x = 1;

    /* Struct allocation fails. */
    {
        struct test_alloc t = { 0, 0, 0 };
        zpq_alloc a = { ta_malloc, ta_free, &t };
        CHECK(zpq_create(cmp_int_ptr, NULL, a) == NULL);
    }

    /* Grow allocation fails: heap unchanged, recovers after. */
    {
        struct test_alloc t = { 0, 0, SIZE_MAX };
        zpq_alloc a = { ta_malloc, ta_free, &t };
        zpq *pq = zpq_create(cmp_int_ptr, NULL, a);
        CHECK(pq != NULL);
        for (int i = 0; i < 8; i++) CHECK(zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 8);
        t.fail_after = t.mallocs; /* next malloc fails */
        CHECK(!zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 8);
        CHECK(zpq_peek(pq) == &x);
        t.fail_after = SIZE_MAX;
        CHECK(zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 9);
        zpq_destroy(pq);
        CHECK(t.mallocs == t.frees);
    }

    /* zpq_from allocation failure. */
    {
        struct test_alloc t = { 0, 0, 1 }; /* struct ok, array fails */
        zpq_alloc a = { ta_malloc, ta_free, &t };
        void *items[2] = { &x, &x };
        CHECK(zpq_from(items, 2, cmp_int_ptr, NULL, a) == NULL);
        CHECK(t.mallocs == t.frees);
    }
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_heapsort_property(void)
{
    /* Push N random values, drain must be non-decreasing; repeat with
     * sizes crossing several growth doublings. */
    static long storage[2048];
    for (size_t n = 0; n <= 1024; n = n ? n * 2 : 1) {
        zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
        CHECK(pq != NULL);
        for (size_t i = 0; i < n; i++) {
            storage[i] = (long)(rng_next() % 1000);
            CHECK(zpq_push(pq, &storage[i]));
        }
        long prev = -1;
        for (size_t i = 0; i < n; i++) {
            long v = *(long *)zpq_pop(pq);
            CHECK(v >= prev);
            prev = v;
        }
        zpq_destroy(pq);
    }

    /* Interleaved push/pop stress: pops always return the live min. */
    for (int trial = 0; trial < 50; trial++) {
        zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
        CHECK(pq != NULL);
        long vals[256];
        bool live[256] = {0};
        size_t n = (size_t)(rng_next() % 200) + 1;
        size_t live_count = 0;
        for (size_t i = 0; i < n; i++) {
            vals[i] = (long)(rng_next() % 10000);
            CHECK(zpq_push(pq, &vals[i]));
            live[i] = true;
            live_count++;
            if (rng_next() % 3 == 0 && zpq_len(pq) > 1) {
                long expected = 10001;
                size_t which = 0;
                for (size_t j = 0; j <= i; j++)
                    if (live[j] && vals[j] < expected) {
                        expected = vals[j];
                        which = j;
                    }
                void *got = zpq_pop(pq);
                CHECK(*(long *)got == expected);
                live[which] = false;
                live_count--;
            }
            CHECK(zpq_len(pq) == live_count);
        }
        long prev = -1;
        void *p;
        while ((p = zpq_pop(pq)) != NULL) {
            CHECK(*(long *)p >= prev);
            prev = *(long *)p;
        }
        zpq_destroy(pq);
    }
}

static void test_cli(void);

int main(void)
{
    test_cli();
    test_basic();
    test_from_and_replace();
    test_alloc_failure();
    test_heapsort_property();
    puts("test_zpq: all groups passed (basic from allocfail heapproperty)");
    return 0;
}

static FILE *cli_sink;
static size_t cli_flushes, cli_storage_allocs, cli_storage_frees;
static struct test_alloc cli_alloc;
static FILE *real_stdout(void) { return stdout; }
static zpq *cli_create(zpq_cmp cmp, void *ctx, zpq_alloc ignored)
{
    (void)ignored;
    cli_alloc = (struct test_alloc){0, 0, SIZE_MAX};
    return zpq_create(cmp, ctx, (zpq_alloc){ta_malloc, ta_free, &cli_alloc});
}
static void *cli_malloc(size_t n)
{
    void *p = malloc(n);
    if (p) cli_storage_allocs++;
    return p;
}
static void cli_free(void *p)
{
    if (p) cli_storage_frees++;
    free(p);
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
#define malloc cli_malloc
#define free cli_free
#define zpq_create cli_create
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef zpq_create
#undef malloc
#undef free
#undef fflush
#undef printf
#undef stdout
#define stdout real_stdout()

static void cli_case(int argc, char **args, int status, const char *want,
                      bool stale_errno)
{
    FILE *sink = tmpfile();
    CHECK(sink != NULL);
    cli_sink = sink;
    cli_flushes = cli_storage_allocs = cli_storage_frees = 0;
    errno = stale_errno ? ERANGE : 0;
    int rc = embedded_cli_main(argc, args);
    cli_sink = stdout;
    CHECK(rc == status);
    CHECK(cli_alloc.mallocs == cli_alloc.frees);
    CHECK(cli_storage_allocs == cli_storage_frees);
    if (!*want) CHECK(cli_flushes == 0);
    char got[256];
    rewind(sink);
    size_t n = fread(got, 1, sizeof got, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(got, want, n));
    CHECK(fclose(sink) == 0);
}
static void cli_numbers(void)
{
    const char *bad[] = {"", " \t", "garbage", "1junk", "1 ", "0x10",
        "999999999999999999999999999999999999", "-999999999999999999999999999999999999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char *args[] = {"zpq", "push", (char *)bad[i], "pop", NULL};
        cli_case(4, args, 2, "", false);
    }
    char minimum[64], maximum[64], want[160];
    snprintf(minimum, sizeof minimum, "%ld", LONG_MIN);
    snprintf(maximum, sizeof maximum, "%ld", LONG_MAX);
    snprintf(want, sizeof want, "%s\n%s\n", minimum, maximum);
    char *bounds[] = {"zpq", "push", maximum, "push", minimum, "pop", "pop", NULL};
    cli_case(7, bounds, 0, want, false);
    char *valid[] = {"zpq", "push", " \t+7", "push", "-2", "push", "-0",
                     "peek", "pop", "len", "pop", "pop", NULL};
    cli_case(12, valid, 0, "-2\n-2\n2\n0\n7\n", true);
    char *late[] = {"zpq", "push", "7", "pop", "push", "junk", NULL};
    cli_case(6, late, 2, "7\n", false);
    char *unknown[] = {"zpq", "len", "unknown", NULL};
    cli_case(3, unknown, 2, "0\n", false);
}
static void cli_sink_failure(const char *op, bool buffered, bool late_error)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL);
    char buffer[4096];
    if (buffered) CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0);
    char *args[] = {"zpq", "push", "7", (char *)op, "unknown", NULL};
    cli_sink = sink;
    cli_storage_allocs = cli_storage_frees = 0;
    int rc = embedded_cli_main(late_error ? 5 : 4, args);
    cli_sink = stdout;
    CHECK(rc == 1 && ferror(sink));
    CHECK(cli_alloc.mallocs == cli_alloc.frees);
    CHECK(cli_storage_allocs == cli_storage_frees);
    (void)fclose(sink);
}
static void test_cli(void)
{
    cli_numbers();
    char *empty[] = {"zpq", "pop", "peek", NULL};
    cli_case(3, empty, 0, "", false);
    char *push[] = {"zpq", "push", "1", NULL};
    cli_case(3, push, 0, "", false);
    char *missing[] = {"zpq", "push", NULL};
    cli_case(2, missing, 2, "", false);
    char *usage[] = {"zpq", NULL};
    cli_case(1, usage, 2, "", false);
    const char *ops[] = {"pop", "peek", "len"};
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        cli_sink_failure(ops[i], false, false);
#ifdef __linux__
        cli_sink_failure(ops[i], true, false);
        cli_sink_failure(ops[i], true, true);
#endif
    }
}
