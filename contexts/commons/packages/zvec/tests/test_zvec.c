/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */

#include "zvec/zvec.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static FILE *cli_sink;
static size_t cli_flushes;
static FILE *real_stdout(void) { return stdout; }
static zvec *cli_create(zvec_alloc ignored);
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
static int cli_puts(const char *text) {
    if (fputs(text, cli_sink) == EOF) return EOF;
    return fputc('\n', cli_sink);
}
#define puts cli_puts
#define zvec_create cli_create
#define fflush cli_flush
#undef stdout
#define stdout cli_sink
#define main zvec_cli_main
#include "../app/main.c"
#undef main
#undef puts
#undef zvec_create
#undef fflush
#undef stdout
#define stdout real_stdout()

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* Counting allocator with a failure switch for failure-path tests. */
struct test_alloc {
    size_t mallocs, frees;
    size_t attempts, requested_sizes[2];
    size_t fail_after; /* fail when mallocs reaches this; SIZE_MAX = never */
};
static void *ta_malloc(void *ctx, size_t size)
{
    struct test_alloc *t = ctx;
    if (t->attempts < 2) t->requested_sizes[t->attempts] = size;
    t->attempts++;
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
static zvec_alloc ta(struct test_alloc *t, size_t fail_after)
{
    *t = (struct test_alloc){ .fail_after = fail_after };
    return (zvec_alloc){ ta_malloc, ta_free, t };
}

static struct test_alloc cli_alloc;
static zvec *cli_create(zvec_alloc ignored)
{
    (void)ignored;
    return zvec_create(ta(&cli_alloc, SIZE_MAX));
}

static void test_initial_capacity(void)
{
    struct test_alloc t;
    const size_t limit = SIZE_MAX / sizeof(void *);

    CHECK(zvec_with_capacity(limit + 1, ta(&t, 1)) == NULL);
    CHECK(t.attempts == 0);
    CHECK(t.mallocs == 0 && t.frees == 0);

    CHECK(zvec_with_capacity(limit, ta(&t, 1)) == NULL);
    CHECK(t.attempts == 2);
    CHECK(t.requested_sizes[1] == limit * sizeof(void *));
    CHECK(t.mallocs == 1 && t.frees == 1);

    CHECK(zvec_with_capacity(4, ta(&t, 0)) == NULL);
    CHECK(t.attempts == 1);
    CHECK(t.mallocs == 0 && t.frees == 0);

    zvec *v = zvec_with_capacity(4, ta(&t, SIZE_MAX));
    CHECK(v != NULL);
    CHECK(zvec_len(v) == 0 && zvec_capacity(v) == 4);
    CHECK(t.attempts == 2);
    CHECK(t.requested_sizes[1] == 4 * sizeof(void *));
    zvec_destroy(v);
    CHECK(t.mallocs == 2 && t.frees == 2);
}

static void test_basic(void)
{
    int a = 1, b = 2, c = 3;
    zvec *v = zvec_create((zvec_alloc){0});
    CHECK(v != NULL);
    CHECK(zvec_len(v) == 0);
    CHECK(zvec_pop(v) == NULL);

    CHECK(zvec_push(v, &a));
    CHECK(zvec_push(v, &b));
    CHECK(zvec_push(v, &c));
    CHECK(zvec_len(v) == 3);
    CHECK(zvec_get(v, 0) == &a);
    CHECK(zvec_get(v, 2) == &c);
    CHECK(zvec_get(v, 3) == NULL);
    CHECK(zvec_get(v, (size_t)-1) == NULL);

    CHECK(zvec_set(v, 1, &a) == &b);
    CHECK(zvec_get(v, 1) == &a);
    CHECK(zvec_set(v, 9, &b) == NULL);

    CHECK(zvec_pop(v) == &c);
    CHECK(zvec_len(v) == 2);
    zvec_destroy(v);
    zvec_destroy(NULL);

    /* NULL-vector tolerance. */
    CHECK(zvec_len(NULL) == 0);
    CHECK(zvec_capacity(NULL) == 0);
    CHECK(zvec_get(NULL, 0) == NULL);
    CHECK(!zvec_push(NULL, &a));
    CHECK(zvec_pop(NULL) == NULL);
    CHECK(!zvec_insert(NULL, 0, &a));
    CHECK(zvec_remove(NULL, 0) == NULL);
    CHECK(zvec_swap_remove(NULL, 0) == NULL);
    zvec_clear(NULL);
    CHECK(!zvec_shrink_to_fit(NULL));
    CHECK(zvec_index_of(NULL, &a) == -1);
}

static void test_insert_remove(void)
{
    int vals[5] = {0, 1, 2, 3, 4};
    zvec *v = zvec_create((zvec_alloc){0});
    for (int i = 0; i < 5; i++) CHECK(zvec_push(v, &vals[i]));

    /* Insert middle/front/back. */
    int x = 99;
    CHECK(zvec_insert(v, 2, &x));
    CHECK(zvec_len(v) == 6);
    CHECK(zvec_get(v, 2) == &x);
    CHECK(zvec_get(v, 3) == &vals[2]);
    CHECK(!zvec_insert(v, 7, &x));
    CHECK(zvec_insert(v, 0, &x));
    CHECK(zvec_insert(v, zvec_len(v), &x)); /* append via insert */

    /* Ordered remove. */
    CHECK(zvec_remove(v, 0) == &x);
    CHECK(zvec_remove(v, 2) == &x);
    CHECK(zvec_get(v, 2) == &vals[2]);
    CHECK(zvec_remove(v, 99) == NULL);

    /* Swap remove. */
    size_t n = zvec_len(v);
    void *last = zvec_get(v, n - 1);
    void *at1 = zvec_get(v, 1);
    CHECK(zvec_swap_remove(v, 1) == at1);
    CHECK(zvec_len(v) == n - 1);
    CHECK(zvec_get(v, 1) == last);

    zvec_clear(v);
    CHECK(zvec_len(v) == 0);
    CHECK(zvec_capacity(v) > 0);
    zvec_destroy(v);
}

static void test_index_of(void)
{
    int a = 1, b = 2;
    zvec *v = zvec_create((zvec_alloc){0});
    CHECK(zvec_index_of(v, &a) == -1);
    CHECK(zvec_push(v, &a));
    CHECK(zvec_push(v, &b));
    CHECK(zvec_push(v, &a));
    CHECK(zvec_index_of(v, &a) == 0); /* first match */
    CHECK(zvec_index_of(v, &b) == 1);
    int z = 3;
    CHECK(zvec_index_of(v, &z) == -1);
    zvec_destroy(v);
}

static void test_alloc_failure(void)
{
    struct test_alloc t;
    int x = 1;

    /* Failure on struct allocation. */
    CHECK(zvec_create(ta(&t, 0)) == NULL);

    /* Failure on first grow: vector unchanged. Flip the switch through
     * the shared allocator context — the vector stays opaque. */
    struct test_alloc t2;
    zvec *v = zvec_create(ta(&t2, SIZE_MAX));
    CHECK(v != NULL);
    t2.fail_after = t2.mallocs; /* next malloc fails */
    CHECK(!zvec_push(v, &x));
    CHECK(zvec_len(v) == 0);
    /* Recovers when allocation works again. */
    t2.fail_after = SIZE_MAX;
    CHECK(zvec_push(v, &x));
    CHECK(zvec_len(v) == 1);
    zvec_destroy(v);

    /* Shrink failure leaves the vector usable. */
    struct test_alloc t3;
    zvec *w = zvec_create(ta(&t3, SIZE_MAX));
    for (int i = 0; i < 33; i++) CHECK(zvec_push(w, &x)); /* cap 64 > len */
    t3.fail_after = t3.mallocs; /* next malloc fails */
    CHECK(!zvec_shrink_to_fit(w));
    CHECK(zvec_len(w) == 33);
    zvec_destroy(w);
}

static void test_growth_and_balance(void)
{
    struct test_alloc t;
    zvec *v = zvec_create(ta(&t, SIZE_MAX));
    int x = 1;
    for (int i = 0; i < 10000; i++) CHECK(zvec_push(v, &x));
    CHECK(zvec_len(v) == 10000);
    for (int i = 0; i < 10000; i++) CHECK(zvec_pop(v) == &x);
    CHECK(zvec_len(v) == 0);
    /* Geometric growth: far fewer allocations than pushes. */
    CHECK(t.mallocs < 30);

    CHECK(zvec_shrink_to_fit(v));
    CHECK(zvec_capacity(v) == 0);
    zvec_destroy(v);

    /* Every allocation is eventually freed exactly once. */
    struct test_alloc t3;
    zvec *w = zvec_with_capacity(4, ta(&t3, SIZE_MAX));
    CHECK(w != NULL && zvec_capacity(w) == 4);
    for (int i = 0; i < 100; i++) CHECK(zvec_push(w, &x));
    CHECK(zvec_shrink_to_fit(w));
    CHECK(zvec_capacity(w) == 100);
    zvec_destroy(w);
    CHECK(t3.mallocs == t3.frees);
}

static void test_stress_vs_model(void)
{
    /* Differential test against a simple open-coded model. */
    zvec *v = zvec_create((zvec_alloc){0});
    long model[4096];
    size_t mlen = 0;
    long storage[4096];
    for (int i = 0; i < 4096; i++) storage[i] = i;

    uint64_t rng = 0x0123456789abcdefull;
    for (int op = 0; op < 20000; op++) {
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        unsigned kind = (unsigned)(rng >> 61); /* top 3 bits */
        size_t idx = mlen ? (size_t)((rng >> 13) % (mlen + 1)) : 0;
        if (mlen >= 4096) kind = 3; /* bounded model: force a pop */
        if (kind <= 2 || mlen == 0) { /* push */
            long *val = &storage[op % 4096];
            CHECK(zvec_push(v, val));
            model[mlen++] = (long)(op % 4096);
        } else if (kind == 3) { /* pop */
            void *got = zvec_pop(v);
            CHECK(got == &storage[model[--mlen]]);
        } else if (kind == 4) { /* insert at idx */
            long *val = &storage[op % 4096];
            CHECK(zvec_insert(v, idx, val));
            memmove(model + idx + 1, model + idx, (mlen - idx) * sizeof(long));
            model[idx] = (long)(op % 4096);
            mlen++;
        } else if (kind == 5) { /* ordered remove */
            void *got = zvec_remove(v, idx % mlen);
            CHECK(got == &storage[model[idx % mlen]]);
            memmove(model + idx % mlen, model + idx % mlen + 1,
                    (mlen - idx % mlen - 1) * sizeof(long));
            mlen--;
        } else { /* get/set check */
            size_t gi = idx % mlen;
            CHECK(zvec_get(v, gi) == &storage[model[gi]]);
        }
        CHECK(zvec_len(v) == mlen);
    }
    zvec_destroy(v);
}

static int cli_case(int argc, char **args, int status, const char *want,
                     bool stale_errno)
{
    FILE *output = tmpfile();
    if (!output) return 1;
    cli_sink = output;
    errno = stale_errno ? ERANGE : 0;
    int bad = zvec_cli_main(argc, args) != status;
    cli_sink = stdout;
    if (cli_alloc.mallocs != cli_alloc.frees) bad = 1;
    rewind(output);
    char bytes[256];
    size_t n = fread(bytes, 1, sizeof bytes, output);
    if (ferror(output) || n != strlen(want) || memcmp(bytes, want, n) != 0) bad = 1;
    if (fclose(output) != 0) bad = 1;
    return bad;
}

static int cli_index_case(const char *operation, const char *index,
                           int status, const char *want, bool stale_errno)
{
    char op[256];
    int n = snprintf(op, sizeof op, strcmp(operation, "insert") == 0
        ? "%s:%s:injected" : "%s:%s", operation, index);
    if (n < 0 || (size_t)n >= sizeof op) return 1;
    char *args[] = {"zvec", "push:first", "push:second", op, NULL};
    return cli_case(4, args, status, want, stale_errno);
}

static void test_cli_invalid_indices(void)
{
    const char *ops[] = {"remove", "swap-remove", "insert"};
    const char *bad[] = {"garbage", "", " \t", "1junk", "1 ", "-1", " -2",
        "184467440737095516160", "0x1"};
    unsigned failures = 0;
    for (size_t op = 0; op < sizeof ops / sizeof ops[0]; op++) {
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            int rc = cli_index_case(ops[op], bad[i], 2, "", false);
            if (rc) failures++;
            fprintf(stderr, "cli_invalid_index op=%s row=%zu result=%s\n",
                    ops[op], i, rc ? "FAIL" : "PASS");
        }
    }
    CHECK(failures == 0);
    CHECK(cli_index_case("remove", "1:extra", 2, "", false) == 0);
    CHECK(cli_index_case("swap-remove", "1:extra", 2, "", false) == 0);
}

static void test_cli_valid_indices(void)
{
    const char *ones[] = {"1", "+1", " \t1"};
    for (size_t i = 0; i < sizeof ones / sizeof ones[0]; i++) {
        CHECK(cli_index_case("remove", ones[i], 0, "first\n", false) == 0);
        CHECK(cli_index_case("swap-remove", ones[i], 0, "first\n", false) == 0);
        CHECK(cli_index_case("insert", ones[i], 0, "first\ninjected\nsecond\n", false) == 0);
    }
    CHECK(cli_index_case("remove", "-0", 0, "second\n", false) == 0);
    CHECK(cli_index_case("swap-remove", "-0", 0, "second\n", false) == 0);
    CHECK(cli_index_case("insert", "-0", 0, "injected\nfirst\nsecond\n", false) == 0);
    char maximum[3 * sizeof(size_t) + 1];
    snprintf(maximum, sizeof maximum, "%zu", SIZE_MAX);
    size_t parsed = 0;
    CHECK(parse_index(maximum, '\0', &parsed, NULL) && parsed == SIZE_MAX);
    errno = ERANGE;
    CHECK(parse_index("1", '\0', &parsed, NULL) && parsed == 1);
    CHECK(cli_index_case("remove", maximum, 0, "first\nsecond\n", false) == 0);
    CHECK(cli_index_case("swap-remove", maximum, 0, "first\nsecond\n", false) == 0);
    CHECK(cli_index_case("insert", maximum, 1, "", false) == 0);
    CHECK(cli_index_case("remove", "1", 0, "first\n", true) == 0);
    char *ops[] = {"zvec", "push:first", "push:second", "push:third",
        "swap-remove:0", "insert:1:with:colon", "pop", NULL};
    CHECK(cli_case(7, ops, 0, "third\nwith:colon\n", false) == 0);
    char *clear[] = {"zvec", "push:first", "clear", "push:last", NULL};
    CHECK(cli_case(4, clear, 0, "last\n", false) == 0);
}

static void test_cli_output(void);

int main(void)
{
    cli_sink = stdout;
    test_cli_output();
    test_cli_invalid_indices();
    test_cli_valid_indices();
    test_initial_capacity();
    test_basic();
    test_insert_remove();
    test_index_of();
    test_alloc_failure();
    test_growth_and_balance();
    test_stress_vs_model();
    puts("test_zvec: all groups passed (capacity basic insert index allocfail growth stress)");
    return 0;
}

static int output_invoke(FILE *sink, int argc, char **args)
{
    cli_sink = sink;
    cli_flushes = 0;
    int rc = zvec_cli_main(argc, args);
    cli_sink = stdout;
    CHECK(cli_alloc.mallocs == cli_alloc.frees);
    return rc;
}
static void output_failure(bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
    char *args[] = {"zvec", "push:first", "push:", "push:last", NULL};
    CHECK(output_invoke(sink, 4, args) == 1);
    CHECK(ferror(sink));
    (void)fclose(sink);
}
static void output_unused(void)
{
    const struct { char *ops[5]; int argc, status; } rows[] = {
        {{"zvec", "clear", NULL}, 2, 0},
        {{"zvec", "push:x", "clear", NULL}, 3, 0},
        {{"zvec", "push:x", "pop", NULL}, 3, 0},
        {{"zvec", "push:x", "remove:garbage", NULL}, 3, 2},
        {{"zvec", "push:x", "unknown", NULL}, 3, 2},
        {{"zvec", NULL}, 1, 2},
        {{"zvec", "insert:1:x", NULL}, 2, 1}
    };
#ifdef _WIN32
    FILE *sink = fopen("NUL", "r");
#else
    FILE *sink = fopen("/dev/null", "r");
#endif
    CHECK(sink != NULL);
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char *args[5];
        memcpy(args, rows[i].ops, sizeof args);
        CHECK(output_invoke(sink, rows[i].argc, args) == rows[i].status);
        CHECK(cli_flushes == 0 && !ferror(sink));
    }
    CHECK(fclose(sink) == 0);
}
static void test_cli_output(void)
{
    char *args[] = {"zvec", "push:first", "push:", "push:last", NULL};
    CHECK(cli_case(4, args, 0, "first\n\nlast\n", false) == 0);
    output_failure(false);
#ifdef __linux__
    output_failure(true);
#endif
    output_unused();
}
