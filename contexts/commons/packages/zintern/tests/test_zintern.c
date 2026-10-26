/* zintern tests: dedup, dense ids, get-without-insert, binary-safe
 * keys, alloc failure, and a randomized differential test against a
 * linear-scan model. */
#include "zintern/zintern.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

static void test_basic(void)
{
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);
    uint32_t a = zintern_put(p, "alpha", 5);
    uint32_t b = zintern_put(p, "beta", 4);
    uint32_t a2 = zintern_put(p, "alpha", 5);
    CHECK(a == 0 && b == 1 && a2 == a);
    CHECK(zintern_count(p) == 2);

    size_t n = 0;
    const char *s = zintern_str(p, a, &n);
    CHECK(s && n == 5 && memcmp(s, "alpha", 5) == 0);
    s = zintern_str(p, b, &n);
    CHECK(s && n == 4 && memcmp(s, "beta", 4) == 0);
    CHECK(zintern_str(p, 2, NULL) == NULL);

    CHECK(zintern_get(p, "alpha", 5) == a);
    CHECK(zintern_get(p, "gamma", 5) == UINT32_MAX);
    CHECK(zintern_count(p) == 2); /* get did not insert */
    zintern_destroy(p);
}

static void test_binary_and_empty(void)
{
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);
    /* empty string is legal and distinct from "\0" */
    uint32_t e = zintern_put(p, "", 0);
    uint32_t z = zintern_put(p, "\0", 1);
    uint32_t zz = zintern_put(p, "\0\0", 2);
    CHECK(e != z && z != zz && e != zz);
    size_t n = 99;
    const char *s = zintern_str(p, e, &n);
    CHECK(s && n == 0);
    s = zintern_str(p, z, &n);
    CHECK(s && n == 1 && s[0] == '\0');
    /* embedded NULs */
    const char bin[] = { 'a', 0, 'b', 0, 'c' };
    uint32_t x = zintern_put(p, bin, sizeof bin);
    CHECK(zintern_get(p, bin, sizeof bin) == x);
    CHECK(zintern_get(p, bin, 3) != x); /* prefix differs */
    zintern_destroy(p);
}

/* alloc injection with a failure counter */
struct alloc_ctl {
    size_t live;
    long fail_after; /* fail when this hits 0; -1 = never */
};

static void *ctl_malloc(void *ctx, size_t n)
{
    struct alloc_ctl *c = ctx;
    if (c->fail_after == 0) return NULL;
    if (c->fail_after > 0) c->fail_after--;
    size_t *m = malloc(n + sizeof(size_t));
    if (!m) return NULL;
    *m = n;
    c->live++;
    return m + 1;
}

static void ctl_free(void *ctx, void *ptr)
{
    struct alloc_ctl *c = ctx;
    if (!ptr) return;
    c->live--;
    free((size_t *)ptr - 1);
}

static void test_alloc_failure(void)
{
    for (long fail_at = 0; fail_at < 40; fail_at++) {
        struct alloc_ctl ctl = { .live = 0, .fail_after = fail_at };
        zintern *p = zintern_create((zintern_alloc){
            ctl_malloc, ctl_free, &ctl });
        if (!p) { CHECK(ctl.live == 0); continue; }
        unsigned ok = 0;
        for (int i = 0; i < 50; i++) {
            char buf[16];
            int bl = snprintf(buf, sizeof buf, "sym%d", i);
            if (zintern_put(p, buf, (size_t)bl) == UINT32_MAX)
                break; /* clean refusal */
            ok++;
        }
        CHECK(ctl.live != (size_t)-1); /* no underflow */
        /* everything interned so far is still retrievable */
        for (unsigned i = 0; i < ok; i++) {
            char buf[16];
            int bl = snprintf(buf, sizeof buf, "sym%u", i);
            uint32_t id = zintern_get(p, buf, (size_t)bl);
            CHECK(id == i);
            size_t n = 0;
            const char *s = zintern_str(p, id, &n);
            CHECK(s && n == (size_t)bl && memcmp(s, buf, n) == 0);
        }
        zintern_destroy(p);
        CHECK(ctl.live == 0); /* no leaks */
    }
}

/* Differential vs linear model with heavy duplication. */
static unsigned long long rng_state;

static unsigned long long rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_differential(void)
{
    rng_state = 0x0123456789ABCDEFull;
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);

    static char model[2048][12];
    static size_t model_len[2048];
    size_t model_n = 0;

    for (int op = 0; op < 60000; op++) {
        char key[12];
        size_t len = (size_t)(rng_next() % 8); /* short keys, hot set */
        for (size_t i = 0; i < len; i++)
            key[i] = (char)('a' + rng_next() % 6);

        /* model lookup */
        uint32_t mid = UINT32_MAX;
        for (size_t i = 0; i < model_n; i++)
            if (model_len[i] == len && memcmp(model[i], key, len) == 0) {
                mid = (uint32_t)i;
                break;
            }

        if (rng_next() % 3 == 0) {
            /* get (no insert) */
            CHECK(zintern_get(p, key, len) == mid);
        } else {
            if (mid == UINT32_MAX && model_n >= 2048)
                continue; /* model full; stay in get-only space */
            uint32_t id = zintern_put(p, key, len);
            CHECK(id != UINT32_MAX);
            if (mid == UINT32_MAX) {
                CHECK(id == (uint32_t)model_n);
                memcpy(model[model_n], key, len);
                model_len[model_n] = len;
                model_n++;
            } else {
                CHECK(id == mid);
            }
        }
        CHECK(zintern_count(p) == model_n);
    }

    /* full content verification */
    for (size_t i = 0; i < model_n; i++) {
        size_t n = 0;
        const char *s = zintern_str(p, (uint32_t)i, &n);
        CHECK(s && n == model_len[i]);
        CHECK(memcmp(s, model[i], n) == 0);
        CHECK(zintern_get(p, model[i], model_len[i]) == (uint32_t)i);
    }
    zintern_destroy(p);
}

static void test_cli(void);

int main(void)
{
    test_cli();
    test_basic();
    test_binary_and_empty();
    test_alloc_failure();
    test_differential();
    puts("test_zintern: all groups passed (basic binary allocfail diff)");
    return 0;
}

static FILE *cli_source, *cli_sink;
static size_t cli_flushes, cli_puts, cli_fail_put;
static bool cli_read_fault;
static struct alloc_ctl cli_alloc;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static zintern *cli_create(zintern_alloc ignored)
{
    (void)ignored;
    cli_alloc = (struct alloc_ctl){.live = 0, .fail_after = -1};
    return zintern_create((zintern_alloc){ctl_malloc, ctl_free, &cli_alloc});
}
static uint32_t cli_put(zintern *p, const void *bytes, size_t n)
{
    if (++cli_puts == cli_fail_put) cli_alloc.fail_after = 0;
    return zintern_put(p, bytes, n);
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
[[maybe_unused]] static int cli_error(FILE *stream)
{
    return (stream == cli_source && cli_read_fault) || ferror(stream);
}
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define fflush cli_flush
#define ferror cli_error
#define zintern_create cli_create
#define zintern_put cli_put
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef zintern_put
#undef zintern_create
#undef ferror
#undef fflush
#undef printf
#undef stdin
#undef stdout
#define stdin real_stdin()
#define stdout real_stdout()

static FILE *cli_input(const char *text)
{
    FILE *source = tmpfile();
    CHECK(source != NULL);
    CHECK(fputs(text, source) >= 0 && fflush(source) == 0);
    rewind(source);
    return source;
}
static int cli_invoke(FILE *source, FILE *sink, const char *mode, bool query_words)
{
    char *args[] = {"zintern", (char *)mode, "b", "a", "b", NULL};
    char large_word[513];
    if (cli_fail_put) {
        memset(large_word, 'x', sizeof large_word - 1);
        large_word[sizeof large_word - 1] = '\0';
        args[3] = large_word;
    }
    cli_source = source;
    cli_sink = sink;
    cli_flushes = cli_puts = 0;
    int rc = embedded_cli_main(query_words ? 5 : (mode ? 2 : 1), args);
    cli_source = stdin;
    cli_sink = stdout;
    CHECK(cli_alloc.live == 0);
    return rc;
}
static void cli_case(const char *input, const char *mode, bool query_words,
                      int status, const char *want)
{
    FILE *source = cli_input(input), *sink = tmpfile();
    CHECK(sink != NULL);
    CHECK(cli_invoke(source, sink, mode, query_words) == status);
    if (!*want) { CHECK(cli_flushes == 0); }
    char bytes[256];
    rewind(sink);
    size_t n = fread(bytes, 1, sizeof bytes, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
    CHECK(fclose(source) == 0 && fclose(sink) == 0);
}
static void cli_failed_output(bool query, bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *source = cli_input("b\na\nb\n");
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
    CHECK(cli_invoke(source, sink, query ? "-q" : NULL, query) == 2);
    CHECK(ferror(sink));
    CHECK(fclose(source) == 0);
    (void)fclose(sink);
}
static void cli_failed_input(void)
{
    cli_read_fault = true;
    cli_case("", NULL, false, 2, "");
    cli_case("b\n", NULL, false, 2, "0\tb\n");
    cli_read_fault = false;
#ifdef _WIN32
    FILE *source = fopen("NUL", "w");
#else
    FILE *source = fopen("/dev/null", "w");
#endif
    FILE *sink = tmpfile();
    CHECK(source != NULL && sink != NULL);
    CHECK(cli_invoke(source, sink, NULL, false) == 2);
    CHECK(cli_flushes == 0 && ftell(sink) == 0);
    CHECK(fclose(source) == 0 && fclose(sink) == 0);
}
static void test_cli(void)
{
    cli_case("b\na\nb\n", NULL, false, 0, "0\tb\n1\ta\n0\tb\n");
    cli_case("ignored", "-q", true, 0, "0\tb\n1\ta\n0\tb\n");
    cli_case("\r\nb\r\n\n", NULL, false, 0, "0\t\n1\tb\n0\t\n");
    cli_case("b\n", "unknown", false, 0, "0\tb\n");
    cli_case("", NULL, false, 0, "");
    cli_case("", "-q", false, 0, "");
    cli_failed_output(false, false);
    cli_failed_output(true, false);
#ifdef __linux__
    cli_failed_output(false, true);
    cli_failed_output(true, true);
#endif
    cli_failed_input();
    cli_fail_put = 2;
    char growth[516];
    memcpy(growth, "b\n", 2);
    memset(growth + 2, 'x', 512);
    memcpy(growth + 514, "\n", 2);
    cli_case(growth, NULL, false, 2, "0\tb\n");
    cli_case("", "-q", true, 2, "0\tb\n");
    cli_fail_put = 0;
}
